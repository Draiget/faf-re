#include "detours_sigscan.h"
#include <algorithm>
#include <cctype>

namespace detours::sigscan {

    static inline int hexval(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    }
    static inline std::optional<std::uint8_t> parse_hex_byte(std::string_view t) {
        if (t == "?" || t == "??") return std::nullopt;
        if (t.size() != 2) return std::nullopt;
        int hi = hexval(t[0]), lo = hexval(t[1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        return static_cast<std::uint8_t>((hi << 4) | lo);
    }

    static void choose_anchor(const std::vector<std::uint8_t>& mask,
        std::size_t& off, std::size_t& len)
    {
        // Pick the longest contiguous run of exact bytes.
        off = 0; len = 0;
        std::size_t cur_o = 0, cur_l = 0;
        for (std::size_t i = 0; i < mask.size(); ++i) {
            if (mask[i]) {
                if (cur_l == 0) cur_o = i;
                ++cur_l;
                if (cur_l > len) { off = cur_o; len = cur_l; }
            } else {
                cur_l = 0;
            }
        }
        // Fallback: if all wildcards (len==0), anchor first byte as fake 1-byte
        if (len == 0 && !mask.empty()) { off = 0; len = 1; }
    }

    static std::vector<int> build_bmh_shift(const std::uint8_t* lit, std::size_t n) {
        // Standard BMH shift table for the last byte of literal.
        std::vector<int> sh(256, static_cast<int>(n));
        if (n == 0) return sh;
        for (std::size_t i = 0; i + 1 < n; ++i) {
            sh[lit[i]] = static_cast<int>(n - 1 - i);
        }
        return sh;
    }

    std::optional<Compiled> compile_ida(std::string_view ida) {
        std::vector<std::uint8_t> bytes, mask;
        bytes.reserve(ida.size() / 2);
        mask.reserve(ida.size() / 2);

        auto skip_space = [&](size_t& i) {
            while (i < ida.size() && std::isspace(static_cast<unsigned char>(ida[i]))) ++i;
            };

        for (size_t i = 0; i < ida.size();) {
            skip_space(i);
            if (i >= ida.size()) break;
            size_t j = i;
            while (j < ida.size() && !std::isspace(static_cast<unsigned char>(ida[j]))) ++j;
            auto tok = ida.substr(i, j - i);
            auto b = parse_hex_byte(tok);
            if (b) { bytes.push_back(*b); mask.push_back(0xFF); } else { bytes.push_back(0);  mask.push_back(0x00); }
            i = j;
        }

        if (bytes.empty()) return std::nullopt;

        Compiled out;
        out.bytes = std::move(bytes);
        out.mask = std::move(mask);

        choose_anchor(out.mask, out.anchor_off, out.anchor_len);

        // Build literal view for anchor
        std::vector<std::uint8_t> lit;
        lit.reserve(out.anchor_len);
        for (size_t k = 0; k < out.anchor_len; ++k) {
            // If anchor contains wildcards (could happen only if everything was wildcard),
            // fill zeros — BMH will just scan byte-by-byte effectively.
            lit.push_back(out.mask[out.anchor_off + k] ? out.bytes[out.anchor_off + k] : 0);
        }
        out.bmh_shift = build_bmh_shift(lit.data(), lit.size());
        return out;
    }

#if defined(_WIN32)
    struct Section {
        std::uint8_t* begin;
        std::size_t   size;
    };

    static bool pe_sections(HMODULE mod, std::vector<Section>& out) {
        auto base = reinterpret_cast<std::uint8_t*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& s = sec[i];
            const auto chars = s.Characteristics;
            // Scan executable (and readable) code sections.
            if (chars & IMAGE_SCN_MEM_EXECUTE) {
                auto* beg = base + s.VirtualAddress;
                std::size_t sz = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
                if (sz) out.push_back({ beg, sz });
            }
        }
        return !out.empty();
    }

    static inline bool verify_full(const std::uint8_t* p,
        const std::uint8_t* pat,
        const std::uint8_t* msk,
        std::size_t n)
    {
        // Simple masked compare. (Replace with SSE2 if you want.)
        for (std::size_t i = 0; i < n; ++i) {
            if (msk[i] && p[i] != pat[i]) return false;
        }
        return true;
    }

    static void* find_in_section(const Section& s, const Compiled& cp, bool require_unique) {
        if (cp.bytes.size() == 0 || cp.anchor_len == 0) return nullptr;

        const std::size_t N = cp.bytes.size();
        const std::size_t A = cp.anchor_off;
        const std::size_t L = cp.anchor_len;

        // Literal pointer for anchor
        const std::uint8_t* anchor_lit = cp.bytes.data() + A;

        std::uint8_t* found = nullptr;

        // Bounds for scanning (ensure room for full pattern once anchor aligns)
        std::uint8_t* const beg = s.begin;
        std::uint8_t* const end = s.begin + s.size;

        if (end - beg < static_cast<ptrdiff_t>(N)) return nullptr;

        // BMH over the anchor (using last byte of anchor)
        const std::uint8_t last = anchor_lit[L - 1];

        for (std::uint8_t* cur = beg; cur <= end - L; ) {
            const std::uint8_t c = cur[L - 1];
            if (c != last) {
                cur += cp.bmh_shift[c];
                continue;
            }
            // Compare the anchor bytes (anchor contains only exact bytes)
            if (L == 1 || std::memcmp(cur, anchor_lit, L) == 0) {
                // Candidate for the full pattern starts at cur - A
                std::uint8_t* cand = cur - A;
                if (cand >= beg && cand <= end - N) {
                    if (verify_full(cand, cp.bytes.data(), cp.mask.data(), N)) {
                        if (!require_unique) return cand;
                        if (found) return invalid_ptr;
                        found = cand;
                    }
                }
                cur += 1; // avoid infinite loop on repeating byte
            } else {
                cur += cp.bmh_shift[c];
            }
        }

        return found;
    }

    void* find_ida(HMODULE mod, const Compiled& cp, bool require_unique) {
        if (!mod) return nullptr;
        std::vector<Section> secs;
        if (!pe_sections(mod, secs)) return nullptr;

        std::uint8_t* uniq = nullptr;
        for (const auto& s : secs) {
            auto* r = static_cast<std::uint8_t*>(find_in_section(s, cp, /*require_unique=*/false));
            if (!r) continue;

            if (!cp.bytes.empty()) {
                if (!uniq) uniq = r;
                else {
                    // If we already have one hit, check if a second exists (could be in same section).
                    // Re-scan the section with unique requirement to confirm.
                    auto* c = static_cast<std::uint8_t*>(find_in_section(s, cp, /*require_unique=*/true));
                    if (c == invalid_ptr) return invalid_ptr;
                    if (c && c != uniq) return invalid_ptr;
                }
            }
        }
        return uniq;
    }

    void* find_ida(std::wstring_view module_name_w, const Compiled& pat, bool require_unique) {
        HMODULE mod = ::GetModuleHandleW(std::wstring(module_name_w).c_str());
        return find_ida(mod, pat, require_unique);
    }
#else
    void* find_ida(HMODULE, const Compiled&, bool) { return nullptr; }
    void* find_ida(std::wstring_view, const Compiled&, bool) { return nullptr; }
#endif

} // namespace
