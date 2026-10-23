// ReSharper disable CppClangTidyClangDiagnosticLanguageExtensionToken
// ReSharper disable CppTooWideScope
// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppClangTidyClangDiagnosticUndefinedReinterpretCast
// ReSharper disable CppUseStructuredBinding
#include "rtti_dump.h"

#ifndef NOMINMAX
// ReSharper disable once IdentifierTypo
#define NOMINMAX 1
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <excpt.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <ranges>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace moho_rtti {

    // ==============================================================================================
    // Internal helpers live in an anonymous namespace
    // ==============================================================================================
    namespace {

        // --------------------------------------- Diagnostics -----------------------------------------
        [[maybe_unused]]
    	void DebugLog(std::string_view s) noexcept {
#if defined(_DEBUG)
            std::string line(s);
            line.push_back('\n');
            OutputDebugStringA(line.c_str());
#else
            (void)s;
#endif
        }

        // --------------------------------------- SEH-safe reads --------------------------------------
        template <class T>
        [[nodiscard]]
    	bool SafeRead(const void* p, T& out) noexcept {
            static_assert(std::is_trivial_v<T>, "SafeRead expects POD/trivial type");
            __try {
                out = *static_cast<const T*>(p);
                return true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                std::memset(&out, 0, sizeof(T));
                return false;
            }
        }

        template <class T>
        [[nodiscard]]
    	bool SafeCopyT(const void* src, T& dst) noexcept {
            __try {
                std::memcpy(&dst, src, sizeof(T));
                return true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                std::memset(&dst, 0, sizeof(T));
                return false;
            }
        }

        // --------------------------------------- PE layout -------------------------------------------
        struct TextRange {
            uintptr_t begin{};
            uintptr_t end{};

            [[nodiscard]]
            [[maybe_unused]]
        	bool contains(const uintptr_t p) const noexcept {
	            return p >= begin && p < end;
            }
        };

        struct Ranges {
            uintptr_t modBeg{}, modEnd{};
            uintptr_t rdataBeg{}, rdataEnd{};
            uintptr_t dataBeg{}, dataEnd{};
            uintptr_t textBeg{}, textEnd{};
        };

        [[nodiscard]]
    	std::optional<TextRange> GetSectionRange(const HMODULE hMod, const char* section) {
            MODULEINFO mi{};
            if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
                return std::nullopt;
            }
            auto base = static_cast<uint8_t*>(mi.lpBaseOfDll);
            const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                return std::nullopt;
            }
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) {
                return std::nullopt;
            }

            const auto sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                char name[9]{};
                std::memcpy(name, sec[i].Name, 8);
                if (std::string(name) == section) {
	                const uintptr_t start = reinterpret_cast<uintptr_t>(base) + sec[i].VirtualAddress;
	                const uintptr_t end = start + std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
                    return TextRange{ start, end };
                }
            }
            return std::nullopt;
        }

        [[nodiscard]]
    	bool GetModuleRangesByAddress(const void* anyPtr, Ranges& out) {
            HMODULE hMod = nullptr;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                static_cast<LPCSTR>(anyPtr), &hMod)) {
                return false;
            }
            MODULEINFO mi{};
            if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
                return false;
            }

            const auto beg = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            const auto end = beg + mi.SizeOfImage;
            out.modBeg = beg;
            out.modEnd = end;

            if (const auto rdata = GetSectionRange(hMod, ".rdata")) {
                out.rdataBeg = rdata->begin;
                out.rdataEnd = rdata->end;
            }
            if (const auto data = GetSectionRange(hMod, ".data")) {
                out.dataBeg = data->begin;
                out.dataEnd = data->end;
            }
            if (const auto text = GetSectionRange(hMod, ".text")) {
                out.textBeg = text->begin;
                out.textEnd = text->end;
            }
            return true;
        }

        [[nodiscard]]
    	bool InConstOrData(const uintptr_t p, const Ranges& rg, const size_t bytes = 1) noexcept {
            if (bytes == 0) {
                return false;
            }
            auto inside = [&](const uintptr_t beg, const uintptr_t end) -> bool {
                if (!beg || !end || beg >= end) {
                    return false;
                }
                if (p < beg || p >= end) {
                    return false;
                }
                const size_t avail = end - p;
                return bytes <= avail;
                };
            return inside(rg.rdataBeg, rg.rdataEnd) || inside(rg.dataBeg, rg.dataEnd);
        }

        [[nodiscard]]
    	bool InText(const uintptr_t p, const Ranges& rg) noexcept {
            if (!rg.textBeg || !rg.textEnd || rg.textBeg >= rg.textEnd) {
                return false;
            }
            return (p >= rg.textBeg && p < rg.textEnd);
        }

        [[nodiscard]]
    	const char* SafeCStrInConstOrData(const uintptr_t p, const Ranges& rg, const size_t max = 4096) {
            if (!InConstOrData(p, rg)) {
                return nullptr;
            }
            const auto s = reinterpret_cast<const char*>(p);
            for (size_t i = 0; i < max; ++i) {
                if (!InConstOrData(p + i, rg)) {
                    return nullptr;
                }
                if (s[i] == '\0') {
                    return s;
                }
            }
            return nullptr;
        }

        // --------------------------------------- DbgHelp wrapper -------------------------------------
        class SymbolEngine final  // NOLINT(cppcoreguidelines-special-member-functions)
    	{
        public:
            SymbolEngine() = default;
            ~SymbolEngine() {
                if (initialized_) {
                    SymCleanup(GetCurrentProcess());
                }
            }

            SymbolEngine(const SymbolEngine&) = delete;
            SymbolEngine& operator=(const SymbolEngine&) = delete;

            void set_search_path(std::string p) {
                path_ = std::move(p);
                if (initialized_) {
                    SymCleanup(GetCurrentProcess());
                    initialized_ = false;
                }
            }

            [[nodiscard]]
        	std::string from_address(uintptr_t va) {
	            const auto it = cache_.find(va);
                if (it != cache_.end()) {
                    return it->second;
                }

                if (!ensure_initialized()) {
                    cache_.emplace(va, std::string{});
                    return {};
                }

                char buf[sizeof(SYMBOL_INFO) + 1024];
	            const auto si = reinterpret_cast<PSYMBOL_INFO>(buf);
                si->SizeOfStruct = sizeof(SYMBOL_INFO);
                si->MaxNameLen = 1024;
                DWORD64 displacement = 0;
                std::string out;
                if (SymFromAddr(GetCurrentProcess(), va, &displacement, si)) {
                    out = si->Name;
                }
                cache_.emplace(va, out);
                return out;
            }

        private:
            [[nodiscard]]
        	bool ensure_initialized() {
                if (initialized_) {
                    return true;
                }
                if (tried_) {
                    return false;
                }
                tried_ = true;

                SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS);
                const char* sp = path_.empty() ? nullptr : path_.c_str();
                if (!SymInitialize(GetCurrentProcess(), sp, TRUE)) {
                    DebugLog("SymInitialize failed");
                    return false;
                }
                initialized_ = true;
                return true;
            }

            bool initialized_{ false };
            bool tried_{ false };
            std::string path_;
            std::unordered_map<uintptr_t, std::string> cache_;
        };

        SymbolEngine gSym;

        // --------------------------------------- Demangling helpers ----------------------------------
#pragma pack(push, 1)
        struct Pmd
        {
	        // ReSharper disable IdentifierTypo
	        int mdisp;
	        int pdisp;
        	int vdisp;
            // ReSharper restore IdentifierTypo
        };
        struct TypeDescriptor
        {
	        [[maybe_unused]] void* pVFTable;
            [[maybe_unused]] void* spare;
        	char name[1];
        };
        struct ClassHierarchyDescriptor
        {
            [[maybe_unused]] DWORD signature;
        	DWORD attributes;
        	DWORD numBaseClasses;
        	DWORD pBaseClassArray;
        };
        struct BaseClassDescriptor
        {
	        DWORD pTypeDescriptor;
            [[maybe_unused]] DWORD numContainedBases;
        	Pmd where;
        	DWORD attributes;
            [[maybe_unused]] DWORD pClassDescriptor;
        };
        struct CompleteObjectLocator
        {
            [[maybe_unused]] DWORD signature;
        	DWORD offset;
            [[maybe_unused]] DWORD cdOffset;
        	DWORD pTypeDescriptor;
        	DWORD pClassDescriptor;
        };
#pragma pack(pop)

        [[nodiscard]]
    	bool IsLikelyMsvcDecorated(const char* s) {
            if (!s) {
                return false;
            }
            if (!(s[0] == '.' && s[1] == '?' && s[2] == 'A')) {
                return false;
            }
            if (!(s[3] == 'V' || s[3] == 'U')) {
                return false;
            }
            const char* p = s + 4;
            size_t seen = 0;
            while (*p && seen < 1024) {
	            const unsigned char c = static_cast<unsigned char>(*p);
                if (c < 0x20 || c >= 0x7F) {
                    return false;
                }
                if (p[0] == '@' && p[1] == '@') {
                    return true;
                }
                ++p;
                ++seen;
            }
            return false;
        }

        [[nodiscard]]
    	std::string Undecorate(const char* decorated) {
            if (!decorated || !*decorated) {
                return {};
            }
            char buf[2048]{};
            if (UnDecorateSymbolName(decorated, buf, sizeof(buf),
                UNDNAME_COMPLETE | UNDNAME_32_BIT_DECODE |
                UNDNAME_NO_THISTYPE | UNDNAME_NO_ACCESS_SPECIFIERS)) {
                return { buf };
            }
            return {};
        }

        [[nodiscard]]
    	std::string StripClassStructPrefix(std::string s) {
            if (s.rfind("class ", 0) == 0) {
                return s.substr(6);
            }
            if (s.rfind("struct ", 0) == 0) {
                return s.substr(7);
            }
            return s;
        }

        // Basic extraction from ".?AVName@Ns@@"
        [[nodiscard]]
    	std::string FromTypeDescriptorNameBasic(const char* decorated) {
            if (!decorated) {
                return {};
            }
            std::string s(decorated);
            if (!(s.rfind(".?A", 0) == 0 && s.size() >= 6 && s.ends_with("@@"))) {
                return {};
            }
            s = s.substr(4, s.size() - 6); // drop ".?AV"/".?AU" and trailing "@@"
            std::vector<std::string> parts;
            std::string cur;
            for (const char c : s) {
                if (c == '@') {
                    if (!cur.empty()) {
                        parts.push_back(cur);
                        cur.clear();
                    }
                } else {
                    cur.push_back(c);
                }
            }
            if (!cur.empty()) {
                parts.push_back(cur);
            }
            if (parts.empty()) {
                return {};
            }
            std::ranges::reverse(parts);
            std::ostringstream oss;
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i) {
                    oss << "::";
                }
                oss << parts[i];
            }
            return oss.str();
        }

        /**
         * \brief Prefer manual split for TypeDescriptor (.?AVName@Ns@@) over DbgHelp undecorator for non-templates.
         */
        [[nodiscard]]
    	std::string DemangleTypeNamePreferBasic(const char* decorated) {
            if (!decorated) {
                return {};
            }
            // If this looks like a template, prefer the DbgHelp undecorator.
            if (std::strncmp(decorated, ".?A", 3) == 0 && std::strstr(decorated, "?$") != nullptr) {
                if (auto s = Undecorate(decorated); !s.empty()) {
                    return StripClassStructPrefix(std::move(s));
                }
            }
            // Non-template: try cheap manual path first.
            if (std::strncmp(decorated, ".?A", 3) == 0) {
                if (auto s = FromTypeDescriptorNameBasic(decorated); !s.empty()) {
                    return s;
                }
            }
            // Fallback to DbgHelp.
            if (auto s = Undecorate(decorated); !s.empty()) {
                return StripClassStructPrefix(std::move(s));
            }
            return FromTypeDescriptorNameBasic(decorated);
        }

        [[nodiscard]]
    	const char* KeywordFromDecorated(const std::string_view dec) {
            if (dec.rfind(".?AV", 0) == 0) {
                return "class";
            }
            if (dec.rfind(".?AU", 0) == 0) {
                return "struct";
            }
            return "class";
        }

        [[nodiscard]]
    	bool IsIdentStart(const char c) {
            return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
        }

        [[nodiscard]]
    	bool IsIdentChar(const char c) {
            return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
        }

        [[nodiscard]]
    	bool IsMostlyAscii(const std::string& s) {
            size_t ascii = 0;
            for (const unsigned char c : s) {
                if (c >= 32 && c < 127) {
                    ++ascii;
                }
            }
            return (s.empty() || (ascii * 100 >= s.size() * 90));
        }

        [[nodiscard]]
    	std::string SanitizeIdentifierFlat(std::string name, const std::string& fallbackTag) {
            if (name.empty() || !IsMostlyAscii(name)) {
                return "Type_" + fallbackTag;
            }

            for (char& c : name) {
                switch (c) {
                case ':': case '<': case '>': case ',': case ' ':
                case '`': case '?': case '$': case '@': case '&':
                case '*': case '.': case '-': case '/': case '\\':
                case '!': case '%': case '^': case '(': case ')':
                case '[': case ']': case '{': case '}': case '=':
                case '+': case '|': case '~': case ';': case '\'':
                case '\"':
                    c = '_';
                    break;
                default:
                    if (!IsIdentChar(c)) {
                        c = '_';
                    }
                    break;
                }
            }

            // collapse "__"
            std::string out;
            out.reserve(name.size());
            bool prevUnd = false;
            for (const char c : name) {
                if (c == '_') {
                    if (!prevUnd) {
                        out.push_back(c);
                    }
                    prevUnd = true;
                } else {
                    out.push_back(c);
                    prevUnd = false;
                }
            }
            if (out.empty() || !IsIdentStart(out[0])) {
                out = "T_" + out;
            }
            if (out.size() > 200) {
                out.resize(200);
            }
            return out;
        }

        void SplitNamespaces(const std::string& full, std::vector<std::string>& ns, std::string& shortName) {
            ns.clear();
            shortName.clear();
            size_t pos, prev = 0;
            while ((pos = full.find("::", prev)) != std::string::npos) {
                ns.emplace_back(full.substr(prev, pos - prev));
                prev = pos + 2;
            }
            shortName = full.substr(prev);
        }

        void SanitizeNsChain(
            const std::vector<std::string>& in,
            std::vector<std::string>& out,
            const bool lowerFirst)
    	{
            out.clear();
            out.reserve(in.size());
            for (size_t i = 0; i < in.size(); ++i) {
                std::string seg = SanitizeIdentifierFlat(in[i], "Ns");
                if (i == 0 && lowerFirst) {
                    for (auto& ch : seg) {
                        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                    }
                }
                out.push_back(std::move(seg));
            }
        }

        [[nodiscard]]
    	std::string Hex(const uintptr_t v) {
            std::ostringstream oss;
            oss << "0x" << std::uppercase << std::hex << v;
            return oss.str();
        }

        // --------------------------------------- Data models -----------------------------------------
        struct BaseInfo {
            std::string nameDecorated;
            std::string name;
            Pmd pmd{};
            uint32_t attributes{};
        };

        struct VTableInfo {
            uintptr_t vftableVA{};
            uint32_t  colOffset{};
            std::vector<uintptr_t> slots;
        };

        struct ClassInfo {
            std::string nameDecorated;
            std::string name;
            uint32_t hierarchyAttributes{};
            std::vector<BaseInfo> bases;
            std::vector<VTableInfo> vtables;
        };

        struct DumpContext {
            std::unordered_map<std::string, ClassInfo> byTypeName;  // key: decorated or fallback
            std::unordered_set<uintptr_t> visitedVFTables;
            std::unordered_map<uintptr_t, std::string> vftToDecorated; // vftable -> decorated/fallback
        };

        // --------------------------------------- Type utilities --------------------------------------
        [[nodiscard]]
    	std::string DemangleDecorated(const char* decorated) {
            static std::unordered_map<std::string, std::string> cache;
            if (!decorated) {
                return {};
            }
            if (const auto it = cache.find(decorated); it != cache.end()) {
                return it->second;
            }
            std::string pretty = DemangleTypeNamePreferBasic(decorated);
            cache.emplace(decorated, pretty);
            return pretty;
        }

        [[nodiscard]]
    	const char* SafeCStr(const void* p, const Ranges& rg, const size_t maxLen = 4096) {
            if (!p) {
                return nullptr;
            }
            const auto address = reinterpret_cast<uintptr_t>(p);
            return SafeCStrInConstOrData(address, rg, maxLen);
        }

        // --------------------------------------- COL validation --------------------------------------
        [[nodiscard]]
    	bool ValidateColAtVa(const uintptr_t va, const Ranges& rg, CompleteObjectLocator& outCol) {
            if (!InConstOrData(va, rg, sizeof(CompleteObjectLocator))) {
                return false;
            }

            CompleteObjectLocator col{};
            __try {
                std::memcpy(&col, reinterpret_cast<const void*>(va), sizeof(col));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }

            if (col.offset > 0x01000000u) { // sanity
                return false;
            }

            // Try resolving TypeDescriptor as VA or RVA
            const auto try_td_as_VA = [&]() -> const TypeDescriptor* {
                if (!col.pTypeDescriptor) {
                    return nullptr;
                }
                const auto tdVA = static_cast<uintptr_t>(col.pTypeDescriptor);
                if (!InConstOrData(tdVA, rg, sizeof(TypeDescriptor))) {
                    return nullptr;
                }
                return reinterpret_cast<const TypeDescriptor*>(tdVA);
            };

            const auto try_td_as_RVA = [&]() -> const TypeDescriptor* {
                if (!col.pTypeDescriptor) {
                    return nullptr;
                }
                const uintptr_t tdRva = static_cast<uintptr_t>(col.pTypeDescriptor);
                const uintptr_t imageSize = (rg.modEnd - rg.modBeg);
                if (tdRva >= imageSize) {
                    return nullptr;
                }
                const uintptr_t tdVA = rg.modBeg + tdRva;
                if (!InConstOrData(tdVA, rg, sizeof(TypeDescriptor))) {
                    return nullptr;
                }
                return reinterpret_cast<const TypeDescriptor*>(tdVA);
            };

            const TypeDescriptor* td = try_td_as_VA();
            if (!td) {
                td = try_td_as_RVA();
            }
            if (!td) {
                return false;
            }

            const char* decorated = SafeCStr(td->name, rg);
            if (!decorated) {
                return false;
            }
            if (!IsLikelyMsvcDecorated(decorated)) {
                return false;
            }

            outCol = col;
            return true;
        }

        /**
         * \brief Try to obtain a valid CompleteObjectLocator for the given vftable address.
         */
        [[nodiscard]]
    	bool TryGetValidCol(void** vtable,
            CompleteObjectLocator& outCol,
            uintptr_t& outColVA) {
            outColVA = 0;
            Ranges rg{};
            if (!GetModuleRangesByAddress(vtable, rg)) {
                return false;
            }

            DWORD raw = 0;
            if (!SafeRead(reinterpret_cast<const BYTE*>(vtable) - 4, raw)) {
                return false;
            }

            // Attempt as VA
            {
                const uintptr_t candidateVa = static_cast<uintptr_t>(raw);
                CompleteObjectLocator tmp{};
                if (ValidateColAtVa(candidateVa, rg, tmp)) {
                    outCol = tmp;
                    outColVA = candidateVa;
                    return true;
                }
            }

            // Attempt as RVA
            {
                const uintptr_t imageSize = (rg.modEnd - rg.modBeg);
                if (raw && raw < imageSize) {
                    const uintptr_t candidateVa = rg.modBeg + static_cast<uintptr_t>(raw);
                    CompleteObjectLocator tmp{};
                    if (ValidateColAtVa(candidateVa, rg, tmp)) {
                        outCol = tmp;
                        outColVA = candidateVa;
                        return true;
                    }
                }
            }

            return false;
        }

        // --------------------------------------- Vtable ingestion ------------------------------------
        void IngestVftable(DumpContext& dc, uintptr_t vftableVa) {
            if (dc.visitedVFTables.contains(vftableVa)) {
                return;
            }
            dc.visitedVFTables.insert(vftableVa);

            Ranges rg{};
            if (!GetModuleRangesByAddress(reinterpret_cast<void*>(vftableVa), rg)) {
                return;
            }
            if (!InConstOrData(vftableVa, rg)) {
                return;
            }

            CompleteObjectLocator colCopy{};
            uintptr_t colVa = 0;
            if (!TryGetValidCol(reinterpret_cast<void**>(vftableVa), colCopy, colVa)) {
                return;
            }

            // Resolve TypeDescriptor
            auto resolveTd = [&](const DWORD f) -> const TypeDescriptor* {
	            const uintptr_t asVa = static_cast<uintptr_t>(f);
                if (InConstOrData(asVa, rg, sizeof(TypeDescriptor))) {
                    return reinterpret_cast<const TypeDescriptor*>(asVa);
                }
                if (f && f < (rg.modEnd - rg.modBeg)) {
	                const uintptr_t rvaVa = rg.modBeg + f;
                    if (InConstOrData(rvaVa, rg, sizeof(TypeDescriptor))) {
                        return reinterpret_cast<const TypeDescriptor*>(rvaVa);
                    }
                }
                return nullptr;
            };

            const TypeDescriptor* td = resolveTd(colCopy.pTypeDescriptor);
            const char* decorated = td ? SafeCStrInConstOrData(reinterpret_cast<uintptr_t>(td->name), rg) : nullptr;

            char fallback[32];
            _snprintf_s(fallback, _countof(fallback), _TRUNCATE, "vft_%08X", vftableVa);
            bool hasName = IsLikelyMsvcDecorated(decorated);
            const char* keyStr = hasName ? decorated : fallback;

            dc.vftToDecorated[vftableVa] = keyStr;
            auto& cls = dc.byTypeName[keyStr];
            if (cls.name.empty()) {
                if (hasName) {
                    cls.nameDecorated = decorated;
                    cls.name = DemangleDecorated(decorated);
                    if (cls.name.empty()) {
                        cls.name = cls.nameDecorated;
                    }
                } else {
                    cls.nameDecorated.clear();
                    cls.name = keyStr;
                }
            }

            // Collect slots (only pointers into .text of the same module)
            VTableInfo vt{};
            vt.vftableVA = vftableVa;
            vt.colOffset = colCopy.offset;
            constexpr size_t maxSlots = 256;
            for (size_t i = 0; i < maxSlots; ++i) {
                uintptr_t fn = 0;
                if (!SafeRead(
                    reinterpret_cast<const void*>(vftableVa + i * sizeof(uintptr_t)), 
                    reinterpret_cast<DWORD&>(fn))) 
                {
                    break;
                }

                if (!fn) {
                    break;
                }

                if (!InText(fn, rg)) {
                    break;
                }
                vt.slots.push_back(fn);
            }

            if (!vt.slots.empty()) {
                cls.vtables.push_back(std::move(vt));
            }

            // Bases
            if (hasName && cls.bases.empty() && colCopy.pClassDescriptor) {
                auto resolveChd = [&](const DWORD f) -> const ClassHierarchyDescriptor* {
	                const uintptr_t va = static_cast<uintptr_t>(f);
                    if (InConstOrData(va, rg, sizeof(ClassHierarchyDescriptor))) {
                        return reinterpret_cast<const ClassHierarchyDescriptor*>(va);
                    }
                    if (f && f < (rg.modEnd - rg.modBeg)) {
	                    const uintptr_t rvaVA = rg.modBeg + f;
                        if (InConstOrData(rvaVA, rg, sizeof(ClassHierarchyDescriptor))) {
                            return reinterpret_cast<const ClassHierarchyDescriptor*>(rvaVA);
                        }
                    }
                    return nullptr;
                };

                const ClassHierarchyDescriptor* chd = resolveChd(colCopy.pClassDescriptor);
                if (chd) {
                    ClassHierarchyDescriptor chdCopy{};
                    if (SafeCopyT(chd, chdCopy)) {
                        cls.hierarchyAttributes = chdCopy.attributes;
                        constexpr uint32_t maxBases = 256;
                        if (chdCopy.numBaseClasses && chdCopy.numBaseClasses <= maxBases) {
                            auto resolveArr = [&](const DWORD f) -> const DWORD* {
	                            const uintptr_t va = static_cast<uintptr_t>(f);
                                if (InConstOrData(va, rg)) {
                                    return reinterpret_cast<const DWORD*>(va);
                                }
                                if (f && f < (rg.modEnd - rg.modBeg)) {
	                                const uintptr_t rvaVA = rg.modBeg + f;
                                    if (InConstOrData(rvaVA, rg)) {
                                        return reinterpret_cast<const DWORD*>(rvaVA);
                                    }
                                }
                                return nullptr;
                            };

                            const DWORD* arr = resolveArr(chdCopy.pBaseClassArray);
                            if (arr) {
                                for (DWORD j = 0; j < chdCopy.numBaseClasses; ++j) {
                                    const BaseClassDescriptor* bcd = nullptr;
                                    DWORD f = arr[j];
                                    uintptr_t va = static_cast<uintptr_t>(f);
                                    if (InConstOrData(va, rg, sizeof(BaseClassDescriptor))) {
                                        bcd = reinterpret_cast<const BaseClassDescriptor*>(va);
                                    } else if (f && f < (rg.modEnd - rg.modBeg)) {
                                        uintptr_t rvaVA = rg.modBeg + f;
                                        if (InConstOrData(rvaVA, rg, sizeof(BaseClassDescriptor))) {
                                            bcd = reinterpret_cast<const BaseClassDescriptor*>(rvaVA);
                                        }
									}
		                            if (!bcd) {
		                                continue;
		                            }

		                            BaseClassDescriptor bcdCopy{};
		                            if (!SafeCopyT(bcd, bcdCopy)) {
		                                continue;
		                            }

		                            const TypeDescriptor* btd = resolveTd(bcdCopy.pTypeDescriptor);
		                            const char* bName = btd ? 
                                        SafeCStrInConstOrData(reinterpret_cast<uintptr_t>(btd->name), rg) :
                                		nullptr;

		                            if (!IsLikelyMsvcDecorated(bName)) {
		                                continue;
		                            }

		                            BaseInfo bi{};
		                            bi.nameDecorated = bName;
		                            bi.name = DemangleDecorated(bName);
		                            if (bi.name.empty()) {
		                                bi.name = bi.nameDecorated;
		                            }

		                            bi.pmd = bcdCopy.where;
		                            bi.attributes = bcdCopy.attributes;
		                            cls.bases.push_back(std::move(bi));
                                }
                            }
                        }
                    }
                }
            }
        }

        // --------------------------------------- Module scanning -------------------------------------
        [[nodiscard]]
    	std::vector<HMODULE> EnumerateModules(const bool excludeSystem) {
            HMODULE hMods[1024];
            DWORD cbNeeded = 0;
            std::vector<HMODULE> out;
            if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
                return out;
            }
            const size_t count = cbNeeded / sizeof(HMODULE);
            out.reserve(count);
            char path[MAX_PATH]{};
            for (size_t i = 0; i < count; ++i) {
                if (!excludeSystem) {
                    out.push_back(hMods[i]);
                    continue;
                }
                if (GetModuleFileNameA(hMods[i], path, MAX_PATH) == 0) {
                    continue;
                }
                std::string s(path);
                std::ranges::transform(s, s.begin(), tolower);
                // ReSharper disable StringLiteralTypo
                if (s.find("\\windows\\") != std::string::npos ||
	                s.find("\\winsxs\\") != std::string::npos ||
	                s.find("\\microsoft\\") != std::string::npos ||
                    s.find("\\program files\\common files\\") != std::string::npos ||  // NOLINT(modernize-raw-string-literal)
                    s.find("\\driverstore\\") != std::string::npos) 
                {
                    continue;
                }
                // ReSharper restore StringLiteralTypo
                out.push_back(hMods[i]);
            }
            return out;
        }

        void ScanModuleForVftables(const HMODULE hMod, DumpContext& dc) {
	        const auto rdataOpt = GetSectionRange(hMod, ".rdata");
	        const auto dataOpt = GetSectionRange(hMod, ".data");
	        const auto textOpt = GetSectionRange(hMod, ".text");
            if (!textOpt) {
                return;
            }

            const auto scanOneRange = [&](const TextRange& dat) {
                for (uintptr_t va = dat.begin + 4; va + 4 <= dat.end; va += 4) {
                    CompleteObjectLocator colCopy{};
                    uintptr_t colVa = 0;
                    if (!TryGetValidCol(reinterpret_cast<void**>(va), colCopy, colVa)) {
                        continue;
                    }
                    IngestVftable(dc, va);
                }
                };

            if (rdataOpt) {
                scanOneRange(*rdataOpt);
            }
            if (dataOpt) {
                scanOneRange(*dataOpt);
            }
        }

        // --------------------------------------- Template awareness ----------------------------------
        struct TplKey {
            std::vector<std::string> ns;
            std::string name;
            bool operator==(const TplKey& o) const { return name == o.name && ns == o.ns; }
        };

        struct TplKeyHash {
            size_t operator()(const TplKey& k) const noexcept {
                size_t h = std::hash<std::string>{}(k.name);
                for (auto& s : k.ns) {
                    h ^= (std::hash<std::string>{}(s)+0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2));
                }
                return h;
            }
        };

        [[nodiscard]]
    	bool ParseTemplatePrimary(const std::string& pretty,
            std::vector<std::string>& nsParts,
            std::string& name,
            int& arity)
    	{
            nsParts.clear();
            name.clear();
            arity = 0;

            // Find top-level '<'
            size_t lt = std::string::npos;
            int depth = 0;
            for (size_t i = 0; i < pretty.size(); ++i) {
	            const char c = pretty[i];
                if (c == '<') {
                    if (depth == 0) {
                        lt = i;
                        break;
                    }
                    ++depth;
                } else if (c == '>') {
                    if (depth > 0) {
                        --depth;
                    }
                }
            }
            if (lt == std::string::npos) {
                return false;
            }

            const std::string head = pretty.substr(0, lt);
            SplitNamespaces(head, nsParts, name);
            if (name.empty()) {
                return false;
            }

            depth = 0;
            int count = 1;
            for (size_t i = lt + 1; i < pretty.size(); ++i) {
	            const char c = pretty[i];
                if (c == '<') {
                    ++depth;
                } else if (c == '>') {
                    if (depth == 0) {
                        arity = count;
                        return true;
                    }
                    --depth;
                } else if (c == ',' && depth == 0) {
                    ++count;
                }
            }
            return false;
        }

        void CollectTemplatePrimaries(
            const DumpContext& dc,
            std::unordered_map<TplKey, int, TplKeyHash>& out)
    	{
            auto consider = [&](const std::string& nm) {
                if (nm.empty()) {
                    return;
                }
                std::vector<std::string> ns;
                std::string shortName;
                int arity = 0;
                if (!ParseTemplatePrimary(nm, ns, shortName, arity)) {
                    return;
                }
                TplKey k{ ns, shortName };
                const auto it = out.find(k);
                if (it == out.end()) {
                    out.emplace(std::move(k), arity);
                } else if (arity > it->second) {
                    it->second = arity;
                }
            };

            for (const auto& val : dc.byTypeName | std::views::values) {
                const auto& [nameDecorated, name, hierarchyAttributes, bases, vtables] = val;
                consider(name);
                for (const auto& b : bases) {
                    consider(name.empty() ? DemangleDecorated(b.nameDecorated.c_str()) : name);
                }
            }
        }

        // --------------------------------------- Emission --------------------------------------------
        struct EmitPlan {
            std::unordered_set<std::string> emitDecorated; // whitelist of decorated names
            std::unordered_set<std::string> fwdDeclared;   // fully-qualified sanitized names already fwd-declared
        };

        [[nodiscard]]
    	bool ShouldEmitClass(const ClassInfo& c,
            const DumpOptions& opts,
            const EmitPlan& plan) {
            if (!opts.emitOnlyInputTypes) {
                return true;
            }
            return plan.emitDecorated.contains(c.nameDecorated);
        }

        [[nodiscard]]
    	std::string ChoosePrettyName(const ClassInfo& c) {
            if (!c.name.empty()) {
                return c.name;
            }
            auto basic = FromTypeDescriptorNameBasic(c.nameDecorated.c_str());
            if (!basic.empty()) {
                return basic;
            }
            return c.nameDecorated;
        }

        [[nodiscard]]
    	std::string QualifiedSanitized(
            const std::string& pretty,
            const bool lowerFirst)
    	{
            std::vector<std::string> ns;
            std::string shortName;
            SplitNamespaces(pretty, ns, shortName);
            std::vector<std::string> sns;
            SanitizeNsChain(ns, sns, lowerFirst);

            std::ostringstream oss;
            for (size_t i = 0; i < sns.size(); ++i) {
                if (i) {
                    oss << "::";
                }
                oss << sns[i];
            }
            if (!sns.empty()) {
                oss << "::";
            }
            oss << SanitizeIdentifierFlat(shortName, "Type");
            return oss.str();
        }

        void EmitForwardDecl(
            std::ostream& ofs,
            const std::string& pretty,
            const std::string& decorated,
            const DumpOptions& opts,
            EmitPlan& plan)
    	{
            std::vector<std::string> ns;
            std::string shortName;
            SplitNamespaces(pretty, ns, shortName);
            std::vector<std::string> sns;
            SanitizeNsChain(ns, sns, opts.lowerFirstNamespace);
            const std::string shortId = SanitizeIdentifierFlat(shortName, "Type");

            std::ostringstream fq;
            for (size_t i = 0; i < sns.size(); ++i) {
                if (i) {
                    fq << "::";
                }
                fq << sns[i];
            }

            if (!sns.empty()) {
                fq << "::";
            }

            fq << shortId;
            const std::string fqKey = fq.str();
            if (!plan.fwdDeclared.insert(fqKey).second) {
                return;
            }

            for (auto& seg : sns) {
                ofs << "namespace " << seg << " { ";
            }
            if (!sns.empty()) {
                ofs << "\n";
            }
            ofs << KeywordFromDecorated(decorated) << " " << shortId << ";\n";
            for (size_t i = 0; i < sns.size(); ++i) {
                ofs << "} ";
            }
            if (!sns.empty()) {
                ofs << "\n";
            }
        }

        /**
         * \brief Emit a single class stub with vtable slots and base classes (best-effort).
         */
        void EmitOneClass(
            std::ostream& ofs, 
            const ClassInfo& c,
            const DumpOptions& opts, 
            const EmitPlan& /*plan*/)
    	{
            if (opts.skipEmptyVftables) {
                bool hasSlots = false;
                for (const auto& [vftableVA, colOffset, slots] : c.vtables) {
                    if (!slots.empty()) {
                        hasSlots = true;
                        break;
                    }
                }
                if (!hasSlots) {
                    return;
                }
            }

            // ReSharper disable StringLiteralTypo
            ofs << "// " << (c.name.empty() ? c.nameDecorated : c.name) << "\n";
            ofs << "// Decorated: " << c.nameDecorated << "\n";
            ofs << "// HierarchyAttribs: 0x" << std::hex << c.hierarchyAttributes << std::dec
	            << " (1=MI,2=VI,4=Ambiguous)\n";

            for (const auto& b : c.bases) {
                ofs << "//   base: " << (b.name.empty() ? b.nameDecorated : b.name)
                    << "  mdisp=" << b.pmd.mdisp
                    << " pdisp=" << b.pmd.pdisp
                    << " vdisp=" << b.pmd.vdisp
                    << " attr=0x" << std::hex << b.attributes << std::dec << "\n";
            }

            for (const auto& vt : c.vtables) {
                ofs << "// vftable@" << Hex(vt.vftableVA)
                    << " subobjectOffset=" << vt.colOffset
                    << " slots=" << vt.slots.size() << "\n";
            }
            // ReSharper restore StringLiteralTypo

            const std::string pretty = ChoosePrettyName(c);

            // Derive namespace chain and/or flattened identifier
            std::vector<std::string> ns;
            std::string shortName;
            SplitNamespaces(pretty, ns, shortName);

            // Build base list
            auto makeBaseNameNested = [&](const std::string& nm) {
                return QualifiedSanitized(nm, opts.lowerFirstNamespace);
            };

            std::vector<std::string> bases;
            for (const auto& b : c.bases) {
                if (b.nameDecorated == c.nameDecorated) {
                    continue;
                }
                std::string nm = !b.name.empty() ? b.name : DemangleDecorated(b.nameDecorated.c_str());
                if (nm.empty()) {
                    nm = b.nameDecorated;
                }
                bases.push_back(makeBaseNameNested(nm));
            }

            if (opts.nsMode == NamespaceMode::kDeriveFromType && !opts.flattenNamespaces) {
                std::vector<std::string> sns;
                SanitizeNsChain(ns, sns, opts.lowerFirstNamespace);
                for (auto& seg : sns) {
                    ofs << "namespace " << seg << " { ";
                }
                if (!sns.empty()) {
                    ofs << "\n";
                }

                const std::string shortId = SanitizeIdentifierFlat(
                    shortName.empty() ? 
	                    pretty : 
	                    shortName,
                    "dec_" + SanitizeIdentifierFlat(c.nameDecorated, "unknown"));

                ofs << KeywordFromDecorated(c.nameDecorated) << " " << shortId;
                if (!bases.empty()) {
                    ofs << " : ";
                    for (size_t i = 0; i < bases.size(); ++i) {
                        if (i) {
                            ofs << ", ";
                        }
                        ofs << "public " << bases[i];
                    }
                }
                ofs << " {\n";

                const VTableInfo* primary = nullptr;
                for (const auto& vt : c.vtables) {
                    if (vt.colOffset == 0) {
                        primary = &vt;
                        break;
                    }
                }

                if (primary) {
                    ofs << "    // Primary vftable (" << primary->slots.size() << " entries)\n";
                    std::unordered_map<std::string, int> used;
                    for (size_t i = 0; i < primary->slots.size(); ++i) {
                        const uintptr_t fva = primary->slots[i];
                        std::string name;
                        if (opts.renameVirtualsWithSymbols) {
                            name = gSym.from_address(fva);
                            if (name.empty()) {
                                std::ostringstream tmp;
                                tmp << "sub_" << std::uppercase << std::hex << fva;
                                name = tmp.str();
                            }
                        } else {
                            std::ostringstream tmp;
                            tmp << "vf" << std::setw(2) << std::setfill('0') << i;
                            name = tmp.str();
                        }
                        std::string ident = SanitizeIdentifierFlat(name, "slot");
                        auto it = used.find(ident);
                        if (it == used.end()) {
                            used[ident] = 0;
                        } else {
                            ++it->second;
                            ident += "_" + std::to_string(it->second);
                        }
                        ofs << "    virtual void " << ident << "() = 0; // " << Hex(fva) << " (slot " << i << ")\n";
                    }
                }

                for (const auto& vt : c.vtables) {
                    if (&vt == primary) {
                        continue;
                    }
                    ofs << "    // Secondary vftable at subobject offset " << vt.colOffset
                        << " (" << vt.slots.size() << " entries)\n";
                    for (size_t i = 0; i < vt.slots.size(); ++i) {
                        ofs << "    /*virtual*/ void vf_sub" << vt.colOffset << "_"
                            << std::setw(2) << std::setfill('0') << i
                            << "(); // " << Hex(vt.slots[i]) << "\n";
                    }
                }

                ofs << "    // TODO: Unknown data fields. Size is unknown at runtime.\n";
                ofs << "    // uint8_t _pad[/* fill after measuring */];\n";
                ofs << "};\n";

                for (size_t i = 0; i < sns.size(); ++i) {
                    ofs << "} ";
                }
                if (!sns.empty()) {
                    ofs << "\n\n";
                }
                return;
            }

            // Flattened or fixed/none modes
            std::string idFlat = SanitizeIdentifierFlat(
                pretty, 
                "dec_" + SanitizeIdentifierFlat(c.nameDecorated, "unknown")
            );

            ofs << KeywordFromDecorated(c.nameDecorated) << " " << idFlat;
            if (!bases.empty()) {
                ofs << " : ";
                for (size_t i = 0; i < bases.size(); ++i) {
                    if (i) {
                        ofs << ", ";
                    }
                    ofs << "public " << bases[i];
                }
            }
            ofs << " {\n";

            const VTableInfo* primary = nullptr;
            for (const auto& vt : c.vtables) {
                if (vt.colOffset == 0) {
                    primary = &vt;
                    break;
                }
            }
            if (primary) {
                ofs << "    // Primary vftable (" << primary->slots.size() << " entries)\n";
                std::unordered_map<std::string, int> used;
                for (size_t i = 0; i < primary->slots.size(); ++i) {
                    const uintptr_t fva = primary->slots[i];
                    std::string name;
                    if (opts.renameVirtualsWithSymbols) {
                        name = gSym.from_address(fva);
                        if (name.empty()) {
                            std::ostringstream tmp;
                            tmp << "sub_" << std::uppercase << std::hex << fva;
                            name = tmp.str();
                        }
                    } else {
                        std::ostringstream tmp;
                        tmp << "vf" << std::setw(2) << std::setfill('0') << i;
                        name = tmp.str();
                    }
                    std::string ident = SanitizeIdentifierFlat(name, "slot");
                    auto it = used.find(ident);
                    if (it == used.end()) {
                        used[ident] = 0;
                    } else {
                        ++it->second;
                        ident += "_" + std::to_string(it->second);
                    }
                    ofs << "    virtual void " << ident << "() = 0; // " << Hex(fva) << " (slot " << i << ")\n";
                }
            }

            for (const auto& vt : c.vtables) {
                if (&vt == primary) {
                    continue;
                }

                ofs << "    // Secondary vftable at subobject offset " << vt.colOffset
                    << " (" << vt.slots.size() << " entries)\n";

                for (size_t i = 0; i < vt.slots.size(); ++i) {
                    ofs << "    /*virtual*/ void vf_sub" << vt.colOffset << "_"
                        << std::setw(2) << std::setfill('0') << i
                        << "(); // " << Hex(vt.slots[i]) << "\n";
                }
            }
            ofs << "    // TODO: Unknown data fields. Size is unknown at runtime.\n";
            ofs << "    // uint8_t _pad[/* fill after measuring */];\n";
            ofs << "};\n\n";
        }

        bool DumpAsCpp(
            const DumpContext& dc, 
            const EmitPlan& plan,
            const std::string& outPathStr, 
            const DumpOptions& opts)
    	{
            std::filesystem::path outPath(outPathStr);
            std::error_code ec;
            if (!outPath.parent_path().empty()) {
                create_directories(outPath.parent_path(), ec);
            }

            std::ofstream ofs(outPath, std::ios::binary);
            if (!ofs) {
                DebugLog("DumpAsCpp: failed to open file for write");
                return false;
            }

            ofs << "// Generated by moho_rtti_dump (MSVC x86)\n";
            ofs << "// NOTE: Field layout and non-virtual methods are unknown at runtime.\n\n";
            // ReSharper disable once StringLiteralTypo
            ofs << "#pragma once\n#include <cstdint>\n\n";

            const bool wrapFixed = (opts.nsMode == NamespaceMode::kFixed && !opts.fixedNamespace.empty());
            if (wrapFixed) {
                ofs << "namespace " << SanitizeIdentifierFlat(opts.fixedNamespace, "ns") << " {\n\n";
            }

            if (opts.emitTemplateStubs) {
                std::unordered_map<TplKey, int, TplKeyHash> templates;
                CollectTemplatePrimaries(dc, templates);
                for (auto& kv : templates) {
                    const TplKey& k = kv.first;
                    int arity = kv.second;
                    std::vector<std::string> sns;
                    SanitizeNsChain(k.ns, sns, opts.lowerFirstNamespace);
                    for (auto& seg : sns) {
                        ofs << "namespace " << seg << " { ";
                    }
                    if (!sns.empty()) {
                        ofs << "\n";
                    }
                    ofs << "template<";
                    for (int i = 0; i < arity; ++i) {
                        if (i) {
                            ofs << ", ";
                        }
                        ofs << "class T" << i;
                        if (i > 0) {
                            ofs << " = void";
                        }
                    }
                    ofs << "> struct " << SanitizeIdentifierFlat(k.name, "Tpl") << " {};\n";
                    for (size_t i = 0; i < sns.size(); ++i) {
                        ofs << "} ";
                    }
                    if (!sns.empty()) {
                        ofs << "\n\n";
                    }
                }
            }

            std::vector<const ClassInfo*> classes;
            classes.reserve(dc.byTypeName.size());
            for (const auto& val : dc.byTypeName | std::views::values) {
                classes.push_back(&val);
            }

            std::ranges::sort(
                classes,
                [](const ClassInfo* a, const ClassInfo* b) {
	                return a->name < b->name;
                });

            for (const ClassInfo* c : classes) {
                if (!ShouldEmitClass(*c, opts, plan)) {
                    continue;
                }
                if (opts.nsMode != NamespaceMode::kFixed && !opts.flattenNamespaces) {
                    // Emit forward-declarations for derived-from-type mode (avoid ordering problems).
                    const std::string pretty = ChoosePrettyName(*c);
                    const std::string& decorated = c->nameDecorated;
                    if (!pretty.empty() && !decorated.empty()) {
                        EmitForwardDecl(ofs, pretty, decorated, opts, const_cast<EmitPlan&>(plan));
                    }
                }
            }

            for (const ClassInfo* c : classes) {
                if (!ShouldEmitClass(*c, opts, plan)) {
                    continue;
                }
                EmitOneClass(ofs, *c, opts, plan);
            }

            if (wrapFixed) {
                ofs << "} // namespace " << SanitizeIdentifierFlat(opts.fixedNamespace, "ns") << "\n";
            }

            return true;
        }

        // --------------------------------------- Input parsing ---------------------------------------
        [[nodiscard]]
    	bool ParseAddressToken(std::string tok, uintptr_t& out) {
            if (tok.empty()) {
                return false;
            }
            // trim
            tok.erase(
                tok.begin(), 
                std::ranges::find_if(
	                tok,
	                [](const unsigned char c) {
		                return !std::isspace(c);
	                }));

            tok.erase(
                std::find_if(
                    tok.rbegin(), 
                    tok.rend(),
                    [](const unsigned char c) {
	                    return !std::isspace(c);
				}).base(), 
				tok.end());

            if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
                tok = tok.substr(2);
            }

            // hex first
            uintptr_t val = 0;
            auto res = std::from_chars(tok.data(), tok.data() + tok.size(), val, 16);
            if (res.ec == std::errc{} && res.ptr == tok.data() + tok.size()) {
                out = val;
                return true;
            }

            // decimal as fallback
            val = 0;
            res = std::from_chars(tok.data(), tok.data() + tok.size(), val, 10);
            if (res.ec == std::errc{} && res.ptr == tok.data() + tok.size()) {
                out = val;
                return true;
            }

            return false;
        }

    } // end anonymous namespace

    // ==============================================================================================
    // Public API
    // ==============================================================================================

    /**
     * \brief Set the DbgHelp symbol search path (used for naming virtuals from PDBs).
     */
    void SetSymbolSearchPath(const std::string& path) {
        gSym.set_search_path(path);
    }

    /**
     * \brief Utility: parse a text file into VTableEntry records.
     */
    bool ParseInputFile(
        const std::string& inputListPath,
        std::vector<VTableEntry>& outEntries)
	{
        outEntries.clear();
        std::ifstream ifs(inputListPath);
        if (!ifs) {
            return false;
        }

        std::string line;
        std::regex comment(R"(^\s*(?:#|//|-).*$)");
        std::regex rx(R"(^\s*([^\s].*?)\s+(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s*$)");

        while (std::getline(ifs, line)) {
            if (line.empty() || std::regex_match(line, comment)) {
                continue;
            }

            std::smatch m;
            if (!std::regex_match(line, m, rx)) {
                // Try splitting by whitespace, pick last token as address
                std::istringstream iss(line);
                std::vector<std::string> tokes;
                std::string t;
                while (iss >> t) {
                    tokes.push_back(t);
                }
                if (tokes.size() < 2) {
                    continue;
                }
                uintptr_t address = 0;
                if (!ParseAddressToken(tokes.back(), address)) {
                    continue;
                }
                std::string name;
                for (size_t i = 0; i + 1 < tokes.size(); ++i) {
                    if (i) {
                        name.push_back(' ');
                    }
                    name += tokes[i];
                }
                outEntries.push_back(VTableEntry{ name, address });
                continue;
            }

            const std::string name = m[1].str();
            const std::string addressToken = m[2].str();
            uintptr_t address = 0;
            if (!ParseAddressToken(addressToken, address)) {
                continue;
            }
            outEntries.push_back(VTableEntry{ name, address });
        }
        return true;
    }

    /**
     * \brief Dump RTTI/vftables for the provided entries into a C++ header file.
     */
    bool DumpRtti(
        const std::vector<VTableEntry>& entries,
        const std::string& outHeaderPath)
	{
	    const DumpOptions opts{};
        return DumpRttiEx(entries, outHeaderPath, opts);
    }

    /**
     * \brief Extended variant with options.
     */
    bool DumpRttiEx(
        const std::vector<VTableEntry>& entries,
        const std::string& outHeaderPath,
        const DumpOptions& opts)
	{
        DumpContext dc;
        EmitPlan plan;

        // Record the set of names we explicitly want to emit (if requested).
        if (opts.emitOnlyInputTypes) {
            for (auto& e : entries) {
                (void)e;
                // We'll populate this set after we ingest vtables and know the decorated names.
            }
        }

        // Ingest provided entries
        for (const auto& e : entries) {
            IngestVftable(dc, e.vftableVa);
        }

        // If we emit-only, compute the decorated names whitelist now.
        if (opts.emitOnlyInputTypes) {
            for (const auto& val : dc.vftToDecorated | std::views::values) {
                plan.emitDecorated.insert(val);
            }
        }

        return DumpAsCpp(dc, plan, outHeaderPath, opts);
    }

    /**
     * \brief Parse a text file with a vftable list and run the dump.
     */
    bool DumpRttiFromFile(
        const std::string& inputListPath,
        const std::string& outHeaderPath)
	{
        std::vector<VTableEntry> entries;
        if (!ParseInputFile(inputListPath, entries)) {
            return false;
        }
        return DumpRtti(entries, outHeaderPath);
    }

    /**
     * \brief Parse multiple files and dump (union of all entries).
     */
    bool DumpRttiFromFiles(
        const std::vector<std::string>& inputListPaths,
        const std::string& outHeaderPath,
        const DumpOptions& opts)
	{
        std::vector<VTableEntry> entries;
        for (const auto& p : inputListPaths) {
            std::vector<VTableEntry> chunk;
            if (!ParseInputFile(p, chunk)) {
                continue;
            }
            entries.insert(entries.end(), chunk.begin(), chunk.end());
        }
        return DumpRttiEx(entries, outHeaderPath, opts);
    }

    /**
     * \brief Scan all loaded modules and dump every valid vftable/type that can be found.
     */
    bool DumpAllRtti(const std::string& outHeaderPath, const DumpOptions& optsIn) {
        DumpOptions opts = optsIn;
        opts.emitOnlyInputTypes = false; // force full emission

        DumpContext dc;
        EmitPlan plan;

        auto mods = EnumerateModules(opts.excludeSystemModules);
        if (opts.parallelScan) {
            const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
            const unsigned T = (opts.scanThreads ? opts.scanThreads : hw);

            std::atomic<size_t> idx{ 0 };
            std::vector<std::thread> th;
            th.reserve(T);
            for (unsigned t = 0; t < T; ++t) {
                th.emplace_back([&]() {
                    for (;;) {
	                    const size_t i = idx.fetch_add(1, std::memory_order_relaxed);
                        if (i >= mods.size()) {
                            break;
                        }
                        ScanModuleForVftables(mods[i], dc);
                    }
                    });
            }
            for (auto& thd : th) {
                thd.join();
            }
        } else {
            for (HMODULE m : mods) {
                ScanModuleForVftables(m, dc);
            }
        }

        return DumpAsCpp(dc, plan, outHeaderPath, opts);
    }

} // namespace moho_rtti
