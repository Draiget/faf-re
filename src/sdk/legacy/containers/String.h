#pragma once

#include <cstdint>
#include <ostream>
#include <ios>

namespace msvc8
{
#pragma pack(push, 4)
    struct string
	{
        void* alVal; // allocator cookie / impl detail (unused for reading)

        union Bx {
            char* ptr;    // heap pointer when not in SSO
            char  buf[16];// SSO buffer (15 chars + NUL)
        } bx;

        uint32_t mySize; // length (not including NUL)
        uint32_t myRes;  // capacity (not including NUL); 15 in SSO

        static constexpr std::size_t maxCapGuard = (1u << 30);

        /**
         * Default ctor - empty SSO string.
         */
        string() noexcept : bx() {
            alVal = nullptr;
            bx.buf[0] = '\0';
            mySize = 0;
            myRes = 15;
        }

        /**
         * From C-string: SSO copy if fits.
         * If not, adopt pointer without ownership (no growth).
         */
        explicit string(const char* s) noexcept;

        /**
         * From string_view: same policy as above (SSO copy if fits, else adopt pointer).
         */
        explicit string(std::string_view sv) noexcept;

        /**
         * From pointer + length.
		 * SSO copy if fits (≤15), otherwise adopt external buffer
		 * (no ownership, no guaranteed trailing NUL).
         */
        explicit string(const char* p, std::size_t n) noexcept;

        /** From [first, last) pointer range. */
        explicit string(const char* first, const char* last) noexcept
            : string(first, (first&& last&& last >= first) ? 
                static_cast<std::size_t>(last - first) : 
                0u) {
        }

        /**
         * Read-only pointer to character data (unsafe if the struct is invalid).
         * Use data_view() / try_view() helpers instead where possible.
         */
        [[nodiscard]]
    	const char* raw_data_unsafe() const noexcept {
            // In MSVC8, SSO is indicated by myRes <= 15.
            return (myRes <= 15) ? bx.buf : bx.ptr;
        }

        /**
         * Mutable pointer to character data (unsafe if the struct is invalid).
         */
        [[nodiscard]]
    	char* raw_data_mut_unsafe() noexcept {
            return (myRes <= 15) ? bx.buf : bx.ptr;
        }

        /**
         * SSO predicate.
         */
        [[nodiscard]]
    	bool is_sso() const noexcept {
	        return myRes <= 15;
        }

        /**
         * Conservative sanity checks to avoid wild reads.
         */
        [[nodiscard]]
    	bool basic_sanity() const noexcept;

        // ReSharper disable once IdentifierTypo
        static constexpr std::size_t npos = static_cast<std::size_t>(-1);

        /**
         * size() - number of characters, excluding NULL
         */
        [[nodiscard]]
    	std::size_t size() const noexcept { return mySize; }

        /**
         * capacity() - maximum storable chars without reallocation
         */
        [[nodiscard]]
    	std::size_t capacity() const noexcept { return myRes; }

        /**
         * empty() - true if size() == 0
         */
        [[nodiscard]]
    	bool empty() const noexcept { return mySize == 0; }

        /**
         * data() / c_str() - pointer to char buffer (always NULL-terminated)
         */
        [[nodiscard]]
    	const char* data() const noexcept {
            return basic_sanity() ? raw_data_unsafe() : "";
        }

        [[nodiscard]]
    	const char* c_str() const noexcept {
	        return data();
        }

        /**
         * view() - lightweight std::string_view over the buffer
         */
        [[nodiscard]]
    	std::string_view view() const noexcept {
            return { data(), size() };
        }

        /**
         * clear() - in-place: sets size to 0 and writes terminal NULL
         */
        void clear() noexcept {
            if (!basic_sanity()) {
                return;
            }
            raw_data_mut_unsafe()[0] = '\0';
            mySize = 0;
        }

        /**
         * resize(newSize, ch) - in-place only; returns false if not enough capacity
         */
        bool resize(std::size_t newSize, char ch = '\0') noexcept;

        /**
         * append(ptr,len) - in-place only; returns false if not enough capacity
         */
        bool append(const char* s, std::size_t n) noexcept;

        /**
         * append(string_view) - in-place only
         */
        bool append(const std::string_view sv) noexcept {
	        return append(sv.data(), sv.size());
        }

        /**
         * append(count, ch) - in-place only; returns false if not enough capacity
         */
        bool append(std::size_t count, char ch) noexcept;

        /**
         * push_back - in-place only
         */
        bool push_back(const char ch) noexcept {
	        return append(&ch, 1);
        }

        /**
         * reverse() - in-place characters reversal, keeps trailing NUL intact
         */
        void reverse() noexcept;

        /**
         * try-reserve: check-only, no reallocation.
         * Returns true if capacity() already >= newCap.
         */
    	void reserve(std::size_t newCap) const noexcept;

        /**
         * find(char, pos) - naive scan; returns npos if not found
         */
        [[nodiscard]]
    	std::size_t find(char ch, std::size_t pos = 0) const noexcept;

        /**
         * find(substr, pos) - naive search; returns npos if not found
         */
        [[nodiscard]]
    	std::size_t find(std::string_view needle, std::size_t pos = 0) const noexcept;

        /**
         * find(const char* s, size_t pos, size_t n) - MSVC-compatible overload.
         * Interprets `s[0 .. n-1]` as the needle. 
         * @return `npos` if not found.
         */
        [[nodiscard]]
        std::size_t find(const char* s, std::size_t pos, std::size_t n) const noexcept;

        /**
         * replace(pos, count, repl) - in-place only.
         * Replaces range [pos, pos+count) with repl;
         * returns false if size would exceed capacity.
         */
        bool replace(std::size_t pos, std::size_t count, std::string_view repl) noexcept;

        /**
         * assign_inplace(src) - overwrite with src if it fits; returns false otherwise
         */
        bool assign_inplace(std::string_view src) noexcept;

        /**
         * operator[] - unchecked access (like MSVC of that era in Release)
         */
        char& operator[](const std::size_t i) noexcept {
	        return raw_data_mut_unsafe()[i];
        }
        const char& operator[](const std::size_t i) const noexcept {
	        return raw_data_unsafe()[i];
        }
        /**
         * Assign from C-string; in-place if it fits, otherwise adopt pointer (non-owning).
         */
        string& operator=(const char* s) noexcept;

        /**
         * Implicit view conversion so that std::string can assign/append from us safely.
         */
        explicit operator std::string_view() const noexcept {
	        return view();
        }

        /**
         * to_std() - copies content into std::string (owned, safe to grow)
         */
        [[nodiscard]]
    	std::string to_std() const {
            return { data(), size() };
        }

        /**
         * Factory to adopt an external mutable buffer with explicit capacity (no ownership).
         */
        static string adopt(char* buf, uint32_t len, uint32_t cap) noexcept;

        /**
         * Assign from a substring of another msvc8::string.
         * Semantics modeled after MSVC8 std::string::assign(str, pos, count).
         *
         * Differences vs original MSVC8:
         *  - No dynamic reallocation is performed (this wrapper is in-place only).
         *  - If requested substring length exceeds capacity(), content is truncated to capacity().
         *
         * @param other Source string.
         * @param pos   Starting position in source (clamped to other.size()).
         * @param count Number of characters to copy; npos means "to the end".
         * @return *this
         */
        string& assign(const string& other, std::size_t pos, std::size_t count = npos) noexcept;

        /**
		 * Return substring [from .. from+maxLen) as a new msvc8::string.
		 * - If length fits SSO (<=15) OR source is SSO, we make an SSO copy.
		 * - Otherwise (heap case with long slice), we adopt a pointer into the
		 *   original buffer without taking ownership (no guaranteed trailing NUL).
		 *
		 * @param from   Start position (clamped: if >= size() -> empty string).
		 * @param maxLen Max number of chars; npos means "to the end".
		 * @return New msvc8::string instance (copy or non-owning view).
		 */
        [[nodiscard]]
        string substr(const std::size_t from, const std::size_t maxLen = npos) const noexcept {
            // Invalid source -> empty
            if (!basic_sanity()) {
                return string{};
            }

            // Clamp 'from' to size; if out of range -> empty
            if (from >= mySize) {
                return string{};
            }

            const std::size_t tail = static_cast<std::size_t>(mySize) - from;
            const std::size_t len = (maxLen == npos || maxLen > tail) ? tail : maxLen;

            // Fast empty
            if (len == 0) {
                return string{};
            }

            const char* src = raw_data_unsafe() + from;

            // If source is SSO, mySize <= 15, so len <= 15 -> SSO copy is guaranteed.
            // If heap and len <= 15, also prefer SSO copy to keep c_str() well-terminated.
            if (is_sso() || len <= 15) {
                return string(src, len); // our (ptr, len) ctor will SSO-copy when len<=15
            }

            // Heap + long slice: adopt pointer into existing buffer (non-owning).
            // Capacity from this slice forward is (myRes - from), clamp to maxCapGuard.
            const uint32_t capForward = (myRes > from)
                ? myRes - from
                : 0u;

            const uint32_t effCap = (capForward > maxCapGuard)
                ? static_cast<uint32_t>(maxCapGuard)
                : capForward;

            // Cast away const: we don't mutate, but adopt() expects mutable char*.
            return adopt(const_cast<char*>(src),
                static_cast<uint32_t>(len),
                effCap);
        }

        /** Compare with another msvc8::string. */
        friend bool operator==(const string& a, const string& b) noexcept {
            const bool as = a.basic_sanity();
            const bool bs = b.basic_sanity();
            const char* ad = as ? a.raw_data_unsafe() : "";
            const char* bd = bs ? b.raw_data_unsafe() : "";
            const std::size_t an = as ? a.mySize : 0u;
            const std::size_t bn = bs ? b.mySize : 0u;
            return eq_buf_(ad, an, bd, bn);
        }

        /** Compare with std::string_view (RHS). */
        friend bool operator==(const string& a, const std::string_view b) noexcept {
            const bool as = a.basic_sanity();
            const char* ad = as ? a.raw_data_unsafe() : "";
            const std::size_t an = as ? a.mySize : 0u;
            return eq_buf_(ad, an, b.data(), b.size());
        }

        /** Compare with std::string_view (LHS). */
        friend bool operator==(const std::string_view a, const string& b) noexcept {
            return b == a;
        }

        /** Compare with C-string (RHS). Treats nullptr as empty. */
        friend bool operator==(const string& a, const char* b) noexcept {
            if (!b) return a.empty();
            const bool as = a.basic_sanity();
            const char* ad = as ? a.raw_data_unsafe() : "";
            const std::size_t an = as ? a.mySize : 0u;
            const std::size_t bn = std::char_traits<char>::length(b);
            return eq_buf_(ad, an, b, bn);
        }

        /** Compare with C-string (LHS). */
        friend bool operator==(const char* a, const string& b) noexcept {
            return b == a;
        }

        /** string + string */
        [[nodiscard]] string operator+(const string& rhs) const noexcept;

        /** string + std::string_view */
        [[nodiscard]] string operator+(std::string_view rhs) const noexcept;

        /** string + C-string */
        [[nodiscard]] string operator+(const char* rhs) const noexcept;

        /** operator+= via concat */
        string& operator+=(const string& rhs) noexcept {
            *this = (*this + rhs);
            return *this;
        }
    private:
        static bool eq_buf_(
            const char* a,
            const std::size_t an,
            const char* b,
            const std::size_t bn
        ) noexcept {
            if (an != bn) return false;
            if (an == 0)  return true;
            return std::memcmp(a, b, an) == 0;
        }

        /** Build msvc8::string from two views: SSO when possible, else adopt TLS buffer. */
        static string concat_impl_(std::string_view a, std::string_view b) noexcept;
    };
#pragma pack(pop)
    static_assert(sizeof(string) == 28, "MSVC8 string must be 28 bytes on x86");


    /** std::string_view + msvc8::string */
    [[nodiscard]] inline string operator+(std::string_view lhs, const string& rhs) noexcept;

    /** const char* + msvc8::string */
    [[nodiscard]] inline string operator+(const char* lhs, const string& rhs) noexcept;

    namespace detail {

        /** Thread-local arena for non-SSO concatenation results. */
        struct TlsConcatArena {
            static constexpr std::size_t kSlots = 4;
            struct Slot { char* p; std::size_t cap; };
            Slot slots[kSlots];
            std::size_t idx;
            TlsConcatArena() : slots{ {nullptr,0},{nullptr,0},{nullptr,0},{nullptr,0} }, idx(0) {}
            ~TlsConcatArena() { for (auto& s : slots) delete[] s.p; }

            char* acquire(const std::size_t need, std::size_t& outCap) {
                idx = (idx + 1) % kSlots;
                auto& s = slots[idx];
                if (s.cap < need) {
                    delete[] s.p;
                    s.cap = std::max<std::size_t>(need, 64);
                    s.p = new char[s.cap];
                }
                outCap = s.cap;
                return s.p;
            }
        };

        inline std::pair<char*, uint32_t> get_concat_buffer(const std::size_t needBytes) {
            thread_local TlsConcatArena arena;
            std::size_t cap{};
            char* p = arena.acquire(needBytes, cap);
            return { p, static_cast<uint32_t>(cap) };
        }

        /** Safe view helper (treat insane as empty). */
        inline std::string_view as_view(const string& s) noexcept {
            return s.basic_sanity() ? std::string_view{ s.raw_data_unsafe(), s.size() } : std::string_view{};
        }

        /** Core concatenation: SSO if total ≤ 15, else adopt TLS buffer. */
        inline string concat_impl(const std::string_view a, const std::string_view b) noexcept {
            const std::size_t total = a.size() + b.size();

            // SSO fast path
            if (total <= 15) {
                string out;
                (void)out.append(a.data(), a.size());
                (void)out.append(b.data(), b.size());
                return out;
            }

            // TLS buffer + adopt
            auto [buf, cap] = get_concat_buffer(total + 1 /* NUL */);
            if (!a.empty()) std::memcpy(buf, a.data(), a.size());
            if (!b.empty()) std::memcpy(buf + a.size(), b.data(), b.size());
            buf[total] = '\0';

            const uint32_t effCap = (cap > 0) ? static_cast<uint32_t>(cap - 1) : 0u; // capacity excludes NUL
            return string::adopt(buf, static_cast<uint32_t>(total), effCap);
        }

    } // namespace detail

    // A safe, read-only facade with ergonomic operators.
    class StringRef {
    public:
        // Construct from a mapped legacy object.
        explicit StringRef(const string& s) noexcept : s_(&s) {}

        // Observers
        [[nodiscard]] const char* data() const noexcept {
            // NOTE: For pure RE inside same address space this is fine.
            // If your source can be invalid, consider asserting here.
            return s_->raw_data_unsafe();
        }

        [[nodiscard]] uint32_t size() const noexcept { return s_->mySize; }
        [[nodiscard]] bool empty() const noexcept { return size() == 0; }
        [[nodiscard]] bool valid() const noexcept { return s_ && s_->basic_sanity(); }

        // Iteration (so you can use ranges/algorithms)
        [[nodiscard]] const char* begin() const noexcept { return data(); }
        [[nodiscard]] const char* end()   const noexcept { return data() + size(); }

        // Conversions - keep them explicit to avoid surprise lifetime bugs.
        // Returns a non-owning view pointing into the target string memory.
        explicit operator std::string_view() const noexcept {
            // In debug you may add: assert(valid());
            return { data(), size() };
        }

        // Owning copy to std::string
        explicit operator std::string() const {
            return { data(), size() };
        }

        // Comparisons (C++20). We delegate to std::string_view logic.
        friend bool operator==(const StringRef& a, const std::string_view b) noexcept {
            return std::string_view(a) == b;
        }
        friend std::strong_ordering operator<=>(const StringRef& a, const std::string_view b) noexcept {
            return std::string_view(a) <=> b;
        }

        // Extra overloads for convenience
        friend bool operator==(const StringRef& a, const char* b) noexcept {
            return std::string_view(a) == std::string_view(b ? b : "");
        }
        friend bool operator==(const char* a, const StringRef& b) noexcept { return b == a; }

        // Stream print
        friend std::ostream& operator<<(std::ostream& os, const StringRef& r) {
            return os.write(r.data(), r.size());
        }

    private:
        const string* s_;
    };
}
