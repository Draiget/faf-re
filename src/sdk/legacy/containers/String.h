#pragma once

#include <cstdint>
#include <ostream>
#include <ios>

namespace msvc8
{
    /**
     * Address: 0x00ABF013 (FUN_00ABF013)
     * Mangled: ?_Xlen@_String_base@std@@SAXXZ
     *
     * IDA signature:
     * void __cdecl __noreturn std::_String_base::_Xlen(void);
     *
     * What it does:
     * Dinkumware's shared (non-templated) "requested string length is not
     * representable" helper - throws std::length_error("string too long")
     * and never returns. In the binary it is called from every
     * basic_string<char>/basic_string<wchar_t> growth path: std::string::assign
     * (0x004056FE), std::string::append (0x00405829, 0x00405840), insert,
     * replace, and the wstring equivalents (18 call sites total, decoded from
     * the raw E8 bytes; see FUN_00ABF013.xrefs.txt). Those STL-internal bodies
     * are tracked `skip` in recovered_progress.json (generic Dinkumware
     * library code, not FA engine logic); `msvc8::string::assign_owned_strong`
     * is this project's higher-level stand-in for their length guard, so that
     * is where this is wired.
     */
    [[noreturn]] void ThrowStringTooLong();

    /**
     * Address: 0x00ABF052 (FUN_00ABF052)
     *
     * IDA signature:
     * void __cdecl __noreturn std::_String_base::_Xran(void);
     *
     * What it does:
     * Dinkumware's shared (non-templated) "position/offset argument out of
     * range" helper - throws std::out_of_range("invalid string position") and
     * never returns. In the binary it is called from std::string::assign
     * (0x004056C3), std::string::append (0x00405803), erase, insert, replace,
     * and the wstring equivalents (12 call sites total, decoded from the raw
     * E8 bytes; see FUN_00ABF052.xrefs.txt). `msvc8::string::assign(other,
     * pos, count)` already models FUN_004056B0 (std::string::assign)
     * including its pos-vs-size check, so this is wired there.
     */
    [[noreturn]] void ThrowInvalidStringPosition();

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
         * Copy semantics, as MSVC8's basic_string has them: each string owns
         * its own buffer.
         *
         * These have to exist now that the converting constructors and the
         * grow path allocate. The implicit shallow copy left two strings
         * pointing at one heap block, and any `tidy` on either - which
         * assign_owned, resize, append and reserve all perform - freed it out
         * from under the other. It showed up as a technique name read back as
         * the contents of an unrelated local: the D3D9 effect loader's
         * `msvc8::vector<msvc8::string>` grew, relocated its elements
         * shallowly, released the originals, and the allocator handed the same
         * block to the next `msvc8::string` built in the loop.
         *
         * Each copy therefore owns a buffer that has to be released again, which
         * is what the destructor below does.
         */
        string(const string& other) noexcept;
        string& operator=(const string& other) noexcept;

        /**
         * Releases the heap buffer, exactly as MSVC8's `~basic_string` does via
         * `_Tidy(true)`.
         *
         * This was deliberately absent for a long time, on the reasoning that
         * nothing in the reconstruction freed a string on scope exit yet and
         * that adding it was a separate, wider change. The cost of leaving it
         * out turned out to be the whole engine: measured against retail on
         * SCMP_009 at the same point in the load, `gpg`'s allocator reported
         * 632.4 MB in use here against retail's 293.3 MB -- 2.16x -- and the
         * allocator's own free-region commit lane (`AllocateFreeRegion`,
         * 0x00958660) discards `VirtualAlloc`'s return value, faithfully to the
         * binary (verified at 0x009586F6 and 0x00958738). Once the process runs
         * far enough ahead of retail's footprint for a commit to fail, that lane
         * hands back a pointer into reserved-but-uncommitted address space and
         * the next store through it faults. Two separate runs died that way, in
         * unrelated places -- `_Alloc_proxy` and `luaH_getstr` -- both reading a
         * `MEM_RESERVE`/`PAGE_NOACCESS` page inside the allocator's own
         * reservation.
         *
         * The large multiplier comes from the containers rather than from
         * scattered locals: `msvc8::vector<T>` guards its element teardown with
         * `if constexpr (!std::is_trivially_destructible_v<T>)`, so while this
         * type stayed trivially destructible every `msvc8::vector<msvc8::string>`
         * released its own block and leaked every element's.
         *
         * `tidy(true, 0)` is the already-recovered lane (0x008846B0 and friends)
         * and leaves the object a valid empty inline string, so running it again
         * -- `scoped_string`'s destructor does, before this base destructor -- is
         * a no-op rather than a double free.
         */
        /**
         * STATUS: the body is currently a no-op. See String.cpp.
         *
         * Freeing here is the correct recovery and its effect was measured --
         * allocator in-use on SCMP_009 went from 632.4 MB to 243.8 MB, below
         * retail's 293.3 MB. But it also makes freed blocks actually recycle,
         * which turned a latent double free into a hard crash: the lobby's
         * `SNetCommandArg` copy faults inside `assign_owned`'s memcpy on a
         * string whose `bx.ptr` is dangling but whose header still passes
         * `basic_sanity()`.
         *
         * The destructor is kept declared, so the type stays
         * non-trivially-destructible and every container keeps running element
         * teardown -- reverting that too would silently change which branch
         * `msvc8::vector`'s `if constexpr (!is_trivially_destructible_v<T>)`
         * guards take, and mask the bug rather than park it.
         *
         * Restore the `tidy(true, 0U);` call once the double free is found.
         */
        ~string() noexcept;

        /**
         * Move semantics: transfer the buffer and leave the source an empty
         * inline string, so ownership stays single and nothing is copied.
         *
         * MSVC8's basic_string had no move operations - it did not need them,
         * because its destructor freed whatever a relocation displaced. Before
         * these existed every `std::move` fell back on the copy assignment: it
         * allocated a fresh buffer for the copy and abandoned the one it
         * displaced.
         *
         * `msvc8::vector::erase` moves the whole tail down one slot per erased
         * element. With the log window's committed history at tens of thousands
         * of lines, one capped log write leaked that many blocks, and a busy
         * logging window exhausted the heap - `assign_owned` then memcpy'd
         * through a failed allocation.
         */
        string(string&& other) noexcept;
        string& operator=(string&& other) noexcept;

        /**
         * From C-string: copies, as MSVC8's own converting ctor does. Input of
         * 15 characters or fewer lands in the inline buffer, longer input gets
         * its own heap block.
         */
        string(const char* s) noexcept;

        /**
         * From string_view: same copying policy as above.
         */
        explicit string(std::string_view sv) noexcept;

        /**
         * From pointer + length: same copying policy as above, always NUL
         * terminated.
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
         *
         * Address: 0x00402790 (FUN_00402790, std::string::c_str lane)
         * Address: 0x00442A60 (FUN_00442A60)
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
	        return raw_data_unsafe();
        }

        /**
         * view() - lightweight std::string_view over the buffer
         */
        [[nodiscard]]
    	std::string_view view() const noexcept {
            return { data(), size() };
        }

        /**
         * Case-insensitive ASCII equality against a string view.
         */
        [[nodiscard]]
        bool equals_no_case(std::string_view rhs) const noexcept;

        /**
         * Case-insensitive ASCII equality against a C-string (nullptr => empty).
         */
        [[nodiscard]]
        bool equals_no_case(const char* rhs) const noexcept {
            return equals_no_case(std::string_view(rhs ? rhs : ""));
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
         * VC8 xstring-style end-of-string helper (`_Eos` equivalent).
         * Writes terminal NUL at `newSize` and updates `mySize`.
         */
        void eos(uint32_t newSize = 0U) noexcept;

        /**
         * VC8 xstring-style storage reset helper (`_Tidy` equivalent).
         * If `built` is true and the string is in heap mode, releases the heap buffer.
         *
         * Address: 0x00402740 (FUN_00402740)
         */
        void tidy(bool built = true, uint32_t newSize = 0U) noexcept;

        /**
         * Owning assignment helper for recovered paths that require VC8-like
         * "copy into owned storage" semantics.
         */
        void assign_owned(std::string_view value);
        void assign_owned(const char* value);

        /**
         * Strong-guarantee owning assignment for recovered MSVC8 paths whose
         * original `basic_string::assign` allocates before releasing the old
         * buffer and propagates allocation/length failures.
         *
         * The length guard is std::_String_base::_Xlen (0x00ABF013): see
         * ThrowStringTooLong().
         */
        void assign_owned_strong(std::string_view value);
        void assign_owned_strong(const char* value);

        /**
         * Grows capacity to hold at least `need` characters, reallocating when
         * the current buffer is too small. Mirrors MSVC8's
         * `basic_string::_Copy`: the request is rounded up with `| 15`, and a
         * request that would grow by less than half is bumped to 1.5x so
         * repeated appends stay amortised. Returns false only on an absurd
         * request or a broken object.
         */
        bool ensure_capacity(std::size_t need) noexcept;

        /**
         * resize(newSize, ch) - grows the buffer when needed.
         */
        bool resize(std::size_t newSize, char ch = '\0') noexcept;

        /**
         * append(ptr,len) - grows the buffer when needed.
         */
        bool append(const char* s, std::size_t n) noexcept;

        /**
         * append(string_view)
         */
        bool append(const std::string_view sv) noexcept {
	        return append(sv.data(), sv.size());
        }

        /**
         * append(count, ch) - grows the buffer when needed.
         */
        bool append(std::size_t count, char ch) noexcept;

        /**
         * push_back
         */
        bool push_back(const char ch) noexcept {
	        return append(&ch, 1);
        }

        /**
         * reverse() - in-place characters reversal, keeps trailing NUL intact
         */
        void reverse() noexcept;

        /**
         * reserve(newCap) - grows the buffer to hold at least `newCap`
         * characters. Never shrinks, matching MSVC8.
         */
    	void reserve(std::size_t newCap) noexcept;

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
         * Semantics modeled after MSVC8 std::string::assign(str, pos, count)
         * (FUN_004056B0), including its out-of-range behavior.
         *
         * Differences vs original MSVC8:
         *  - If requested substring length exceeds capacity(), content is truncated to capacity()
         *    instead of reallocating without bound.
         *
         * @param other Source string.
         * @param pos   Starting position in source.
         * @param count Number of characters to copy; npos means "to the end".
         * @return *this
         * @throws std::out_of_range via ThrowInvalidStringPosition() (the
         *         std::_String_base::_Xran equivalent, 0x00ABF052) if
         *         pos > other.size().
         */
        string& assign(const string& other, std::size_t pos, std::size_t count = npos);
        string& assign(std::size_t count, char ch) noexcept {
            clear();
            (void)append(count, ch);
            return *this;
        }
        string& assign(const char* s) noexcept {
            return (*this = s);
        }

        /**
         * Address: 0x004422C0 (FUN_004422C0)
         * Address: 0x00445FD0 (FUN_00445FD0)
         *
         * What it does:
         * Resets this string to empty SSO state and assigns full contents from
         * another string.
         */
        string& reset_and_assign(const string& other) noexcept;

        string& assign(const char* data, std::size_t size) noexcept;

        string& erase(const std::size_t pos = 0, const std::size_t count = npos) noexcept {
            if (!basic_sanity() || pos >= mySize) {
                return *this;
            }

            const std::size_t available = static_cast<std::size_t>(mySize) - pos;
            const std::size_t removeCount = (count == npos || count > available) ? available : count;
            if (removeCount == 0) {
                return *this;
            }

            char* const dst = raw_data_mut_unsafe();
            const std::size_t tailCount = available - removeCount;
            if (tailCount != 0) {
                std::memmove(dst + pos, dst + pos + removeCount, tailCount);
            }
            mySize = static_cast<uint32_t>(static_cast<std::size_t>(mySize) - removeCount);
            dst[mySize] = '\0';
            return *this;
        }

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

        [[nodiscard]] int compare(std::string_view rhs) const noexcept {
            const std::string_view lhs = view();
            const std::size_t shared = lhs.size() < rhs.size() ? lhs.size() : rhs.size();
            const int cmp = shared == 0 ? 0 : std::memcmp(lhs.data(), rhs.data(), shared);
            if (cmp != 0) {
                return cmp;
            }
            if (lhs.size() < rhs.size()) {
                return -1;
            }
            if (lhs.size() > rhs.size()) {
                return 1;
            }
            return 0;
        }

        [[nodiscard]] int compare(const char* rhs) const noexcept {
            return compare(std::string_view(rhs ? rhs : ""));
        }

        [[nodiscard]] int compare(
            const std::size_t pos,
            const std::size_t count,
            const std::string_view rhs
        ) const noexcept {
            const std::string_view lhs = view();
            const std::size_t clampedPos = pos > lhs.size() ? lhs.size() : pos;
            const std::size_t lhsTail = lhs.size() - clampedPos;
            const std::size_t lhsCount = (count == npos || count > lhsTail) ? lhsTail : count;
            const std::string_view lhsSlice(lhs.data() + clampedPos, lhsCount);

            const std::size_t shared = lhsSlice.size() < rhs.size() ? lhsSlice.size() : rhs.size();
            const int cmp = shared == 0 ? 0 : std::memcmp(lhsSlice.data(), rhs.data(), shared);
            if (cmp != 0) {
                return cmp;
            }
            if (lhsSlice.size() < rhs.size()) {
                return -1;
            }
            if (lhsSlice.size() > rhs.size()) {
                return 1;
            }
            return 0;
        }

        [[nodiscard]] int compare(
            const std::size_t pos,
            const std::size_t count,
            const char* rhs,
            const std::size_t rhsCount
        ) const noexcept {
            if (rhs == nullptr) {
                return compare(pos, count, std::string_view());
            }
            return compare(pos, count, std::string_view(rhs, rhsCount));
        }

        [[nodiscard]] bool operator<(const string& rhs) const noexcept {
            return compare(rhs.view()) < 0;
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
        static unsigned char ascii_tolower_(unsigned char ch) noexcept {
            return (ch >= static_cast<unsigned char>('A') && ch <= static_cast<unsigned char>('Z'))
                ? static_cast<unsigned char>(ch - static_cast<unsigned char>('A') + static_cast<unsigned char>('a'))
                : ch;
        }

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

#pragma pack(push, 4)
    /**
     * Scope-owning form of the legacy string layout.
     *
     * The ABI-facing `msvc8::string` intentionally has no destructor because
     * much of the reconstruction still performs explicit `_Tidy` calls. Local
     * strings and value-container elements from the original binary did have
     * ordinary RAII, so this same-size adapter restores that lifetime without
     * changing the layout or globally double-freeing explicit-cleanup lanes.
     */
    class scoped_string final : public string
    {
    public:
        scoped_string() noexcept = default;
        explicit scoped_string(const char* value);
        explicit scoped_string(std::string_view value);
        scoped_string(const string& other);
        scoped_string(const scoped_string& other);
        scoped_string(scoped_string&& other) noexcept;
        scoped_string& operator=(const string& other);
        scoped_string& operator=(const scoped_string& other);
        scoped_string& operator=(scoped_string&& other) noexcept;
        ~scoped_string();
    };
#pragma pack(pop)
    static_assert(sizeof(scoped_string) == 28, "MSVC8 scoped string must be 28 bytes on x86");


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

        /**
         * Core concatenation. The result owns its bytes.
         *
         * The long path used to hand back a string pointing into a
         * thread-local arena with myRes set to the arena capacity, which made
         * it look heap-backed: a later tidy() would ::operator delete an arena
         * pointer, and the next concatenation on the same thread overwrote the
         * text of a string somebody was still holding.
         */
        inline string concat_impl(const std::string_view a, const std::string_view b) noexcept {
            string out;
            out.reserve(a.size() + b.size());
            (void)out.append(a.data(), a.size());
            (void)out.append(b.data(), b.size());
            return out;
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
