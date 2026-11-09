#pragma once

#include <cstdint>
#include <cstring>
#include <ios>
#include <new>
#include <ostream>
#include <string_view>

#include "legacy/containers/Layout.h"

namespace fa
{
    /**
     * Address: 0x00ABF013 (FUN_00ABF013)
     * Mangled: ?_Xlen@_String_base@std@@SAXXZ
     *
     * IDA signature:
     * void __cdecl __noreturn std::_String_base::_Xlen(void);
     *
     * What it does: Dinkumware's shared (non-templated) "requested string
     * length is not representable" helper - throws std::length_error("string
     * too long") and never returns. In the binary it is called from every
     * basic_string<char>/basic_string<wchar_t> growth path: std::string::assign
     * (0x004056FE), std::string::append (0x00405829, 0x00405840), insert,
     * replace, and the wstring equivalents (18 call sites total, decoded from
     * the raw E8 bytes; see FUN_00ABF013.xrefs.txt).
     * `fa::string::assign_owned_strong` is this project's higher-level
     * stand-in for their length guard, so that is where this is wired.
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
     * E8 bytes; see FUN_00ABF052.xrefs.txt). `fa::string::assign(other,
     * pos, count)` already models FUN_004056B0 (std::string::assign)
     * including its pos-vs-size check, so this is wired there.
     */
    [[noreturn]] void ThrowInvalidStringPosition();

#pragma pack(push, 4)
    struct string
	{
#if FAF_RETAIL_LAYOUT
        void* alVal = nullptr; // allocator word, never read
#endif

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
         * `fa::vector<fa::string>` grew, relocated its elements
         * shallowly, released the originals, and the allocator handed the same
         * block to the next `fa::string` built in the loop.
         *
         * Each copy therefore owns a buffer that has to be released again, which
         * is what the destructor below does.
         *
         * Inline strings copy here without a call; `CopySlow` and `AssignSlow`
         * handle everything else, including a source that fails `basic_sanity`.
         */
        string(const string& other) noexcept {
            if (other.myRes == 15U && other.mySize <= 15U) {
                bx = other.bx;
                mySize = other.mySize;
                myRes = 15U;
            } else {
                CopySlow(other);
            }
        }

        string& operator=(const string& other) noexcept {
            if (myRes == 15U && other.myRes == 15U && other.mySize <= 15U) {
                bx = other.bx;
                mySize = other.mySize;
                return *this;
            }
            return AssignSlow(other);
        }

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
         * scattered locals: `fa::vector<T>` guards its element teardown with
         * `if constexpr (!std::is_trivially_destructible_v<T>)`, so while this
         * type stayed trivially destructible every `fa::vector<fa::string>`
         * released its own block and leaked every element's.
         *
         * `tidy(true, 0)` is the already-recovered lane (0x008846B0 and friends)
         * and leaves the object a valid empty inline string, so running it again
         * -- `scoped_string`'s destructor does, before this base destructor -- is
         * a no-op rather than a double free.
         */
        /**
         * The dangling source this used to hit was `substr` adopting a pointer
         * into another string's buffer; see its comment. With that gone,
         * nothing in the class produces a heap-looking string it does not own,
         * and the release below is safe.
         */
        ~string() noexcept {
            if (myRes >= 0x10U && bx.ptr != nullptr) {
                ::operator delete(bx.ptr);
            }
            mySize = 0U;
            myRes = 15U;
            bx.buf[0] = '\0';
        }

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
         * `fa::vector::erase` moves the whole tail down one slot per erased
         * element. With the log window's committed history at tens of thousands
         * of lines, one capped log write leaked that many blocks, and a busy
         * logging window exhausted the heap - `assign_owned` then memcpy'd
         * through a failed allocation.
         */
        string(string&& other) noexcept : bx(other.bx), mySize(other.mySize), myRes(other.myRes) {
            other.bx.buf[0] = '\0';
            other.mySize = 0U;
            other.myRes = 15U;
        }

        string& operator=(string&& other) noexcept {
            if (this == &other) {
                return *this;
            }

            // Release whatever this string owned before taking the source's buffer;
            // without this the displaced block would leak exactly as the copy
            // assignment used to.
            if (myRes >= 0x10U && bx.ptr != nullptr) {
                ::operator delete(bx.ptr);
            }

            bx = other.bx;
            mySize = other.mySize;
            myRes = other.myRes;
            other.bx.buf[0] = '\0';
            other.mySize = 0U;
            other.myRes = 15U;
            return *this;
        }

        /**
         * From C-string: copies, as MSVC8's own converting ctor does. Input of
         * 15 characters or fewer lands in the inline buffer, longer input gets
         * its own heap block.
         *
         * The binary does not null-check the source (0x00405550: strlen would
         * fault). The guard only turns a crash into an empty string and cannot
         * change behaviour on any input the original survived.
         */
        string(const char* s) noexcept {
            InitFrom(s, s != nullptr ? std::strlen(s) : 0U);
        }

        /**
         * From string_view: same copying policy as above.
         */
        explicit string(std::string_view sv) noexcept {
            InitFrom(sv.data(), sv.size());
        }

        /**
         * From pointer + length: same copying policy as above, always NUL
         * terminated.
         */
        explicit string(const char* p, std::size_t n) noexcept {
            InitFrom(p, p != nullptr ? n : 0U);
        }

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
         * Conservative sanity checks to avoid wild reads: the length fits the
         * capacity, the capacity is not absurd, an inline string has MSVC8's
         * fixed 15 and a heap string has a buffer.
         */
        [[nodiscard]]
    	bool basic_sanity() const noexcept {
            if (mySize > myRes || myRes > maxCapGuard) {
                return false;
            }
            return is_sso() ? myRes == 15U : bx.ptr != nullptr;
        }

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
         * Address: 0x0045F3F0 (FUN_0045F3F0 -- `_Tidy(true)` -- free the heap buffer and restore the empty SSO state for `fa::string` (the canonical path keys of both wait-handle-set maps); callers 0x0045E870, 0x0045F670, 0x0045F7A0; formerly `ResetLegacyStringStorage` in moho/misc/FileWaitHandleSet.cpp (RULE ONE), removed 2026-09-11.)
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
         * append(ptr,len) - grows the buffer when needed. The source may lie
         * inside this string.
         */
        bool append(const char* s, const std::size_t n) noexcept {
            if (s != nullptr && basic_sanity() && n <= static_cast<std::size_t>(myRes) - mySize) {
                char* const p = raw_data_mut_unsafe();
                std::memmove(p + mySize, s, n);
                mySize += static_cast<uint32_t>(n);
                p[mySize] = '\0';
                return true;
            }
            return AppendSlow(s, n);
        }

        /**
         * append(string_view)
         */
        bool append(const std::string_view sv) noexcept {
	        return append(sv.data(), sv.size());
        }

        /**
         * append(count, ch) - grows the buffer when needed.
         */
        bool append(const std::size_t count, const char ch) noexcept {
            if (basic_sanity() && count <= static_cast<std::size_t>(myRes) - mySize) {
                char* const p = raw_data_mut_unsafe();
                std::memset(p + mySize, static_cast<unsigned char>(ch), count);
                mySize += static_cast<uint32_t>(count);
                p[mySize] = '\0';
                return true;
            }
            return AppendSlow(count, ch);
        }

        /**
         * push_back
         */
        bool push_back(const char ch) noexcept {
            return append(std::size_t{1}, ch);
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
         * Assign from C-string; in-place when it fits the current capacity,
         * otherwise through `assign_owned`, which takes a block of its own.
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
         * Assign from a substring of another fa::string.
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
		 * Return substring [from .. from+maxLen) as a new fa::string.
		 *
		 * Always a copy, which is what MSVC8's own `basic_string::substr` is:
		 * `return basic_string(*this, off, count)`.
		 *
		 * It used to adopt a pointer into the source's buffer whenever the
		 * source was heap-backed and the slice ran past 15 characters. That
		 * produced a string with `myRes >= 16` - heap-backed, to every other
		 * member of this class - over memory it did not own, and `tidy` frees
		 * on exactly that test, as does the binary's own emission of it
		 * (FUN_008846B0). So the object could not exist in the type this
		 * models, and it is why the destructor had to stay a no-op: `CLobby`
		 * builds its player names with `desired.substr(0, maxLen)`, the
		 * temporary released the *source's* block, and the name that reached
		 * `SNetCommandArg` pointed at freed memory while still passing
		 * `basic_sanity()`.
		 *
		 * @param from   Start position (clamped: if >= size() -> empty string).
		 * @param maxLen Max number of chars; npos means "to the end".
		 * @return New fa::string instance (copy or non-owning view).
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

            // The (ptr, len) constructor copies: inline below 16 characters,
            // its own heap block above.
            return string(src, len);
        }

        /** Compare with another fa::string. */
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

        /** operator+= appends in place, as the binary's `append` (0x004058F0) does: it grows through `_Copy` (0x00405C20) only when capacity runs out. */
        string& operator+=(const string& rhs) noexcept {
            const std::string_view view = rhs.view();
            (void)append(view.data(), view.size());
            return *this;
        }

        string& operator+=(const char* rhs) noexcept {
            if (rhs != nullptr) {
                (void)append(rhs, std::strlen(rhs));
            }
            return *this;
        }

        string& operator+=(const char ch) noexcept {
            (void)push_back(ch);
            return *this;
        }
    private:
        /** Constructor body: inline up to 15 characters, its own heap block above. */
        void InitFrom(const char* const p, const std::size_t n) noexcept {
            if (n <= 15U) {
                if (n != 0U) {
                    std::memcpy(bx.buf, p, n);
                }
                bx.buf[n] = '\0';
                mySize = static_cast<uint32_t>(n);
                myRes = 15U;
                return;
            }
            InitHeap(p, n);
        }

        void InitHeap(const char* p, std::size_t n) noexcept;
        void CopySlow(const string& other) noexcept;
        string& AssignSlow(const string& other) noexcept;
        bool AppendSlow(const char* s, std::size_t n) noexcept;
        bool AppendSlow(std::size_t count, char ch) noexcept;

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
    };
#pragma pack(pop)
    static_assert(sizeof(string) == 28, "MSVC8 string must be 28 bytes on x86");

#pragma pack(push, 4)
    /**
     * Same-size form of `fa::string` whose assignment takes the new buffer
     * before it releases the old one and reports failures.
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


    /** std::string_view + fa::string */
    [[nodiscard]] inline string operator+(std::string_view lhs, const string& rhs) noexcept;

    /** const char* + fa::string */
    [[nodiscard]] inline string operator+(const char* lhs, const string& rhs) noexcept;

    namespace detail {

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

}
