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
    };
#pragma pack(pop)

    static_assert(sizeof(string) == 28, "MSVC8 string must be 28 bytes on x86");

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
        friend bool operator==(const StringRef& a, std::string_view b) noexcept {
            return std::string_view(a) == b;
        }
        friend std::strong_ordering operator<=>(const StringRef& a, std::string_view b) noexcept {
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
