#include "String.h"

msvc8::string::string(const char* s) noexcept {
    alVal = nullptr;
    if (!s) {
        bx.buf[0] = '\0';
        mySize = 0;
        myRes = 15;
    } else {
        const std::size_t n = std::strlen(s);
        if (n <= 15) {
            std::memcpy(bx.buf, s, n);
            bx.buf[n] = '\0';
            mySize = static_cast<uint32_t>(n);
            myRes = 15;
        } else {
            // Adopt external buffer (NO ownership). Capacity == length, no growth allowed.
            bx.ptr = const_cast<char*>(s);
            mySize = static_cast<uint32_t>(n);
            myRes = static_cast<uint32_t>(n);
        }
    }
}

msvc8::string::string(std::string_view sv) noexcept {
    alVal = nullptr;
    if (sv.size() <= 15) {
        if (!sv.empty())
            std::memcpy(bx.buf, sv.data(), sv.size());
        bx.buf[sv.size()] = '\0';
        mySize = sv.size();
        myRes = 15;
    } else {
        bx.ptr = const_cast<char*>(sv.data());
        mySize = sv.size();
        myRes = sv.size();
    }
}

msvc8::string::string(const char* p, const std::size_t n) noexcept {
    alVal = nullptr;
    if (!p) {
        bx.buf[0] = '\0';
        mySize = 0;
        myRes = 15;
        return;
    }
    if (n <= 15) {
        if (n) std::memcpy(bx.buf, p, n);
        bx.buf[n] = '\0';
        mySize = n;
        myRes = 15;
    } else {
        // Adopt external storage (non-owning). We do NOT write a NUL terminator here.
        bx.ptr = const_cast<char*>(p);
        mySize = n;
        myRes = n;
    }
}

bool msvc8::string::basic_sanity() const noexcept {
    // Length must fit capacity; capacity must not be absurd.
    constexpr uint32_t maxCap = 1u << 30; // arbitrary big guard

    if (mySize > myRes) {
        return false;
    }
    if (myRes > maxCap) {
        return false;
    }
    if (is_sso()) {
        if (myRes != 15) {
            // MSVC8 used fixed 15 for SSO
            return false; 
        }
    } else {
        if (bx.ptr == nullptr) return false;
    }
    return true;
}

bool msvc8::string::resize(const std::size_t newSize, const char ch) noexcept {
    if (!basic_sanity()) {
        return false;
    }
    if (newSize > myRes) {
        // no reallocation by design
        return false; 
    }
    char* p = raw_data_mut_unsafe();
    if (newSize > mySize) {
        std::memset(p + mySize, static_cast<unsigned char>(ch), newSize - mySize);
    }
    mySize = newSize;
    p[mySize] = '\0';
    return true;
}

bool msvc8::string::append(const char* s, const std::size_t n) noexcept {
    if (!basic_sanity() || s == nullptr) {
        return false;
    }
    if (mySize > myRes || n > (std::numeric_limits<uint32_t>::max)()) {
        return false;
    }
    if (mySize + n > myRes) {
        // no growth
        return false; 
    }
    char* p = raw_data_mut_unsafe();
    std::memcpy(p + mySize, s, n);
    mySize += n;
    p[mySize] = '\0';
    return true;
}

bool msvc8::string::append(const std::size_t count, const char ch) noexcept {
    if (!basic_sanity()) {
        return false;
    }
    if (count == 0) {
        return true;
    }
    if (mySize > myRes) {
        return false;
    }
    if (count > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    if (mySize + count > myRes) {
        return false; // no reallocation by design
    }

    char* p = raw_data_mut_unsafe();
    std::memset(p + mySize, static_cast<unsigned char>(ch), count);
    mySize += static_cast<uint32_t>(count);
    p[mySize] = '\0';
    return true;
}

void msvc8::string::reverse() noexcept {
    if (!basic_sanity() || mySize <= 1) {
        return;
    }
    char* p = raw_data_mut_unsafe();
    std::size_t i = 0, j = mySize - 1;
    while (i < j) {
	    const char tmp = p[i];
        p[i] = p[j];
        p[j] = tmp;
        ++i; --j;
    }
    // p[mySize] remains '\0'
}

void msvc8::string::reserve(const std::size_t newCap) const noexcept {
    // Basic invariants first
    if (!basic_sanity()) {
        return;
    }

    // Guard against absurd requests (mirrors the sanity guard)
    if (newCap > maxCapGuard) {
        return;
    }

    // We never grow in this safe shim: success only if already enough.
    // return newCap <= myRes;
    // Use for (bool) implementation when needed.
}

std::size_t msvc8::string::find(const char ch, const std::size_t pos) const noexcept {
    if (!basic_sanity() || pos > mySize) {
        return npos;
    }
    const char* p = raw_data_unsafe();
    for (std::size_t i = pos; i < mySize; ++i) {
        if (p[i] == ch) return i;
    }
    return npos;
}

std::size_t msvc8::string::find(const std::string_view needle, const std::size_t pos) const noexcept {
    if (!basic_sanity()) {
        return npos;
    }
    if (needle.empty()) {
        return (pos <= mySize) ? 
            pos :
    		npos;
    }
    if (needle.size() > mySize || pos > mySize - needle.size()) {
        return npos;
    }
    const char* hay = raw_data_unsafe();
    const char* nd = needle.data();
    const std::size_t n = needle.size();
    for (std::size_t i = pos; i + n <= mySize; ++i) {
        if (hay[i] == nd[0] && std::memcmp(hay + i, nd, n) == 0) {
            return i;
        }
    }
    return npos;
}

std::size_t msvc8::string::find(const char* s, const std::size_t pos, const std::size_t n) const noexcept {
    if (!basic_sanity()) {
        return npos;
    }
    if (n == 0) {
        return (pos <= mySize) ? 
            pos :
    		npos;
    }
    if (!s) {
        return npos;
    }
    if (n > mySize || pos > mySize - n) {
        return npos;
    }
    const char* hay = raw_data_unsafe();
    for (std::size_t i = pos; i + n <= mySize; ++i) {
        if (hay[i] == s[0] && std::memcmp(hay + i, s, n) == 0)
            return i;
    }
    return npos;
}

bool msvc8::string::replace(const std::size_t pos, std::size_t count, const std::string_view repl) noexcept {
    if (!basic_sanity()) {
        return false;
    }
    if (pos > mySize) {
        return false;
    }
    if (count > mySize - pos) {
        count = mySize - pos;
    }
    const std::size_t tail = mySize - (pos + count);
    const std::size_t newSize = mySize - count + repl.size();
    if (newSize > myRes) {
        // no growth
        return false; 
    }
    char* p = raw_data_mut_unsafe();
    if (repl.size() != count) {
        // Move tail to its new position (use memmove for overlap)
        std::memmove(p + pos + repl.size(), p + pos + count, tail);
    }
    if (!repl.empty()) {
        std::memcpy(p + pos, repl.data(), repl.size());
    }
    mySize = static_cast<uint32_t>(newSize);
    p[mySize] = '\0';
    return true;
}

bool msvc8::string::assign_inplace(const std::string_view src) noexcept {
    if (!basic_sanity()) {
        return false;
    }
    if (src.size() > myRes) {
        return false;
    }
    char* p = raw_data_mut_unsafe();
    if (!src.empty()) {
        std::memcpy(p, src.data(), src.size());
    }
    mySize = src.size();
    p[mySize] = '\0';
    return true;
}

msvc8::string& msvc8::string::operator=(const char* s) noexcept {
    // Accept nullptr as "clear"
    if (!s) {
	    clear();
    	return *this;
    }

    const std::size_t n = std::strlen(s);

    // If fits current capacity (including SSO), copy in-place and NUL-terminate.
    if (n <= myRes) {
        if (!basic_sanity()) {
	        clear();
        	return *this;
        }

        char* p = raw_data_mut_unsafe();
        if (n) std::memcpy(p, s, n);
        mySize = static_cast<uint32_t>(n);
        p[mySize] = '\0';
        return *this;
    }

    // Otherwise adopt external buffer (non-owning, no growth).
    // Capacity becomes exactly n (excludes the terminator).
    bx.ptr = const_cast<char*>(s);
    mySize = static_cast<uint32_t>(n);
    myRes = static_cast<uint32_t>(n);
    return *this;
}

msvc8::string msvc8::string::adopt(char* buf, const uint32_t len, const uint32_t cap) noexcept {
    string s;
    s.bx.ptr = buf;
    s.mySize = len;
    s.myRes = cap;
    // leave _Alval as nullptr; we never free adopted memory
    return s;
}

msvc8::string& msvc8::string::assign(const string& other, std::size_t pos, std::size_t count) noexcept {
    // Basic sanity checks: if source is bogus, clear destination.
    if (!other.basic_sanity()) {
        clear();
        return *this;
    }

    // Range check like _Xran(): clamp pos to size (produces empty result if pos == size).
    if (pos > other.mySize) {
        pos = other.mySize;
    }

    const std::size_t remainder = static_cast<std::size_t>(other.mySize) - pos;
    std::size_t len = (count == npos || count > remainder) ? remainder : count;

    // Self-assign path (this == &other): turn into in-place substring.
    if (this == &other) {
        if (len == 0) {
            // Empty result
            raw_data_mut_unsafe()[0] = '\0';
            mySize = 0;
            return *this;
        }
        // Move [pos..pos+len) to the beginning; safe with memmove for overlap.
        char* d = raw_data_mut_unsafe();
        std::memmove(d, d + pos, len);
        d[len] = '\0';
        mySize = static_cast<uint32_t>(len);
        return *this;
    }

    // Non-self: fast empty case.
    if (len == 0) {
        raw_data_mut_unsafe()[0] = '\0';
        mySize = 0;
        return *this;
    }

    // Destination pointer and capacity.
    char* dst = raw_data_mut_unsafe();
    const auto  dstCap = static_cast<std::size_t>(myRes);

    // Source pointer (to substring start).
    const char* src = other.raw_data_unsafe() + pos;

    // MSVC8 would reallocate if len > capacity(); we cannot, so we truncate.
    const std::size_t ncopy = (len <= dstCap) ? len : dstCap;

    if (ncopy) {
        // Use memmove, not memcpy, to be robust in rare aliasing cases.
        std::memmove(dst, src, ncopy);
    }

    // Always NUL-terminate within available space.
    dst[ncopy] = '\0';
    mySize = static_cast<uint32_t>(ncopy);
    return *this;
}

msvc8::string msvc8::string::operator+(const string& rhs) const noexcept {
    return msvc8::detail::concat_impl(this->view(), rhs.view());
}

msvc8::string msvc8::string::operator+(std::string_view rhs) const noexcept {
    return msvc8::detail::concat_impl(this->view(), rhs);
}

msvc8::string msvc8::string::operator+(const char* rhs) const noexcept {
    return msvc8::detail::concat_impl(this->view(), std::string_view(rhs ? rhs : ""));
}

msvc8::string msvc8::string::concat_impl_(std::string_view a, std::string_view b) noexcept {
    const std::size_t total = a.size() + b.size();

    if (total <= 15) {
        string out;
        (void)out.append(a.data(), a.size());
        (void)out.append(b.data(), b.size());
        return out;
    }

    auto [buf, cap] = detail::get_concat_buffer(total + 1 /* NUL */);
    if (a.size()) std::memcpy(buf, a.data(), a.size());
    if (b.size()) std::memcpy(buf + a.size(), b.data(), b.size());
    buf[total] = '\0';

    const uint32_t effCap = (cap > 0) ? static_cast<uint32_t>(cap - 1) : 0u; // cap excludes NUL
    return string::adopt(buf, static_cast<uint32_t>(total), effCap);
}

msvc8::string msvc8::operator+(std::string_view lhs, const string& rhs) noexcept {
    return detail::concat_impl(lhs, rhs.view());
}

msvc8::string msvc8::operator+(const char* lhs, const string& rhs) noexcept {
    return detail::concat_impl(std::string_view(lhs ? lhs : ""), rhs.view());
}
