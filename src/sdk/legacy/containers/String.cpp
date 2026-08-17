#include "String.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

// All three converting constructors copy, which is what MSVC8's
// `std::basic_string` does: short input goes in the inline buffer, anything
// longer gets a heap block of its own.
//
// They used to *adopt* the caller's pointer once the input passed 15
// characters, and that was wrong in two directions at once. A `myRes` above 15
// means "heap-backed" to the rest of this class, so `tidy` would
// `::operator delete` a buffer the string never allocated; and the string
// stayed valid only as long as the caller's buffer did, which is never true for
// the common `msvc8::string s(temporary.c_str())` form - the temporary dies at
// the end of the full expression and the allocator writes its free-list link
// over the first four bytes. That is exactly what killed startup: the
// data-path script came back as "\xE0\xB7\x55\x04" + "rogramData\FAForever\bin\
// SupComDataPath.lua", so the file could not be opened and
// DISK_SetupDataAndSearchPaths died in gpg::Die.
//
// These stay `noexcept`, so an allocation failure terminates rather than
// unwinding as MSVC8's would. Nothing on these paths catches std::bad_alloc,
// so the outcome is the same either way.
msvc8::string::string(const string& other) noexcept {
    alVal = nullptr;
    bx.buf[0] = '\0';
    mySize = 0;
    myRes = 15;
    if (other.basic_sanity() && other.mySize != 0U) {
        assign_owned(std::string_view(other.raw_data_unsafe(), other.mySize));
    }
}

msvc8::string& msvc8::string::operator=(const string& other) noexcept {
    if (this == &other) {
        return *this;
    }

    // Read the source before tidy() touches this object - self-overlapping
    // buffers would otherwise be freed mid-copy.
    if (!other.basic_sanity() || other.mySize == 0U) {
        assign_owned(std::string_view{});
        return *this;
    }

    const string copied(other);
    tidy(true, 0U);
    bx = copied.bx;
    mySize = copied.mySize;
    myRes = copied.myRes;
    return *this;
}

msvc8::string::string(string&& other) noexcept {
    alVal = other.alVal;
    bx = other.bx;
    mySize = other.mySize;
    myRes = other.myRes;
    other.alVal = nullptr;
    other.bx.buf[0] = '\0';
    other.mySize = 0;
    other.myRes = 15;
}

msvc8::string& msvc8::string::operator=(string&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    // Release whatever this string owned before taking the source's buffer;
    // without this the displaced block would leak exactly as the copy
    // assignment used to.
    tidy(true, 0U);

    alVal = other.alVal;
    bx = other.bx;
    mySize = other.mySize;
    myRes = other.myRes;
    other.alVal = nullptr;
    other.bx.buf[0] = '\0';
    other.mySize = 0;
    other.myRes = 15;
    return *this;
}

/**
 * Address: 0x00405550 (FUN_00405550, ??0string@std@@QAE@PBD@Z)
 * Mangled: ??0string@std@@QAE@PBD@Z
 *
 * IDA signature:
 * std::string *__thiscall std::string::string(std::string *this, const char *str);
 *
 * What it does:
 * Puts the string in the empty small-buffer state, then assigns the source
 * measured with strlen. The binary delegates to the (pointer, length) ctor
 * for that second step; assign_owned takes the same path here.
 *
 * The binary does not null-check the source - strlen would fault. This
 * reconstruction keeps the guard, which only turns a crash into an empty
 * string and cannot change behaviour on any input the original survived.
 */
msvc8::string::string(const char* s) noexcept {
    alVal = nullptr;
    bx.buf[0] = '\0';
    mySize = 0;
    myRes = 15;
    if (s != nullptr) {
        assign_owned(std::string_view(s));
    }
}

msvc8::string::string(std::string_view sv) noexcept {
    alVal = nullptr;
    bx.buf[0] = '\0';
    mySize = 0;
    myRes = 15;
    assign_owned(sv);
}

msvc8::string::string(const char* p, const std::size_t n) noexcept {
    alVal = nullptr;
    bx.buf[0] = '\0';
    mySize = 0;
    myRes = 15;
    if (p != nullptr && n != 0U) {
        assign_owned(std::string_view(p, n));
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

void msvc8::string::eos(const uint32_t newSize) noexcept {
    const uint32_t boundedSize = (newSize <= myRes) ? newSize : myRes;
    mySize = boundedSize;

    char* const out = raw_data_mut_unsafe();
    if (out != nullptr) {
        out[boundedSize] = '\0';
    }
}

/**
 * Address: 0x00402740 (FUN_00402740)
 *
 * What it does:
 * Resets string storage to SSO lane and optionally preserves `newSize` bytes
 * from the old heap buffer before freeing it.
 */
void msvc8::string::tidy(const bool built, const uint32_t newSize) noexcept {
    // Preserve legacy lane shape:
    // if (built && large) { optional memcpy to SSO; delete(oldHeap); }
    if (built && myRes >= 0x10U) {
        char* const oldHeap = bx.ptr;
        if (oldHeap != nullptr) {
            if (newSize != 0U) {
                (void)memcpy_s(&bx, 0x10U, oldHeap, newSize);
            }
            ::operator delete(oldHeap);
        }
    }

    mySize = newSize;
    myRes = 15U;
    // Binary lane writes trailing NUL directly in inline storage.
    bx.buf[newSize] = '\0';
}

/**
 * Address: 0x006582E0 (FUN_006582E0)
 *
 * What it does:
 * Resets each legacy string in `[begin, end)` to empty SSO state and releases
 * heap-backed buffers when present.
 */
[[maybe_unused]] static void ResetStringRange(msvc8::string* begin, msvc8::string* end) noexcept
{
    while (begin != end) {
        begin->tidy(true, 0U);
        ++begin;
    }
}

void msvc8::string::assign_owned(const std::string_view value) {
    tidy(true, 0U);

    const std::size_t boundedSize = std::min<std::size_t>(
        value.size(),
        static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())
    );

    if (boundedSize <= 15U) {
        if (boundedSize != 0U) {
            std::memcpy(bx.buf, value.data(), boundedSize);
        }
        myRes = 15U;
        eos(static_cast<uint32_t>(boundedSize));
        return;
    }

    auto* const ownedBuffer = static_cast<char*>(::operator new(boundedSize + 1U));
    std::memcpy(ownedBuffer, value.data(), boundedSize);
    ownedBuffer[boundedSize] = '\0';

    bx.ptr = ownedBuffer;
    mySize = static_cast<uint32_t>(boundedSize);
    myRes = static_cast<uint32_t>(boundedSize);
}

void msvc8::string::assign_owned(const char* const value) {
    assign_owned(std::string_view(value ? value : ""));
}

void msvc8::string::assign_owned_strong(const std::string_view value) {
    if (value.size() > maxCapGuard) {
        throw std::length_error("legacy string too long");
    }

    if (value.size() <= 15U) {
        char inlineCopy[16]{};
        if (!value.empty()) {
            std::memcpy(inlineCopy, value.data(), value.size());
        }

        tidy(true, 0U);
        if (!value.empty()) {
            std::memcpy(bx.buf, inlineCopy, value.size());
        }
        mySize = static_cast<uint32_t>(value.size());
        myRes = 15U;
        bx.buf[mySize] = '\0';
        return;
    }

    auto* const replacement = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(replacement, value.data(), value.size());
    replacement[value.size()] = '\0';

    tidy(true, 0U);
    bx.ptr = replacement;
    mySize = static_cast<uint32_t>(value.size());
    myRes = static_cast<uint32_t>(value.size());
}

void msvc8::string::assign_owned_strong(const char* const value) {
    assign_owned_strong(std::string_view(value ? value : ""));
}

msvc8::scoped_string::scoped_string(const char* const value)
  : string()
{
    assign_owned_strong(value);
}

msvc8::scoped_string::scoped_string(const std::string_view value)
  : string()
{
    assign_owned_strong(value);
}

msvc8::scoped_string::scoped_string(const string& other)
  : string()
{
    assign_owned_strong(other.basic_sanity() ? other.view() : std::string_view{});
}

msvc8::scoped_string::scoped_string(const scoped_string& other)
  : scoped_string(static_cast<const string&>(other))
{
}

msvc8::scoped_string::scoped_string(scoped_string&& other) noexcept
  : string(std::move(static_cast<string&>(other)))
{
}

msvc8::scoped_string& msvc8::scoped_string::operator=(const string& other)
{
    if (this != &other) {
        assign_owned_strong(other.basic_sanity() ? other.view() : std::string_view{});
    }
    return *this;
}

msvc8::scoped_string& msvc8::scoped_string::operator=(const scoped_string& other)
{
    return operator=(static_cast<const string&>(other));
}

msvc8::scoped_string& msvc8::scoped_string::operator=(scoped_string&& other) noexcept
{
    string::operator=(std::move(static_cast<string&>(other)));
    return *this;
}

msvc8::scoped_string::~scoped_string()
{
    tidy(true, 0U);
}

bool msvc8::string::equals_no_case(const std::string_view rhs) const noexcept {
    const bool sane = basic_sanity();
    const char* lhs = sane ? raw_data_unsafe() : "";
    const std::size_t lhsSize = sane ? mySize : 0u;

    if (lhsSize != rhs.size()) {
        return false;
    }

    for (std::size_t i = 0; i < lhsSize; ++i) {
        const auto lc = static_cast<unsigned char>(lhs[i]);
        const auto rc = static_cast<unsigned char>(rhs[i]);
        if (ascii_tolower_(lc) != ascii_tolower_(rc)) {
            return false;
        }
    }

    return true;
}

// MSVC8's `basic_string::_Copy`, which is what every growing operation on this
// type funnels through in the binary. The requested size is rounded up with
// `| 15` so the first heap block is a whole allocation quantum, and a request
// that would grow the buffer by less than half is bumped to 1.5x instead, which
// is what keeps repeated appends amortised.
//
// This shim used to refuse to grow at all - `reserve` was a no-op and both
// `append` overloads returned false once the 15-character inline buffer was
// full. Every string the engine builds character by character was therefore
// silently cut to 15 bytes: gpg::STR_ToLower turned
// "C:\ProgramData\FAForever\bin\SupComDataPath.lua" into "c:\programdata\", so
// STR_CanonizeFilename handed CreateFileW a directory, the data-path script
// could not be opened, and startup died in gpg::Die.
bool msvc8::string::ensure_capacity(const std::size_t need) noexcept {
    if (!basic_sanity()) {
        return false;
    }
    if (need <= myRes) {
        return true;
    }
    if (need > maxCapGuard) {
        return false;
    }

    std::size_t newCapacity = need | 15U;
    if (newCapacity > maxCapGuard) {
        newCapacity = need;
    } else if (newCapacity / 3U < myRes / 2U && myRes <= maxCapGuard - myRes / 2U) {
        newCapacity = static_cast<std::size_t>(myRes) + myRes / 2U;
    }

    auto* const grown = static_cast<char*>(::operator new(newCapacity + 1U, std::nothrow));
    if (grown == nullptr) {
        return false;
    }

    const char* const old = raw_data_unsafe();
    if (mySize != 0U) {
        std::memcpy(grown, old, mySize);
    }
    grown[mySize] = '\0';

    if (myRes >= 16U && bx.ptr != nullptr) {
        ::operator delete(bx.ptr);
    }

    bx.ptr = grown;
    myRes = static_cast<uint32_t>(newCapacity);
    return true;
}

bool msvc8::string::resize(const std::size_t newSize, const char ch) noexcept {
    if (!ensure_capacity(newSize)) {
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
    if (n > (std::numeric_limits<uint32_t>::max)() - mySize) {
        return false;
    }
    if (n == 0) {
        return true;
    }
    if (!ensure_capacity(mySize + n)) {
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
    if (count > std::numeric_limits<uint32_t>::max() - mySize) {
        return false;
    }
    if (!ensure_capacity(mySize + count)) {
        return false;
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

void msvc8::string::reserve(const std::size_t newCap) noexcept {
    // MSVC8's reserve never shrinks below the current size, and a request that
    // already fits is a no-op; ensure_capacity covers both.
    (void)ensure_capacity(newCap);
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

    // Otherwise grow and copy, as MSVC8's assign does. This used to adopt the
    // caller's pointer and set myRes to its length, which marks the string
    // heap-backed to the rest of the class - so a later tidy() ran
    // ::operator delete over whatever was assigned. Every one of these was a
    // string literal: CConAlias::ShutdownRecovered freed .rdata at process
    // exit and took the engine allocator down with it.
    assign_owned(std::string_view(s, n));
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

/**
 * Address: 0x004422C0 (FUN_004422C0)
 * Address: 0x00445FD0 (FUN_00445FD0)
 *
 * What it does:
 * Reinitializes this string to empty SSO storage, then copies full source text.
 */
msvc8::string& msvc8::string::reset_and_assign(const string& other) noexcept {
    mySize = 0U;
    myRes = 15U;
    bx.buf[0] = '\0';
    return assign(other, 0U, npos);
}

msvc8::string& msvc8::string::assign(const string& other, std::size_t pos, const std::size_t count) noexcept {
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
        mySize = len;
        return *this;
    }

    // Non-self: fast empty case.
    if (len == 0) {
        raw_data_mut_unsafe()[0] = '\0';
        mySize = 0;
        return *this;
    }

    // Grow first, exactly as MSVC8's assign() does. Truncating to whatever
    // capacity happened to be there silently caps the result at 15 bytes for
    // any string still in its small buffer - which is how the preferences path
    // came out as "C:\Users\Draige".
    (void)ensure_capacity(len);

    // Destination pointer and capacity, read after any reallocation.
    char* dst = raw_data_mut_unsafe();
    const auto  dstCap = myRes;

    // Source pointer (to substring start). Taken after the grow too: `other`
    // is a different object here (the self-assign case returned above), so it
    // cannot have moved, but reading it late keeps the two in step.
    const char* src = other.raw_data_unsafe() + pos;

    // Only clamp if the grow failed.
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

msvc8::string& msvc8::string::assign(const char* data, const std::size_t size) noexcept {
    if (!data || size == 0) {
        clear();
        return *this;
    }

    // Small-String Optimization (≤15): copy into inline buffer and NUL-terminate.
    if (size <= 15) {
        std::memcpy(bx.buf, data, size);
        bx.buf[size] = '\0';
        mySize = size;
        myRes = 15;
        return *this;
    }

    // Long data: copy into owned storage. Adopting here marked the string
    // heap-backed while it pointed at the caller's buffer, so tidy() freed
    // memory this string never allocated.
    assign_owned(std::string_view(data, size));
    return *this;
}

msvc8::string msvc8::string::operator+(const string& rhs) const noexcept {
    return detail::concat_impl(view(), rhs.view());
}

msvc8::string msvc8::string::operator+(const std::string_view rhs) const noexcept {
    return detail::concat_impl(view(), rhs);
}

msvc8::string msvc8::string::operator+(const char* rhs) const noexcept {
    return detail::concat_impl(view(), std::string_view(rhs ? rhs : ""));
}

// Owning concatenation; see detail::concat_impl in the header for why the
// thread-local arena path had to go.
msvc8::string msvc8::string::concat_impl_(const std::string_view a, const std::string_view b) noexcept {
    string out;
    out.reserve(a.size() + b.size());
    (void)out.append(a.data(), a.size());
    (void)out.append(b.data(), b.size());
    return out;
}

msvc8::string msvc8::operator+(const std::string_view lhs, const string& rhs) noexcept {
    return detail::concat_impl(lhs, rhs.view());
}

msvc8::string msvc8::operator+(const char* lhs, const string& rhs) noexcept {
    return detail::concat_impl(std::string_view(lhs ? lhs : ""), rhs.view());
}
