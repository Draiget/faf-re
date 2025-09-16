#include "Global.h"

#include <cstdarg>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
using namespace gpg;

// 0x0093EDE0
void gpg::HandleAssertFailure(const char* msg, int line, const char* file) {
    InvokeDieHandler(STR_Printf("Failed assertion: %s\nFile: %s\nLine: %d", msg, file, line).c_str());
}

// 0x00938FE0
die_handler_t SetDieHandler(die_handler_t handler) {
	const die_handler_t old = dieHandler;
    dieHandler = handler;
    return old;
}

// 0x00938FF0
void gpg::InvokeDieHandler(const char* msg) {
    if (dieHandler != nullptr) {
        dieHandler(msg);
    }
}

// 0x00939000
void gpg::Die(const char* args, ...) {
    va_list va;
    va_start(va, args);
    const char* fmt = va_arg(args, const char*);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);
    InvokeDieHandler(msg.c_str());
    __debugbreak();
    while (true)
    {
    }
}

bool gpg::func_ParseNum(const char* start, const char* end, int* dest) noexcept {
    if (!start || !end || start >= end || !dest) return false;

    // Sign
    bool neg = false;
    if (*start == '-') { neg = true; ++start; if (start >= end) return false; }

    // Base autodetect
    int base = 10;
    if (*start == '0') {
        if ((start + 1) < end && (start[1] == 'x' || start[1] == 'X')) {
            base = 16; start += 2; if (start >= end) return false;
        } else {
            base = 8;  // note: original treats leading '0' as octal
            ++start;   // keep at least one digit after the leading zero for octal
            if (start > end) return false;
            // allow value "0" (single zero)
            if (start == end) { *dest = 0; return true; }
            // if next char is not valid octal digit, fail (strictness matches original)
            if (*start < '0' || *start > '7') return false;
        }
    }

    int value = 0;
    const char* p = start;

    while (p < end && *p != '\0') {
        const unsigned char c = static_cast<unsigned char>(*p);
        int digit;

        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else {
            // ASCII lowercasing without locale
            const unsigned char lc = static_cast<unsigned char>(c | 0x20);
            if (lc < 'a' || lc > 'z') return false;
            digit = 10 + (lc - 'a');
        }

        if (digit >= base) {
            return false;
        }

        // Accumulate (no overflow check in original; keep semantics)
        value = value * base + digit;
        ++p;
    }

    if (neg) value = -value;
    *dest = value;
    return true;
}
