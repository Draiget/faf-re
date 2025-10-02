#pragma once

#include <locale>

#include "legacy/containers/Vector.h"

namespace msvc8
{
	struct string;
}

namespace moho
{
    /**
     * Trim leading/trailing ASCII spaces; returns [outBegin,outEnd).
     */
    inline void TrimRange(const char* s, size_t n, const char*& outBegin, const char*& outEnd);

    /**
     * Split by commas, trim tokens, skip empty.
     * Writes into out (appends).
     */
    inline void SplitByComma(const msvc8::string& src, msvc8::vector<msvc8::string>& out);

    /**
     * Join strings with a separator.
     */
    inline msvc8::string Join(const msvc8::vector<msvc8::string>& items, const char* sep);

    /**
     * Check exact, case-sensitive membership in comma-separated list.
     * Returns true if 'name' equals any trimmed token in 'ignoreList'.
     */
    inline bool IsNameIgnored(const msvc8::string& ignoreList, const char* name);
}
