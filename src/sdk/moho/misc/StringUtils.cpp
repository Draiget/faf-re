#include "StringUtils.h"

#include "legacy/containers/String.h"
using namespace moho;

void moho::TrimRange(const char* s, const size_t n, const char*& outBegin, const char*& outEnd) {
    const char* b = s;
    const char* e = s + n;
    while (b < e && std::isspace(static_cast<unsigned char>(*b))) {
	    ++b;
    }
    while (e > b && std::isspace(static_cast<unsigned char>(e[-1]))) {
	    --e;
    }
    outBegin = b;
    outEnd = e;
}

void moho::SplitByComma(const msvc8::string& src, msvc8::vector<msvc8::string>& out) {
    const char* s = src.c_str();
    const size_t n = src.size();
    size_t i = 0;
    while (i < n) {
        // skip delimiters and spaces
        while (i < n && (s[i] == ',' || std::isspace(static_cast<unsigned char>(s[i])))) {
	        ++i;
        }
        if (i >= n) {
	        break;
        }

        // read token till next comma
        size_t j = i;
        while (j < n && s[j] != ',') ++j;

        // trim [i, j)
        const char* tb; const char* te;
        TrimRange(s + i, j - i, tb, te);
        if (te > tb) {
            out.push_back(msvc8::string(tb, static_cast<size_t>(te - tb)));
        }
        i = (j < n ? j + 1 : j);
    }
}

msvc8::string moho::Join(const msvc8::vector<msvc8::string>& items, const char* sep) {
    msvc8::string out;
    if (items.empty()) {
	    return out;
    }

    const size_t sepLen = std::strlen(sep);
    // Compute total size to reduce reallocations (optional; MSVC8 string has SSO=15)
    size_t total = 0;
    for (const auto& item : items) {
	    total += item.size();
    }
    total += sepLen * (!items.empty() ? (items.size() - 1) : 0);
    out.reserve(total);

    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out.append(sep);
        out.append(items[i].c_str(), items[i].size());
    }
    return out;
}

bool moho::IsNameIgnored(const msvc8::string& ignoreList, const char* name) {
    if (!name || ignoreList.empty()) {
	    return false;
    }

    msvc8::vector<msvc8::string> tokens;
    tokens.reserve(8); // small, avoids reallocs
    SplitByComma(ignoreList, tokens);

    const size_t len = std::strlen(name);
    for (const auto& t : tokens) {
	    if (t.size() == len && std::memcmp(t.c_str(), name, len) == 0) {
	        return true;
        }
    }
    return false;
}
