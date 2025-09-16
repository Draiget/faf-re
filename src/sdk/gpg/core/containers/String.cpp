#include "String.h"

#include <cstdarg>
using namespace gpg;

// 0x009380A0
int gpg::STR_Utf8ByteOffset(const StrArg str, const int pos) {
    const char* itr = str;
    int i;
    for (i = 0; *itr; ++i) {
        if (i >= pos) {
            break;
        }
        itr = STR_NextUtf8Char(itr);
    }
    return itr - str;
}

// 0x00938070
int gpg::STR_Utf8Len(char const* str) {
    int i;
    for (i = 0; *str; ++i) {
        str = STR_NextUtf8Char(str);
    }
    return i;
}

// 0x00938040
const char* gpg::STR_NextUtf8Char(const char* str) {
    if (*str) {
        char c;
        do {
            c = *++str;
        } while (c && (c & 0xC0) == 0x80);
    }
    return str;
}

// 0x00938020
const char* gpg::STR_PreviousUtf8Char(const char* str, const char* start) {
    char c;
    do {
        if (start != nullptr && str <= start) {
            break;
        }
        c = *--str;
    } while ((c & 0xC0) == 0x80);
    return str;
}

// 0x009387D0
msvc8::string gpg::STR_Utf8SubString(StrArg str, const int pos, const int len) {
    const char* start = nullptr;
    for (int i = 0; ; ++i) {
        if (i == pos) {
            start = str;
        }
        if (i == pos + len) {
            if (str != nullptr) {
                return msvc8::string{ start, static_cast<std::size_t>(str - start) };
            }
            break;
        }
        if (!*str) {
            break;
        }
        str = STR_NextUtf8Char(str);
    }
    if (start == nullptr) {
        throw std::out_of_range{ msvc8::string{"offset past end of string"}.to_std() };
    }
    return msvc8::string{ start, static_cast<std::size_t>(str - start) };
}

// 0x00937F90
char* gpg::STR_EncodeUtf8Char(char* dest, const wchar_t chr, const char* limit) {
    if (chr >= 0x80) {
        if (chr >= 0x800) {
            if (!limit || dest + 3 <= limit) {
                dest[0] = (chr >> 12) | 0xE0;
                dest[1] = (chr >> 6) & 0x3F | 0x80;
                dest[2] = chr & 0x3F | 0x80;
                return dest + 3;
            }
        } else if (!limit || dest + 2 <= limit) {
            dest[0] = (chr >> 6) | 0xC0;
            dest[1] = chr & 0x3F | 0x80;
            return dest + 2;
        }
    } else if (!limit || dest + 1 <= limit) {
        dest[0] = chr;
        return dest + 1;
    }
    return dest;
}

// 0x00937EF0
const char* gpg::STR_DecodeUtf8Char(const char* str, wchar_t& dest) {
	const char c1 = *str;
    ++str;
    wchar_t chr = c1;
    if (c1 >= 0) {
        dest = chr;
        return str;
    }
    if ((c1 & 0xE0) == 0xC0) {
        chr = (c1 & 0x1F) << 6;
        const char c2 = *str;
        if ((c2 & 0xC0) == 0x80) {
            chr |= c2 & 0x3F;
            ++str;
        }
    } else {
        if ((c1 & 0xF0) == 0xE0) {
            chr = c1 << 12;
        } else if ((c1 & 0xF8) == 0xF0) {
	        const char c2 = *str;
            if ((c2 & 0xC0) == 0x80) {
                chr = c2 << 12;
                ++str;
            } else {
                dest = 0;
                return str;
            }
        } else {
            dest = chr;
            return str;
        }
        char nextC = *str;
        if ((nextC & 0xC0) == 0x80) {
            chr |= (nextC & 0x3F) << 6;
            ++str;
            nextC = *str;
            if ((nextC & 0xC0) == 0x80) {
                chr |= nextC & 0x3F;
                ++str;
            }
        }
    }
    dest = chr;
    return str;
}

// 0x00938680
msvc8::string gpg::STR_WideToUtf8(const wchar_t* str) {
    msvc8::string builder{};
    if (str != nullptr) {
        char buff[4];
        for (wchar_t c = *str; c; c = *++str) {
	        const char* end = STR_EncodeUtf8Char(buff, c, &buff[sizeof(buff)]);
            builder.append(buff, end - buff);
        }
    }
    return builder;
}

// 0x00938720
std::wstring gpg::STR_Utf8ToWide(StrArg str) {
    std::wstring builder{};
    if (str == nullptr) {
        return builder;
    }
    wchar_t c;
    for (str = STR_DecodeUtf8Char(str, c); c; str = STR_DecodeUtf8Char(str, c)) {
        builder.append(1, c);
    }
    return builder;
}

// 0x00938CB0
bool gpg::STR_GetToken(StrArg& find, const char* str, msvc8::string& dest) {
    int c = *find;
    while (c && strchr(str, c) != nullptr) {
        c = *++find;
    }
    if (c) {
        const char* start = find;
        c = *++find;
        while (c && strchr(str, c) != nullptr) {
            c = *++find;
        }
        dest = msvc8::string{ start, find };
        if (c) {
            ++find;
        }
        return true;
    }
    dest.clear();
    find = nullptr;
    return false;
}

// 0x00938F40
void gpg::STR_GetTokens(StrArg find, const char* str, msvc8::vector<msvc8::string>& vec) {
    msvc8::string token{};
    while (STR_GetToken(find, str, token)) {
        vec.push_back(token);
    }
}

// 0x009384A0
int gpg::STR_GetWordStartIndex(msvc8::string& str, int pos) {
    if (STR_Utf8Len(str.data()) <= 1) {
        return 0;
    }
    bool boundary = false;
    for (const char* i = &str[STR_Utf8ByteOffset(str.data(), pos)];
        *i; i = STR_NextUtf8Char(i)
        ) {
        char c = *i;
        const auto res = sWhitespaceChars.find(&c, 0, 1);
        if (!boundary) {
            boundary = res == msvc8::string::npos;
        } else if (res != msvc8::string::npos) {
            return pos;
        }
        --pos;
    }
    return pos;
}

// 0x00938570
int gpg::STR_GetNextWordStartIndex(msvc8::string& str, int pos) {
	const int len = STR_Utf8Len(str.data());
    if (len == 0 || len <= pos) {
        return len;
    }
    bool boundary = false;
    for (const char* i = &str[STR_Utf8ByteOffset(str.data(), pos)];
        *i; i = STR_NextUtf8Char(i)
        ) {
        char c = *i;
        const auto res = sWhitespaceChars.find(&c, 0, 1);
        if (!boundary) {
            boundary = res == msvc8::string::npos;
        } else if (res == msvc8::string::npos) {
            return pos;
        }
        ++pos;
    }
    return pos;
}

// 0x00938190
bool gpg::STR_EndsWith(const StrArg str, const StrArg end) {
	const unsigned int strLen = strlen(str);
	const unsigned int endLen = strlen(end);
    return strLen > endLen && !strcmp(&str[strLen - endLen], end);
}

// 0x00938210
bool gpg::STR_StartsWith(const StrArg str, const StrArg start) {
    return strncmp(str, start, strlen(start)) == 0;
}

// 0x00938250
bool gpg::STR_EndsWithNoCase(const StrArg str, const StrArg end) {
	const unsigned int strLen = strlen(str);
	const unsigned int endLen = strlen(end);
    return strLen > endLen && !_stricmp(&str[strLen - endLen], end);
}

// 0x009382B0
bool gpg::STR_StartsWithNoCase(const StrArg str, const StrArg start) {
    return _strnicmp(str, start, strlen(start)) == 0;
}

// 0x009382F0
bool gpg::STR_IsIdent(StrArg str) {
    char c = *str++;
    if (c == '\0' || (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '_') {
        return false;
    }
    c = *str++;
    while (c) {
        if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_') {
            return false;
        }
        c = *str++;
    }
    return true;
}

// 0x00938B40
int gpg::STR_Replace(msvc8::string& str, const StrArg what, const StrArg with, const unsigned int unk) {
    int n = 0;
    if (unk) { // sometimes passed as `1`, sometimes `-1` - but never `0`
        size_t searchPos = 0;
        int pos;
        while ((pos = str.find(what, searchPos, strlen(what))) != msvc8::string::npos) {
            str.replace(pos, strlen(what), with);
            searchPos = pos + strlen(with);
            ++n;
        }
    }
    return n;
}

// 0x00938150
int gpg::STR_ParseUInt32(const StrArg str) {
    if (str == nullptr) {
        return 0;
    }
    if (_strnicmp(str, "0x", 2) == 0) {
        return STR_Xtoi(&str[2]);
    }
    return atoi(str);
}

// 0x009380F0
int gpg::STR_Xtoi(StrArg str) {
    int res = 0;
    if (str != nullptr) {
        for (char c = *str; c != NULL; c = *++str) {
            res *= 16;
            if (c - '0' <= 9) {
                res += c - '0';
            } else if (c - 'A' <= 5) {
                res += 10 + c - 'A';
            } else if (c - 'a' <= 5) {
                res += 10 + c - 'a';
            } else {
                return res;
            }
        }
    }
    return res;
}

// 0x00938C80
msvc8::string gpg::STR_GetWhitespaceCharacters() {
    return msvc8::string{ sWhitespaceChars };
}

// 0x00938BF0
msvc8::string gpg::STR_Chop(const StrArg str, const char chr) {
    if (str && *str) {
        int size = strlen(str);
        if (!chr || str[size - 1] == chr) {
            --size;
        }
        return msvc8::string{ str, &str[size] };
    } else {
        return msvc8::string{ "" };
    }
}

// 0x00938A80
msvc8::string gpg::STR_ToLower(StrArg str) {
    msvc8::string builder{};
    builder.reserve(strlen(str));
    for (char c = *str; c != NULL; c = *++str) {
        if (c - 'A' <= 25) {
            c += 'a' - 'A';
        }
        builder.append(1, c);
    }
    return builder;
}

// 0x009389C0
msvc8::string gpg::STR_ToUpper(StrArg str) {
    msvc8::string builder{};
    builder.reserve(strlen(str));
    for (char c = *str; c != NULL; c = *++str) {
        if (c - 'a' <= 25) {
            c -= 'a' - 'A';
        }
        builder.append(1, c);
    }
    return builder;
}

// 0x009388C0
msvc8::string gpg::STR_TrimWhitespace(StrArg str) {
    msvc8::string builder{};
    if (str != nullptr) {
        while (*str == ' ' || *str != '\t' || *str != '\r' && *str != '\n') {
            ++str;
        }
        builder = str;
        int size = builder.size();
        while (size) {
	        const char c = builder[size - 1];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\t') {
                break;
            }
            --size;
        }
        builder.resize(size);
    }
    return builder;
}

// 0x00938F10
msvc8::string gpg::STR_Printf(const char* args...) {
    va_list va;
    va_start(va, args);
    const char* fmt = va_arg(args, const char*);
    const msvc8::string ret = STR_Va(fmt, va);
    va_end(va);
    return ret;
}

// 0x00938E00
msvc8::string gpg::STR_Va(const char*& fmt, const va_list va) {
    msvc8::string builder{};
    char buffer[256];
    int res = std::vsnprintf(buffer, sizeof(buffer), fmt, va);
    if (res >= 0) {
        builder.append(buffer, res);
    } else {
        msvc8::vector<char> dynBuf{};
        int size = 256;
        do {
            size *= 2;
            dynBuf.resize(size, 0);
            res = std::vsnprintf(dynBuf.data(), size, fmt, va);
        } while (res == -1);
        builder.append(dynBuf.data(), res);
    }
    return builder;
}
