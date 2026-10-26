#pragma once

// Engine addition (dedicated-server plan WPL.17): Lua's number text as the Windows C runtime
// writes and reads it, on every platform.
//
// The sim's Lua formats numbers with sprintf (tostring's "%.14g", string.format's e/E/f/g/G) and
// parses them with strtod (luaO_str2d). tools/mathsweep/NumberTextSweep.cpp compared the
// Windows x64 UCRT with glibc on every float, and the probes in that tool's notes on the
// special values: the two agree everywhere but on NaNs.
//   - Formatting: the x87 indefinite (0xFFF8000000000000) is "-nan(ind)" ("-NAN(IND)" for the
//     upper-case conversions) on Windows and "-nan" with glibc; every other NaN, the
//     infinities and every number print alike, flags and width included.
//   - Parsing: UCRT reads "nan" (any case, optional sign) as 0x7FFFFFFFFFFFFFFF with the sign,
//     "nan(ind)" as the indefinite whatever the sign, "nan(snan)" as 0x7FF0000000000001 with
//     the sign, and "nan(other n-chars)" as plain "nan"; glibc returns its default quiet NaN.
// On Windows both functions are the CRT calls themselves.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace lua
{
  /// sprintf(out, form, value) for one floating conversion, with Windows' NaN text.
  inline int FormatNumberLikeWindowsCrt(char* const out, const char* const form, const double value)
  {
#if !defined(_WIN32)
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    if (bits == 0xFFF8000000000000ull) {
      // "%" flags width [.precision] conversion: Windows pads its longer text like glibc pads
      // "-nan" (spaces, the '-' flag left-aligns, '0' and the precision do not apply).
      const char* cursor = form + 1;
      bool leftAlign = false;
      while (*cursor == '-' || *cursor == '+' || *cursor == ' ' || *cursor == '#' || *cursor == '0') {
        leftAlign = leftAlign || *cursor == '-';
        ++cursor;
      }
      int width = 0;
      while (*cursor >= '0' && *cursor <= '9') {
        width = width * 10 + (*cursor - '0');
        ++cursor;
      }
      if (*cursor == '.') {
        ++cursor;
        while (*cursor >= '0' && *cursor <= '9') {
          ++cursor;
        }
      }
      const bool upper = *cursor == 'E' || *cursor == 'F' || *cursor == 'G';
      return std::sprintf(out, leftAlign ? "%-*s" : "%*s", width, upper ? "-NAN(IND)" : "-nan(ind)");
    }
#endif
    return std::sprintf(out, form, value);
  }

  /// strtod(text, end), with Windows' NaN spellings and values.
  inline double ParseNumberLikeWindowsCrt(const char* const text, char** const end)
  {
#if !defined(_WIN32)
    const char* cursor = text;
    while (*cursor == ' ' || (*cursor >= '\t' && *cursor <= '\r')) {
      ++cursor;
    }
    bool negative = false;
    if (*cursor == '+' || *cursor == '-') {
      negative = *cursor == '-';
      ++cursor;
    }
    const auto lower = [](const char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
    if (lower(cursor[0]) == 'n' && lower(cursor[1]) == 'a' && lower(cursor[2]) == 'n') {
      cursor += 3;
      std::uint64_t bits = 0x7FFFFFFFFFFFFFFFull;
      if (*cursor == '(') {
        const char* close = cursor + 1;
        while ((*close >= '0' && *close <= '9') || (*close >= 'a' && *close <= 'z') || (*close >= 'A' && *close <= 'Z') ||
               *close == '_') {
          ++close;
        }
        if (*close == ')') {
          const std::size_t length = static_cast<std::size_t>(close - cursor - 1);
          const char* const inner = cursor + 1;
          const auto is = [&](const char* word) {
            for (std::size_t at = 0; at < length; ++at) {
              if (word[at] == '\0' || lower(inner[at]) != word[at]) {
                return false;
              }
            }
            return word[length] == '\0';
          };
          if (is("ind")) {
            bits = 0xFFF8000000000000ull;
            negative = false;
          } else if (is("snan")) {
            bits = 0x7FF0000000000001ull;
          }
          cursor = close + 1;
        }
      }
      if (negative) {
        bits |= 0x8000000000000000ull;
      }
      if (end != nullptr) {
        *end = const_cast<char*>(cursor);
      }
      double value = 0.0;
      std::memcpy(&value, &bits, sizeof(value));
      return value;
    }
#endif
    return std::strtod(text, end);
  }
} // namespace lua
