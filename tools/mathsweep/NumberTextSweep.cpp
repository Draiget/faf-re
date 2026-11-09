// Engine addition (dedicated-server plan WPL.17): Lua's number text on every float, hashed per
// block of 2^20 inputs, to diff between C libraries.
//
// The sim's Lua formats a number with sprintf("%.14g", (double)f) (luaV_tostring, io write) and
// parses with (float)strtod (luaO_str2d). For every float bit pattern this prints, per block:
//   format <block> <hash of the formatted strings>
//   parse  <block> <hash of (float)strtod(formatted)>
// Usage: NumberTextSweep [first-block last-block]; build like MathSweep.cpp. Built with
// -DFAF_ENGINE_NUMBER_TEXT -I src it runs the engine's lua/LuaNumberText.h instead of the C
// library calls (on Windows the two are the same).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#if defined(FAF_ENGINE_NUMBER_TEXT)
#include "lua/LuaNumberText.h"
#define FORMAT_NUMBER(out, size, form, value) lua::FormatNumberLikeWindowsCrt(out, form, value)
#define PARSE_NUMBER(text, end) lua::ParseNumberLikeWindowsCrt(text, end)
#else
#define FORMAT_NUMBER(out, size, form, value) std::snprintf(out, size, form, value)
#define PARSE_NUMBER(text, end) std::strtod(text, end)
#endif

static inline float AsFloat(std::uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }
static inline std::uint32_t AsBits(float f) { std::uint32_t u; std::memcpy(&u, &f, 4); return u; }

int main(int argc, char** argv)
{
  const unsigned first = argc > 2 ? static_cast<unsigned>(std::strtoul(argv[1], nullptr, 10)) : 0u;
  const unsigned last = argc > 2 ? static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10)) : 4095u;
  for (std::uint64_t block = first; block <= last; ++block) {
    std::uint64_t formatHash = 1469598103934665603ull;
    std::uint64_t parseHash = 1469598103934665603ull;
    for (std::uint64_t index = 0; index < (1ull << 20); ++index) {
      const auto bits = static_cast<std::uint32_t>((block << 20) | index);
      char text[64];
      const int length = FORMAT_NUMBER(text, sizeof(text), "%.14g", static_cast<double>(AsFloat(bits)));
      for (int at = 0; at < length; ++at) {
        formatHash = (formatHash ^ static_cast<unsigned char>(text[at])) * 1099511628211ull;
      }
      formatHash = (formatHash ^ 0xFFu) * 1099511628211ull;
      char* end = nullptr;
      const float parsed = static_cast<float>(PARSE_NUMBER(text, &end));
      parseHash = (parseHash ^ AsBits(parsed)) * 1099511628211ull;
      parseHash = (parseHash ^ static_cast<std::uint32_t>(end - text)) * 1099511628211ull;
    }
    std::printf("format %llu %016llx\nparse %llu %016llx\n", static_cast<unsigned long long>(block),
                static_cast<unsigned long long>(formatHash), static_cast<unsigned long long>(block),
                static_cast<unsigned long long>(parseHash));
  }
  return 0;
}
