// Exhaustive comparison helper (plan WPL.12): for every float in [-1, 1] (and every float for
// the unbounded functions), the bits of (float)f((double)x) hashed per block of 2^20 inputs.
// Usage: MathSweep <asin|acos|exp|log> -> lines "fn block hash"; run on both platforms and diff.
// Build without optimisation on Windows (cl /Od /MT /fp:precise: /O2 can vectorise the calls into
// the CRT's vector variants) and with -O2 -ffp-contract=off -fno-builtin on Linux.
// 2026-10-26: all four identical on Windows x64 (static UCRT) and Linux x64 (glibc 2.39 libm),
// tmp/server/linux/mathsweep/.
// glibc picks its exp/log/pow bodies by CPU (FMA/AVX2 variants on x86-64-v3). 2026-10-29: run
// with GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2,-FMA,-AVX512F (ld.so --list-diagnostics:
// dl_hwcaps_subdirs_active 0x7 -> 0x4), all four are still identical to Windows x64, so a CPU
// without FMA gets the same results.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

static inline float AsFloat(std::uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }
static inline std::uint32_t AsBits(float f) { std::uint32_t u; std::memcpy(&u, &f, 4); return u; }

int main(int argc, char** argv)
{
  if (argc < 2) return 2;
  const char* fn = argv[1];
  const bool bounded = std::strcmp(fn, "asin") == 0 || std::strcmp(fn, "acos") == 0;
  for (std::uint64_t block = 0; block < (1ull << 12); ++block) {
    std::uint64_t hash = 1469598103934665603ull;
    bool any = false;
    for (std::uint64_t i = 0; i < (1ull << 20); ++i) {
      const std::uint32_t bits = static_cast<std::uint32_t>((block << 20) | i);
      const float x = AsFloat(bits);
      if (bounded && !(x >= -1.0f && x <= 1.0f)) continue;
      if (std::isnan(x)) continue;
      const double d = static_cast<double>(x);
      double r;
      if (fn[0] == 'a' && fn[1] == 's') r = std::asin(d);
      else if (fn[0] == 'a') r = std::acos(d);
      else if (fn[0] == 'e') r = std::exp(d);
      else r = std::log(d);
      const std::uint32_t out = AsBits(static_cast<float>(r));
      hash = (hash ^ bits) * 1099511628211ull;
      hash = (hash ^ out) * 1099511628211ull;
      any = true;
    }
    if (any) std::printf("%s %llu %016llx\n", fn, static_cast<unsigned long long>(block), static_cast<unsigned long long>(hash));
  }
  return 0;
}
