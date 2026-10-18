// difffuzz - differential fuzzing of pure leaf functions: the retail
// ForgedAlliance.exe (mapped, never run) against the recovered C++ compiled
// from src\sdk. No replay, no engine startup. See ..\README.md.

#include "fuzz.h"
#include "pe_image.h"
#include "retail_thunks.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <float.h>
#include <xmmintrin.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" int global_mode_sse2;

namespace
{
  using difffuzz::kCanary;
  using difffuzz::kMaxWords;
  using difffuzz::Target;
  using u32 = std::uint32_t;

  // Retail `global_mode_sse2` (written by register_sseCompatMode 0x00A8ECBF,
  // which never runs here).
  constexpr u32 kRetailGlobalModeSse2 = 0x01107030u;
  // Retail `__sse2_available` (CPUID result written by the CRT init entry
  // 0x00AAA8C5): 1 on any machine that runs the game, independent of
  // _set_SSE2_enable. _ftol2 (0x00A89CC0) takes `cvttsd2si` when it is set and
  // an x87 `fistp qword` lane (which wraps instead of saturating) otherwise.
  constexpr u32 kRetailSse2Available = 0x01107034u;

  // Retail static initializers run once after mapping (see README):
  //   0x00BEDC30  `fld1; atan; fmul 4.0; fstp [0x00FB78FC]` - the float pi
  //               QuatToAxisAndAngle (0x006C10E7) loads for w <= -1.
  //   0x00BEDC60  `fld [0x00FB78FC]; fmul 0.5; fstp [0x00FB7914]` - the
  //               float pi/2 COORDS_Pitch (0x0050B784) subtracts.
  constexpr u32 kRetailStaticInits[] = {0x00BEDC30u, 0x00BEDC60u};

  // The simulation's FP environment: _controlfp(_PC_24, _MCW_PC) on top of
  // the Windows default (round-nearest, every exception masked) gives x87
  // control word 0x007F; MXCSR stays at its 0x1F80 default.
  u32 gControlWord = 0x007Fu;
  // In game the sticky exception flags are usually already set (0x1FBF at
  // math.pow, beat 8678); SSE2 libm bodies can branch on them.
  u32 gMxcsr = 0x1FBFu;
  // Value poked into retail `global_mode_sse2`. The game runs with 0: CScApp
  // calls _set_SSE2_enable(0) unless /sse2 is given, so the CRT math entries
  // (_CIpow, _CIacos, ...) take their x87 bodies. --sse2 1 tests the SSE2 ones.
  u32 gGlobalModeSse2 = 0u;

  void SetFpEnv() noexcept
  {
    unsigned short cw = static_cast<unsigned short>(gControlWord);
    __asm {
      fninit
      fldcw cw
    }
    _mm_setcsr(gMxcsr);
  }

  [[nodiscard]] unsigned short ReadControlWord() noexcept
  {
    unsigned short cw;
    __asm fnstcw cw
    return cw;
  }

  /// x87 stack depth (8 - number of empty tag slots), to catch an unbalanced
  /// call on either side.
  [[nodiscard]] int X87Depth() noexcept
  {
    unsigned short sw;
    __asm fnstsw sw
    const int top = (sw >> 11) & 7;
    return top == 0 ? 0 : 8 - top;
  }

  // SEH has to live in a function without C++ unwinding objects.
  DWORD CallGuarded(void (*fn)(const u32*, u32*), const u32* in, u32* out) noexcept
  {
    __try {
      fn(in, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return GetExceptionCode();
    }
    return 0;
  }

  DWORD CallGuardedInit(const u32 va) noexcept
  {
    __try {
      retail::RunStaticInit(va);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return GetExceptionCode();
    }
    return 0;
  }

  void PrintWords(const char* label, const u32* w, const int n, const char* layout)
  {
    std::printf("      %-7s [%s]\n        ", label, layout);
    for (int i = 0; i < n; ++i) {
      float f;
      std::memcpy(&f, &w[i], 4);
      std::printf("%08X(%.9g)%s", w[i], static_cast<double>(f), (i % 4 == 3 && i + 1 < n) ? "\n        " : " ");
    }
    std::printf("\n");
  }

  [[nodiscard]] bool IsNan(const u32 w) noexcept
  {
    return (w & 0x7F800000u) == 0x7F800000u && (w & 0x007FFFFFu) != 0;
  }

  [[nodiscard]] bool OnlyNanPayloadDiffers(const u32* a, const u32* b, const int n) noexcept
  {
    for (int i = 0; i < n; ++i) {
      if (a[i] != b[i] && !(IsNan(a[i]) && IsNan(b[i]))) {
        return false;
      }
    }
    return true;
  }

  /// Any input word outside the range where x87 _PC_24 and SSE single
  /// arithmetic can only agree: denormal, inf, NaN, or a magnitude whose
  /// square/product leaves the float exponent range.
  [[nodiscard]] bool InputsExtreme(const u32* in, const int n) noexcept
  {
    for (int i = 0; i < n; ++i) {
      const u32 e = (in[i] >> 23) & 0xFFu;
      if ((in[i] & 0x7FFFFFFFu) == 0) {
        continue;
      }
      if (e == 0 || e == 0xFF || e < 127 - 63 || e > 127 + 63) {
        return true;
      }
    }
    return false;
  }

  struct Options
  {
    bool strictNan = false;
    bool skipExtreme = false;
    unsigned long long iters = 1000000ull;
    unsigned long long seed = 0x5EED2007ull;
    int maxMismatch = 5;
    const char* filter = nullptr;
    std::string image;
    bool list = false;
  };

  [[nodiscard]] std::string DefaultImagePath()
  {
    char exe[MAX_PATH];
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string dir = exe;
    // Walk up from the exe until <dir>\bin\2025.7.1\ForgedAlliance.exe exists.
    for (int up = 0; up < 6; ++up) {
      const auto slash = dir.find_last_of("\\/");
      if (slash == std::string::npos) {
        break;
      }
      dir.resize(slash);
      const std::string candidate = dir + "\\bin\\2025.7.1\\ForgedAlliance.exe";
      if (GetFileAttributesA(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return candidate;
      }
    }
    return "bin\\2025.7.1\\ForgedAlliance.exe";
  }

  void Usage()
  {
    std::printf(
      "difffuzz [--iters N] [--seed S] [--filter NAME] [--max-mismatch N]\n"
      "         [--image PATH] [--cw 0xNNNN] [--snan] [--strict-nan] [--list]\n"
      "  --filter   run only targets whose name contains NAME (comma-separated list ok)\n"
      "  --cw       x87 control word (default 0x007F: _PC_24, round-nearest, all masked)\n"
      "  --snan     allow signaling NaNs in generated inputs\n"
      "  --strict-nan  count NaN-payload-only differences as mismatches\n"
      "  --skip-extreme  drop inputs that are denormal/inf/NaN or outside 2^-63..2^63\n"
    );
  }

  [[nodiscard]] bool Matches(const char* name, const char* filter)
  {
    if (filter == nullptr) {
      return true;
    }
    std::string f = filter;
    std::size_t start = 0;
    while (start <= f.size()) {
      const std::size_t comma = f.find(',', start);
      const std::string token = f.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
      if (!token.empty() && std::strstr(name, token.c_str()) != nullptr) {
        return true;
      }
      if (comma == std::string::npos) {
        break;
      }
      start = comma + 1;
    }
    return false;
  }
} // namespace

int main(int argc, char** argv)
{
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--iters") {
      opt.iters = std::strtoull(next(), nullptr, 0);
    } else if (a == "--seed") {
      opt.seed = std::strtoull(next(), nullptr, 0);
    } else if (a == "--filter") {
      opt.filter = next();
    } else if (a == "--max-mismatch") {
      opt.maxMismatch = std::atoi(next());
    } else if (a == "--image") {
      opt.image = next();
    } else if (a == "--sse2") {
      gGlobalModeSse2 = static_cast<u32>(std::strtoul(next(), nullptr, 0));
    } else if (a == "--mxcsr") {
      gMxcsr = static_cast<u32>(std::strtoul(next(), nullptr, 0));
    } else if (a == "--cw") {
      gControlWord = static_cast<u32>(std::strtoul(next(), nullptr, 0));
    } else if (a == "--skip-extreme") {
      opt.skipExtreme = true;
    } else if (a == "--strict-nan") {
      opt.strictNan = true;
    } else if (a == "--snan") {
      difffuzz::gAllowSnan = true;
    } else if (a == "--list") {
      opt.list = true;
    } else {
      Usage();
      return a == "--help" || a == "-h" ? 0 : 2;
    }
  }

  int targetCount = 0;
  const Target* const targets = difffuzz::MathTargets(targetCount);
  if (opt.list) {
    for (int t = 0; t < targetCount; ++t) {
      std::printf("%-22s 0x%08X  %s\n", targets[t].name, targets[t].va, targets[t].source);
    }
    return 0;
  }

  if (opt.image.empty()) {
    opt.image = DefaultImagePath();
  }
  if (GetEnvironmentVariableA("DIFFFUZZ_CHILD", nullptr, 0) == 0) {
    u32 base = 0;
    u32 size = 0;
    if (!difffuzz::ReadImageExtent(opt.image, base, size)) {
      std::fprintf(stderr, "difffuzz: cannot read PE header of %s\n", opt.image.c_str());
      return 3;
    }
    std::fflush(stdout);
    return difffuzz::RelaunchWithPreclaimedImage(base, size);
  }

  difffuzz::RetailImage image;
  std::string error;
  if (!image.Load(opt.image, error)) {
    std::fprintf(stderr, "difffuzz: cannot map %s: %s\n", opt.image.c_str(), error.c_str());
    return 3;
  }
  image.PokeDword(kRetailGlobalModeSse2, gGlobalModeSse2);
  image.PokeDword(kRetailSse2Available, 1u);
  // Our copy (sdk_mirror.cpp) follows, so both sides take the same CRT lane.
  global_mode_sse2 = static_cast<int>(gGlobalModeSse2);

  // Pure retail C-init entries whose BSS results the targets read. They run
  // in the CRT's static-init pass, before any thread sets _PC_24, so under
  // the Windows default control word 0x027F.
  for (const u32 init : kRetailStaticInits) {
    unsigned short defaultCw = 0x027F;
    __asm {
      fninit
      fldcw defaultCw
    }
    if (CallGuardedInit(init) != 0) {
      std::fprintf(stderr, "difffuzz: retail static init 0x%08X faulted\n", init);
      return 3;
    }
  }
  std::printf(
    "difffuzz: mapped %s at 0x%08X (0x%X bytes, %u imports trapped)\n", opt.image.c_str(), image.Base(),
    image.SizeOfImage(), image.ImportCount()
  );

  SetFpEnv();
  std::printf(
    "difffuzz: x87 CW=0x%04X MXCSR=0x%04X seed=0x%llX iters=%llu (%s build)\n", ReadControlWord(), _mm_getcsr(),
    opt.seed, opt.iters,
#ifdef NDEBUG
    "release"
#else
    "debug"
#endif
  );

  int failed = 0;
  int ran = 0;
  for (int t = 0; t < targetCount; ++t) {
    const Target& tg = targets[t];
    if (!Matches(tg.name, opt.filter)) {
      continue;
    }
    ++ran;
    if (!image.IsExecutable(tg.va)) {
      std::printf("[ERR ] %-22s 0x%08X is not in an executable section\n", tg.name, tg.va);
      ++failed;
      continue;
    }

    difffuzz::Rng rng(opt.seed ^ (0x100000001B3ull * (t + 1)));
    unsigned long long done = 0;
    int mismatches = 0;
    unsigned long long nanPayload = 0;
    unsigned long long skipped = 0;
    bool crashed = false;
    for (; done < opt.iters && mismatches < opt.maxMismatch; ++done) {
      u32 in[kMaxWords]{};
      u32 inR[kMaxWords];
      u32 inO[kMaxWords];
      u32 outR[kMaxWords];
      u32 outO[kMaxWords];
      tg.gen(rng, in);
      if (opt.skipExtreme && InputsExtreme(in, tg.inWords)) {
        ++skipped;
        continue;
      }
      std::memcpy(inR, in, sizeof(in));
      std::memcpy(inO, in, sizeof(in));
      for (int k = 0; k < kMaxWords; ++k) {
        outR[k] = kCanary;
        outO[k] = kCanary;
      }

      SetFpEnv();
      const DWORD exR = CallGuarded(tg.retail, inR, outR);
      const int depthR = X87Depth();
      const unsigned short cwR = ReadControlWord();
      SetFpEnv();
      const DWORD exO = CallGuarded(tg.ours, inO, outO);
      const int depthO = X87Depth();
      const unsigned short cwO = ReadControlWord();

      if (exR != 0 || exO != 0) {
        std::printf(
          "[CRASH] %-22s iter %llu: retail exception 0x%08lX, ours 0x%08lX\n", tg.name, done, exR, exO
        );
        PrintWords("input", in, tg.inWords, tg.inLayout);
        crashed = true;
        break;
      }

      bool same = std::memcmp(outR, outO, sizeof(u32) * tg.outWords) == 0 && depthR == depthO && cwR == cwO;
      if (!same && !opt.strictNan && depthR == depthO && cwR == cwO && OnlyNanPayloadDiffers(outR, outO, tg.outWords)) {
        // Both sides produced a NaN in every differing word; only which
        // operand's payload propagated differs (x87 picks the larger
        // significand, SSE the first source operand). Tallied, not failed.
        if (nanPayload++ == 0) {
          std::printf("[nan-payload] %s iter %llu (first example; tallied, not counted as a failure)\n", tg.name, done);
          PrintWords("input", in, tg.inWords, tg.inLayout);
          PrintWords("retail", outR, tg.outWords, tg.outLayout);
          PrintWords("ours", outO, tg.outWords, tg.outLayout);
        }
        same = true;
      }
      if (!same) {
        ++mismatches;
        std::printf(
          "[MISMATCH %d] %s (retail 0x%08X vs %s) iter %llu  inputs: %s\n", mismatches, tg.name, tg.va, tg.source, done,
          InputsExtreme(in, tg.inWords) ? "EXTREME (denormal/inf/NaN or |x| outside 2^-63..2^63)" : "ordinary"
        );
        PrintWords("input", in, tg.inWords, tg.inLayout);
        PrintWords("retail", outR, tg.outWords, tg.outLayout);
        PrintWords("ours", outO, tg.outWords, tg.outLayout);
        if (depthR != depthO || cwR != cwO) {
          std::printf("      x87 depth retail=%d ours=%d, CW retail=0x%04X ours=0x%04X\n", depthR, depthO, cwR, cwO);
        }
      }
    }

    if (crashed) {
      ++failed;
    } else if (mismatches == 0) {
      std::printf(
        "[PASS] %-22s 0x%08X  %llu/%llu bit-identical", tg.name, tg.va, done - skipped - nanPayload, done - skipped
      );
      if (nanPayload != 0) {
        std::printf(" (+%llu NaN-payload-only)", nanPayload);
      }
      if (skipped != 0) {
        std::printf(" (%llu extreme inputs skipped)", skipped);
      }
      std::printf("\n");
    } else {
      ++failed;
      std::printf("[FAIL] %-22s 0x%08X  %d mismatches in first %llu iterations\n", tg.name, tg.va, mismatches, done);
    }
    std::fflush(stdout);
  }

  std::printf("difffuzz: %d/%d targets passed\n", ran - failed, ran);
  return failed == 0 ? 0 : 1;
}
