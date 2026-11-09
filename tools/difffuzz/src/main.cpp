// difffuzz - differential fuzzing of pure leaf functions: the retail
// ForgedAlliance.exe (mapped, never run) against the recovered C++ compiled
// from src. No replay, no engine startup. See ..\README.md.

#include "dump_format.h"
#include "fuzz.h"
#include "pe_image.h"
#include "retail_thunks.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <float.h>
#include <malloc.h>
#include <xmmintrin.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" int global_mode_sse2;

namespace difffuzz
{
  namespace specrun
  {
    // Defined in spec_run.cpp (which owns the Options struct): builds one
    // call stub per spec entry and runs the spec rows, one child process per
    // row (--spec-row selects a single row).
    int RunSpecMain(
      const char* specPath, const unsigned long long iters, const unsigned long long seed, const char* filter,
      const char* dump, const char* values, const long rowIndex, const unsigned rowTimeoutSeconds, RetailImage& image
    );
  } // namespace specrun
} // namespace difffuzz

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
  //   0x00BC74B0  `movss [0x010A9C04], _FInf` - CColPrimitiveBase.cpp's copy
  //               of gpg::pInf, the time limit CColPrimitive_Sphere::CollideBox
  //               (0x004FE902) hands IntrBox3Sphere3f::Find.
  //   0x00BC4930  `movss [0x010A7CB0], [0x00F3F7E0]` (0x7FC00000) - the NaN
  //               CHeightField::Intersection (0x00476F33) fills its own hit
  //               record with.
  //   0x00BC6C20  `movss [0x010A99A4], [0x00F3F7E0]` - the NaN its miss
  //               vector is built from (0x00476FD4); unset, a miss returned 0.
  constexpr u32 kRetailStaticInits[] = {0x00BEDC30u, 0x00BEDC60u, 0x00BC74B0u, 0x00BC4930u, 0x00BC6C20u};

  // The retail allocator's three primitives, all cdecl with the argument at
  // [esp+4]. Its heap is set up by CRT init, which never runs here, so each
  // entry is patched to jump to the harness's own heap. operator new
  // (0x00A825B9 via malloc 0x00957A70), operator delete (0x00957A60 via
  // 0x00957AF0), calloc (0x00957A80, 0x00957AB0) and realloc (0x00957B00) all
  // reach these three, so retail constructors and container growth run.
  //   0x00958B20  malloc_0
  //   0x00958C40  free
  //   0x00957EA0  msize
  // 16-byte aligned, as an SSE2 build may rely on its small-block heap's, and
  // zeroed, so a read of a buffer retail never wrote gives the same value on
  // every run (the golden file needs that). Each block carries its size in a
  // 16-byte header and 16 guard bytes after it; free checks the guard, so a
  // retail write past a block is reported (gRetailHeapOverruns) instead of
  // corrupting the harness heap.
  constexpr std::size_t kHeapHeader = 16;
  constexpr std::size_t kHeapGuard = 16;
  constexpr unsigned char kHeapGuardByte = 0xAB;
  unsigned gRetailHeapOverruns = 0;
  void* __cdecl RetailHeapMalloc(const std::size_t size)
  {
    unsigned char* const block = static_cast<unsigned char*>(_aligned_malloc(kHeapHeader + size + kHeapGuard, 16));
    if (block == nullptr) {
      return nullptr;
    }
    std::memcpy(block, &size, sizeof(size));
    std::memset(block + kHeapHeader, 0, size);
    std::memset(block + kHeapHeader + size, kHeapGuardByte, kHeapGuard);
    return block + kHeapHeader;
  }
  void __cdecl RetailHeapFree(void* const p)
  {
    if (p == nullptr) {
      return;
    }
    unsigned char* const block = static_cast<unsigned char*>(p) - kHeapHeader;
    std::size_t size;
    std::memcpy(&size, block, sizeof(size));
    for (std::size_t i = 0; i < kHeapGuard; ++i) {
      if (block[kHeapHeader + size + i] != kHeapGuardByte) {
        if (gRetailHeapOverruns++ < 8) {
          std::printf("[HEAP] retail wrote past a %u-byte block at +%u\n", static_cast<unsigned>(size), static_cast<unsigned>(size + i));
        }
        break;
      }
    }
    _aligned_free(block);
  }
  std::size_t __cdecl RetailHeapMsize(void* const p)
  {
    if (p == nullptr) {
      return 0;
    }
    std::size_t size;
    std::memcpy(&size, static_cast<unsigned char*>(p) - kHeapHeader, sizeof(size));
    return size;
  }
  struct RetailHeapEntry
  {
    u32 va;
    const void* target;
  };
  const RetailHeapEntry kRetailHeapEntries[] = {
    {0x00958B20u, reinterpret_cast<const void*>(&RetailHeapMalloc)},
    {0x00958C40u, reinterpret_cast<const void*>(&RetailHeapFree)},
    {0x00957EA0u, reinterpret_cast<const void*>(&RetailHeapMsize)},
  };

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

  /// The generators run under the Windows default control word 0x027F (53-bit
  /// precision), as faf_math_dump runs them on every platform: under _PC_24 the
  /// x87 rounds their double arithmetic, and their inputs would differ.
  void SetGeneratorFpEnv() noexcept
  {
    unsigned short cw = 0x027F;
    __asm {
      fninit
      fldcw cw
    }
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

  // A retail or engine call that never returns (a grid walk on an input it
  // cannot finish) would stall the run without a word. The main loop counts
  // its iterations; the watchdog ends the process with the target, iteration
  // and input once one iteration has run for kHangSeconds.
  constexpr int kHangSeconds = 60;
  volatile LONG gWatchCalls = 0;
  const difffuzz::Target* volatile gWatchTarget = nullptr;
  volatile unsigned long long gWatchIteration = 0;
  u32 gWatchInput[difffuzz::kMaxWords];

  DWORD WINAPI WatchdogMain(void*)
  {
    LONG seen = gWatchCalls;
    int still = 0;
    for (;;) {
      Sleep(1000);
      const LONG now = gWatchCalls;
      still = now == seen ? still + 1 : 0;
      seen = now;
      const difffuzz::Target* const tg = gWatchTarget;
      if (still < kHangSeconds || tg == nullptr) {
        continue;
      }
      std::printf("[HANG] %-22s iter %llu: one call ran for %d s\n      input   ", tg->name, gWatchIteration, kHangSeconds);
      for (int i = 0; i < tg->inWords; ++i) {
        std::printf(" %08X", gWatchInput[i]);
      }
      std::printf("  (%s)\n", tg->inLayout);
      std::fflush(stdout);
      ExitProcess(4);
    }
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
    const char* dump = nullptr; // retail's outputs in faf_math_dump's format
    const char* values = nullptr; // retail's values for sampled inputs (dump_format.h)
    const char* lines = nullptr; // retail's values for every input from `from` on
    unsigned long long from = 0;
    const char* spec = nullptr; // tools/retail-recorder's RRS1 file: call every function in it (spec_run.cpp)
    unsigned long long specIters = 100000ull;
    long specRow = -1; // >= 0: run exactly this selected row (a child of the parent spec run)
    unsigned rowTimeout = 300; // per-row child timeout, seconds
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
      "         [--image PATH] [--cw 0xNNNN] [--snan] [--strict-nan] [--list] [--dump FILE] [--values FILE]\n"
      "  --filter   run only targets whose name contains NAME (comma-separated list ok)\n"
      "  --cw       x87 control word (default 0x007F: _PC_24, round-nearest, all masked)\n"
      "  --snan     allow signaling NaNs in generated inputs\n"
      "  --strict-nan  count NaN-payload-only differences as mismatches\n"
      "  --skip-extreme  drop inputs that are denormal/inf/NaN or outside 2^-63..2^63\n"
      "  --dump FILE  also write retail's outputs as faf_math_dump writes ours (dump_format.h)\n"
      "  --values FILE  also write retail's values for up to 64 sampled inputs per target\n"
      "  --lines FILE [--from N]  also write retail's values for every input from iteration N on\n"
      "                 (faf_math_dump --lines writes ours in the same format, to diff a failing block)\n"
      "  --spec FILE  call every auto-callable function of the retail-recorder spec file directly\n"
      "                 (spec rows, no hand-written thunks); --dump/--values then write those rows' files\n"
      "  --spec-iters N  iterations per spec row (default 100000)\n"
      "  --spec-row N  run exactly spec row N in this process (used internally by --spec)\n"
      "  --row-timeout S  per-row child timeout in seconds (default 300)\n"
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
    } else if (a == "--dump") {
      opt.dump = next();
    } else if (a == "--values") {
      opt.values = next();
    } else if (a == "--lines") {
      opt.lines = next();
    } else if (a == "--from") {
      opt.from = std::strtoull(next(), nullptr, 0);
    } else if (a == "--spec") {
      opt.spec = next();
    } else if (a == "--spec-iters") {
      opt.specIters = std::strtoull(next(), nullptr, 0);
    } else if (a == "--spec-row") {
      opt.specRow = std::strtol(next(), nullptr, 0);
    } else if (a == "--row-timeout") {
      opt.rowTimeout = static_cast<unsigned>(std::strtoul(next(), nullptr, 0));
    } else {
      Usage();
      return a == "--help" || a == "-h" ? 0 : 2;
    }
  }

  if ((opt.dump != nullptr || opt.values != nullptr || opt.lines != nullptr) && opt.skipExtreme) {
    std::fprintf(stderr, "difffuzz: --dump, --values and --lines need every iteration; drop --skip-extreme\n");
    return 2;
  }

  int targetCount = 0;
  const Target* const targets = difffuzz::AllTargets(targetCount);
  if (opt.list) {
    for (int t = 0; t < targetCount; ++t) {
      std::printf("%-22s 0x%08X  %s\n", targets[t].name, targets[t].va, targets[t].source);
    }
    return 0;
  }

  if (opt.image.empty()) {
    opt.image = DefaultImagePath();
  }

  // The spec lane (tools/retail-recorder's RRS1 file), parent mode: it spawns
  // one child per row (--spec-row), and each child maps the retail image in
  // its own process, so the parent never maps it (its own mapping at
  // 0x00400000 would block every child).
  if (opt.spec != nullptr && opt.specRow < 0) {
    difffuzz::RetailImage unused;
    return difffuzz::specrun::RunSpecMain(
      opt.spec, opt.specIters, opt.seed, opt.filter, opt.dump, opt.values, opt.specRow, opt.rowTimeout, unused
    );
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
  for (const RetailHeapEntry& entry : kRetailHeapEntries) {
    if (!image.PatchJump(entry.va, entry.target)) {
      std::fprintf(stderr, "difffuzz: cannot redirect the retail allocator at 0x%08X\n", entry.va);
      return 3;
    }
  }
  if (HANDLE watchdog = CreateThread(nullptr, 0, &WatchdogMain, nullptr, 0, nullptr)) {
    CloseHandle(watchdog);
  }

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

  // The spec lane, child mode (--spec-row): this process has the image
  // mapped and runs exactly one row.
  if (opt.spec != nullptr) {
    SetFpEnv();
    return difffuzz::specrun::RunSpecMain(
      opt.spec, opt.specIters, opt.seed, opt.filter, opt.dump, opt.values, opt.specRow, opt.rowTimeout, image
    );
  }

  std::FILE* dumpFile = nullptr;
  if (opt.dump != nullptr) {
    dumpFile = std::fopen(opt.dump, "wb");
    if (dumpFile == nullptr) {
      std::fprintf(stderr, "difffuzz: cannot write %s\n", opt.dump);
      return 3;
    }
  }
  std::FILE* valuesFile = nullptr;
  if (opt.values != nullptr) {
    valuesFile = std::fopen(opt.values, "wb");
    if (valuesFile == nullptr) {
      std::fprintf(stderr, "difffuzz: cannot write %s\n", opt.values);
      return 3;
    }
  }
  std::FILE* linesFile = nullptr;
  if (opt.lines != nullptr) {
    linesFile = std::fopen(opt.lines, "wb");
    if (linesFile == nullptr) {
      std::fprintf(stderr, "difffuzz: cannot write %s\n", opt.lines);
      return 3;
    }
  }
  bool dumpComplete = true;

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
    difffuzz::BlockDump dump;
    difffuzz::ValueSampler sampler;
    const unsigned overrunsBefore = gRetailHeapOverruns;
    for (; done < opt.iters && mismatches < opt.maxMismatch; ++done) {
      u32 in[kMaxWords]{};
      u32 inR[kMaxWords];
      u32 inO[kMaxWords];
      u32 outR[kMaxWords];
      u32 outO[kMaxWords];
      SetGeneratorFpEnv();
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

      std::memcpy(gWatchInput, in, sizeof(in));
      gWatchIteration = done;
      gWatchTarget = &tg;
      InterlockedIncrement(&gWatchCalls);

      SetFpEnv();
      const DWORD exR = CallGuarded(tg.retail, inR, outR);
      const int depthR = X87Depth();
      const unsigned short cwR = ReadControlWord();
      // A retail-only row (no engine function in this build) compares retail
      // with itself: the crash, x87 depth and control-word checks still run.
      DWORD exO = 0;
      int depthO = depthR;
      unsigned short cwO = cwR;
      if (tg.ours != nullptr) {
        SetFpEnv();
        exO = CallGuarded(tg.ours, inO, outO);
        depthO = X87Depth();
        cwO = ReadControlWord();
      } else {
        std::memcpy(outO, outR, sizeof(outR));
        if (depthR != 0 || cwR != static_cast<unsigned short>(gControlWord)) {
          depthO = 0;
          cwO = static_cast<unsigned short>(gControlWord);
        }
      }

      if (exR != 0 || exO != 0) {
        std::printf(
          "[CRASH] %-22s iter %llu: retail exception 0x%08lX, ours 0x%08lX\n", tg.name, done, exR, exO
        );
        PrintWords("input", in, tg.inWords, tg.inLayout);
        crashed = true;
        break;
      }

      bool same = std::memcmp(outR, outO, sizeof(u32) * tg.outWords) == 0 && depthR == depthO && cwR == cwO;
      if (!same && !opt.strictNan && !tg.rawOutputs && depthR == depthO && cwR == cwO && OnlyNanPayloadDiffers(outR, outO, tg.outWords)) {
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
      if (dumpFile != nullptr || valuesFile != nullptr || linesFile != nullptr) {
        u32 retailWords[kMaxWords];
        std::memcpy(retailWords, outR, sizeof(outR));
        if (!opt.strictNan && !tg.rawOutputs) {
          difffuzz::CanonicalizeNans(retailWords, tg.outWords);
        }
        if (dumpFile != nullptr) {
          dump.Add(dumpFile, tg.name, done, opt.iters, in, tg.inWords, retailWords, tg.outWords);
        }
        if (valuesFile != nullptr && sampler.Take(in, tg.inWords, retailWords, tg.outWords)) {
          difffuzz::WriteValueLine(valuesFile, tg.name, done, in, tg.inWords, retailWords, tg.outWords);
        }
        if (linesFile != nullptr && done >= opt.from) {
          difffuzz::WriteValueLine(linesFile, tg.name, done, in, tg.inWords, retailWords, tg.outWords);
        }
      }
    }
    if (done != opt.iters) {
      dumpComplete = false;
    }

    if (gRetailHeapOverruns != overrunsBefore) {
      std::printf(
        "[HEAP] %-22s 0x%08X  retail wrote past %u heap block(s)\n", tg.name, tg.va, gRetailHeapOverruns - overrunsBefore
      );
      crashed = true;
    }
    if (crashed) {
      ++failed;
    } else if (mismatches == 0 && tg.ours == nullptr) {
      std::printf("[RETAIL] %-22s 0x%08X  %llu retail calls (ours: faf_math_dump)\n", tg.name, tg.va, done - skipped);
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
  if (dumpFile != nullptr) {
    std::fclose(dumpFile);
    std::printf(
      "difffuzz: retail outputs %s %s\n", dumpComplete ? "written to" : "INCOMPLETE (a target stopped early) in", opt.dump
    );
  }
  if (valuesFile != nullptr) {
    std::fclose(valuesFile);
    std::printf(
      "difffuzz: retail values %s %s\n", dumpComplete ? "written to" : "INCOMPLETE (a target stopped early) in", opt.values
    );
  }
  if (linesFile != nullptr) {
    std::fclose(linesFile);
  }
  return failed == 0 && dumpComplete ? 0 : 1;
}
