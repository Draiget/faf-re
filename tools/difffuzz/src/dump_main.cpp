// faf_math_dump (dedicated-server plan WPR.21): the difffuzz targets' own side
// only, linked against the engine's objects, on any platform. Every target's
// generator runs with difffuzz's seed and stream, our function runs on each
// input, and the inputs and outputs are hashed per block of iterations
// (dump_format.h). Windows x64, Windows x86 and Linux x64 must write the file
// retail writes (difffuzz --dump), tests/math_dump/golden.txt. See
// ..\README.md, "Cross-platform dump".

#include "dump_format.h"
#include "fuzz.h"

#include "legacy/math/X87Math.h"
#include "platform/X87Precision.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <thread>

namespace
{
  using difffuzz::kCanary;
  using difffuzz::kMaxWords;
  using difffuzz::Target;
  using u32 = std::uint32_t;

  struct Options
  {
    unsigned long long iters = 1000000ull;
    unsigned long long seed = 0x5EED2007ull; // difffuzz's default
    const char* filter = nullptr;
    const char* out = nullptr;
    const char* check = nullptr;
    const char* values = nullptr;
    bool lines = false;
    unsigned long long from = 0;
    bool strictNan = false;
  };

  const char* PlatformName()
  {
#if defined(_WIN32) && defined(_M_X64)
    return "windows-x64";
#elif defined(_WIN32)
    return "windows-x86";
#elif defined(__x86_64__)
    return "linux-x64";
#else
    return "unknown";
#endif
  }

  [[nodiscard]] bool Matches(const char* name, const char* filter)
  {
    if (filter == nullptr) {
      return true;
    }
    const std::string f = filter;
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

  // The generator runs at the x87 default precision (53 bits) and our function
  // in the simulation's (24 bits). On x86, clang converts the generator's
  // 64-bit integers to double with x87 `fild`, so under 24 bits its inputs
  // would differ from x64's. The x64 builds do nothing here.
  void GeneratorFpEnv() noexcept
  {
#if defined(_PC_53)
    platform::SetX87PrecisionControl(_PC_53);
#endif
  }
  void SimFpEnv() noexcept
  {
#if defined(_PC_24)
    platform::SetX87PrecisionControl(_PC_24);
#endif
  }

  void PrintWords(const u32* words, const int count)
  {
    for (int i = 0; i < count; ++i) {
      std::printf(" %08X", words[i]);
    }
  }

  void Usage()
  {
    std::printf(
      "faf_math_dump (--out FILE | --check GOLDEN | --values VALUES | --check GOLDEN --values VALUES)\n"
      "              [--iters N] [--seed S] [--filter a,b] [--strict-nan] [--lines [--from N]]\n"
      "  --out    writes \"target block input-hash output-hash\" per %llu iterations\n"
      "  --check  writes the same lines and compares them with GOLDEN (exit 1 on a difference)\n"
      "  --values runs our function on every \"target iteration inputs -> outputs\" line of VALUES\n"
      "           (retail's, from difffuzz --values) and compares the outputs (exit 1 on a difference)\n"
      "  --lines  writes every \"target iteration inputs -> outputs\" from iteration N on instead\n"
      "  --strict-nan  keeps NaN payloads in the outputs (not with --values: its NaNs are canonical)\n",
      difffuzz::kDumpBlock
    );
  }

  // A call that never returns (a grid walk on an input it cannot finish) would
  // hold the post-build check forever. RunOurs counts its calls; the watchdog
  // ends the process with the target, iteration and input once one call has
  // run for kHangSeconds.
  constexpr int kHangSeconds = 60;
  std::atomic<unsigned long long> gCalls{0};
  std::atomic<const Target*> gTarget{nullptr};
  std::atomic<unsigned long long> gIteration{0};
  u32 gInput[kMaxWords];

  void StartWatchdog()
  {
    std::thread([] {
      unsigned long long seen = gCalls.load();
      int still = 0;
      for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        const unsigned long long now = gCalls.load();
        still = now == seen ? still + 1 : 0;
        seen = now;
        const Target* const tg = gTarget.load();
        if (still < kHangSeconds || tg == nullptr) {
          continue;
        }
        std::printf("HANG %s iteration %llu: one call ran for %d s\n  input   ", tg->name, gIteration.load(), kHangSeconds);
        PrintWords(gInput, tg->inWords);
        std::printf("  (%s)\n", tg->inLayout);
        std::fflush(stdout);
        std::_Exit(4);
      }
    }).detach();
  }

  /// Our function's outputs for one input, in the simulation's FP environment.
  void RunOurs(const Target& tg, const u32* in, u32* outWords, const bool strictNan, const unsigned long long iteration)
  {
    std::memcpy(gInput, in, sizeof(u32) * tg.inWords);
    gIteration.store(iteration);
    gTarget.store(&tg);
    gCalls.fetch_add(1);
    for (int i = 0; i < kMaxWords; ++i) {
      outWords[i] = kCanary;
    }
    u32 inCopy[kMaxWords];
    std::memcpy(inCopy, in, sizeof(inCopy));
    SimFpEnv();
    tg.ours(inCopy, outWords);
    if (!strictNan && !tg.rawOutputs) {
      difffuzz::CanonicalizeNans(outWords, tg.outWords);
    }
  }

  /// Every line of the values file whose target matches the filter: our outputs
  /// for its inputs against retail's. A selected target with no line fails too
  /// (a new target needs a new values file). Returns the number of failures.
  int CheckValues(const Options& opt)
  {
    std::FILE* const file = std::fopen(opt.values, "rb");
    if (file == nullptr) {
      std::fprintf(stderr, "faf_math_dump: cannot read %s\n", opt.values);
      return -1;
    }
    int targetCount = 0;
    const Target* const targets = difffuzz::AllTargets(targetCount);
    std::map<std::string, int> byName;
    for (int t = 0; t < targetCount; ++t) {
      byName[targets[t].name] = t;
    }
    std::map<int, int> casesPerTarget;
    int cases = 0;
    int bad = 0;
    constexpr int kPrintLimit = 20;
    std::string line;
    char buffer[1024];
    int lineNumber = 0;
    while (std::fgets(buffer, sizeof(buffer), file) != nullptr) {
      line += buffer;
      if (line.empty() || (line.back() != '\n' && !std::feof(file))) {
        continue; // a line longer than the buffer: keep reading it
      }
      ++lineNumber;
      while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
      }
      const std::string text = line;
      line.clear();
      if (text.empty() || text[0] == '#') {
        continue;
      }

      const std::size_t nameEnd = text.find(' ');
      const std::size_t arrow = text.find(" ->");
      const std::string name = text.substr(0, nameEnd);
      const auto found = byName.find(name);
      if (nameEnd == std::string::npos || arrow == std::string::npos || found == byName.end()) {
        std::printf("BAD %s:%d: not a line of a known target: %s\n", opt.values, lineNumber, text.c_str());
        ++bad;
        continue;
      }
      const Target& tg = targets[found->second];
      if (!Matches(tg.name, opt.filter)) {
        continue;
      }
      u32 in[kMaxWords]{};
      u32 expected[kMaxWords]{};
      int inCount = 0;
      int outCount = 0;
      char* cursor = nullptr;
      const unsigned long long iteration = std::strtoull(text.c_str() + nameEnd + 1, &cursor, 10);
      const char* const inputsEnd = text.c_str() + arrow;
      while (cursor < inputsEnd && inCount < kMaxWords) {
        char* next = nullptr;
        const unsigned long word = std::strtoul(cursor, &next, 16);
        if (next == cursor || next > inputsEnd) {
          break;
        }
        in[inCount++] = static_cast<u32>(word);
        cursor = next;
      }
      const auto onlySpaces = [](const char* from, const char* to) {
        for (; from < to && *from != '\0'; ++from) {
          if (*from != ' ') {
            return false;
          }
        }
        return true;
      };
      bool wellFormed = onlySpaces(cursor, inputsEnd);
      cursor = const_cast<char*>(inputsEnd) + 3;
      while (*cursor != '\0' && outCount < kMaxWords) {
        char* next = nullptr;
        const unsigned long word = std::strtoul(cursor, &next, 16);
        if (next == cursor) {
          break;
        }
        expected[outCount++] = static_cast<u32>(word);
        cursor = next;
      }
      wellFormed = wellFormed && onlySpaces(cursor, cursor + std::strlen(cursor));
      if (!wellFormed) {
        std::printf("BAD %s:%d: not hex words around \" ->\": %s\n", opt.values, lineNumber, text.c_str());
        ++bad;
        continue;
      }
      if (inCount != tg.inWords || outCount != tg.outWords) {
        std::printf(
          "BAD %s:%d: %s takes %d input and %d output words, the line has %d and %d\n", opt.values, lineNumber, tg.name,
          tg.inWords, tg.outWords, inCount, outCount
        );
        ++bad;
        continue;
      }

      u32 ours[kMaxWords];
      RunOurs(tg, in, ours, false, iteration);
      ++cases;
      ++casesPerTarget[found->second];
      if (std::memcmp(ours, expected, sizeof(u32) * tg.outWords) != 0) {
        if (bad < kPrintLimit) {
          std::printf("FAIL %s iteration %llu\n  input   ", tg.name, iteration);
          PrintWords(in, tg.inWords);
          std::printf("  (%s)\n  retail  ", tg.inLayout);
          PrintWords(expected, tg.outWords);
          std::printf("  (%s)\n  ours    ", tg.outLayout);
          PrintWords(ours, tg.outWords);
          std::printf("\n");
        }
        ++bad;
      }
    }
    std::fclose(file);

    int covered = 0;
    for (int t = 0; t < targetCount; ++t) {
      if (!Matches(targets[t].name, opt.filter)) {
        continue;
      }
      if (casesPerTarget.count(t) != 0) {
        ++covered;
      } else {
        std::printf("MISSING %s: no line in %s (a new target needs a new values file)\n", targets[t].name, opt.values);
        ++bad;
      }
    }
    std::printf(
      "faf_math_dump --values: %d cases over %d targets, %d differ or missing from %s\n", cases, covered, bad, opt.values
    );
    return bad;
  }

  void Run(const Options& opt, std::FILE* out, int& ran)
  {
    int targetCount = 0;
    const Target* const targets = difffuzz::AllTargets(targetCount);
    for (int t = 0; t < targetCount; ++t) {
      const Target& tg = targets[t];
      if (!Matches(tg.name, opt.filter)) {
        continue;
      }
      ++ran;
      // difffuzz's per-target stream, so a line here names the same input there.
      difffuzz::Rng rng(opt.seed ^ (0x100000001B3ull * (t + 1)));
      difffuzz::BlockDump dump;
      for (unsigned long long done = 0; done < opt.iters; ++done) {
        u32 in[kMaxWords]{};
        u32 outWords[kMaxWords];
        GeneratorFpEnv();
        tg.gen(rng, in);
        RunOurs(tg, in, outWords, opt.strictNan, done);

        if (opt.lines) {
          if (done >= opt.from) {
            difffuzz::WriteValueLine(out, tg.name, done, in, tg.inWords, outWords, tg.outWords);
          }
          continue;
        }
        dump.Add(out, tg.name, done, opt.iters, in, tg.inWords, outWords, tg.outWords);
      }
    }
  }

  /// "target block" -> the rest of the line, for every line of a dump file.
  [[nodiscard]] bool ReadDump(std::FILE* file, std::map<std::string, std::string>& lines)
  {
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), file) != nullptr) {
      std::string line = buffer;
      while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
      }
      if (line.empty() || line[0] == '#') {
        continue;
      }
      const std::size_t first = line.find(' ');
      const std::size_t second = first == std::string::npos ? first : line.find(' ', first + 1);
      if (second == std::string::npos) {
        return false;
      }
      lines[line.substr(0, second)] = line.substr(second + 1);
    }
    return true;
  }

  /// Every line this run wrote must be in the golden file with the same hashes.
  /// Returns the number of differing or missing lines.
  int Check(std::FILE* produced, const char* goldenPath)
  {
    std::FILE* const golden = std::fopen(goldenPath, "rb");
    std::map<std::string, std::string> expected;
    if (golden == nullptr || !ReadDump(golden, expected)) {
      std::fprintf(stderr, "faf_math_dump: cannot read %s\n", goldenPath);
      if (golden != nullptr) {
        std::fclose(golden);
      }
      return -1;
    }
    std::fclose(golden);

    std::rewind(produced);
    std::map<std::string, std::string> actual;
    if (!ReadDump(produced, actual)) {
      return -1;
    }
    int bad = 0;
    for (const auto& [key, hashes] : actual) {
      const auto it = expected.find(key);
      if (it == expected.end()) {
        std::printf("MISSING %s: not in %s (iterations past the golden file's, or a new target)\n", key.c_str(), goldenPath);
        ++bad;
      } else if (it->second != hashes) {
        const bool inputs = it->second.substr(0, 16) != hashes.substr(0, 16);
        std::printf(
          "FAIL %s: %s differ (golden %s, here %s)\n", key.c_str(), inputs ? "inputs" : "outputs", it->second.c_str(),
          hashes.c_str()
        );
        ++bad;
      }
    }
    std::printf("faf_math_dump --check: %zu blocks, %d differ from %s\n", actual.size(), bad, goldenPath);
    return bad;
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
    } else if (a == "--out") {
      opt.out = next();
    } else if (a == "--check") {
      opt.check = next();
    } else if (a == "--values") {
      opt.values = next();
    } else if (a == "--lines") {
      opt.lines = true;
    } else if (a == "--from") {
      opt.from = std::strtoull(next(), nullptr, 0);
    } else if (a == "--strict-nan") {
      opt.strictNan = true;
    } else {
      Usage();
      return a == "--help" || a == "-h" ? 0 : 2;
    }
  }
  const bool hashes = opt.out != nullptr || opt.check != nullptr;
  if ((opt.out != nullptr && opt.check != nullptr) || (!hashes && opt.values == nullptr)
      || (opt.check != nullptr && opt.lines) || (opt.values != nullptr && (opt.lines || opt.strictNan))) {
    Usage();
    return 2;
  }

  // The simulation thread's floating-point environment, as faf_sim_math_tests
  // sets it: x87 precision at 24 bits on x86 (SimFpEnv, per call; the x64
  // helpers set it themselves) and the CRT's SSE2 math lane off. difffuzz
  // compares under the same environment (CW 0x007F, global_mode_sse2 = 0).
  (void)SetSse2Mode(0);
  StartWatchdog();

  int valuesBad = 0;
  if (opt.values != nullptr) {
    valuesBad = CheckValues(opt);
    if (!hashes) {
      return valuesBad < 0 ? 3 : (valuesBad == 0 ? 0 : 1);
    }
  }

  std::FILE* const out = opt.out != nullptr ? std::fopen(opt.out, "wb") : std::tmpfile();
  if (out == nullptr) {
    std::fprintf(stderr, "faf_math_dump: cannot write %s\n", opt.out != nullptr ? opt.out : "a temporary file");
    return 3;
  }

  int ran = 0;
  Run(opt, out, ran);
  std::printf(
    "faf_math_dump (%s): %d targets, %llu iterations each, seed 0x%llX%s\n", PlatformName(), ran, opt.iters, opt.seed,
    opt.strictNan ? ", strict NaN" : ""
  );
  int result = ran == 0 ? 2 : 0;
  if (opt.check != nullptr && ran != 0) {
    const int bad = Check(out, opt.check);
    result = bad < 0 ? 3 : (bad == 0 ? 0 : 1);
  }
  std::fclose(out);
  if (valuesBad != 0 && result == 0) {
    result = valuesBad < 0 ? 3 : 1;
  }
  return result;
}
