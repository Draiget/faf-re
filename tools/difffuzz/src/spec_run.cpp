// The --spec lane of difffuzz: reads tools/retail-recorder's RRS1 spec file
// (spec.py) and calls every selected function in the mapped retail image
// directly, with generated inputs, writing golden (--dump) and values
// (--values) files in faf_math_dump's formats. This is the automatic part of
// the checksum coverage: many functions get retail rows without a
// hand-written thunk each.
//
// A row runs in a child process (the parent spawns itself with --spec-row):
// a function whose error path reaches the OS (an assert calling
// GetModuleFileNameA, retail's own SEH handler) can kill its process in a way
// the in-process SEH guard cannot catch, and one such row must not end the
// whole run. The parent waits with a timeout per row, so a hung call (a grid
// walk that never finishes) is killed and reported too. Each child re-does
// the image pre-claim relaunch, so the 0x00400000 mapping works.
//
// What a row is: the spec's idea of a plain cdecl function - every argument a
// scalar the Hex-Rays prototype and the asm agree on, on the stack, with a
// non-void result. Functions with a pointer or struct argument (the spec's
// unhashed ones), a register argument (often an unmarked `this`) or no result
// are counted and skipped: they need an object builder or a hand-written row
// that reads the asm first. Spec rows are retail's side only; an ours-side
// adapter still comes one at a time (a difffuzz/faf_math_dump row with a
// generator and an ENGINE_ONLY ours), which is what turns a spec row into a
// checked test.

#include "fuzz.h"
#include "pe_image.h"
#include "spec_rows.h"
#include "spec_stub.h"

#include "dump_format.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace difffuzz
{
  namespace specrun
  {
    using u32 = std::uint32_t;

    struct Options
    {
      const char* specPath = nullptr;
      unsigned long long iters = 100000ull;
      unsigned long long seed = 0x5EED2007ull; // difffuzz's default
      const char* filter = nullptr;
      const char* dump = nullptr;
      const char* values = nullptr;
      long rowIndex = -1; // >= 0: run exactly this selected row (child mode)
      unsigned maxPrint = 5;
      unsigned rowTimeoutSeconds = 300;
    };

    // A comma-separated substring filter, as difffuzz's --filter: a token
    // matches when the row name contains it (compared at the token's length,
    // so the token needs no terminator of its own).
    [[nodiscard]] bool Matches(const char* name, const char* filter)
    {
      if (filter == nullptr) {
        return true;
      }
      for (const char* f = filter; *f != '\0';) {
        const char* start = f;
        while (*f != '\0' && *f != ',') {
          ++f;
        }
        const std::size_t len = static_cast<std::size_t>(f - start);
        if (len > 0) {
          for (const char* h = name; *h != '\0'; ++h) {
            std::size_t i = 0;
            while (i < len && h[i] == start[i]) {
              ++i;
            }
            if (i == len) {
              return true;
            }
          }
        }
        if (*f == ',') {
          ++f;
        }
      }
      return false;
    }

    DWORD CallGuarded(const spec::StubFn fn, const u32* in, u32* out) noexcept
    {
      __try {
        fn(in, out);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
      }
      return 0;
    }

    /// One row, in this process: call the retail function `iters` times and
    /// write its dump/values lines to already-open files. Returns 0 when every
    /// call survived.
    int RunRow(
      const spec::Row& r, const unsigned long long iters, const unsigned long long seed, const std::size_t rowIndex,
      std::FILE* dumpFile, std::FILE* valuesFile
    )
    {
      constexpr int kStubSpacing = 128;
      unsigned char* const code = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, kStubSpacing, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
      );
      if (code == nullptr) {
        std::fprintf(stderr, "difffuzz --spec: cannot allocate the stub buffer\n");
        return 3;
      }
      const int len = spec::BuildStub(*r.entry, code);
      if (len <= 0 || len > kStubSpacing) {
        std::printf("[ERR ] %-16s stub did not fit (%d bytes)\n", r.name, len);
        VirtualFree(code, 0, MEM_RELEASE);
        return 3;
      }
      const spec::StubFn stub = reinterpret_cast<spec::StubFn>(code);

      // difffuzz's per-target stream, so a line here names the same input in a
      // later run of the same row.
      Rng rng(seed ^ (0x100000001B3ull * (rowIndex + 1)));
      difffuzz::BlockDump dump;
      difffuzz::ValueSampler sampler;
      u32 in[spec::kMaxSpecWords]{};
      u32 out[2];
      unsigned long long done = 0;
      for (; done < iters; ++done) {
        spec::GenSpecInputs(rng, in, r.inWords);
        out[0] = out[1] = kCanary;
        const DWORD ex = CallGuarded(stub, in, out);
        if (ex != 0) {
          std::printf("[CRASH] %-16s iter %llu: exception 0x%08lX\n", r.name, done, ex);
          std::printf("      input   ");
          for (int w = 0; w < r.inWords; ++w) {
            std::printf(" %08X", in[w]);
          }
          std::printf("\n");
          break;
        }
        if (r.floatOut) {
          difffuzz::CanonicalizeNans(out, r.outWords);
        }
        if (dumpFile != nullptr) {
          dump.Add(dumpFile, r.name, done, iters, in, r.inWords, out, r.outWords);
        }
        if (valuesFile != nullptr && sampler.Take(in, r.inWords, out, r.outWords)) {
          difffuzz::WriteValueLine(valuesFile, r.name, done, in, r.inWords, out, r.outWords);
        }
      }
      VirtualFree(code, 0, MEM_RELEASE);
      return done == iters ? 0 : 1;
    }

    /// The child's own dump/values path for one row, next to the parent's
    /// files: "<parent>.row<N>.tmp".
    void RowFilePath(const char* parent, const std::size_t row, char* out, const std::size_t outBytes)
    {
      std::snprintf(out, outBytes, "%s.row%zu.tmp", parent != nullptr ? parent : "difffuzz_spec", row);
    }

    /// Spawns this exe with `--spec-row row` and waits up to the timeout.
    /// Returns the child's exit code, or -1 when it could not start, -2 on
    /// timeout (the child is killed).
    int RunRowChild(const Options& opt, const std::size_t row, const char* dumpTmp, const char* valuesTmp)
    {
      char exe[MAX_PATH];
      GetModuleFileNameA(nullptr, exe, MAX_PATH);
      char cmd[2048];
      std::snprintf(
        cmd, sizeof(cmd), "\"%s\" --spec \"%s\" --spec-row %zu --spec-iters %llu --seed %llu", exe, opt.specPath, row,
        opt.iters, opt.seed
      );
      if (dumpTmp != nullptr) {
        char tail[512];
        std::snprintf(tail, sizeof(tail), " --dump \"%s\"", dumpTmp);
        std::strncat(cmd, tail, sizeof(cmd) - std::strlen(cmd) - 1);
      }
      if (valuesTmp != nullptr) {
        char tail[512];
        std::snprintf(tail, sizeof(tail), " --values \"%s\"", valuesTmp);
        std::strncat(cmd, tail, sizeof(cmd) - std::strlen(cmd) - 1);
      }

      STARTUPINFOA si{};
      si.cb = sizeof(si);
      PROCESS_INFORMATION pi{};
      if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return -1;
      }
      CloseHandle(pi.hThread);
      const DWORD waited = WaitForSingleObject(pi.hProcess, opt.rowTimeoutSeconds * 1000ull);
      int code = -2;
      if (waited == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        code = static_cast<int>(exitCode);
      } else {
        TerminateProcess(pi.hProcess, static_cast<UINT>(-2));
      }
      CloseHandle(pi.hProcess);
      return code;
    }

    /// Appends one file's contents to another (both binary).
    bool AppendFile(const char* from, std::FILE* to)
    {
      std::FILE* f = std::fopen(from, "rb");
      if (f == nullptr) {
        return false;
      }
      char buffer[4096];
      std::size_t n;
      while ((n = std::fread(buffer, 1, sizeof(buffer), f)) != 0) {
        std::fwrite(buffer, 1, n, to);
      }
      std::fclose(f);
      return true;
    }

    int Run(const Options& opt, RetailImage& image)
    {
      spec::File file;
      std::string error;
      if (!spec::ReadSpec(opt.specPath, file, error)) {
        std::fprintf(stderr, "difffuzz --spec: %s: %s\n", opt.specPath, error.c_str());
        return 3;
      }
      std::vector<spec::Row> rows;
      std::vector<std::pair<std::string, int>> skipped;
      spec::SelectValueRows(file, rows, skipped);
      std::printf("difffuzz --spec: %zu entries, %zu auto rows\n", file.entries.size(), rows.size());
      for (const auto& why : skipped) {
        std::printf("  skipped %4d  %s\n", why.second, why.first.c_str());
      }

      // Child mode (--spec-row): run exactly one row in this process, alone.
      if (opt.rowIndex >= 0) {
        if (static_cast<std::size_t>(opt.rowIndex) >= rows.size()) {
          std::fprintf(stderr, "difffuzz --spec-row: index %ld out of %zu rows\n", opt.rowIndex, rows.size());
          return 3;
        }
        const spec::Row& r = rows[static_cast<std::size_t>(opt.rowIndex)];
        if (!image.IsExecutable(r.va)) {
          std::fprintf(stderr, "difffuzz --spec-row: 0x%08X is not executable\n", r.va);
          return 3;
        }
        std::FILE* dumpFile = opt.dump != nullptr ? std::fopen(opt.dump, "wb") : nullptr;
        std::FILE* valuesFile = opt.values != nullptr ? std::fopen(opt.values, "wb") : nullptr;
        const int rc = RunRow(r, opt.iters, opt.seed, static_cast<std::size_t>(opt.rowIndex), dumpFile, valuesFile);
        if (dumpFile != nullptr) {
          std::fclose(dumpFile);
        }
        if (valuesFile != nullptr) {
          std::fclose(valuesFile);
        }
        return rc;
      }

      // Parent mode: one child per selected row.
      std::FILE* dumpFile = opt.dump != nullptr ? std::fopen(opt.dump, "wb") : nullptr;
      std::FILE* valuesFile = opt.values != nullptr ? std::fopen(opt.values, "wb") : nullptr;
      int ran = 0;
      int failed = 0;
      unsigned printed = 0;
      for (std::size_t i = 0; i < rows.size(); ++i) {
        const spec::Row& r = rows[i];
        if (!Matches(r.name, opt.filter)) {
          continue;
        }
        ++ran;
        char dumpTmp[MAX_PATH + 64] = {};
        char valuesTmp[MAX_PATH + 64] = {};
        if (dumpFile != nullptr) {
          RowFilePath(opt.dump, i, dumpTmp, sizeof(dumpTmp));
        }
        if (valuesFile != nullptr) {
          RowFilePath(opt.values, i, valuesTmp, sizeof(valuesTmp));
        }
        const int rc =
          RunRowChild(opt, i, dumpTmp[0] != 0 ? dumpTmp : nullptr, valuesTmp[0] != 0 ? valuesTmp : nullptr);
        bool ok = rc == 0;
        if (ok && dumpTmp[0] != 0) {
          ok = AppendFile(dumpTmp, dumpFile);
          DeleteFileA(dumpTmp);
        }
        if (ok && valuesTmp[0] != 0) {
          ok = AppendFile(valuesTmp, valuesFile);
          DeleteFileA(valuesTmp);
        }
        if (ok) {
          std::printf(
            "[RETAIL] %-16s 0x%08X  %llu calls, %d in / %d out words\n", r.name, r.va, opt.iters, r.inWords, r.outWords
          );
        } else {
          ++failed;
          if (printed++ < opt.maxPrint) {
            std::printf(
              "[FAIL ] %-16s 0x%08X  %s\n", r.name, r.va,
              rc == -1 ? "could not start the child" : rc == -2 ? "timed out (killed)" : "crashed"
            );
          }
        }
        std::fflush(stdout);
      }
      if (dumpFile != nullptr) {
        std::fclose(dumpFile);
      }
      if (valuesFile != nullptr) {
        std::fclose(valuesFile);
      }
      std::printf("difffuzz --spec: %d rows run, %d failed\n", ran, failed);
      return failed == 0 ? 0 : 1;
    }
  } // namespace specrun
} // namespace difffuzz

namespace difffuzz
{
  namespace specrun
  {
    int RunSpecMain(
      const char* specPath, const unsigned long long iters, const unsigned long long seed, const char* filter,
      const char* dump, const char* values, const long rowIndex, const unsigned rowTimeoutSeconds, RetailImage& image
    )
    {
      Options opt;
      opt.specPath = specPath;
      opt.iters = iters;
      opt.seed = seed;
      opt.filter = filter;
      opt.dump = dump;
      opt.values = values;
      opt.rowIndex = rowIndex;
      opt.rowTimeoutSeconds = rowTimeoutSeconds == 0 ? 300 : rowTimeoutSeconds;
      return Run(opt, image);
    }
  } // namespace specrun
} // namespace difffuzz
