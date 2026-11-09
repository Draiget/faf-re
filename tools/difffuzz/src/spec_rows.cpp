// The spec rows: reader and selector for tools/retail-recorder's RRS1 file
// (spec.py), and the input generator every selected row shares. See
// spec_rows.h and tools/retail-recorder/SPEC_FORMAT.md.
#include "spec_rows.h"

#include "fuzz.h"

#include <cstdio>
#include <cstring>

namespace difffuzz
{
  namespace spec
  {
    using u32 = std::uint32_t;

    bool ReadSpec(const char* path, File& out, std::string& error)
    {
      std::FILE* f = std::fopen(path, "rb");
      if (f == nullptr) {
        error = "cannot open the file";
        return false;
      }
      char magic[4] = {};
      u32 count = 0;
      if (std::fread(magic, 1, 4, f) != 4 || std::memcmp(magic, "RRS1", 4) != 0
          || std::fread(&count, 4, 1, f) != 1) {
        std::fclose(f);
        error = "not an RRS1 file (run tools/retail-recorder/spec.py)";
        return false;
      }
      out.entries.resize(count);
      for (u32 i = 0; i < count; ++i) {
        Entry& e = out.entries[i];
        std::uint8_t rec[9];
        if (std::fread(rec, 1, 9, f) != 9) {
          std::fclose(f);
          error = "truncated entry header";
          return false;
        }
        std::memcpy(&e.va, rec, 4);
        std::memcpy(&e.pop, rec + 4, 2);
        e.prologue = rec[6];
        e.ret = rec[7];
        e.args.resize(rec[8]);
        for (Arg& a : e.args) {
          if (std::fread(&a, 1, 4, f) != 4) {
            std::fclose(f);
            error = "truncated argument record";
            return false;
          }
        }
      }
      std::fclose(f);
      return true;
    }

    void SelectValueRows(
      const File& file, std::vector<Row>& rows, std::vector<std::pair<std::string, int>>& skippedWhy
    )
    {
      const auto skip = [&skippedWhy](const char* why) {
        for (auto& p : skippedWhy) {
          if (p.first == why) {
            ++p.second;
            return;
          }
        }
        skippedWhy.emplace_back(why, 1);
      };
      for (const Entry& e : file.entries) {
        if (e.ret == kRetNone) {
          skip("no result");
          continue;
        }
        if (e.args.empty()) {
          skip("no placed arguments (spec review list)");
          continue;
        }
        // Every argument must be a scalar the Hex-Rays prototype and the asm
        // agree on (hashed): an unhashed argument is a pointer or a struct by
        // value, and calling with a raw word in its place crashes (FUN_0091A570
        // dereferences both its stack words). Those stay for hand-written
        // rows, which read the asm first.
        bool unhashed = false;
        for (const Arg& a : e.args) {
          if (a.hashed == 0u) {
            unhashed = true;
            break;
          }
        }
        if (unhashed) {
          skip("a pointer or struct argument (unhashed): calling it needs an object");
          continue;
        }
        if ((e.ret == kRetEax || e.ret == kRetEdxEax) && e.pop != 0) {
          skip("callee pops (std/thiscall) with a register result: this is probably a method");
          continue;
        }
        // A register argument comes from the Hex-Rays prototype only, which
        // often misses `this` in esi or an input register the function reads
        // before writing (FUN_00415560 reads [esi] first). A callee that
        // takes every argument on the stack (a plain cdecl function) is the
        // only shape whose inputs the stub fully controls, so those are the
        // rows auto-called; a register-argument entry stays for the review
        // list, where a hand-written row reads the asm first.
        bool hasRegisterArg = false;
        int words = 0;
        for (const Arg& a : e.args) {
          if ((a.location & 0x80u) == 0u) {
            hasRegisterArg = true;
            break;
          }
          words += a.words;
        }
        if (hasRegisterArg) {
          skip("a register argument (prototype-placed; this may sit unmarked in a register)");
          continue;
        }
        if (words > kMaxSpecWords) {
          skip("too many argument words");
          continue;
        }
        Row r;
        r.entry = &e;
        r.va = e.va;
        r.inWords = words;
        r.outWords = e.ret == kRetSt0Double || e.ret == kRetEdxEax ? 2 : 1;
        r.floatOut = e.ret == kRetSt0Float || e.ret == kRetSt0Double;
        std::snprintf(r.name, sizeof(r.name), "spec_%08X", e.va);
        rows.push_back(r);
      }
    }

    /// One input word: an integer edge case a third of the time (the sizes and
    /// limits Lua table sizing and clamps live on), a float otherwise (the
    /// spec file marks an argument float when the prototype says so, but the
    /// Hex-Rays prototypes cannot be trusted for the register/stack split, so
    /// every word draws both kinds).
    [[nodiscard]] u32 GenSpecWord(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 12) {
        const u32 shift = rng.Below(33);
        return shift >= 32u ? 0u : (1u << shift) + rng.Below(3) - 1u;
      }
      if (mode < 20) {
        return rng.Below(64);
      }
      if (mode < 26) {
        return 0xFFFFFFFFu - rng.Below(4);
      }
      if (mode < 33) {
        return rng.Chance(50) ? 0u : rng.Chance(50) ? 0x80000000u : 0x7FFFFFFFu;
      }
      return GenFloat(rng);
    }

    void GenSpecInputs(Rng& rng, u32* in, const int words)
    {
      for (int i = 0; i < words; ++i) {
        in[i] = GenSpecWord(rng);
      }
    }
  } // namespace spec
} // namespace difffuzz
