#pragma once

// The RRS1 spec file of tools/retail-recorder/spec.py, read by difffuzz
// --spec: the functions to call in the mapped retail image directly, many at
// once, without a hand-written thunk per function. The binary layout is
// documented in tools/retail-recorder/SPEC_FORMAT.md.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace difffuzz
{
  struct Rng;
  namespace spec
  {
    enum : std::uint8_t
    {
      kRetNone = 0,
      kRetEax = 1,
      kRetSt0Float = 2,
      kRetSt0Double = 3,
      kRetEdxEax = 4,
    };

    struct Arg
    {
      std::uint8_t location; // 0..6 = eax ecx edx ebx esi edi ebp; 0x80|n = stack dword n
      std::uint8_t words;    // 1 or 2
      std::uint8_t hashed;   // scalar by the Hex-Rays prototype and the asm check
      std::uint8_t isFloat;  // float or double
    };

    struct Entry
    {
      std::uint32_t va = 0;
      std::uint16_t pop = 0;
      std::uint8_t prologue = 0; // hooking only; a direct call needs no copy
      std::uint8_t ret = kRetNone;
      std::vector<Arg> args;
    };

    struct File
    {
      std::vector<Entry> entries;
    };

    bool ReadSpec(const char* path, File& out, std::string& error);

    constexpr int kMaxSpecWords = 32; // argument words one auto row may take

    /// A row selected for direct calls. `in` holds one dword per argument word
    /// in declaration order; the stub built from the row (spec_stub.h) moves
    /// them into the ABI the spec describes and stores the result words.
    struct Row
    {
      const Entry* entry = nullptr;
      std::uint32_t va = 0;
      int inWords = 0;  // total argument words
      int outWords = 0; // 1 (eax, st0 float), 2 (st0 double, edx:eax)
      bool floatOut = false; // st0 result: canonicalise NaN output words
      char name[16] = {};    // "spec_0091A510"
    };

    /// The entries worth calling automatically: every argument a scalar the
    /// prototype and the asm agree on (a pointer Hex-Rays typed int stays in,
    /// and the call crashes on it - the run reports it), register arguments
    /// single-word only, and a non-void result. `skippedWhy` counts the rest.
    void SelectValueRows(const File& file, std::vector<Row>& rows, std::vector<std::pair<std::string, int>>& skippedWhy);

    /// Fills the input words of one spec row (spec_rows.cpp): integers on the
    /// sizes and limits the engine's sizing and clamp code lives on, floats
    /// otherwise.
    void GenSpecInputs(Rng& rng, std::uint32_t* in, const int words);
  } // namespace spec
} // namespace difffuzz
