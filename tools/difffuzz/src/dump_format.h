#pragma once

// The hash file faf_math_dump writes and difffuzz --dump writes from retail's
// outputs (dedicated-server plan WPR.21): one line per target and block of
// kDumpBlock iterations, `target block input-hash output-hash`, FNV-1a over
// the input words and the output words. The two files compare byte for byte.

#include <cstdint>
#include <cstdio>

namespace difffuzz
{
  constexpr unsigned long long kDumpBlock = 65536ull;
  constexpr std::uint64_t kHashSeed = 1469598103934665603ull; // FNV-1a offset basis

  /// Without --strict-nan every NaN output word becomes the default quiet
  /// NaN, as difffuzz tallies NaN-payload-only differences instead of failing
  /// them: which operand's payload an operation keeps follows the x87/SSE
  /// split and the compiler's operand order, which no source change pins down.
  inline void CanonicalizeNans(std::uint32_t* words, const int count) noexcept
  {
    for (int i = 0; i < count; ++i) {
      if ((words[i] & 0x7F800000u) == 0x7F800000u && (words[i] & 0x007FFFFFu) != 0) {
        words[i] = 0x7FC00000u;
      }
    }
  }

  /// One target's running hashes; Add once per iteration.
  struct BlockDump
  {
    std::uint64_t inHash = kHashSeed;
    std::uint64_t outHash = kHashSeed;

    static std::uint64_t Mix(std::uint64_t hash, const std::uint32_t* words, const int count) noexcept
    {
      for (int i = 0; i < count; ++i) {
        hash = (hash ^ words[i]) * 1099511628211ull;
      }
      return hash;
    }

    /// Hashes iteration `done` (0-based) and writes the block's line after its
    /// last iteration or after iteration `iters - 1`.
    void Add(
      std::FILE* out, const char* name, const unsigned long long done, const unsigned long long iters,
      const std::uint32_t* in, const int inWords, const std::uint32_t* outWords, const int outCount
    )
    {
      inHash = Mix(inHash, in, inWords);
      outHash = Mix(outHash, outWords, outCount);
      if ((done + 1) % kDumpBlock == 0 || done + 1 == iters) {
        std::fprintf(
          out, "%s %llu %016llx %016llx\n", name, done / kDumpBlock, static_cast<unsigned long long>(inHash),
          static_cast<unsigned long long>(outHash)
        );
        inHash = kHashSeed;
        outHash = kHashSeed;
      }
    }
  };

  // The values file (plan WPL.26): retail's actual outputs for a few dozen
  // inputs per target, one line each, `target iteration in-words -> out-words`
  // in hex (the format of faf_math_dump --lines). difffuzz --values writes it
  // from retail and faf_math_dump --values runs our function on each line's
  // inputs, so a difference names the input and both values.
  inline void WriteValueLine(
    std::FILE* out, const char* name, const unsigned long long iteration, const std::uint32_t* in, const int inWords,
    const std::uint32_t* outWords, const int outCount
  )
  {
    std::fprintf(out, "%s %llu", name, iteration);
    for (int i = 0; i < inWords; ++i) {
      std::fprintf(out, " %08X", in[i]);
    }
    std::fprintf(out, " ->");
    for (int i = 0; i < outCount; ++i) {
      std::fprintf(out, " %08X", outWords[i]);
    }
    std::fprintf(out, "\n");
  }

  /// A word worth a recorded case: a float NaN, infinity, denormal or -0, or
  /// an integer at the int range's edges (the x87 integer indefinite).
  [[nodiscard]] inline bool IsSpecialWord(const std::uint32_t word) noexcept
  {
    const std::uint32_t exponent = word & 0x7F800000u;
    const std::uint32_t mantissa = word & 0x007FFFFFu;
    return exponent == 0x7F800000u || (exponent == 0 && mantissa != 0) || word == 0x80000000u || word == 0x7FFFFFFFu;
  }

  /// Which iterations of a target's stream go into the values file: the first
  /// kValuesFirst, then up to kValuesSpecial whose inputs hold a special word
  /// and up to kValuesSpecial whose (retail) outputs do.
  struct ValueSampler
  {
    static constexpr int kValuesFirst = 16;
    static constexpr int kValuesSpecial = 24;
    int first = 0;
    int specialIn = 0;
    int specialOut = 0;

    [[nodiscard]] static bool AnySpecial(const std::uint32_t* words, const int count) noexcept
    {
      for (int i = 0; i < count; ++i) {
        if (IsSpecialWord(words[i])) {
          return true;
        }
      }
      return false;
    }

    [[nodiscard]] bool Take(
      const std::uint32_t* in, const int inWords, const std::uint32_t* outWords, const int outCount
    ) noexcept
    {
      if (first < kValuesFirst) {
        ++first;
        return true;
      }
      if (specialIn < kValuesSpecial && AnySpecial(in, inWords)) {
        ++specialIn;
        return true;
      }
      if (specialOut < kValuesSpecial && AnySpecial(outWords, outCount)) {
        ++specialOut;
        return true;
      }
      return false;
    }
  };
} // namespace difffuzz
