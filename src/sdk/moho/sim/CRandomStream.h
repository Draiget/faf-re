#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/sim/CMersenneTwister.h"

namespace moho
{
  /**
   * Address: 0x0040F0D0 (FUN_0040F0D0)
   *
   * What it does:
   * Reflection type init for `CRandomStream` (`sizeof = 0x9CC`).
   *
   * Layout evidence:
   * - 0x0040F030 serializes:
   *   - `CMersenneTwister` payload at `+0x0000..+0x09C3`
   *   - cached gaussian float at `+0x09C4`
   *   - has-cached flag at `+0x09C8`
   * - MohoEngine `?FRandGaussian@CRandomStream@Moho@@QAEMXZ` (0x1000D1F0)
   *   reads/writes the same slots.
   */
  class CRandomStream
  {
  public:
    CMersenneTwister twister;         // +0x0000
    float marsagliaPair;              // +0x09C4
    std::uint8_t hasMarsagliaPair;    // +0x09C8
    std::uint8_t pad_09C9_09CC[0x03]; // +0x09C9

    /**
     * Address: 0x0040EA40 (FUN_0040EA40)
     *
     * What it does:
     * Seeds the embedded twister state and clears cached gaussian sample state.
     */
    void Seed(std::uint32_t seed) noexcept;

    /**
     * Address: 0x0040EEC0 (FUN_0040EEC0, FA)
     * Address: 0x1000D1F0 (?FRandGaussian@CRandomStream@Moho@@QAEMXZ, MohoEngine)
     *
     * What it does:
     * Generates a standard-normal random value using Marsaglia polar method
     * with one-value cache in `marsagliaPair/hasMarsagliaPair`.
     */
    float FRandGaussian() noexcept;
  };

  static_assert(offsetof(CRandomStream, twister) == 0x0000, "CRandomStream::twister offset must be 0x0000");
  static_assert(offsetof(CRandomStream, marsagliaPair) == 0x09C4, "CRandomStream::marsagliaPair offset must be 0x09C4");
  static_assert(
    offsetof(CRandomStream, hasMarsagliaPair) == 0x09C8, "CRandomStream::hasMarsagliaPair offset must be 0x09C8"
  );
  static_assert(sizeof(CRandomStream) == 0x9CC, "CRandomStream size must be 0x9CC");
} // namespace moho
