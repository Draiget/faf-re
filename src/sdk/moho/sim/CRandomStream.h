#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/sim/CMersenneTwister.h"

namespace gpg
{
  struct MD5Context;
  class RType;
  class ReadArchive;
  class WriteArchive;
}

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
    static gpg::RType* sType;

    /**
     * What it does:
     * Default-initializes storage; reflection/typeinfo paths seed explicitly.
     */
    CRandomStream() = default;

    /**
     * Address: 0x0040EA60 (FUN_0040EA60, Moho::CRandomStream::CRandomStream)
     *
     * What it does:
     * Seeds the embedded twister state and clears cached gaussian sample state.
     */
    explicit CRandomStream(std::uint32_t seed) noexcept;

    CMersenneTwister twister;      // +0x0000 (mTwister)
    float marsagliaPair;           // +0x09C4 (mMarsagliaPair)
    bool hasMarsagliaPair;         // +0x09C8 (mHasMarsagliaPair)
    std::uint8_t pad_09C9_09CC[3]; // +0x09C9

    /**
     * Address: 0x0040EA40 (FUN_0040EA40)
     *
     * What it does:
     * Seeds the embedded twister state and clears cached gaussian sample state.
     */
    void Seed(std::uint32_t seed) noexcept;

    /**
     * Address: 0x0040EA70 (FUN_0040EA70, Moho::CRandomStream::FRand)
     *
     * What it does:
     * Returns one uniform random sample in [0,1) from the embedded twister.
     */
    float FRand() noexcept;

    /**
     * Address: 0x0051B5C0 (FUN_0051B5C0, Moho::CRandomStream::FRand)
     *
     * What it does:
     * Returns one uniform random sample in [lower, upper) from the embedded twister.
     */
    float FRand(float lower, float upper) noexcept;

    /**
     * Address: 0x0040F030 (FUN_0040F030, Moho::CRandomStream::Checksum)
     *
     * What it does:
     * Hashes twister state words plus gaussian-cache lanes into MD5.
     */
    void Checksum(gpg::MD5Context& md5) const;

    /**
     * Address: 0x0040EEC0 (FUN_0040EEC0, FA)
     * Address: 0x1000D1F0 (?FRandGaussian@CRandomStream@Moho@@QAEMXZ, MohoEngine)
     *
     * What it does:
     * Generates a standard-normal random value using Marsaglia polar method
     * with one-value cache in `marsagliaPair/hasMarsagliaPair`.
     */
    float FRandGaussian() noexcept;

    /**
     * Address: 0x0040F810 (FUN_0040F810, Moho::CRandomStream::MemberDeserialize)
     *
     * What it does:
     * Deserializes the embedded MT state, cached gaussian sample, and cache flag.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0040F870 (FUN_0040F870, Moho::CRandomStream::MemberSerialize)
     *
     * What it does:
     * Serializes the embedded MT state, cached gaussian sample, and cache flag.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(CRandomStream, twister) == 0x0000, "CRandomStream::twister offset must be 0x0000");
  static_assert(offsetof(CRandomStream, marsagliaPair) == 0x09C4, "CRandomStream::marsagliaPair offset must be 0x09C4");
  static_assert(
    offsetof(CRandomStream, hasMarsagliaPair) == 0x09C8, "CRandomStream::hasMarsagliaPair offset must be 0x09C8"
  );
  static_assert(sizeof(CRandomStream) == 0x9CC, "CRandomStream size must be 0x9CC");
} // namespace moho
