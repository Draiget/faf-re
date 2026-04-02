#include "CRandomStream.h"

#include <cmath>
#include <typeinfo>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"

gpg::RType* moho::CMersenneTwister::sType = nullptr;
gpg::RType* moho::CRandomStream::sType = nullptr;

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kTwistMiddle = 0x18D; // 397
    constexpr std::uint32_t kTwistSplit = 0x0E3;  // 227
    constexpr std::uint32_t kLow31Mask = 0x7FFFFFFFu;
    constexpr std::uint32_t kSeedFactor = 0x6C078965u;
    constexpr std::uint32_t kTemperMaskB = 0xFF3A58ADu;
    constexpr std::uint32_t kTemperMaskC = 0xFFFFDF8Cu;
    constexpr std::uint32_t kTwistMagTable[2] = {0u, 0x9908B0DFu};
    constexpr double kInvTwoTo31 = 4.656612873077392578125e-10;  // 1 / 2^31
    constexpr double kInvTwoTo32 = 2.3283064365386962890625e-10; // 1 / 2^32

    [[nodiscard]] float NextSignedUnit(CRandomStream& stream) noexcept
    {
      const std::uint32_t value = stream.twister.NextUInt32();
      return static_cast<float>(static_cast<double>(value) * kInvTwoTo31 - 1.0);
    }

    [[nodiscard]] const gpg::RRef& NullOwnerRef()
    {
      static const gpg::RRef kNullOwner{nullptr, nullptr};
      return kNullOwner;
    }

    [[nodiscard]] gpg::RType* CachedCMersenneTwisterType()
    {
      gpg::RType* type = CMersenneTwister::sType;
      if (!type) {
        type = gpg::LookupRType(typeid(CMersenneTwister));
        CMersenneTwister::sType = type;
      }
      return type;
    }
  } // namespace

  /**
   * Address: 0x0040EB50 (FUN_0040EB50, Moho::CMersenneTwister::CMersenneTwister)
   *
   * What it does:
   * Seeds MT state from caller seed.
   */
  CMersenneTwister::CMersenneTwister(const std::uint32_t seed) noexcept
  {
    Seed(seed);
  }

  /**
   * Address: 0x0040EB60 (FUN_0040EB60)
   * Mangled: ?Seed@CMersenneTwister@Moho@@QAEXI@Z
   *
   * What it does:
   * Seeds MT state from a 32-bit seed and immediately shuffles it.
   */
  void CMersenneTwister::Seed(const std::uint32_t seed) noexcept
  {
    state[0] = seed;
    for (std::uint32_t i = 1; i < kStateWordCount; ++i) {
      const std::uint32_t prev = state[i - 1];
      state[i] = ((prev >> 30) ^ prev) * kSeedFactor + i;
    }

    k = kStateWordCount;
    ShuffleState();
  }

  /**
   * Address: 0x0040EBB0 (FUN_0040EBB0)
   * Mangled: ?ShuffleState@CMersenneTwister@Moho@@AAEXXZ
   *
   * What it does:
   * Twists the 624-word MT block and resets extraction index to zero.
   */
  void CMersenneTwister::ShuffleState() noexcept
  {
    std::uint32_t i = 0;
    for (; i < kTwistSplit; ++i) {
      const std::uint32_t mixed = ((state[i + 1] ^ state[i]) & kLow31Mask) ^ state[i];
      state[i] = (mixed >> 1) ^ kTwistMagTable[mixed & 1u] ^ state[i + kTwistMiddle];
    }

    for (; i < (kStateWordCount - 1); ++i) {
      const std::uint32_t mixed = ((state[i + 1] ^ state[i]) & kLow31Mask) ^ state[i];
      state[i] = (mixed >> 1) ^ kTwistMagTable[mixed & 1u] ^ state[i - kTwistSplit];
    }

    const std::uint32_t tailMixed = ((state[0] ^ state[kStateWordCount - 1]) & kLow31Mask) ^ state[kStateWordCount - 1];
    state[kStateWordCount - 1] = (tailMixed >> 1) ^ kTwistMagTable[tailMixed & 1u] ^ state[kTwistMiddle - 1];
    k = 0;
  }

  /**
   * Address: 0x0040E9F0 (FUN_0040E9F0)
   *
   * What it does:
   * Returns one tempered MT sample and auto-shuffles when index is exhausted.
   */
  std::uint32_t CMersenneTwister::NextUInt32() noexcept
  {
    if (k >= kStateWordCount) {
      ShuffleState();
    }

    std::uint32_t value = state[k++];
    value ^= (value >> 11);
    value ^= (value & kTemperMaskB) << 7;
    value ^= (value & kTemperMaskC) << 15;
    return (value >> 18) ^ value;
  }

  float CMersenneTwister::ToUnitFloat(const std::uint32_t value) noexcept
  {
    return static_cast<float>(static_cast<double>(value) * kInvTwoTo32);
  }

  /**
   * Address: 0x0040EC60 (FUN_0040EC60, Moho::CMersenneTwister::Checksum)
   *
   * What it does:
   * Appends MT state words to MD5 (excludes extraction position lane).
   */
  void CMersenneTwister::Checksum(gpg::MD5Context& md5) const
  {
    md5.Update(state, sizeof(state));
  }

  /**
   * Address: 0x0040F7A0 (FUN_0040F7A0, Moho::CMersenneTwister::MemberDeserialize)
   *
   * What it does:
   * Reads the full MT state vector and extraction position from archive.
   */
  void CMersenneTwister::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    for (std::uint32_t i = 0; i < kStateWordCount; ++i) {
      archive->ReadUInt(&state[i]);
    }

    int pos = 0;
    archive->ReadInt(&pos);
    k = static_cast<std::uint32_t>(pos);
  }

  /**
   * Address: 0x0040F7E0 (FUN_0040F7E0, Moho::CMersenneTwister::MemberSerialize)
   *
   * What it does:
   * Writes the full MT state vector and extraction position to archive.
   */
  void CMersenneTwister::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    for (std::uint32_t i = 0; i < kStateWordCount; ++i) {
      archive->WriteUInt(state[i]);
    }

    archive->WriteInt(static_cast<int>(k));
  }

  /**
   * Address: 0x0040EA60 (FUN_0040EA60, Moho::CRandomStream::CRandomStream)
   *
   * What it does:
   * Seeds twister state from caller seed and clears cached Marsaglia-pair flag.
   */
  CRandomStream::CRandomStream(const std::uint32_t seed) noexcept
  {
    twister.Seed(seed);
    hasMarsagliaPair = 0;
  }

  /**
   * Address: 0x0040EA70 (FUN_0040EA70, Moho::CRandomStream::FRand)
   *
   * What it does:
   * Returns one uniform random sample in [0,1) from the embedded twister.
   */
  float CRandomStream::FRand() noexcept
  {
    return static_cast<float>(static_cast<double>(twister.NextUInt32()) * kInvTwoTo32);
  }

  /**
   * Address: 0x0040F030 (FUN_0040F030, Moho::CRandomStream::Checksum)
   *
   * What it does:
   * Appends deterministic RNG state and gaussian-cache lanes into MD5.
   */
  void CRandomStream::Checksum(gpg::MD5Context& md5) const
  {
    md5.Update(twister.state, sizeof(twister.state));
    md5.Update(&hasMarsagliaPair, sizeof(hasMarsagliaPair));
    if (hasMarsagliaPair) {
      md5.Update(&marsagliaPair, sizeof(marsagliaPair));
    }
  }

  /**
   * Address: 0x0040EA40 (FUN_0040EA40)
   *
   * What it does:
   * Seeds twister state and clears cached Marsaglia-pair availability.
   */
  void CRandomStream::Seed(const std::uint32_t seed) noexcept
  {
    twister.Seed(seed);
    hasMarsagliaPair = 0;
  }

  /**
   * Address: 0x0040EEC0 (FUN_0040EEC0, FA)
   * Address: 0x1000D1F0 (?FRandGaussian@CRandomStream@Moho@@QAEMXZ, MohoEngine)
   *
   * What it does:
   * Generates a standard-normal random value using Marsaglia polar method
   * with one-value cache in `marsagliaPair/hasMarsagliaPair`.
   */
  float CRandomStream::FRandGaussian() noexcept
  {
    if (hasMarsagliaPair != 0) {
      hasMarsagliaPair = 0;
      return marsagliaPair;
    }

    float x = 0.0f;
    float y = 0.0f;
    float radiusSquared = 1.0f;
    do {
      x = NextSignedUnit(*this);
      y = NextSignedUnit(*this);
      radiusSquared = x * x + y * y;
    } while (radiusSquared >= 1.0f);

    // Keep the original loop condition (`radiusSquared >= 1.0f`) for binary parity.
    const float scale = std::sqrt((-2.0f * std::log(radiusSquared)) / radiusSquared);
    hasMarsagliaPair = 1;
    marsagliaPair = y * scale;
    return x * scale;
  }

  /**
   * Address: 0x0040F810 (FUN_0040F810, Moho::CRandomStream::MemberDeserialize)
   *
   * What it does:
   * Deserializes the embedded MT state, cached gaussian sample, and cache flag.
   */
  void CRandomStream::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->Read(CachedCMersenneTwisterType(), &twister, NullOwnerRef());
    archive->ReadFloat(&marsagliaPair);
    archive->ReadBool(&hasMarsagliaPair);
  }

  /**
   * Address: 0x0040F870 (FUN_0040F870, Moho::CRandomStream::MemberSerialize)
   *
   * What it does:
   * Serializes the embedded MT state, cached gaussian sample, and cache flag.
   */
  void CRandomStream::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->Write(CachedCMersenneTwisterType(), &twister, NullOwnerRef());
    archive->WriteFloat(marsagliaPair);
    archive->WriteBool(hasMarsagliaPair);
  }
} // namespace moho
