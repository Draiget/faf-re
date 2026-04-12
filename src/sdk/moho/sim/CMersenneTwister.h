#pragma once

#include <cstddef>
#include <cstdint>

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
   * Binary-facing MT19937 state used by sim/gameplay random streams.
   *
   * Layout evidence:
   * - `?FRandGaussian@CRandomStream@Moho@@QAEMXZ` (0x0040EEC0) reads:
   *   - state words at `+0x0000..+0x09BF`
   *   - index word at `+0x09C0`
   * - `?Seed@CMersenneTwister@Moho@@QAEXI@Z` (0x0040EB60) writes all state words.
   * - `?ShuffleState@CMersenneTwister@Moho@@AAEXXZ` (0x0040EBB0) twists all state words.
   */
  class CMersenneTwister
  {
  public:
    static gpg::RType* sType;

    static constexpr std::uint32_t kStateWordCount = 0x270; // 624
    using StateWords = std::uint32_t[kStateWordCount];

    StateWords state; // +0x0000 (mState)
    std::uint32_t k;  // +0x09C0 (mPos)

    /**
     * What it does:
     * Default-initializes storage; reflected/new-ref paths seed explicitly.
     */
    CMersenneTwister() = default;

    /**
     * Address: 0x0040EB50 (FUN_0040EB50, Moho::CMersenneTwister::CMersenneTwister)
     *
     * What it does:
     * Seeds the MT state from caller seed.
     */
    explicit CMersenneTwister(std::uint32_t seed) noexcept;

    /**
     * Address: 0x0040EB60 (FUN_0040EB60)
     * Mangled: ?Seed@CMersenneTwister@Moho@@QAEXI@Z
     *
     * What it does:
     * Seeds MT19937 state from a 32-bit seed and performs one immediate
     * shuffle pass so extraction starts from a twisted block.
     */
    void Seed(std::uint32_t seed) noexcept;

    /**
     * Address: 0x0040EBB0 (FUN_0040EBB0)
     * Mangled: ?ShuffleState@CMersenneTwister@Moho@@AAEXXZ
     *
     * What it does:
     * Twists the 624-word MT state block and resets extraction index.
     */
    void ShuffleState() noexcept;

    /**
     * Address: 0x0040E9F0 (FUN_0040E9F0)
     *
     * What it does:
     * Returns one tempered 32-bit MT sample, auto-shuffling when needed.
     */
    [[nodiscard]] std::uint32_t NextUInt32() noexcept;

    /**
     * Helper conversion used by recovered gameplay paths to map MT output
     * into `[0, 1)` float range.
     */
    [[nodiscard]] static float ToUnitFloat(std::uint32_t value) noexcept;

    /**
     * Address: 0x0040EC60 (FUN_0040EC60, Moho::CMersenneTwister::Checksum)
     *
     * What it does:
     * Appends the 624-word MT state block to MD5 (excludes extraction index).
     */
    void Checksum(gpg::MD5Context& md5) const;

    /**
     * Address: 0x0040F7A0 (FUN_0040F7A0, Moho::CMersenneTwister::MemberDeserialize)
     *
     * What it does:
     * Reads the full MT state vector and the extraction position from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0040F7E0 (FUN_0040F7E0, Moho::CMersenneTwister::MemberSerialize)
     *
     * What it does:
     * Writes the full MT state vector and the extraction position to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(CMersenneTwister, state) == 0x0000, "CMersenneTwister::state offset must be 0x0000");
  static_assert(offsetof(CMersenneTwister, k) == 0x09C0, "CMersenneTwister::k offset must be 0x09C0");
  static_assert(sizeof(CMersenneTwister) == 0x9C4, "CMersenneTwister size must be 0x9C4");
} // namespace moho
