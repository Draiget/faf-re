#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "remote/wire/BitStream.h"
#include "remote/wire/NameTable.h"
#include "remote/wire/SoundTable.h"

// Engine addition, server mode (plan WP7.2): the tables a session builds as it goes (sounds,
// names, resource deposits) and the reliable-stream record that carries their new entries. The
// server writes the entries added since its last record before the frames that use them; the
// client reads them in order. Record: varuint count of sound entries and the entries, then the
// same for names, deposits and terrain edits.

namespace faf::remote::wire
{
  /**
   * A resource deposit (WP11.2): the sim's `ResourceDeposit`, its type and footprint in map
   * cells. Deposits are created by sim Lua (`CreateResourceDeposit`) and never removed, so a
   * session sends each one once, in the sim's order.
   */
  struct SDeposit
  {
    std::uint8_t type = 0; // EDepositType
    std::int32_t x0 = 0;
    std::int32_t z0 = 0;
    std::int32_t x1 = 0;
    std::int32_t z1 = 0;

    [[nodiscard]] bool operator==(const SDeposit&) const noexcept = default;
  };

  /** An inclusive rectangle of height-field cells, as `gpg::Rect2i` holds one. */
  struct SCellRect
  {
    std::int32_t x0 = 0;
    std::int32_t z0 = 0;
    std::int32_t x1 = 0;
    std::int32_t z1 = 0;

    [[nodiscard]] bool operator==(const SCellRect&) const noexcept = default;
  };

  /**
   * A terrain edit (WP11.2): one of the sim's changed-terrain rectangles for a beat
   * (`SSyncData::mPlayableRectUpdates`, from `Sim::FlattenMapRect`) and the heights the sim's
   * height field holds in it afterwards, clipped to the field, row by row. All edits are sent
   * (§6: the client renders the live height field, edits appear in fog as they do today).
   */
  struct STerrainEdit
  {
    SCellRect dirty;                    // as the sim listed it
    SCellRect cells;                    // `dirty` within the field; empty (x0 > x1) when outside
    std::vector<std::uint16_t> heights; // (x1 - x0 + 1) * (z1 - z0 + 1) of `cells`, rows of x

    [[nodiscard]] bool operator==(const STerrainEdit&) const noexcept = default;
  };

  class CSessionTableWriters
  {
  public:
    static constexpr std::uint32_t kMaxDeposits = 1u << 16;
    static constexpr std::uint32_t kMaxTerrainEdits = 1u << 12; // in one record
    static constexpr std::uint32_t kMaxEditCells = 1u << 21;    // in one edit: a 1025-cell square fits

    /** The sound table id of `entry`, interning it (and queueing it for the next record). */
    [[nodiscard]] std::uint32_t Sound(const SSoundEntry& entry);
    /** The name table id of `name`, as `Sound`. */
    [[nodiscard]] std::uint32_t Name(std::string_view name);
    /** Queues a deposit the sim added (false past `kMaxDeposits`, which the client would refuse). */
    bool Deposit(const SDeposit& deposit);
    /** Deposits queued or written so far: the sim's deposits from this index on are new. */
    [[nodiscard]] std::size_t DepositCount() const noexcept { return mDepositCount; }
    /** Queues a terrain edit (false when it is too large or too many are queued). */
    bool TerrainEdit(STerrainEdit edit);

    /** True when entries are waiting for `WritePending`. */
    [[nodiscard]] bool HasPending() const noexcept
    {
      return !mNewSounds.empty() || !mNewNames.empty() || !mNewDeposits.empty() || !mNewTerrainEdits.empty();
    }

    /** Writes the queued entries and forgets them. */
    void WritePending(BitWriter& writer);

  private:
    CSoundTableWriter mSounds;
    CNameTableWriter mNames;
    std::vector<std::uint32_t> mNewSounds;
    std::vector<std::uint32_t> mNewNames;
    std::vector<SDeposit> mNewDeposits;
    std::size_t mDepositCount = 0;
    std::vector<STerrainEdit> mNewTerrainEdits;
  };

  class CSessionTableReaders
  {
  public:
    /** Reads one record; false (with whatever was read kept) when it is malformed. */
    [[nodiscard]] bool Read(BitReader& reader);

    [[nodiscard]] const CSoundTableReader& Sounds() const noexcept { return mSounds; }
    [[nodiscard]] const CNameTableReader& Names() const noexcept { return mNames; }
    /** Every deposit read so far, in the sim's order. */
    [[nodiscard]] const std::vector<SDeposit>& Deposits() const noexcept { return mDeposits; }
    /** The terrain edits read since the last call, in order (the client applies each once). */
    [[nodiscard]] std::vector<STerrainEdit> TakeTerrainEdits() noexcept
    {
      std::vector<STerrainEdit> taken;
      taken.swap(mTerrainEdits);
      return taken;
    }

  private:
    CSoundTableReader mSounds;
    CNameTableReader mNames;
    std::vector<SDeposit> mDeposits;
    std::vector<STerrainEdit> mTerrainEdits;
  };
} // namespace faf::remote::wire
