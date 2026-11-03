#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "remote/wire/BitStream.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/IntelGridDelta.h"

// Engine addition, server mode (plan WP5.13): the client side of the army lane and the view
// army's intel grids on the wire.
//
// Army lane: every army's record as the view gets it (`ArmyRecordForView`, remote/ViewPackets.h),
// positionally as `Sim::Sync` fills them, each sent whole when it differs from the record the
// client holds and as one bit when it does not. `SArmyRecord` is `SSTIArmyVariableData` without
// its pointers: the category filter goes as category bits, and the path preview's cells and
// footprint pointer (`mWordVectorWithMeta`, `Sim.cpp:2916`) are not sent; the client's preview,
// a debug view behind `ui_PathPreview` (off by default, `CWldSession.cpp:769`), shows nothing.
//
// Grid lane: the vision and water grids of the view's army and of every army that lists it as an
// ally, each as a run-length delta (IntelGridDelta.h) against the copy the client holds, tagged
// with its army, kind and cell size (`CIntelGrid::mGridSize`) so the client can build its own grid.

namespace faf::remote::wire
{
  struct SArmyRecord
  {
    static constexpr std::size_t kMaxSetMembers = 64;
    static constexpr std::size_t kMaxTypeLength = 64;

    std::array<float, 10> economy{};        // stored, income, reclaimed, last use requested, actual: energy, mass each
    std::array<std::uint64_t, 2> maxStorage{}; // energy, mass
    std::uint8_t resourceSharing = 0;
    std::vector<std::uint32_t> neutrals;
    std::vector<std::uint32_t> allies;
    std::vector<std::uint32_t> enemies;
    std::uint8_t isAlly = 0;
    std::vector<std::uint32_t> validCommandSources;
    std::uint32_t playerColor = 0;
    std::uint32_t armyColor = 0;
    std::string armyType;
    std::int32_t faction = 0;
    std::uint8_t useWholeMap = 0;
    std::uint8_t showScore = 0;
    SCategoryBits categoryFilter;
    std::uint8_t isOutOfGame = 0;
    std::array<float, 2> armyStart{};
    std::int32_t noRushTimer = 0;
    float noRushRadius = 0.0f;
    std::array<float, 2> noRushOffset{};
    float handicapValue = 0.0f;
    float handicapExtra = 0.0f;

    [[nodiscard]] bool operator==(const SArmyRecord& other) const noexcept = default;
  };

  inline constexpr std::size_t kMaxArmyRecords = 32;

  /** Every record, each in full where it differs from `baseline` (null: all in full). False for a malformed record. */
  [[nodiscard]] bool EncodeArmyLane(
    const std::vector<SArmyRecord>& records, const std::vector<SArmyRecord>* baseline, BitWriter& writer
  );

  /** Reads one lane against `baseline` (the records the encoder used). False for anything malformed. */
  [[nodiscard]] bool DecodeArmyLane(
    BitReader& reader, const std::vector<SArmyRecord>* baseline, std::vector<SArmyRecord>& out
  );

  /** One grid of the lane: whose, which (0 vision, 1 water), its cell size, its cells. */
  struct SGridSlot
  {
    std::uint8_t army = 0;
    std::uint8_t kind = 0;
    std::uint32_t gridSize = 0;
    SGridBits bits;

    [[nodiscard]] bool operator==(const SGridSlot& other) const noexcept = default;
  };

  inline constexpr std::size_t kMaxGridSlots = 64;
  inline constexpr std::uint32_t kMaxGridCells = 1u << 22;

  /**
   * The view's grids this beat, each a delta against the slot of the same army and kind in
   * `held` (the client's copies; none: all hidden). False for a malformed grid.
   */
  /** One slot of the lane, against the `baseline` its client holds (null: none). */
  [[nodiscard]] bool EncodeGridSlot(const SGridSlot& slot, const SGridBits* baseline, BitWriter& writer);
  [[nodiscard]] bool EncodeGridLane(
    const std::vector<SGridSlot>& grids, const std::vector<SGridSlot>& held, BitWriter& writer
  );

  /** Reads one grid lane against `held` and replaces it with the grids sent. False for anything malformed. */
  [[nodiscard]] bool DecodeGridLane(BitReader& reader, std::vector<SGridSlot>& held);
} // namespace faf::remote::wire
