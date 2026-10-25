#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "remote/wire/BitStream.h"
#include "remote/wire/OrdinalTable.h"
#include "remote/wire/Quantize.h"

// Engine addition, server mode: the entities lane of a view frame (plan §7.1, WP7.3, WP7.4,
// WPR.38).
//
// A view frame is plain data: the quantised state of every entity one view knows in one
// tick. The server sends a frame as its difference from a baseline frame the client has
// acknowledged (or from nothing: a full frame). The client decodes it into a full frame,
// keeps decoded frames as its baselines, and updates its world from the difference between
// the frame it shows and the next one (`ComputeFrameDelta`), so a mistake in applying one
// update is corrected by the next.

namespace faf::remote::wire
{
  /** A unit's own state, beyond what every entity has. Exact floats (the UI shows them). */
  struct SUnitFields
  {
    float fuelRatio = 0.0f;
    float shieldRatio = 0.0f;
    float workProgress = 0.0f;
    std::uint64_t unitStates = 0;   // EUnitState bits
    std::uint32_t scriptBits = 0;   // the toggle buttons' bits
    std::array<std::uint16_t, 4> siloCounts{}; // tactical build, nuke build, tactical stored, nuke stored
    std::uint8_t unitFlags = 0;     // paused, auto mode, auto surface, busy, repeat queue, ...
  };

  /** One entity's state in a view frame. Floats the UI shows as numbers are exact. */
  struct SEntityRecord
  {
    std::uint32_t id = 0;
    std::uint32_t blueprint = COrdinalTable::kNone; // ordinal into SContentTables::blueprints
    std::uint8_t army = 0xFFu;                      // 0xFF: no army
    QuantizedPosition position{};
    std::uint32_t orientation = 0;                  // PackQuaternion
    float health = 0.0f;
    float maxHealth = 0.0f;
    float fractionComplete = 0.0f;
    std::uint16_t flags = 0;
    bool isUnit = false;                            // `unit` is meaningful
    SUnitFields unit{};

    /**
     * Bitwise: two NaNs with one bit pattern are equal, 0.0 and -0.0 are not. A non-unit's
     * `unit` block is not compared (it is never sent).
     */
    [[nodiscard]] bool operator==(const SEntityRecord& other) const noexcept;
  };

  /**
   * Change-mask bits, one per field after the id. On the wire the mask is a varint, so the
   * fields that change every tick come first and a typical change costs one mask byte.
   * `kFieldKind` carries `isUnit`; the unit bits are only valid for a unit.
   */
  enum EEntityField : std::uint16_t
  {
    kFieldPosition = 1u << 0,
    kFieldOrientation = 1u << 1,
    kFieldHealth = 1u << 2,
    kFieldFraction = 1u << 3,
    kFieldFlags = 1u << 4,
    kFieldMaxHealth = 1u << 5,
    kFieldBlueprint = 1u << 6,
    kFieldArmy = 1u << 7,
    kFieldUnitFuel = 1u << 8,
    kFieldUnitShield = 1u << 9,
    kFieldUnitWork = 1u << 10,
    kFieldUnitStates = 1u << 11,
    kFieldUnitScriptBits = 1u << 12,
    kFieldUnitSilos = 1u << 13,
    kFieldUnitFlags = 1u << 14,
    kFieldKind = 1u << 15,
  };

  inline constexpr std::uint16_t kEntityFields = 0x00FFu;
  inline constexpr std::uint16_t kUnitFields = 0x7F00u;
  /** What a creation writes: everything, the unit block only for a unit. */
  [[nodiscard]] std::uint16_t CreationFields(const SEntityRecord& record) noexcept;

  /** The fields in which two records of one entity differ. */
  [[nodiscard]] std::uint16_t ChangedFields(const SEntityRecord& before, const SEntityRecord& after) noexcept;

  struct SViewFrame
  {
    std::uint32_t frameId = 0;
    std::uint32_t beat = 0;
    std::vector<SEntityRecord> entities; // ascending, unique ids

    [[nodiscard]] bool operator==(const SViewFrame& other) const noexcept = default;
    [[nodiscard]] bool IsWellFormed() const noexcept;
  };

  inline constexpr std::uint32_t kNoBaseline = 0xFFFFFFFFu;

  /** What turns one frame into the next: what the encoder sends and the client applies. */
  struct SFrameDelta
  {
    std::vector<std::uint32_t> removed;      // ascending
    std::vector<SEntityRecord> created;      // ascending ids
    struct SChange
    {
      std::uint16_t fields = 0;
      SEntityRecord record;                   // the new state (only `fields` differ)
    };
    std::vector<SChange> changed;            // ascending ids
  };

  /** `baseline` null: everything in `frame` is created. Both frames must be well formed. */
  [[nodiscard]] SFrameDelta ComputeFrameDelta(const SViewFrame* baseline, const SViewFrame& frame);

  /** What both ends agree on at connect (the map size fixes the position quantiser). */
  struct SFrameCodec
  {
    SPositionQuantizer position = SPositionQuantizer::ForMap(1024.0f, 1024.0f);
    std::uint32_t maxEntities = 1u << 16;
  };

  /**
   * Writes `frame` relative to `baseline` (null: a full frame). False, with nothing useful
   * written, when a frame is not well formed or a value does not fit the codec.
   */
  [[nodiscard]] bool EncodeFrame(
    const SViewFrame& frame, const SViewFrame* baseline, const SFrameCodec& codec, BitWriter& writer
  );

  /** The baseline a frame on the wire was encoded against (`kNoBaseline` for a full frame). */
  [[nodiscard]] std::uint32_t PeekFrameBaseline(std::span<const std::uint8_t> bytes) noexcept;

  /**
   * Reads one frame. `baseline` must be the frame the encoder used (same id), or null for a
   * full frame. False for anything malformed or inconsistent with the baseline; never reads
   * out of bounds and never allocates more than the codec's entity limit allows.
   */
  [[nodiscard]] bool DecodeFrame(
    BitReader& reader, const SViewFrame* baseline, const SFrameCodec& codec, SViewFrame& out
  );
} // namespace faf::remote::wire
