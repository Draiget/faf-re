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

  /**
   * How an entity is drawn and what its UI shows beyond the basics: the client resolves the
   * mesh (and its resource) from the ordinal, the rest is the sim's data as is. Defaults are
   * the sim's (`SSTIEntityVariableData`'s constructor); a creation sends only what differs.
   */
  struct SAppearance
  {
    static constexpr std::uint32_t kNoAttachParent = 0xF0000000u; // the sim's invalid entity id
    static constexpr std::size_t kMaxAttachments = 64;

    std::uint32_t mesh = COrdinalTable::kNone;      // ordinal into SContentTables::meshes
    std::array<float, 3> scale{1.0f, 1.0f, 1.0f};
    std::uint32_t attachParent = kNoAttachParent;
    std::vector<std::uint32_t> attachments;          // the entities attached to this one
    float impact = 1.0f;
    std::array<float, 4> scroll{};                   // texture scroll: beat start x, y, beat end x, y
    std::uint8_t visualFlags = 0;                    // hidden, alt footprint, alt footprint 2, killed, refresh UI
    std::array<std::uint32_t, 8> intel{};            // vision, water vision, radar, sonar, omni, radar/sonar stealth, cloak

    [[nodiscard]] bool operator==(const SAppearance& other) const noexcept;
  };

  /** One entity's state in a view frame. Floats the UI shows as numbers are exact. */
  struct SEntityRecord
  {
    std::uint32_t id = 0;
    std::uint32_t blueprint = COrdinalTable::kNone; // ordinal into SContentTables::blueprints
    std::uint8_t army = 0xFFu;                      // 0xFF: no army
    QuantizedPosition position{};                    // with dead reckoning: the anchor position
    /**
     * A position outside the quantiser's range (an effect projectile drifting off the map, say)
     * goes as exact floats instead: `position`, `velocity` and `anchorBeat` are then zero.
     */
    bool farPosition = false;
    std::array<float, 3> farValue{};
    /** Dead reckoning (WP7.5): quantiser steps per beat since `anchorBeat`; zero without it. */
    std::array<std::int32_t, 3> velocity{};
    std::uint32_t anchorBeat = 0;
    std::uint32_t orientation = 0;                  // yawOnly ? QuantizeYaw : PackQuaternion
    bool yawOnly = false;                           // a rotation about the vertical axis only
    float health = 0.0f;
    float maxHealth = 0.0f;
    float fractionComplete = 0.0f;
    std::uint16_t flags = 0;
    bool isUnit = false;                            // `unit` is meaningful
    SUnitFields unit{};
    SAppearance appearance{};

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
  enum EEntityField : std::uint32_t
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
    kFieldMesh = 1u << 16,
    kFieldScale = 1u << 17,
    kFieldAttachment = 1u << 18,
    kFieldVisualFlags = 1u << 19,
    kFieldImpact = 1u << 20,
    kFieldScroll = 1u << 21,
    kFieldIntel = 1u << 22,
  };

  inline constexpr std::uint32_t kEntityFields = 0x00FFu;
  inline constexpr std::uint32_t kUnitFields = 0x7F00u;
  inline constexpr std::uint32_t kAppearanceFields = 0x7F0000u;
  inline constexpr std::uint32_t kAllFields = kEntityFields | kUnitFields | kFieldKind | kAppearanceFields;

  /**
   * What a creation writes: the basic fields and the kind always, the unit block for a unit,
   * the appearance fields that differ from their defaults.
   */
  [[nodiscard]] std::uint32_t CreationFields(const SEntityRecord& record) noexcept;

  /** The fields in which two records of one entity differ. */
  [[nodiscard]] std::uint32_t ChangedFields(const SEntityRecord& before, const SEntityRecord& after) noexcept;

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
      std::uint32_t fields = 0;
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
    /**
     * Dead reckoning (WP7.5): a position travels with its anchor beat and a velocity, and the
     * client shows `PredictPosition`. Without it both are zero and not sent.
     */
    bool deadReckoning = false;
  };

  /** Where the client shows a dead-reckoned record at `beat`: integer steps, clamped to the axes. */
  [[nodiscard]] QuantizedPosition PredictPosition(
    const SEntityRecord& record, std::uint32_t beat, const SFrameCodec& codec
  ) noexcept;

  /**
   * The server side of dead reckoning for one view and entity: `sent` is the record the view
   * holds, `actual` the sim's quantised position this beat and `previousActual` last beat's.
   * When the prediction is more than `tolerance` steps off on any axis, re-anchors `sent` at
   * `actual` with the last beat's motion as velocity (a new record is anchored where it is
   * created, with zero velocity, by its builder); otherwise
   * leaves the position fields alone. Returns whether it re-anchored.
   */
  bool ApplyDeadReckoning(
    SEntityRecord& sent, const QuantizedPosition& actual, const QuantizedPosition& previousActual, std::uint32_t beat,
    std::uint32_t tolerance, const SFrameCodec& codec
  ) noexcept;

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
