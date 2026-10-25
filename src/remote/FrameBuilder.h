#pragma once

#include <cstdint>
#include <map>

#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"

// Engine addition, server mode: the server side of the entities lane. It follows the entity
// state a sim publishes in its sync packets (creations, entity and unit updates, erases and
// deletes, in `CWldSession::DoBeat`'s order) and turns it into one view frame per beat.
// Today it builds the full-vision frame of a canonical (focus -1) packet; the per-view filter
// (WP5.2, the oracle of WP4) sits on top of it later.
//
// Erase versus delete (WP7.7): a deleted entity leaves the frame. An erased one (a prop the
// sim is done with, `Prop::Sync`) stays as an orphaned record, flag `kEntityFlagOrphaned`,
// for `orphanBeats` beats, so a client decoding against any baseline from that window tells
// the two apart: a record that turns orphaned is erased (the client orphans its entity and
// deletes it once its view sees the spot, `UserEntity::OrphanUpdate`), a record that goes
// away while not orphaned is deleted. A client whose baseline is older than the window reads
// an erase as a delete; the server keeps its baselines inside it.

namespace moho
{
  struct SSyncData;
  struct SSTIEntityVariableData;
  struct SSTIUnitVariableData;
}

namespace faf::remote
{
  /** Flag bit of an erased entity's record while the frame keeps it (see above). */
  inline constexpr std::uint16_t kEntityFlagOrphaned = 1u << 12;

  /** How long an erased record stays in the frame: 5 seconds of beats. */
  inline constexpr std::uint32_t kDefaultOrphanBeats = 50;

  /** Being built, dead, the visibility mode and the layer, as the record's 16 flag bits. */
  [[nodiscard]] std::uint16_t PackEntityFlags(const moho::SSTIEntityVariableData& data) noexcept;

  /** The reverse of `PackEntityFlags`, into `data` (the orphan bit is not entity data). */
  void UnpackEntityFlags(std::uint16_t flags, moho::SSTIEntityVariableData& data) noexcept;

  /** Hidden, alt footprint, alt footprint 2, destroyed by a kill, refresh UI: `SAppearance::visualFlags`. */
  [[nodiscard]] std::uint8_t PackVisualFlags(const moho::SSTIEntityVariableData& data) noexcept;

  /**
   * A frame's appearance block, written into entity data: everything but the mesh (the caller
   * resolves the ordinal), the sounds and the underlay texture.
   */
  void UnpackAppearance(const wire::SAppearance& look, moho::SSTIEntityVariableData& data);

  /** A frame's unit block, written into a unit update's data. */
  void UnpackUnitFields(const wire::SUnitFields& unit, moho::SSTIUnitVariableData& data) noexcept;

  class CViewFrameBuilder
  {
  public:
    CViewFrameBuilder(
      const wire::SContentTables& tables, const wire::SFrameCodec& codec, std::uint32_t orphanBeats = kDefaultOrphanBeats
    );

    /** Applies one packet's entity lanes to the world the frames are built from. */
    void Apply(const moho::SSyncData& packet);

    /** The frame of the world as it stands, stamped with `beat` and the next frame id. */
    [[nodiscard]] wire::SViewFrame Build(std::uint32_t beat);

    [[nodiscard]] const wire::SFrameCodec& Codec() const noexcept { return mCodec; }
    [[nodiscard]] std::size_t EntityCount() const noexcept { return mWorld.size(); }
    /** Creations whose blueprint is missing from the content tables (should stay 0). */
    [[nodiscard]] std::uint64_t UnknownBlueprints() const noexcept { return mUnknownBlueprints; }

  private:
    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    std::uint32_t mOrphanBeats;
    std::map<std::uint32_t, wire::SEntityRecord> mWorld;
    std::map<std::uint32_t, std::uint32_t> mOrphanedAt; // id -> beat of its erase
    std::uint32_t mNextFrameId = 1;
    std::uint64_t mUnknownBlueprints = 0;
  };

  /**
   * Dead reckoning for one view (WP7.5): rewrites each record of a built frame so it keeps the
   * anchor the view holds while the view's prediction stays within `tolerance` quantiser steps
   * of the sim's position, and re-anchors it otherwise. Frames go through it in beat order.
   */
  class CDeadReckoner
  {
  public:
    explicit CDeadReckoner(std::uint32_t tolerance) noexcept
      : mTolerance(tolerance)
    {}

    /** `codec.deadReckoning` must be on. */
    void Apply(wire::SViewFrame& frame, const wire::SFrameCodec& codec);

    [[nodiscard]] std::uint32_t Tolerance() const noexcept { return mTolerance; }
    [[nodiscard]] std::uint64_t Reanchors() const noexcept { return mReanchors; }

  private:
    struct SSent
    {
      wire::SEntityRecord record;        // as the view holds it
      wire::QuantizedPosition actual{};  // the sim's position that beat
    };

    std::uint32_t mTolerance;
    std::map<std::uint32_t, SSent> mSent;
    std::uint64_t mReanchors = 0;
  };
} // namespace faf::remote
