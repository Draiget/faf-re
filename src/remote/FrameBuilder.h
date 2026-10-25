#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "boost/shared_ptr.h"

#include "remote/wire/EntityFrame.h"
#include "remote/wire/OrdinalTable.h"
#include "remote/wire/SessionTables.h"

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
  class StatItem;
  template <class T>
  class Stats;
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

  /**
   * A unit's stats tree as `SUnitFields::stats`: every item's path and value interned in the
   * session's name table, sorted by name id.
   */
  void ReadUnitStats(
    moho::Stats<moho::StatItem>& stats, wire::CSessionTableWriters& session, std::vector<wire::SUnitStat>& out
  );

  /** A frame's unit block, written into a unit update's data. */
  void UnpackUnitFields(const wire::SUnitFields& unit, moho::SSTIUnitVariableData& data) noexcept;

  class CViewFrameBuilder
  {
  public:
    CViewFrameBuilder(
      const wire::SContentTables& tables, const wire::SFrameCodec& codec, std::uint32_t orphanBeats = kDefaultOrphanBeats
    );

    /**
     * The session tables sounds and underlay names are interned into (WP7.2); without them the
     * frames name no sounds and no underlays.
     */
    void SetSessionTables(wire::CSessionTableWriters* session) noexcept { mSession = session; }

    /** Applies one packet's entity lanes to the world the frames are built from. */
    void Apply(const moho::SSyncData& packet);

    /** The frame of the world as it stands, stamped with `beat` and the next frame id. */
    [[nodiscard]] wire::SViewFrame Build(std::uint32_t beat);

    [[nodiscard]] const wire::SFrameCodec& Codec() const noexcept { return mCodec; }
    [[nodiscard]] std::size_t EntityCount() const noexcept { return mWorld.size(); }
    /** Creations whose blueprint is missing from the content tables (should stay 0). */
    [[nodiscard]] std::uint64_t UnknownBlueprints() const noexcept { return mUnknownBlueprints; }
    /** Underlay textures that are not plain file textures (should stay 0). */
    [[nodiscard]] std::uint64_t UnknownUnderlays() const noexcept { return mUnknownUnderlays; }
    /** Beats with more resource deposits than the session record may carry (should stay 0). */
    [[nodiscard]] std::uint64_t DepositOverflows() const noexcept { return mDepositOverflows; }
    /** Terrain edits the session record could not carry (should stay 0). */
    [[nodiscard]] std::uint64_t TerrainEditOverflows() const noexcept { return mTerrainEditOverflows; }

  private:
    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    std::uint32_t mOrphanBeats;
    std::map<std::uint32_t, wire::SEntityRecord> mWorld;
    std::map<std::uint32_t, std::uint32_t> mOrphanedAt; // id -> beat of its erase
    std::map<std::uint32_t, boost::shared_ptr<moho::Stats<moho::StatItem>>> mUnitStats; // the sim's live trees
    std::uint32_t mNextFrameId = 1;
    std::uint64_t mUnknownBlueprints = 0;
    std::uint64_t mUnknownUnderlays = 0;
    std::uint64_t mDepositOverflows = 0;
    std::uint64_t mTerrainEditOverflows = 0;
    wire::SUnitDetail mDetailScratch;            // a unit update's detail, before it is compared
    std::vector<wire::SUnitStat> mStatsScratch;  // a unit's stats, likewise
    wire::CSessionTableWriters* mSession = nullptr;
  };

  /**
   * Dead reckoning for one view (WP7.5, WP7.8): rewrites each record of a built frame so it
   * keeps the anchor the view holds while the view's prediction stays within the scheme's
   * tolerance of the sim's position, and re-anchors it, with the motion the scheme fits to the
   * last beats' positions, otherwise. Frames go through it in beat order.
   */
  class CDeadReckoner
  {
  public:
    explicit CDeadReckoner(const wire::SReckoningScheme& scheme) noexcept
      : mScheme(scheme)
    {}

    /** `codec.deadReckoning` must be on; orientations are reckoned with `codec.orientationReckoning`. */
    void Apply(wire::SViewFrame& frame, const wire::SFrameCodec& codec);

    [[nodiscard]] const wire::SReckoningScheme& Scheme() const noexcept { return mScheme; }
    [[nodiscard]] std::uint32_t Tolerance() const noexcept { return mScheme.tolerance; }
    [[nodiscard]] std::uint64_t Reanchors() const noexcept { return mReanchors; }
    [[nodiscard]] std::uint64_t OrientationReanchors() const noexcept { return mOrientationReanchors; }

  private:
    struct SSent
    {
      wire::SEntityRecord anchor; // the motion fields as the view holds them; the rest unused
      std::array<wire::QuantizedPosition, wire::kReckoningHistory> history{}; // the sim's, oldest first
      std::uint32_t historyCount = 0;
      std::array<std::uint32_t, wire::kReckoningHistory> yawHistory{}; // while yaw-only, oldest first
      std::uint32_t yawCount = 0;
      std::uint32_t lastBeat = 0;
    };

    wire::SReckoningScheme mScheme;
    std::map<std::uint32_t, SSent> mSent;
    std::uint64_t mReanchors = 0;
    std::uint64_t mOrientationReanchors = 0;
  };
} // namespace faf::remote
