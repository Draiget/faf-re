#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/unit/core/Unit.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/SessionTables.h"

// Engine addition, server mode (plan WP11.2): the client side of the entities lane. It decodes
// each beat's view frame against the frame it decoded last, and rewrites the packet's entity
// lanes (creations, entity updates, erases, deletes, and which unit updates apply) from the
// frames alone, with the client's own blueprints and its own record of what it last showed,
// so the session's `DoBeat` runs on what the wire carried.
//
// What the wire does not carry yet comes from the packet the rebuilder is handed: unit
// creation constant data (the stats tree), the tick an entity was created, the entity data a
// frame has no field for (mesh, scale, sounds, underlay, attachments, intel attributes) and
// the unit updates themselves, onto which the frame's unit block is written. In loopback that
// packet is the server's own; against a real server the same places take client-owned objects
// (research/WP11.2-sync-rebuild.md). Every such borrowing is counted in `SRebuildStats`.

namespace moho
{
  class RRuleGameRules;
  struct REntityBlueprint;
  struct RMeshBlueprint;
  class RScmResource;
  class CSndParams;
  class StatItem;
  template <class T>
  class Stats;
  class CD3DBatchTexture;
  struct SSyncData;
}

namespace faf::remote::client
{
  /** The client's mesh blueprint for each ordinal of the meshes table (null: not in its rules). */
  [[nodiscard]] std::vector<moho::RMeshBlueprint*> ResolveMeshes(
    moho::RRuleGameRules& rules, const wire::SContentTables& tables
  );

  /** The client's blueprint for each ordinal of the blueprints table (null: not in its rules). */
  [[nodiscard]] std::vector<const moho::REntityBlueprint*> ResolveBlueprints(
    moho::RRuleGameRules& rules, const wire::SContentTables& tables
  );

  struct SRebuildStats
  {
    std::uint64_t frames = 0;
    std::uint64_t frameBytes = 0;
    std::uint64_t decodeFailures = 0;
    std::uint64_t created = 0;
    std::uint64_t erased = 0;
    std::uint64_t deleted = 0;
    std::uint64_t entityUpdates = 0;
    std::uint64_t settleUpdates = 0;       // an update only to bring the last transform to rest
    // Checks against the packet the rebuilder was handed (loopback: the server's packet).
    std::uint64_t createdNotInPacket = 0;
    std::uint64_t packetCreatedNotRebuilt = 0; // e.g. created and deleted in one beat
    std::uint64_t blueprintMismatches = 0;
    std::uint64_t noBlueprint = 0;       // creations with no blueprint (the sim's packet has none either unless blueprintMismatches)
    std::uint64_t eraseMismatches = 0;
    std::uint64_t deleteMismatches = 0;
    std::uint64_t packetUpdatesDropped = 0; // entity or unit updates for ids the client does not hold
    std::uint64_t unitChangesWithoutUpdate = 0;
    std::uint64_t entityDataBorrowed = 0;  // updates the packet also has (compared, not used)
    std::uint64_t meshMismatches = 0;      // client's mesh blueprint versus the packet's
    std::uint64_t meshResourceMismatches = 0;
    std::uint64_t soundMismatches = 0;     // client's ambient/rumble params versus the packet's
    std::uint64_t underlayMismatches = 0;
    std::uint64_t unknownTableIds = 0;     // a sound or name id the session tables do not have
    std::uint64_t unitConstantsMissing = 0;   // creation constants that differ from the packet's
    std::uint64_t tickMismatches = 0;         // creation tick (the beat's) versus the packet's
    std::uint64_t statsApplied = 0;           // unit stat items written into client trees
    std::uint64_t unitUpdates = 0;            // unit updates built by the client
    std::uint64_t unitPosesBorrowed = 0;      // of them, with the packet's poses (the pose lane is WP8)
    std::uint64_t unitDataMismatches = 0;     // client-built unit data versus the packet's, poses aside
    std::uint64_t positionsOutOfRange = 0;  // shown more than a unit from the sim: clamped by the quantiser
    double maxPositionError = 0.0;         // shown versus packet, world units, any axis
    double maxOrientationError = 0.0;      // shown versus packet, degrees between the two rotations
    double decodeSeconds = 0.0;            // DecodeFrame
    double deltaSeconds = 0.0;             // ComputeFrameDelta against the frame shown
    double rebuildSeconds = 0.0;           // the packet's entity lanes
  };

  class CSyncRebuilder
  {
  public:
    CSyncRebuilder(
      const wire::SFrameCodec& codec, std::vector<const moho::REntityBlueprint*> blueprints,
      std::vector<moho::RMeshBlueprint*> meshes
    );

    /**
     * Decodes one entities-lane frame and rewrites `packet`'s entity lanes from it. False,
     * with the packet untouched, when the frame does not decode against the last one.
     */
    bool Apply(std::span<const std::uint8_t> frameBytes, moho::SSyncData& packet);

    [[nodiscard]] const SRebuildStats& Stats() const noexcept { return mStats; }
    /** The last frame decoded: the baseline the next frame must name. */
    [[nodiscard]] const wire::SViewFrame* Baseline() const noexcept { return mHasShown ? &mShown : nullptr; }

  private:
    struct SHeldEntity
    {
      bool live = false; // in the session's id map (not orphaned)
      moho::SSTIEntityVariableData data{};
      boost::shared_ptr<moho::Stats<moho::StatItem>> stats; // a unit's stats tree (the client's own)
      std::unique_ptr<moho::SSTIUnitVariableData> unit;     // a unit's data as last given to the session
    };

    /** A frame's unit detail into a unit's data, with the client's own blueprints and names. */
    void UnpackUnitDetail(const wire::SUnitDetail& detail, moho::SSTIUnitVariableData& data);

    /** Every field but the poses (checks against the packet). */
    [[nodiscard]] bool SameUnitData(const moho::SSTIUnitVariableData& a, const moho::SSTIUnitVariableData& b) const;

    /** Writes a frame's unit stats into the client's tree of that unit. */
    void ApplyUnitStats(const std::vector<wire::SUnitStat>& stats, moho::Stats<moho::StatItem>& tree);

    struct SMeshResource
    {
      bool resolved = false;
      boost::shared_ptr<moho::RScmResource> resource;
    };

    /** The session tables the frames' sound and name ids refer to (WP7.2). */
  public:
    void SetSessionTables(const wire::CSessionTableReaders* session) noexcept { mSession = session; }
    /** The client's rules (the category universe of unit category sets). */
    void SetRules(moho::RRuleGameRules* rules) noexcept { mRules = rules; }

  private:
    struct SUnderlay
    {
      bool resolved = false;
      boost::shared_ptr<moho::CD3DBatchTexture> texture;
    };

    [[nodiscard]] moho::CSndParams* ResolveSound(std::uint32_t id);
    [[nodiscard]] boost::shared_ptr<moho::CD3DBatchTexture> ResolveUnderlay(std::uint32_t id);

    /** Mesh blueprint and resource for a meshes-table ordinal, as `Entity::SetMesh` sets them. */
    void ResolveMesh(std::uint32_t ordinal, moho::SSTIEntityVariableData& data);

    [[nodiscard]] moho::VTransform ShownTransform(const wire::SEntityRecord& record, std::uint32_t beat) const;

    wire::SFrameCodec mCodec;
    std::vector<const moho::REntityBlueprint*> mBlueprints;
    std::vector<moho::RMeshBlueprint*> mMeshes;
    std::vector<SMeshResource> mMeshResources;
    const wire::CSessionTableReaders* mSession = nullptr;
    moho::RRuleGameRules* mRules = nullptr;
    std::vector<moho::CSndParams*> mSounds;   // by sound id, resolved on first use
    std::vector<SUnderlay> mUnderlays;        // by name id
    wire::SViewFrame mShown;
    bool mHasShown = false;
    std::unordered_map<std::uint32_t, SHeldEntity> mHeld;
    SRebuildStats mStats;
  };
} // namespace faf::remote::client
