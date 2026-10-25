#pragma once

#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

#include "moho/entity/SSTIEntityVariableData.h"
#include "remote/wire/EntityFrame.h"

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
    std::uint64_t entityDataBorrowed = 0;  // updates taking the sounds and underlay from the packet
    std::uint64_t meshMismatches = 0;      // client's mesh blueprint versus the packet's
    std::uint64_t meshResourceMismatches = 0;
    std::uint64_t unitConstantsMissing = 0;
    std::uint64_t positionsOutOfRange = 0;  // shown more than a unit from the sim: clamped by the quantiser
    double maxPositionError = 0.0;
    double decodeSeconds = 0.0;            // DecodeFrame
    double deltaSeconds = 0.0;             // ComputeFrameDelta against the frame shown
    double rebuildSeconds = 0.0;           // the packet's entity lanes         // shown versus packet, world units, any axis
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
    };

    struct SMeshResource
    {
      bool resolved = false;
      boost::shared_ptr<moho::RScmResource> resource;
    };

    /** Mesh blueprint and resource for a meshes-table ordinal, as `Entity::SetMesh` sets them. */
    void ResolveMesh(std::uint32_t ordinal, moho::SSTIEntityVariableData& data);

    [[nodiscard]] moho::VTransform ShownTransform(const wire::SEntityRecord& record, std::uint32_t beat) const;

    wire::SFrameCodec mCodec;
    std::vector<const moho::REntityBlueprint*> mBlueprints;
    std::vector<moho::RMeshBlueprint*> mMeshes;
    std::vector<SMeshResource> mMeshResources;
    wire::SViewFrame mShown;
    bool mHasShown = false;
    std::unordered_map<std::uint32_t, SHeldEntity> mHeld;
    SRebuildStats mStats;
  };
} // namespace faf::remote::client
