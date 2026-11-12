#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "remote/client/EffectLaneApplier.h"
#include "remote/client/SyncRebuilder.h"
#include "remote/client/ViewMerge.h"
#include "remote/wire/ArmyLane.h"
#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP11, WP12.1; research/WP11-network-client-map.md): the client half of a server's
// views, with no sim behind it. It reads the server's `GameInfo` and `View` messages (net/GameLinks.h), merges each
// view's own and team frames, rebuilds the beat's entity lanes into a fresh `SSyncData` (`CSyncRebuilder`) and keeps
// the army and grid lanes as this client holds them. The game client's network driver and the probe's `--rebuild`
// share it.

namespace moho
{
  class CHeightField;
  class RRuleGameRules;
  struct SSyncData;
} // namespace moho

namespace faf::remote::client
{
  /** `GameInfo`: the map's size, the player's army (-1: none) and command source. */
  struct SServerGameInfo
  {
    float mapSizeX = 0.0f;
    float mapSizeZ = 0.0f;
    std::int32_t army = -1;
    std::uint32_t source = 0;
  };

  /** Reads a whole `GameInfo` message (its kind byte first). */
  [[nodiscard]] bool ReadGameInfo(std::span<const std::uint8_t> message, SServerGameInfo& out);

  /** One `View` message, as spans into its bytes: beat, entity counts, then the five lanes. */
  struct SViewMessage
  {
    std::uint32_t beat = 0;
    std::uint64_t ownEntities = 0;
    std::uint64_t teamEntities = 0;
    std::span<const std::uint8_t> own;
    std::span<const std::uint8_t> team;
    std::span<const std::uint8_t> armies;
    std::span<const std::uint8_t> grids;
    std::span<const std::uint8_t> lua;
    std::span<const std::uint8_t> poses; // plan WP8.1: the sixth lane, when the server sends poses
    bool hasPoses = false;
    std::span<const std::uint8_t> effects; // plan WP9.1 step 3: the seventh (wire/EffectLane.h); empty: no op
    std::uint32_t lanesSkipped = 0;        // lanes after those this build knows, skipped
  };

  /**
   * Reads a whole `View` message (its kind byte first); its lanes must end at the message's last byte. Lanes after the
   * effects lane, from a newer server, are skipped.
   */
  [[nodiscard]] bool ReadViewMessage(std::span<const std::uint8_t> message, SViewMessage& out);

  /** One `SessionTables` message, its record as a span into its bytes. */
  struct STablesMessage
  {
    std::uint32_t beat = 0;
    bool reset = false;
    std::span<const std::uint8_t> record; // empty with a reset
  };

  /** Reads a whole `SessionTables` message (its kind byte first). */
  [[nodiscard]] bool ReadTablesMessage(std::span<const std::uint8_t> message, STablesMessage& out);

  /**
   * Plan WP9.3: a client that doesn't run effects yet only keeps and counts them (`CEffectLaneApplier::SetHorizon`),
   * and can't tell when one's lifetime ends, so one no op has named for this many beats is forgotten.
   */
  inline constexpr std::uint32_t kCountedEffectBeats = 600;

  struct SServerViewStats
  {
    std::uint64_t views = 0;
    std::uint64_t applied = 0;
    std::uint64_t frameFailures = 0; // own or team frame not decoding, or not applying
    std::uint64_t armyLanes = 0;
    std::uint64_t armyFailures = 0;
    std::uint64_t gridLanes = 0;
    std::uint64_t gridFailures = 0;
    std::uint64_t blueprintsKnown = 0;
    std::uint64_t tableRecords = 0;
    std::uint64_t tableFailures = 0;
    std::uint64_t tableResets = 0;
    std::uint64_t poseLanes = 0;
    std::uint64_t poseFailures = 0; // pose lanes that didn't decode
    std::uint64_t poseBytes = 0;
    std::uint64_t effectFailures = 0; // effects lanes that didn't decode
  };

  class CServerViewClient
  {
  public:
    /** `rules`: the client's own, from its own load of the match's map and mods; must outlive this. */
    CServerViewClient(moho::RRuleGameRules& rules, const SServerGameInfo& info);

    /** One view into `packet`'s entity lanes (a fresh packet: nothing else to start from), and its army and grid lanes.
     */
    bool Apply(const SViewMessage& view, moho::SSyncData& packet);
    /**
     * A `SessionTables` message (plan WP11 step 4): the sounds, names, deposits and terrain edits the views after it
     * name. A reset forgets the tables: the server sends every record again from the first.
     */
    bool ApplyTables(const STablesMessage& tables);
    /**
     * The heights this client's terrain starts from (its own load of the map): the server's terrain edits are applied
     * to a copy, which each beat's packet then carries as the sim's field would.
     */
    void SeedTerrain(
      const moho::CHeightField& heights
    )
    {
      mRebuilder->SeedTerrain(heights);
    }
    [[nodiscard]] const wire::CSessionTableReaders& Tables() const noexcept
    {
      return *mTables;
    }

    [[nodiscard]] const SServerGameInfo& Info() const noexcept
    {
      return mInfo;
    }
    [[nodiscard]] const std::vector<wire::SArmyRecord>& Armies() const noexcept
    {
      return mArmies;
    }
    [[nodiscard]] const std::vector<wire::SGridSlot>& Grids() const noexcept
    {
      return mGrids;
    }
    [[nodiscard]] const SServerViewStats& Stats() const noexcept
    {
      return mStats;
    }
    [[nodiscard]] const SRebuildStats& RebuildStats() const noexcept
    {
      return mRebuilder->Stats();
    }
    /** The last merged frame shown. */
    [[nodiscard]] const wire::SViewFrame* Shown() const noexcept
    {
      return mRebuilder->Baseline();
    }
    [[nodiscard]] std::uint64_t BlipsLeftOut() const noexcept
    {
      return mMerger.BlipsLeftOut();
    }
    /**
     * Plan WP9.3: each view's effects lane, applied after its frames: entities checked against the frame shown (or
     * the one before, for an emitter placed at an entity the view removed), blueprints against the client's rules.
     * Until effects run outside the sim (WP9.3's hosting), nothing is drawn: the effects are kept and counted.
     */
    [[nodiscard]] const CEffectLaneApplier& Effects() const noexcept
    {
      return *mEffects;
    }

  private:
    /** Whether the frame shown holds an entity with this id; `orRemoved`: or the one before it did. */
    [[nodiscard]] bool HoldsEntity(std::int32_t id, bool orRemoved) const;

    using SEffectTarget = CEffectCountTarget<
      std::function<bool(std::int32_t, bool)>,
      std::function<bool(moho::EEffectOp, const std::string&)>>;

    SServerGameInfo mInfo;
    wire::SFrameCodec mCodec{};
    std::unique_ptr<wire::CSessionTableReaders> mTables;
    std::unique_ptr<CSyncRebuilder> mRebuilder;
    CViewFrameMerger mMerger;
    std::vector<wire::SArmyRecord> mArmies;
    bool mHaveArmies = false;
    std::vector<wire::SGridSlot> mGrids;
    std::vector<wire::SUnitPose> mPoses; // this view's pose lane, while it's applied
    SServerViewStats mStats;
    std::vector<std::uint32_t> mPreviousIds; // the ids of the frame shown before the view being applied
    std::unique_ptr<SEffectTarget> mEffectTarget;
    std::unique_ptr<CEffectLaneApplier> mEffects;
  };
} // namespace faf::remote::client
