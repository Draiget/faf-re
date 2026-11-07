#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

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
}

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
  };

  /** Reads a whole `View` message (its kind byte first); its lanes must end at the message's last byte. */
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
  };

  class CServerViewClient
  {
  public:
    /** `rules`: the client's own, from its own load of the match's map and mods; must outlive this. */
    CServerViewClient(moho::RRuleGameRules& rules, const SServerGameInfo& info);

    /** One view into `packet`'s entity lanes (a fresh packet: nothing else to start from), and its army and grid lanes. */
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
    void SeedTerrain(const moho::CHeightField& heights) { mRebuilder->SeedTerrain(heights); }
    [[nodiscard]] const wire::CSessionTableReaders& Tables() const noexcept { return *mTables; }

    [[nodiscard]] const SServerGameInfo& Info() const noexcept { return mInfo; }
    [[nodiscard]] const std::vector<wire::SArmyRecord>& Armies() const noexcept { return mArmies; }
    [[nodiscard]] const std::vector<wire::SGridSlot>& Grids() const noexcept { return mGrids; }
    [[nodiscard]] const SServerViewStats& Stats() const noexcept { return mStats; }
    [[nodiscard]] const SRebuildStats& RebuildStats() const noexcept { return mRebuilder->Stats(); }
    /** The last merged frame shown. */
    [[nodiscard]] const wire::SViewFrame* Shown() const noexcept { return mRebuilder->Baseline(); }
    [[nodiscard]] std::uint64_t BlipsLeftOut() const noexcept { return mMerger.BlipsLeftOut(); }

  private:
    SServerGameInfo mInfo;
    wire::SFrameCodec mCodec{};
    std::unique_ptr<wire::CSessionTableReaders> mTables;
    std::unique_ptr<CSyncRebuilder> mRebuilder;
    CViewFrameMerger mMerger;
    std::vector<wire::SArmyRecord> mArmies;
    bool mHaveArmies = false;
    std::vector<wire::SGridSlot> mGrids;
    SServerViewStats mStats;
  };
} // namespace faf::remote::client
