#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "lua/LuaObject.h"
#include "moho/sim/Sim.h"
#include "moho/task/CLuaTask.h"

// Engine addition, server mode (plan §8, WP6, no FAF Lua changes): sim Lua writes one `Sync` table
// for the whole game, and on a lockstep client that table is built under the client's own focus
// army. The server has no such client, so this works out what each player's client would hold:
//
// 1. Contextual focus (WP6.2): while a command or `SimCallback` of a command source runs,
//    `GetFocusArmy()` returns that source's army; otherwise -1.
// 2. Context-tagged writes (WP6.3): while a focus is set, the global `Sync` is that army's own
//    table and `print` goes to that army alone.
// 3. Routing policy (WP6.4): the focus -1 table is split key by key (`SyncKeyRoutes`). A key the
//    table doesn't list goes to observers only and is counted.
// 4. Focus fan-out (WP6.5): the few functions that write per-player data only under a real focus
//    are wrapped by name and run under each player's focus, or their owner's.
//
// 5. Moving views (WP6.7): `SetFocusArmy` from sim Lua, or a command source moved to another army
//    (`MergeArmyPair`, `lua/simInit.lua:514`, a forked thread that reads focus -1, so its own
//    `SetFocusArmy` never runs here), runs `NoteFocusArmyChanged` under that view's new focus.
// 6. Reconnects (WP6.8): `RequestResync` sends what loading a saved game sends for the UI's state,
//    with `NoteFocusArmyChanged` for the units' data, under that view's focus.
//
// 7. Threads of one player: a forked thread reads focus -1, and can't be wrapped, since it can't
//    yield across a C call. The few that belong to one army wholly run under its focus, each time
//    they run (`kOwnedThreads`).
//
// Every player's payload is put together from encoded pieces of those tables, so routing creates
// no Lua tables on the way out, and the sim's own heap sees only the writes the game makes.
//
// 8. Recall votes (`lua/sim/Recall.lua`): the game asks "is this client on the voting team?" once,
//    in a callback or thread that also changes the sim. Those run once, under the voter's or the
//    requester's focus, so the answer is yes; the functions that then write `Sync` run once per view
//    on that team. Its status thread, one per client on a lockstep client's sim, becomes a due tick
//    per view here. A lockstep game never sees any of this: nothing is wrapped without a router.
// 9. Reclaim labels (`Sync.Reclaim`): a lockstep client is told of every wreck, seen or not. A view
//    gets the map's first labels; any later one, or change to one, waits until it sees the spot.

namespace faf::remote
{
  /** How a top-level `Sync` key of the focus -1 table reaches the players. */
  enum class ESyncRoute : std::uint8_t
  {
    Everyone,     // written the same under every focus
    Reclaim,      // a table by prop id: the map's first ones to all, then for views that see the spot
    EntityOwner,  // a table by entity id: the unit's owner (`Unit:UpdateUnitData`, `lua/sim/Unit.lua:77`)
    EntityAllies, // a table by entity id: the unit's owner and allies (`SyncUnitEnhancements`)
    ReleasedIds,  // a table by entity id: whoever got that id's unit data
    Score,        // by army: the view and its allies whole, others their score (`lua/sim/score.lua:283`)
    ScoreAccum,   // everyone, with the view's own `focusArmyIndex` (`lua/sim/score.lua:284`)
    NukeLaunch,   // a list: allies whole, enemies without the location (`DefaultProjectileWeapon.lua:1078`)
    Observers,    // nothing for a player: debug data, or written at focus -1 for observers alone
  };

  struct SSyncKeyRoute
  {
    std::string_view key;
    ESyncRoute route;
  };

  /** The FAF game version `SyncKeyRoutes` was audited on; running on another one is logged. */
  inline constexpr std::string_view kSyncPolicyGameVersion = "3835";
  /** That version's keys (`.plans/dedicated-server/research/WP6.1-sync-keys.md`), sorted. */
  [[nodiscard]] std::span<const SSyncKeyRoute> SyncKeyRoutes() noexcept;
  /** The route of `key`, or `ESyncRoute::Observers` with `known` false. */
  [[nodiscard]] ESyncRoute RouteOfSyncKey(std::string_view key, bool& known) noexcept;

  /** Which players a `Sync` field may name an entity to. */
  enum class ESyncIdAudience : std::uint8_t
  {
    Owner,  // the unit's owner
    Allies, // the unit's owner and allies
    Seen,   // a prop whose label the view may hold: from the map's start, or at a spot it sees
  };

  /**
   * A `Sync` field that holds entity ids (WP6.10). Only recon blips and foreign projectiles are
   * renumbered for a view (remote/ViewIdMap.h), and these fields name units and props, which keep
   * their sim ids; by-id keys go through the translator anyway. The spy checks the audience.
   */
  struct SSyncIdField
  {
    std::string_view key;
    std::string_view field; // empty: the keys of the key's own table
    ESyncIdAudience audience;
  };
  [[nodiscard]] std::span<const SSyncIdField> SyncIdFields() noexcept;

  class CSyncRouter final : public moho::ISyncRouting, public moho::ILuaThreadRouting
  {
  public:
    /** A view's id for a sim id, for ids written into its payload (WP6.10). */
    using IdTranslator = std::function<std::uint32_t(std::size_t view, std::uint32_t simId)>;

    explicit CSyncRouter(std::size_t viewCount);
    ~CSyncRouter() override;

    void SetIdTranslator(IdTranslator translator) { mTranslate = std::move(translator); }
    /** Each view's payloads go to `<prefix>_<view>.bin` too (`tools/sync-routing/compare.py`). */
    void SetDumpPrefix(std::string prefix) { mDumpPrefix = std::move(prefix); }
    /** Called when a beat's payloads are ready, with what they were written under still in place. */
    void SetPayloadObserver(std::function<void(moho::Sim&)> observer) { mPayloadObserver = std::move(observer); }
    /**
     * Plan WP13.6: called on the sim thread with a view whose command source has left every army (a defeat, once the
     * whole team is out and the game allows observers: `lua/sim/MatchState.lua` `ObserverAfterDeath`).
     */
    void SetSourceGoneHandler(std::function<void(std::size_t view)> handler) { mSourceGone = std::move(handler); }

    [[nodiscard]] std::int32_t FocusForLua() const noexcept override;
    void EnterCommand(moho::Sim& sim) override;
    void LeaveCommand(moho::Sim& sim) override;
    bool Print(const fa::string& line) override;
    void SetFocusFromLua(std::int32_t army) override;
    void OnThreadForked(lua_State* parent, lua_State* thread) override;
    bool EnterThread(lua_State* thread) override;
    void LeaveThread() override;
    void OnThreadEnded(lua_State* thread) override;
    void OnSyncTable(moho::Sim& sim, LuaPlus::LuaObject& syncTable, const moho::SSyncData& packet) override;

    [[nodiscard]] std::size_t ViewCount() const noexcept { return mPlayers.size(); }
    /** `view`'s `Sync` table of the last beat, encoded as `LuaObject::ToByteStream` encodes one. */
    [[nodiscard]] std::span<const std::uint8_t> Payload(const std::size_t view) const noexcept { return mPlayers[view].payload; }
    /** Whether sim Lua wrote `key` under this view's focus this beat. */
    [[nodiscard]] bool WroteUnderFocus(std::size_t view, const char* key) const;
    /** `view`'s print lines of the last beat. */
    [[nodiscard]] const std::vector<std::string>& Prints(const std::size_t view) const noexcept { return mPlayers[view].prints; }
    /** Calls a fanned-out function made to an engine function not known to only read (should stay 0). */
    [[nodiscard]] std::uint64_t FanOutViolations() const noexcept { return mFanOutViolations; }
    /** Counts and logs one such call; on the sim's thread. */
    void NoteFanOutViolation(const char* name);
    /** Writes of keys `SyncKeyRoutes` doesn't list, which only observers get. */
    [[nodiscard]] std::uint64_t UnknownKeyWrites() const noexcept { return mUnknownKeyWrites; }

    /** The army `view` is focused on, or -1. Each starts on the army of its own index. */
    [[nodiscard]] std::int32_t ViewArmy(const std::size_t view) const noexcept { return mPlayers[view].army; }
    /** The first view focused on `army`, or -1. */
    [[nodiscard]] std::int32_t ViewOfArmy(std::int32_t army) const noexcept;
    /** At the next beat's sync, `view` moves to `army` (-1: an observer) as a lockstep client's focus does. */
    void MoveView(std::size_t view, std::int32_t army);
    /** At the next beat's sync, `view` is sent what a client needs after reconnecting. */
    void RequestResync(std::size_t view);
    /** The view whose focus is set now, or -1. */
    [[nodiscard]] std::int32_t CurrentView() const noexcept { return mFrames.empty() ? -1 : mFrames.back().view; }
    /** `view`'s recall status is sent at this beat's sync. */
    void MarkRecallStatus(const std::size_t view) noexcept { mPlayers[view].recallStatusTick = 0; }
    /** While above 0, `SyncRecallStatus` is for the view whose focus is set, not its whole team. */
    [[nodiscard]] int SingleViewRecallStatus() const noexcept { return mSingleViewRecallStatus; }
    void AddSingleViewRecallStatus(const int delta) noexcept { mSingleViewRecallStatus += delta; }
    /** `ResyncRecallVoting`, for an army's defeat. */
    [[nodiscard]] const LuaPlus::LuaObject& RecallResync() const noexcept { return mRecallResync; }
    /** While set, a thread forked with an army number is that army's recall vote. */
    void SetForkingRecallVote(const bool forking) noexcept { mForkingRecallVote = forking; }

    /** From here to `LeaveView`, `Sync` and `GetFocusArmy()` are those of view `view` (-1: the sim's own). */
    void EnterView(moho::Sim& sim, std::int32_t view);
    void LeaveView(moho::Sim& sim);
    /** From here to `LeaveView`, `Sync` is the sim's own and `GetFocusArmy()` -1, inside a command too. */
    void EnterSimOwn(moho::Sim& sim);
    /** The view whose client sent the command running now, or -1. */
    [[nodiscard]] std::int32_t SourceView(const moho::Sim& sim) const;
    /** Whether the army of `view` counts `army` as an ally, or is it. */
    [[nodiscard]] bool Allied(const moho::Sim& sim, std::size_t view, std::int32_t army) const;
    [[nodiscard]] moho::Sim* CurrentSim() const noexcept { return mSim; }

  private:
    /** One player's side of the routing. */
    struct SPlayerSync
    {
      std::int32_t army = -1;         // what `GetFocusArmy()` returns under this view
      std::int32_t source = -1;       // its client's command source, once known
      bool sourceOnFocus = false;     // the focused army held that source when last looked at
      std::int64_t recallStatusTick = -1; // the tick its recall status is next sent; -1: none due
      LuaPlus::LuaObject context;     // the table writes under this player's focus go to
      bool contextUsed = false;       // since the last beat
      std::vector<std::uint8_t> body; // the entries of the beat's table so far
      std::vector<std::uint8_t> payload;
      std::vector<std::uint8_t> keyBody; // one key's entries, for a key routed entry by entry
      std::vector<std::string> prints;
      std::vector<std::string> nextPrints; // written under this player's focus since the last beat
    };
    struct SFrame
    {
      std::int32_t view;
      LuaPlus::LuaObject previousSync;
    };

    void InstallWrappers(moho::Sim& sim);
    void FollowCommandSources(const moho::Sim& sim);
    void RunRecallStatus(moho::Sim& sim);
    void RouteReclaim(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void ApplyMovesAndResyncs(moho::Sim& sim);
    void RouteKey(moho::Sim& sim, LuaPlus::LuaObject& key, std::string_view name, LuaPlus::LuaObject& value);
    void RouteById(moho::Sim& sim, LuaPlus::LuaObject& key, std::string_view name, LuaPlus::LuaObject& value, ESyncRoute route);
    void RouteScore(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void RouteNukes(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void RouteScoreAccum(LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void CloseKey(LuaPlus::LuaObject& key, std::string_view name);

    std::vector<SPlayerSync> mPlayers;
    std::vector<SFrame> mFrames;
    std::unordered_map<lua_State*, std::int32_t> mThreadViews; // threads that belong to one player
    std::vector<const void*> mOwnedThreadFunctions;            // what such a thread starts with
    std::vector<std::pair<std::size_t, std::int32_t>> mMoves; // view, army: at the next sync
    std::vector<std::size_t> mResyncs;
    LuaPlus::LuaObject mRecallCooldown;   // `ArmyRecallRequestCooldown`, unwrapped
    LuaPlus::LuaObject mRecallCannot;     // `SyncCannotRequestRecall`, unwrapped
    LuaPlus::LuaObject mRecallResync;     // `ResyncRecallVoting`, wrapped

    /** A prop's label not yet where it should be, by prop id. */
    struct SReclaimLabel
    {
      float x = 0.0f;
      float y = 0.0f;
      float z = 0.0f;
      std::vector<std::uint8_t> entry; // its latest key and value, encoded
      std::uint32_t pending = 0;       // views that don't have that yet, by bit
      std::uint32_t delivered = 0;     // views that hold a label for it, by bit
      bool gone = false;
      bool listed = false;             // in `mReclaimPending`
      bool fresh = false;              // written this beat
    };
    std::unordered_map<std::uint32_t, SReclaimLabel> mReclaim;
    std::vector<std::uint32_t> mReclaimPending;
    std::vector<std::uint32_t> mReclaimFirst; // ids of the map's first labels
    bool mReclaimFirstSorted = false;
    int mSingleViewRecallStatus = 0;
    bool mForkingRecallVote = false;
    std::function<void(moho::Sim&)> mPayloadObserver;
    std::function<void(std::size_t)> mSourceGone;
    IdTranslator mTranslate;
    moho::Sim* mSim = nullptr;
    bool mWrappersInstalled = false;
    std::vector<std::uint8_t> mScratch;
    std::vector<std::pair<std::uint32_t, std::int32_t>> mOwners; // sim id -> army, by id: who got its unit data
    std::uint64_t mUnknownKeyWrites = 0;
    std::uint64_t mFanOutViolations = 0;
    std::vector<std::string> mLoggedKeys;
    std::string mDumpPrefix;
  };
} // namespace faf::remote
