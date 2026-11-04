#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "lua/LuaObject.h"
#include "moho/sim/Sim.h"

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
// Every player's payload is put together from encoded pieces of those tables, so routing creates
// no Lua tables on the way out, and the sim's own heap sees only the writes the game makes.
//
// What this can't reach from the engine, for the user's decision (WP6.6): code running in a forked
// Lua thread reads focus -1 and can't be wrapped, since a thread can't yield across a C call. That
// leaves `AIBrain:PlayVOSoundThread` (voice-overs) and `lua/sim/Recall.lua`'s voting thread, plus
// `DiplomacyHandler`'s announcement to third parties.

namespace faf::remote
{
  /** How a top-level `Sync` key of the focus -1 table reaches the players. */
  enum class ESyncRoute : std::uint8_t
  {
    Everyone,     // written the same under every focus
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

  /** FAF game version 3835's keys (`.plans/dedicated-server/research/WP6.1-sync-keys.md`), sorted. */
  [[nodiscard]] std::span<const SSyncKeyRoute> SyncKeyRoutes() noexcept;
  /** The route of `key`, or `ESyncRoute::Observers` with `known` false. */
  [[nodiscard]] ESyncRoute RouteOfSyncKey(std::string_view key, bool& known) noexcept;

  class CSyncRouter final : public moho::ISyncRouting
  {
  public:
    /** A view's id for a sim id, for ids written into its payload (WP6.10). */
    using IdTranslator = std::function<std::uint32_t(std::size_t view, std::uint32_t simId)>;

    explicit CSyncRouter(std::size_t viewCount);
    ~CSyncRouter() override;

    void SetIdTranslator(IdTranslator translator) { mTranslate = std::move(translator); }
    /** Each view's payloads go to `<prefix>_<view>.bin` too (`tools/sync-routing/compare.py`). */
    void SetDumpPrefix(std::string prefix) { mDumpPrefix = std::move(prefix); }

    [[nodiscard]] std::int32_t FocusForLua() const noexcept override;
    void EnterCommand(moho::Sim& sim) override;
    void LeaveCommand(moho::Sim& sim) override;
    bool Print(const msvc8::string& line) override;
    void OnSyncTable(moho::Sim& sim, LuaPlus::LuaObject& syncTable, const moho::SSyncData& packet) override;

    [[nodiscard]] std::size_t ViewCount() const noexcept { return mPlayers.size(); }
    /** `view`'s `Sync` table of the last beat, encoded as `LuaObject::ToByteStream` encodes one. */
    [[nodiscard]] std::span<const std::uint8_t> Payload(const std::size_t view) const noexcept { return mPlayers[view].payload; }
    /** `view`'s print lines of the last beat. */
    [[nodiscard]] const std::vector<std::string>& Prints(const std::size_t view) const noexcept { return mPlayers[view].prints; }
    /** Calls a fanned-out function made to an engine function not known to only read (should stay 0). */
    [[nodiscard]] std::uint64_t FanOutViolations() const noexcept { return mFanOutViolations; }
    /** Counts and logs one such call; on the sim's thread. */
    void NoteFanOutViolation(const char* name);
    /** Writes of keys `SyncKeyRoutes` doesn't list, which only observers get. */
    [[nodiscard]] std::uint64_t UnknownKeyWrites() const noexcept { return mUnknownKeyWrites; }

    /** From here to `LeaveView`, `Sync` and `GetFocusArmy()` are those of army `view` (-1: the sim's own). */
    void EnterView(moho::Sim& sim, std::int32_t view);
    void LeaveView(moho::Sim& sim);
    /** From here to `LeaveView`, `Sync` is the sim's own and `GetFocusArmy()` -1, inside a command too. */
    void EnterSimOwn(moho::Sim& sim);
    /** The army of the command running now, or -1. */
    [[nodiscard]] std::int32_t SourceArmy(const moho::Sim& sim) const;
    /** Whether the army of `view` counts `army` as an ally, or is it. */
    [[nodiscard]] bool Allied(const moho::Sim& sim, std::size_t view, std::int32_t army) const;
    [[nodiscard]] moho::Sim* CurrentSim() const noexcept { return mSim; }

  private:
    /** One player's side of the routing. */
    struct SPlayerSync
    {
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
    void RouteKey(moho::Sim& sim, LuaPlus::LuaObject& key, std::string_view name, LuaPlus::LuaObject& value);
    void RouteById(moho::Sim& sim, LuaPlus::LuaObject& key, std::string_view name, LuaPlus::LuaObject& value, ESyncRoute route);
    void RouteScore(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void RouteNukes(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void RouteScoreAccum(LuaPlus::LuaObject& key, LuaPlus::LuaObject& value);
    void CloseKey(LuaPlus::LuaObject& key, std::string_view name);

    std::vector<SPlayerSync> mPlayers;
    std::vector<SFrame> mFrames;
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
