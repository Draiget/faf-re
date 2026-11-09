#include "remote/SyncRouting.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <utility>

#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaTableIterator.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityId.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/SimDriver.h"
#include "remote/VisibilityOracle.h"
#include "moho/sim/Sim.h"

// Engine addition, server mode: see SyncRouting.h.

namespace faf::remote
{
  namespace
  {
    // `LuaObject::ToByteStream`'s tags.
    constexpr std::uint8_t kTagNumber = 0;
    constexpr std::uint8_t kTagString = 1;
    constexpr std::uint8_t kTagTableBegin = 4;
    constexpr std::uint8_t kTagTableEnd = 5;

    constexpr SSyncKeyRoute kRoutes[] = {
      {"AIBrainData", ESyncRoute::Everyone},
      {"AIChat", ESyncRoute::Everyone},
      {"AIPlatoonInfo", ESyncRoute::Observers},
      {"Abilities", ESyncRoute::Everyone},
      {"AddCameraMarkers", ESyncRoute::Everyone},
      {"AddPingGroups", ESyncRoute::Everyone},
      {"AddTransmissions", ESyncRoute::Everyone},
      {"ArmyTransfer", ESyncRoute::Everyone},
      {"BenchmarkInfo", ESyncRoute::Observers},
      {"BenchmarkModules", ESyncRoute::Observers},
      {"BenchmarkOutput", ESyncRoute::Observers},
      {"BrokenAlliances", ESyncRoute::Everyone},
      {"Buffs", ESyncRoute::Everyone},
      {"CameraRequests", ESyncRoute::Everyone},
      {"CampaignMode", ESyncRoute::Everyone},
      {"CancelCountdown", ESyncRoute::Everyone},
      {"ChangeCameraZoom", ESyncRoute::Everyone},
      {"Cheaters", ESyncRoute::Everyone},
      {"CreateSimDialogue", ESyncRoute::Everyone},
      {"DestroyDialogue", ESyncRoute::Everyone},
      {"DiplomacyAction", ESyncRoute::Everyone},
      {"DiplomacyAnnouncement", ESyncRoute::Everyone},
      {"EndDemo", ESyncRoute::Everyone},
      {"EndGameMovie", ESyncRoute::Everyone},
      {"EnforceRating", ESyncRoute::Everyone},
      {"EnhanceMessage", ESyncRoute::Observers},
      {"EnhanceRestrict", ESyncRoute::Everyone},
      {"Events", ESyncRoute::Everyone},
      {"FloatingEntityText", ESyncRoute::Everyone},
      {"FocusArmyChanged", ESyncRoute::Everyone},
      {"FormedAlliances", ESyncRoute::Everyone},
      {"GameEnded", ESyncRoute::Everyone},
      {"GameHasAIs", ESyncRoute::Everyone},
      {"GameResult", ESyncRoute::Everyone},
      {"GridPresenceUIDebugCell", ESyncRoute::Observers},
      {"GridPresenceUIDebugUpdate", ESyncRoute::Observers},
      {"GridReclaimUIDebugCell", ESyncRoute::Observers},
      {"GridReclaimUIDebugUpdate", ESyncRoute::Observers},
      {"GridReconUIDebugCell", ESyncRoute::Observers},
      {"GridReconUIDebugUpdate", ESyncRoute::Observers},
      {"HelpPrompt", ESyncRoute::Everyone},
      {"HighlightUIPanel", ESyncRoute::Everyone},
      {"IsSavedGame", ESyncRoute::Everyone},
      {"LockInput", ESyncRoute::Everyone},
      {"MPTaunt", ESyncRoute::Everyone},
      {"MassFabs", ESyncRoute::Observers},
      {"MaxPingMarkers", ESyncRoute::Everyone},
      {"MissionText", ESyncRoute::Everyone},
      {"NISMode", ESyncRoute::Everyone},
      {"NISVideo", ESyncRoute::Everyone},
      {"NavCanPathToDebug", ESyncRoute::Observers},
      {"NavDebugGetLabel", ESyncRoute::Observers},
      {"NavDebugGetLabelMetadata", ESyncRoute::Observers},
      {"NavLayerData", ESyncRoute::Everyone},
      {"NewPlayableArea", ESyncRoute::Everyone},
      {"NewTech", ESyncRoute::Everyone},
      {"NukeLaunchData", ESyncRoute::NukeLaunch},
      {"ObjectiveTimer", ESyncRoute::Everyone},
      {"ObjectivesTable", ESyncRoute::Everyone},
      {"ObjectivesUpdateTable", ESyncRoute::Everyone},
      {"OperationComplete", ESyncRoute::Everyone},
      {"Paused", ESyncRoute::Everyone},
      {"PausedBy", ESyncRoute::Everyone},
      {"Ping", ESyncRoute::Everyone},
      {"PlayMFDMovie", ESyncRoute::Everyone},
      {"PlayerQueries", ESyncRoute::Everyone},
      {"PrintText", ESyncRoute::Everyone},
      {"ProfilerData", ESyncRoute::Observers},
      {"QueryResults", ESyncRoute::Everyone},
      {"RecallRequest", ESyncRoute::Observers},
      {"Reclaim", ESyncRoute::Reclaim},
      {"ReleaseIds", ESyncRoute::ReleasedIds},
      {"RemoveCameraMarkers", ESyncRoute::Everyone},
      {"RemovePingGroups", ESyncRoute::Everyone},
      {"RequestPlayerFaction", ESyncRoute::Everyone},
      {"RequestingExit", ESyncRoute::Everyone},
      {"Restrictions", ESyncRoute::Everyone},
      {"Score", ESyncRoute::Score},
      {"ScoreAccum", ESyncRoute::ScoreAccum},
      {"SetAlliedVictory", ESyncRoute::Observers},
      {"SetButtonDisabled", ESyncRoute::Everyone},
      {"SetDialogueText", ESyncRoute::Everyone},
      {"SharePaintingBrushStroke", ESyncRoute::Everyone},
      {"Sounds", ESyncRoute::Everyone},
      {"StartCountdown", ESyncRoute::Everyone},
      {"StartPositions", ESyncRoute::Everyone},
      {"StatsToSend", ESyncRoute::Everyone},
      {"Teamkill", ESyncRoute::Everyone},
      {"TimeoutsRemaining", ESyncRoute::Everyone},
      {"ToggleGamePanels", ESyncRoute::Everyone},
      {"ToggleLifeBarsOff", ESyncRoute::Everyone},
      {"ToggleLifeBarsOn", ESyncRoute::Everyone},
      {"UnitData", ESyncRoute::EntityOwner},
      {"UnlockInput", ESyncRoute::Everyone},
      {"UpdateButtonText", ESyncRoute::Everyone},
      {"UpdatePosition", ESyncRoute::Everyone},
      {"UserConRequests", ESyncRoute::Everyone},
      {"UserUnitEnhancements", ESyncRoute::EntityAllies},
      {"VideoText", ESyncRoute::Everyone},
      {"Voice", ESyncRoute::Observers},
      {"WepPriority", ESyncRoute::Observers},
      {"__ArmyStats", ESyncRoute::Observers},
    };

    constexpr SSyncIdField kIdFields[] = {
      {"CancelCountdown", "entity", ESyncIdAudience::Owner},  // `lua/SimSync.lua:189`
      {"FloatingEntityText", "entity", ESyncIdAudience::Owner}, // `lua/SimSync.lua:164`
      {"Reclaim", "", ESyncIdAudience::Seen},                 // `lua/sim/Prop.lua:390`
      {"ReleaseIds", "", ESyncIdAudience::Owner},             // `lua/sim/Unit.lua:2173`
      {"StartCountdown", "entity", ESyncIdAudience::Owner},   // `lua/SimSync.lua:177`
      {"UnitData", "", ESyncIdAudience::Owner},               // `lua/sim/Unit.lua:79`
      {"UserUnitEnhancements", "", ESyncIdAudience::Allies},  // `lua/SimSync.lua:109`
    };

    /** A stream that appends to a vector, for `LuaObject::ToByteStream`. */
    class CByteVectorStream final : public gpg::Stream
    {
    public:
      explicit CByteVectorStream(std::vector<std::uint8_t>& out) noexcept
        : mOut(out)
      {}

    protected:
      void VirtWrite(const char* const data, const std::size_t size) override
      {
        mOut.insert(mOut.end(), reinterpret_cast<const std::uint8_t*>(data), reinterpret_cast<const std::uint8_t*>(data) + size);
      }

    private:
      std::vector<std::uint8_t>& mOut;
    };

    void Encode(LuaPlus::LuaObject& value, std::vector<std::uint8_t>& out)
    {
      CByteVectorStream stream(out);
      (void)value.ToByteStream(stream);
    }

    void AppendString(std::vector<std::uint8_t>& out, const std::string_view text)
    {
      out.push_back(kTagString);
      out.insert(out.end(), text.begin(), text.end());
      out.push_back(0u);
    }

    void AppendNumber(std::vector<std::uint8_t>& out, const float value)
    {
      out.push_back(kTagNumber);
      const auto* const bytes = reinterpret_cast<const std::uint8_t*>(&value);
      out.insert(out.end(), bytes, bytes + sizeof(value));
    }

    /** An id key of a table written by sim Lua: a string of digits or a number. */
    [[nodiscard]] bool ParseId(const LuaPlus::LuaObject& key, std::uint32_t& id)
    {
      if (key.IsNumber()) {
        id = static_cast<std::uint32_t>(key.GetNumber());
        return true;
      }
      if (!key.IsString()) {
        return false;
      }
      const char* const text = key.GetString();
      const char* const end = text + std::strlen(text);
      return std::from_chars(text, end, id).ptr == end;
    }

    CSyncRouter* sActiveRouter = nullptr;

    /** Enters a view for one call, on every way out of it. */
    struct SViewScope
    {
      CSyncRouter& router;
      moho::Sim& sim;
      SViewScope(CSyncRouter& r, moho::Sim& s, const std::int32_t view)
        : router(r)
        , sim(s)
      {
        router.EnterView(sim, view);
      }
      ~SViewScope() { router.LeaveView(sim); }
    };

    /**
     * Whether an engine function reads only, as a function run once per player must (plan WPR.26):
     * more than one run of a write would change the sim. `Get`, `Is` and `Can` name the sim's
     * readers; the rest are the Lua library's and the log's, which touch no sim state, and
     * `SyncRecallStatus`, whose wrapper here only notes a due tick.
     */
    [[nodiscard]] bool ReadsOnly(const char* const name) noexcept
    {
      if (name == nullptr) {
        return false;
      }
      for (const char* const prefix : {"Get", "Is", "Can"}) {
        if (std::strncmp(name, prefix, std::strlen(prefix)) == 0) {
          return true;
        }
      }
      for (const char* const known :
           {"insert", "remove", "getn", "getsize", "empty", "find", "pairs", "ipairs", "next", "type", "tostring", "tonumber", "unpack",
            "rawget", "getmetatable", "setmetatable", "assert", "import", "WARN", "LOG", "SPEW", "_ALERT", "format", "len", "sub", "lower",
            "upper", "OkayToMessWithArmy", "ArmyIsCivilian", "ArmyIsOutOfGame", "EntityCategoryContains",
            "SyncRecallStatus"}) {
        if (std::strcmp(name, known) == 0) {
          return true;
        }
      }
      return false;
    }

    int RecallResyncThunk(lua_State* state);

    /**
     * What has no name to go by, as a call from C or a metamethod: a category set's `+`, `-` and `*`,
     * which make a new set, and `ResyncRecallVoting`'s wrapper, a call of this file's own.
     */
    [[nodiscard]] bool IsKnownNameless(lua_State* const state, lua_Debug* const debug)
    {
      lua_getinfo(state, "f", debug);
      const lua_CFunction function = lua_tocfunction(state, -1);
      lua_settop(state, -2);
      return function == &moho::cfunc_EntityCategory__add || function == &moho::cfunc_EntityCategory__sub
             || function == &moho::cfunc_EntityCategory__mul || function == &RecallResyncThunk;
    }

    void FanOutCallHook(lua_State* const state, lua_Debug* const debug)
    {
      if (lua_getinfo(state, "Sn", debug) != 0 && debug->what != nullptr && std::strcmp(debug->what, "C") == 0 && !ReadsOnly(debug->name)
          && !(debug->name == nullptr && IsKnownNameless(state, debug)) && sActiveRouter != nullptr) {
        sActiveRouter->NoteFanOutViolation(debug->name != nullptr ? debug->name : "?");
      }
    }

    /** The call hook above, for the runs of one function under each player's focus. */
    struct SFanOutGuard
    {
      lua_State* state;
      lua_Hook hook;
      int mask;
      int count;
      explicit SFanOutGuard(lua_State* const s)
        : state(s)
        , hook(lua_gethook(s))
        , mask(lua_gethookmask(s))
        , count(lua_gethookcount(s))
      {
        lua_sethook(state, &FanOutCallHook, LUA_MASKCALL, 0);
      }
      ~SFanOutGuard() { lua_sethook(state, hook, mask, count); }
    };

    void CallOriginal(lua_State* const state, const int argumentCount, const int results)
    {
      lua_pushvalue(state, lua_upvalueindex(1));
      for (int argument = 1; argument <= argumentCount; ++argument) {
        lua_pushvalue(state, argument);
      }
      lua_call(state, argumentCount, results);
    }

    /**
     * A function that writes only `Sync`, and writes per-player data only under a real focus: once
     * under each view's focus and once as it stands, for observers (WP6.5). `SendData`,
     * `FloatingEntityText`, `StartCountdown`, `CancelCountdown`: `lua/SimPing.lua:171`,
     * `lua/SimSync.lua:160-193`.
     */
    int FanOutThunk(lua_State* const state)
    {
      CSyncRouter* const router = sActiveRouter;
      const int argumentCount = lua_gettop(state);
      if (router != nullptr && router->CurrentSim() != nullptr) {
        moho::Sim& sim = *router->CurrentSim();
        const SFanOutGuard guard(state);
        for (std::size_t view = 0; view < router->ViewCount(); ++view) {
          SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
          CallOriginal(state, argumentCount, 0);
        }
        if (router->FocusForLua() >= 0) {
          return 0; // that view's turn was above; the sim's own table isn't the current one
        }
      }
      CallOriginal(state, argumentCount, 0);
      return 0;
    }

    /**
     * `DoCallback(name, data, units)` (`lua/SimCallbacks.lua:58`), for the callbacks whose writes
     * aren't for their source alone. `SharePaintingBrushStroke` (`:860`) tests a focus read when the
     * file loaded, -1 here, so it would reach everyone; a lockstep client gets it from allies. It
     * writes only `Sync`. `GiveResourcesToPlayer` and the like keep the source's focus.
     */
    int DoCallbackThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const char* const name = argumentCount > 0 && lua_isstring(state, 1) ? lua_tostring(state, 1) : nullptr;
      if (router != nullptr && name != nullptr && std::strcmp(name, "SetRecallVote") == 0) {
        // `ArmyRequestRecall` (`lua/sim/Recall.lua:267`) forks the vote's thread, a local function.
        router->SetForkingRecallVote(true);
        struct SEnd
        {
          CSyncRouter& router;
          ~SEnd() { router.SetForkingRecallVote(false); }
        } end{*router};
        CallOriginal(state, argumentCount, 0);
        return 0;
      }
      if (router != nullptr && router->CurrentSim() != nullptr && name != nullptr
          && std::strcmp(name, "SharePaintingBrushStroke") == 0) {
        moho::Sim& sim = *router->CurrentSim();
        const std::int32_t sourceView = router->SourceView(sim);
        const std::int32_t source = sourceView >= 0 ? router->ViewArmy(static_cast<std::size_t>(sourceView)) : -1;
        const SFanOutGuard guard(state);
        for (std::size_t view = 0; view < router->ViewCount(); ++view) {
          if (router->Allied(sim, view, source)) {
            SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
            CallOriginal(state, argumentCount, 0);
          }
        }
        return 0;
      }
      CallOriginal(state, argumentCount, 0);
      return 0;
    }

    /** `SendChatToReplay(data)` (`lua/SimUtils.lua:1453`) writes for every client, whoever sent it. */
    int SimOwnThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      if (router == nullptr || router->CurrentSim() == nullptr) {
        CallOriginal(state, argumentCount, 0);
        return 0;
      }
      moho::Sim& sim = *router->CurrentSim();
      router->EnterSimOwn(sim);
      struct SLeave
      {
        CSyncRouter& router;
        moho::Sim& sim;
        ~SLeave() { router.LeaveView(sim); }
      } leave{*router, sim};
      CallOriginal(state, argumentCount, 0);
      return 0;
    }

    /**
     * Threads that act only for their brain's player, once they start: what they write depends on
     * that player's focus alone. `lua/aibrain.lua:286` tells the player of a voice-over only when the
     * brain is the player's. A brain's `EnergyExcessThread`
     * (`lua/aibrains/components/EnergyManagerBrainComponent.lua:80`) starts before a server's routing
     * does, so it's found by its field when the routing starts.
     */
    struct SOwnedThread
    {
      const char* module;
      const char* className;
      const char* function;
    };
    constexpr SOwnedThread kOwnedThreads[] = {
      {"/lua/aibrain.lua", "AIBrain", "PlayVOSoundThread"},
    };
    constexpr const char* kOwnedThreadFields[] = {"EnergyExcessThread"};

    /** The army (1-based) of a unit's `Army` or a brain's `GetArmyIndex()`; 0 if neither. */
    [[nodiscard]] int ArmyOfSelf(lua_State* const state, const int index)
    {
      lua_pushstring(state, "Army");
      lua_gettable(state, index);
      int army = lua_isnumber(state, -1) ? static_cast<int>(lua_tonumber(state, -1)) : 0;
      lua_settop(state, -2);
      if (army != 0) {
        return army;
      }
      lua_pushstring(state, "GetArmyIndex");
      lua_gettable(state, index);
      if (lua_isfunction(state, -1)) {
        lua_pushvalue(state, index);
        lua_call(state, 1, 1);
        army = lua_isnumber(state, -1) ? static_cast<int>(lua_tonumber(state, -1)) : 0;
      }
      lua_settop(state, -2);
      return army;
    }

    /**
     * A method that writes per-player data only under its object's own focus: under each view
     * focused on its owner. `Unit:SendNotifyMessage` (`lua/sim/Unit.lua:4971`) writes only `Sync`.
     */
    int OwnerThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const int army = router != nullptr && router->CurrentSim() != nullptr && argumentCount > 0 && lua_istable(state, 1)
                         ? ArmyOfSelf(state, 1)
                         : 0;
      if (army <= 0 || router->ViewOfArmy(army - 1) < 0) {
        const int base = lua_gettop(state);
        CallOriginal(state, argumentCount, LUA_MULTRET);
        return lua_gettop(state) - base;
      }
      moho::Sim& sim = *router->CurrentSim();
      const SFanOutGuard guard(state);
      for (std::size_t view = 0; view < router->ViewCount(); ++view) {
        if (router->ViewArmy(view) == army - 1) {
          SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
          CallOriginal(state, argumentCount, 0);
        }
      }
      return 0;
    }

    /**
     * `DiplomacyHandler(action)` (`lua/SimDiplomacy.lua:6`) writes the action for its target only
     * under the target's focus, and changes alliances: once, under the first view on `action.To`.
     * Its announcement of an alliance made or broken, for everyone but the two sides (`:52`), then
     * goes to each of those.
     */
    int ActionTargetThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      int army = 0;
      if (router != nullptr && router->CurrentSim() != nullptr && argumentCount > 0 && lua_istable(state, 1)) {
        lua_pushstring(state, "To");
        lua_gettable(state, 1);
        army = lua_isnumber(state, -1) ? static_cast<int>(lua_tonumber(state, -1)) : 0;
        lua_settop(state, -2);
      }
      const std::int32_t view = army > 0 ? router->ViewOfArmy(army - 1) : -1;
      if (view < 0) {
        CallOriginal(state, argumentCount, 0);
        return 0;
      }
      moho::Sim& sim = *router->CurrentSim();
      {
        SViewScope scope(*router, sim, view);
        CallOriginal(state, argumentCount, 0);
      }
      lua_pushstring(state, "Action");
      lua_gettable(state, 1);
      const char* const kind = lua_isstring(state, -1) ? lua_tostring(state, -1) : "";
      const bool announced = std::strcmp(kind, "accept") == 0 || std::strcmp(kind, "break") == 0;
      lua_settop(state, -2);
      if (announced) {
        lua_pushstring(state, "From");
        lua_gettable(state, 1);
        const int from = lua_isnumber(state, -1) ? static_cast<int>(lua_tonumber(state, -1)) : 0;
        lua_settop(state, -2);
        LuaPlus::LuaObject announce = moho::SCR_Import(sim.mLuaState, "/lua/simdiplomacy.lua")["SyncAnnouncement"];
        if (announce.IsFunction()) {
          const SFanOutGuard guard(state);
          for (std::size_t other = 0; other < router->ViewCount(); ++other) {
            const std::int32_t otherArmy = router->ViewArmy(other);
            if (otherArmy != army - 1 && otherArmy != from - 1) {
              SViewScope scope(*router, sim, static_cast<std::int32_t>(other));
              announce.PushStack(state);
              lua_pushvalue(state, 1);
              lua_call(state, 1, 0);
            }
          }
        }
      }
      return 0;
    }

    /**
     * `lua/sim/Recall.lua`'s writers, called when the code that runs once found that its focus is on
     * the voting team: once under each view of that team. `SyncRecallVote` and `SyncOpenRecallVote`
     * (which reads the view's own focus), `SyncCancelRecallVote`.
     */
    int RecallTeamThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const std::int32_t focus = router != nullptr ? router->FocusForLua() : -1;
      if (focus < 0 || router->CurrentSim() == nullptr) {
        CallOriginal(state, argumentCount, 0);
        return 0;
      }
      moho::Sim& sim = *router->CurrentSim();
      const SFanOutGuard guard(state);
      for (std::size_t view = 0; view < router->ViewCount(); ++view) {
        if (router->Allied(sim, view, focus)) {
          SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
          CallOriginal(state, argumentCount, 0);
        }
      }
      return 0;
    }

    /**
     * `SyncCloseRecallVote(passed)`: the team's writer, and what the voting thread does for a client
     * off the team when the vote passes (`lua/sim/Recall.lua:195`), which under the requester's focus
     * it doesn't reach.
     */
    int RecallCloseThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const std::int32_t focus = router != nullptr ? router->FocusForLua() : -1;
      const bool passed = argumentCount > 0 && lua_toboolean(state, 1) != 0;
      (void)RecallTeamThunk(state);
      if (!passed || focus < 0 || router->CurrentSim() == nullptr) {
        return 0;
      }
      moho::Sim& sim = *router->CurrentSim();
      LuaPlus::LuaState* const luaState = sim.mLuaState;
      LuaPlus::LuaObject brains = luaState->GetGlobals()["ArmyBrains"];
      LuaPlus::LuaObject brain = brains.IsTable() ? brains[static_cast<int32_t>(focus + 1)] : LuaPlus::LuaObject{};
      LuaPlus::LuaObject nickname = brain.IsTable() ? brain["Nickname"] : LuaPlus::LuaObject{};
      LuaPlus::LuaObject announce = moho::SCR_Import(luaState, "/lua/simdiplomacy.lua")["SyncAnnouncement"];
      if (!announce.IsFunction()) {
        return 0;
      }
      LuaPlus::LuaObject announcement;
      announcement.AssignNewTable(luaState, 0, 2u);
      announcement.SetString("Action", "recall");
      announcement.SetString("Team", nickname.IsString() ? nickname.GetString() : "");
      const SFanOutGuard guard(state);
      for (std::size_t view = 0; view < router->ViewCount(); ++view) {
        if (!router->Allied(sim, view, focus)) {
          SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
          announce.PushStack(state);
          announcement.PushStack(state);
          lua_call(state, 1, 0);
        }
      }
      return 0;
    }

    /**
     * `SyncRecallStatus()`: a lockstep client's sim keeps one thread that sends its status as its
     * cooldown runs out. Here each view has a due tick (`RunRecallStatus`).
     */
    int RecallStatusThunk(lua_State* const state)
    {
      CSyncRouter* const router = sActiveRouter;
      if (router == nullptr || router->CurrentSim() == nullptr) {
        return 0;
      }
      const moho::Sim& sim = *router->CurrentSim();
      const std::int32_t focus = router->FocusForLua();
      for (std::size_t view = 0; view < router->ViewCount(); ++view) {
        const bool due = focus < 0 || (router->SingleViewRecallStatus() > 0 ? static_cast<std::int32_t>(view) == router->CurrentView()
                                                                           : router->Allied(sim, view, focus));
        if (due) {
          router->MarkRecallStatus(view);
        }
      }
      return 0;
    }

    /** `ResyncRecallVoting()` writes for the view whose focus is set: its status too, and no other's. */
    int RecallResyncThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      if (router != nullptr) {
        router->AddSingleViewRecallStatus(1);
      }
      struct SEnd
      {
        CSyncRouter* router;
        ~SEnd()
        {
          if (router != nullptr) {
            router->AddSingleViewRecallStatus(-1);
          }
        }
      } end{router};
      CallOriginal(state, argumentCount, 0);
      return 0;
    }

    /**
     * `AIBrain:SetDefeatStatus(status)` (`lua/aibrain.lua:435`) tells `lua/sim/Recall.lua:45` of a
     * defeat through a function it took before there was a router: what that does, for each view on
     * the army's team, after it has run as it is.
     */
    int RecallDefeatThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const bool recalled = argumentCount > 1 && lua_isstring(state, 2) && std::strcmp(lua_tostring(state, 2), "Recalled") == 0;
      const int army = router != nullptr && argumentCount > 0 && lua_istable(state, 1) ? ArmyOfSelf(state, 1) : 0;
      CallOriginal(state, argumentCount, 0);
      if (army <= 0 || recalled || router->CurrentSim() == nullptr || !router->RecallResync().IsFunction()) {
        return 0;
      }
      moho::Sim& sim = *router->CurrentSim();
      const SFanOutGuard guard(state);
      for (std::size_t view = 0; view < router->ViewCount(); ++view) {
        if (router->Allied(sim, view, army - 1)) {
          SViewScope scope(*router, sim, static_cast<std::int32_t>(view));
          router->RecallResync().PushStack(state);
          lua_call(state, 0, 0);
        }
      }
      return 0;
    }

    struct SWrappedFunction
    {
      const char* module;    // null: a global
      const char* className; // null: a function of the module
      const char* name;
      lua_CFunction thunk;
    };
    constexpr SWrappedFunction kWrapped[] = {
      {"/lua/SimPing.lua", nullptr, "SendData", &FanOutThunk},
      {nullptr, nullptr, "FloatingEntityText", &FanOutThunk},
      {nullptr, nullptr, "StartCountdown", &FanOutThunk},
      {nullptr, nullptr, "CancelCountdown", &FanOutThunk},
      {"/lua/SimDiplomacy.lua", nullptr, "DiplomacyHandler", &ActionTargetThunk},
      {"/lua/sim/Unit.lua", "Unit", "SendNotifyMessage", &OwnerThunk},
      {"/lua/SimCallbacks.lua", nullptr, "DoCallback", &DoCallbackThunk},
      {"/lua/SimUtils.lua", nullptr, "SendChatToReplay", &SimOwnThunk},
      {"/lua/sim/recall.lua", nullptr, "SyncRecallVote", &RecallTeamThunk},
      {"/lua/sim/recall.lua", nullptr, "SyncOpenRecallVote", &RecallTeamThunk},
      {"/lua/sim/recall.lua", nullptr, "SyncCancelRecallVote", &RecallTeamThunk},
      {"/lua/sim/recall.lua", nullptr, "SyncCloseRecallVote", &RecallCloseThunk},
      {"/lua/sim/recall.lua", nullptr, "SyncRecallStatus", &RecallStatusThunk},
      {"/lua/sim/recall.lua", nullptr, "ResyncRecallVoting", &RecallResyncThunk},
      {"/lua/aibrain.lua", "AIBrain", "SetDefeatStatus", &RecallDefeatThunk},
    };
  } // namespace

  std::span<const SSyncKeyRoute> SyncKeyRoutes() noexcept
  {
    return kRoutes;
  }

  std::span<const SSyncIdField> SyncIdFields() noexcept
  {
    return kIdFields;
  }

  ESyncRoute RouteOfSyncKey(const std::string_view key, bool& known) noexcept
  {
    const auto found = std::lower_bound(std::begin(kRoutes), std::end(kRoutes), key, [](const SSyncKeyRoute& entry, const std::string_view value) {
      return entry.key < value;
    });
    known = found != std::end(kRoutes) && found->key == key;
    return known ? found->route : ESyncRoute::Observers;
  }

  CSyncRouter::CSyncRouter(const std::size_t viewCount)
    : mPlayers(viewCount)
  {
    sActiveRouter = this;
    moho::LUA_SetThreadRouting(this);
    for (std::size_t view = 0; view < mPlayers.size(); ++view) {
      mPlayers[view].army = static_cast<std::int32_t>(view);
    }
  }

  CSyncRouter::~CSyncRouter()
  {
    if (sActiveRouter == this) {
      sActiveRouter = nullptr;
      moho::LUA_SetThreadRouting(nullptr);
    }
  }

  std::int32_t CSyncRouter::FocusForLua() const noexcept
  {
    return mFrames.empty() || mFrames.back().view < 0 ? -1 : mPlayers[static_cast<std::size_t>(mFrames.back().view)].army;
  }

  std::int32_t CSyncRouter::ViewOfArmy(const std::int32_t army) const noexcept
  {
    for (std::size_t view = 0; view < mPlayers.size(); ++view) {
      if (mPlayers[view].army == army) {
        return static_cast<std::int32_t>(view);
      }
    }
    return -1;
  }

  std::int32_t CSyncRouter::SourceView(const moho::Sim& sim) const
  {
    const auto source = static_cast<unsigned int>(sim.mCurCommandSource);
    for (std::size_t view = 0; view < mPlayers.size(); ++view) {
      if (mPlayers[view].source == static_cast<std::int32_t>(source)) {
        return static_cast<std::int32_t>(view);
      }
    }
    // Before the first sync, or a source no view's client has: the first army it may command
    // (`GetArmyOfCommandSource`, `lua/SimUtils.lua`). One that commands no army is an observer's.
    for (std::size_t army = 0; army < sim.mArmiesList.size(); ++army) {
      const moho::CArmyImpl* const candidate = sim.mArmiesList[army];
      if (candidate != nullptr && candidate->mVarDat.mValidCommandSources.Contains(source)) {
        return ViewOfArmy(static_cast<std::int32_t>(army));
      }
    }
    return -1;
  }

  void CSyncRouter::FollowCommandSources(const moho::Sim& sim)
  {
    // A session gives humans their sources in army order (`lua/simInit.lua:459-470`, `:480-487`), and
    // an army can hold several: with shared control, its allies' too.
    std::int32_t human = 0;
    for (std::size_t view = 0; view < mPlayers.size() && view < sim.mArmiesList.size(); ++view) {
      SPlayerSync& player = mPlayers[view];
      if (player.source >= 0) {
        if (player.army < 0 || static_cast<std::size_t>(player.army) >= sim.mArmiesList.size()) {
          continue;
        }
        const moho::CArmyImpl* const current = sim.mArmiesList[static_cast<std::size_t>(player.army)];
        const auto source = static_cast<unsigned int>(player.source);
        const bool onFocus = current != nullptr && current->mVarDat.mValidCommandSources.Contains(source);
        const bool left = player.sourceOnFocus && !onFocus;
        player.sourceOnFocus = onFocus;
        if (!left) {
          continue; // a view moved with `SetFocusArmy` isn't holding its source there
        }
        // Gone from its army. A defeat just removes it (`lua/sim/MatchState.lua` `ObserverAfterDeath`); a merge
        // gives it to another.
        bool moved = false;
        for (std::size_t army = 0; army < sim.mArmiesList.size(); ++army) {
          const moho::CArmyImpl* const candidate = sim.mArmiesList[army];
          if (candidate != nullptr && candidate->mVarDat.mValidCommandSources.Contains(source)) {
            MoveView(view, static_cast<std::int32_t>(army));
            moved = true;
            break;
          }
        }
        if (!moved && mSourceGone) {
          mSourceGone(view); // plan WP13.6
        }
        continue;
      }
      const moho::CArmyImpl* const army = sim.mArmiesList[view];
      if (army == nullptr) {
        continue;
      }
      for (std::int32_t source = 0; source < 64; ++source) {
        if (army->mVarDat.mValidCommandSources.Contains(static_cast<unsigned int>(source))) {
          player.source = army->mVarDat.mValidCommandSources.Contains(static_cast<unsigned int>(human)) ? human : source;
          player.sourceOnFocus = true;
          ++human;
          break;
        }
      }
    }
  }

  void CSyncRouter::MoveView(const std::size_t view, const std::int32_t army)
  {
    mMoves.emplace_back(view, army);
  }

  void CSyncRouter::RequestResync(const std::size_t view)
  {
    mResyncs.push_back(view);
  }

  void CSyncRouter::SetFocusFromLua(const std::int32_t army)
  {
    // The server's own filter stays -1. A call with no view's focus set has no client to move.
    if (!mFrames.empty() && mFrames.back().view >= 0) {
      MoveView(static_cast<std::size_t>(mFrames.back().view), army);
    }
  }

  void CSyncRouter::ApplyMovesAndResyncs(moho::Sim& sim)
  {
    const auto toLuaArmy = [](const std::int32_t army) { return army == -1 ? -1 : army + 1; };
    for (const auto& [view, army] : mMoves) {
      SPlayerSync& player = mPlayers[view];
      const std::int32_t previous = player.army;
      if (previous == army) {
        continue;
      }
      player.army = army;
      const moho::CArmyImpl* const focused =
        army >= 0 && static_cast<std::size_t>(army) < sim.mArmiesList.size() ? sim.mArmiesList[static_cast<std::size_t>(army)] : nullptr;
      player.sourceOnFocus = focused != nullptr && player.source >= 0
                             && focused->mVarDat.mValidCommandSources.Contains(static_cast<unsigned int>(player.source));
      SViewScope scope(*this, sim, static_cast<std::int32_t>(view));
      try {
        // What `Sim::Sync` calls when a lockstep client's focus changes.
        const LuaPlus::LuaFunction<> note(sim.mLuaState->GetGlobal("NoteFocusArmyChanged"));
        note.Call_Int2(toLuaArmy(army), toLuaArmy(previous));
      } catch (const std::exception& error) {
        gpg::Warnf("sync routing: NoteFocusArmyChanged failed: %s", error.what());
      }
    }
    mMoves.clear();

    for (const std::size_t view : mResyncs) {
      SViewScope scope(*this, sim, static_cast<std::int32_t>(view));
      try {
        // The parts of `OnPostLoad` (`lua/simInit.lua:565`) that write only `Sync`: the others fork
        // threads or re-add objectives, which stay as they are for everyone else.
        for (const char* const module : {"/lua/sim/simuistate.lua", "/lua/simdialogue.lua"}) {
          const LuaPlus::LuaFunction<> onPostLoad(moho::SCR_Import(sim.mLuaState, module)["OnPostLoad"]);
          onPostLoad();
        }
        // `simInit` also imports `/lua/simsync.lua`, a second copy of what `doscript` already ran
        // (`:5`), whose `UnitData` and `Sync` are empty and its own. The live ones are the globals, and
        // the global `NoteFocusArmyChanged` sends the view's unit data and allies' enhancements, the
        // latter replacing `simuistate`'s every unit's, and its pings and recall votes.
        const std::int32_t army = toLuaArmy(mPlayers[view].army);
        const LuaPlus::LuaFunction<> note(sim.mLuaState->GetGlobal("NoteFocusArmyChanged"));
        note.Call_Int2(army, army);
      } catch (const std::exception& error) {
        gpg::Warnf("sync routing: a view's resync failed: %s", error.what());
      }
    }
    mResyncs.clear();
  }

  void CSyncRouter::EnterCommand(moho::Sim& sim)
  {
    EnterView(sim, SourceView(sim));
  }

  void CSyncRouter::EnterSimOwn(moho::Sim& sim)
  {
    mSim = &sim;
    SFrame frame{-1, LuaPlus::LuaObject{}};
    for (const SFrame& outer : mFrames) {
      if (outer.previousSync.IsTable()) {
        // The outermost saved table is the sim's own.
        LuaPlus::LuaObject globals = sim.mLuaState->GetGlobals();
        frame.previousSync = globals["Sync"];
        globals.SetObject("Sync", outer.previousSync);
        break;
      }
    }
    mFrames.push_back(std::move(frame));
  }

  void CSyncRouter::LeaveCommand(moho::Sim& sim)
  {
    LeaveView(sim);
  }

  void CSyncRouter::EnterView(moho::Sim& sim, const std::int32_t view)
  {
    mSim = &sim;
    SFrame frame{view, LuaPlus::LuaObject{}};
    if (view >= 0 && static_cast<std::size_t>(view) < mPlayers.size()) {
      SPlayerSync& target = mPlayers[static_cast<std::size_t>(view)];
      LuaPlus::LuaState* const state = sim.mLuaState;
      LuaPlus::LuaObject globals = state->GetGlobals();
      frame.previousSync = globals["Sync"];
      if (!target.context.IsTable()) {
        // As `lua/SimSync.lua:10-19` sets up `Sync`: code writes straight into these four.
        target.context.AssignNewTable(state, 0, 4u);
        for (const char* const key : {"AIBrainData", "UnitData", "ReleaseIds", "Reclaim"}) {
          LuaPlus::LuaObject inner;
          inner.AssignNewTable(state, 0, 0u);
          target.context.SetObject(key, inner);
        }
      }
      target.contextUsed = true;
      globals.SetObject("Sync", target.context);
    }
    mFrames.push_back(std::move(frame));
  }

  void CSyncRouter::LeaveView(moho::Sim& sim)
  {
    SFrame& frame = mFrames.back();
    if (frame.previousSync.IsTable()) {
      LuaPlus::LuaObject globals = sim.mLuaState->GetGlobals();
      globals.SetObject("Sync", frame.previousSync);
    }
    mFrames.pop_back();
  }

  void CSyncRouter::NoteFanOutViolation(const char* const name)
  {
    ++mFanOutViolations;
    if (std::find(mLoggedKeys.begin(), mLoggedKeys.end(), name) == mLoggedKeys.end()) {
      mLoggedKeys.emplace_back(name);
      gpg::Warnf("sync routing: a function run for each player called '%s', which isn't known to only read", name);
    }
  }

  void CSyncRouter::OnThreadForked(lua_State* const parent, lua_State* const thread)
  {
    if (mForkingRecallVote && lua_gettop(parent) >= 2 && lua_isnumber(parent, 2)) {
      const std::int32_t view = ViewOfArmy(static_cast<std::int32_t>(lua_tonumber(parent, 2)) - 1);
      if (view >= 0) {
        mThreadViews[thread] = view;
      }
      return;
    }
    if (mOwnedThreadFunctions.empty() || lua_gettop(parent) < 2 || !lua_istable(parent, 2)
        || std::find(mOwnedThreadFunctions.begin(), mOwnedThreadFunctions.end(), lua_topointer(parent, 1)) == mOwnedThreadFunctions.end()) {
      return;
    }
    const std::int32_t view = ViewOfArmy(ArmyOfSelf(parent, 2) - 1);
    if (view >= 0) {
      mThreadViews[thread] = view;
    }
  }

  bool CSyncRouter::EnterThread(lua_State* const thread)
  {
    const auto found = mThreadViews.find(thread);
    if (found == mThreadViews.end() || mSim == nullptr) {
      return false;
    }
    EnterView(*mSim, found->second);
    return true;
  }

  void CSyncRouter::LeaveThread()
  {
    LeaveView(*mSim);
  }

  void CSyncRouter::OnThreadEnded(lua_State* const thread)
  {
    mThreadViews.erase(thread);
  }

  bool CSyncRouter::Print(const fa::string& line)
  {
    if (mFrames.empty() || mFrames.back().view < 0) {
      return false;
    }
    mPlayers[static_cast<std::size_t>(mFrames.back().view)].nextPrints.emplace_back(line.c_str());
    return true;
  }

  bool CSyncRouter::WroteUnderFocus(const std::size_t view, const char* const key) const
  {
    const SPlayerSync& player = mPlayers[view];
    return player.contextUsed && player.context.IsTable() && !const_cast<LuaPlus::LuaObject&>(player.context)[key].IsNil();
  }

  void CSyncRouter::InstallWrappers(moho::Sim& sim)
  {
    mWrappersInstalled = true;
    LuaPlus::LuaState* const luaState = sim.mLuaState;
    lua_State* const state = luaState->m_state;
    LuaPlus::LuaObject globals = luaState->GetGlobals();

    for (const SOwnedThread& owned : kOwnedThreads) {
      LuaPlus::LuaObject owner = moho::SCR_Import(luaState, owned.module);
      if (owner.IsTable()) {
        owner = owner[owned.className];
      }
      LuaPlus::LuaObject function = owner.IsTable() ? owner[owned.function] : LuaPlus::LuaObject{};
      if (function.IsFunction()) {
        mOwnedThreadFunctions.push_back(function.m_object.value.p);
      } else {
        gpg::Warnf("sync routing: no %s.%s for its thread to follow", owned.className, owned.function);
      }
    }
    // Before the wrappers go on: these two are called as they are. A session starts with every
    // client's status to send (`init`, `lua/sim/Recall.lua:32`).
    LuaPlus::LuaObject recall = moho::SCR_Import(luaState, "/lua/sim/recall.lua");
    if (recall.IsTable()) {
      mRecallCooldown = recall["ArmyRecallRequestCooldown"];
      mRecallCannot = recall["SyncCannotRequestRecall"];
      for (SPlayerSync& player : mPlayers) {
        player.recallStatusTick = static_cast<std::int64_t>(sim.mCurTick) + 1;
      }
    }
    LuaPlus::LuaObject brains = globals["ArmyBrains"];
    if (brains.IsTable()) {
      for (LuaPlus::LuaTableIterator entry(brains, 1); !entry.m_isDone; entry.Next()) {
        LuaPlus::LuaObject brain = entry.GetValue();
        if (!brain.IsTable()) {
          continue;
        }
        LuaPlus::LuaObject armyField = brain["Army"];
        const std::int32_t view = armyField.IsNumber() ? ViewOfArmy(static_cast<std::int32_t>(armyField.GetNumber()) - 1) : -1;
        if (view < 0) {
          continue;
        }
        for (const char* const field : kOwnedThreadFields) {
          LuaPlus::LuaObject thread = brain[field];
          if (thread.Type() == LUA_TTHREAD) {
            mThreadViews[static_cast<lua_State*>(thread.m_object.value.p)] = view;
          }
        }
      }
    }

    LuaPlus::LuaObject getVersion = moho::SCR_Import(luaState, "/lua/version.lua")["GetVersion"];
    if (getVersion.IsFunction()) {
      const int top = lua_gettop(state);
      getVersion.PushStack(state);
      lua_call(state, 0, 1);
      const char* const version = lua_isstring(state, -1) ? lua_tostring(state, -1) : nullptr;
      if (version == nullptr || kSyncPolicyGameVersion != version) {
        gpg::Warnf(
          "sync routing: the policy was audited on FAF game version %.*s, not %s: keys new since then go to observers only",
          static_cast<int>(kSyncPolicyGameVersion.size()), kSyncPolicyGameVersion.data(), version != nullptr ? version : "(none)"
        );
      }
      lua_settop(state, top);
    }

    LuaPlus::LuaObject modules = globals["__modules"];
    for (const SWrappedFunction& wrapped : kWrapped) {
      LuaPlus::LuaObject owner = wrapped.module != nullptr ? moho::SCR_Import(luaState, wrapped.module) : globals;
      if (wrapped.className != nullptr && owner.IsTable()) {
        owner = owner[wrapped.className];
      }
      if (!owner.IsTable()) {
        gpg::Warnf("sync routing: no %s to wrap %s in", wrapped.className != nullptr ? wrapped.className : wrapped.module, wrapped.name);
        continue;
      }
      LuaPlus::LuaObject original = owner[wrapped.name];
      if (!original.IsFunction()) {
        gpg::Warnf("sync routing: %s is not a function here, so it isn't wrapped", wrapped.name);
        continue;
      }
      const int top = lua_gettop(state);
      original.PushStack(state);
      lua_pushcclosure(state, wrapped.thunk, 1);
      LuaPlus::LuaObject thunk(luaState, -1);
      lua_settop(state, top);
      owner.SetObject(wrapped.name, thunk);
      if (wrapped.thunk == &RecallResyncThunk) {
        mRecallResync = thunk;
      }

      // Classes copy their base's functions when they are made, so the classes that exist already
      // hold the original. Those made from now on copy the wrapper.
      if (wrapped.className != nullptr && modules.IsTable()) {
        for (LuaPlus::LuaTableIterator module(modules, 1); !module.m_isDone; module.Next()) {
          LuaPlus::LuaObject moduleTable = module.GetValue();
          if (!moduleTable.IsTable()) {
            continue;
          }
          for (LuaPlus::LuaTableIterator entry(moduleTable, 1); !entry.m_isDone; entry.Next()) {
            LuaPlus::LuaObject candidate = entry.GetValue();
            if (!candidate.IsTable()) {
              continue;
            }
            LuaPlus::LuaObject method = candidate[wrapped.name];
            if (method.IsFunction() && method.m_object.value.p == original.m_object.value.p) {
              candidate.SetObject(wrapped.name, thunk);
            }
          }
        }
      }
    }
  }

  bool CSyncRouter::Allied(const moho::Sim& sim, const std::size_t view, const std::int32_t army) const
  {
    const std::int32_t focus = view < mPlayers.size() ? mPlayers[view].army : -1;
    if (army < 0 || focus < 0 || static_cast<std::size_t>(focus) >= sim.mArmiesList.size()) {
      return false;
    }
    if (focus == army) {
      return true;
    }
    const moho::CArmyImpl* const candidate = sim.mArmiesList[static_cast<std::size_t>(focus)];
    return candidate != nullptr && candidate->mVarDat.mAllies.Contains(static_cast<unsigned int>(army));
  }

  void CSyncRouter::RunRecallStatus(moho::Sim& sim)
  {
    if (!mRecallCooldown.IsFunction() || !mRecallCannot.IsFunction()) {
      return;
    }
    lua_State* const state = sim.mLuaState->m_state;
    const auto tick = static_cast<std::int64_t>(sim.mCurTick);
    for (std::size_t view = 0; view < mPlayers.size(); ++view) {
      SPlayerSync& player = mPlayers[view];
      if (player.recallStatusTick < 0 || player.recallStatusTick > tick) {
        continue;
      }
      player.recallStatusTick = -1;
      if (player.army < 0) {
        continue;
      }
      // `SyncRecallStatusThread` (`lua/sim/Recall.lua:471`): the status, and when to look again.
      SViewScope scope(*this, sim, static_cast<std::int32_t>(view));
      const int top = lua_gettop(state);
      try {
        mRecallCooldown.PushStack(state);
        lua_pushnumber(state, static_cast<float>(player.army + 1));
        lua_call(state, 1, 2);
        if (lua_isnumber(state, -1)) {
          player.recallStatusTick = tick + std::max<std::int64_t>(1, static_cast<std::int64_t>(lua_tonumber(state, -1)));
        }
        mRecallCannot.PushStack(state);
        lua_pushvalue(state, top + 1);
        lua_call(state, 1, 0);
      } catch (const std::exception& error) {
        gpg::Warnf("sync routing: a view's recall status failed: %s", error.what());
      }
      lua_settop(state, top);
    }
  }

  void CSyncRouter::RouteReclaim(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value)
  {
    // The map's own props label themselves when they are made, before the first beat is over.
    const bool first = sim.mCurBeat <= 1u;
    const std::uint32_t everyView = mPlayers.size() >= 32u ? 0xFFFFFFFFu : (std::uint32_t{1} << mPlayers.size()) - 1u;
    if (value.IsTable()) {
      for (LuaPlus::LuaTableIterator entry(value, 1); !entry.m_isDone; entry.Next()) {
        LuaPlus::LuaObject entryKey = entry.GetKey();
        LuaPlus::LuaObject entryValue = entry.GetValue();
        mScratch.clear();
        Encode(entryKey, mScratch);
        Encode(entryValue, mScratch);
        std::uint32_t id = 0;
        if (first || !ParseId(entryKey, id)) {
          if (ParseId(entryKey, id)) {
            mReclaimFirst.push_back(id);
          }
          for (SPlayerSync& view : mPlayers) {
            view.keyBody.insert(view.keyBody.end(), mScratch.begin(), mScratch.end());
          }
          continue;
        }
        SReclaimLabel& label = mReclaim[id];
        if (label.entry.empty() && !label.listed && label.delivered == 0u && !label.gone) {
          if (!mReclaimFirstSorted) {
            std::sort(mReclaimFirst.begin(), mReclaimFirst.end());
            mReclaimFirstSorted = true;
          }
          if (std::binary_search(mReclaimFirst.begin(), mReclaimFirst.end(), id)) {
            label.delivered = everyView;
          }
        }
        label.entry = mScratch;
        label.fresh = true;
        label.gone = !entryValue.IsTable();
        if (!label.gone) {
          LuaPlus::LuaObject position = entryValue["position"];
          if (position.IsTable()) {
            label.x = static_cast<float>(position[1].GetNumber());
            label.y = static_cast<float>(position[2].GetNumber());
            label.z = static_cast<float>(position[3].GetNumber());
          }
        }
        // A wreck that goes before a view saw it was never there for that view.
        label.pending = label.gone ? label.delivered : everyView;
        if (label.pending == 0u) {
          if (!label.listed) {
            mReclaim.erase(id);
          }
          continue;
        }
        if (!label.listed) {
          label.listed = true;
          mReclaimPending.push_back(id);
        }
      }
    }

    // What views may have now. A label still waiting is looked at every few beats: a player doesn't
    // tell a label's delay from a tenth of a second or so, and there can be many of them.
    const auto beat = static_cast<std::uint32_t>(sim.mCurBeat);
    for (std::size_t i = 0; i < mReclaimPending.size();) {
      const std::uint32_t id = mReclaimPending[i];
      SReclaimLabel& label = mReclaim[id];
      if (label.fresh || ((id + beat) & 3u) == 0u) {
        const Wm3::Vec3f position{label.x, label.y, label.z};
        for (std::size_t view = 0; view < mPlayers.size() && view < 32u; ++view) {
          const std::uint32_t bit = std::uint32_t{1} << view;
          if ((label.pending & bit) != 0u
              && (ViewCanSeePoint(sim, mPlayers[view].army, position, false) || ViewCanSeePoint(sim, mPlayers[view].army, position, true))) {
            mPlayers[view].keyBody.insert(mPlayers[view].keyBody.end(), label.entry.begin(), label.entry.end());
            label.pending &= ~bit;
            label.delivered |= bit;
          }
        }
        label.fresh = false;
      }
      if (label.pending == 0u) {
        label.listed = false;
        if (label.gone) {
          mReclaim.erase(id);
        } else {
          label.entry.clear();
          label.entry.shrink_to_fit();
        }
        mReclaimPending[i] = mReclaimPending.back();
        mReclaimPending.pop_back();
        continue;
      }
      ++i;
    }
    CloseKey(key, "Reclaim");
  }

  void CSyncRouter::CloseKey(LuaPlus::LuaObject& key, const std::string_view name)
  {
    // One key's entries, routed one by one, with what the view's own table holds under that key.
    mScratch.clear();
    Encode(key, mScratch);
    for (SPlayerSync& view : mPlayers) {
      view.body.insert(view.body.end(), mScratch.begin(), mScratch.end());
      view.body.push_back(kTagTableBegin);
      view.body.insert(view.body.end(), view.keyBody.begin(), view.keyBody.end());
      if (view.contextUsed) {
        LuaPlus::LuaObject own = view.context[std::string(name).c_str()];
        if (own.IsTable()) {
          for (LuaPlus::LuaTableIterator entry(own, 1); !entry.m_isDone; entry.Next()) {
            LuaPlus::LuaObject entryKey = entry.GetKey();
            LuaPlus::LuaObject entryValue = entry.GetValue();
            Encode(entryKey, view.body);
            Encode(entryValue, view.body);
          }
        }
      }
      view.body.push_back(kTagTableEnd);
      view.keyBody.clear();
    }
  }

  void CSyncRouter::RouteById(
    moho::Sim& sim, LuaPlus::LuaObject& key, const std::string_view name, LuaPlus::LuaObject& value, const ESyncRoute route
  )
  {
    const auto ownerEntry = [this](const std::uint32_t id) {
      return std::lower_bound(mOwners.begin(), mOwners.end(), id, [](const std::pair<std::uint32_t, std::int32_t>& entry, const std::uint32_t wanted) {
        return entry.first < wanted;
      });
    };
    for (LuaPlus::LuaTableIterator entry(value, 1); !entry.m_isDone; entry.Next()) {
      LuaPlus::LuaObject entryKey = entry.GetKey();
      LuaPlus::LuaObject entryValue = entry.GetValue();
      std::uint32_t id = 0;
      if (!ParseId(entryKey, id)) {
        // Not a unit's: `Sync.UnitData.Chat` (`lua/SimUtils.lua:1455`) is every player's.
        mScratch.clear();
        Encode(entryKey, mScratch);
        Encode(entryValue, mScratch);
        for (SPlayerSync& view : mPlayers) {
          view.keyBody.insert(view.keyBody.end(), mScratch.begin(), mScratch.end());
        }
        continue;
      }
      const moho::Entity* const entity = sim.mEntityDB != nullptr ? sim.mEntityDB->FindEntityById(id) : nullptr;
      // A dead unit's id still says whose it was. A lockstep client gets every unit's death (`false`
      // here, `lua/sim/Unit.lua:2167-2173`) whether it ever saw the unit or not; a player has nothing
      // under another army's id to clear, so that stays with the owner.
      std::int32_t owner = entity != nullptr                                                      ? entity->GetArmyIndex()
                           : moho::ClassifyEntityIdFamily(id) == moho::EEntityIdFamily::Unit ? moho::ExtractEntityIdSourceIndex(id)
                                                                                                : -1;
      if (route == ESyncRoute::EntityOwner) {
        const auto found = ownerEntry(id);
        if (found != mOwners.end() && found->first == id) {
          found->second = owner;
        } else {
          mOwners.insert(found, {id, owner});
        }
      } else if (route == ESyncRoute::ReleasedIds) {
        const auto found = ownerEntry(id);
        if (found != mOwners.end() && found->first == id) {
          owner = found->second;
          mOwners.erase(found);
        }
      }

      mScratch.clear();
      Encode(entryValue, mScratch);
      for (std::size_t index = 0; index < mPlayers.size(); ++index) {
        const bool wanted = route == ESyncRoute::EntityAllies ? Allied(sim, index, owner)
                                                              : (owner < 0 || mPlayers[index].army == owner);
        if (!wanted) {
          continue;
        }
        std::vector<std::uint8_t>& out = mPlayers[index].keyBody;
        const std::uint32_t viewId = mTranslate ? mTranslate(index, id) : id;
        if (viewId == id) {
          Encode(entryKey, out);
        } else if (entryKey.IsNumber()) {
          AppendNumber(out, static_cast<float>(viewId));
        } else {
          char text[16];
          const int length = std::snprintf(text, sizeof(text), "%u", viewId);
          AppendString(out, std::string_view(text, static_cast<std::size_t>(length)));
        }
        out.insert(out.end(), mScratch.begin(), mScratch.end());
      }
    }
    CloseKey(key, name);
  }

  void CSyncRouter::RouteScore(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value)
  {
    LuaPlus::LuaObject options = sim.mLuaState->GetGlobals()["ScenarioInfo"];
    if (options.IsTable()) {
      options = options["Options"];
    }
    LuaPlus::LuaObject scoreOption = options.IsTable() ? options["Score"] : LuaPlus::LuaObject{};
    const bool hidden = !scoreOption.IsString() || std::strcmp(scoreOption.GetString(), "no") == 0;
    LuaPlus::LuaObject brains = sim.mLuaState->GetGlobals()["ArmyBrains"];

    for (LuaPlus::LuaTableIterator entry(value, 1); !entry.m_isDone; entry.Next()) {
      LuaPlus::LuaObject entryKey = entry.GetKey();
      LuaPlus::LuaObject entryValue = entry.GetValue();
      if (!entryKey.IsNumber() || !entryValue.IsTable()) {
        mScratch.clear();
        Encode(entryKey, mScratch);
        Encode(entryValue, mScratch);
        for (SPlayerSync& view : mPlayers) {
          view.keyBody.insert(view.keyBody.end(), mScratch.begin(), mScratch.end());
        }
        continue;
      }
      const auto army = static_cast<std::int32_t>(entryKey.GetNumber()) - 1;
      LuaPlus::LuaObject general = entryValue["general"];
      LuaPlus::LuaObject score = general.IsTable() ? general["score"] : LuaPlus::LuaObject{};
      const float scoreValue = !hidden && score.IsNumber() ? static_cast<float>(score.GetNumber()) : -1.0f;

      // `lua/sim/score.lua:292-308`: the short form. `brain:IsDefeated()` is the army out of the game,
      // which the score's own `Defeated` can show a beat ahead of.
      const moho::CArmyImpl* const scoreArmy =
        army >= 0 && static_cast<std::size_t>(army) < sim.mArmiesList.size() ? sim.mArmiesList[static_cast<std::size_t>(army)] : nullptr;
      LuaPlus::LuaObject defeated = entryValue["Defeated"];
      LuaPlus::LuaObject status = brains.IsTable() ? brains[static_cast<int32_t>(army + 1)] : LuaPlus::LuaObject{};
      status = status.IsTable() ? status["Status"] : LuaPlus::LuaObject{};
      const bool isDefeated = !defeated.IsNil() || (scoreArmy != nullptr && scoreArmy->mVarDat.mIsOutOfGame != 0u)
                              || (status.IsString() && (std::strcmp(status.GetString(), "Defeat") == 0 || std::strcmp(status.GetString(), "Recalled") == 0));
      std::vector<std::uint8_t> shortForm;
      if (isDefeated) {
        AppendString(shortForm, "Defeated");
        shortForm.push_back(3u); // boolean
        shortForm.push_back(1u);
      }
      AppendString(shortForm, "general");
      shortForm.push_back(kTagTableBegin);
      AppendString(shortForm, "score");
      AppendNumber(shortForm, scoreValue);
      shortForm.push_back(kTagTableEnd);

      // The whole form; with score hidden its `general.score` is -1 as well.
      mScratch.clear();
      if (!hidden) {
        Encode(entryValue, mScratch);
      } else {
        mScratch.push_back(kTagTableBegin);
        for (LuaPlus::LuaTableIterator field(entryValue, 1); !field.m_isDone; field.Next()) {
          LuaPlus::LuaObject fieldKey = field.GetKey();
          LuaPlus::LuaObject fieldValue = field.GetValue();
          Encode(fieldKey, mScratch);
          if (!fieldKey.IsString() || std::strcmp(fieldKey.GetString(), "general") != 0 || !fieldValue.IsTable()) {
            Encode(fieldValue, mScratch);
            continue;
          }
          mScratch.push_back(kTagTableBegin);
          for (LuaPlus::LuaTableIterator inner(fieldValue, 1); !inner.m_isDone; inner.Next()) {
            LuaPlus::LuaObject innerKey = inner.GetKey();
            LuaPlus::LuaObject innerValue = inner.GetValue();
            if (innerKey.IsString() && std::strcmp(innerKey.GetString(), "score") == 0) {
              continue;
            }
            Encode(innerKey, mScratch);
            Encode(innerValue, mScratch);
          }
          AppendString(mScratch, "score");
          AppendNumber(mScratch, -1.0f);
          mScratch.push_back(kTagTableEnd);
        }
        mScratch.push_back(kTagTableEnd);
      }
      for (std::size_t index = 0; index < mPlayers.size(); ++index) {
        std::vector<std::uint8_t>& out = mPlayers[index].keyBody;
        Encode(entryKey, out);
        if (!isDefeated && Allied(sim, index, army)) {
          out.insert(out.end(), mScratch.begin(), mScratch.end());
        } else {
          out.push_back(kTagTableBegin);
          out.insert(out.end(), shortForm.begin(), shortForm.end());
          out.push_back(kTagTableEnd);
        }
      }
    }
    CloseKey(key, "Score");
  }

  void CSyncRouter::RouteNukes(moho::Sim& sim, LuaPlus::LuaObject& key, LuaPlus::LuaObject& value)
  {
    // `lua/sim/weapons/DefaultProjectileWeapon.lua:1078-1089`: `army` is 0-based, and an enemy gets
    // no location.
    for (LuaPlus::LuaTableIterator entry(value, 1); !entry.m_isDone; entry.Next()) {
      LuaPlus::LuaObject entryKey = entry.GetKey();
      LuaPlus::LuaObject entryValue = entry.GetValue();
      if (!entryValue.IsTable()) {
        continue;
      }
      LuaPlus::LuaObject army = entryValue["army"];
      const std::int32_t launcher = army.IsNumber() ? static_cast<std::int32_t>(army.GetNumber()) : -1;
      mScratch.clear();
      Encode(entryValue, mScratch);
      for (std::size_t index = 0; index < mPlayers.size(); ++index) {
        std::vector<std::uint8_t>& out = mPlayers[index].keyBody;
        Encode(entryKey, out);
        if (Allied(sim, index, launcher)) {
          out.insert(out.end(), mScratch.begin(), mScratch.end());
        } else {
          out.push_back(kTagTableBegin);
          AppendString(out, "army");
          AppendNumber(out, static_cast<float>(launcher));
          out.push_back(kTagTableEnd);
        }
      }
    }
    CloseKey(key, "NukeLaunchData");
  }

  void CSyncRouter::RouteScoreAccum(LuaPlus::LuaObject& key, LuaPlus::LuaObject& value)
  {
    mScratch.clear();
    for (LuaPlus::LuaTableIterator entry(value, 1); !entry.m_isDone; entry.Next()) {
      LuaPlus::LuaObject entryKey = entry.GetKey();
      if (entryKey.IsString() && std::strcmp(entryKey.GetString(), "focusArmyIndex") == 0) {
        continue;
      }
      LuaPlus::LuaObject entryValue = entry.GetValue();
      Encode(entryKey, mScratch);
      Encode(entryValue, mScratch);
    }
    for (std::size_t index = 0; index < mPlayers.size(); ++index) {
      std::vector<std::uint8_t>& out = mPlayers[index].keyBody;
      out.insert(out.end(), mScratch.begin(), mScratch.end());
      AppendString(out, "focusArmyIndex");
      AppendNumber(out, static_cast<float>(mPlayers[index].army < 0 ? -1 : mPlayers[index].army + 1));
    }
    CloseKey(key, "ScoreAccum");
  }

  void CSyncRouter::RouteKey(moho::Sim& sim, LuaPlus::LuaObject& key, const std::string_view name, LuaPlus::LuaObject& value)
  {
    bool known = false;
    const ESyncRoute route = RouteOfSyncKey(name, known);
    if (!known) {
      ++mUnknownKeyWrites;
      if (std::find(mLoggedKeys.begin(), mLoggedKeys.end(), name) == mLoggedKeys.end()) {
        mLoggedKeys.emplace_back(name);
        gpg::Warnf("sync routing: Sync key '%s' has no route: observers only", mLoggedKeys.back().c_str());
      }
    }
    if (value.IsTable()) {
      switch (route) {
        case ESyncRoute::EntityOwner:
        case ESyncRoute::EntityAllies:
        case ESyncRoute::ReleasedIds:
          RouteById(sim, key, name, value, route);
          return;
        case ESyncRoute::Score:
          RouteScore(sim, key, value);
          return;
        case ESyncRoute::Reclaim:
          RouteReclaim(sim, key, value);
          return;
        case ESyncRoute::NukeLaunch:
          RouteNukes(sim, key, value);
          return;
        case ESyncRoute::ScoreAccum:
          RouteScoreAccum(key, value);
          return;
        default:
          break;
      }
    }
    if (route == ESyncRoute::Observers) {
      return;
    }
    mScratch.clear();
    Encode(key, mScratch);
    const std::size_t keySize = mScratch.size();
    Encode(value, mScratch);
    const std::string nameText(name);
    for (SPlayerSync& view : mPlayers) {
      LuaPlus::LuaObject own = view.contextUsed ? view.context[nameText.c_str()] : LuaPlus::LuaObject{};
      if (!own.IsTable() || !value.IsTable()) {
        view.body.insert(view.body.end(), mScratch.begin(), mScratch.end());
        continue;
      }
      // The view's own table has this key too: one table with both, its list entries numbered on.
      view.body.insert(view.body.end(), mScratch.begin(), mScratch.begin() + static_cast<std::ptrdiff_t>(keySize));
      view.body.push_back(kTagTableBegin);
      int next = 1;
      for (LuaPlus::LuaObject* const part : {&value, &own}) {
        for (LuaPlus::LuaTableIterator entry(*part, 1); !entry.m_isDone; entry.Next()) {
          LuaPlus::LuaObject entryKey = entry.GetKey();
          LuaPlus::LuaObject entryValue = entry.GetValue();
          if (entryKey.IsNumber()) {
            AppendNumber(view.body, static_cast<float>(next++));
          } else {
            Encode(entryKey, view.body);
          }
          Encode(entryValue, view.body);
        }
      }
      view.body.push_back(kTagTableEnd);
    }
  }

  void CSyncRouter::OnSyncTable(moho::Sim& sim, LuaPlus::LuaObject& syncTable, const moho::SSyncData& packet)
  {
    mSim = &sim;
    if (!mWrappersInstalled) {
      InstallWrappers(sim);
    }
    FollowCommandSources(sim);
    if (!mMoves.empty() || !mResyncs.empty()) {
      ApplyMovesAndResyncs(sim);
    }
    RunRecallStatus(sim);
    for (SPlayerSync& view : mPlayers) {
      view.body.clear();
      view.keyBody.clear();
    }
    if (syncTable.IsTable()) {
      for (LuaPlus::LuaTableIterator entry(syncTable, 1); !entry.m_isDone; entry.Next()) {
        LuaPlus::LuaObject key = entry.GetKey();
        LuaPlus::LuaObject value = entry.GetValue();
        if (key.IsString()) {
          RouteKey(sim, key, key.GetString(), value);
        }
      }
    }

    // What only a view's own table holds, and the beat's table of each view.
    for (SPlayerSync& view : mPlayers) {
      if (view.contextUsed) {
        for (LuaPlus::LuaTableIterator entry(view.context, 1); !entry.m_isDone; entry.Next()) {
          LuaPlus::LuaObject key = entry.GetKey();
          LuaPlus::LuaObject value = entry.GetValue();
          if (!key.IsString()) {
            continue;
          }
          // A key the sim's own table has too came with `RouteKey`, unless that key stops there: a
          // key for observers, which this view's own table may still have an entry of for it.
          bool known = false;
          if (syncTable.IsTable() && !syncTable[key.GetString()].IsNil() && RouteOfSyncKey(key.GetString(), known) != ESyncRoute::Observers) {
            continue;
          }
          Encode(key, view.body);
          Encode(value, view.body);
        }
      }
      view.payload.clear();
      view.payload.reserve(view.body.size() + 2u);
      view.payload.push_back(kTagTableBegin);
      view.payload.insert(view.payload.end(), view.body.begin(), view.body.end());
      view.payload.push_back(kTagTableEnd);
    }

    if (!mDumpPrefix.empty()) {
      for (std::size_t index = 0; index < mPlayers.size(); ++index) {
        const std::string path = mDumpPrefix + "_" + std::to_string(index) + ".bin";
        std::FILE* const file = std::fopen(path.c_str(), packet.mCurBeat <= 0 ? "wb" : "ab");
        if (file != nullptr) {
          const std::vector<std::uint8_t>& payload = mPlayers[index].payload;
          const std::uint32_t head[2] = {static_cast<std::uint32_t>(packet.mCurBeat), static_cast<std::uint32_t>(payload.size())};
          std::fwrite(head, sizeof(head), 1u, file);
          std::fwrite(payload.data(), 1u, payload.size(), file);
          std::fclose(file);
        }
      }
    }

    // Print lines written with no focus reach every player, as they do every lockstep client, after
    // those written under the player's focus.
    for (SPlayerSync& view : mPlayers) {
      view.prints.swap(view.nextPrints);
      view.nextPrints.clear();
      for (const fa::string& line : packet.mPrintField) {
        view.prints.emplace_back(line.c_str());
      }
    }

    // The beat's payloads and print lines are all there (a server sends them now, plan WP11 `LuaSync`).
    if (mPayloadObserver) {
      mPayloadObserver(sim);
    }

    // The views' own tables are emptied as `Sync` is, by the game's own function.
    LuaPlus::LuaObject globals = sim.mLuaState->GetGlobals();
    bool swapped = false;
    LuaPlus::LuaObject canonical;
    for (SPlayerSync& view : mPlayers) {
      if (view.contextUsed) {
        if (!swapped) {
          canonical = globals["Sync"];
          swapped = true;
        }
        globals.SetObject("Sync", view.context);
        (void)moho::SCR_LuaDoString("ResetSyncTable()", sim.mLuaState);
        view.contextUsed = false;
      }
    }
    if (swapped) {
      globals.SetObject("Sync", canonical);
    }
  }
} // namespace faf::remote
