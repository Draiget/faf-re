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
#include "moho/entity/EntityDb.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/SimDriver.h"
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
      {"Reclaim", ESyncRoute::Everyone},
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
     * readers; the rest are the Lua library's and the log's, which touch no sim state.
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
            "upper", "OkayToMessWithArmy", "ArmyIsCivilian", "EntityCategoryContains"}) {
        if (std::strcmp(name, known) == 0) {
          return true;
        }
      }
      return false;
    }

    void FanOutCallHook(lua_State* const state, lua_Debug* const debug)
    {
      if (lua_getinfo(state, "Sn", debug) != 0 && debug->what != nullptr && std::strcmp(debug->what, "C") == 0 && !ReadsOnly(debug->name)
          && sActiveRouter != nullptr) {
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
      if (router != nullptr && router->CurrentSim() != nullptr && name != nullptr
          && std::strcmp(name, "SharePaintingBrushStroke") == 0) {
        moho::Sim& sim = *router->CurrentSim();
        const std::int32_t source = router->SourceArmy(sim);
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
     * A method that writes per-player data only under its object's own focus: once, under the
     * owner's. `Unit:SendNotifyMessage` (`lua/sim/Unit.lua:4971`).
     */
    int OwnerThunk(lua_State* const state)
    {
      const int argumentCount = lua_gettop(state);
      CSyncRouter* const router = sActiveRouter;
      const int army = router != nullptr && router->CurrentSim() != nullptr && argumentCount > 0 && lua_istable(state, 1)
                         ? ArmyOfSelf(state, 1)
                         : 0;
      if (army <= 0 || static_cast<std::size_t>(army) > router->ViewCount()) {
        const int base = lua_gettop(state);
        CallOriginal(state, argumentCount, LUA_MULTRET);
        return lua_gettop(state) - base;
      }
      SViewScope scope(*router, *router->CurrentSim(), army - 1);
      const int base = lua_gettop(state);
      CallOriginal(state, argumentCount, LUA_MULTRET);
      return lua_gettop(state) - base;
    }

    /**
     * `DiplomacyHandler(action)` (`lua/SimDiplomacy.lua:6`) writes the action for its target only
     * under the target's focus, and changes alliances once: once, under `action.To`'s.
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
      if (army <= 0 || static_cast<std::size_t>(army) > router->ViewCount()) {
        CallOriginal(state, argumentCount, 0);
        return 0;
      }
      SViewScope scope(*router, *router->CurrentSim(), army - 1);
      CallOriginal(state, argumentCount, 0);
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
    };
  } // namespace

  std::span<const SSyncKeyRoute> SyncKeyRoutes() noexcept
  {
    return kRoutes;
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
  }

  CSyncRouter::~CSyncRouter()
  {
    if (sActiveRouter == this) {
      sActiveRouter = nullptr;
    }
  }

  std::int32_t CSyncRouter::FocusForLua() const noexcept
  {
    return mFrames.empty() ? -1 : mFrames.back().view;
  }

  std::int32_t CSyncRouter::SourceArmy(const moho::Sim& sim) const
  {
    // `GetArmyOfCommandSource` (`lua/SimUtils.lua`): the army the source may command. A source that
    // commands no army is an observer's.
    const auto source = static_cast<unsigned int>(sim.mCurCommandSource);
    for (std::size_t army = 0; army < sim.mArmiesList.size() && army < mPlayers.size(); ++army) {
      const moho::CArmyImpl* const candidate = sim.mArmiesList[army];
      if (candidate != nullptr && candidate->mVarDat.mValidCommandSources.Contains(source)) {
        return static_cast<std::int32_t>(army);
      }
    }
    return -1;
  }

  void CSyncRouter::EnterCommand(moho::Sim& sim)
  {
    EnterView(sim, SourceArmy(sim));
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

  bool CSyncRouter::Print(const msvc8::string& line)
  {
    const std::int32_t view = FocusForLua();
    if (view < 0) {
      return false;
    }
    mPlayers[static_cast<std::size_t>(view)].nextPrints.emplace_back(line.c_str());
    return true;
  }

  void CSyncRouter::InstallWrappers(moho::Sim& sim)
  {
    mWrappersInstalled = true;
    LuaPlus::LuaState* const luaState = sim.mLuaState;
    lua_State* const state = luaState->m_state;
    LuaPlus::LuaObject globals = luaState->GetGlobals();
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
    if (army < 0 || view >= sim.mArmiesList.size()) {
      return false;
    }
    if (view == static_cast<std::size_t>(army)) {
      return true;
    }
    const moho::CArmyImpl* const candidate = sim.mArmiesList[view];
    return candidate != nullptr && candidate->mVarDat.mAllies.Contains(static_cast<unsigned int>(army));
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
      std::int32_t owner = entity != nullptr ? entity->GetArmyIndex() : -1;
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
                                                              : (owner < 0 || static_cast<std::size_t>(owner) == index);
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
      const bool isDefeated = !defeated.IsNil() || (scoreArmy != nullptr && scoreArmy->mVarDat.mIsOutOfGame != 0u);
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
      AppendNumber(out, static_cast<float>(index + 1u));
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
          if (!key.IsString() || (syncTable.IsTable() && !syncTable[key.GetString()].IsNil())) {
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
      for (const msvc8::string& line : packet.mPrintField) {
        view.prints.emplace_back(line.c_str());
      }
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
