#include "headless/ReplaySyncWriters.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"

// Engine addition, server mode: see ReplaySyncWriters.h.

namespace faf::headless
{
  namespace
  {
    std::mutex gLock;
    std::map<std::string, std::map<std::string, std::uint64_t>> gWrites; // key -> call site -> writes
    std::atomic<bool> gInstalled{false};
    LuaPlus::LuaState* gSimState = nullptr; // set by the init form, in the sim thread
    std::string gInstallError;

    // Runs once in the sim's Lua state. `rec(key, level)` is the C recorder; `level` is the
    // writer's stack level seen from it (3 through `__newindex` and its handler, 2 through the
    // `table.insert` wrapper). Every table in the
    // sim shares one default metatable (empty in the game's Lua); a recorded table gets a copy
    // of it plus a `__newindex`. Writes of nil (the engine clears `PausedBy` every beat) are not
    // counted.
    constexpr const char* kInstallScript = R"lua(
local rec = __faf_sync_record
local setmetatable, getmetatable, rawset, type, unpack = setmetatable, getmetatable, rawset, type, unpack
local defaultmt = getmetatable({})
local watched = setmetatable({}, { __mode = "k" })
local function recorded(t, onwrite)
  local mt = {}
  local old = getmetatable(t)
  if old then for name, value in old do mt[name] = value end end
  local prior = mt.__newindex
  mt.__newindex = function(s, k, v)
    onwrite(k, v)
    if type(prior) == "function" then prior(s, k, v)
    elseif type(prior) == "table" then prior[k] = v
    else rawset(s, k, v) end
  end
  setmetatable(t, mt)
end
local function watch(t, key)
  if type(t) == "table" and watched[t] == nil and getmetatable(t) == defaultmt then
    watched[t] = key
    recorded(t, function(k, v) if v ~= nil then rec(key, 3) end end)
  end
end
for k, v in Sync do watch(v, k) end
recorded(Sync, function(k, v) if v ~= nil then rec(k, 3) watch(v, k) end end)
local insert = table.insert
table.insert = function(t, ...)
  local key = watched[t]
  if key ~= nil then rec(key, 2) end
  return insert(t, unpack(arg))
end
)lua";

    [[nodiscard]] std::string ValueText(lua_State* const state, const int index)
    {
      switch (lua_type(state, index)) {
      case LUA_TSTRING:
        return lua_tostring(state, index);
      case LUA_TNUMBER:
        return gpg::STR_Printf("[%g]", static_cast<double>(lua_tonumber(state, index))).c_str();
      default:
        return std::string("<") + lua_typename(state, lua_type(state, index)) + ">";
      }
    }

    /** A script's path inside its archive ("lua/sim/score.lua"), or Lua's short name. */
    [[nodiscard]] std::string SourceName(const lua_Debug& frame)
    {
      std::string path = frame.source != nullptr ? frame.source : "";
      for (char& c : path) {
        c = c == '\\' ? '/' : c;
      }
      for (const char* const marker : {".nx2/", ".scd/", ".zip/"}) {
        if (const std::size_t at = path.find(marker); at != std::string::npos) {
          path = path.substr(at + std::strlen(marker));
          while (!path.empty() && path.front() == '/') {
            path.erase(0, 1);
          }
          return path;
        }
      }
      return frame.short_src;
    }

    int RecordSyncWrite(lua_State* const state)
    {
      // The writer's level comes as argument 2; no frame there means the metamethod was called
      // from C++.
      const int level = lua_type(state, 2) == LUA_TNUMBER ? static_cast<int>(lua_tonumber(state, 2)) : 2;
      std::string site = "C++ (no Lua caller)";
      lua_Debug frame{};
      if (lua_getstack(state, level, &frame) != 0 && lua_getinfo(state, "Sl", &frame) != 0) {
        site = frame.currentline >= 0 ? gpg::STR_Printf("%s:%d", SourceName(frame).c_str(), frame.currentline).c_str()
                                      : gpg::STR_Printf("%s (C function)", SourceName(frame).c_str()).c_str();
      }
      const std::string key = ValueText(state, 1);
      std::lock_guard<std::mutex> lock(gLock);
      ++gWrites[key][site];
      return 0;
    }

    void InstallHook(lua_State* const state, lua_Debug* const)
    {
      // The hook fires on every call until `Sync` exists. Raw access only: the sim's globals
      // table has an `__index` (lua/system/config.lua), whose call would re-enter this hook.
      static thread_local bool inside = false;
      if (gInstalled.load() || inside) {
        return;
      }
      inside = true;
      struct SLeave
      {
        ~SLeave() { inside = false; }
      } leave;
      lua_pushstring(state, "Sync");
      lua_rawget(state, LUA_GLOBALSINDEX);
      const bool ready = lua_type(state, -1) == LUA_TTABLE;
      lua_pop(state, 1);
      if (!ready) {
        return; // SimSync.lua has not run yet
      }
      if (!moho::SCR_LuaDoString(kInstallScript, gSimState)) {
        std::lock_guard<std::mutex> lock(gLock);
        gInstallError = "the install script failed (see the log)";
      }
      gInstalled.store(true);
      (void)lua_sethook(state, nullptr, 0, 0);
    }
  } // namespace

  namespace
  {
    /** Runs on every new sim Lua state, in the sim thread, before the sim's scripts. */
    class CSyncWritersInitForm final : public moho::CScrLuaInitForm
    {
    public:
      explicit CSyncWritersInitForm(moho::CScrLuaInitFormSet& set)
        : CScrLuaInitForm(set, "__faf_sync_record", "headless", "headless --sync-writers")
      {}

      void Run(LuaPlus::LuaState* const state) override
      {
        gSimState = state;
        lua_register(state->m_state, "__faf_sync_record", &RecordSyncWrite);
        (void)lua_sethook(state->m_state, &InstallHook, LUA_MASKCALL, 0);
      }
    };
  } // namespace

  void CSyncWriters::Enable()
  {
    static bool enabled = false;
    if (enabled) {
      return;
    }
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      static CSyncWritersInitForm form(*set); // links itself into the set for the process's life
      enabled = true;
    }
  }

  bool CSyncWriters::Installed() const noexcept
  {
    return gInstalled.load();
  }

  std::string CSyncWriters::Write(const std::string& path) const
  {
    std::lock_guard<std::mutex> lock(gLock);
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "w") != 0 || file == nullptr) {
      return "sync writers: cannot write " + path;
    }
    std::fprintf(file, "# key\twrites\tcall site (headless --sync-writers)\n");
    std::size_t sites = 0;
    std::uint64_t writes = 0;
    for (const auto& [key, bySite] : gWrites) {
      for (const auto& [site, count] : bySite) {
        std::fprintf(file, "%s\t%llu\t%s\n", key.c_str(), static_cast<unsigned long long>(count), site.c_str());
        ++sites;
        writes += count;
      }
    }
    std::fclose(file);
    return gpg::STR_Printf(
      "sync writers: %zu keys, %zu call sites, %llu writes%s%s", gWrites.size(), sites,
      static_cast<unsigned long long>(writes), gInstalled.load() ? "" : " (hook never installed)",
      gInstallError.empty() ? "" : (std::string(", install error: ") + gInstallError).c_str()
    ).c_str();
  }
} // namespace faf::headless
