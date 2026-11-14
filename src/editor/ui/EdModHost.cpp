#include "editor/ui/EdModHost.h"

#include "editor/doc/EdDocument.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/luaplus/include/lauxlib.h"

#include <fstream>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    using Mod = EdModHost::Mod;

    EdModHost* gHost = nullptr;

    Mod* ModOf(
      lua_State* L
    )
    {
      return static_cast<Mod*>(lua_touserdata(L, lua_upvalueindex(1)));
    }

    std::string ArgString(
      lua_State* L,
      const int index
    )
    {
      const char* const text = lua_isstring(L, index) != 0 ? lua_tostring(L, index) : nullptr;
      return text != nullptr ? text : std::string();
    }

    /** Editor.Command(id, title, fn [, keys]) */
    int LuaCommand(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string id = ArgString(L, 1);
      const std::string title = ArgString(L, 2);
      if (mod == nullptr || gHost == nullptr || id.empty() || lua_type(L, 3) != LUA_TFUNCTION) {
        lua_pushstring(L, "Editor.Command(id, title, fn [, keys]): an id, a title and a function");
        lua_error(L);
        return 0;
      }
      const std::string keys = ArgString(L, 4);
      lua_pushvalue(L, 3);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      gHost->AddCommand(*mod, id, title.empty() ? id : title, keys, ref);
      return 0;
    }

    /** Editor.Log(text) */
    int LuaLog(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      gpg::Logf("editor mod %s: %s", mod != nullptr ? mod->info.name.c_str() : "?", ArgString(L, 1).c_str());
      return 0;
    }

    /** Editor.Run(commandId) -> bool */
    int LuaRun(
      lua_State* L
    )
    {
      lua_pushboolean(L, gHost != nullptr && gHost->RunCommand(ArgString(L, 1)) ? 1 : 0);
      return 1;
    }

    /** Editor.Map() -> { path = ... } or nil */
    int LuaMap(
      lua_State* L
    )
    {
      if (gHost == nullptr || gHost->Document().Path().empty()) {
        lua_pushnil(L);
        return 1;
      }
      lua_newtable(L);
      lua_pushstring(L, "path");
      lua_pushstring(L, gHost->Document().Path().c_str());
      lua_settable(L, -3);
      return 1;
    }

    void SetFunction(
      lua_State* L,
      const char* name,
      lua_CFunction function,
      Mod* mod
    )
    {
      lua_pushstring(L, name);
      lua_pushlightuserdata(L, mod);
      lua_pushcclosure(L, function, 1);
      lua_settable(L, -3);
    }
  } // namespace

  EdModHost::EdModHost(
    EdDocument& document
  )
    : mDocument(document)
  {
    gHost = this;
  }

  EdModHost::~EdModHost()
  {
    if (gHost == this) {
      gHost = nullptr;
    }
  }

  void EdModHost::SetEnabledFile(
    const std::filesystem::path& file
  )
  {
    mEnabledFile = file;
    std::ifstream in(file, std::ios::binary);
    if (in) {
      std::ostringstream text;
      text << in.rdbuf();
      mEnabled = ParseEnabledMods(text.str());
    }
  }

  void EdModHost::SaveEnabled()
  {
    if (!mEnabledFile.empty()) {
      std::ofstream out(mEnabledFile, std::ios::binary | std::ios::trunc);
      out << SaveEnabledMods(mEnabled);
    }
  }

  void EdModHost::Scan(
    const std::filesystem::path& mods
  )
  {
    mFolder = mods;
    for (EditorModInfo& info : FindEditorMods(mods)) {
      const bool known = std::any_of(mMods.begin(), mMods.end(), [&](const std::unique_ptr<Mod>& m) {
        return m->info.uid == info.uid;
      });
      if (known) {
        continue;
      }
      auto mod = std::make_unique<Mod>();
      mod->info = std::move(info);
      Mod& added = *mod;
      mMods.push_back(std::move(mod));
      if (mEnabled.count(added.info.uid) != 0) {
        Start(added);
      }
    }
    gpg::Logf("editor: %zu editor mods in %s, %zu turned on", mMods.size(), mods.string().c_str(), mEnabled.size());
  }

  bool EdModHost::SetEnabled(
    const std::string& uid,
    const bool on
  )
  {
    for (const std::unique_ptr<Mod>& mod : mMods) {
      if (mod->info.uid != uid) {
        continue;
      }
      if (on) {
        mEnabled.insert(uid);
        Start(*mod);
      } else {
        mEnabled.erase(uid);
        Stop(*mod, "turned off");
      }
      SaveEnabled();
      return true;
    }
    return false;
  }

  void EdModHost::Start(
    Mod& mod
  )
  {
    if (mod.running) {
      return;
    }
    mod.commands.clear();
    if (const std::string why = EditorModIncompatibility(mod.info.api); !why.empty()) {
      mod.error = why;
      gpg::Warnf("editor mod %s not started: %s", mod.info.name.c_str(), why.c_str());
      return;
    }
    std::ifstream in(mod.info.folder / "editor" / "commands.lua", std::ios::binary);
    if (!in) {
      mod.error = "it has no editor/commands.lua";
      return;
    }
    std::ostringstream text;
    text << in.rdbuf();
    const std::string script = text.str();
    // Lua's base library without its file loading, and the Editor table.
    mod.lua = std::make_unique<LuaPlus::LuaState>(LuaPlus::LuaState::LIB_BASE);
    lua_State* const L = mod.lua->GetCState();
    for (const char* name : {"dofile", "loadfile", "require", "loadlib"}) {
      lua_pushstring(L, name);
      lua_pushnil(L);
      lua_settable(L, LUA_GLOBALSINDEX);
    }
    lua_pushstring(L, "Editor");
    lua_newtable(L);
    SetFunction(L, "Command", &LuaCommand, &mod);
    SetFunction(L, "Log", &LuaLog, &mod);
    SetFunction(L, "Run", &LuaRun, &mod);
    SetFunction(L, "Map", &LuaMap, &mod);
    lua_pushstring(L, "ApiVersion");
    lua_pushnumber(L, kEditorApiVersion);
    lua_settable(L, -3);
    lua_settable(L, LUA_GLOBALSINDEX);
    mod.running = true;
    mod.error.clear();
    const std::string chunk = "=" + mod.info.name + "/editor/commands.lua";
    if (luaL_loadbuffer(L, script.data(), script.size(), chunk.c_str()) != 0 || LuaCallProtected(L, 0, 0) != 0) {
      const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
      lua_settop(L, 0);
      Fail(mod, message);
      return;
    }
    gpg::Logf("editor mod %s started: %zu commands", mod.info.name.c_str(), mod.commands.size());
  }

  void EdModHost::Stop(
    Mod& mod,
    const std::string& why
  )
  {
    mod.running = false;
    mod.error = why;
    if (mod.lua) {
      lua_State* const L = mod.lua->GetCState();
      for (const int ref : mod.refs) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
      }
    }
    mod.refs.clear();
    mod.lua.reset();
  }

  void EdModHost::Fail(
    Mod& mod,
    const std::string& what
  )
  {
    gpg::Warnf(
      "editor mod %s failed: %s; its commands are off until the editor starts again",
      mod.info.name.c_str(),
      what.c_str()
    );
    Stop(mod, "failed: " + what);
  }

  void EdModHost::AddCommand(
    Mod& mod,
    const std::string& id,
    const std::string& title,
    const std::string& keys,
    const int ref
  )
  {
    if (mCommands == nullptr) {
      return;
    }
    const std::string full = EditorModCommandId(mod.info.name, id);
    Mod* const owner = &mod;
    const std::size_t index = mod.refs.size();
    mod.refs.push_back(ref);
    mod.commands.push_back(full);
    EdCommand command;
    command.id = full;
    command.title = title;
    command.category = "Mod: " + mod.info.name;
    command.keys = keys;
    command.description = "From the editor mod " + mod.info.name;
    command.run = [this, owner, index, full] {
      if (!owner->running || owner->lua == nullptr || index >= owner->refs.size()) {
        return;
      }
      lua_State* const L = owner->lua->GetCState();
      lua_rawgeti(L, LUA_REGISTRYINDEX, owner->refs[index]);
      ++mRunDepth;
      const int result = LuaCallProtected(L, 0, 0);
      --mRunDepth;
      if (result != 0) {
        const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
        lua_settop(L, 0);
        Fail(*owner, full + ": " + message);
      }
    };
    command.why = [owner] {
      return owner->running ? std::string() : "the editor mod " + owner->info.name + " is " + owner->error;
    };
    mCommands->Add(std::move(command));
  }

  bool EdModHost::RunCommand(
    const std::string& id
  )
  {
    // A mod's command may run the editor's (and other mods'), a few deep at most.
    if (mCommands == nullptr || mRunDepth > 4) {
      return false;
    }
    return mCommands->Run(id);
  }

  void EdModHost::Draw(
    bool& open
  )
  {
    if (!ImGui::Begin(Panel("Editor mods###EditorMods"), &open)) {
      ImGui::End();
      return;
    }
    ImGui::TextWrapped(
      "Mods that add commands to the editor (mod_info.lua: editor_mod = true; editor/commands.lua). They are off until "
      "turned on here, run apart from the game, and a mod whose command fails is turned off until the editor starts "
      "again."
    );
    ImGui::TextDisabled("In %s", mFolder.string().c_str());
    if (mMods.empty()) {
      ImGui::TextDisabled("No editor mods there.");
    }
    for (const std::unique_ptr<Mod>& mod : mMods) {
      ImGui::PushID(mod->info.uid.c_str());
      bool on = mEnabled.count(mod->info.uid) != 0;
      if (ImGui::Checkbox(mod->info.name.c_str(), &on)) {
        (void)SetEnabled(mod->info.uid, on);
      }
      ImGui::SameLine();
      if (mod->running) {
        ImGui::TextDisabled("%zu commands", mod->commands.size());
      } else if (!mod->error.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "%s", mod->error.c_str());
      }
      if (!mod->info.description.empty()) {
        ImGui::TextDisabled("  %s", mod->info.description.c_str());
      }
      ImGui::PopID();
    }
    ImGui::End();
  }
} // namespace faf::editor
