#pragma once

#include "editor/doc/EdEditorMods.h"

#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace LuaPlus
{
  class LuaState;
}

namespace faf::editor
{
  class EdCommands;
  class EdDocument;

  /**
   * Runs the turned-on editor mods: each one's `editor/commands.lua` in a Lua state of its own (Lua's base library
   * without its file loading, and the `Editor` table), whose `Editor.Command(id, title, fn [, keys])` adds a command to
   * the editor (palette, keys; id `mod.<mod>.<id>`). The `Editor` table also has `Log(text)`, `Run(commandId)` (one of
   * the editor's commands; false when it can't run) and `Map()` (the open map: `{ path = ... }`, or nil), and
   * `ApiVersion`. A command that raises an error is reported with its mod's name and turns that mod's commands off
   * until the editor starts again.
   */
  class EdModHost
  {
  public:
    EdModHost(EdDocument& document);
    ~EdModHost();

    void Attach(
      EdCommands* commands
    ) noexcept
    {
      mCommands = commands;
    }
    /** Where the turned-on mods are kept (empty: not kept, as in test runs); read when set. */
    void SetEnabledFile(const std::filesystem::path& file);
    /** Looks for editor mods in a mods folder and runs the turned-on ones. */
    void Scan(const std::filesystem::path& mods);
    /** Turns a mod on (runs it) or off (its commands say so); kept in the enabled file. */
    bool SetEnabled(const std::string& uid, bool on);
    void Draw(bool& open);

    struct Mod
    {
      EditorModInfo info;
      std::unique_ptr<LuaPlus::LuaState> lua;
      std::vector<std::string> commands; // the ids it added
      std::vector<int> refs;             // their functions in its registry
      std::string error;                 // why it isn't running ("" while it is)
      bool running = false;
    };
    [[nodiscard]] const std::vector<std::unique_ptr<Mod>>& Mods() const noexcept
    {
      return mMods;
    }

    // The Lua side (static functions find their mod through an upvalue).
    void AddCommand(Mod& mod, const std::string& id, const std::string& title, const std::string& keys, int ref);
    bool RunCommand(const std::string& id);
    void Fail(Mod& mod, const std::string& what);
    [[nodiscard]] EdDocument& Document() noexcept
    {
      return mDocument;
    }

  private:
    void Start(Mod& mod);
    void Stop(Mod& mod, const std::string& why);
    void SaveEnabled();

    EdDocument& mDocument;
    EdCommands* mCommands = nullptr;
    std::vector<std::unique_ptr<Mod>> mMods;
    std::set<std::string> mEnabled;
    std::filesystem::path mEnabledFile;
    std::filesystem::path mFolder;
    int mRunDepth = 0;
  };
} // namespace faf::editor
