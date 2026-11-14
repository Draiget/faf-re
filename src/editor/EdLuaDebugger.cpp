#include "editor/EdLuaDebugger.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/luaplus/include/lauxlib.h"
#include "moho/lua/CScrLuaInitForm.h"

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    /** A Lua value on the stack's top as the Debugger shows it: numbers, strings, booleans; a table's entry count. */
    [[nodiscard]] std::string Describe(
      lua_State* const state,
      const int index
    )
    {
      char text[160];
      switch (lua_type(state, index)) {
      case LUA_TNIL:
        return "nil";
      case LUA_TBOOLEAN:
        return lua_toboolean(state, index) != 0 ? "true" : "false";
      case LUA_TNUMBER:
        (void)std::snprintf(text, sizeof(text), "%.6g", static_cast<double>(lua_tonumber(state, index)));
        return text;
      case LUA_TSTRING: {
        std::string value = lua_tostring(state, index);
        if (value.size() > 100) {
          value = value.substr(0, 100) + "...";
        }
        return "\"" + value + "\"";
      }
      case LUA_TTABLE: {
        // Raw entries only: a table's __index may run Lua.
        int count = 0;
        const int at = index < 0 ? lua_gettop(state) + index + 1 : index;
        lua_pushnil(state);
        while (count < 1000 && lua_next(state, at) != 0) {
          lua_pop(state, 1);
          ++count;
        }
        (void)std::snprintf(text, sizeof(text), "table (%d%s entries)", count, count >= 1000 ? "+" : "");
        return text;
      }
      default:
        return lua_typename(state, lua_type(state, index));
      }
    }

    void Hook(
      lua_State* const state,
      lua_Debug* const ar
    )
    {
      if (ar->event == LUA_HOOKLINE) {
        EdLuaDebugger::Get().OnLine(state, ar);
      }
    }

    /** Runs on every new sim Lua state, on the sim thread, before the sim's scripts: the hook when armed. */
    class CDebuggerInitForm final : public moho::CScrLuaInitForm
    {
    public:
      explicit CDebuggerInitForm(
        moho::CScrLuaInitFormSet& set
      )
        : CScrLuaInitForm(set, "__faf_editor_debugger", "editor", "the map editor's script debugger")
      {}

      void Run(
        LuaPlus::LuaState* const state
      ) override
      {
        EdLuaDebugger::Get().OnNewState(state->m_state);
      }
    };
  } // namespace

  EdLuaDebugger& EdLuaDebugger::Get()
  {
    static EdLuaDebugger debugger;
    return debugger;
  }

  void EdLuaDebugger::Register()
  {
    if (mRegistered) {
      return;
    }
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      static CDebuggerInitForm form(*set); // links itself into the set for the process's life
      mRegistered = true;
    } else {
      gpg::Warnf("editor: debugger: the sim's Lua start-up set isn't there");
    }
  }

  void EdLuaDebugger::SetArmed(
    const bool armed
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    mArmed = armed;
  }

  bool EdLuaDebugger::Armed() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mArmed;
  }

  bool EdLuaDebugger::Hooked() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mHooked;
  }

  void EdLuaDebugger::ToggleBreakpoint(
    const std::string& file,
    const int line
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    const std::string name = Lower(file);
    const auto found = std::find_if(mBreakpoints.begin(), mBreakpoints.end(), [&](const Breakpoint& b) {
      return b.file == name && b.line == line;
    });
    if (found != mBreakpoints.end()) {
      mBreakpoints.erase(found);
    } else {
      mBreakpoints.push_back({name, line});
    }
  }

  bool EdLuaDebugger::HasBreakpoint(
    std::string_view file,
    const int line
  ) const
  {
    std::lock_guard<std::mutex> lock(mLock);
    const std::string name = Lower(std::string(file));
    return std::any_of(mBreakpoints.begin(), mBreakpoints.end(), [&](const Breakpoint& b) {
      return b.file == name && b.line == line;
    });
  }

  std::vector<EdLuaDebugger::Breakpoint> EdLuaDebugger::Breakpoints() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mBreakpoints;
  }

  void EdLuaDebugger::SetWatches(
    std::vector<std::string> watches
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    mWatchList = std::move(watches);
  }

  EdLuaDebugger::Pause EdLuaDebugger::Snapshot() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mPause;
  }

  void EdLuaDebugger::Resume(
    const EdStepMode mode
  )
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (!mPause.paused) {
        return;
      }
      mMode = mode;
      mResume = true;
    }
    mWake.notify_all();
  }

  void EdLuaDebugger::Release()
  {
    {
      std::lock_guard<std::mutex> lock(mLock);
      mMode = EdStepMode::Run;
      mResume = true;
      mReleased = true;
    }
    mWake.notify_all();
  }

  void EdLuaDebugger::OnNewState(
    lua_State* const state
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    mMode = EdStepMode::Run;
    mResume = false;
    mReleased = false;
    mPause = Pause{};
    mHooked = mArmed;
    if (mArmed) {
      (void)lua_sethook(state, &Hook, LUA_MASKLINE, 0);
      gpg::Logf("editor: debugger: on for this play (%zu breakpoints)", mBreakpoints.size());
    }
  }

  int EdLuaDebugger::Depth(
    lua_State* const state
  )
  {
    lua_Debug level{};
    int depth = 0;
    while (lua_getstack(state, depth, &level) != 0) {
      ++depth;
    }
    return depth;
  }

  void EdLuaDebugger::OnLine(
    lua_State* const state,
    lua_Debug* const ar
  )
  {
    // Quick out: not armed, or running with no breakpoint on this line number.
    EdStepMode mode;
    int stepDepth;
    bool lineHasBreakpoint = false;
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (!mArmed || mReleased) {
        return;
      }
      mode = mMode;
      stepDepth = mStepDepth;
      for (const Breakpoint& b : mBreakpoints) {
        lineHasBreakpoint = lineHasBreakpoint || b.line == ar->currentline;
      }
    }
    if (mode == EdStepMode::Run && !lineHasBreakpoint) {
      return;
    }
    if (lua_getinfo(state, "Sl", ar) == 0 || ar->source == nullptr) {
      return;
    }
    bool atBreakpoint = false;
    std::string file;
    {
      std::lock_guard<std::mutex> lock(mLock);
      for (const Breakpoint& b : mBreakpoints) {
        if (b.line == ar->currentline && SourceIsFile(ar->source, b.file)) {
          atBreakpoint = true;
          file = b.file;
        }
      }
    }
    // Steps stop only in the map's own files (a source under /maps/), not inside the game's libraries.
    const std::string source = Lower(ar->source);
    const bool mapFile = source.find("/maps/") != std::string::npos;
    if (!atBreakpoint && !mapFile) {
      return;
    }
    const int depth = Depth(state);
    if (!ShouldPause(mode, depth, stepDepth, atBreakpoint)) {
      return;
    }

    // What the pause shows: the place, the locals, the watches, the stack.
    Pause pause;
    pause.paused = true;
    pause.file = file.empty() ? source.substr(source.find_last_of("/\\") + 1) : file;
    pause.line = ar->currentline;
    for (int i = 1; i < 200; ++i) {
      const char* const name = lua_getlocal(state, ar, i);
      if (name == nullptr) {
        break;
      }
      if (name[0] != '(') { // Lua's temporaries ("(for index)") aren't the script's
        pause.locals.emplace_back(name, Describe(state, -1));
      }
      lua_pop(state, 1);
    }
    std::vector<std::string> watches;
    {
      std::lock_guard<std::mutex> lock(mLock);
      watches = mWatchList;
    }
    for (const std::string& expression : watches) {
      const std::string chunk = "return " + expression;
      std::string value;
      if (luaL_loadbuffer(state, chunk.c_str(), chunk.size(), "=watch") != 0) {
        value = std::string("can't read: ") + (lua_tostring(state, -1) != nullptr ? lua_tostring(state, -1) : "?");
        lua_pop(state, 1);
      } else if (LuaCallProtected(state, 0, 1) != 0) {
        value = std::string("error: ") + (lua_tostring(state, -1) != nullptr ? lua_tostring(state, -1) : "?");
        lua_pop(state, 1);
      } else {
        value = Describe(state, -1);
        lua_pop(state, 1);
      }
      pause.watches.emplace_back(expression, value);
    }
    lua_Debug level{};
    for (int i = 0; i < 24 && lua_getstack(state, i, &level) != 0; ++i) {
      if (lua_getinfo(state, "Sln", &level) != 0) {
        char line[260];
        (void)std::snprintf(
          line,
          sizeof(line),
          "%s  %s:%d",
          level.name != nullptr ? level.name : "(main)",
          level.short_src,
          level.currentline
        );
        pause.stack.emplace_back(line);
      }
    }
    gpg::Logf(
      "editor: debugger: paused at %s line %d (%zu locals)", pause.file.c_str(), pause.line, pause.locals.size()
    );

    // The sim thread waits here until the editor resumes it (or the play stops).
    std::unique_lock<std::mutex> lock(mLock);
    mPause = std::move(pause);
    mResume = false;
    mWake.wait(lock, [this] {
      return mResume;
    });
    mResume = false;
    mPause = Pause{};
    mStepDepth = depth;
  }
} // namespace faf::editor
