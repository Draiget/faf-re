#pragma once

#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct lua_State;
struct lua_Debug;

namespace faf::editor
{
  /** How the debugger goes on from a pause: to the next breakpoint, the next line, the next line here or above, out. */
  enum class EdStepMode
  {
    Run,
    Into,
    Over,
    Out,
  };

  /**
   * Whether a Lua chunk's source (`@/maps/x/x_script.lua`, as Lua names it) is the file `file` (`x_script.lua`):
   * case aside, either slash.
   */
  [[nodiscard]] bool SourceIsFile(std::string_view source, std::string_view file);

  /**
   * Whether to pause at a line: at a breakpoint while running; any line stepping into; a line at the same depth or
   * above stepping over (`depth` the stack's depth now, `stepDepth` where the step began); above, stepping out.
   */
  [[nodiscard]] bool ShouldPause(EdStepMode mode, int depth, int stepDepth, bool atBreakpoint);

  /**
   * The Script Editor's debugger for test plays (design §8 Script): while armed, a line hook on the sim's Lua state
   * (installed when the sim makes its state, on the sim thread) stops the sim at breakpoints in the map's scripts and
   * when stepping. Paused, the sim thread waits; the editor keeps drawing and shows where, the locals, the watched
   * expressions and the stack, and resumes it. Stopping the play releases it first (EdPlay::Stop).
   */
  class EdLuaDebugger
  {
  public:
    struct Breakpoint
    {
      std::string file; // "x_script.lua", lower case
      int line = 0;
    };
    struct Pause
    {
      bool paused = false;
      std::string file; // the file's name as the chunk names it
      int line = 0;
      std::vector<std::pair<std::string, std::string>> locals;
      std::vector<std::pair<std::string, std::string>> watches;
      std::vector<std::string> stack;
    };

    static EdLuaDebugger& Get();

    /** Links the hook's installer into the sim's Lua start-up (once, at the editor's start). */
    void Register();

    // The editor's thread.
    void SetArmed(bool armed);
    [[nodiscard]] bool Armed() const;
    /** Whether the play running now got the hook (it began armed). */
    [[nodiscard]] bool Hooked() const;
    void ToggleBreakpoint(const std::string& file, int line);
    [[nodiscard]] bool HasBreakpoint(std::string_view file, int line) const;
    [[nodiscard]] std::vector<Breakpoint> Breakpoints() const;
    void SetWatches(std::vector<std::string> watches);
    [[nodiscard]] Pause Snapshot() const;
    /** Resumes a pause in that mode. */
    void Resume(EdStepMode mode);
    /** A play is stopping: any pause resumed, stepping ended and no more pauses this play, so the sim thread can
     * finish. */
    void Release();

    // The sim's thread.
    void OnNewState(lua_State* state);
    void OnLine(lua_State* state, lua_Debug* ar);

  private:
    EdLuaDebugger() = default;
    [[nodiscard]] static int Depth(lua_State* state);

    mutable std::mutex mLock;
    std::condition_variable mWake;
    bool mArmed = false;
    std::vector<Breakpoint> mBreakpoints;
    std::vector<std::string> mWatchList;
    Pause mPause;
    bool mResume = false;
    EdStepMode mMode = EdStepMode::Run;
    int mStepDepth = 0;
    bool mRegistered = false;
    /** Released (a stop, the editor closing): no more pauses until the next play makes its Lua state. */
    bool mReleased = false;
    bool mHooked = false;
  };
} // namespace faf::editor
