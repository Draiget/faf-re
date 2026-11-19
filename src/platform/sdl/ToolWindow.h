#pragma once

// Engine addition (issue #412): the developer windows (log window, Lua debugger, emitter editor,
// reference editor) on Dear ImGui, each in a window of its own made by SDL3 and drawn with SDL's
// software renderer, apart from the game's device (#418). They replace the 2.4.2 window library
// dialogs and frames.
//
// All calls are made on the main thread. The main loop calls RenderAll once a frame; their input
// reaches them through the window system (src/platform/sdl/WindowSdl.cpp), not the game.

#include <functional>
#include <string>

struct ImGuiContext;
struct SDL_Renderer;
struct SDL_Window;

namespace platform::tools
{
  class ToolWindow
  {
  public:
    // The window is made hidden; nothing is made without a window system.
    ToolWindow(const char* utf8Title, int width, int height);
    virtual ~ToolWindow();

    ToolWindow(const ToolWindow&) = delete;
    ToolWindow& operator=(const ToolWindow&) = delete;

    void Show(bool show);
    [[nodiscard]] bool IsShown() const
    {
      return mShown;
    }
    void Raise();
    void SetTitle(const char* utf8Title);
    // False when the window couldn't be made (no window system, no renderer).
    [[nodiscard]] bool IsValid() const
    {
      return mRenderer != nullptr;
    }

    // Draws a frame when one is due (RenderAll does it for every shown window): soon after input
    // or RequestRedraw, else only at the idle refresh. SDL's software renderer draws these
    // windows, so a frame costs CPU in proportion to the window's size.
    void Render();

    // Content changed without input reaching the window (new log lines, a script pause): draw
    // it at the next content frame. Call from Tick or Draw.
    void RequestRedraw();

    // The frame's screen position and outer size, borders and caption included, as the retail
    // window library placed and measured its dialogs and frames (the Windows.Log.* and
    // Windows.Debug.* preferences hold them); -1 keeps a value. False without a window.
    void SetBounds(int x, int y, int width, int height);
    bool GetBounds(int& x, int& y, int& width, int& height) const;

  protected:
    // Every frame, shown or not, before drawing (RenderAll).
    virtual void Tick() {}

    // A shown window with no input and no RequestRedraw is drawn again after this many
    // milliseconds, for content that changes without telling the window; 0 never. A window whose
    // every change calls RequestRedraw sets 0.
    void SetIdleRefreshMs(
      const unsigned int milliseconds
    )
    {
      mIdleRefreshMs = milliseconds;
    }

    // The window's content, inside an ImGui window filling the client area. ImGui's context is
    // this window's while it runs.
    virtual void Draw() = 0;
    // The close button: hides the window unless overridden.
    virtual void OnCloseRequested()
    {
      Show(false);
    }

  private:
    friend bool HandleToolEvent(const void* sdlEvent);
    friend void RenderAll();

    SDL_Window* mWindow = nullptr;
    SDL_Renderer* mRenderer = nullptr;
    ImGuiContext* mContext = nullptr;
    bool mShown = false;
    unsigned long long mLastFrameTicks = 0;
    // Until then the window draws at the input rate: ImGui's hover, press and tooltip states
    // settle over the frames after an event.
    unsigned long long mInputUntilTicks = 0;
    // Frames still owed for a content change: ImGui applies a scroll or a new layout a frame late.
    int mPendingFrames = 0;
    unsigned int mIdleRefreshMs = 250;
  };

  // Draws every shown tool window that has a frame due, at most about 60 times a second each
  // while it gets input, 10 for content changes alone. The main loop calls it
  // once a frame, and so does any loop that holds the game while it pumps events (the Lua
  // debugger at a breakpoint, moho::sAppPumpStep).
  void RenderAll();
} // namespace platform::tools
