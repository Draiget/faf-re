#pragma once

// Engine addition (issue #412): the developer windows (log window, Lua debugger, emitter editor,
// reference editor) on Dear ImGui, each in a window of its own made by SDL3 and drawn with SDL's
// renderer (Direct3D 11 or 12 on Windows, Vulkan or OpenGL elsewhere), apart from the game's
// device. They replace the 2.4.2 window library dialogs and frames.
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

    // Draws one frame now (RenderAll does it for every shown window).
    void Render();

    // The frame's screen position and outer size, borders and caption included, as the retail
    // window library placed and measured its dialogs and frames (the Windows.Log.* and
    // Windows.Debug.* preferences hold them); -1 keeps a value. False without a window.
    void SetBounds(int x, int y, int width, int height);
    bool GetBounds(int& x, int& y, int& width, int& height) const;

  protected:
    // Every frame, shown or not, before drawing (RenderAll).
    virtual void Tick() {}

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
  };

  // Draws every shown tool window, at most about 60 times a second each. The main loop calls it
  // once a frame, and so does any loop that holds the game while it pumps events (the Lua
  // debugger at a breakpoint, moho::sAppPumpStep).
  void RenderAll();
} // namespace platform::tools
