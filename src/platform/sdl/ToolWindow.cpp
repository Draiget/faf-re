// Engine addition (issue #412): see ToolWindow.h.

#include "platform/sdl/ToolWindow.h"

#include <algorithm>
#include <cstdio>
#include <vector>

#include <SDL3/SDL.h>

#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlrenderer3.h"

#include "gpg/core/utils/Logging.h"
#include "platform/Window.h"
#include "platform/sdl/WindowSdlPlatform.h"

namespace platform::tools
{
  namespace
  {
    std::vector<ToolWindow*> gToolWindows;
    bool gHookInstalled = false;

    // A font with more than ImGui's built-in Latin glyphs, for log lines and Lua sources in other
    // scripts: the first of the system's that exists. ImGui 1.92 makes glyphs as they are drawn.
    void AddSystemFont(
      ImGuiIO& io
    )
    {
      static const char* const kCandidates[] = {
#if FAFRE_PLATFORM_WINDOWS
        "C:\\Windows\\Fonts\\consola.ttf",
        "C:\\Windows\\Fonts\\cour.ttf",
#else
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
#endif
      };
      for (const char* const path : kCandidates) {
        if (FILE* const file = std::fopen(path, "rb"); file != nullptr) {
          std::fclose(file);
          if (io.Fonts->AddFontFromFileTTF(path, 15.0f) != nullptr) {
            return;
          }
        }
      }
      (void)io.Fonts->AddFontDefault();
    }
  } // namespace

  // The window system's hook (WindowSdlPlatform.h): an event for a tool window goes to its ImGui.
  bool HandleToolEvent(
    const void* const sdlEvent
  )
  {
    const auto& event = *static_cast<const SDL_Event*>(sdlEvent);
    SDL_Window* const window = SDL_GetWindowFromEvent(&event);
    if (window == nullptr) {
      return false;
    }
    for (ToolWindow* const tool : gToolWindows) {
      if (tool->mWindow != window) {
        continue;
      }
      if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED) {
        tool->OnCloseRequested();
        return true;
      }
      ImGuiContext* const previous = ImGui::GetCurrentContext();
      ImGui::SetCurrentContext(tool->mContext);
      (void)ImGui_ImplSDL3_ProcessEvent(&event);
      ImGui::SetCurrentContext(previous);
      return true;
    }
    return false;
  }

  ToolWindow::ToolWindow(
    const char* const utf8Title,
    const int width,
    const int height
  )
  {
    if (!platform::window::IsInitialized()) {
      return;
    }
    mWindow =
      SDL_CreateWindow(utf8Title != nullptr ? utf8Title : "", width, height, SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIDDEN);
    if (mWindow == nullptr) {
      gpg::Warnf("Tool window \"%s\": %s", utf8Title != nullptr ? utf8Title : "", SDL_GetError());
      return;
    }
    mRenderer = SDL_CreateRenderer(mWindow, nullptr);
    if (mRenderer == nullptr) {
      gpg::Warnf("Tool window \"%s\": no renderer: %s", utf8Title != nullptr ? utf8Title : "", SDL_GetError());
      SDL_DestroyWindow(mWindow);
      mWindow = nullptr;
      return;
    }
    // The game sets the pace; a tool window never waits for the display.
    (void)SDL_SetRenderVSync(mRenderer, 0);
    (void)SDL_StartTextInput(mWindow);

    ImGuiContext* const previous = ImGui::GetCurrentContext();
    mContext = ImGui::CreateContext();
    ImGui::SetCurrentContext(mContext);
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    AddSystemFont(io);
    (void)ImGui_ImplSDL3_InitForSDLRenderer(mWindow, mRenderer);
    (void)ImGui_ImplSDLRenderer3_Init(mRenderer);
    ImGui::SetCurrentContext(previous);

    if (!gHookInstalled) {
      platform::window::sdl::SetToolEventHook(&HandleToolEvent);
      gHookInstalled = true;
    }
    gToolWindows.push_back(this);
  }

  ToolWindow::~ToolWindow()
  {
    gToolWindows.erase(std::remove(gToolWindows.begin(), gToolWindows.end(), this), gToolWindows.end());
    if (mContext != nullptr) {
      ImGuiContext* const previous = ImGui::GetCurrentContext();
      ImGui::SetCurrentContext(mContext);
      ImGui_ImplSDLRenderer3_Shutdown();
      ImGui_ImplSDL3_Shutdown();
      ImGui::DestroyContext(mContext);
      ImGui::SetCurrentContext(previous == mContext ? nullptr : previous);
      mContext = nullptr;
    }
    if (mRenderer != nullptr) {
      SDL_DestroyRenderer(mRenderer);
      mRenderer = nullptr;
    }
    if (mWindow != nullptr) {
      SDL_DestroyWindow(mWindow);
      mWindow = nullptr;
    }
  }

  void ToolWindow::Show(
    const bool show
  )
  {
    mShown = show;
    if (mWindow == nullptr) {
      return;
    }
    if (show) {
      (void)SDL_ShowWindow(mWindow);
      (void)SDL_RaiseWindow(mWindow);
      mLastFrameTicks = 0;
      Render();
    } else {
      (void)SDL_HideWindow(mWindow);
    }
  }

  void ToolWindow::Raise()
  {
    if (mWindow != nullptr) {
      (void)SDL_RaiseWindow(mWindow);
    }
  }

  void ToolWindow::SetTitle(
    const char* const utf8Title
  )
  {
    if (mWindow != nullptr) {
      (void)SDL_SetWindowTitle(mWindow, utf8Title != nullptr ? utf8Title : "");
    }
  }

  void ToolWindow::Render()
  {
    if (!mShown || mRenderer == nullptr) {
      return;
    }
    if ((SDL_GetWindowFlags(mWindow) & SDL_WINDOW_MINIMIZED) != 0) {
      return;
    }
    const Uint64 now = SDL_GetTicks();
    if (mLastFrameTicks != 0 && now - mLastFrameTicks < 16u) {
      return;
    }
    mLastFrameTicks = now;

    ImGuiContext* const previous = ImGui::GetCurrentContext();
    ImGui::SetCurrentContext(mContext);
    ImGui_ImplSDLRenderer3_NewFrame();
    ImGui_ImplSDL3_NewFrame();
    ImGui::NewFrame();

    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    if (ImGui::Begin("##tool", nullptr, kFlags)) {
      Draw();
    }
    ImGui::End();
    ImGui::PopStyleVar();

    ImGui::Render();
    const ImGuiIO& io = ImGui::GetIO();
    (void)SDL_SetRenderScale(mRenderer, io.DisplayFramebufferScale.x, io.DisplayFramebufferScale.y);
    (void)SDL_SetRenderDrawColor(mRenderer, 30, 30, 30, 255);
    (void)SDL_RenderClear(mRenderer);
    ImGui_ImplSDLRenderer3_RenderDrawData(ImGui::GetDrawData(), mRenderer);
    (void)SDL_RenderPresent(mRenderer);
    ImGui::SetCurrentContext(previous);
  }

  void ToolWindow::SetBounds(
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (mWindow == nullptr) {
      return;
    }
    if (width > 0 || height > 0) {
      int currentWidth = 0;
      int currentHeight = 0;
      (void)SDL_GetWindowSize(mWindow, &currentWidth, &currentHeight);
      (void)SDL_SetWindowSize(mWindow, width > 0 ? width : currentWidth, height > 0 ? height : currentHeight);
    }
    if (x != -1 || y != -1) {
      int currentX = 0;
      int currentY = 0;
      (void)SDL_GetWindowPosition(mWindow, &currentX, &currentY);
      (void)SDL_SetWindowPosition(mWindow, x != -1 ? x : currentX, y != -1 ? y : currentY);
    }
  }

  bool ToolWindow::GetBounds(
    int& x,
    int& y,
    int& width,
    int& height
  ) const
  {
    if (mWindow == nullptr) {
      return false;
    }
    (void)SDL_GetWindowPosition(mWindow, &x, &y);
    (void)SDL_GetWindowSize(mWindow, &width, &height);
    return true;
  }

  void RenderAll()
  {
    // A window's Tick or Draw may open or close tool windows.
    const std::vector<ToolWindow*> windows = gToolWindows;
    const auto stillOpen = [](ToolWindow* const tool) {
      return std::find(gToolWindows.begin(), gToolWindows.end(), tool) != gToolWindows.end();
    };
    for (ToolWindow* const tool : windows) {
      if (stillOpen(tool)) {
        tool->Tick();
      }
    }
    for (ToolWindow* const tool : windows) {
      if (stillOpen(tool)) {
        tool->Render();
      }
    }
  }
} // namespace platform::tools
