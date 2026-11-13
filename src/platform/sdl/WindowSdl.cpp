// Engine addition (issues #256, #407): platform::window (src/platform/Window.h) on SDL3, for every
// platform. Windows are SDL windows; their events become platform::window events. What one system
// alone needs is behind platform/sdl/WindowSdlPlatform.h.

#include "platform/Window.h"

#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include <SDL3/SDL.h>

#include <Windows.h>

#include "gpg/core/utils/Logging.h"
#include "platform/sdl/WindowSdlPlatform.h"

namespace
{
  bool gInitialized = false;
  // The windows made here, the first being the main one.
  std::vector<SDL_Window*> gWindows;
  // Events PollEvent returns before SDL's: typed text, one character each, and what the system
  // file queued (WindowSdlPlatform.h).
  std::deque<platform::window::Event> gQueued;
  platform::window::EventFilter gEventFilter = nullptr;
  platform::window::sdl::ToolEventHook gToolEventHook = nullptr;
  platform::window::CursorRequestHandler gCursorRequestHandler = nullptr;

  [[nodiscard]] SDL_Window* AsWindow(
    void* const handle
  )
  {
    return static_cast<SDL_Window*>(handle);
  }

  // --- Keys: SDL's key codes (the layout's) to Windows virtual-key codes ----------------------

  [[nodiscard]] int VirtualKeyOf(
    const SDL_Keycode key
  )
  {
    if (key >= SDLK_A && key <= SDLK_Z) {
      return 'A' + static_cast<int>(key - SDLK_A);
    }
    if (key >= SDLK_0 && key <= SDLK_9) {
      return '0' + static_cast<int>(key - SDLK_0);
    }
    if (key >= SDLK_F1 && key <= SDLK_F12) {
      return VK_F1 + static_cast<int>(key - SDLK_F1);
    }
    if (key >= SDLK_F13 && key <= SDLK_F24) {
      return VK_F13 + static_cast<int>(key - SDLK_F13);
    }
    switch (key) {
    case SDLK_BACKSPACE:
      return VK_BACK;
    case SDLK_TAB:
      return VK_TAB;
    case SDLK_CLEAR:
      return VK_CLEAR;
    case SDLK_RETURN:
      return VK_RETURN;
    case SDLK_PAUSE:
      return VK_PAUSE;
    case SDLK_CAPSLOCK:
      return VK_CAPITAL;
    case SDLK_ESCAPE:
      return VK_ESCAPE;
    case SDLK_SPACE:
      return VK_SPACE;
    case SDLK_PAGEUP:
      return VK_PRIOR;
    case SDLK_PAGEDOWN:
      return VK_NEXT;
    case SDLK_END:
      return VK_END;
    case SDLK_HOME:
      return VK_HOME;
    case SDLK_LEFT:
      return VK_LEFT;
    case SDLK_UP:
      return VK_UP;
    case SDLK_RIGHT:
      return VK_RIGHT;
    case SDLK_DOWN:
      return VK_DOWN;
    case SDLK_SELECT:
      return VK_SELECT;
    case SDLK_EXECUTE:
      return VK_EXECUTE;
    case SDLK_PRINTSCREEN:
      return VK_SNAPSHOT;
    case SDLK_INSERT:
      return VK_INSERT;
    case SDLK_DELETE:
      return VK_DELETE;
    case SDLK_HELP:
      return VK_HELP;
    case SDLK_LGUI:
      return VK_LWIN;
    case SDLK_RGUI:
      return VK_RWIN;
    case SDLK_APPLICATION:
      return VK_APPS;
    case SDLK_KP_0:
      return VK_NUMPAD0;
    case SDLK_KP_1:
      return VK_NUMPAD1;
    case SDLK_KP_2:
      return VK_NUMPAD2;
    case SDLK_KP_3:
      return VK_NUMPAD3;
    case SDLK_KP_4:
      return VK_NUMPAD4;
    case SDLK_KP_5:
      return VK_NUMPAD5;
    case SDLK_KP_6:
      return VK_NUMPAD6;
    case SDLK_KP_7:
      return VK_NUMPAD7;
    case SDLK_KP_8:
      return VK_NUMPAD8;
    case SDLK_KP_9:
      return VK_NUMPAD9;
    case SDLK_KP_MULTIPLY:
      return VK_MULTIPLY;
    case SDLK_KP_PLUS:
      return VK_ADD;
    case SDLK_KP_MINUS:
      return VK_SUBTRACT;
    case SDLK_KP_PERIOD:
      return VK_DECIMAL;
    case SDLK_KP_DIVIDE:
      return VK_DIVIDE;
    case SDLK_KP_ENTER:
      return VK_RETURN;
    case SDLK_NUMLOCKCLEAR:
      return VK_NUMLOCK;
    case SDLK_SCROLLLOCK:
      return VK_SCROLL;
    case SDLK_LSHIFT:
    case SDLK_RSHIFT:
      return VK_SHIFT;
    case SDLK_LCTRL:
    case SDLK_RCTRL:
      return VK_CONTROL;
    case SDLK_LALT:
    case SDLK_RALT:
      return VK_MENU;
    case SDLK_SEMICOLON:
      return VK_OEM_1;
    case SDLK_EQUALS:
    case SDLK_PLUS:
      return VK_OEM_PLUS;
    case SDLK_COMMA:
      return VK_OEM_COMMA;
    case SDLK_MINUS:
      return VK_OEM_MINUS;
    case SDLK_PERIOD:
      return VK_OEM_PERIOD;
    case SDLK_SLASH:
      return VK_OEM_2;
    case SDLK_GRAVE:
      return VK_OEM_3;
    case SDLK_LEFTBRACKET:
      return VK_OEM_4;
    case SDLK_BACKSLASH:
      return VK_OEM_5;
    case SDLK_RIGHTBRACKET:
      return VK_OEM_6;
    case SDLK_APOSTROPHE:
      return VK_OEM_7;
    default:
      return 0;
    }
  }

  // The left/right virtual key GetKeyState also answers for a modifier (Windows keeps both).
  [[nodiscard]] int SidedVirtualKeyOf(
    const SDL_Keycode key
  )
  {
    switch (key) {
    case SDLK_LSHIFT:
      return VK_LSHIFT;
    case SDLK_RSHIFT:
      return VK_RSHIFT;
    case SDLK_LCTRL:
      return VK_LCONTROL;
    case SDLK_RCTRL:
      return VK_RCONTROL;
    case SDLK_LALT:
      return VK_LMENU;
    case SDLK_RALT:
      return VK_RMENU;
    default:
      return 0;
    }
  }

  [[nodiscard]] std::uint32_t ModifiersOf(
    const SDL_Keymod mod
  )
  {
    std::uint32_t modifiers = 0;
    if ((mod & SDL_KMOD_SHIFT) != 0) {
      modifiers |= platform::window::kModifierShift;
    }
    if ((mod & SDL_KMOD_CTRL) != 0) {
      modifiers |= platform::window::kModifierControl;
    }
    if ((mod & SDL_KMOD_ALT) != 0) {
      modifiers |= platform::window::kModifierAlt;
    }
    if ((mod & SDL_KMOD_GUI) != 0) {
      modifiers |= platform::window::kModifierMeta;
    }
    return modifiers;
  }

  [[nodiscard]] std::uint32_t ButtonsDownOf(
    const SDL_MouseButtonFlags flags
  )
  {
    std::uint32_t buttons = 0;
    if ((flags & SDL_BUTTON_LMASK) != 0) {
      buttons |= platform::window::kLeftDown;
    }
    if ((flags & SDL_BUTTON_MMASK) != 0) {
      buttons |= platform::window::kMiddleDown;
    }
    if ((flags & SDL_BUTTON_RMASK) != 0) {
      buttons |= platform::window::kRightDown;
    }
    return buttons;
  }

  // SDL reports the mouse in window points; the engine works in pixels.
  void ToPixels(
    SDL_Window* const window,
    const float x,
    const float y,
    int& outX,
    int& outY
  )
  {
    const float density = window != nullptr ? SDL_GetWindowPixelDensity(window) : 1.0f;
    const float scale = density > 0.0f ? density : 1.0f;
    outX = static_cast<int>(std::lround(x * scale));
    outY = static_cast<int>(std::lround(y * scale));
  }

  void SetModifierKeyState(
    const SDL_Keycode key,
    const bool down
  )
  {
    if (const int sided = SidedVirtualKeyOf(key); sided != 0) {
      platform::window::sdl::OnKey(sided, down);
    }
  }

  // A window's newest size change in SDL's queue stands for the ones before it: a drag of the
  // window's edge queues many, and each costs the renderer a new swap chain.
  [[nodiscard]] bool LaterResizeQueued(
    const SDL_WindowID windowId
  )
  {
    SDL_Event queued[64];
    const int count = SDL_PeepEvents(
      queued, 64, SDL_PEEKEVENT, SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED, SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED
    );
    for (int index = 0; index < count; ++index) {
      if (queued[index].window.windowID == windowId) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] bool Translate(
    const SDL_Event& source,
    platform::window::Event& out
  )
  {
    using platform::window::EventType;
    namespace system = platform::window::sdl;
    out = platform::window::Event{};
    switch (source.type) {
    case SDL_EVENT_QUIT:
      out.type = EventType::Quit;
      return true;
    case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
      out.type = EventType::CloseRequested;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      return true;
    case SDL_EVENT_WINDOW_MOVED:
      out.type = EventType::Moved;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      out.x = source.window.data1;
      out.y = source.window.data2;
      system::OnWindowRectChanged(AsWindow(out.window));
      return true;
    case SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED:
      if (LaterResizeQueued(source.window.windowID)) {
        return false;
      }
      out.type = EventType::Resized;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      out.width = source.window.data1;
      out.height = source.window.data2;
      system::OnWindowRectChanged(AsWindow(out.window));
      return true;
    case SDL_EVENT_WINDOW_MINIMIZED:
      out.type = EventType::Minimized;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      system::OnWindowMinimized(AsWindow(out.window), true);
      return true;
    case SDL_EVENT_WINDOW_RESTORED:
      out.type = EventType::Restored;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      system::OnWindowMinimized(AsWindow(out.window), false);
      return true;
    case SDL_EVENT_WINDOW_MAXIMIZED:
      out.type = EventType::Maximized;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      system::OnWindowMinimized(AsWindow(out.window), false);
      return true;
    case SDL_EVENT_WINDOW_FOCUS_GAINED:
      out.type = EventType::FocusGained;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      system::OnFocusChanged(AsWindow(out.window));
      return true;
    case SDL_EVENT_WINDOW_FOCUS_LOST:
      out.type = EventType::FocusLost;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      system::OnFocusChanged(nullptr);
      return true;
    case SDL_EVENT_WINDOW_EXPOSED:
      out.type = EventType::Exposed;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      return true;
    case SDL_EVENT_WINDOW_MOUSE_ENTER:
      out.type = EventType::MouseEnter;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      return true;
    case SDL_EVENT_WINDOW_MOUSE_LEAVE:
      out.type = EventType::MouseLeave;
      out.window = SDL_GetWindowFromID(source.window.windowID);
      return true;
    case SDL_EVENT_DISPLAY_ADDED:
    case SDL_EVENT_DISPLAY_REMOVED:
    case SDL_EVENT_DISPLAY_MOVED:
    case SDL_EVENT_DISPLAY_ORIENTATION:
      system::OnDisplaysChanged();
      out.type = EventType::DisplaysChanged;
      return true;
    case SDL_EVENT_MOUSE_MOTION: {
      SDL_Window* const window = SDL_GetWindowFromID(source.motion.windowID);
      out.type = EventType::MouseMove;
      out.window = window;
      ToPixels(window, source.motion.x, source.motion.y, out.x, out.y);
      out.buttonsDown = ButtonsDownOf(source.motion.state);
      out.modifiers = ModifiersOf(SDL_GetModState());
      float globalX = 0.0f;
      float globalY = 0.0f;
      (void)SDL_GetGlobalMouseState(&globalX, &globalY);
      system::OnCursorMoved(static_cast<int>(globalX), static_cast<int>(globalY));
      return true;
    }
    case SDL_EVENT_MOUSE_BUTTON_DOWN:
    case SDL_EVENT_MOUSE_BUTTON_UP: {
      const bool down = source.type == SDL_EVENT_MOUSE_BUTTON_DOWN;
      SDL_Window* const window = SDL_GetWindowFromID(source.button.windowID);
      int button = 0;
      switch (source.button.button) {
      case SDL_BUTTON_LEFT:
        button = platform::window::kButtonLeft;
        break;
      case SDL_BUTTON_MIDDLE:
        button = platform::window::kButtonMiddle;
        break;
      case SDL_BUTTON_RIGHT:
        button = platform::window::kButtonRight;
        break;
      case SDL_BUTTON_X1:
      case SDL_BUTTON_X2: {
        // FAF's patch to the retail viewport's window procedure (FA-Binary-Patches
        // OnWindowMessage, at 0x00430C0E) hands the side buttons on as presses of VK_XBUTTON1 and
        // VK_XBUTTON2, so key bindings can name them.
        const int virtualKey = source.button.button == SDL_BUTTON_X1 ? VK_XBUTTON1 : VK_XBUTTON2;
        system::OnKey(virtualKey, down);
        out.type = down ? EventType::KeyDown : EventType::KeyUp;
        out.window = window;
        out.virtualKey = virtualKey;
        out.modifiers = ModifiersOf(SDL_GetModState());
        return true;
      }
      default:
        return false;
      }
      out.type = down ? EventType::MouseDown : EventType::MouseUp;
      out.window = window;
      out.button = button;
      out.clicks = source.button.clicks;
      ToPixels(window, source.button.x, source.button.y, out.x, out.y);
      out.buttonsDown = ButtonsDownOf(SDL_GetMouseState(nullptr, nullptr));
      out.modifiers = ModifiersOf(SDL_GetModState());
      static constexpr int kButtonKeys[] = {0, VK_LBUTTON, VK_MBUTTON, VK_RBUTTON};
      system::OnKey(kButtonKeys[button], down);
      return true;
    }
    case SDL_EVENT_MOUSE_WHEEL: {
      SDL_Window* const window = SDL_GetWindowFromID(source.wheel.windowID);
      out.type = EventType::MouseWheel;
      out.window = window;
      out.wheel = source.wheel.direction == SDL_MOUSEWHEEL_FLIPPED ? -source.wheel.y : source.wheel.y;
      ToPixels(window, source.wheel.mouse_x, source.wheel.mouse_y, out.x, out.y);
      out.buttonsDown = ButtonsDownOf(SDL_GetMouseState(nullptr, nullptr));
      out.modifiers = ModifiersOf(SDL_GetModState());
      return true;
    }
    case SDL_EVENT_KEY_DOWN:
    case SDL_EVENT_KEY_UP: {
      const bool down = source.type == SDL_EVENT_KEY_DOWN;
      const int virtualKey = VirtualKeyOf(source.key.key);
      SetModifierKeyState(source.key.key, down);
      if (virtualKey == 0) {
        return false;
      }
      system::OnKey(virtualKey, down);
      out.type = down ? EventType::KeyDown : EventType::KeyUp;
      out.window = SDL_GetWindowFromID(source.key.windowID);
      out.virtualKey = virtualKey;
      out.repeat = source.key.repeat;
      out.modifiers = ModifiersOf(source.key.mod);
      return true;
    }
    default:
      return false;
    }
  }

  // Typed text arrives as UTF-8 strings; the engine takes one character per event.
  void QueueText(
    const SDL_TextInputEvent& text
  )
  {
    const auto* bytes = reinterpret_cast<const unsigned char*>(text.text);
    SDL_Window* const window = SDL_GetWindowFromID(text.windowID);
    const std::uint32_t modifiers = ModifiersOf(SDL_GetModState());
    while (bytes != nullptr && *bytes != 0) {
      std::uint32_t codepoint = 0;
      int length = 1;
      if (*bytes < 0x80u) {
        codepoint = *bytes;
      } else if ((*bytes & 0xE0u) == 0xC0u) {
        codepoint = *bytes & 0x1Fu;
        length = 2;
      } else if ((*bytes & 0xF0u) == 0xE0u) {
        codepoint = *bytes & 0x0Fu;
        length = 3;
      } else {
        codepoint = *bytes & 0x07u;
        length = 4;
      }
      for (int index = 1; index < length; ++index) {
        if ((bytes[index] & 0xC0u) != 0x80u) {
          return; // broken UTF-8: drop the rest
        }
        codepoint = (codepoint << 6) | (bytes[index] & 0x3Fu);
      }
      bytes += length;
      platform::window::Event event{};
      event.type = platform::window::EventType::Text;
      event.window = window;
      event.codepoint = codepoint;
      event.modifiers = modifiers;
      gQueued.push_back(event);
    }
  }

  // The next event for the engine, before the filter sees it.
  [[nodiscard]] bool NextEvent(
    platform::window::Event& event
  )
  {
    if (!gQueued.empty()) {
      event = gQueued.front();
      gQueued.pop_front();
      return true;
    }
    SDL_Event source{};
    while (SDL_PollEvent(&source)) {
      if (gToolEventHook != nullptr && gToolEventHook(&source)) {
        continue;
      }
      if (source.type == SDL_EVENT_TEXT_INPUT) {
        QueueText(source.text);
        if (!gQueued.empty()) {
          event = gQueued.front();
          gQueued.pop_front();
          return true;
        }
        continue;
      }
      if (Translate(source, event)) {
        return true;
      }
    }
    return false;
  }
} // namespace

namespace platform::window::sdl
{
  void SetToolEventHook(
    const ToolEventHook hook
  )
  {
    gToolEventHook = hook;
  }

  void QueueEvent(
    const Event& event
  )
  {
    gQueued.push_back(event);
  }

  bool CallCursorRequestHandler(
    SDL_Window* const window
  )
  {
    return gCursorRequestHandler != nullptr && gCursorRequestHandler(window);
  }
} // namespace platform::window::sdl

namespace platform::window
{
  bool Init()
  {
    if (gInitialized) {
      return true;
    }
    // Closing the last window asks the engine (the main frame's close shows the escape dialog);
    // it isn't a request to quit.
    (void)SDL_SetHint(SDL_HINT_QUIT_ON_LAST_WINDOW_CLOSE, "0");
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) {
      gpg::Warnf("Window system: %s", SDL_GetError());
      return false;
    }
    gInitialized = true;
    gpg::Logf(
      "Window system: SDL %d.%d.%d on %s",
      SDL_MAJOR_VERSION,
      SDL_MINOR_VERSION,
      SDL_MICRO_VERSION,
      SDL_GetCurrentVideoDriver()
    );
    sdl::OnInit();
    sdl::OnDisplaysChanged();
    return true;
  }

  void Shutdown()
  {
    if (!gInitialized) {
      return;
    }
    for (SDL_Window* const window : gWindows) {
      sdl::OnWindowDestroyed(window);
      SDL_DestroyWindow(window);
    }
    gWindows.clear();
    gQueued.clear();
    HideSplash();
    sdl::OnShutdown();
    SDL_Quit();
    gInitialized = false;
  }

  bool IsInitialized()
  {
    return gInitialized;
  }

  Handle CreateTopLevel(
    const char* const utf8Title,
    const int x,
    const int y,
    const int width,
    const int height,
    const bool resizable
  )
  {
    if (!gInitialized) {
      return nullptr;
    }
    SDL_PropertiesID properties = SDL_CreateProperties();
    (void)SDL_SetStringProperty(properties, SDL_PROP_WINDOW_CREATE_TITLE_STRING, utf8Title != nullptr ? utf8Title : "");
    (void)SDL_SetNumberProperty(properties, SDL_PROP_WINDOW_CREATE_X_NUMBER, x < 0 ? SDL_WINDOWPOS_CENTERED : x);
    (void)SDL_SetNumberProperty(properties, SDL_PROP_WINDOW_CREATE_Y_NUMBER, y < 0 ? SDL_WINDOWPOS_CENTERED : y);
    (void)SDL_SetNumberProperty(properties, SDL_PROP_WINDOW_CREATE_WIDTH_NUMBER, width > 0 ? width : 1024);
    (void)SDL_SetNumberProperty(properties, SDL_PROP_WINDOW_CREATE_HEIGHT_NUMBER, height > 0 ? height : 768);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_RESIZABLE_BOOLEAN, resizable);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_HIDDEN_BOOLEAN, true);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_HIGH_PIXEL_DENSITY_BOOLEAN, true);
    sdl::OnCreateProperties(properties);
    SDL_Window* const window = SDL_CreateWindowWithProperties(properties);
    SDL_DestroyProperties(properties);
    if (window == nullptr) {
      gpg::Warnf("Window system: can't create a window: %s", SDL_GetError());
      return nullptr;
    }
    // Typed text for the chat, the console and the edit boxes, through the input method.
    (void)SDL_StartTextInput(window);
    gWindows.push_back(window);
    sdl::OnWindowCreated(window);
    if (x >= 0 && y >= 0) {
      SetFramePosition(window, x, y);
    }
    sdl::OnWindowRectChanged(window);
    return window;
  }

  void GetFramePosition(
    const Handle window,
    int* const x,
    int* const y
  )
  {
    int clientX = 0;
    int clientY = 0;
    int top = 0;
    int left = 0;
    if (window != nullptr) {
      (void)SDL_GetWindowPosition(AsWindow(window), &clientX, &clientY);
      (void)SDL_GetWindowBordersSize(AsWindow(window), &top, &left, nullptr, nullptr);
    }
    if (x != nullptr) {
      *x = clientX - left;
    }
    if (y != nullptr) {
      *y = clientY - top;
    }
  }

  void SetFramePosition(
    const Handle window,
    const int x,
    const int y
  )
  {
    if (window == nullptr) {
      return;
    }
    int top = 0;
    int left = 0;
    (void)SDL_GetWindowBordersSize(AsWindow(window), &top, &left, nullptr, nullptr);
    (void)SDL_SetWindowPosition(AsWindow(window), x + left, y + top);
    (void)SDL_SyncWindow(AsWindow(window));
    sdl::OnWindowRectChanged(AsWindow(window));
  }

  Handle CreateChild(
    const Handle parent,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (!gInitialized || parent == nullptr) {
      return nullptr;
    }
    SDL_Window* const window = sdl::CreateChild(AsWindow(parent), x, y, width, height);
    if (window == nullptr) {
      return nullptr;
    }
    (void)SDL_StartTextInput(window);
    gWindows.push_back(window);
    sdl::OnWindowCreated(window);
    sdl::OnWindowRectChanged(window);
    return window;
  }

  void Destroy(
    const Handle window
  )
  {
    if (window == nullptr) {
      return;
    }
    void* const native = sdl::IsChild(AsWindow(window)) ? sdl::NativeHandleOf(AsWindow(window)) : nullptr;
    for (auto it = gWindows.begin(); it != gWindows.end(); ++it) {
      if (*it == window) {
        gWindows.erase(it);
        break;
      }
    }
    // Events still queued for it name a window that is gone.
    for (auto it = gQueued.begin(); it != gQueued.end();) {
      it = it->window == window ? gQueued.erase(it) : it + 1;
    }
    sdl::OnWindowDestroyed(AsWindow(window));
    SDL_DestroyWindow(AsWindow(window));
    if (native != nullptr) {
      sdl::DestroyChildNative(native);
    }
  }

  void Show(
    const Handle window,
    const bool show
  )
  {
    if (window != nullptr) {
      (void)(show ? SDL_ShowWindow(AsWindow(window)) : SDL_HideWindow(AsWindow(window)));
    }
  }

  bool GetMousePosition(
    const Handle window,
    int& x,
    int& y
  )
  {
    SDL_Window* const native = AsWindow(window);
    if (native == nullptr || SDL_GetMouseFocus() != native || SDL_GetKeyboardFocus() != native) {
      return false;
    }
    float mouseX = 0.0f;
    float mouseY = 0.0f;
    (void)SDL_GetMouseState(&mouseX, &mouseY);
    // Cursor coordinates identify a point inside a pixel, not its nearest pixel boundary.
    // Rounding makes the penultimate row/column scroll and rejects part of the last one.
    const float density = SDL_GetWindowPixelDensity(native);
    const float scale = density > 0.0f ? density : 1.0f;
    x = static_cast<int>(std::floor(mouseX * scale));
    y = static_cast<int>(std::floor(mouseY * scale));
    int width = 0;
    int height = 0;
    if (!SDL_GetWindowSizeInPixels(native, &width, &height)) {
      return false;
    }
    return x >= 0 && y >= 0 && x < width && y < height;
  }

  void SetTitle(
    const Handle window,
    const char* const utf8Title
  )
  {
    if (window != nullptr) {
      (void)SDL_SetWindowTitle(AsWindow(window), utf8Title != nullptr ? utf8Title : "");
    }
  }

  void SetBounds(
    const Handle window,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (window == nullptr) {
      return;
    }
    if (sdl::SetChildBounds(AsWindow(window), x, y, width, height)) {
      sdl::OnWindowRectChanged(AsWindow(window));
      return;
    }
    if (x != -1 || y != -1) {
      int currentX = 0;
      int currentY = 0;
      (void)SDL_GetWindowPosition(AsWindow(window), &currentX, &currentY);
      (void)SDL_SetWindowPosition(AsWindow(window), x != -1 ? x : currentX, y != -1 ? y : currentY);
    }
    if (width != -1 || height != -1) {
      int currentWidth = 0;
      int currentHeight = 0;
      (void)SDL_GetWindowSize(AsWindow(window), &currentWidth, &currentHeight);
      (void)SDL_SetWindowSize(
        AsWindow(window), width != -1 ? width : currentWidth, height != -1 ? height : currentHeight
      );
    }
    (void)SDL_SyncWindow(AsWindow(window));
    sdl::OnWindowRectChanged(AsWindow(window));
  }

  void Maximize(
    const Handle window
  )
  {
    if (window != nullptr) {
      (void)SDL_MaximizeWindow(AsWindow(window));
    }
  }

  void Minimize(
    const Handle window
  )
  {
    if (window != nullptr) {
      (void)SDL_MinimizeWindow(AsWindow(window));
    }
  }

  void Restore(
    const Handle window
  )
  {
    if (window != nullptr) {
      (void)SDL_RestoreWindow(AsWindow(window));
    }
  }

  void SetFullscreen(
    const Handle window,
    const bool fullscreen
  )
  {
    if (window != nullptr) {
      (void)SDL_SetWindowFullscreen(AsWindow(window), fullscreen);
    }
  }

  void Raise(
    const Handle window
  )
  {
    if (window != nullptr) {
      (void)SDL_RaiseWindow(AsWindow(window));
    }
  }

  void GetBounds(
    const Handle window,
    int* const x,
    int* const y,
    int* const width,
    int* const height
  )
  {
    if (window != nullptr && sdl::GetChildBounds(AsWindow(window), x, y, width, height)) {
      return;
    }
    int positionX = 0;
    int positionY = 0;
    int pixelWidth = 0;
    int pixelHeight = 0;
    if (window != nullptr) {
      (void)SDL_GetWindowPosition(AsWindow(window), &positionX, &positionY);
      (void)SDL_GetWindowSizeInPixels(AsWindow(window), &pixelWidth, &pixelHeight);
    }
    if (x != nullptr) {
      *x = positionX;
    }
    if (y != nullptr) {
      *y = positionY;
    }
    if (width != nullptr) {
      *width = pixelWidth;
    }
    if (height != nullptr) {
      *height = pixelHeight;
    }
  }

  void SetKeyboardFocus(
    const Handle window
  )
  {
    if (window != nullptr) {
      sdl::SetKeyboardFocus(AsWindow(window));
    }
  }

  bool HasKeyboardFocus()
  {
    return gInitialized && SDL_GetKeyboardFocus() != nullptr;
  }

  void* NativeHandle(
    const Handle window
  )
  {
    return window != nullptr ? sdl::NativeHandleOf(AsWindow(window)) : nullptr;
  }

  Handle FromNativeHandle(
    void* const native
  )
  {
    if (native == nullptr) {
      return nullptr;
    }
    for (SDL_Window* const window : gWindows) {
      if (sdl::NativeHandleOf(window) == native) {
        return window;
      }
    }
    return nullptr;
  }

  void AddSystemMenuItem(
    const Handle window,
    const int command,
    const char* const utf8Label
  )
  {
    if (window != nullptr) {
      sdl::AddSystemMenuItem(AsWindow(window), command, utf8Label);
    }
  }

  bool HasEvents()
  {
    if (!gInitialized) {
      return false;
    }
    if (!gQueued.empty()) {
      return true;
    }
    SDL_PumpEvents();
    return SDL_HasEvents(SDL_EVENT_FIRST, SDL_EVENT_LAST) || !gQueued.empty();
  }

  bool PollEvent(
    Event& event
  )
  {
    if (!gInitialized) {
      return false;
    }
    while (NextEvent(event)) {
      if (gEventFilter == nullptr || !gEventFilter(event)) {
        return true;
      }
    }
    return false;
  }

  void SetEventFilter(
    const EventFilter filter
  )
  {
    gEventFilter = filter;
  }

  void SetCursorRequestHandler(
    const CursorRequestHandler handler
  )
  {
    gCursorRequestHandler = handler;
  }

  namespace
  {
    // One folder pick in flight: what SDL's dialog is given and what its callback answers.
    struct FolderPick
    {
      std::string title;
      std::string location;
      std::mutex mutex;
      std::condition_variable answered;
      bool done = false;
      bool chosen = false;
      std::string path;
    };

    void SDLCALL OnFolderPicked(
      void* const userdata,
      const char* const* const fileList,
      const int filter
    )
    {
      (void)filter;
      auto& pick = *static_cast<FolderPick*>(userdata);
      std::lock_guard<std::mutex> lock(pick.mutex);
      if (fileList != nullptr && fileList[0] != nullptr) {
        pick.chosen = true;
        pick.path = fileList[0];
      } else if (fileList == nullptr) {
        gpg::Warnf("Folder picker: %s", SDL_GetError());
      }
      pick.done = true;
      pick.answered.notify_all();
    }

    // On the main thread, as SDL's dialogs require.
    void SDLCALL StartFolderPick(
      void* const userdata
    )
    {
      auto& pick = *static_cast<FolderPick*>(userdata);
      const SDL_PropertiesID properties = SDL_CreateProperties();
      (void)SDL_SetStringProperty(properties, SDL_PROP_FILE_DIALOG_TITLE_STRING, pick.title.c_str());
      if (!pick.location.empty()) {
        (void)SDL_SetStringProperty(properties, SDL_PROP_FILE_DIALOG_LOCATION_STRING, pick.location.c_str());
      }
      (void)SDL_SetBooleanProperty(properties, SDL_PROP_FILE_DIALOG_MANY_BOOLEAN, false);
      SDL_ShowFileDialogWithProperties(SDL_FILEDIALOG_OPENFOLDER, &OnFolderPicked, &pick, properties);
      SDL_DestroyProperties(properties);
    }

    SDL_Window* gSplashWindow = nullptr;
    SDL_Renderer* gSplashRenderer = nullptr;
  } // namespace

  bool PickFolder(
    const char* const utf8Title,
    std::string& utf8Path
  )
  {
    if (!gInitialized) {
      return false; // headless: no dialog, the path stays as it is
    }
    FolderPick pick;
    pick.title = utf8Title != nullptr ? utf8Title : "";
    pick.location = utf8Path;
    if (SDL_IsMainThread()) {
      StartFolderPick(&pick);
      // The window system keeps running (the game's events wait in SDL's queue) until it answers.
      for (;;) {
        {
          std::lock_guard<std::mutex> lock(pick.mutex);
          if (pick.done) {
            break;
          }
        }
        SDL_PumpEvents();
        SDL_Delay(10);
      }
    } else {
      // The main thread opens it when it next reads events; this thread waits, as the binary's
      // modal DirDialog held the thread that asked.
      if (!SDL_RunOnMainThread(&StartFolderPick, &pick, false)) {
        return false;
      }
      std::unique_lock<std::mutex> lock(pick.mutex);
      pick.answered.wait(lock, [&pick]() {
        return pick.done;
      });
    }
    std::lock_guard<std::mutex> lock(pick.mutex);
    if (!pick.chosen) {
      return false;
    }
    utf8Path = pick.path;
    return true;
  }

  bool ShowSplash(
    const char* const utf8PngPath,
    const int width,
    const int height
  )
  {
    HideSplash();
    if (!gInitialized || utf8PngPath == nullptr || width <= 0 || height <= 0) {
      return false;
    }
    SDL_Surface* const image = SDL_LoadPNG(utf8PngPath);
    if (image == nullptr) {
      return false;
    }
    gSplashWindow = SDL_CreateWindow(
      "", width, height, SDL_WINDOW_BORDERLESS | SDL_WINDOW_ALWAYS_ON_TOP | SDL_WINDOW_UTILITY | SDL_WINDOW_HIDDEN
    );
    if (gSplashWindow != nullptr) {
      (void)SDL_SetWindowPosition(gSplashWindow, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);
      gSplashRenderer = SDL_CreateRenderer(gSplashWindow, nullptr);
    }
    if (gSplashRenderer != nullptr) {
      SDL_Texture* const texture = SDL_CreateTextureFromSurface(gSplashRenderer, image);
      (void)SDL_ShowWindow(gSplashWindow);
      (void)SDL_RenderClear(gSplashRenderer);
      if (texture != nullptr) {
        (void)SDL_RenderTexture(gSplashRenderer, texture, nullptr, nullptr);
      }
      (void)SDL_RenderPresent(gSplashRenderer);
      SDL_DestroyTexture(texture);
    }
    SDL_DestroySurface(image);
    if (gSplashRenderer == nullptr) {
      HideSplash();
      return false;
    }
    return true;
  }

  void HideSplash()
  {
    if (gSplashRenderer != nullptr) {
      SDL_DestroyRenderer(gSplashRenderer);
      gSplashRenderer = nullptr;
    }
    if (gSplashWindow != nullptr) {
      SDL_DestroyWindow(gSplashWindow);
      gSplashWindow = nullptr;
    }
  }

  void SetTextInputArea(
    const Handle window,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (window == nullptr) {
      return;
    }
    const SDL_Rect area{x, y, width, height};
    (void)SDL_SetTextInputArea(AsWindow(window), &area, 0);
    (void)SDL_StartTextInput(AsWindow(window));
  }
} // namespace platform::window
