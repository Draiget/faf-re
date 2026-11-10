// Engine addition (issue #256): platform::window (src/platform/Window.h) on SDL3, for the Linux
// client. Windows are SDL windows made for Vulkan; their events become platform::window events, and
// the Win32 window, cursor, clipboard and message-box calls the engine makes
// (src/platform/posix/Win32WindowPosix.h) are routed here by Init.

#include "platform/Window.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <SDL3/SDL.h>

#include <Windows.h>

#include "gpg/core/utils/Logging.h"
#include "platform/posix/Win32WindowPosix.h"

namespace
{
  bool gInitialized = false;
  // The windows made here, the first being the main one (the cursor clip's window).
  std::vector<SDL_Window*> gWindows;

  [[nodiscard]] SDL_Window* AsWindow(void* const handle)
  {
    return static_cast<SDL_Window*>(handle);
  }

  // --- Keys: SDL's key codes (the layout's) to Windows virtual-key codes ----------------------

  [[nodiscard]] int VirtualKeyOf(const SDL_Keycode key)
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
      case SDLK_BACKSPACE: return VK_BACK;
      case SDLK_TAB: return VK_TAB;
      case SDLK_CLEAR: return VK_CLEAR;
      case SDLK_RETURN: return VK_RETURN;
      case SDLK_PAUSE: return VK_PAUSE;
      case SDLK_CAPSLOCK: return VK_CAPITAL;
      case SDLK_ESCAPE: return VK_ESCAPE;
      case SDLK_SPACE: return VK_SPACE;
      case SDLK_PAGEUP: return VK_PRIOR;
      case SDLK_PAGEDOWN: return VK_NEXT;
      case SDLK_END: return VK_END;
      case SDLK_HOME: return VK_HOME;
      case SDLK_LEFT: return VK_LEFT;
      case SDLK_UP: return VK_UP;
      case SDLK_RIGHT: return VK_RIGHT;
      case SDLK_DOWN: return VK_DOWN;
      case SDLK_SELECT: return VK_SELECT;
      case SDLK_EXECUTE: return VK_EXECUTE;
      case SDLK_PRINTSCREEN: return VK_SNAPSHOT;
      case SDLK_INSERT: return VK_INSERT;
      case SDLK_DELETE: return VK_DELETE;
      case SDLK_HELP: return VK_HELP;
      case SDLK_LGUI: return VK_LWIN;
      case SDLK_RGUI: return VK_RWIN;
      case SDLK_APPLICATION: return VK_APPS;
      case SDLK_KP_0: return VK_NUMPAD0;
      case SDLK_KP_1: return VK_NUMPAD1;
      case SDLK_KP_2: return VK_NUMPAD2;
      case SDLK_KP_3: return VK_NUMPAD3;
      case SDLK_KP_4: return VK_NUMPAD4;
      case SDLK_KP_5: return VK_NUMPAD5;
      case SDLK_KP_6: return VK_NUMPAD6;
      case SDLK_KP_7: return VK_NUMPAD7;
      case SDLK_KP_8: return VK_NUMPAD8;
      case SDLK_KP_9: return VK_NUMPAD9;
      case SDLK_KP_MULTIPLY: return VK_MULTIPLY;
      case SDLK_KP_PLUS: return VK_ADD;
      case SDLK_KP_MINUS: return VK_SUBTRACT;
      case SDLK_KP_PERIOD: return VK_DECIMAL;
      case SDLK_KP_DIVIDE: return VK_DIVIDE;
      case SDLK_KP_ENTER: return VK_RETURN;
      case SDLK_NUMLOCKCLEAR: return VK_NUMLOCK;
      case SDLK_SCROLLLOCK: return VK_SCROLL;
      case SDLK_LSHIFT:
      case SDLK_RSHIFT: return VK_SHIFT;
      case SDLK_LCTRL:
      case SDLK_RCTRL: return VK_CONTROL;
      case SDLK_LALT:
      case SDLK_RALT: return VK_MENU;
      case SDLK_SEMICOLON: return VK_OEM_1;
      case SDLK_EQUALS:
      case SDLK_PLUS: return VK_OEM_PLUS;
      case SDLK_COMMA: return VK_OEM_COMMA;
      case SDLK_MINUS: return VK_OEM_MINUS;
      case SDLK_PERIOD: return VK_OEM_PERIOD;
      case SDLK_SLASH: return VK_OEM_2;
      case SDLK_GRAVE: return VK_OEM_3;
      case SDLK_LEFTBRACKET: return VK_OEM_4;
      case SDLK_BACKSLASH: return VK_OEM_5;
      case SDLK_RIGHTBRACKET: return VK_OEM_6;
      case SDLK_APOSTROPHE: return VK_OEM_7;
      default: return 0;
    }
  }

  // The left/right virtual key GetKeyState also answers for a modifier (Windows keeps both).
  [[nodiscard]] int SidedVirtualKeyOf(const SDL_Keycode key)
  {
    switch (key) {
      case SDLK_LSHIFT: return VK_LSHIFT;
      case SDLK_RSHIFT: return VK_RSHIFT;
      case SDLK_LCTRL: return VK_LCONTROL;
      case SDLK_RCTRL: return VK_RCONTROL;
      case SDLK_LALT: return VK_LMENU;
      case SDLK_RALT: return VK_RMENU;
      default: return 0;
    }
  }

  [[nodiscard]] std::uint32_t ModifiersOf(const SDL_Keymod mod)
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

  [[nodiscard]] std::uint32_t ButtonsDownOf(const SDL_MouseButtonFlags flags)
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
  void ToPixels(SDL_Window* const window, const float x, const float y, int& outX, int& outY)
  {
    const float density = window != nullptr ? SDL_GetWindowPixelDensity(window) : 1.0f;
    const float scale = density > 0.0f ? density : 1.0f;
    outX = static_cast<int>(std::lround(x * scale));
    outY = static_cast<int>(std::lround(y * scale));
  }

  // What GetWindowRect, GetClientRect and the cursor's screen position answer from
  // (Win32WindowPosix.cpp).
  void PublishWindowRect(SDL_Window* const window)
  {
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    platform::window::GetBounds(window, &x, &y, &width, &height);
    platform::posix::SetWindowScreenRect(window, x, y, x + width, y + height);
  }

  void PublishMonitors()
  {
    int count = 0;
    SDL_DisplayID* const displays = SDL_GetDisplays(&count);
    std::vector<int> rects;
    const SDL_DisplayID primary = SDL_GetPrimaryDisplay();
    // The primary first, as SetMonitors expects.
    for (int pass = 0; pass < 2 && displays != nullptr; ++pass) {
      for (int index = 0; index < count; ++index) {
        if ((pass == 0) != (displays[index] == primary)) {
          continue;
        }
        SDL_Rect bounds{};
        if (SDL_GetDisplayBounds(displays[index], &bounds)) {
          rects.insert(rects.end(), {bounds.x, bounds.y, bounds.x + bounds.w, bounds.y + bounds.h});
        }
      }
    }
    SDL_free(displays);
    platform::posix::SetMonitors(rects.data(), static_cast<int>(rects.size() / 4u));
  }

  // --- The Win32 calls routed here (Win32WindowPosix.h) ------------------------------------

  void WarpCursor(const int x, const int y)
  {
    (void)SDL_WarpMouseGlobal(static_cast<float>(x), static_cast<float>(y));
  }

  void Focus(void* const window)
  {
    if (window != nullptr) {
      (void)SDL_RaiseWindow(AsWindow(window));
    }
  }

  void ShowWindowCommand(void* const window, const int command)
  {
    if (window == nullptr) {
      return;
    }
    switch (command) {
      case SW_HIDE: (void)SDL_HideWindow(AsWindow(window)); break;
      case SW_MINIMIZE:
      case SW_SHOWMINIMIZED: (void)SDL_MinimizeWindow(AsWindow(window)); break;
      case SW_SHOWMAXIMIZED: (void)SDL_MaximizeWindow(AsWindow(window)); break;
      case SW_RESTORE: (void)SDL_RestoreWindow(AsWindow(window)); break;
      default: (void)SDL_ShowWindow(AsWindow(window)); break;
    }
  }

  void SetWindowPosition(void* const window, const int x, const int y, const int width, const int height, const unsigned int flags)
  {
    if (window == nullptr) {
      return;
    }
    if ((flags & SWP_NOMOVE) == 0u) {
      (void)SDL_SetWindowPosition(AsWindow(window), x, y);
    }
    if ((flags & SWP_NOSIZE) == 0u) {
      (void)SDL_SetWindowSize(AsWindow(window), width, height);
    }
  }

  void ClipCursor(const bool clip, const int left, const int top, const int right, const int bottom)
  {
    if (gWindows.empty()) {
      return;
    }
    SDL_Window* const window = gWindows.front();
    if (!clip) {
      (void)SDL_SetWindowMouseRect(window, nullptr);
      return;
    }
    int windowX = 0;
    int windowY = 0;
    (void)SDL_GetWindowPosition(window, &windowX, &windowY);
    const SDL_Rect rect{left - windowX, top - windowY, right - left, bottom - top};
    (void)SDL_SetWindowMouseRect(window, &rect);
  }

  void SetTitleHook(void* const window, const char* const utf8Title)
  {
    if (window != nullptr) {
      (void)SDL_SetWindowTitle(AsWindow(window), utf8Title);
    }
  }

  void ScreenSaver(const bool allowed)
  {
    (void)(allowed ? SDL_EnableScreenSaver() : SDL_DisableScreenSaver());
  }

  void* CreateCursor(const unsigned int* const bgraBottomUp, const int hotspotX, const int hotspotY)
  {
    SDL_Surface* const surface = SDL_CreateSurface(32, 32, SDL_PIXELFORMAT_ARGB8888);
    if (surface == nullptr) {
      return nullptr;
    }
    // B,G,R,A bytes are ARGB8888 words on a little-endian machine; rows arrive bottom-up.
    for (int row = 0; row < 32; ++row) {
      auto* const destination = reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(surface->pixels) + row * surface->pitch);
      const unsigned int* const source = bgraBottomUp + (31 - row) * 32;
      for (int column = 0; column < 32; ++column) {
        destination[column] = source[column];
      }
    }
    SDL_Cursor* const cursor = SDL_CreateColorCursor(surface, hotspotX, hotspotY);
    SDL_DestroySurface(surface);
    return cursor;
  }

  void DestroyCursor(void* const cursor)
  {
    SDL_DestroyCursor(static_cast<SDL_Cursor*>(cursor));
  }

  void SetCursorHook(void* const cursor)
  {
    (void)SDL_SetCursor(cursor != nullptr ? static_cast<SDL_Cursor*>(cursor) : SDL_GetDefaultCursor());
  }

  void ShowCursorHook(const bool shown)
  {
    (void)(shown ? SDL_ShowCursor() : SDL_HideCursor());
  }

  bool MessageBoxHook(void* const window, const char* const utf8Text, const char* const utf8Caption, const bool yesNo)
  {
    if (!yesNo) {
      (void)SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, utf8Caption, utf8Text, AsWindow(window));
      return true;
    }
    const SDL_MessageBoxButtonData buttons[] = {
      {SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT, 0, "No"},
      {SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT, 1, "Yes"},
    };
    SDL_MessageBoxData data{};
    data.flags = SDL_MESSAGEBOX_INFORMATION;
    data.window = AsWindow(window);
    data.title = utf8Caption;
    data.message = utf8Text;
    data.numbuttons = 2;
    data.buttons = buttons;
    int chosen = 0;
    return SDL_ShowMessageBox(&data, &chosen) && chosen == 1;
  }

  bool SetClipboardText(const char* const utf8Text)
  {
    return SDL_SetClipboardText(utf8Text);
  }

  std::string GetClipboardText()
  {
    char* const text = SDL_GetClipboardText();
    std::string result = text != nullptr ? text : "";
    SDL_free(text);
    return result;
  }

  bool OpenUrlHook(const char* const utf8Url)
  {
    return SDL_OpenURL(utf8Url);
  }

  bool EventsPending()
  {
    return platform::window::HasEvents();
  }

  // --- Events --------------------------------------------------------------------------------

  void SetModifierKeyState(const SDL_Keycode key, const bool down)
  {
    if (const int sided = SidedVirtualKeyOf(key); sided != 0) {
      platform::posix::SetKeyDown(sided, down);
    }
  }

  [[nodiscard]] bool Translate(const SDL_Event& source, platform::window::Event& out)
  {
    using platform::window::EventType;
    out = platform::window::Event{};
    switch (source.type) {
      case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
        out.type = EventType::CloseRequested;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        return true;
      case SDL_EVENT_WINDOW_MOVED:
        out.type = EventType::Moved;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        out.x = source.window.data1;
        out.y = source.window.data2;
        PublishWindowRect(AsWindow(out.window));
        return true;
      case SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED:
        out.type = EventType::Resized;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        out.width = source.window.data1;
        out.height = source.window.data2;
        PublishWindowRect(AsWindow(out.window));
        return true;
      case SDL_EVENT_WINDOW_MINIMIZED:
        out.type = EventType::Minimized;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        platform::posix::SetWindowMinimized(out.window, true);
        return true;
      case SDL_EVENT_WINDOW_RESTORED:
        out.type = EventType::Restored;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        platform::posix::SetWindowMinimized(out.window, false);
        return true;
      case SDL_EVENT_WINDOW_MAXIMIZED:
        out.type = EventType::Maximized;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        platform::posix::SetWindowMinimized(out.window, false);
        return true;
      case SDL_EVENT_WINDOW_FOCUS_GAINED:
        out.type = EventType::FocusGained;
        out.window = SDL_GetWindowFromID(source.window.windowID);
        return true;
      case SDL_EVENT_WINDOW_FOCUS_LOST:
        out.type = EventType::FocusLost;
        out.window = SDL_GetWindowFromID(source.window.windowID);
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
        PublishMonitors();
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
        platform::posix::SetCursorScreenPos(static_cast<int>(globalX), static_cast<int>(globalY));
        return true;
      }
      case SDL_EVENT_MOUSE_BUTTON_DOWN:
      case SDL_EVENT_MOUSE_BUTTON_UP: {
        int button = 0;
        switch (source.button.button) {
          case SDL_BUTTON_LEFT: button = platform::window::kButtonLeft; break;
          case SDL_BUTTON_MIDDLE: button = platform::window::kButtonMiddle; break;
          case SDL_BUTTON_RIGHT: button = platform::window::kButtonRight; break;
          default: return false; // the side buttons: wx 2.4.2 had none
        }
        SDL_Window* const window = SDL_GetWindowFromID(source.button.windowID);
        const bool down = source.type == SDL_EVENT_MOUSE_BUTTON_DOWN;
        out.type = down ? EventType::MouseDown : EventType::MouseUp;
        out.window = window;
        out.button = button;
        out.clicks = source.button.clicks;
        ToPixels(window, source.button.x, source.button.y, out.x, out.y);
        out.buttonsDown = ButtonsDownOf(SDL_GetMouseState(nullptr, nullptr));
        out.modifiers = ModifiersOf(SDL_GetModState());
        static constexpr int kButtonKeys[] = {0, VK_LBUTTON, VK_MBUTTON, VK_RBUTTON};
        platform::posix::SetKeyDown(kButtonKeys[button], down);
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
        platform::posix::SetKeyDown(virtualKey, down);
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
  std::vector<platform::window::Event> gPendingText;

  void QueueText(const SDL_TextInputEvent& text)
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
      gPendingText.push_back(event);
    }
  }
} // namespace

namespace platform::window
{
  bool Init()
  {
    if (gInitialized) {
      return true;
    }
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) {
      gpg::Warnf("Window system: %s", SDL_GetError());
      return false;
    }
    gInitialized = true;
    gpg::Logf("Window system: SDL %d.%d.%d on %s", SDL_MAJOR_VERSION, SDL_MINOR_VERSION, SDL_MICRO_VERSION,
              SDL_GetCurrentVideoDriver());
    PublishMonitors();

    platform::posix::gWarpCursorHook = &WarpCursor;
    platform::posix::gFocusHook = &Focus;
    platform::posix::gShowWindowHook = &ShowWindowCommand;
    platform::posix::gSetWindowPosHook = &SetWindowPosition;
    platform::posix::gClipCursorHook = &ClipCursor;
    platform::posix::gSetWindowTitleHook = &SetTitleHook;
    platform::posix::gScreenSaverHook = &ScreenSaver;
    platform::posix::gCreateCursorHook = &CreateCursor;
    platform::posix::gDestroyCursorHook = &DestroyCursor;
    platform::posix::gSetCursorHook = &SetCursorHook;
    platform::posix::gShowCursorHook = &ShowCursorHook;
    platform::posix::gMessageBoxHook = &MessageBoxHook;
    platform::posix::gSetClipboardTextHook = &SetClipboardText;
    platform::posix::gGetClipboardTextHook = &GetClipboardText;
    platform::posix::gOpenUrlHook = &OpenUrlHook;
    platform::posix::gWindowEventsPendingHook = &EventsPending;
    return true;
  }

  void Shutdown()
  {
    if (!gInitialized) {
      return;
    }
    platform::posix::gWindowEventsPendingHook = nullptr;
    for (SDL_Window* const window : gWindows) {
      platform::posix::ForgetWindow(window);
      SDL_DestroyWindow(window);
    }
    gWindows.clear();
    SDL_Quit();
    gInitialized = false;
  }

  bool IsInitialized()
  {
    return gInitialized;
  }

  Handle CreateTopLevel(const char* const utf8Title, const int x, const int y, const int width, const int height, const bool resizable)
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
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_VULKAN_BOOLEAN, true);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_RESIZABLE_BOOLEAN, resizable);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_HIDDEN_BOOLEAN, true);
    (void)SDL_SetBooleanProperty(properties, SDL_PROP_WINDOW_CREATE_HIGH_PIXEL_DENSITY_BOOLEAN, true);
    SDL_Window* const window = SDL_CreateWindowWithProperties(properties);
    SDL_DestroyProperties(properties);
    if (window == nullptr) {
      gpg::Warnf("Window system: can't create a window: %s", SDL_GetError());
      return nullptr;
    }
    // Typed text for the chat and the console.
    (void)SDL_StartTextInput(window);
    gWindows.push_back(window);
    PublishWindowRect(window);
    return window;
  }

  void Destroy(const Handle window)
  {
    if (window == nullptr) {
      return;
    }
    for (auto it = gWindows.begin(); it != gWindows.end(); ++it) {
      if (*it == window) {
        gWindows.erase(it);
        break;
      }
    }
    platform::posix::ForgetWindow(window);
    SDL_DestroyWindow(AsWindow(window));
  }

  void Show(const Handle window, const bool show)
  {
    if (window != nullptr) {
      (void)(show ? SDL_ShowWindow(AsWindow(window)) : SDL_HideWindow(AsWindow(window)));
    }
  }

  void SetTitle(const Handle window, const char* const utf8Title)
  {
    SetTitleHook(window, utf8Title);
  }

  void SetBounds(const Handle window, const int x, const int y, const int width, const int height)
  {
    if (window == nullptr) {
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
      (void)SDL_SetWindowSize(AsWindow(window), width != -1 ? width : currentWidth, height != -1 ? height : currentHeight);
    }
    (void)SDL_SyncWindow(AsWindow(window));
    PublishWindowRect(AsWindow(window));
  }

  void Maximize(const Handle window)
  {
    if (window != nullptr) {
      (void)SDL_MaximizeWindow(AsWindow(window));
    }
  }

  void Minimize(const Handle window)
  {
    if (window != nullptr) {
      (void)SDL_MinimizeWindow(AsWindow(window));
    }
  }

  void Restore(const Handle window)
  {
    if (window != nullptr) {
      (void)SDL_RestoreWindow(AsWindow(window));
    }
  }

  void SetFullscreen(const Handle window, const bool fullscreen)
  {
    if (window != nullptr) {
      (void)SDL_SetWindowFullscreen(AsWindow(window), fullscreen);
    }
  }

  void Raise(const Handle window)
  {
    Focus(window);
  }

  void GetBounds(const Handle window, int* const x, int* const y, int* const width, int* const height)
  {
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

  bool HasEvents()
  {
    if (!gInitialized) {
      return false;
    }
    if (!gPendingText.empty()) {
      return true;
    }
    SDL_PumpEvents();
    return SDL_HasEvents(SDL_EVENT_FIRST, SDL_EVENT_LAST);
  }

  bool PollEvent(Event& event)
  {
    if (!gInitialized) {
      return false;
    }
    if (!gPendingText.empty()) {
      event = gPendingText.front();
      gPendingText.erase(gPendingText.begin());
      return true;
    }
    SDL_Event source{};
    while (SDL_PollEvent(&source)) {
      if (source.type == SDL_EVENT_TEXT_INPUT) {
        QueueText(source.text);
        if (!gPendingText.empty()) {
          event = gPendingText.front();
          gPendingText.erase(gPendingText.begin());
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
} // namespace platform::window
