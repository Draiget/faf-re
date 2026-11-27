// Engine addition: scripted input for test runs (`/testinput <file>`, platform/sdl/TestInput.h).
//
// One step per line; `#` starts a comment. Steps run in order, each logged as "TESTINPUT <n>: <line>".
//
//   wait <ms>                      pause
//   waitlog <text>                 until a logged line contains <text> (120 s, then "TESTINPUT timeout")
//   key [@<win>] <vk> [ctrl] [shift] [alt]   press and release a Windows virtual-key code (hex 0x41,
//                                  decimal, or one letter/digit), with the modifier keys held around it
//   hold <ctrl|shift|alt>...       these modifier keys go down and stay held - for the mouse steps
//                                  that follow and for the engine's own key polls (MAUI_KeyIsDown,
//                                  which otherwise needs the desktop's key state and foreground) -
//                                  until `release` or the end of the script
//   release                        the held modifier keys go up
//   text [@<win>] <utf-8>          the input method commits this text (SDL_EVENT_TEXT_INPUT)
//                                  (keys and text go to the window with the keyboard, else the main one)
//   move <win> <x> <y>             the mouse moves to client pixel x, y of a window
//   down|up <win> <x> <y> [button] a button (left, middle, right) goes down or up there; it stays held
//                                  for the moves until its up (a drag over several frames)
//   click <win> <x> <y> [button] [clicks]
//   drag <win> <x1> <y1> <x2> <y2> [steps]   left button down, moves, up, all within one frame
//   wheel <win> <x> <y> <notches>  the wheel turns (positive: away from the user)
//   con <command>                  a console command
//   clipsave                       keeps the desktop's clipboard text, put back when the script ends
//   clip <utf-8>                   the clipboard's text becomes this (keeping the old text first)
//   getclip                        logs "TESTINPUT clip: <the clipboard's text>"
//   pick <folder> | pick cancel    the next folder picker answers this without a dialog
//   frames <label> <count>         logs frame-interval statistics over the next <count> frames
//   close [<win>]                  a window's close button (the main window's by default)
//   log <text>                     logs "TESTINPUT note: <text>"
//
// <win> is `main` (the game's window), `view` (its child window, where there is one; else main),
// or the title of a developer window with `_` for spaces (Moho_Log).
//
// Mouse steps go through SDL's own input entry points (the ones its platform drivers call), so
// SDL's mouse state follows the script, and the window gets SDL's mouse and keyboard focus for
// them. The desktop's cursor never moves: where the game asks the desktop for the cursor
// (ShellGetMousePosition, platform/shell/Shell.cpp), it gets the script's position instead
// (GetScriptMouseScreenPosition) until the script ends.

#include "platform/sdl/TestInput.h"

#include <cmath>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <SDL3/SDL.h>
#include <ranges>

#include "gpg/core/utils/Logging.h"
#include "platform/sdl/WindowSdlPlatform.h"

// SDL's internal input entry points (src/events/SDL_mouse_c.h, SDL_keyboard_c.h): SDL is linked
// statically on every platform (src/CMakeLists.txt, cmake/FafPosixClient.cmake).
extern "C" void
SDL_SendMouseMotion(Uint64 timestamp, SDL_Window* window, SDL_MouseID mouseID, bool relative, float x, float y);
extern "C" void SDL_SendMouseButtonClicks(
  Uint64 timestamp,
  SDL_Window* window,
  SDL_MouseID mouseID,
  Uint8 button,
  bool down,
  int clicks
);
extern "C" bool SDL_SetKeyboardFocus(SDL_Window* window);

namespace
{
  constexpr Uint64 kWaitLogTimeoutMs = 120000;
  constexpr SDL_MouseID kScriptMouseId = 1; // SDL_DEFAULT_MOUSE_ID

  struct Script
  {
    // Read by NoteLogLine on any thread that logs; written by Start and Tick on the main thread.
    std::atomic<bool> active{false};
    platform::window::test::CommandRunner runCommand = nullptr;
    std::vector<std::string> lines;
    std::size_t next = 0;
    Uint64 resumeAtMs = 0;
    // waitlog
    std::mutex waitMutex;
    std::string waitText;
    std::atomic<bool> waitSeen{false};
    Uint64 waitDeadlineMs = 0;
    // frames
    std::string framesLabel;
    int framesLeft = 0;
    Uint64 lastFrameNs = 0;
    std::vector<double> frameMs;
    // Text and clipboard steps' strings, kept alive while SDL's queue holds pointers to them.
    std::deque<std::string> texts;
    // The desktop's clipboard text from before the first `clip` step, put back when the script ends.
    bool clipboardSaved = false;
    std::string savedClipboard;
  };

  // Set by the first mouse step: from then on the script owns the cursor position.
  std::atomic<bool> sScriptMouse{false};

  // The modifiers a `hold` step holds (SDL_Keymod bits). Read by IsModifierHeld on the main thread's
  // key polls; written by the steps on the main thread.
  std::atomic<unsigned int> sHeldModifiers{0};

  struct HeldModifier
  {
    const char* name;
    SDL_Keycode key;
    SDL_Scancode scancode;
    SDL_Keymod flag;
  };

  constexpr HeldModifier kHoldableModifiers[] = {
    {"ctrl", SDLK_LCTRL, SDL_SCANCODE_LCTRL, SDL_KMOD_LCTRL},
    {"shift", SDLK_LSHIFT, SDL_SCANCODE_LSHIFT, SDL_KMOD_LSHIFT},
    {"alt", SDLK_LALT, SDL_SCANCODE_LALT, SDL_KMOD_LALT},
  };

  void SaveClipboard(
    Script& script
  )
  {
    if (script.clipboardSaved) {
      return;
    }
    char* const text = SDL_GetClipboardText();
    script.savedClipboard = text != nullptr ? text : "";
    SDL_free(text);
    script.clipboardSaved = true;
  }

  Script& TheScript()
  {
    static Script script;
    return script;
  }

  [[nodiscard]] std::vector<std::string> Words(
    const std::string& line
  )
  {
    std::vector<std::string> words;
    std::istringstream stream(line);
    std::string word;
    while (stream >> word) {
      words.push_back(word);
    }
    return words;
  }

  // What follows the first word.
  [[nodiscard]] std::string Rest(
    const std::string& line
  )
  {
    const std::size_t verbEnd = line.find_first_of(" \t");
    if (verbEnd == std::string::npos) {
      return {};
    }
    const std::size_t start = line.find_first_not_of(" \t", verbEnd);
    return start == std::string::npos ? std::string{} : line.substr(start);
  }

  [[nodiscard]] SDL_Window* MainWindow()
  {
    int count = 0;
    SDL_Window** const windows = SDL_GetWindows(&count);
    SDL_Window* found = nullptr;
    for (int index = 0; windows != nullptr && index < count && found == nullptr; ++index) {
      const char* const title = SDL_GetWindowTitle(windows[index]);
      if (title != nullptr && std::strncmp(title, "Forged Alliance", 15) == 0) {
        found = windows[index];
      }
    }
    SDL_free(windows);
    return found;
  }

  [[nodiscard]] SDL_Window* FindWindow(
    const std::string& name
  )
  {
    SDL_Window* const mainWindow = MainWindow();
    if (name == "main") {
      return mainWindow;
    }
    int count = 0;
    SDL_Window** const windows = SDL_GetWindows(&count);
    SDL_Window* found = nullptr;
    std::string title = name;
    std::replace(title.begin(), title.end(), '_', ' ');
    for (int index = 0; windows != nullptr && index < count && found == nullptr; ++index) {
      SDL_Window* const window = windows[index];
      if (name == "view") {
        if (platform::window::sdl::IsChild(window)) {
          found = window;
        }
        continue;
      }
      const char* const windowTitle = SDL_GetWindowTitle(window);
      if (windowTitle != nullptr && std::strncmp(windowTitle, title.c_str(), title.size()) == 0) {
        found = window;
      }
    }
    SDL_free(windows);
    if (found == nullptr && name == "view") {
      return mainWindow; // the viewport shares its parent's window here
    }
    return found;
  }

  // Client pixels to the window's points, which SDL's mouse events carry.
  void ToPoints(
    SDL_Window* const window,
    const float pixelX,
    const float pixelY,
    float& x,
    float& y
  )
  {
    const float density = SDL_GetWindowPixelDensity(window);
    const float scale = density > 0.0f ? density : 1.0f;
    x = pixelX / scale;
    y = pixelY / scale;
  }

  [[nodiscard]] Uint8 ButtonOf(
    const std::string& name
  )
  {
    if (name == "right") {
      return SDL_BUTTON_RIGHT;
    }
    if (name == "middle") {
      return SDL_BUTTON_MIDDLE;
    }
    return SDL_BUTTON_LEFT;
  }

  // The window takes SDL's keyboard focus (the mouse focus follows the motion), as a click on it
  // would give it; the game reads the cursor only for the window that has both.
  void FocusForMouse(
    SDL_Window* const window
  )
  {
    sScriptMouse = true;
    if (SDL_GetKeyboardFocus() != window) {
      (void)SDL_SetKeyboardFocus(window);
    }
  }

  void PushMotion(
    SDL_Window* const window,
    const float x,
    const float y,
    const float /*xrel*/,
    const float /*yrel*/,
    const SDL_MouseButtonFlags /*state*/
  )
  {
    FocusForMouse(window);
    SDL_SendMouseMotion(0, window, kScriptMouseId, false, x, y);
  }

  void PushButton(
    SDL_Window* const window,
    const float x,
    const float y,
    const Uint8 button,
    const bool down,
    const Uint8 clicks
  )
  {
    FocusForMouse(window);
    SDL_SendMouseMotion(0, window, kScriptMouseId, false, x, y);
    SDL_SendMouseButtonClicks(0, window, kScriptMouseId, button, down, clicks);
  }

  void PushKey(
    SDL_Window* const window,
    const SDL_Keycode key,
    const SDL_Scancode scancode,
    const SDL_Keymod modifiers,
    const bool down
  )
  {
    SDL_Event event{};
    event.type = down ? SDL_EVENT_KEY_DOWN : SDL_EVENT_KEY_UP;
    event.key.windowID = window != nullptr ? SDL_GetWindowID(window) : 0;
    event.key.key = key;
    event.key.scancode = scancode;
    event.key.mod = modifiers;
    event.key.down = down;
    event.key.repeat = false;
    (void)SDL_PushEvent(&event);
  }

  [[nodiscard]] int VirtualKeyOfWord(
    const std::string& word
  )
  {
    if (word.size() == 1 && std::isalnum(static_cast<unsigned char>(word[0]))) {
      return std::toupper(static_cast<unsigned char>(word[0]));
    }
    return static_cast<int>(std::strtol(word.c_str(), nullptr, 0));
  }

  // The key window: the one of ours with the keyboard, else the main window, as the desktop would
  // give it the keyboard first.
  [[nodiscard]] SDL_Window* KeyWindow()
  {
    SDL_Window* const focus = SDL_GetKeyboardFocus();
    return focus != nullptr ? focus : MainWindow();
  }

  // A `@<win>` word after the verb names the window a key or text step goes to; else KeyWindow().
  [[nodiscard]] SDL_Window* TargetWindow(
    std::vector<std::string>& words
  )
  {
    if (words.size() > 1 && !words[1].empty() && words[1][0] == '@') {
      SDL_Window* const window = FindWindow(words[1].substr(1));
      if (window == nullptr) {
        gpg::Warnf("TESTINPUT %s: no window '%s'", words[0].c_str(), words[1].c_str());
      }
      words.erase(words.begin() + 1);
      return window;
    }
    return KeyWindow();
  }

  void RunKey(
    std::vector<std::string> words
  )
  {
    SDL_Window* const window = TargetWindow(words);
    if (words.size() < 2) {
      gpg::Warnf("TESTINPUT key: no key");
      return;
    }
    const int virtualKey = VirtualKeyOfWord(words[1]);
    unsigned int keycode = 0;
    int scancode = 0;
    if (!platform::window::sdl::KeyOfVirtualKey(virtualKey, keycode, scancode)) {
      gpg::Warnf("TESTINPUT key: no key gives virtual key 0x%X", virtualKey);
      return;
    }
    struct Modifier
    {
      const char* name;
      SDL_Keycode key;
      SDL_Scancode scancode;
      SDL_Keymod flag;
    };
    static constexpr Modifier kModifiers[] = {
      {"ctrl", SDLK_LCTRL, SDL_SCANCODE_LCTRL, SDL_KMOD_LCTRL},
      {"shift", SDLK_LSHIFT, SDL_SCANCODE_LSHIFT, SDL_KMOD_LSHIFT},
      {"alt", SDLK_LALT, SDL_SCANCODE_LALT, SDL_KMOD_LALT},
    };
    SDL_Keymod held = SDL_KMOD_NONE;
    std::vector<const Modifier*> pressed;
    for (std::size_t index = 2; index < words.size(); ++index) {
      for (const Modifier& modifier : kModifiers) {
        if (words[index] == modifier.name) {
          held = static_cast<SDL_Keymod>(held | modifier.flag);
          PushKey(window, modifier.key, modifier.scancode, held, true);
          pressed.push_back(&modifier);
        }
      }
    }
    PushKey(window, keycode, static_cast<SDL_Scancode>(scancode), held, true);
    PushKey(window, keycode, static_cast<SDL_Scancode>(scancode), held, false);
    for (auto& entry : pressed | std::views::reverse) {
      held = static_cast<SDL_Keymod>(held & ~entry->flag);
      PushKey(window, entry->key, entry->scancode, held, false);
    }
  }

  // `hold`: the keys go down in SDL's queue, and SDL's modifier state - which the mouse events'
  // modifiers are read from (WindowSdl.cpp) - holds them, re-applied each frame by Tick.
  void RunHold(
    const std::vector<std::string>& words
  )
  {
    SDL_Window* const window = KeyWindow();
    unsigned int held = sHeldModifiers.load();
    for (std::size_t index = 1; index < words.size(); ++index) {
      for (const HeldModifier& modifier : kHoldableModifiers) {
        if (words[index] == modifier.name && (held & modifier.flag) == 0u) {
          held |= modifier.flag;
          PushKey(window, modifier.key, modifier.scancode, static_cast<SDL_Keymod>(held), true);
        }
      }
    }
    sHeldModifiers = held;
    SDL_SetModState(static_cast<SDL_Keymod>(SDL_GetModState() | held));
  }

  void RunRelease()
  {
    SDL_Window* const window = KeyWindow();
    unsigned int held = sHeldModifiers.exchange(0u);
    for (const HeldModifier& modifier : kHoldableModifiers) {
      if ((held & modifier.flag) != 0u) {
        held &= ~static_cast<unsigned int>(modifier.flag);
        PushKey(window, modifier.key, modifier.scancode, static_cast<SDL_Keymod>(held), false);
        SDL_SetModState(static_cast<SDL_Keymod>(SDL_GetModState() & ~modifier.flag));
      }
    }
  }

  void RunMouse(
    const std::vector<std::string>& words
  )
  {
    const std::string& verb = words[0];
    SDL_Window* const window = words.size() > 1 ? FindWindow(words[1]) : nullptr;
    if (window == nullptr) {
      gpg::Warnf("TESTINPUT %s: no window '%s'", verb.c_str(), words.size() > 1 ? words[1].c_str() : "");
      return;
    }
    const auto number = [&words](const std::size_t index, const float fallback) {
      return index < words.size() ? static_cast<float>(std::atof(words[index].c_str())) : fallback;
    };
    float x = 0.0f;
    float y = 0.0f;
    ToPoints(window, number(2, 0.0f), number(3, 0.0f), x, y);
    // The buttons a `down` step left held, for the moves until its `up` (a drag over several frames).
    static SDL_MouseButtonFlags sHeld = 0;
    static float sLastX = 0.0f;
    static float sLastY = 0.0f;
    if (verb == "move") {
      PushMotion(window, x, y, x - sLastX, y - sLastY, sHeld);
    } else if (verb == "down" || verb == "up") {
      const Uint8 button = ButtonOf(words.size() > 4 ? words[4] : "left");
      PushMotion(window, x, y, x - sLastX, y - sLastY, sHeld);
      PushButton(window, x, y, button, verb == "down", 1);
      if (verb == "down") {
        sHeld |= SDL_BUTTON_MASK(button);
      } else {
        sHeld &= ~SDL_BUTTON_MASK(button);
      }
    } else if (verb == "click") {
      const Uint8 button = ButtonOf(words.size() > 4 ? words[4] : "left");
      const int clicks = std::max(1, static_cast<int>(number(5, 1.0f)));
      PushMotion(window, x, y, 0.0f, 0.0f, 0);
      for (int click = 1; click <= clicks; ++click) {
        PushButton(window, x, y, button, true, static_cast<Uint8>(click));
        PushButton(window, x, y, button, false, static_cast<Uint8>(click));
      }
    } else if (verb == "drag") {
      float toX = 0.0f;
      float toY = 0.0f;
      ToPoints(window, number(4, 0.0f), number(5, 0.0f), toX, toY);
      const int steps = std::max(1, static_cast<int>(number(6, 8.0f)));
      PushMotion(window, x, y, 0.0f, 0.0f, 0);
      PushButton(window, x, y, SDL_BUTTON_LEFT, true, 1);
      float lastX = x;
      float lastY = y;
      for (int step = 1; step <= steps; ++step) {
        const float t = static_cast<float>(step) / static_cast<float>(steps);
        const float stepX = x + (toX - x) * t;
        const float stepY = y + (toY - y) * t;
        PushMotion(window, stepX, stepY, stepX - lastX, stepY - lastY, SDL_BUTTON_LMASK);
        lastX = stepX;
        lastY = stepY;
      }
      PushButton(window, toX, toY, SDL_BUTTON_LEFT, false, 1);
    } else if (verb == "wheel") {
      PushMotion(window, x, y, 0.0f, 0.0f, 0);
      SDL_Event event{};
      event.type = SDL_EVENT_MOUSE_WHEEL;
      event.wheel.windowID = SDL_GetWindowID(window);
      event.wheel.y = number(4, 1.0f);
      event.wheel.direction = SDL_MOUSEWHEEL_NORMAL;
      event.wheel.mouse_x = x;
      event.wheel.mouse_y = y;
      (void)SDL_PushEvent(&event);
    }
    sLastX = x;
    sLastY = y;
    float stateX = 0.0f;
    float stateY = 0.0f;
    const SDL_MouseButtonFlags buttons = SDL_GetMouseState(&stateX, &stateY);
    gpg::Logf(
      "TESTINPUT mouse: window %u, mouse focus %u, keyboard focus %u, SDL state %.0f %.0f buttons 0x%x",
      SDL_GetWindowID(window),
      SDL_GetMouseFocus() != nullptr ? SDL_GetWindowID(SDL_GetMouseFocus()) : 0u,
      SDL_GetKeyboardFocus() != nullptr ? SDL_GetWindowID(SDL_GetKeyboardFocus()) : 0u,
      stateX,
      stateY,
      static_cast<unsigned int>(buttons)
    );
  }

  void FinishFrames(
    Script& script
  )
  {
    std::vector<double> sorted = script.frameMs;
    std::sort(sorted.begin(), sorted.end());
    double sum = 0.0;
    for (const double value : sorted) {
      sum += value;
    }
    const auto at = [&sorted](const double fraction) {
      if (sorted.empty()) {
        return 0.0;
      }
      const auto index = static_cast<std::size_t>(fraction * static_cast<double>(sorted.size() - 1));
      return sorted[index];
    };
    gpg::Logf(
      "TESTINPUT frames %s: n=%zu avg=%.3f p50=%.3f p95=%.3f p99=%.3f max=%.3f ms",
      script.framesLabel.c_str(),
      sorted.size(),
      sorted.empty() ? 0.0 : sum / static_cast<double>(sorted.size()),
      at(0.50),
      at(0.95),
      at(0.99),
      sorted.empty() ? 0.0 : sorted.back()
    );
    script.framesLeft = 0;
    script.frameMs.clear();
  }

  // Runs one step; false when the script waits before the next.
  bool RunStep(
    Script& script,
    const std::string& line
  )
  {
    const std::vector<std::string> words = Words(line);
    const std::string& verb = words[0];
    const Uint64 now = SDL_GetTicks();
    if (verb == "wait") {
      script.resumeAtMs = now + static_cast<Uint64>(words.size() > 1 ? std::atoll(words[1].c_str()) : 0);
      return false;
    }
    if (verb == "waitlog") {
      std::lock_guard<std::mutex> lock(script.waitMutex);
      script.waitText = Rest(line);
      script.waitSeen = false;
      script.waitDeadlineMs = now + kWaitLogTimeoutMs;
      return false;
    }
    if (verb == "key") {
      RunKey(words);
    } else if (verb == "hold") {
      RunHold(words);
    } else if (verb == "release") {
      RunRelease();
    } else if (verb == "text") {
      std::vector<std::string> target = words;
      SDL_Window* const window = TargetWindow(target);
      std::string text = Rest(line);
      if (target.size() < words.size()) {
        text = Rest(text); // after the @<win> word
      }
      script.texts.push_back(text);
      SDL_Event event{};
      event.type = SDL_EVENT_TEXT_INPUT;
      event.text.windowID = window != nullptr ? SDL_GetWindowID(window) : 0;
      event.text.text = script.texts.back().c_str();
      (void)SDL_PushEvent(&event);
    } else if (
      verb == "move" || verb == "down" || verb == "up" || verb == "click" || verb == "drag" || verb == "wheel"
    ) {
      RunMouse(words);
    } else if (verb == "con") {
      if (script.runCommand != nullptr) {
        script.runCommand(Rest(line).c_str());
      }
    } else if (verb == "clipsave") {
      SaveClipboard(script);
    } else if (verb == "clip") {
      SaveClipboard(script);
      (void)SDL_SetClipboardText(Rest(line).c_str());
    } else if (verb == "getclip") {
      char* const text = SDL_GetClipboardText();
      gpg::Logf("TESTINPUT clip: %s", text != nullptr ? text : "");
      SDL_free(text);
    } else if (verb == "pick") {
      const std::string answer = Rest(line);
      platform::window::sdl::AnswerNextFolderPick(answer != "cancel", answer.c_str());
    } else if (verb == "frames") {
      script.framesLabel = words.size() > 1 ? words[1] : "frames";
      script.framesLeft = words.size() > 2 ? std::atoi(words[2].c_str()) : 300;
      script.frameMs.clear();
      script.lastFrameNs = 0;
      return false; // the next steps wait for the measurement
    } else if (verb == "close") {
      SDL_Window* const window = words.size() > 1 ? FindWindow(words[1]) : MainWindow();
      SDL_Event event{};
      event.type = SDL_EVENT_WINDOW_CLOSE_REQUESTED;
      event.window.windowID = window != nullptr ? SDL_GetWindowID(window) : 0;
      (void)SDL_PushEvent(&event);
    } else if (verb == "log") {
      gpg::Logf("TESTINPUT note: %s", Rest(line).c_str());
    } else {
      gpg::Warnf("TESTINPUT: unknown step '%s'", verb.c_str());
    }
    return true;
  }
} // namespace

namespace platform::window::test
{
  bool Start(
    const char* const utf8Path,
    const CommandRunner runCommand
  )
  {
    std::ifstream file(utf8Path, std::ios::binary);
    if (!file) {
      gpg::Warnf("TESTINPUT: can't read %s", utf8Path);
      return false;
    }
    Script& script = TheScript();
    std::string line;
    while (std::getline(file, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      const std::size_t first = line.find_first_not_of(" \t");
      if (first == std::string::npos || line[first] == '#') {
        continue;
      }
      script.lines.push_back(line.substr(first));
    }
    script.runCommand = runCommand;
    script.active = true;
    gpg::Logf("TESTINPUT: %zu steps from %s", script.lines.size(), utf8Path);
    return true;
  }

  bool IsActive()
  {
    return TheScript().active;
  }

  void Tick()
  {
    Script& script = TheScript();
    if (!script.active) {
      return;
    }
    if (const unsigned int held = sHeldModifiers.load(); held != 0u) {
      SDL_SetModState(static_cast<SDL_Keymod>(SDL_GetModState() | held));
    }
    if (script.framesLeft > 0) {
      const Uint64 nowNs = SDL_GetTicksNS();
      if (script.lastFrameNs != 0) {
        script.frameMs.push_back(static_cast<double>(nowNs - script.lastFrameNs) / 1.0e6);
        if (--script.framesLeft == 0) {
          FinishFrames(script);
        }
      }
      script.lastFrameNs = nowNs;
      if (script.framesLeft > 0) {
        return;
      }
    }
    const Uint64 now = SDL_GetTicks();
    {
      std::lock_guard<std::mutex> lock(script.waitMutex);
      if (!script.waitText.empty()) {
        if (script.waitSeen) {
          script.waitText.clear();
        } else if (now >= script.waitDeadlineMs) {
          gpg::Warnf("TESTINPUT timeout waiting for '%s'", script.waitText.c_str());
          script.waitText.clear();
        } else {
          return;
        }
      }
    }
    if (now < script.resumeAtMs) {
      return;
    }
    while (script.next < script.lines.size()) {
      const std::string line = script.lines[script.next];
      ++script.next;
      gpg::Logf("TESTINPUT %zu: %s", script.next, line.c_str());
      if (!RunStep(script, line)) {
        return;
      }
      // A step can hold the thread (a console command stopped at a breakpoint) while the later steps
      // run from the debugger's loop; a wait one of them began holds here too.
      if (SDL_GetTicks() < script.resumeAtMs || script.framesLeft > 0) {
        return;
      }
      {
        std::lock_guard<std::mutex> lock(script.waitMutex);
        if (!script.waitText.empty()) {
          return;
        }
      }
    }
    if (script.next >= script.lines.size() && script.framesLeft == 0) {
      if (script.clipboardSaved) {
        (void)SDL_SetClipboardText(script.savedClipboard.c_str());
        script.clipboardSaved = false;
      }
      RunRelease();
      gpg::Logf("TESTINPUT: done");
      script.active = false;
    }
  }

  bool GetScriptMouseScreenPosition(
    int& x,
    int& y
  )
  {
    if (!sScriptMouse.load(std::memory_order_relaxed) || !TheScript().active) {
      return false;
    }
    SDL_Window* const window = SDL_GetMouseFocus();
    if (window == nullptr) {
      return false;
    }
    float mouseX = 0.0f;
    float mouseY = 0.0f;
    (void)SDL_GetMouseState(&mouseX, &mouseY);
    int windowX = 0;
    int windowY = 0;
    if (!SDL_GetWindowPosition(window, &windowX, &windowY)) {
      return false;
    }
    const float density = SDL_GetWindowPixelDensity(window);
    const float scale = density > 0.0f ? density : 1.0f;
    x = static_cast<int>(std::floor((static_cast<float>(windowX) + mouseX) * scale));
    y = static_cast<int>(std::floor((static_cast<float>(windowY) + mouseY) * scale));
    return true;
  }

  bool IsModifierHeld(
    const int virtualKey
  )
  {
    const unsigned int held = sHeldModifiers.load(std::memory_order_relaxed);
    if (held == 0u) {
      return false;
    }
    switch (virtualKey) {
    case 0x10: // VK_SHIFT
    case 0xA0: // VK_LSHIFT
    case 0xA1: // VK_RSHIFT
      return (held & SDL_KMOD_SHIFT) != 0u;
    case 0x11: // VK_CONTROL
    case 0xA2: // VK_LCONTROL
    case 0xA3: // VK_RCONTROL
      return (held & SDL_KMOD_CTRL) != 0u;
    case 0x12: // VK_MENU
    case 0xA4: // VK_LMENU
    case 0xA5: // VK_RMENU
      return (held & SDL_KMOD_ALT) != 0u;
    default:
      return false;
    }
  }

  void NoteLogLine(
    const char* const utf8Line
  )
  {
    Script& script = TheScript();
    if (!script.active || utf8Line == nullptr || std::strncmp(utf8Line, "TESTINPUT", 9) == 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(script.waitMutex);
    if (!script.waitText.empty() && std::strstr(utf8Line, script.waitText.c_str()) != nullptr) {
      script.waitSeen = true;
    }
  }
} // namespace platform::window::test
