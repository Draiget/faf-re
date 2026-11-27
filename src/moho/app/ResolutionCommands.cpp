#include "moho/app/ResolutionCommands.h"

#include <Windows.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>

#include "gpg/gal/Device.hpp"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/app/CScApp.h"
#include "moho/app/AppRuntimeTypes.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/WRenViewport.h"
#include "platform/Window.h"
#include "platform/shell/gdicmn.h"
#include "platform/shell/toplevel.h"

namespace
{
  /// 0x00E00779, the `.data` initializer of `Moho::CConFunc_SC_PrimaryAdapter`
  /// (+0x08). This startup command carries no console-help text in the
  /// binary.
  constexpr const char* kConsoleStartupSCPrimaryAdapterDescription = "";

  // 0x00F5BE50. The registrar below only patches the vftable and the
  // `mFunc` slot at +0x0C; the name and (empty) description lanes are
  // `.data` initializers, matching the pattern already established for the
  // `dump_Frames`/`dump_Frame` registrars in FrameDumpCommands.cpp.
  /**
   * Address: 0x00BE9480 (FUN_00BE9480, dynamic initializer for `gCConFunc_SC_PrimaryAdapter`)
   * Address: 0x00C08D30 (FUN_00C08D30, dynamic atexit destructor for `gCConFunc_SC_PrimaryAdapter`)
   */
  moho::CConFunc gCConFunc_SC_PrimaryAdapter(
    "SC_PrimaryAdapter",
    kConsoleStartupSCPrimaryAdapterDescription,
    &moho::SC_PrimaryAdapter
  );

  /// 0x00E00779 (the same shared empty-string literal `SC_PrimaryAdapter`
  /// uses), the `.data` initializer of `Moho::CConFunc_SC_VerticalSync`
  /// (+0x08). No console-help text in the binary.
  constexpr const char* kConsoleStartupSCVerticalSyncDescription = "";

  /**
   * Address: 0x00BE9580 (FUN_00BE9580, dynamic initializer for `gCConFunc_SC_VerticalSync`)
   * Address: 0x00C08DF0 (FUN_00C08DF0, dynamic atexit destructor for `gCConFunc_SC_VerticalSync`)
   */
  moho::CConFunc
    gCConFunc_SC_VerticalSync("SC_VerticalSync", kConsoleStartupSCVerticalSyncDescription, &moho::SC_VerticalSync);

  /// 0x00E4F1E0, the `.data` initializer of `Moho::CConFunc_SC_ToggleCursorClip`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCToggleCursorClipDescription =
    "Set the cursor clip to either the pre-launch clip or the current clip";

  /**
   * Address: 0x00BE96C0 (FUN_00BE96C0, dynamic initializer for `gCConFunc_SC_ToggleCursorClip`)
   * Address: 0x00C08EE0 (FUN_00C08EE0, dynamic atexit destructor for `gCConFunc_SC_ToggleCursorClip`)
   */
  moho::CConFunc gCConFunc_SC_ToggleCursorClip(
    "SC_ToggleCursorClip",
    kConsoleStartupSCToggleCursorClipDescription,
    &moho::SC_ToggleCursorClip
  );

  /// 0x00E00779 (the same shared empty-string literal `SC_PrimaryAdapter`
  /// uses), the `.data` initializer of `Moho::CConFunc_SC_SecondaryAdapter`
  /// (+0x08). No console-help text in the binary.
  constexpr const char* kConsoleStartupSCSecondaryAdapterDescription = "";

  /**
   * Address: 0x00BE94C0 (FUN_00BE94C0, dynamic initializer for `gCConFunc_SC_SecondaryAdapter`)
   * Address: 0x00C08D60 (FUN_00C08D60, dynamic atexit destructor for `gCConFunc_SC_SecondaryAdapter`)
   */
  moho::CConFunc gCConFunc_SC_SecondaryAdapter(
    "SC_SecondaryAdapter",
    kConsoleStartupSCSecondaryAdapterDescription,
    &moho::SC_SecondaryAdapter
  );

  /// Style bits observed at the "argument is literally `windowed`" branch's
  /// `SetWindowStyleFlag` call site (0x008D35DB): decodes to
  /// `wxCAPTION | wxCLIP_CHILDREN | wxSYSTEM_MENU | wxMINIMIZE_BOX |
  /// wxMAXIMIZE_BOX | wxRESIZE_BORDER` - a real bordered, resizable frame.
  constexpr long kBorderedAdapterStyle = 0x20400E40;

  /// Style bits observed at the "argument is anything else" branch's
  /// `SetWindowStyleFlag` call site (0x008D367F): decodes to
  /// `wxBORDER_NONE | wxSYSTEM_MENU` - a borderless popup-style frame used
  /// for an explicit `width,height,fps` resolution request.
  constexpr long kBorderlessAdapterStyle = 0x200800;

  constexpr const char* kPreviousWidthPrefKey = "Windows.Main.Previous.width";
  constexpr const char* kPreviousHeightPrefKey = "Windows.Main.Previous.height";
  constexpr const char* kSupComFrameXPreferenceKey = "Windows.Main.x";
  constexpr const char* kSupComFrameYPreferenceKey = "Windows.Main.y";
  constexpr const char* kSupComFrameWidthPreferenceKey = "Windows.Main.width";
  constexpr const char* kSupComFrameHeightPreferenceKey = "Windows.Main.height";
  constexpr const char* kLockFullscreenCursorOptionKey = "lock_fullscreen_cursor_to_window";
} // namespace

namespace moho
{
  /**
   * Address: 0x008D34D0 (FUN_008D34D0, sub_8D34D0)
   *
   * Handles the `primary_adapter` console command (display resolution / fullscreen / windowed mode switch).
   */
  void SC_PrimaryAdapter(
    const fa::vector<fa::string>& args
  )
  {
    // Engine addition (moho::gAppWindowed): the map editor keeps its own window; the game's display
    // option (Options, Video, primary adapter) would make it a borderless or fixed-size frame.
    if (gAppWindowed) {
      gpg::Logf("SC_PrimaryAdapter: the map editor keeps its window");
      return;
    }

    gpg::gal::Device* const deviceInstance = gpg::gal::Device::GetInstance();
    CD3DDevice* const device = D3D_GetDevice();

    // 0x008D34F1-0x008D3510: the binary calls `GetDeviceContext()` purely to
    // feed its return value into the `DeviceContext` copy constructor
    // (0x00430480) below - `deviceContext` is a local snapshot of the live
    // device-context state, matching `gpg::gal::DeviceContext(const
    // DeviceContext&)`'s documented address.
    gpg::gal::DeviceContext deviceContext(*deviceInstance->GetDeviceContext());
    gpg::gal::Head& head = deviceContext.GetHead(0);

    sDeviceLock = true;

    const fa::string* const valueToken = ConCommandArg(args, 1);

    // `overridden` is a sentinel meaning some other path already applied an
    // explicit resolution override; this invocation is then a no-op beyond
    // the device-lock toggle.
    if (args.size() == 2u && valueToken != nullptr && valueToken->view() != "overridden") {
      // The main window is the SupCom frame: slot 131 below is
      // TopLevelWindowMSW::Maximize, not a viewport hook.
      ShellTopLevelWindow* const mainWindow = static_cast<ShellTopLevelWindow*>(sMainWindow);

      // 0x008D35AA-0x008D35B4: `head.mWindowed` is set from the *inverse* of
      // the "argument equals `windowed`" test, and it is reused with that
      // same polarity for the cursor-clip gate near the end of this
      // function (0x008D374B). That is the binary's own behavior, not a
      // recovery inversion: a literal `windowed` argument restores the
      // previously-saved bordered window (no cursor clip needed - it is not
      // covering the whole screen), while any other argument goes to the
      // borderless "fullscreen-styled" adapter mode that `mWindowed` here
      // actually flags, which is exactly when
      // `lock_fullscreen_cursor_to_window` (below) is meaningful.
      head.mWindowed = (valueToken->view() != "windowed");
      head.mWidth = static_cast<std::uint32_t>(wnd_DefaultCreateWidth);
      head.mHeight = static_cast<std::uint32_t>(wnd_DefaultCreateHeight);

      if (head.mWindowed) {
        mainWindow->SetWindowStyleFlag(kBorderlessAdapterStyle);
        mainWindow->Maximize(false);

        // 0x008D369D-0x008D36AA: parses `valueToken` as a `width,height,fps`
        // CSV triple (`Resolution::Resolution(const std::string&)` /
        // `CFG_ParseResolutionTriple`, both 0x008CD6C0).
        ResolutionTriple parsedResolution{};
        (void)CFG_ParseResolutionTriple(valueToken->c_str(), &parsedResolution);
        head.mWidth = static_cast<std::uint32_t>(parsedResolution.width);
        head.mHeight = static_cast<std::uint32_t>(parsedResolution.height);
        head.framesPerSecond = static_cast<std::uint32_t>(parsedResolution.framesPerSecond);

        // Engine change (issue #505): a resolution below the display's own switches the display to it, as
        // the binary's Direct3D 9 exclusive full screen did, and the window covers the display. The flip
        // swap chains of Direct3D 12 and Vulkan never change the mode, so the frame was left a small
        // borderless window in the display's corner. At the display's own size the window covers it as is.
        // Two heads keep the borderless frames: a window with a mode of its own is minimised when the
        // other one takes the keyboard.
        const bool ownMode = deviceContext.GetHeadCount() == 1 &&
          platform::window::SetFullscreenMode(
                               mainWindow->GetPlatformWindow(),
                               static_cast<int>(head.mWidth),
                               static_cast<int>(head.mHeight),
                               static_cast<int>(head.framesPerSecond)
          );

        // Engine addition: position fullscreen window on the monitor containing the window. Asked after
        // the mode call: leaving a mode of its own can move the displays.
        const HWND windowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(mainWindow->GetHandle()));
        if (!ownMode) {
          int monitorX = 0;
          int monitorY = 0;
          if (windowHandle != nullptr) {
            const HMONITOR monitor = ::MonitorFromWindow(windowHandle, MONITOR_DEFAULTTONEAREST);
            MONITORINFO monitorInfo{};
            monitorInfo.cbSize = sizeof(monitorInfo);
            if (monitor != nullptr && ::GetMonitorInfoW(monitor, &monitorInfo) != FALSE) {
              monitorX = static_cast<int>(monitorInfo.rcMonitor.left);
              monitorY = static_cast<int>(monitorInfo.rcMonitor.top);
            }
          }
          mainWindow->SetSize(monitorX, monitorY, static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));
          if (windowHandle != nullptr) {
            ::SetWindowPos(windowHandle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED);
          }
        }
      } else {
        // Engine change (issue #505): give the display its desktop mode back before the frame gets its border.
        platform::window::SetFullscreen(mainWindow->GetPlatformWindow(), false);
        mainWindow->SetWindowStyleFlag(kBorderedAdapterStyle);

        IUserPrefs* const preferences = USER_GetPreferences();
        const std::int32_t defaultWidth = static_cast<std::int32_t>(wnd_DefaultCreateWidth);
        const std::int32_t defaultHeight = static_cast<std::int32_t>(wnd_DefaultCreateHeight);
        std::int32_t savedWidth = defaultWidth;
        std::int32_t savedHeight = defaultHeight;
        if (preferences != nullptr) {
          savedWidth = preferences->GetInteger(
            fa::string(kPreviousWidthPrefKey),
            preferences->GetInteger(fa::string(kSupComFrameWidthPreferenceKey), defaultWidth)
          );
          savedHeight = preferences->GetInteger(
            fa::string(kPreviousHeightPrefKey),
            preferences->GetInteger(fa::string(kSupComFrameHeightPreferenceKey), defaultHeight)
          );
        }
        head.mWidth = static_cast<std::uint32_t>(savedWidth);
        head.mHeight = static_cast<std::uint32_t>(savedHeight);
        head.framesPerSecond = 0;

        // Engine addition: restore and clamp window position when returning to windowed mode.
        int posX = INT_MIN;
        int posY = INT_MIN;
        if (preferences != nullptr) {
          posX = preferences->GetInteger(fa::string(kSupComFrameXPreferenceKey), INT_MIN);
          posY = preferences->GetInteger(fa::string(kSupComFrameYPreferenceKey), INT_MIN);
        }

        const HWND windowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(mainWindow->GetHandle()));
        if (posX != INT_MIN && posY != INT_MIN) {
          ShellPoint pos(posX, posY);
          moho::ClampPositionToMonitor(&pos, head.mWidth, head.mHeight);
          mainWindow->SetSize(pos.x, pos.y, static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));
        } else {
          mainWindow->SetClientSize(static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));
        }
        if (windowHandle != nullptr) {
          ::SetWindowPos(windowHandle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED);
        }
      }

      mainWindow->Refresh(true, nullptr);
      ren_Viewport->SetSize(
        -1, -1, static_cast<int>(head.mWidth), static_cast<int>(head.mHeight), SHELL_SIZE_USE_EXISTING
      );

      device->Clear();
      (void)device->InitContext(&deviceContext);

      if (deviceContext.GetHeadCount() == 1 && head.mWindowed && OPTIONS_GetInt(kLockFullscreenCursorOptionKey) == 1) {
        const HWND windowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(mainWindow->GetHandle()));
        RECT windowRect{};
        ::GetWindowRect(windowHandle, &windowRect);
        ::ClipCursor(&windowRect);
      } else {
        ::ClipCursor(nullptr);
      }
    }

    sDeviceLock = false;
  }

  /**
   * Address: 0x008D3BE0 (FUN_008D3BE0, sub_8D3BE0)
   *
   * What it does:
   * See header. The `atoi(args[1]) == 1` result (0x008D3C60-0x008D3C6E) is
   * stored to `[esp+0x18]`, which is +0x10 of the context copy at
   * `[esp+0x08]`: `mVSync`. Mirrors `SC_PrimaryAdapter`'s
   * device-context-copy/`sDeviceLock`/`Clear`+`InitContext` idiom above;
   * unlike that command, `deviceInstance` here is also never null-checked by
   * the binary before the initial `GetDeviceContext()` dereference, matching
   * what this recovery keeps.
   */
  void SC_VerticalSync(
    const fa::vector<fa::string>& args
  )
  {
    gpg::gal::Device* const deviceInstance = gpg::gal::Device::GetInstance();
    CD3DDevice* const device = D3D_GetDevice();
    gpg::gal::DeviceContext deviceContext(*deviceInstance->GetDeviceContext());

    sDeviceLock = true;

    if (args.size() == 2u) {
      deviceContext.mVSync = std::atoi(args[1].c_str()) == 1;
      device->Clear();
      (void)device->InitContext(&deviceContext);
    }

    sDeviceLock = false;
  }

  /**
   * Address: 0x008D41B0 (FUN_008D41B0, sub_8D41B0)
   *
   * What it does:
   * See header. The binary's real comparison (Hex-Rays mis-renders it as a
   * bogus `std::operator<<char>` call) is
   * `args[1].compare(0, args[1].size(), "0", 1) == 0`, i.e. `*args[1] ==
   * "0"`; equal releases the clip, anything else attempts to clip to the
   * primary window's rect under the guards described in the header.
   */
  void SC_ToggleCursorClip(
    const fa::vector<fa::string>& args
  )
  {
    if (args.size() > 2u) {
      return;
    }

    const fa::string* const modeToken = ConCommandArg(args, 1u);
    if (modeToken != nullptr && modeToken->view() == "0") {
      ::ClipCursor(nullptr);
      return;
    }

    gpg::gal::Device* const deviceInstance = gpg::gal::Device::GetInstance();
    if (deviceInstance == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const deviceContext = deviceInstance->GetDeviceContext();
    if (deviceContext == nullptr || deviceContext->GetHeadCount() != 1) {
      return;
    }

    const gpg::gal::Head& head = deviceContext->GetHead(0);
    if (!head.mWindowed) {
      return;
    }

    const HWND windowHandle = static_cast<HWND>(head.mHandle);
    RECT windowRect{};
    ::GetWindowRect(windowHandle, &windowRect);
    ::ClipCursor(&windowRect);
  }

  /**
   * Address: 0x008D37C0 (FUN_008D37C0, sub_8D37C0)
   *
   * What it does:
   * See header. The binary's real comparison (Hex-Rays mis-renders it as a
   * bogus `std::operator<<char>` call) is
   * `args[1].compare(0, args[1].size(), "true", 4) == 0`, i.e. `*args[1] ==
   * "true"`.
   */
  void SC_SecondaryAdapter(
    const fa::vector<fa::string>& args
  )
  {
    if (args.size() != 2u) {
      return;
    }

    const fa::string* const modeToken = ConCommandArg(args, 1u);
    const bool adapterNotCommandLineOverridden = modeToken != nullptr && modeToken->view() == "true";
    SetupSecondaryAdapterSettings(adapterNotCommandLineOverridden);
  }

} // namespace moho

namespace
{
  // The binary runs this registrar from the CRT static-initializer array; a
  // file-scope bootstrap object reproduces that, matching
  // `FrameDumpConsoleRegistrations` in FrameDumpCommands.cpp.
} // namespace
