#include "moho/app/ResolutionCommands.h"

#include <Windows.h>

#include <cstdint>
#include <cstdlib>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"

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
  moho::CConFunc gCConFunc_SC_PrimaryAdapter{};

  /// 0x00E00779 (the same shared empty-string literal `SC_PrimaryAdapter`
  /// uses), the `.data` initializer of `Moho::CConFunc_SC_VerticalSync`
  /// (+0x08). No console-help text in the binary.
  constexpr const char* kConsoleStartupSCVerticalSyncDescription = "";
  moho::CConFunc gCConFunc_SC_VerticalSync{};

  /// 0x00E4F1E0, the `.data` initializer of `Moho::CConFunc_SC_ToggleCursorClip`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCToggleCursorClipDescription =
    "Set the cursor clip to either the pre-launch clip or the current clip";
  moho::CConFunc gCConFunc_SC_ToggleCursorClip{};

  /// 0x00E00779 (the same shared empty-string literal `SC_PrimaryAdapter`
  /// uses), the `.data` initializer of `Moho::CConFunc_SC_SecondaryAdapter`
  /// (+0x08). No console-help text in the binary.
  constexpr const char* kConsoleStartupSCSecondaryAdapterDescription = "";
  moho::CConFunc gCConFunc_SC_SecondaryAdapter{};

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
  constexpr const char* kLockFullscreenCursorOptionKey = "lock_fullscreen_cursor_to_window";
} // namespace

namespace moho
{
  void SC_PrimaryAdapter(void* const commandArgs)
  {
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

    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    const msvc8::string* const valueToken = args.At(1);

    // `overridden` is a sentinel meaning some other path already applied an
    // explicit resolution override; this invocation is then a no-op beyond
    // the device-lock toggle.
    if (args.Count() == 2u && valueToken != nullptr && valueToken->view() != "overridden") {
      auto* const mainWindow = reinterpret_cast<WD3DViewport*>(sMainWindow);

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
        mainWindow->D3DWindowOnDeviceInit(false);

        // 0x008D369D-0x008D36AA: parses `valueToken` as a `width,height,fps`
        // CSV triple (`Resolution::Resolution(const std::string&)` /
        // `CFG_ParseResolutionTriple`, both 0x008CD6C0).
        ResolutionTriple parsedResolution{};
        (void)CFG_ParseResolutionTriple(valueToken->c_str(), &parsedResolution);
        head.mWidth = static_cast<std::uint32_t>(parsedResolution.width);
        head.mHeight = static_cast<std::uint32_t>(parsedResolution.height);
        head.framesPerSecond = static_cast<std::uint32_t>(parsedResolution.framesPerSecond);
      } else {
        mainWindow->SetWindowStyleFlag(kBorderedAdapterStyle);

        IUserPrefs* const preferences = USER_GetPreferences();
        head.mWidth = static_cast<std::uint32_t>(preferences->GetInteger(
          msvc8::string(kPreviousWidthPrefKey), static_cast<std::int32_t>(wnd_DefaultCreateWidth)
        ));
        head.mHeight = static_cast<std::uint32_t>(preferences->GetInteger(
          msvc8::string(kPreviousHeightPrefKey), static_cast<std::int32_t>(wnd_DefaultCreateHeight)
        ));
        head.framesPerSecond = 0;

        const HWND windowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(mainWindow->GetHandle()));
        ::SetWindowPos(windowHandle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
      }

      mainWindow->DoSetClientSize(static_cast<std::int32_t>(head.mWidth), static_cast<std::int32_t>(head.mHeight));
      mainWindow->Refresh(true, nullptr);
      ren_Viewport->DoSetSize(
        -1, -1, static_cast<std::int32_t>(head.mWidth), static_cast<std::int32_t>(head.mHeight), 0
      );

      device->Clear();
      (void)device->InitContext(&deviceContext);

      if (deviceContext.GetHeadCount() == 1 && head.mWindowed
          && OPTIONS_GetInt(kLockFullscreenCursorOptionKey) == 1) {
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
   * Address: 0x00C08D30 (FUN_00C08D30, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_PrimaryAdapter`.
   */
  void cleanup_CConFunc_SC_PrimaryAdapter()
  {
    CleanupStartupConCommand(gCConFunc_SC_PrimaryAdapter);
  }

  void register_CConFunc_SC_PrimaryAdapter()
  {
    gCConFunc_SC_PrimaryAdapter.InitializeRecovered(
      kConsoleStartupSCPrimaryAdapterDescription, "SC_PrimaryAdapter", &moho::SC_PrimaryAdapter
    );
    (void)std::atexit(&cleanup_CConFunc_SC_PrimaryAdapter);
  }

  /**
   * Address: 0x008D3BE0 (FUN_008D3BE0, sub_8D3BE0)
   *
   * What it does:
   * See header. The binary's `atoi(args[1])==1` parse (0x008D3C67) has no
   * side effects and its result is never read again, so it is omitted here;
   * the observable behavior - an unconditional device-context reset gated
   * only on argument *count* - is preserved exactly. Mirrors
   * `SC_PrimaryAdapter`'s device-context-copy/`sDeviceLock`/`Clear`+
   * `InitContext` idiom above; unlike that command, `deviceInstance` here is
   * also never null-checked by the binary before the initial
   * `GetDeviceContext()` dereference, matching what this recovery keeps.
   */
  void SC_VerticalSync(void* const commandArgs)
  {
    gpg::gal::Device* const deviceInstance = gpg::gal::Device::GetInstance();
    CD3DDevice* const device = D3D_GetDevice();
    gpg::gal::DeviceContext deviceContext(*deviceInstance->GetDeviceContext());

    sDeviceLock = true;

    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() == 2u) {
      device->Clear();
      (void)device->InitContext(&deviceContext);
    }

    sDeviceLock = false;
  }

  /**
   * Address: 0x00C08DF0 (FUN_00C08DF0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_VerticalSync`.
   */
  void cleanup_CConFunc_SC_VerticalSync()
  {
    CleanupStartupConCommand(gCConFunc_SC_VerticalSync);
  }

  void register_CConFunc_SC_VerticalSync()
  {
    gCConFunc_SC_VerticalSync.InitializeRecovered(
      kConsoleStartupSCVerticalSyncDescription, "SC_VerticalSync", &moho::SC_VerticalSync
    );
    (void)std::atexit(&cleanup_CConFunc_SC_VerticalSync);
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
  void SC_ToggleCursorClip(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() > 2u) {
      return;
    }

    const msvc8::string* const modeToken = args.At(1u);
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
   * Address: 0x00C08EE0 (FUN_00C08EE0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_ToggleCursorClip`.
   */
  void cleanup_CConFunc_SC_ToggleCursorClip()
  {
    CleanupStartupConCommand(gCConFunc_SC_ToggleCursorClip);
  }

  void register_CConFunc_SC_ToggleCursorClip()
  {
    gCConFunc_SC_ToggleCursorClip.InitializeRecovered(
      kConsoleStartupSCToggleCursorClipDescription, "SC_ToggleCursorClip", &moho::SC_ToggleCursorClip
    );
    (void)std::atexit(&cleanup_CConFunc_SC_ToggleCursorClip);
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
  void SC_SecondaryAdapter(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() != 2u) {
      return;
    }

    const msvc8::string* const modeToken = args.At(1u);
    const bool adapterNotCommandLineOverridden = modeToken != nullptr && modeToken->view() == "true";
    SetupSecondaryAdapterSettings(adapterNotCommandLineOverridden);
  }

  /**
   * Address: 0x00C08D60 (FUN_00C08D60, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_SecondaryAdapter`.
   */
  void cleanup_CConFunc_SC_SecondaryAdapter()
  {
    CleanupStartupConCommand(gCConFunc_SC_SecondaryAdapter);
  }

  void register_CConFunc_SC_SecondaryAdapter()
  {
    gCConFunc_SC_SecondaryAdapter.InitializeRecovered(
      kConsoleStartupSCSecondaryAdapterDescription, "SC_SecondaryAdapter", &moho::SC_SecondaryAdapter
    );
    (void)std::atexit(&cleanup_CConFunc_SC_SecondaryAdapter);
  }
} // namespace moho

namespace
{
  // The binary runs this registrar from the CRT static-initializer array; a
  // file-scope bootstrap object reproduces that, matching
  // `FrameDumpConsoleRegistrations` in FrameDumpCommands.cpp.
  struct ResolutionConsoleRegistrations
  {
    ResolutionConsoleRegistrations()
    {
      moho::register_CConFunc_SC_PrimaryAdapter();
      moho::register_CConFunc_SC_VerticalSync();
      moho::register_CConFunc_SC_ToggleCursorClip();
      moho::register_CConFunc_SC_SecondaryAdapter();
    }
  };

  [[maybe_unused]] ResolutionConsoleRegistrations gResolutionConsoleRegistrations;
} // namespace
