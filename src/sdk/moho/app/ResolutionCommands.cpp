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
} // namespace moho

namespace
{
  // The binary runs this registrar from the CRT static-initializer array; a
  // file-scope bootstrap object reproduces that, matching
  // `FrameDumpConsoleRegistrations` in FrameDumpCommands.cpp.
  struct ResolutionConsoleRegistrations
  {
    ResolutionConsoleRegistrations() { moho::register_CConFunc_SC_PrimaryAdapter(); }
  };

  [[maybe_unused]] ResolutionConsoleRegistrations gResolutionConsoleRegistrations;
} // namespace
