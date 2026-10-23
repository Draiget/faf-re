#pragma once

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  /**
   * Address: 0x008D34D0 (FUN_008D34D0)
   *
   * IDA signature:
   * int __cdecl sub_8D34D0(int commandArgs);
   *
   * What it does:
   * `SC_PrimaryAdapter` console command. With exactly one argument that is
   * not the literal `overridden` sentinel, re-applies the primary render
   * adapter's window style, size, and cursor-clip state:
   *   - argument equals `windowed` exactly: restores the bordered/resizable
   *     window style (`wxCAPTION|wxCLIP_CHILDREN|wxSYSTEM_MENU|
   *     wxMINIMIZE_BOX|wxMAXIMIZE_BOX|wxRESIZE_BORDER`, 0x20400E40) and the
   *     size last saved to `Windows.Main.Previous.width`/`.height` in user
   *     prefs.
   *   - any other argument: applies the borderless adapter style
   *     (`wxBORDER_NONE|wxSYSTEM_MENU`, 0x200800) and parses the argument
   *     itself as a `width,height,fps` resolution triple
   *     (`CFG_ParseResolutionTriple`).
   * Either way it resizes `sMainWindow`/`ren_Viewport` to match, resets the
   * D3D device context, and - only when the argument was *not* literally
   * `windowed` and `lock_fullscreen_cursor_to_window` is enabled - clips the
   * OS cursor to the window rect; otherwise the clip is released.
   *
   * `sDeviceLock` is held for the duration so device-context readers never
   * observe a half-updated head while the resize is in flight.
   */
  void SC_PrimaryAdapter(const msvc8::vector<msvc8::string>& args);


  /**
   * Address: 0x008D3BE0 (FUN_008D3BE0)
   *
   * IDA signature:
   * int __cdecl sub_8D3BE0(int commandArgs);
   *
   * What it does:
   * `SC_VerticalSync` console command. Unconditionally resets the primary
   * D3D device context (`CD3DDevice::Clear()` + `InitContext()`) while
   * `sDeviceLock` is held, whenever exactly one argument is present. The
   * binary parses that argument via `atoi(...)==1` but never reads the
   * parsed value afterward - the reset is gated only on argument *count*,
   * not on what the argument says.
   */
  void SC_VerticalSync(const msvc8::vector<msvc8::string>& args);


  /**
   * Address: 0x008D41B0 (FUN_008D41B0)
   *
   * IDA signature:
   * unsigned int __cdecl sub_8D41B0(int commandArgs);
   *
   * What it does:
   * `SC_ToggleCursorClip [0]` console command. With at most one argument:
   * argument literally `"0"` releases the OS cursor clip
   * (`ClipCursor(nullptr)`); any other argument (or none) clips the cursor
   * to the primary window's rect, but only when the device instance exists,
   * has exactly one head, and that head is windowed - otherwise this is a
   * no-op. More than one argument is a no-op.
   */
  void SC_ToggleCursorClip(const msvc8::vector<msvc8::string>& args);


  /**
   * Address: 0x008D37C0 (FUN_008D37C0)
   *
   * IDA signature:
   * int __cdecl sub_8D37C0(int commandArgs);
   *
   * What it does:
   * `SC_SecondaryAdapter <true|...>` console command. With exactly one
   * argument, forwards `argument == "true"` to the already-recovered
   * `SetupSecondaryAdapterSettings(bool adapterNotCommandLineOverridden)`
   * (StartupHelpers.cpp), which republishes the secondary-adapter Lua
   * options-menu state.
   */
  void SC_SecondaryAdapter(const msvc8::vector<msvc8::string>& args);

} // namespace moho
