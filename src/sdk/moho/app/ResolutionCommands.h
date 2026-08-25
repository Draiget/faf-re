#pragma once

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
  void SC_PrimaryAdapter(void* commandArgs);

  /**
   * Address: 0x00BE9480 (FUN_00BE9480, register_CConFunc_SC_PrimaryAdapter)
   *
   * What it does:
   * Registers the `SC_PrimaryAdapter` startup console command and installs
   * its process-exit teardown. The store
   * `Moho__CConFunc_SC_PrimaryAdapter.mFunc = offset Moho__SC_PrimaryAdapter`
   * at 0x00BE94A0 is the only reference to `SC_PrimaryAdapter` in the image.
   */
  void register_CConFunc_SC_PrimaryAdapter();

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
  void SC_VerticalSync(void* commandArgs);

  /**
   * Address: 0x00BE9580 (FUN_00BE9580, register_CConFunc_SC_VerticalSync)
   *
   * What it does:
   * Registers the `SC_VerticalSync` startup console command and installs its
   * process-exit teardown. The store
   * `dword_F5BE9C = offset sub_8D3BE0` at 0x00BE958C is the only reference to
   * `Moho::SC_VerticalSync` in the image.
   */
  void register_CConFunc_SC_VerticalSync();

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
  void SC_ToggleCursorClip(void* commandArgs);

  /**
   * Address: 0x00BE96C0 (FUN_00BE96C0, register_CConFunc_SC_ToggleCursorClip)
   *
   * What it does:
   * Registers the `SC_ToggleCursorClip` startup console command and installs
   * its process-exit teardown. The store
   * `dword_F5BEEC = offset sub_8D41B0` at 0x00BE96CC is the only reference to
   * `Moho::SC_ToggleCursorClip` in the image.
   */
  void register_CConFunc_SC_ToggleCursorClip();
} // namespace moho
