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
} // namespace moho
