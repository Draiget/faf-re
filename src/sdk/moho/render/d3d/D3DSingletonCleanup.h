#pragma once

#include "legacy/containers/AutoPtr.h"

namespace moho
{
  class CD3DVertexStream;
  class CD3DIndexSheet;

  /**
   * Address: 0x00BC40C0 (FUN_00BC40C0, dynamic initializer for `sVertexStream`)
   * Address: 0x00BEF190 (FUN_00BEF190, dynamic atexit destructor for `sVertexStream`)
   *
   * What it does:
   * Owns the shared unit-quad vertex stream (`Moho::sVertexStream`, binary
   * global 0x010A792C). Every replace path in the binary is the
   * `auto_ptr::reset` shape: delete the old holder when it differs from the
   * incoming pointer, then store the incoming pointer.
   */
  extern msvc8::auto_ptr<CD3DVertexStream> sVertexStream;

  /**
   * Address: 0x00BC40D0 (FUN_00BC40D0, dynamic initializer for `sIndexSheet`)
   * Address: 0x00BEF1B0 (FUN_00BEF1B0, dynamic atexit destructor for `sIndexSheet`)
   *
   * What it does:
   * Owns the shared quad index sheet (`Moho::sIndexSheet`, binary global
   * 0x010A7928).
   */
  extern msvc8::auto_ptr<CD3DIndexSheet> sIndexSheet;

  class CD3DVertexFormat;

  /**
   * Address: 0x0043C690 (FUN_0043C690, sub_43C690)
   *
   * What it does:
   * Allocates one new shared vertex stream of 0x10000 vertices using
   * the provided vertex format, replaces the `sVertexStream` singleton
   * (releasing the previous slot holder through its deleting dtor
   * thunk), then locks the stream, initializes 0x4000 unit-quad corner
   * templates (each vertex carrying an 8-float UV/axis pattern), and
   * unlocks the stream.
   */
  void func_CreateSharedVertexStream(CD3DVertexFormat* vertexFormat);

  /**
   * Address: 0x0043C800 (FUN_0043C800, func_InitIndexSheet)
   *
   * What it does:
   * Lazily creates the shared index sheet (size 0x18000 indices) via
   * the device resources, replaces the `sIndexSheet` singleton, locks
   * the sheet, fills it with the repeating quad index pattern for
   * 0x4000 quads (6 indices per quad: 0,1,2,0,2,3 relative to each
   * quad's base), and unlocks.
   */
  void func_InitSharedIndexSheet();

  /**
   * Address: 0x0043C8E0 (FUN_0043C8E0, sub_43C8E0)
   *
   * What it does:
   * Returns the shared index-sheet singleton, invoking
   * `func_InitSharedIndexSheet` first when the slot is empty.
   */
  CD3DIndexSheet* func_GetSharedIndexSheet();

  /**
   * Address: 0x0043C900 (FUN_0043C900, sub_43C900)
   *
   * What it does:
   * Deletes the shared index-sheet singleton through its deleting
   * dtor thunk (when present) and clears the slot.
   */
  void func_ClearSharedIndexSheet();

  /**
   * Address: 0x0043CA50 (FUN_0043CA50, sub_43CA50)
   *
   * What it does:
   * Moves one vertex-stream pointer from caller storage into the
   * `sVertexStream` singleton slot, destroying any prior holder
   * (if different from the new one) via its deleting dtor. Returns
   * the address of the updated slot.
   */
  msvc8::auto_ptr<CD3DVertexStream>* func_MoveIntoSharedVertexStream(CD3DVertexStream** inOutStream);

  /**
   * Address: 0x0043CAF0 (FUN_0043CAF0, sub_43CAF0)
   *
   * What it does:
   * Replaces the `sVertexStream` singleton with the caller-supplied
   * pointer, destroying the prior holder (if different) via its
   * deleting dtor thunk.
   */
  void func_SetSharedVertexStream(CD3DVertexStream* stream);
} // namespace moho
