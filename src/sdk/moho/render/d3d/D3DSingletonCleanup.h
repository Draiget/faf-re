#pragma once

namespace moho
{
  class CD3DVertexStream;
  class CD3DIndexSheet;

  /**
   * Accessor for the `sVertexStream` global slot that holds one shared
   * vertex-stream wrapper (orig: `dword_10A792C`). Returns a reference
   * to the pointer slot so callers can both read and replace the
   * tracked singleton; the allocator/lifetime contract matches the
   * binary's direct `Moho::sVertexStream` data-section access pattern.
   */
  CD3DVertexStream*& SharedVertexStreamSlot() noexcept;

  /**
   * Accessor for the `sIndexSheet` global slot that holds one shared
   * index-sheet wrapper (orig: `dword_10A7928`). Same read/write
   * contract as `SharedVertexStreamSlot`.
   */
  CD3DIndexSheet*& SharedIndexSheetSlot() noexcept;

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
  CD3DVertexStream** func_MoveIntoSharedVertexStream(CD3DVertexStream** inOutStream);

  /**
   * Address: 0x0043CAF0 (FUN_0043CAF0, sub_43CAF0)
   *
   * What it does:
   * Replaces the `sVertexStream` singleton with the caller-supplied
   * pointer, destroying the prior holder (if different) via its
   * deleting dtor thunk.
   */
  void func_SetSharedVertexStream(CD3DVertexStream* stream);

  /**
   * Address: 0x00BC40C0 (FUN_00BC40C0, register_sVertexStream)
   *
   * What it does:
   * Registers the recovered process-exit cleanup thunk for the global
   * `CD3DVertexStream` singleton slot.
   */
  void register_D3DVertexStreamCleanup();

  /**
   * Address: 0x00BEF190 (FUN_00BEF190, ??1sVertexStream@Moho@@QAE@@Z)
   *
   * What it does:
   * Deletes the recovered global `CD3DVertexStream` singleton when present.
   */
  void cleanup_D3DVertexStream();

  /**
   * Address: 0x00BC40D0 (FUN_00BC40D0, register_sIndexSheet)
   *
   * What it does:
   * Registers the recovered process-exit cleanup thunk for the global
   * `CD3DIndexSheet` singleton slot.
   */
  void register_D3DIndexSheetCleanup();

  /**
   * Address: 0x00BEF1B0 (FUN_00BEF1B0, ??1sIndexSheet@Moho@@QAE@@Z)
   *
   * What it does:
   * Deletes the recovered global `CD3DIndexSheet` singleton when present.
   */
  void cleanup_D3DIndexSheet();
} // namespace moho
