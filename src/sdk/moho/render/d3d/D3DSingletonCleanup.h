#pragma once

namespace moho
{
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
