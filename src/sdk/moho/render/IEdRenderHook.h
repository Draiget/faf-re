#pragma once

#include <cstddef>

namespace moho
{
  /**
   * VFTABLE: 0x00E3CAF8
   * COL:     0x00E96668
   */
  class IEdRenderHook
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * What it does:
     * Abstract editor-render callback lane 0.
     */
    virtual void Hook0() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * What it does:
     * Abstract editor-render callback lane 1.
     */
    virtual void Hook1() = 0;
  };

  /**
   * Address: 0x010A640C (Moho::ed_Hook, data)
   *
   * What it does:
   * Process-global editor render-hook pointer lane.
   */
  extern IEdRenderHook* ed_Hook;

  /**
   * Address: 0x007B6410 (FUN_007B6410)
   *
   * IEdRenderHook *
   *
   * IDA signature:
   * _DWORD *__usercall sub_7B6410@<eax>(_DWORD *result@<eax>)
   *
   * What it does:
   * Writes the `IEdRenderHook` vtable pointer into one object lane and returns
   * the same object pointer.
   */
  [[nodiscard]] IEdRenderHook* InitializeEdRenderHookVTableEax(IEdRenderHook* hook);

  /**
   * Address: 0x007B6420 (FUN_007B6420)
   *
   * IEdRenderHook *
   *
   * IDA signature:
   * void __thiscall sub_7B6420(_DWORD *this)
   *
   * What it does:
   * Writes the `IEdRenderHook` vtable pointer into one object lane.
   */
  void InitializeEdRenderHookVTableEcx(IEdRenderHook* hook);

  /**
   * Address: 0x007B6440 (FUN_007B6440)
   *
   * IEdRenderHook *
   *
   * IDA signature:
   * int sub_7B6440()
   *
   * What it does:
   * Returns the process-global editor render-hook pointer (`Moho::ed_Hook`).
   */
  [[nodiscard]] IEdRenderHook* GetEditorRenderHook();

  static_assert(sizeof(IEdRenderHook) == 0x04, "IEdRenderHook size must be 0x04");
} // namespace moho
