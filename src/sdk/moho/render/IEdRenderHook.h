#pragma once

#include <cstddef>

namespace moho
{
  /**
   * VFTABLE: 0x00E3CAF8
   * COL:     0x00E96668
   *
   * Callback the in-engine editor installs through `ED_SetHook` to draw its
   * own overlay at the end of `WRenViewport::RenderUI`. The shipped game never
   * installs one: no class in the binary derives from it (the vftable is
   * stored only by the two bodies below), so both slots stay `_purecall`
   * here and in MohoEngine.dll.
   */
  class IEdRenderHook
  {
  public:
    /**
     * Address: 0x007B6420 (FUN_007B6420)
     * Slot: 0 (0x00A82547 `_purecall`)
     *
     * IDA signature:
     * void __thiscall sub_7B6420(_DWORD *this)
     *
     * What it does:
     * Restores the interface vftable. Pure virtual, so the vftable holds
     * `_purecall` in slot 0; the definition in IEdRenderHook.cpp is the
     * out-of-line body a pure virtual destructor still needs. It stays
     * thiscall (LTCG moved the non-virtual one-pointer bodies next to it,
     * the ctor and `ED_SetHook`, onto EAX) because a derived class's
     * destructor can reach it virtually.
     */
    virtual ~IEdRenderHook() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * What it does:
     * Draws the editor overlay for the current head. Dispatched only by
     * `ED_Render` (0x007B6450) and its inlined copy in
     * `WRenViewport::RenderUI` (0x007F8A04..0x007F8A13, `call [vtbl+4]`).
     */
    virtual void Render() = 0;

  protected:
    /**
     * Address: 0x007B6410 (FUN_007B6410)
     *
     * IDA signature:
     * _DWORD *__usercall sub_7B6410@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Stores the interface vftable and returns `this`. The EAX in/out
     * convention is LTCG's; the thiscall form would need `mov eax, ecx`.
     */
    IEdRenderHook();
  };

  static_assert(sizeof(IEdRenderHook) == 0x04, "IEdRenderHook size must be 0x04");

  /**
   * Address: 0x010A640C (Moho::ed_Hook, data)
   *
   * What it does:
   * The installed editor render hook, or null (always null in the game).
   */
  extern IEdRenderHook* ed_Hook;

  /**
   * Address: 0x007B6430 (FUN_007B6430)
   *
   * IDA signature:
   * int __usercall sub_7B6430@<eax>(int result@<eax>)
   *
   * What it does:
   * Installs `hook` as the editor render hook (`ed_Hook = hook`).
   */
  void ED_SetHook(IEdRenderHook* hook);

  /**
   * Address: 0x007B6440 (FUN_007B6440)
   *
   * IDA signature:
   * int sub_7B6440()
   *
   * What it does:
   * Returns the installed editor render hook.
   */
  [[nodiscard]] IEdRenderHook* ED_GetHook();

  /**
   * Address: 0x007B6450 (FUN_007B6450)
   *
   * IDA signature:
   * int sub_7B6450()
   *
   * What it does:
   * Calls `ed_Hook->Render()` when a hook is installed (tail call through
   * vftable slot 1). Returns nothing: with no hook, EAX is left untouched,
   * which is IDA's uninitialised `result`.
   */
  void ED_Render();
} // namespace moho
