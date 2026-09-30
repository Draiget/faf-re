#include "moho/render/IEdRenderHook.h"

namespace moho
{
IEdRenderHook* ed_Hook = nullptr;

/**
 * Address: 0x007B6410 (FUN_007B6410)
 *
 * IDA signature:
 * _DWORD *__usercall sub_7B6410@<eax>(_DWORD *result@<eax>)
 *
 * What it does:
 * Stores the interface vftable and returns `this`.
 */
IEdRenderHook::IEdRenderHook() = default;

/**
 * Address: 0x007B6420 (FUN_007B6420)
 *
 * IDA signature:
 * void __thiscall sub_7B6420(_DWORD *this)
 *
 * What it does:
 * Restores the interface vftable; the out-of-line body of the pure virtual
 * destructor.
 */
IEdRenderHook::~IEdRenderHook() = default;

/**
 * Address: 0x007B6430 (FUN_007B6430)
 *
 * IDA signature:
 * int __usercall sub_7B6430@<eax>(int result@<eax>)
 *
 * What it does:
 * Installs `hook` as the editor render hook.
 */
void ED_SetHook(IEdRenderHook* const hook)
{
  ed_Hook = hook;
}

/**
 * Address: 0x007B6440 (FUN_007B6440)
 *
 * IDA signature:
 * int sub_7B6440()
 *
 * What it does:
 * Returns the installed editor render hook.
 */
IEdRenderHook* ED_GetHook()
{
  return ed_Hook;
}

/**
 * Address: 0x007B6450 (FUN_007B6450)
 *
 * IDA signature:
 * int sub_7B6450()
 *
 * What it does:
 * Calls `ed_Hook->Render()` when a hook is installed.
 */
void ED_Render()
{
  if (ed_Hook != nullptr) {
    ed_Hook->Render();
  }
}
} // namespace moho
