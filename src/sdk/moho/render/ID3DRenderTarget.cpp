#include "ID3DRenderTarget.h"

namespace moho
{
  /**
   * Address: 0x0043EC50 (FUN_0043EC50, sub_43EC50)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived render targets.
   */
  ID3DRenderTarget::ID3DRenderTarget() = default;

  /**
   * Address: 0x0043CC80 (FUN_0043CC80, ID3DRenderTarget dtor body)
   * Address: 0x0043CC90 (FUN_0043CC90, sub_43CC90, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CC80 and a separate scalar-deleting thunk at 0x0043CC90. Both
   * addresses cover this defaulted dtor.
   */
  ID3DRenderTarget::~ID3DRenderTarget() = default;
} // namespace moho
