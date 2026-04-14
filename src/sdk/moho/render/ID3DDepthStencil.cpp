#include "ID3DDepthStencil.h"

namespace moho
{
  /**
   * Address: 0x0043F090 (FUN_0043F090, sub_43F090)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived depth stencils.
   */
  ID3DDepthStencil::ID3DDepthStencil() = default;

  /**
   * Address: 0x0043CCB0 (FUN_0043CCB0, ID3DDepthStencil dtor body)
   * Address: 0x0043CCC0 (FUN_0043CCC0, sub_43CCC0, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CCB0 and a separate scalar-deleting thunk at 0x0043CCC0.
   */
  ID3DDepthStencil::~ID3DDepthStencil() = default;
} // namespace moho
