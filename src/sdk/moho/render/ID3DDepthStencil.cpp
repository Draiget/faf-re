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
   * Address: 0x0043CCC0 (FUN_0043CCC0, sub_43CCC0)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DDepthStencil::~ID3DDepthStencil() = default;
} // namespace moho
