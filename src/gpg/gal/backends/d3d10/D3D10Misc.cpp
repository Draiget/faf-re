#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
  namespace
  {

    // `{proxy, first, last, end}` at 0x10 is `fa::vector<EffectMacro>`
    // itself, so the lane is the container, not a view over it.
    using EffectMacroVector = fa::vector<EffectMacro>;

    static_assert(sizeof(EffectMacroVector) == 0x10, "EffectMacroVector size must be 0x10");

    // Defined later in this TU; used by the vector<void*>::_Insert_n grow lane below.

  } // namespace

} // namespace gpg::gal
