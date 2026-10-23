#include "StateCache.h"

#include "gpg/gal/D3D9Utils.h"

namespace gpg::gal
{
  // The three caches `StateManagerD3D9` holds, emitted here once each.
  template class StateCache<_D3DRENDERSTATETYPE, unsigned int>;
  template class StateCache<_D3DSAMPLERSTATETYPE, unsigned int>;
  template class StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>;

  // vtable + map {proxy, head, size}; the constructor at 0x00948010 writes
  // [+0]=vtable, [+8]=head, [+0xC]=size and leaves the proxy at +4 unset.
  static_assert(sizeof(StateCache<_D3DRENDERSTATETYPE, unsigned int>) == 0x10, "StateCache size must be 0x10");
  static_assert(sizeof(StateCache<_D3DSAMPLERSTATETYPE, unsigned int>) == 0x10, "StateCache size must be 0x10");
  static_assert(sizeof(StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>) == 0x10, "StateCache size must be 0x10");
} // namespace gpg::gal
