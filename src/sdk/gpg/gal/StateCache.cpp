#include "StateCache_D3DRENDERSTATETYPE.hpp"
#include "StateCache_D3DSAMPLERSTATETYPE.hpp"
#include "StateCache_D3DTEXTURESTAGESTATETYPE.hpp"

namespace gpg::gal
{
  /**
   * Address: 0x00948190 (FUN_00948190)
   *
   * What it does:
   * Clears render-state cache nodes before object teardown.
   */
  StateCache<d3d9::RenderState, unsigned int>::~StateCache()
  {
    tree_.clear();
  }

  /**
   * Address: 0x009481E0 (FUN_009481E0)
   *
   * What it does:
   * Clears sampler-state cache nodes before object teardown.
   */
  StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::~StateCache()
  {
    tree_.clear();
  }

  /**
   * Address: 0x00948230 (FUN_00948230)
   *
   * What it does:
   * Clears texture-stage cache nodes before object teardown.
   */
  StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::~StateCache()
  {
    tree_.clear();
  }
} // namespace gpg::gal
