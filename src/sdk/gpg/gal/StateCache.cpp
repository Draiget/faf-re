#include "StateCache_D3DRENDERSTATETYPE.hpp"
#include "StateCache_D3DSAMPLERSTATETYPE.hpp"
#include "StateCache_D3DTEXTURESTAGESTATETYPE.hpp"

namespace gpg::gal
{
  /**
   * Address: 0x00948090 (FUN_00948090)
   *
   * What it does:
   * Initializes sampler-state cache tree sentinel lanes and zeroes the
   * cached node-count lane.
   */
  StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::StateCache()
    : tree_()
  {
  }

  /**
   * Address: 0x00948110 (FUN_00948110)
   *
   * What it does:
   * Initializes texture-stage cache tree sentinel lanes and zeroes the
   * cached node-count lane.
   */
  StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::StateCache()
    : tree_()
  {
  }

  /**
   * Address: 0x00948010 (FUN_00948010)
   *
   * What it does:
   * Initializes render-state cache tree sentinel lanes and zeroes the
   * cached node-count lane.
   */
  StateCache<d3d9::RenderState, unsigned int>::StateCache()
    : tree_()
  {
  }

  /**
   * Address: 0x009480D0 (FUN_009480D0)
   *
   * What it does:
   * Runs the non-deleting sampler-state cache destructor lane that clears the
   * embedded tree and keeps object storage ownership with the caller.
   */
  [[maybe_unused]] void RuntimeDestroySamplerStateCacheTreeOnlyLaneA(
    StateCache<_D3DSAMPLERSTATETYPE, unsigned int>* const stateCache
  ) noexcept
  {
    stateCache->StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::~StateCache();
  }

  /**
   * Address: 0x00948150 (FUN_00948150)
   *
   * What it does:
   * Runs the non-deleting texture-stage cache destructor lane that clears the
   * embedded tree and keeps object storage ownership with the caller.
   */
  [[maybe_unused]] void RuntimeDestroyTextureStageStateCacheTreeOnlyLaneA(
    StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>* const stateCache
  ) noexcept
  {
    stateCache->StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::~StateCache();
  }

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
