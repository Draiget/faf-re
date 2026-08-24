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
   * Runs the non-deleting sampler-state cache destructor lane: an explicit
   * destructor call (MSVC8's "base object destructor" form) that tears down
   * `tree_` and keeps object storage ownership with the caller. The real
   * body at this address inlines the same `erase_range(begin(), end())` +
   * `operator delete(header)` sequence as `~StateCache` below rather than
   * calling it as a separate function -- the compiler duplicated the tiny
   * teardown body for this calling-convention variant instead of emitting
   * one shared symbol, matching the sibling-emission pattern documented on
   * `legacy/containers/RbTree.h`'s `erase_range` citation for 0x00947C50.
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
   * Runs the non-deleting texture-stage cache destructor lane, the same
   * base-object-destructor variant as
   * `RuntimeDestroySamplerStateCacheTreeOnlyLaneA` above, inlining
   * `erase_range(begin(), end())` (`call sub_947D10`) + explicit
   * `operator delete(header)` rather than calling `~StateCache` directly.
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
   * Tears down the render-state cache tree before object teardown.
   *
   * The real disassembly inlines `tree_`'s own `erase_range(begin(),
   * end())` (0x009481AC, `call sub_947B90`) followed by an explicit
   * `operator delete` on the header (0x009481B5) -- `msvc8::map<
   * d3d9::RenderState, unsigned int>::~map()`'s exact shape, not a
   * `clear()` call (`clear()` never frees the header). Now that `tree_`
   * is a real `msvc8::map`, its own implicit member destruction performs
   * that same sequence automatically, so this destructor's body is
   * intentionally empty. See `legacy/containers/RbTree.h`'s `erase_range`
   * citation for 0x00947B90 and `StateCache_D3DRENDERSTATETYPE.hpp`.
   */
  StateCache<d3d9::RenderState, unsigned int>::~StateCache()
  {
  }

  /**
   * Address: 0x009481E0 (FUN_009481E0)
   *
   * What it does:
   * Tears down the sampler-state cache tree before object teardown.
   *
   * Same shape as the render-state destructor above: the real body inlines
   * `erase_range(begin(), end())` (0x009481FC, `call sub_947C50`) then an
   * explicit `operator delete` on the header (0x00948205), reproduced here
   * by `tree_`'s implicit `msvc8::map<_D3DSAMPLERSTATETYPE, unsigned
   * int>::~map()`. See `legacy/containers/RbTree.h`'s `erase_range`
   * citation for 0x00947C50 and `StateCache_D3DSAMPLERSTATETYPE.hpp`.
   */
  StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::~StateCache()
  {
  }

  /**
   * Address: 0x00948230 (FUN_00948230)
   *
   * What it does:
   * Tears down the texture-stage cache tree before object teardown.
   *
   * Same shape again: the real body inlines `erase_range(begin(), end())`
   * (0x0094824C, `call sub_947D10`) then an explicit `operator delete` on
   * the header (0x00948255), reproduced here by `tree_`'s implicit
   * `msvc8::map<_D3DTEXTURESTAGESTATETYPE, unsigned int>::~map()`. See
   * `legacy/containers/RbTree.h`'s `erase_range` citation for 0x00947D10
   * and `StateCache_D3DTEXTURESTAGESTATETYPE.hpp`.
   */
  StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::~StateCache()
  {
  }
} // namespace gpg::gal
