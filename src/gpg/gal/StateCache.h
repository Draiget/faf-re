#pragma once

#include "legacy/containers/Map.h"

namespace gpg::gal
{
  /**
   * VFTABLE: 0x00D47F74 (StateCache<_D3DRENDERSTATETYPE, unsigned int>)
   * VFTABLE: 0x00D47F7C (StateCache<_D3DSAMPLERSTATETYPE, unsigned int>)
   * VFTABLE: 0x00D47F84 (StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>)
   * COL:     0x00E5358C (render states)
   *
   * The value `StateManagerD3D9` last handed the device for each state of
   * one kind, so a D3DX effect setting the same state twice costs one device
   * call. One cache holds the render states; there is one per sampler and one
   * per texture stage.
   */
  template <class StateT, class ValueT>
  class StateCache
  {
  public:
    using state_type = StateT;
    using value_type = ValueT;

    /**
     * Address: 0x00948010 (FUN_00948010, render states)
     * Address: 0x00948090 (FUN_00948090, sampler states)
     * Address: 0x00948110 (FUN_00948110, texture-stage states)
     *
     * What it does:
     * An empty cache. `StateManagerD3D9`'s constructor (0x00948280) inlines
     * the render-state one and hands the other two to
     * `eh vector constructor iterator` for its sampler and stage arrays.
     */
    StateCache() = default;

    /**
     * Address: 0x00948190 (FUN_00948190, render states, scalar deleting destructor)
     * Address: 0x009481E0 (FUN_009481E0, sampler states, scalar deleting destructor)
     * Address: 0x00948230 (FUN_00948230, texture-stage states, scalar deleting destructor)
     * Address: 0x009480D0 (FUN_009480D0, sampler states, the array element destructor)
     * Address: 0x00948150 (FUN_00948150, texture-stage states, the array element destructor)
     *
     * What it does:
     * Frees the map. The array element copies are the ones
     * `StateManagerD3D9`'s constructor passes to `eh vector constructor
     * iterator` (0x009482DD, 0x009482F8) and its destructor to
     * `eh vector destructor iterator`.
     */
    virtual ~StateCache() = default;

    /**
     * Address: 0x00949C80 (FUN_00949C80, render states)
     * Address: 0x00949CE0 (FUN_00949CE0, sampler states)
     * Address: 0x00949D40 (FUN_00949D40, texture-stage states)
     *
     * What it does:
     * Records `value` for `state`. False only when the cache already holds
     * exactly that value, i.e. when the device call can be skipped.
     */
    bool Update(const state_type& state, const value_type& value)
    {
      const typename msvc8::map<state_type, value_type>::iterator it = tree_.find(state);
      if (it == tree_.end())
      {
        tree_[state] = value;
        return true;
      }

      if (value == it->second)
      {
        return false;
      }

      it->second = value;
      return true;
    }

  protected:
    msvc8::map<state_type, value_type> tree_; // +0x04 {proxy, head, size}
  };
} // namespace gpg::gal
