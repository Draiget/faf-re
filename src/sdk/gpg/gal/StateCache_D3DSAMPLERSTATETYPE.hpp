// ReSharper disable CppTooWideScope
#pragma once

#include "StateCache.h"
#include "D3D9Utils.h"
#include "legacy/containers/Map.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47F7C
     * COL:  0x00E535D4
     */
    template<>
    class StateCache<_D3DSAMPLERSTATETYPE, unsigned int>
    {
    public:
        using state_type = d3d9::SamplerState;
        using value_type = unsigned int;

        /**
         * Address: 0x00948090 (FUN_00948090)
         *
         * What it does:
         * Initializes sampler-state cache tree sentinel lanes and zeroes the
         * cached node-count lane. Default-constructs `tree_`, which buys the
         * heap-allocated header sentinel (`sub_946FE0`, this specialisation's
         * `alloc_raw`) and self-links it -- matches `msvc8::rb_tree`'s
         * default constructor exactly.
         */
        StateCache();

        /**
         * Address: 0x009481E0 (FUN_009481E0)
         *
         * Slot: 0
         * Demangled: sub_9481E0
         *
         * What it does:
         * Tears down the sampler-state cache tree before object teardown.
         * The real body inlines `tree_`'s own `erase_range(begin(), end())`
         * (`call sub_947C50`, `legacy/containers/RbTree.h`) followed by an
         * explicit `operator delete` on the header -- i.e. `msvc8::map<
         * _D3DSAMPLERSTATETYPE, unsigned int>::~map()`'s real shape, not a
         * `clear()` call. `tree_`'s implicit member destruction already
         * reproduces this exactly, so this destructor's body is empty; see
         * `StateCache.cpp`.
         */
        virtual ~StateCache();

    protected:
        /**
         * Real binary layout: a heap-allocated-header MSVC8 `_Tree`
         * (`{proxy, head, size}`, isNil@+0x15 on its 8-byte-value nodes),
         * confirmed by `~StateCache`'s own disassembly at 0x009481FC
         * (`erase_range` via `sub_947C50`) and 0x00948205 (explicit
         * `operator delete` on the header) -- not the previously-modelled
         * `msvc8::EmbeddedTree<>` (embedded by-value head, no-arg `clear()`
         * only), which cannot represent the separately-heap-allocated
         * header this address frees. See `legacy/containers/RbTree.h`'s
         * `erase_range` citation for 0x00947C50 for the full callsite
         * evidence.
         */
        msvc8::map<state_type, value_type> tree_;
    };

    // vtable ptr (0x04) + tree_ {proxy, head, size} (0x0C) -- confirmed
    // against the ctor's own field writes at 0x00948090 ([edi+0]=vftable,
    // [edi+8]=head, [edi+0xC]=size; [edi+4]=proxy is left unset).
    static_assert(
        sizeof(StateCache<_D3DSAMPLERSTATETYPE, unsigned int>) == 0x10,
        "StateCache<SamplerState, uint> size must be 0x10"
    );

}
