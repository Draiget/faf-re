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
    class StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>
    {
    public:
        using state_type = d3d9::TextureStageState;
        using value_type = unsigned int;

        /**
         * Address: 0x00948110 (FUN_00948110)
         *
         * What it does:
         * Initializes texture-stage cache tree sentinel lanes and zeroes the
         * cached node-count lane. Default-constructs `tree_`, which buys the
         * heap-allocated header sentinel (`sub_947030`, this specialisation's
         * `alloc_raw`) and self-links it -- matches `msvc8::rb_tree`'s
         * default constructor exactly.
         */
        StateCache();

        /**
         * Address: 0x00948230 (FUN_00948230)
         *
         * Slot: 0
         * Demangled: sub_948230
         *
         * What it does:
         * Tears down the texture-stage cache tree before object teardown.
         * The real body inlines `tree_`'s own `erase_range(begin(), end())`
         * (`call sub_947D10`, `legacy/containers/RbTree.h`) followed by an
         * explicit `operator delete` on the header -- i.e. `msvc8::map<
         * _D3DTEXTURESTAGESTATETYPE, unsigned int>::~map()`'s real shape,
         * not a `clear()` call. `tree_`'s implicit member destruction
         * already reproduces this exactly, so this destructor's body is
         * empty; see `StateCache.cpp`.
         */
        virtual ~StateCache();

    protected:
        /**
         * Real binary layout: a heap-allocated-header MSVC8 `_Tree`
         * (`{proxy, head, size}`, isNil@+0x15 on its 8-byte-value nodes),
         * confirmed by `~StateCache`'s own disassembly at 0x0094824C
         * (`erase_range` via `sub_947D10`) and 0x00948255 (explicit
         * `operator delete` on the header) -- not the previously-modelled
         * `msvc8::EmbeddedTree<>` (embedded by-value head, no-arg `clear()`
         * only), which cannot represent the separately-heap-allocated
         * header this address frees. See `legacy/containers/RbTree.h`'s
         * `erase_range` citation for 0x00947D10 for the full callsite
         * evidence.
         */
        msvc8::map<state_type, value_type> tree_;
    };

    // vtable ptr (0x04) + tree_ {proxy, head, size} (0x0C) -- confirmed
    // against the ctor's own field writes at 0x00948110 ([edi+0]=vftable,
    // [edi+8]=head, [edi+0xC]=size; [edi+4]=proxy is left unset).
    static_assert(
        sizeof(StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>) == 0x10,
        "StateCache<TextureStageState, uint> size must be 0x10"
    );

}
