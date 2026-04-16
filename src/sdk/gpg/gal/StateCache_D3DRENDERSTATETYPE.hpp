// ReSharper disable CppTooWideScope
#pragma once

#include "StateCache.h"
#include "D3D9Utils.h"
#include "legacy/containers/Tree.h"

namespace gpg::gal
{
    /**
	 * VFTABLE: 0x00D47F74
	 * COL:     0x00E5358C
	 */
    template<>
    class StateCache<d3d9::RenderState, unsigned int>
    {
    public:
        using state_type = d3d9::RenderState;
        using value_type = unsigned int;

        /**
         * Address: 0x00948010 (FUN_00948010)
         *
         * What it does:
         * Initializes render-state cache tree sentinel lanes and zeroes the
         * cached node-count lane.
         */
        StateCache();

        /**
         * Address: 0x00948190 (FUN_00948190)
         *
         * Slot: 0
         * Demangled: sub_948190
         *
         * What it does:
         * Clears the render-state cache tree and releases owned nodes.
         */
        virtual ~StateCache();

    protected:
        /**
         * Address: 0x00948190 (FUN_00948190)
         *
         * Embedded VC8-like tree sentinel + clear-on-destruction.
         */
        msvc8::EmbeddedTree<> tree_;
    };

}
