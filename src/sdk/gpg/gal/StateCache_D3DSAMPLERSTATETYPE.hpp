// ReSharper disable CppTooWideScope
#pragma once

#include "StateCache.h"
#include "D3D9Utils.h"
#include "legacy/containers/Tree.h"

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
         * cached node-count lane.
         */
        StateCache();

        /**
         * Address: 0x009481E0 (FUN_009481E0)
         *
         * Slot: 0
         * Demangled: sub_9481E0
         *
         * What it does:
         * Clears the sampler-state cache tree and releases owned nodes.
         */
        virtual ~StateCache();

    protected:
        msvc8::EmbeddedTree<> tree_;
    };

}
