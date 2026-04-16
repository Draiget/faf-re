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
         * cached node-count lane.
         */
        StateCache();

        /**
         * Address: 0x00948230 (FUN_00948230)
         *
         * Slot: 0
         * Demangled: sub_948230
         *
         * What it does:
         * Clears the texture-stage cache tree and releases owned nodes.
         */
        virtual ~StateCache();

    protected:
        msvc8::EmbeddedTree<> tree_;
    };

}
