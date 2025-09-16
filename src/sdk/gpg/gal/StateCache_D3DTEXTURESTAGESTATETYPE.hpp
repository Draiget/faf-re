// ReSharper disable CppTooWideScope
#pragma once

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
         * Address: 0x00948230
         * Slot: 0
         * Demangled: sub_948230
         */
        virtual ~StateCache() = default;

    protected:
        msvc8::tree::EmbeddedTree<> tree_;
    };
}
