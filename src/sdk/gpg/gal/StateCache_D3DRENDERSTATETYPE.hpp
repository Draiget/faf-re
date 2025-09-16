// ReSharper disable CppTooWideScope
#pragma once

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
	     * Scalar deleting destructor.
		 *
         * Address: 0x00948190
         * Slot: 0
         * Demangled: sub_948190
         */
        virtual ~StateCache() = default;

    protected:
        /**0x00948190
         * Embedded VC8-like tree sentinel + clear-on-destruction.
         */
        msvc8::tree::EmbeddedTree<> tree_;
    };
}
