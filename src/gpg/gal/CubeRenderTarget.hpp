#pragma once

#include "boost/noncopyable.hpp"

namespace gpg::gal
{
    class CubeRenderTargetContext;

    /**
     * VFTABLE: 0x00D43000
     * COL:  0x00E50B9C
     *
     * The backend-neutral six-face colour target. `CubeRenderTargetD3D9`
     * (vtable 0x00D47CB4) and `CubeRenderTargetD3D10` (0x00D4300C) implement
     * it; `OutputContext::cubeTarget` holds one together with the face index
     * to render into.
     */
    class CubeRenderTarget : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008F7F20 (FUN_008F7F20)
         *
         * What it does:
         * Installs the abstract cube-render-target vtable.
         */
        CubeRenderTarget();

        /**
         * Slot: 0 (`_purecall` in the base table, so the destructor is pure)
         *
         * What it does:
         * Derived destructors reinstall 0x00D43000 as their last step
         * (0x008F8068 in `CubeRenderTargetD3D10`).
         */
        virtual ~CubeRenderTarget() = 0;

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the creation descriptor the target was built from.
         */
        virtual CubeRenderTargetContext* GetContext() = 0;
    };

    static_assert(sizeof(CubeRenderTarget) == 0x04, "CubeRenderTarget size must be 0x04");
} // namespace gpg::gal
