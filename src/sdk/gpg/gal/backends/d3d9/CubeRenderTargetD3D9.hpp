#pragma once

#include <cstddef>

#include "gpg/gal/CubeRenderTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47CB4
     * COL:  0x00E531E8
     */
    class CubeRenderTargetD3D9
    {
    public:
        /**
         * Address: 0x00941430 (FUN_00941430)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to cube-target teardown helpers.
         */
        virtual ~CubeRenderTargetD3D9();

        /**
         * Address: 0x00941240 (FUN_00941240)
         *
         * What it does:
         * Returns the embedded cube render-target context lane at `this+0x04`.
         */
        virtual CubeRenderTargetContext* GetContext();

        /**
         * Address: 0x009414D0 (FUN_009414D0)
         *
         * int
         *
         * What it does:
         * Validates one cube face index and returns its retained native face surface.
         */
        void* GetSurface(int face) const;

    public:
        CubeRenderTargetContext context_{}; // +0x04
        void* cubeTexture_ = nullptr;       // +0x10
        void* faceSurfaces_[6]{};           // +0x14
    };

    static_assert(offsetof(CubeRenderTargetD3D9, context_) == 0x04, "CubeRenderTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(CubeRenderTargetD3D9, cubeTexture_) == 0x10, "CubeRenderTargetD3D9::cubeTexture_ offset must be 0x10");
    static_assert(offsetof(CubeRenderTargetD3D9, faceSurfaces_) == 0x14, "CubeRenderTargetD3D9::faceSurfaces_ offset must be 0x14");
    static_assert(sizeof(CubeRenderTargetD3D9) == 0x2C, "CubeRenderTargetD3D9 size must be 0x2C");
}
