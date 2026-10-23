#pragma once

#include <cstddef>

#include <d3d9.h>

#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/CubeRenderTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47CB4
     * COL:  0x00E531E8
     */
    class CubeRenderTargetD3D9 : public CubeRenderTarget
    {
    public:
        /**
         * Address: 0x009411E0 (FUN_009411E0)
         *
         * What it does:
         * Initializes one empty D3D9 cube-render-target wrapper with default
         * context and cleared texture/face-surface lanes.
         */
        CubeRenderTargetD3D9();

        /**
         * Address: 0x00941450 (FUN_00941450, gpg::gal::CubeRenderTargetD3D9::CubeRenderTargetD3D9)
         *
         * What it does:
         * Initializes cube-target state, applies one context/texture payload,
         * and acquires one face-surface handle per cube face.
         */
        CubeRenderTargetD3D9(const CubeRenderTargetContext* context, IDirect3DCubeTexture9* cubeTexture);

        /**
         * Address: 0x00941330 (FUN_00941330)
         * Address: 0x00941430 (FUN_00941430, scalar deleting destructor)
         *
         * What it does:
         * Releases the face surfaces and the texture.
         */
        ~CubeRenderTargetD3D9() override;

        /**
         * Address: 0x009412B0 (FUN_009412B0)
         *
         * What it does:
         * Releases the six face surfaces, then the cube texture, and empties
         * the context.
         */
        void Reset();

        /**
         * Address: 0x00941390 (FUN_00941390)
         *
         * What it does:
         * Takes `cubeTexture` over as the target of `context` and holds the
         * top level of each face; undoes itself if that throws.
         */
        void SetTexture(const CubeRenderTargetContext* context, IDirect3DCubeTexture9* cubeTexture);

        /**
         * Address: 0x00941240 (FUN_00941240)
         *
         * What it does:
         * Returns the embedded cube render-target context lane at `this+0x04`.
         */
        CubeRenderTargetContext* GetContext() override;

        /**
         * Address: 0x009414D0 (FUN_009414D0)
         *
         * int
         *
         * What it does:
         * Validates one cube face index and returns its retained native face surface.
         */
        IDirect3DSurface9* GetSurface(int face) const;

        /**
         * Address: 0x00941270 (FUN_00941270)
         *
         * What it does:
         * Returns the retained `IDirect3DCubeTexture9*` at `this+0x10`. Its
         * callers are `DeviceD3D9::SaveCubeRenderTarget` (the DDS dump) and
         * the effect variable's cube-target setter at 0x00944630, which hands
         * it to `ID3DXEffect::SetTexture`.
         */
        IDirect3DCubeTexture9* GetTexture() const;

    public:
        CubeRenderTargetContext context_{}; // +0x04
        IDirect3DCubeTexture9* cubeTexture_ = nullptr; // +0x10
        IDirect3DSurface9* faceSurfaces_[6]{};         // +0x14, level 0 of each face
    };

    static_assert(offsetof(CubeRenderTargetD3D9, context_) == 0x04, "CubeRenderTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(CubeRenderTargetD3D9, cubeTexture_) == 0x10, "CubeRenderTargetD3D9::cubeTexture_ offset must be 0x10");
    static_assert(offsetof(CubeRenderTargetD3D9, faceSurfaces_) == 0x14, "CubeRenderTargetD3D9::faceSurfaces_ offset must be 0x14");
    static_assert(sizeof(CubeRenderTargetD3D9) == 0x2C, "CubeRenderTargetD3D9 size must be 0x2C");
}
