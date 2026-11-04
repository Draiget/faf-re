#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x009411E0 (FUN_009411E0)
     *
     * What it does:
     * An empty cube render target.
     */
    CubeRenderTargetD3D9::CubeRenderTargetD3D9()
        : context_()
        , cubeTexture_(nullptr)
        , faceSurfaces_{}
    {}

    /**
     * Address: 0x00941450 (FUN_00941450)
     *
     * What it does:
     * Wraps `cubeTexture` as a cube render target of `context`.
     */
    CubeRenderTargetD3D9::CubeRenderTargetD3D9(
        const CubeRenderTargetContext* const context,
        IDirect3DCubeTexture9* const cubeTexture
    )
        : context_()
        , cubeTexture_(nullptr)
        , faceSurfaces_{}
    {
        SetTexture(context, cubeTexture);
    }

    /**
     * Address: 0x00941330 (FUN_00941330)
     * Address: 0x00941430 (FUN_00941430, scalar deleting destructor)
     *
     * What it does:
     * Releases the face surfaces and the texture.
     */
    CubeRenderTargetD3D9::~CubeRenderTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x009412B0 (FUN_009412B0)
     *
     * What it does:
     * Releases the six face surfaces, then the cube texture, and empties the
     * context.
     */
    void CubeRenderTargetD3D9::Reset()
    {
        for (IDirect3DSurface9*& faceSurface : faceSurfaces_)
        {
            SafeRelease(faceSurface);
        }
        std::memset(faceSurfaces_, 0, sizeof(faceSurfaces_));

        SafeRelease(cubeTexture_);
        context_ = CubeRenderTargetContext();
    }

    /**
     * Address: 0x00941390 (FUN_00941390)
     *
     * What it does:
     * Takes `cubeTexture` over as the target of `context` and holds the top
     * level of each face. Undoes itself if that throws.
     */
    void CubeRenderTargetD3D9::SetTexture(
        const CubeRenderTargetContext* const context,
        IDirect3DCubeTexture9* const cubeTexture
    )
    {
        Reset();
        context_ = *context;
        cubeTexture_ = cubeTexture;
        try
        {
            for (int face = 0; face < kCubeFaceCount; ++face)
            {
                cubeTexture_->GetCubeMapSurface(static_cast<D3DCUBEMAP_FACES>(face), 0U, &faceSurfaces_[face]);
            }
        }
        catch (...)
        {
            Reset();
            throw;
        }
    }

    /**
     * Address: 0x00941240 (FUN_00941240)
     *
     * What it does:
     * Returns the target's context.
     */
    CubeRenderTargetContext* CubeRenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x009414D0 (FUN_009414D0)
     *
     * What it does:
     * Returns the top-level surface of `face`. Only the upper bound is
     * checked (`cmp eax,6; jl`).
     */
    IDirect3DSurface9* CubeRenderTargetD3D9::GetSurface(const int face) const
    {
        if (face >= kCubeFaceCount)
        {
            ThrowGalError("CubeRenderTargetD3D9.cpp", 104, "invalid cube face index specified");
        }

        return faceSurfaces_[face];
    }

    /**
     * Address: 0x00941270 (FUN_00941270)
     *
     * What it does:
     * Returns the cube texture.
     */
    IDirect3DCubeTexture9* CubeRenderTargetD3D9::GetTexture() const
    {
        return cubeTexture_;
    }
}

