#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x008F5260 (FUN_008F5260)
     *
     * What it does:
     * An empty render target.
     */
    RenderTargetD3D9::RenderTargetD3D9()
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {}

    /**
     * Address: 0x008F5620 (FUN_008F5620)
     *
     * What it does:
     * Wraps `renderTexture` as a render target of `context`.
     */
    RenderTargetD3D9::RenderTargetD3D9(const RenderTargetContext* const context, IDirect3DTexture9* const renderTexture)
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {
        SetRenderTexture(context, renderTexture);
    }

    /**
     * Address: 0x008F5470 (FUN_008F5470)
     *
     * What it does:
     * Wraps a surface that has no texture behind it - a head's back buffer
     * (`DeviceD3D9::CreateHeads`).
     */
    RenderTargetD3D9::RenderTargetD3D9(IDirect3DSurface9* const backBufferSurface)
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {
        SetSurface(backBufferSurface);
    }

    /**
     * Address: 0x008F53B0 (FUN_008F53B0)
     * Address: 0x008F5450 (FUN_008F5450, scalar deleting destructor)
     *
     * What it does:
     * Releases the surface and the texture.
     */
    RenderTargetD3D9::~RenderTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x008F5350 (FUN_008F5350)
     *
     * What it does:
     * Releases the surface and the texture and empties the context.
     */
    void RenderTargetD3D9::Reset()
    {
        SafeRelease(surface_);
        SafeRelease(texture_);
        context_ = RenderTargetContext();
    }

    /**
     * Address: 0x008F5410 (FUN_008F5410)
     *
     * What it does:
     * Takes `surface` over and sizes the context from its description.
     */
    void RenderTargetD3D9::SetSurface(IDirect3DSurface9* const surface)
    {
        Reset();
        surface_ = surface;

        D3DSURFACE_DESC surfaceDesc;
        surface_->GetDesc(&surfaceDesc);
        context_.width_ = surfaceDesc.Width;
        context_.height_ = surfaceDesc.Height;
    }

    /**
     * Address: 0x008F5500 (FUN_008F5500)
     *
     * What it does:
     * Takes `renderTexture` over as the target of `context` and renders into
     * its top level; the context is resized to that surface. Undoes itself
     * when the surface cannot be had.
     */
    void RenderTargetD3D9::SetRenderTexture(const RenderTargetContext* const context, IDirect3DTexture9* const renderTexture)
    {
        Reset();
        context_ = *context;
        texture_ = renderTexture;
        try
        {
            const HRESULT result = texture_->GetSurfaceLevel(0U, &surface_);
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("RenderTargetD3D9.cpp", 89, result);
            }

            D3DSURFACE_DESC surfaceDesc;
            surface_->GetDesc(&surfaceDesc);
            context_.width_ = surfaceDesc.Width;
            context_.height_ = surfaceDesc.Height;
        }
        catch (...)
        {
            Reset();
            throw;
        }
    }

    /**
     * Address: 0x008F52C0 (FUN_008F52C0)
     *
     * What it does:
     * Returns the target's context.
     */
    RenderTargetContext* RenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F52D0 (FUN_008F52D0, Moho::D3DSurface::GetSurface)
     * Mangled: ?GetSurface@D3DSurface@Moho@@QAEPAUIDirect3DSurface9@@XZ
     *
     * What it does:
     * Returns the surface rendered into.
     */
    IDirect3DSurface9* RenderTargetD3D9::GetSurface()
    {
        return surface_;
    }

    /**
     * Address: 0x008F52E0 (FUN_008F52E0)
     *
     * What it does:
     * Returns the texture behind the surface, for
     * `EffectVariableD3D9::SetRenderTarget` to bind through `ID3DXEffect::SetTexture`.
     */
    IDirect3DTexture9* RenderTargetD3D9::GetTexture()
    {
        return texture_;
    }

    /**
     * Address: 0x008F5300 (FUN_008F5300)
     *
     * What it does:
     * A GDI device context on the surface, or null when the target has no
     * surface (`cmp [ecx+0x14],0; je` at 0x008F5301).
     */
    HDC RenderTargetD3D9::GetDC()
    {
        if (surface_ == nullptr)
        {
            return nullptr;
        }

        HDC deviceContext = nullptr;
        surface_->GetDC(&deviceContext);
        return deviceContext;
    }
}

