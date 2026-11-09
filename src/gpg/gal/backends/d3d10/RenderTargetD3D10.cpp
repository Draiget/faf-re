#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    int MapDxgiToGalRenderTargetFormat(const int dxgiFormat)
    {
      for (const DXGIFormatPair& pair : kRenderTargetDxgiGalPairs) {
        if (pair.dxgi == dxgiFormat) {
          return pair.gal;
        }
      }

      return 8;
    }

    /**
     * Address: 0x00902EB0 (FUN_00902EB0)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `RenderTargetD3D10`.
     */
    void DestroyRenderTargetD3D10Body(RenderTargetD3D10* const renderTarget)
    {
      renderTarget->DestroyState();
    }
}


  /**
   * Address: 0x00902D20 (FUN_00902D20, ??0RenderTargetD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes default render-target context lanes and null resource pointers.
   */
  RenderTargetD3D10::RenderTargetD3D10()
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
  }

  /**
   * Address: 0x00902FE0 (FUN_00902FE0)
   *
   * void *,void *,void *
   *
   * What it does:
   * Initializes one render-target wrapper from retained texture/view pointers and
   * derives context width/height/format from the source texture descriptor.
   */
  RenderTargetD3D10::RenderTargetD3D10(
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    InitializeFromResource(renderTexture, renderTargetView, shaderResourceView);
  }

  /**
   * Address: 0x00903050 (FUN_00903050)
   *
   * RenderTargetContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one render-target wrapper from caller-provided context metadata and
   * retained texture/view pointers.
   */
  RenderTargetD3D10::RenderTargetD3D10(
    const RenderTargetContext* const context,
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    DestroyState();
    context_.width_ = context->width_;
    context_.height_ = context->height_;
    context_.format_ = context->format_;
    renderTexture_ = renderTexture;
    renderTargetView_ = renderTargetView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x00902F10 (FUN_00902F10)
   *
   * void *,void *,void *
   *
   * What it does:
   * Reinitializes state from retained texture/view pointers and rebuilds context
   * width/height/format from texture descriptor lanes.
   */
  void RenderTargetD3D10::InitializeFromResource(
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
  {
    DestroyState();

    D3D10_TEXTURE2D_DESC textureDesc{};
    renderTexture->GetDesc(&textureDesc);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalRenderTargetFormat(static_cast<int>(textureDesc.Format)));
    context_.width_ = textureDesc.Width;
    context_.height_ = textureDesc.Height;

    renderTexture_ = renderTexture;
    renderTargetView_ = renderTargetView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x009030E0 (FUN_009030E0)
   *
   * What it does:
   * Validates and returns the retained render-texture lane.
   */
  ID3D10Texture2D* RenderTargetD3D10::GetRenderTextureOrThrow()
  {
    if (renderTexture_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 100, "invalid render target");
    }

    return renderTexture_;
  }

  /**
   * Address: 0x00902FC0 (FUN_00902FC0)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_00902EB0`.
   */
  RenderTargetD3D10::~RenderTargetD3D10()
  {
    DestroyRenderTargetD3D10Body(this);
  }

  /**
   * Address: 0x00902D80 (FUN_00902D80)
   *
   * What it does:
   * Returns the embedded render-target context lane at `this+0x04`.
   */
  RenderTargetContext* RenderTargetD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00902D70 (FUN_00902D70)
   *
   * What it does:
   * D3D10 has no GDI-compatible surface to hand out (`xor eax,eax; ret`).
   */
  HDC RenderTargetD3D10::GetDC()
  {
    return nullptr;
  }

  /**
   * Address: 0x00902E30 (FUN_00902E30)
   *
   * What it does:
   * Releases retained D3D10 resource/view pointers and resets context lanes.
   */
  void RenderTargetD3D10::DestroyState()
  {
    SafeRelease(renderTexture_);
    SafeRelease(renderTargetView_);
    SafeRelease(shaderResourceView_);

    const RenderTargetContext resetContext{};
    context_.width_ = resetContext.width_;
    context_.height_ = resetContext.height_;
    context_.format_ = resetContext.format_;
  }

  /**
   * Address: 0x00903190 (FUN_00903190)
   *
   * What it does:
   * Validates and returns the retained render-target-view lane.
   */
  ID3D10RenderTargetView* RenderTargetD3D10::GetRenderTargetViewOrThrow()
  {
    if (renderTargetView_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 106, "invalid render target view");
    }

    return renderTargetView_;
  }

  /**
   * Address: 0x00903240 (FUN_00903240)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* RenderTargetD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 112, "invalid shader resource view");
    }

    return shaderResourceView_;
  }
}

