#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    /**
     * Address: 0x0094B210 (FUN_0094B210)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `DepthStencilTargetD3D10`.
     */
    void DestroyDepthStencilTargetD3D10Body(DepthStencilTargetD3D10* const depthStencilTarget)
    {
      depthStencilTarget->DestroyState();
    }
}


  /**
   * Address: 0x0094B100 (FUN_0094B100, DepthStencilTargetD3D10 default-state init lane)
   *
   * What it does:
   * Initializes one D3D10 depth-stencil target object to default context
   * values and null retained texture/view lanes.
   */
  [[nodiscard]] DepthStencilTargetD3D10* InitializeDepthStencilTargetD3D10DefaultState(
    DepthStencilTargetD3D10* const target
  )
  {
    target->context_ = DepthStencilTargetContext{};
    target->depthStencilTexture_ = nullptr;
    target->depthStencilView_ = nullptr;
    target->shaderResourceView_ = nullptr;
    return target;
  }

  /**
   * Address: 0x0094B2D0 (FUN_0094B2D0)
   *
   * DepthStencilTargetContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 depth-stencil wrapper from context + texture/DSV/SRV lanes.
   */
  DepthStencilTargetD3D10::DepthStencilTargetD3D10(
    const DepthStencilTargetContext* const context,
    ID3D10Texture2D* const depthStencilTexture,
    ID3D10DepthStencilView* const depthStencilView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , depthStencilTexture_(nullptr)
    , depthStencilView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    (void)InitializeDepthStencilTargetD3D10DefaultState(this);
    DestroyState();
    context_.width_ = context->width_;
    context_.height_ = context->height_;
    context_.format_ = context->format_;
    context_.field0x10_ = context->field0x10_;
    depthStencilTexture_ = depthStencilTexture;
    depthStencilView_ = depthStencilView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x0094B2B0 (FUN_0094B2B0)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_0094B210`.
   */
  DepthStencilTargetD3D10::~DepthStencilTargetD3D10()
  {
    DestroyDepthStencilTargetD3D10Body(this);
  }

  /**
   * Address: 0x0094B160 (FUN_0094B160)
   *
   * What it does:
   * Returns the embedded depth-stencil context lane at `this+0x04`.
   */
  DepthStencilTargetContext* DepthStencilTargetD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094B1A0 (FUN_0094B1A0)
   *
   * What it does:
   * Releases retained depth-stencil texture/view pointers and resets context lanes.
   */
  void DepthStencilTargetD3D10::DestroyState()
  {
    SafeRelease(depthStencilTexture_);
    SafeRelease(depthStencilView_);

    const DepthStencilTargetContext resetContext{};
    context_.width_ = resetContext.width_;
    context_.height_ = resetContext.height_;
    context_.format_ = resetContext.format_;
    context_.field0x10_ = resetContext.field0x10_;
  }

  /**
   * Address: 0x0094B370 (FUN_0094B370)
   *
   * What it does:
   * Validates and returns the retained depth-stencil-texture lane.
   */
  ID3D10Texture2D* DepthStencilTargetD3D10::GetDepthStencilTextureOrThrow()
  {
    if (depthStencilTexture_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 70, "invalid depth stencil texture");
    }

    return depthStencilTexture_;
  }

  /**
   * Address: 0x0094B420 (FUN_0094B420)
   *
   * What it does:
   * Validates and returns the retained depth-stencil-view lane.
   */
  ID3D10DepthStencilView* DepthStencilTargetD3D10::GetDepthStencilViewOrThrow()
  {
    if (depthStencilView_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 76, "invalid depth stencil view");
    }

    return depthStencilView_;
  }

  /**
   * Address: 0x0094B4D0 (FUN_0094B4D0)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* DepthStencilTargetD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 82, "invalid shader resource view");
    }

    return shaderResourceView_;
  }
}

