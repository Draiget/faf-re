#pragma once

// FAF addition, not in the shipped binary: the Direct3D 11 counterparts of
// RenderTargetD3D10, DepthStencilTargetD3D10 and CubeRenderTargetD3D10.

#include <d3d11.h>
#include <wrl/client.h>

#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
  /** A colour target: its texture, render-target view and shader-resource view. */
  class RenderTargetD3D11 final : public RenderTarget
  {
  public:
    RenderTargetD3D11(
      ID3D11Texture2D* texture, ID3D11RenderTargetView* renderTargetView, ID3D11ShaderResourceView* shaderResourceView
    );
    ~RenderTargetD3D11() override;

    RenderTargetContext* GetContext() override;
    /** Direct3D 11 has no GDI surface to hand out, as on D3D10. */
    HDC GetDC() override;

    [[nodiscard]] ID3D11Texture2D* GetTexture() const;
    [[nodiscard]] ID3D11RenderTargetView* GetRenderTargetView() const;
    [[nodiscard]] ID3D11ShaderResourceView* GetShaderResourceView() const;

  private:
    RenderTargetContext mContext;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> mTexture;
    Microsoft::WRL::ComPtr<ID3D11RenderTargetView> mRenderTargetView;
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> mShaderResourceView;
  };

  /** A depth-stencil target; sampled targets also carry a shader-resource view. */
  class DepthStencilTargetD3D11 final : public DepthStencilTarget
  {
  public:
    DepthStencilTargetD3D11(
      const DepthStencilTargetContext& context,
      ID3D11Texture2D* texture,
      ID3D11DepthStencilView* depthStencilView,
      ID3D11ShaderResourceView* shaderResourceView
    );
    ~DepthStencilTargetD3D11() override;

    DepthStencilTargetContext* GetContext() override;

    [[nodiscard]] ID3D11DepthStencilView* GetDepthStencilView() const;
    [[nodiscard]] ID3D11ShaderResourceView* GetShaderResourceView() const;

  private:
    DepthStencilTargetContext mContext;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> mTexture;
    Microsoft::WRL::ComPtr<ID3D11DepthStencilView> mDepthStencilView;
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> mShaderResourceView;
  };

  /**
   * An empty cube target. The D3D10 backend never creates a native cube
   * target either (`CreateCubeRenderTarget`, 0x008FA6B0); this keeps the same
   * behaviour until cube rendering is ported.
   */
  class CubeRenderTargetD3D11 final : public CubeRenderTarget
  {
  public:
    explicit CubeRenderTargetD3D11(const CubeRenderTargetContext& context);
    ~CubeRenderTargetD3D11() override;

    CubeRenderTargetContext* GetContext() override;

  private:
    CubeRenderTargetContext mContext;
  };
} // namespace gpg::gal
