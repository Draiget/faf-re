#pragma once

// FAF addition, not in the shipped binary: the Direct3D 11 counterparts of
// PipelineStateD3D10 and CursorD3D10.

#include <cstdint>

#include <d3d11.h>
#include <wrl/client.h>

#include "boost/shared_ptr.h"
#include "gpg/gal/PipelineState.hpp"
#include "platform/Platform.h"

namespace gpg::gal
{
  class CursorContext;
  class Texture;

  /**
   * The two fixed state packs of the D3D10 backend (`CreateState1`,
   * 0x009024F0, and `CreateState2`, 0x00902940), plus FAF's colour-write and
   * wireframe overrides, which the D3D10 backend keeps in file statics.
   */
  class PipelineStateD3D11 final : public PipelineState
  {
  public:
    PipelineStateD3D11(ID3D11Device* device, ID3D11DeviceContext* immediate);
    ~PipelineStateD3D11() override;

    /** Binds the start-up pack: no culling, ALWAYS depth, linear wrap sampler on every slot. */
    void SetDeviceState();
    /** Unbinds every pixel-shader resource slot. */
    void ClearTextures();
    /** Binds the pack every technique begins with: back-face culling, LESS_EQUAL depth. */
    void BeginTechnique();
    void EndTechnique();

    void SetColorWriteMask(bool writeColor, bool writeAlpha) noexcept;
    void SetWireframe(bool enabled) noexcept { mWireframe = enabled; }

    /**
     * Lays the colour-write mask and wireframe fill over the state an effect
     * pass just bound, as D3D9 does with COLORWRITEENABLE / FILLMODE: only
     * where the pass sets no blend (rasterizer) state of its own. The D3D10
     * backend's `ApplyStateOverrides` instead overrode any pass whose mask
     * was 0x0F, which also caught passes that ask for RGBA explicitly (the
     * minimap writes alpha 0 that way, and its glow went white).
     */
    void ApplyOverrides(bool passSetsBlend, bool passSetsRasterizer);

  private:
    Microsoft::WRL::ComPtr<ID3D11Device> mDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mImmediate;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> mStartupRasterizer;
    Microsoft::WRL::ComPtr<ID3D11DepthStencilState> mStartupDepthStencil;
    Microsoft::WRL::ComPtr<ID3D11BlendState> mStartupBlend;
    Microsoft::WRL::ComPtr<ID3D11SamplerState> mStartupSampler;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> mTechniqueRasterizer;
    Microsoft::WRL::ComPtr<ID3D11DepthStencilState> mTechniqueDepthStencil;
    Microsoft::WRL::ComPtr<ID3D11BlendState> mTechniqueBlend;
    UINT8 mColorWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    bool mWireframe = false;
  };

  /** The Windows cursor the D3D10 backend uses in place of a hardware cursor. */
  class CursorD3D11
  {
  public:
    CursorD3D11() = default;
    CursorD3D11(const CursorD3D11&) = delete;
    CursorD3D11& operator=(const CursorD3D11&) = delete;
    ~CursorD3D11();

    void Destroy() noexcept;
    HCURSOR SetCursor(const CursorContext& context);
    HCURSOR InitCursor();
    int ShowCursor(bool show);

  private:
    HCURSOR mPreviousCursor = nullptr;
    HICON mCursorIcon = nullptr;
  };
} // namespace gpg::gal
