#include "moho/render/CRenFrame.h"

#include <Windows.h>
#include <d3d9.h>

#include <cstdint>
#include <cstring>

#include "boost/weak_ptr.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/ShaderVar.h"

namespace moho
{
  // ---------------------------------------------------------------------------
  // Bloom tuning globals consumed by the frame post-process pass.
  //
  // Both live in .data at fixed defaults in the shipped binary:
  //   ren_BloomBlurKernelScale @ 0x00F57E68 = 1.5f
  //   ren_BloomGlowCopyScale   @ 0x00F57E6C = 2.0f
  // (byte-verified from bin/2025.7.1/ForgedAlliance.exe). They follow the same
  // definition pattern as the other moho `ren_*` render-tuning globals.
  // ---------------------------------------------------------------------------
  float ren_BloomBlurKernelScale = 1.5f;
  float ren_BloomGlowCopyScale = 2.0f;

  namespace
  {
    constexpr int kRenFrameVertexFormatToken = 8;
    constexpr int kRenFrameVertexCountToken = 6;
    constexpr float kHalfPixelOffset = 0.5f;

    // FUN_007F6030 issues a non-indexed triangle-strip fullscreen quad
    // (*primitiveType == 5 == D3DPT_TRIANGLESTRIP) over 4 transformed verts.
    constexpr std::int32_t kTriangleStripPrimitiveToken = 5;
    constexpr std::int32_t kRenFrameQuadLastVertexIndex = 3;

    struct RenFrameTransformedVertex
    {
      float x;
      float y;
      float z;
      float rhw;
      float u0;
      float v0;
      float u1;
      float v1;
    };

    static_assert(sizeof(RenFrameTransformedVertex) == 0x20, "RenFrameTransformedVertex size must be 0x20");

    // -------------------------------------------------------------------------
    // "frame" effect shader-variable set.
    //
    // These are the global ShaderVar slots the frame/bloom post-process effect
    // binds. In the shipped binary they are registered by a static bootstrap
    // (register block at 0x00BE10E0) via RegisterShaderVar(<hlslName>, &var,
    // "frame"). Each HLSL variable name below is byte-verified as an exact
    // null-terminated string in bin/2025.7.1/ForgedAlliance.exe:
    //   FrameTexture1..4 -> "FrameTexture1".."FrameTexture4"
    //   BlurScale        -> "BlurScale"
    //   GlowCopyScale    -> "GlowCopyScale"
    //   framewidth/frameheight/viewport are lowercase in the binary (the IDA
    //   symbol labels FrameWidth/FrameHeight/ViewPort were approximations).
    //
    // Mirrors the DEFINE_WATER2_SHADER_VAR_GETTER lazy-register idiom
    // (see moho/terrain/water/WaterShaderVars.cpp).
    // -------------------------------------------------------------------------
#define DEFINE_FRAME_SHADER_VAR_GETTER(FUNC_NAME, VARIABLE_NAME) \
    [[nodiscard]] ShaderVar& FUNC_NAME() \
    { \
      static ShaderVar shaderVar{}; \
      static const bool registered = (RegisterShaderVar(VARIABLE_NAME, &shaderVar, "frame"), true); \
      (void)registered; \
      return shaderVar; \
    }

    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameTexture1ShaderVar, "FrameTexture1")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameTexture2ShaderVar, "FrameTexture2")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameTexture3ShaderVar, "FrameTexture3")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameTexture4ShaderVar, "FrameTexture4")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameBlurScaleShaderVar, "BlurScale")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameGlowCopyScaleShaderVar, "GlowCopyScale")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameWidthShaderVar, "framewidth")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameFrameHeightShaderVar, "frameheight")
    DEFINE_FRAME_SHADER_VAR_GETTER(GetFrameViewPortShaderVar, "viewport")

#undef DEFINE_FRAME_SHADER_VAR_GETTER

    // The frame texture slots are bound through the weak-texture binder
    // (ShaderVar::GetTexture(const boost::weak_ptr<gpg::gal::TextureD3D9>&),
    // FUN_00491280). In the binary the &mFrameTextureN handle
    // (boost::shared_ptr<ID3DRenderTarget>) is passed directly to that binder:
    // boost's shared_ptr and weak_ptr share the same {px, pn} two-pointer
    // layout, and the binder only reads px + the shared-count lane. The same
    // reinterpret bridge is used for the refraction slot in WRenViewport
    // (moho/app/WxRuntimeTypes.cpp).
    void BindFrameTexture(ShaderVar& shaderVar, const boost::shared_ptr<ID3DRenderTarget>& renderTarget)
    {
      shaderVar.GetTexture(
        reinterpret_cast<const boost::weak_ptr<gpg::gal::TextureD3D9>&>(renderTarget)
      );
    }
  } // namespace

  /**
   * Address: 0x007F5C10 (FUN_007F5C10, Moho::CRenFrame::CRenFrame)
   */
  CRenFrame::CRenFrame()
    : mName()
    , mVertexSheet(nullptr)
    , mWidth(0.0f)
    , mHeight(0.0f)
    , mFrameTexture1()
    , mFrameTexture2()
    , mFrameTexture3()
    , mFrameTexture4()
  {}

  /**
   * Address: 0x007F5C80 (FUN_007F5C80, Moho::CRenFrame::~CRenFrame)
   */
  CRenFrame::~CRenFrame()
  {
    ResetTransientResources();
  }

  /**
   * Address: 0x007F5D00 (FUN_007F5D00, Moho::CRenFrame::SetTexture)
   */
  void CRenFrame::SetTexture(const unsigned int textureSlot, boost::shared_ptr<ID3DRenderTarget> texture)
  {
    (void)textureSlot;
    mFrameTexture1 = texture;
  }

  /**
   * Address: 0x007F5DA0 (FUN_007F5DA0, Moho::CRenFrame::InitTransformedVerts)
   *
   * float width, float height
   *
   * What it does:
   * Rebuilds the cached transformed fullscreen-quad vertices used by
   * CRenFrame pass rendering, with a half-pixel screen-space offset.
   */
  void CRenFrame::InitTransformedVerts(const float width, const float height)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kRenFrameVertexFormatToken);
    if (vertexFormat == nullptr) {
      gpg::Die("CRenFrame::InitVerts: Unable to create vertex format");
    }

    if (mVertexSheet != nullptr) {
      if (mWidth == width && mHeight == height) {
        return;
      }
    } else {
      mVertexSheet = resources->NewVertexSheet(0U, kRenFrameVertexCountToken, vertexFormat);
    }

    if (mVertexSheet == nullptr) {
      gpg::Die("CRenFrame::InitVerts: Unable to create vertex sheet");
    }

    const float maxX = width - kHalfPixelOffset;
    const float maxY = height - kHalfPixelOffset;
    mWidth = width;
    mHeight = height;

    const RenFrameTransformedVertex quadVertices[4] = {
      {-0.5f, -0.5f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f},
      {maxX, -0.5f, 1.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f},
      {-0.5f, maxY, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f},
      {maxX, maxY, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f},
    };

    ID3DVertexStream* const vertexStream = mVertexSheet->GetVertStream(0U);
    const int vertexCount = mVertexSheet->Func5();
    void* const lockedVertices = vertexStream->Lock(0, vertexCount, false, false);
    std::memcpy(lockedVertices, quadVertices, sizeof(quadVertices));
    mVertexSheet->GetVertStream(0U)->Unlock();
  }

  void CRenFrame::ResetTransientResources() noexcept
  {
    mVertexSheet = nullptr;
  }

  /**
   * Address: 0x007F6030 (FUN_007F6030, Moho::CRenFrame::Render)
   * Mangled: ?Render@CRenFrame@Moho@@QAEXHH@Z
   *
   * IDA signature:
   * void __thiscall Moho::CRenFrame::Render(Moho::CRenFrame *this, int width, int height);
   *
   * What it does:
   * Runs one frame/bloom post-process pass: selects the "frame" effect and this
   * pass's technique (mName), binds the four frame render targets into the
   * FrameTexture1..4 shader variables, pushes the blur/glow-copy scale and the
   * width/height scalars, packs the active viewport rectangle into the viewport
   * shader variable, and issues a non-indexed triangle-strip fullscreen-quad
   * draw over the cached vertex sheet.
   */
  void CRenFrame::Render(const int width, const int height)
  {
    auto* const galDevice = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    CD3DDevice* device = D3D_GetDevice();
    device->SelectFxFile("frame");

    device = D3D_GetDevice();
    device->SelectTechnique(mName.c_str());

    BindFrameTexture(GetFrameFrameTexture1ShaderVar(), mFrameTexture1);
    BindFrameTexture(GetFrameFrameTexture2ShaderVar(), mFrameTexture2);
    BindFrameTexture(GetFrameFrameTexture3ShaderVar(), mFrameTexture3);
    BindFrameTexture(GetFrameFrameTexture4ShaderVar(), mFrameTexture4);

    // Each scalar is written only when its shader variable resolves against the
    // loaded "frame" effect. Exists() is the same guard the binary inlines
    // before dispatching the raw effect-variable SetFloat.
    if (ShaderVar& blurScale = GetFrameBlurScaleShaderVar(); blurScale.Exists()) {
      blurScale.mEffectVariable->SetFloat(ren_BloomBlurKernelScale);
    }
    if (ShaderVar& glowCopyScale = GetFrameGlowCopyScaleShaderVar(); glowCopyScale.Exists()) {
      glowCopyScale.mEffectVariable->SetFloat(ren_BloomGlowCopyScale);
    }
    if (ShaderVar& frameWidth = GetFrameFrameWidthShaderVar(); frameWidth.Exists()) {
      frameWidth.mEffectVariable->SetFloat(static_cast<float>(width));
    }
    if (ShaderVar& frameHeight = GetFrameFrameHeightShaderVar(); frameHeight.Exists()) {
      frameHeight.mEffectVariable->SetFloat(static_cast<float>(height));
    }

    D3DVIEWPORT9 viewport{};
    viewport.MaxZ = 1.0f;
    galDevice->GetViewport(&viewport);

    const float viewportRect[4] = {
      static_cast<float>(viewport.X),
      static_cast<float>(viewport.Y),
      static_cast<float>(viewport.Width),
      static_cast<float>(viewport.Height),
    };
    if (ShaderVar& viewPort = GetFrameViewPortShaderVar(); viewPort.Exists()) {
      viewPort.mEffectVariable->SetMem(4U, viewportRect);
    }

    CD3DVertexSheetViewRuntime quadView{};
    quadView.sheet = mVertexSheet;
    quadView.startVertex = 0;
    quadView.baseVertex = 0;
    quadView.endVertex = kRenFrameQuadLastVertexIndex;

    std::int32_t primitiveType = kTriangleStripPrimitiveToken;
    (void)D3D_GetDevice()->DrawPrimitiveList(&quadView, &primitiveType);
  }
} // namespace moho
