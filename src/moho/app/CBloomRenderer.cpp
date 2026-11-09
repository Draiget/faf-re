#include "moho/app/WxPrivate.h"

namespace moho
{
  // Bloom-pass engine globals consumed by CBloomRenderer::DoBloom
  // (FUN_007F5160). They live in the shipped binary's data segments; their
  // owning translation unit is not recovered yet, so they are forward-declared
  // here as externs (same convention as the ren_* flags declared later in this
  // file and ren_ShowNormals in MediumFidelityTerrain.cpp).
  //   ren_BloomBlurCount @0x00F57E7C = 2 (byte-verified in
  //   bin/2025.7.1/ForgedAlliance.exe: `02 00 00 00`).
  extern int ren_BloomBlurCount;
  extern ShaderVar shaderVarFrameGlowCopyAdd;
}

namespace
{

  void DestroyFrameVertexSheet(moho::ID3DVertexSheet*& vertexSheet) noexcept
  {
    moho::ID3DVertexSheet* const retainedSheet = vertexSheet;
    if (retainedSheet == nullptr) {
      return;
    }

    retainedSheet->Destroy();
    vertexSheet = nullptr;
  }
}


// ---------------------------------------------------------------------------
// CBloomRenderer
// ---------------------------------------------------------------------------

/**
 * Address: 0x007F6420 (FUN_007F6420)
 * Mangled: ??0CBloomRenderer@Moho@@QAE@XZ
 */
moho::CBloomRenderer::CBloomRenderer()
{
  mHeight = 0;
  mWidth = 0;
  mHead = 0;
}

/**
 * Address: 0x007F64A0 (FUN_007F64A0)
 * Mangled: ??1CBloomRenderer@Moho@@QAE@XZ
 */
moho::CBloomRenderer::~CBloomRenderer()
{
  ResetRenderTargets();
}

/**
 * Address: 0x007F4F10 (FUN_007F4F10)
 */
void moho::CBloomRenderer::ResetRenderTargets() noexcept
{
  DestroyFrameVertexSheet(mExtractFrame.mVertexSheet);
  DestroyFrameVertexSheet(mCompositeFrame.mVertexSheet);
  mRenderTargets[0].reset();
  mRenderTargets[1].reset();
}

/**
 * Address: 0x007F4D00 (FUN_007F4D00)
 */
int moho::CBloomRenderer::Init(const int head)
{
  mHead = static_cast<std::uint32_t>(head);

  const unsigned int headIndex = static_cast<unsigned int>(head);
  mWidth = static_cast<std::uint32_t>(D3D_GetDevice()->GetHeadWidth(headIndex)) >> 1;
  mHeight = static_cast<std::uint32_t>(D3D_GetDevice()->GetHeadHeight(headIndex)) >> 1;

  // Both targets are created at the cached half size. The binary re-fetches
  // the device singleton for each call rather than caching it.
  for (auto& renderTarget : mRenderTargets) {
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    ID3DDeviceResources::RenderTargetHandle newTarget{};
    resources->CreateRenderTarget(newTarget, static_cast<int>(mWidth), static_cast<int>(mHeight), 2);
    renderTarget = newTarget;
  }

  mCompositeFrame.InitTransformedVerts(static_cast<float>(mWidth), static_cast<float>(mHeight));

  // The extract quad covers the whole head, not the half-size target.
  mExtractFrame.InitTransformedVerts(
    static_cast<float>(static_cast<unsigned int>(D3D_GetDevice()->GetHeadWidth(headIndex))),
    static_cast<float>(static_cast<unsigned int>(D3D_GetDevice()->GetHeadHeight(headIndex)))
  );

  return 1;
}

/**
 * Address: 0x007F4FB0 (FUN_007F4FB0)
 * Mangled: ?RenderToBlur@CBloomRenderer@Moho@@AAEXPBDV?$shared_ptr@VID3DRenderTarget@Moho@@@boost@@@Z
 */
void moho::CBloomRenderer::RenderToBlur(
  const char* const technique,
  boost::shared_ptr<ID3DRenderTarget> texture
)
{
  CRenFrame& frame = mCompositeFrame;
  frame.mName = technique;

  // The binary drops the SetTexture texture-slot argument at this call site
  // (only the shared_ptr is pushed); CRenFrame::SetTexture ignores the slot and
  // always assigns mFrameTexture1, so slot 0 is 1:1.
  frame.SetTexture(0u, texture);
  frame.Render(static_cast<int>(mWidth), static_cast<int>(mHeight));
}

/**
 * Address: 0x007F5070 (FUN_007F5070)
 * Mangled: ?RenderToBackBuffer@CBloomRenderer@Moho@@AAEXPBDV?$shared_ptr@VID3DRenderTarget@Moho@@@boost@@@Z
 */
void moho::CBloomRenderer::RenderToBackBuffer(
  boost::shared_ptr<ID3DRenderTarget> texture
)
{
  CRenFrame& frame = mExtractFrame;
  frame.mName = "TFrameAdd";
  frame.SetTexture(0u, texture);

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device->GetDeviceContext();
  const gpg::gal::Head& head = context->GetHead(mHead);
  frame.Render(static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));
}

/**
 * Address: 0x007F5160 (FUN_007F5160)
 * Mangled: ?DoBloom@CBloomRenderer@Moho@@QAEXM@Z
 *
 * `amount` is the glow-copy bias. 0x007F527E `fld [esp+30h+a18]` pushes the
 * incoming argument into shaderVarFrameGlowCopyAdd; the 1.0f loaded from
 * 0x00DFEC20 at 0x007F51FC/0x007F524F is the temporary viewport's MaxZ, not
 * this value. An earlier revision read those two slots as one and hard-wired
 * GlowCopyAdd = 1.0, which makes frame.fx's CopyGlowingPS
 * (`a = saturate((a - 0.02) * GlowCopyScale + GlowCopyAdd)`) saturate for every
 * pixel: the whole scene was copied as glow, blurred, and added back One+One
 * onto the back buffer -- the global white-out of terrain and meshes alike.
 */
void moho::CBloomRenderer::DoBloom(const float amount)
{
  // Both targets must be present (the binary tests [ebx+8] and [ebx+0x10]).
  if (mRenderTargets[0].get() == nullptr || mRenderTargets[1].get() == nullptr) {
    return;
  }

  gpg::gal::Device* const deviceInstance = gpg::gal::Device::GetInstance();

  // The binary keeps only the .px of the returned depth stencil in `edi` for
  // the whole routine.
  boost::shared_ptr<CD3DDepthStencil> activeDepthStencil;
  ID3DDepthStencil* const depthStencil = D3D_GetDevice()->GetDepthStencil(activeDepthStencil).get();

  D3DVIEWPORT9 savedViewport{};

  // Acquire this head's writer-lock render target, then StretchRect it into
  // the blur target. This seeds the blur target with the current back buffer.
  boost::shared_ptr<ID3DRenderTarget> writerLock;
  D3D_GetDevice()->GetWriterLock1(writerLock, static_cast<int>(mHead));
  D3D_GetDevice()->SetViewRect(writerLock.get(), mRenderTargets[1].get(), nullptr, nullptr);

  // Save the current device viewport, then install a full-frame viewport
  // (0,0,width,height,0,1) for the post-process passes.
  deviceInstance->GetViewport(&savedViewport);

  D3DVIEWPORT9 bloomViewport{};
  bloomViewport.X = 0u;
  bloomViewport.Y = 0u;
  bloomViewport.Width = mWidth;
  bloomViewport.Height = mHeight;
  bloomViewport.MinZ = 0.0f;
  bloomViewport.MaxZ = 1.0f;
  deviceInstance->SetViewport(&bloomViewport);

  if (shaderVarFrameGlowCopyAdd.Exists()) {
    shaderVarFrameGlowCopyAdd.SetFloat(amount);
  }

  // Copy the glowing scene into the extract target, sourced from the blur
  // target.
  D3D_GetDevice()->SetRenderTarget1(mRenderTargets[0].get(), depthStencil, false, 0, 1.0f, 0);
  RenderToBlur("TCopyGlowingStuff", mRenderTargets[1]);

  // Ping-pong Gaussian blur: horizontal pass reads the glow target and writes
  // the blur target, vertical pass reads the blur target and writes the glow
  // target, repeated ren_BloomBlurCount times.
  for (int pass = 0; pass < ren_BloomBlurCount; ++pass) {
    D3D_GetDevice()->SetRenderTarget1(mRenderTargets[1].get(), depthStencil, false, 0, 1.0f, 0);
    RenderToBlur("TBlurHorizontal", mRenderTargets[0]);

    D3D_GetDevice()->SetRenderTarget1(mRenderTargets[0].get(), depthStencil, false, 0, 1.0f, 0);
    RenderToBlur("TBlurVertical", mRenderTargets[1]);
  }

  // Restore the saved viewport, rebind this head's back buffer as the render
  // target, and additively composite the accumulated glow onto it.
  deviceInstance->SetViewport(&savedViewport);
  D3D_GetDevice()->SetRenderTarget2(static_cast<int>(mHead), false, 0, 1.0f, 0);
  RenderToBackBuffer(mRenderTargets[0]);
}
