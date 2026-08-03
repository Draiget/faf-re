#include "moho/render/Shadow.h"

#include <Windows.h>

#include <cstring>
#include <new>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ScreenQuadVertexSheet.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/d3d/CD3DVertexSheet.h"

namespace
{
  // Depth-stencil format the shadow map's companion buffer is created with.
  constexpr int kShadowDepthStencilFormat = 3;

  /**
   * Address: 0x007FE760 (FUN_007FE760)
   *
   * What it does:
   * Clears the cached fidelity/blur/size settings and releases every render
   * resource the shadow renderer holds. Called both from the destructor and
   * from `Init` - on entry, and again on either failure path.
   */
  int ReleaseShadowRenderResources(moho::Shadow* const shadow) noexcept
  {
    shadow->mShadowFidelity = 0;
    shadow->mShadowBlurEnabled = false;

    shadow->mShadowMap.reset();
    shadow->mBlurTargetA.reset();
    shadow->mBlurTargetB.reset();
    shadow->mDepthStencil.reset();
    shadow->mQuadVertexSheet.reset();
    for (boost::shared_ptr<void>& resource : shadow->mUnreferencedResources) {
      resource.reset();
    }

    shadow->mShadowSize = 0;
    return 0;
  }

  struct BlinkyBoxListNode
  {
    BlinkyBoxListNode* next;
    BlinkyBoxListNode* prev;
  };

  BlinkyBoxListNode gBlinkyBoxesListHead{&gBlinkyBoxesListHead, &gBlinkyBoxesListHead};

  /**
   * Address: 0x007FE040 (FUN_007FE040)
   *
   * What it does:
   * Unlinks one blinky-box node from its current intrusive list and reinserts
   * it at the head of the global blinky-box list.
   */
  [[maybe_unused]] [[nodiscard]] BlinkyBoxListNode* RelinkBlinkyBoxNodeToGlobalHead(BlinkyBoxListNode* const node)
  {
    if (node == nullptr || node->next == nullptr || node->prev == nullptr) {
      return node;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node;
    node->prev = node;

    node->next = gBlinkyBoxesListHead.next;
    node->prev = &gBlinkyBoxesListHead;
    gBlinkyBoxesListHead.next = node;
    node->next->prev = node;
    return node;
  }
} // namespace

namespace moho
{
  extern int ren_ShadowSize;
  extern bool ren_ShadowBlur;

  /**
   * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes shadow-renderer fidelity/size flags, constructs the light-space
   * camera at `+0x18`, and null-clears every resource handle.
   */
  Shadow::Shadow()
    : mUnusedHeaderWord(0)
    , mShadowFidelity(0)
    , mShadowBlurEnabled(false)
    , mPadding0D_0F{}
    , mShadowSize(0)
    , mShadowCameraValid(false)
    , mPadding15_17{}
    , mCamera()
    , mShadowMap()
    , mBlurTargetA()
    , mBlurTargetB()
    , mDepthStencil()
    , mQuadVertexSheet()
    , mUnreferencedResources{}
  {}

  /**
   * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs non-deleting teardown for one shadow runtime object.
   */
  Shadow::~Shadow()
  {
    (void)ReleaseShadowRenderResources(this);
  }

  /**
   * Address: 0x007DB350 (FUN_007DB350)
   *
   * What it does:
   * Returns a retained copy of the shadow-map render target for shader binding.
   */
  boost::shared_ptr<CD3DRenderTarget>& Shadow::GetShadowMap(
    boost::shared_ptr<CD3DRenderTarget>& outShadowMap
  ) const
  {
    outShadowMap = mShadowMap;
    return outShadowMap;
  }

  /**
   * Address: 0x007FE3E0 (FUN_007FE3E0, Moho::Shadow::Init)
   *
   * IDA signature:
   * int __usercall Moho::Shadow::Init@<eax>(int fidelity, Moho::Shadow *this);
   *
   * What it does:
   * Rebuilds every shadow render resource for the requested fidelity. Latches
   * the current shadow-size/blur tuning, drops what was held before, and for a
   * non-zero fidelity allocates the shadow-map target (plus the two blur
   * ping-pong targets when blur is enabled), the depth stencil, and the
   * fullscreen quad the blur passes draw - scaled to the shadow resolution.
   */
  int Shadow::Init(const int fidelity)
  {
    // Both tuning values are sampled before the reset below, which zeroes the
    // cached copies.
    const int shadowSize = ren_ShadowSize;
    const bool shadowBlur = ren_ShadowBlur;

    (void)ReleaseShadowRenderResources(this);

    mShadowFidelity = fidelity;
    mShadowBlurEnabled = shadowBlur;
    mShadowSize = shadowSize;

    if (fidelity == 0) {
      return 1;
    }

    // Fidelity 1 uses the cheaper target format; every higher level uses the
    // wider one.
    const int targetFormat = (fidelity != 1) ? 7 : 2;

    // The binary pulls the GAL device singleton here and discards it; the call
    // is kept because it is what forces the backend to be resolved before the
    // resource factory below is used.
    (void)gpg::gal::Device::GetInstance();

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    resources->CreateRenderTarget(mShadowMap, shadowSize, shadowSize, targetFormat);
    if (mShadowBlurEnabled) {
      resources->CreateRenderTarget(mBlurTargetA, shadowSize, shadowSize, targetFormat);
      resources->CreateRenderTarget(mBlurTargetB, shadowSize, shadowSize, targetFormat);
    }

    resources->CreateDepthStencil(mDepthStencil, shadowSize, shadowSize, kShadowDepthStencilFormat);
    if (!mDepthStencil) {
      gpg::Warnf("unable to create depth sheet used by the shadow map");
      (void)ReleaseShadowRenderResources(this);
      return 0;
    }

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kScreenQuadVertexFormatToken);
    mQuadVertexSheet.reset(
      resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat)
    );
    if (!mQuadVertexSheet) {
      gpg::Warnf("unable to create the main vertex sheet used by the shadow map");
      (void)ReleaseShadowRenderResources(this);
      return 0;
    }

    // The template is a unit quad; scale it out to the shadow-map resolution.
    // The binary leaves the texture coordinates alone, which is what passing
    // 1.0f for both texture scales does here.
    const float shadowSizeF = static_cast<float>(shadowSize);
    FillScreenQuadVertexSheet(*mQuadVertexSheet, shadowSizeF, shadowSizeF, 1.0f, 1.0f);
    return 1;
  }

  /**
   * Address: 0x007FE1A0 (FUN_007FE1A0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `Shadow`, forwarding through
   * `Shadow::~Shadow` and optional storage release.
   */
  [[nodiscard]] Shadow* DestroyShadowDeleting(Shadow* const shadow, const unsigned char deleteFlag)
  {
    shadow->~Shadow();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(shadow));
    }
    return shadow;
  }
} // namespace moho
