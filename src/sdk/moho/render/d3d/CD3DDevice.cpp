#include "CD3DDevice.h"

#include <Windows.h>
#include <d3d9.h>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/d3d/CD3DDeviceResources.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/D3DSingletonCleanup.h"
#include "moho/render/SParticleBuffer.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/ID3DIndexSheet.h"
#include "moho/render/ID3DDepthStencil.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/textures/DeviceExitListener.h"
#include "Wm3Vector2.h"

namespace
{
  moho::StatItem* sEngineStatFrameTime = nullptr;
  moho::StatItem* sEngineStatFrameFps = nullptr;
  moho::StatItem* sEngineStatRenderPresentCount = nullptr;
  moho::StatItem* sEngineStatRenderPrimitiveCount = nullptr;
  moho::StatItem* sEngineStatRenderVertexCount = nullptr;
  moho::StatItem* sEngineStatRenderDrawPrimCalls = nullptr;
  moho::StatItem* sEngineStatRenderUnitPrimitiveCount = nullptr;
  moho::StatItem* sEngineStatRenderUnitVertexCount = nullptr;
  moho::StatItem* sEngineStatRenderQuadBatchCount = nullptr;
  moho::StatItem* sEngineStatRenderTextBatchCount = nullptr;
  moho::StatItem* sEngineStatRenderFlatDecals = nullptr;
  moho::StatItem* sEngineStatRenderDecals = nullptr;

  float sDeltaFrame = 0.0f;
  float sWeightedFrameRate = 0.0f;
  std::int32_t sCurGameTick = 0;

  [[nodiscard]] std::int32_t FloatToBits(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::bit_cast<std::uint32_t>(value));
  }

  void PublishFloatStat(moho::StatItem* item, const float value)
  {
    if (item == nullptr) {
      return;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
    const long nextBits = static_cast<long>(FloatToBits(value));

    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, nextBits, observed) != observed);
  }

  moho::StatItem* EnsureEngineIntStat(moho::StatItem*& slot, const char* const statName)
  {
    if (slot == nullptr) {
      if (moho::EngineStats* const stats = moho::GetEngineStats(); stats != nullptr) {
        slot = stats->GetItem2(statName);
        if (slot != nullptr) {
          (void)slot->Release(0);
        }
      }
    }
    return slot;
  }

  int ResetStatCounter(moho::StatItem* const item)
  {
    if (item == nullptr) {
      return 0;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, 0, observed) != observed);
    return static_cast<int>(observed);
  }

  int AddToStatCounter(moho::StatItem* const item, const unsigned int amount)
  {
    if (item == nullptr) {
      return 0;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
    return static_cast<int>(::InterlockedExchangeAdd(counter, static_cast<long>(amount)));
  }

  template <class T>
  boost::shared_ptr<T>& CopyRetainedHandle(const boost::shared_ptr<T>& source, boost::shared_ptr<T>& out)
  {
    out = source;
    return out;
  }

  /**
   * Address: 0x004408F0 (FUN_004408F0, sub_4408F0)
   *
   * What it does:
   * Performs one resource-transition reset over tracked D3D object lanes:
   * - notifies effects with `OnLost`
   * - drops retained surface/buffer handles from tracked sheet/target lists
   * - optionally destroys all compiled effects during full teardown.
   */
  void ResetResourcesForContextTransition(moho::CD3DDeviceResources& resources, const bool destroyEffects)
  {
    for (moho::CD3DEffect* const effect : resources.mEffects) {
      if (effect != nullptr && effect->mEffect) {
        effect->mEffect->OnLost();
      }
    }

    for (auto* vertexSheet :
         resources.mVertexSheet2.mLink.owners_member<moho::CD3DVertexSheet, &moho::CD3DVertexSheet::mLink>()) {
      const std::uint32_t streamCount = static_cast<std::uint32_t>(vertexSheet->mStreams.size());
      for (std::uint32_t streamIndex = 0U; streamIndex < streamCount; ++streamIndex) {
        if (!vertexSheet->mOwnedStreamMask.TestBit(streamIndex)) {
          continue;
        }

        if (moho::CD3DVertexStream* const stream = vertexSheet->mStreams[streamIndex]; stream != nullptr) {
          stream->mBuffer.reset();
        }
      }
    }

    for (auto* indexSheet :
         resources.mIndexSheet2.mLink.owners_member<moho::CD3DIndexSheet, &moho::CD3DIndexSheet::mLink>()) {
      indexSheet->mBuffer.reset();
    }

    for (auto* renderTarget :
         resources.mRenderTarget.mLink.owners_member<moho::CD3DRenderTarget, &moho::CD3DRenderTarget::mLink>()) {
      renderTarget->mSurface.reset();
    }

    for (auto* depthStencil :
         resources.mDepthStencil.mLink.owners_member<moho::CD3DDepthStencil, &moho::CD3DDepthStencil::mLink>()) {
      depthStencil->mSurface.reset();
    }

    for (auto* dynamicSheet : resources.mTextureSheet.mLink.owners_member<
                               moho::CD3DDynamicTextureSheet,
                               &moho::CD3DDynamicTextureSheet::mLink>()) {
      dynamicSheet->mTexture.reset();
    }

    if (destroyEffects) {
      for (moho::CD3DEffect*& effect : resources.mEffects) {
        delete effect;
        effect = nullptr;
      }
      resources.mEffects.clear();
    }
  }

  /**
   * Address: 0x0042E252 (FUN_0042E1E0 helper lane)
   *
   * What it does:
   * Clears all pooled world-particle buffer GPU handles during one device
   * reset transition.
   */
  void ResetWorldParticleBuffers()
  {
    for (moho::ParticleBuffer* const particleBuffer : moho::sWorldParticles.PooledBuffers()) {
      if (particleBuffer != nullptr) {
        particleBuffer->Reset();
      }
    }
  }

  /**
   * FAF instrumentation, not in the shipped binary.
   *
   * With FAF_DRAW_STATS_LOG=<frames> in the environment, logs the draw calls,
   * primitives and vertices submitted per frame, averaged over every <frames>
   * frames: figures to compare renderer changes by without driving the UI.
   * An instanced draw counts once, with one instance's primitives.
   */
  class DrawStatisticsLog
  {
  public:
    void AddFrame(const gpg::gal::DrawStatistics& frame)
    {
      if (mInterval < 0) {
        mInterval = ReadInterval();
      }
      if (mInterval == 0) {
        return;
      }

      mDrawCalls += frame.drawCalls;
      mPrimitives += frame.primitives;
      mVertices += frame.vertices;
      if (++mFrames < mInterval) {
        return;
      }

      const double frames = static_cast<double>(mFrames);
      gpg::Logf(
        "Draw stats over %d frames: %.1f draw calls, %.0f primitives, %.0f vertices per frame",
        mFrames, static_cast<double>(mDrawCalls) / frames, static_cast<double>(mPrimitives) / frames,
        static_cast<double>(mVertices) / frames
      );
      LogEntityCounts();
      mFrames = 0;
      mDrawCalls = 0;
      mPrimitives = 0;
      mVertices = 0;
    }

  private:
    /**
     * The id-based entity counts `EntityDB` keeps per family (reserve +1,
     * `~Entity` -1) next to the live object counts `InstanceCounter` keeps,
     * so a growing total shows which kind of entity piles up and whether the
     * objects are really alive. Read-only: a stat nobody has created yet
     * prints as -1.
     */
    static void LogEntityCounts()
    {
      moho::EngineStats* const stats = moho::GetEngineStats();
      if (stats == nullptr) {
        return;
      }
      const auto value = [stats](const char* const path) {
        const moho::StatItem* const item = stats->GetItem(path, false);
        return item != nullptr ? static_cast<int>(item->mPrimaryValueBits) : -1;
      };
      gpg::Logf(
        "Entity counts: ids %d (unit %d, projectile %d, prop %d, blip %d, shield %d, other %d); "
        "live Entity %d, Unit %d, Projectile %d, Prop %d, ReconBlip %d",
        value("EntityCount"), value("EntityCount_Unit"), value("EntityCount_Projectile"),
        value("EntityCount_Prop"), value("EntityCount_Blip"), value("EntityCount_Shield"),
        value("EntityCount_Other"), value("Instance Counts_class moho::Entity"),
        value("Instance Counts_class moho::Unit"), value("Instance Counts_class moho::Projectile"),
        value("Instance Counts_class moho::Prop"), value("Instance Counts_class moho::ReconBlip")
      );
    }

    [[nodiscard]] static int ReadInterval() noexcept
    {
      char text[16] = {};
      std::size_t length = 0;
      if (::getenv_s(&length, text, sizeof(text), "FAF_DRAW_STATS_LOG") != 0 || length == 0u) {
        return 0;
      }
      return std::max(0, std::atoi(text));
    }

    int mInterval = -1; // -1 until the environment has been read
    int mFrames = 0;
    std::uint64_t mDrawCalls = 0;
    std::uint64_t mPrimitives = 0;
    std::uint64_t mVertices = 0;
  };

  DrawStatisticsLog sDrawStatisticsLog;
} // namespace

namespace moho
{
  /**
   * Address: 0x0042DBE0 (FUN_0042DBE0, the scalar deleting destructor)
   * Address: 0x00430DF0 (FUN_00430DF0, the non-deleting body this definition
   *   emits: `~CursorContext`, the four shared handles, both lock arrays,
   *   `~CD3DDeviceResources` (0x00440660) and the broadcaster ring unlink)
   * Address: 0x00430D70 (FUN_00430D70, the interface-level destructor step:
   *   ring unlinked and vptr reset to 0x00E01F04)
   *
   * What it does:
   * Destroys the device's members in reverse order. The field resets the old
   * hand-written body performed do not exist in the binary (0x00430DF0
   * releases members only) and were removed.
   */
  CD3DDevice::~CD3DDevice() = default;

  /**
   * Address: 0x00430C20 (FUN_00430C20, ??0CD3DDevice@Moho@@QAE@XZ)
   * Address: 0x00430D50 (FUN_00430D50, the interface-level constructor step:
   *   vptr 0x00E01F04 and the broadcaster ring at +0x04 self-linked before
   *   this body runs; zero callers, the base-construction step of this one)
   *
   * What it does:
   * Initializes the device's state bytes and embedded resource owner:
   * clear/initialized/scene-open cleared, cursor shown and viewport
   * background drawn by default, software-VP/direct-debug copied from the
   * command-line overrides, then `mResources` handed its owner pointer.
   */
  CD3DDevice::CD3DDevice()
    : mClearEnabled(0)
    , mInitialized(0)
    , mViewport(nullptr)
    , mShowingCursor(1)
    , mDrawViewportBackground(1)
    , mSoftwareVP((d3d_ForceSoftwareVP || d3d_ForceDirect3DDebugEnabled) ? 1u : 0u)
    , mDirectDebug(d3d_ForceDirect3DDebugEnabled ? 1u : 0u)
    , mSceneStarted(0)
  {
    mCurEffect = nullptr;
    mResources.SetDevice(this);
  }

  /**
   * Address: 0x0042EE70 (FUN_0042EE70)
   *
   * What it does:
   * Returns the device's embedded resource owner; the whole binary body is
   * `lea eax, [ecx+0x1C]`.
   */
  ID3DDeviceResources* CD3DDevice::GetResources()
  {
    return &mResources;
  }

  /**
   * Address: 0x0042E1E0 (FUN_0042E1E0, Moho::CD3DDevice::InitContext)
   *
   * What it does:
   * Rebinds one GAL device-context payload, rebuilds per-head writer locks,
   * recreates tracked device resources, and re-emits init callbacks/events.
   *
   * The body from `mInitialized = 0` on runs under
   * `catch (const gpg::gal::Error&)` (FuncInfo 0x00F24DEC: one try block over
   * states 0..5, adjectives 9, catch object at ebp-0x28, handler 0x0042E6CB).
   * The handler warns "%s(%d) %s" (0x00E0196C) and falls through to
   * `return mInitialized`, so a rebind whose `Reset` throws - the device was
   * lost again before `IDirect3DDevice9::Reset` - answers false instead of
   * propagating.
   */
  bool CD3DDevice::InitContext(gpg::gal::DeviceContext* const context)
  {
    if (context == nullptr) {
      return false;
    }

    try {
      mInitialized = 0;

      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const int headCount = context->GetHeadCount();
      const std::size_t lockHeadCount =
        std::min(static_cast<std::size_t>(headCount), std::size(mRenderTargetLocks));

      // false = rebind, not shutdown: keep the batchers, only Reset the mesh
      // renderer. Everything else the viewport holds is released either way,
      // which is what lets `Reset`'s `IDirect3DDevice9::Reset` succeed.
      if (mViewport != nullptr) {
        mViewport->D3DWindowOnDeviceExit(false);
      }

      const moho::SD3DDeviceEvent deviceExitEvent{1u, false, {0u, 0u, 0u}};
      BroadcastEvent(deviceExitEvent);
      ResetResourcesForContextTransition(mResources, false);
      ResetWorldParticleBuffers();

      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        ReleaseHeadWriterLocks(headIndex);
      }

      if (device != nullptr) {
        device->Reset(context);
      }

      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        if (device == nullptr) {
          break;
        }

        // 0x0042E3BE: slot 7, then a copy of the head's output context.
        const gpg::gal::OutputContext outputContext =
          *device->GetHeadOutputContext(static_cast<unsigned int>(headIndex));

        mRenderTargetLocks[headIndex].reset(new moho::CD3DRenderTarget(this, outputContext.surface));
        mDepthStencilLocks[headIndex].reset(new moho::CD3DDepthStencil(this, outputContext.depthStencil));
      }

      mResources.InitResources(false);

      if (mViewport != nullptr) {
        mViewport->D3DWindowOnDeviceInit(false);
      }

      const moho::SD3DDeviceEvent deviceInitEvent{0u, false, {0u, 0u, 0u}};
      BroadcastEvent(deviceInitEvent);

      for (int headIndex = 1; headIndex < headCount; ++headIndex) {
        const gpg::gal::Head& head = context->GetHead(static_cast<unsigned int>(headIndex));
        ::ShowWindow(static_cast<HWND>(head.mWindow), SW_SHOWNORMAL);
      }

      if (mCursorContext.texture_.get() != nullptr && device != nullptr) {
        device->SetCursor(&mCursorContext);
      }

      mInitialized = 1;
    } catch (const gpg::gal::Error& error) {
      gpg::Warnf("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
    return mInitialized != 0;
  }

  /**
   * Address: 0x0042E750 (FUN_0042E750, Moho::CD3DDevice::Destroy)
   *
   * What it does:
   * Emits device-exit callbacks/events, tears down tracked resources and
   * per-head writer locks, resets cursor context lanes, and dispatches backend
   * destroy. The whole body runs under `catch (const gpg::gal::Error&)`
   * (FuncInfo 0x00F1DD54, try over states 0..1): the handler at 0x0042E9A3
   * hands the error's file, line and text to `gpg::Die`.
   */
  void CD3DDevice::Destroy()
  {
    try {
      mInitialized = 0;
      // true = app shutdown (the binary pushes 1 at 0x0042E786): the batchers
      // and the map-imager border go too, and the mesh renderer is fully shut
      // down rather than reset.
      if (mViewport != nullptr) {
        mViewport->D3DWindowOnDeviceExit(true);
      }

      const moho::SD3DDeviceEvent deviceExitEvent{1u, true, {0u, 0u, 0u}};
      BroadcastEvent(deviceExitEvent);
      ResetResourcesForContextTransition(mResources, true);
      mResources.ClearCachedVertexFormats();

      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      int headCount = 0;
      if (device != nullptr) {
        if (gpg::gal::DeviceContext* const context = device->GetDeviceContext(); context != nullptr) {
          headCount = context->GetHeadCount();
        }
      }

      const std::size_t lockHeadCount =
        std::min(static_cast<std::size_t>(headCount), std::size(mRenderTargetLocks));
      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        ReleaseHeadWriterLocks(headIndex);
      }

      // 0x0042E902: back to a default cursor - a temporary context,
      // copy-assigned over the device's.
      mCursorContext = gpg::gal::CursorContext();

      if (device != nullptr) {
        gpg::gal::Device::DestroyInstance();
      }
    } catch (const gpg::gal::Error& error) {
      gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
  }

  /**
   * Inlined block from FUN_0042E1E0 (0x0042E278..0x0042E30D) and the matching
   * lane in FUN_0042E750: the per-head release loop the compiler inlined at
   * each call site, kept out of line here as one named helper.
   *
   * What it does:
   * Drops one head's retained render-target and depth-stencil writer-lock
   * wrappers, resetting their retained surfaces first (surface px nulled at
   * 0x0042E28D, then the handle released).
   */
  void CD3DDevice::ReleaseHeadWriterLocks(const std::size_t headIndex)
  {
    if (auto* const renderTarget = static_cast<CD3DRenderTarget*>(mRenderTargetLocks[headIndex].get());
        renderTarget != nullptr) {
      renderTarget->mSurface.reset();
    }
    mRenderTargetLocks[headIndex].reset();

    if (auto* const depthStencil = static_cast<CD3DDepthStencil*>(mDepthStencilLocks[headIndex].get());
        depthStencil != nullptr) {
      depthStencil->mSurface.reset();
    }
    mDepthStencilLocks[headIndex].reset();
  }

  /**
   * Address: 0x0042DBF0 (FUN_0042DBF0)
   *
   * What it does:
   * Returns the active gal device, or null before one exists.
   */
  gpg::gal::Device* CD3DDevice::GetGalDevice()
  {
    if (!gpg::gal::Device::IsReady()) {
      return nullptr;
    }
    return gpg::gal::Device::GetInstance();
  }

  /**
   * Address: 0x0042DC10 (FUN_0042DC10)
   *
   * What it does:
   * Binds the active render viewport, rebuilds per-head writer-lock wrappers
   * from backend output contexts, refreshes fidelity-support lanes, initializes
   * device resources, and emits one device-init event.
   */
  void CD3DDevice::SetRenViewport(WRenViewport* const viewport)
  {
    mViewport = viewport;

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    if (context == nullptr) {
      return;
    }

    if (moho::CFG_GetArgOption("/softwareinstancing", 0, nullptr)) {
      context->mHWBasedInstancing = false;
    }

    // Every head must carry both formats. The first gates the high shadow
    // fidelity step, the second gates the advanced path outright.
    constexpr std::int32_t kShadowFidelityFormat = 7;
    constexpr std::int32_t kAdvancedFidelityFormat = 17;
    const int headCount = context->GetHeadCount();
    bool supportsAdvancedShadowFidelity = true;
    bool supportsAdvancedFidelity = true;
    if (headCount > 0) {
      for (int headIndex = 0; headIndex < headCount; ++headIndex) {
        const gpg::gal::Head& head = context->GetHead(static_cast<unsigned int>(headIndex));
        supportsAdvancedShadowFidelity =
          supportsAdvancedShadowFidelity && head.HasCapability1(kShadowFidelityFormat);
        supportsAdvancedFidelity = supportsAdvancedFidelity && head.HasCapability2(kAdvancedFidelityFormat);
      }
    }

    // A head missing the advanced format drops straight to the low branch.
    if (supportsAdvancedFidelity && context->mPixelShaderProfile > 5) {
      moho::graphics_FidelitySupported = 2;
      moho::shadow_FidelitySupported = supportsAdvancedShadowFidelity ? 3 : 1;
    } else {
      moho::graphics_FidelitySupported = 1;
      moho::shadow_FidelitySupported = supportsAdvancedShadowFidelity ? 2 : 1;
    }

    const std::size_t lockHeadCount =
      std::min(static_cast<std::size_t>(headCount), std::size(mRenderTargetLocks));
    for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
      ReleaseHeadWriterLocks(headIndex);

      const gpg::gal::OutputContext outputContext =
        *device->GetHeadOutputContext(static_cast<unsigned int>(headIndex));

      mRenderTargetLocks[headIndex].reset(new moho::CD3DRenderTarget(this, outputContext.surface));
      mDepthStencilLocks[headIndex].reset(new moho::CD3DDepthStencil(this, outputContext.depthStencil));
    }

    // 0x0042DFC8: `push 0x28; call operator new; call 0x0043EBC0` - a fresh
    // default `CD3DRenderTarget` (0x28 bytes), then the same for the depth
    // stencil.
    mRenderTarget.reset(new moho::CD3DRenderTarget());
    mDepthStencil.reset(new moho::CD3DDepthStencil());

    mResources.InitResources(true);

    mDrawViewportBackground = 0u;
    const moho::SD3DDeviceEvent deviceInitEvent{0u, true, {0u, 0u, 0u}};
    BroadcastEvent(deviceInitEvent);

    if (mViewport != nullptr) {
      mViewport->D3DWindowOnDeviceInit(true);
    }
    mInitialized = 1u;
  }

  /**
   * Address: 0x0042E9D0 (FUN_0042E9D0)
   *
   * What it does:
   * Returns the currently bound render viewport pointer.
   */
  WRenViewport* CD3DDevice::GetViewport()
  {
    return mViewport;
  }

  /**
   * Address: 0x0042E9E0 (FUN_0042E9E0)
   *
   * What it does:
   * Triggers a viewport refresh for the active device window and reports success.
   */
  bool CD3DDevice::Refresh()
  {
    if (WRenViewport* const viewport = GetViewport(); viewport != nullptr) {
      viewport->Refresh(true, nullptr);
    }
    return true;
  }

  /**
   * Address: 0x0042E720 (FUN_0042E720)
   *
   * What it does:
   * Initializes this device by forwarding the active GAL device context to
   * the virtual `InitContext` lane.
   */
  void CD3DDevice::Init()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    (void)InitContext(context);
  }

  /**
   * Address: 0x0042EA00 (FUN_0042EA00)
   *
   * unsigned int
   *
   * What it does:
   * Returns one head width from the active GAL device context.
   */
  int CD3DDevice::GetHeadWidth(const unsigned int headIndex)
  {
    if (!gpg::gal::Device::IsReady()) {
      return 0;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    return static_cast<int>(context->GetHead(headIndex).mWidth);
  }

  /**
   * Address: 0x0042EA30 (FUN_0042EA30)
   *
   * unsigned int
   *
   * What it does:
   * Returns one head height from the active GAL device context.
   */
  int CD3DDevice::GetHeadHeight(const unsigned int headIndex)
  {
    if (!gpg::gal::Device::IsReady()) {
      return 0;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    return static_cast<int>(context->GetHead(headIndex).mHeight);
  }

  /**
   * Address: 0x0042EAE0 (FUN_0042EAE0)
   *
   * What it does:
   * Re-applies the hardware cursor through the active gal device's slot 32
   * (`InitCursor`) when there is one. The viewport's window procedure calls it
   * for WM_SETCURSOR over the client area (0x00430BC4). This used to be a
   * static `gpg::gal::Device::InitCursor` that cast the device to the D3D9
   * backend; a gal static cannot share the virtual's name, and the body lives
   * with the render device here, not in the gal library.
   */
  void D3D_InitCursor()
  {
    if (gpg::gal::Device::IsReady()) {
      gpg::gal::Device::GetInstance()->InitCursor();
    }
  }

  /**
   * Address: 0x0042EA60 (FUN_0042EA60)
   *
   * Wm3::Vector2i *,int
   *
   * What it does:
   * Writes one `(width,height)` pair into caller-provided output vector.
   */
  Wm3::Vector2i* CD3DDevice::GetSize(Wm3::Vector2i* const outSize, const int headIndex)
  {
    const int height = GetHeadHeight(headIndex);
    outSize->x = GetHeadWidth(headIndex);
    outSize->y = height;
    return outSize;
  }

  /**
   * Address: 0x0042EA90 (FUN_0042EA90)
   *
   * int
   *
   * What it does:
   * Returns one head aspect ratio as `width / height`.
   */
  double CD3DDevice::GetAspectRatio(const int headIndex)
  {
    const float width = static_cast<float>(static_cast<unsigned int>(GetHeadWidth(headIndex)));
    return width / static_cast<double>(static_cast<unsigned int>(GetHeadHeight(headIndex)));
  }

  /**
   * Address: 0x0042ED50 (FUN_0042ED50)
   *
   * Wm3::Vector2i *,Wm3::Vector2i *,float *,float *
   *
   * What it does:
   * Reads the active viewport and exports origin/size/depth range.
   */
  void CD3DDevice::GetView(
    Wm3::Vector2i* const outPos,
    Wm3::Vector2i* const outSize,
    float* const outMinZ,
    float* const outMaxZ
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    D3DVIEWPORT9 viewport{};
    viewport.MaxZ = 1.0f;
    device->GetViewport(&viewport);

    outPos->x = static_cast<int>(viewport.X);
    outPos->y = static_cast<int>(viewport.Y);
    outSize->x = static_cast<int>(viewport.Width);
    outSize->y = static_cast<int>(viewport.Height);
    *outMinZ = viewport.MinZ;
    *outMaxZ = viewport.MaxZ;
  }

  /**
   * Address: 0x0042EDE0 (FUN_0042EDE0)
   *
   * Wm3::Vector2i *,Wm3::Vector2i *,float,float
   *
   * What it does:
   * Applies one viewport payload onto the active GAL backend.
   */
  void CD3DDevice::SetViewport(
    Wm3::Vector2i* const pos, Wm3::Vector2i* const size, const float minZ, const float maxZ
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    D3DVIEWPORT9 viewport{};
    viewport.X = static_cast<DWORD>(pos->x);
    viewport.Y = static_cast<DWORD>(pos->y);
    viewport.Width = static_cast<DWORD>(size->x);
    viewport.Height = static_cast<DWORD>(size->y);
    viewport.MinZ = minZ;
    viewport.MaxZ = maxZ;
    device->SetViewport(&viewport);
  }

  /**
   * Address: 0x004310D0 (FUN_004310D0, Moho::CD3DDevice::Func9)
   *
   * boost::shared_ptr<moho::CD3DDynamicTextureSheet> &,moho::ID3DTextureSheet *,boost::detail::sp_counted_base *,int,bool
   *
   * What it does:
   * Creates one dynamic texture sheet from source dimensions (archive or
   * runtime lane), copies source pixels into the destination texture, and
   * releases caller-provided shared-count guard.
   */
  boost::shared_ptr<CD3DDynamicTextureSheet>& CD3DDevice::CreateDynamicTextureSheetFromSource(
    boost::shared_ptr<CD3DDynamicTextureSheet>& outSheet,
    ID3DTextureSheet* const sourceTextureSheet,
    boost::detail::sp_counted_base* const sourceSheetGuard,
    const int format,
    const bool archiveMode
  )
  {
    outSheet.reset();

    if (sourceTextureSheet != nullptr) {
      Wm3::Vector3f dimensions{};
      sourceTextureSheet->GetDimensions(&dimensions);

      ID3DDeviceResources* const resources = GetResources();
      if (resources != nullptr) {
        const int width = static_cast<int>(dimensions.x);
        const int height = static_cast<int>(dimensions.y);
        if (archiveMode) {
          (void)resources->CreateDynamicTextureSheet(outSheet, width, height, format);
        } else {
          (void)resources->NewDynamicTextureSheet(outSheet, width, height, format);
        }
      }

      if (gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
          device != nullptr && outSheet.get() != nullptr) {
        ID3DTextureSheet::TextureHandle destinationTexture{};
        outSheet->GetTexture(destinationTexture);

        ID3DTextureSheet::TextureHandle sourceTexture{};
        sourceTextureSheet->GetTexture(sourceTexture);

        if (sourceTexture.get() != nullptr && destinationTexture.get() != nullptr) {
          device->UpdateSurface(sourceTexture, destinationTexture, nullptr, nullptr);
        }
      }
    }

    if (sourceSheetGuard != nullptr) {
      sourceSheetGuard->release();
    }

    return outSheet;
  }

  /**
   * Address: 0x0042EB40 (FUN_0042EB40)
   *
   * What it does:
   * Points the hardware cursor at the sheet's texture with the given hotspot
   * and hands the context to the device (slot 31, `[vtbl+0x7C]` at
   * 0x0042ECD5). The sheet's texture is fetched twice, once to test it and
   * once to store it. A `gpg::gal::Error` - the only handler in the EH table
   * (FuncInfo 0x00EDDF14) - is swallowed and reported as `false`.
   */
  bool CD3DDevice::SetCursor(
    const int hotspotX, const int hotspotY, const boost::shared_ptr<ID3DTextureSheet> cursorTexture
  )
  {
    bool isSet = false;
    try {
      ID3DTextureSheet::TextureHandle probe{};
      if (!gpg::gal::Device::IsReady() || cursorTexture.get() == nullptr ||
          cursorTexture->GetTexture(probe).get() == nullptr) {
        return false;
      }

      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      mCursorContext.hotspotX_ = hotspotX;
      mCursorContext.hotspotY_ = hotspotY;
      ID3DTextureSheet::TextureHandle cursorPixels{};
      mCursorContext.texture_ = cursorTexture->GetTexture(cursorPixels);
      device->SetCursor(&mCursorContext);
      isSet = true;
    } catch (const gpg::gal::Error&) {
    }

    return isSet;
  }

  /**
   * Address: 0x0042EB00 (FUN_0042EB00)
   *
   * bool
   *
   * What it does:
   * Shows or hides cursor through backend dispatch and updates local cursor state.
   */
  int CD3DDevice::ShowCursor(const bool show)
  {
    int result = gpg::gal::Device::IsReady() ? 1 : 0;
    if (result != 0) {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      result = device->ShowCursor(show);
      mShowingCursor = show ? 1u : 0u;
    }
    return result;
  }

  [[nodiscard]] bool CD3DDevice::IsCursorPixelSourceReady() const
  {
    return mCursorContext.texture_.get() != nullptr;
  }

  [[nodiscard]] bool CD3DDevice::IsCursorShowing() const
  {
    return mShowingCursor != 0;
  }

  [[nodiscard]] bool CD3DDevice::ShouldDrawViewportBackground() const
  {
    return mDrawViewportBackground != 0;
  }

  /**
   * Address: 0x0042EE80 (FUN_0042EE80)
   *
   * boost::shared_ptr<moho::ID3DRenderTarget> &,int
   *
   * What it does:
   * Copies one retained render-target writer lock from indexed device storage.
   */
  boost::shared_ptr<ID3DRenderTarget>&
  CD3DDevice::GetWriterLock1(boost::shared_ptr<ID3DRenderTarget>& outLock, const int index)
  {
    const auto& source = mRenderTargetLocks[static_cast<std::size_t>(index)];
    return CopyRetainedHandle(source, outLock);
  }

  /**
   * Address: 0x0042EEB0 (FUN_0042EEB0)
   *
   * boost::shared_ptr<moho::ID3DDepthStencil> &,int
   *
   * What it does:
   * Copies one retained depth-stencil writer lock from indexed device storage.
   */
  boost::shared_ptr<ID3DDepthStencil>&
  CD3DDevice::GetWriterLock2(boost::shared_ptr<ID3DDepthStencil>& outLock, const int index)
  {
    const auto& source = mDepthStencilLocks[static_cast<std::size_t>(index)];
    return CopyRetainedHandle(source, outLock);
  }

  /**
   * Address: 0x0042EEE0 (FUN_0042EEE0)
   *
   * boost::shared_ptr<void> &
   *
   * What it does:
   * Copies one retained generic shared handle from runtime state lane #1.
   */
  boost::shared_ptr<void>& CD3DDevice::Func16(boost::shared_ptr<void>& outHandle)
  {
    return CopyRetainedHandle(mWriterLockContext1, outHandle);
  }

  /**
   * Address: 0x0042EF10 (FUN_0042EF10)
   *
   * boost::shared_ptr<void> &
   *
   * What it does:
   * Copies one retained generic shared handle from runtime state lane #2.
   */
  boost::shared_ptr<void>& CD3DDevice::Func17(boost::shared_ptr<void>& outHandle)
  {
    return CopyRetainedHandle(mWriterLockContext2, outHandle);
  }

  /**
   * Address: 0x0042EF40 (FUN_0042EF40)
   *
   * What it does:
   * Copies the device's own render-target wrapper handle from runtime state.
   */
  boost::shared_ptr<CD3DRenderTarget>& CD3DDevice::GetRenderTarget(boost::shared_ptr<CD3DRenderTarget>& outTarget)
  {
    return CopyRetainedHandle(mRenderTarget, outTarget);
  }

  /**
   * Address: 0x0042EF70 (FUN_0042EF70)
   *
   * boost::shared_ptr<moho::CD3DDepthStencil> &
   *
   * What it does:
   * Copies one active depth-stencil handle from runtime state.
   */
  boost::shared_ptr<CD3DDepthStencil>&
  CD3DDevice::GetDepthStencil(boost::shared_ptr<CD3DDepthStencil>& outDepthStencil)
  {
    return CopyRetainedHandle(mDepthStencil, outDepthStencil);
  }

  /**
   * Address: 0x0042EFC0 (FUN_0042EFC0)
   *
   * int,bool,int,float,int
   *
   * What it does:
   * Acquires indexed writer locks and dispatches `BeginScene1`.
   */
  void CD3DDevice::BeginScene2(const int index, const bool clear, const int color, const float zValue, const int stencil)
  {
    boost::shared_ptr<ID3DDepthStencil> writerLock2{};
    (void)GetWriterLock2(writerLock2, index);

    boost::shared_ptr<ID3DRenderTarget> writerLock1{};
    (void)GetWriterLock1(writerLock1, index);

    BeginScene1(writerLock1.get(), writerLock2.get(), clear, color, zValue, stencil);
  }

  /**
   * Address: 0x0042F0C0 (FUN_0042F0C0)
   *
   * moho::ID3DRenderTarget *,moho::ID3DDepthStencil *,bool,int,float,int
   *
   * What it does:
   * Builds output/depth context bindings, clears target lanes, begins a scene,
   * then applies one clear payload and marks scene state as active.
   */
  void CD3DDevice::BeginScene1(
    ID3DRenderTarget* const renderTarget,
    ID3DDepthStencil* const depthStencil,
    const bool clear,
    const int color,
    const float zValue,
    const int stencil
  )
  {
    if (mSceneStarted != 0) {
      return;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    ID3DRenderTarget::SurfaceHandle renderSurface{};
    renderTarget->GetSurface(renderSurface);
    ID3DDepthStencil::SurfaceHandle depthSurface{};
    depthStencil->GetSurface(depthSurface);

    const gpg::gal::OutputContext outputContext(renderSurface, depthSurface);
    device->ClearTarget(&outputContext);
    (void)device->BeginScene();
    device->Clear(clear, clear, clear, static_cast<std::uint32_t>(color), zValue, stencil);
    mSceneStarted = 1;
  }

  /**
   * Address: 0x0042EFA0 (FUN_0042EFA0)
   *
   * What it does:
   * Begins one backend scene only when scene state is not active.
   */
  void CD3DDevice::BeginScene()
  {
    if (mSceneStarted != 0) {
      return;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    (void)device->BeginScene();
    mSceneStarted = 1;
  }

  /**
   * Address: 0x0042F360 (FUN_0042F360)
   *
   * What it does:
   * Ends active backend scene and clears local scene-active state.
   */
  void CD3DDevice::EndScene()
  {
    if (mSceneStarted == 0) {
      return;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    device->EndScene();
    mSceneStarted = 0;
  }

  /**
   * Address: 0x0042F1A0 (FUN_0042F1A0)
   *
   * int,bool,int,float,int
   *
   * What it does:
   * Acquires indexed writer locks and dispatches `SetRenderTarget1`.
   */
  void CD3DDevice::SetRenderTarget2(
    const int index, const bool clear, const int color, const float zValue, const int stencil
  )
  {
    boost::shared_ptr<ID3DDepthStencil> writerLock2{};
    (void)GetWriterLock2(writerLock2, index);

    boost::shared_ptr<ID3DRenderTarget> writerLock1{};
    (void)GetWriterLock1(writerLock1, index);

    SetRenderTarget1(writerLock1.get(), writerLock2.get(), clear, color, zValue, stencil);
  }

  /**
   * Address: 0x0042F2A0 (FUN_0042F2A0)
   *
   * moho::ID3DRenderTarget *,moho::ID3DDepthStencil *,bool,int,float,int
   *
   * What it does:
   * Applies output/depth context bindings and issues one backend clear payload.
   */
  void CD3DDevice::SetRenderTarget1(
    ID3DRenderTarget* const renderTarget,
    ID3DDepthStencil* const depthStencil,
    const bool clear,
    const int color,
    const float zValue,
    const int stencil
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    ID3DRenderTarget::SurfaceHandle renderSurface{};
    renderTarget->GetSurface(renderSurface);
    ID3DDepthStencil::SurfaceHandle depthSurface{};
    depthStencil->GetSurface(depthSurface);

    const gpg::gal::OutputContext outputContext(renderSurface, depthSurface);
    device->ClearTarget(&outputContext);
    device->Clear(clear, clear, clear, static_cast<std::uint32_t>(color), zValue, stencil);
  }

  /**
   * Address: 0x0042F380 (FUN_0042F380)
   *
   * What it does:
   * Lazily binds render stat lanes and resets all tracked render counters.
   */
  int CD3DDevice::InitRenderEngineStats()
  {
    int result = 0;
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderPresentCount, "Render_PresentCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderPrimitiveCount, "Render_PrimitiveCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderVertexCount, "Render_VertexCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderDrawPrimCalls, "Render_DrawPrimCalls"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderUnitPrimitiveCount, "Render_UnitPrimitiveCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderUnitVertexCount, "Render_UnitVertexCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderQuadBatchCount, "Render_QuadBatchCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderTextBatchCount, "Render_TextBatchCount"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderFlatDecals, "Render_FlatDecals"));
    result = ResetStatCounter(EnsureEngineIntStat(sEngineStatRenderDecals, "Render_Decals"));
    return result;
  }

  /**
   * FAF instrumentation - not a recovered function.
   *
   * What it does:
   * See the header. The shipped engine resets these three stats every frame
   * and `ShowStats` displays them, but its release build never increments
   * them: `AddPrimStats` / `AddVertexStats` survive only through the vtable
   * (their StatItem slots, 0x010C6300..0x010C630C, are referenced by nothing
   * else), and no code in the binary writes `Render_DrawPrimCalls` beyond
   * `InitRenderEngineStats`' reset. The primitive and vertex figures go through
   * those adders, so they land in the same named stats the engine resets.
   */
  void CD3DDevice::PublishDrawStatistics()
  {
    const gpg::gal::DrawStatistics submitted = gpg::gal::TakeDrawStatistics();
    (void)AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderDrawPrimCalls, "Render_DrawPrimCalls"), submitted.drawCalls);
    (void)AddPrimStats(submitted.primitives, false);
    (void)AddVertexStats(submitted.vertices, false);
    sDrawStatisticsLog.AddFrame(submitted);
  }

  /**
   * Address: 0x0042F6A0 (FUN_0042F6A0)
   *
   * unsigned int,bool
   *
   * What it does:
   * Adds primitive-count stats, with optional unit-primitive lane update.
   */
  int CD3DDevice::AddPrimStats(const unsigned int amount, const bool unitPrimitive)
  {
    int result = AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderPrimitiveCount, "Render_PrimitiveCount"), amount);
    if (unitPrimitive) {
      (void)AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderUnitPrimitiveCount, "Render_UnitPrimitiveCount"), amount);
    }
    return result;
  }

  /**
   * Address: 0x0042F720 (FUN_0042F720)
   *
   * unsigned int,bool
   *
   * What it does:
   * Adds vertex-count stats, with optional unit-vertex lane update.
   */
  int CD3DDevice::AddVertexStats(const unsigned int amount, const bool unitVertex)
  {
    int result = AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderVertexCount, "Render_VertexCount"), amount);
    if (unitVertex) {
      (void)AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderUnitVertexCount, "Render_UnitVertexCount"), amount);
    }
    return result;
  }

  /**
   * Address: 0x0042F7A0 (FUN_0042F7A0)
   *
   * unsigned int
   *
   * What it does:
   * Adds one quad-batch count delta to render stats.
   */
  int CD3DDevice::AddQuadBatchCount(const unsigned int amount)
  {
    return AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderQuadBatchCount, "Render_QuadBatchCount"), amount);
  }

  /**
   * Address: 0x0042F7E0 (FUN_0042F7E0)
   *
   * unsigned int
   *
   * What it does:
   * Adds one text-batch count delta to render stats.
   */
  int CD3DDevice::AddTextBatchStats(const unsigned int amount)
  {
    return AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderTextBatchCount, "Render_TextBatchCount"), amount);
  }

  /**
   * Address: 0x0042F820 (FUN_0042F820)
   *
   * int
   *
   * What it does:
   * Applies one packed anti-aliasing sample option to all heads, then rebuilds
   * device context through `InitContext`.
   */
  void CD3DDevice::SetAntiAliasingSamples(const int sampleCount)
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = device->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context = *activeContext;
    const int headCount = context.GetHeadCount();
    for (int headIndex = 0; headIndex < headCount; ++headIndex) {
      gpg::gal::Head& head = context.GetHead(static_cast<std::uint32_t>(headIndex));
      head.antialiasingHigh = static_cast<std::uint32_t>(sampleCount >> 5);
      head.antialiasingLow = static_cast<std::uint32_t>(sampleCount & 0x1F);
    }

    (void)InitContext(&context);
  }

  /**
   * Address: 0x0042FB90 (FUN_0042FB90)
   *
   * moho::ID3DVertexSheet *,moho::ID3DIndexSheet *,D3DPRIMITIVETYPE *
   *
   * What it does:
   * Binds one vertex/index sheet pair, iterates active effect passes, and
   * submits one indexed draw context with zero start/base offsets.
   *
   * Two nested `catch (const gpg::gal::Error&)` blocks (FuncInfo 0x00F188A0),
   * both fatal through `gpg::Die`: the outer try (states 0..3, handler
   * 0x0042FCBE) covers everything after the device lookup, the inner one
   * (states 1..2, handler 0x0042FC77) only each pass's draw.
   */
  bool CD3DDevice::DrawIndexedSheetPrimitive(
    ID3DVertexSheet* const vertexSheet, ID3DIndexSheet* const indexSheet, std::int32_t* const primitiveType
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    try {
      vertexSheet->Func9();
      indexSheet->SetBufferIndices();

      gpg::gal::EffectTechnique* const technique = GetCurEffect()->mCurrentTechnique.get();
      const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
      for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
        technique->BeginPass(static_cast<int>(passIndex));

        try {
          // 0x0042FC32: the five-argument constructor, so the sheet's vertex count
          // is the vertex count and the index sheet's size the index count.
          gpg::gal::DrawIndexedContext drawContext(
            static_cast<gpg::gal::DrawContext::TOPOLOGY>(*primitiveType),
            static_cast<std::uint32_t>(vertexSheet->Func5()),
            indexSheet->GetSize(),
            0U,
            0U
          );
          (void)device->DrawIndexedPrimitive(&drawContext);
        } catch (const gpg::gal::Error& error) {
          gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
        }

        technique->EndPass();
      }
      technique->EndTechnique();
    } catch (const gpg::gal::Error& error) {
      gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
    return true;
  }

  /**
   * Address: 0x0042F8D0 (FUN_0042F8D0)
   *
   * CD3DVertexSheet::View const *,D3DPRIMITIVETYPE *
   *
   * What it does:
   * Binds one vertex-sheet view, iterates active effect passes, and submits one
   * non-indexed primitive draw per pass.
   *
   * Two nested `catch (const gpg::gal::Error&)` blocks (FuncInfo 0x00F189C8),
   * both fatal through `gpg::Die`: the outer try (states 0..3, handler
   * 0x0042F9E4) covers everything after the device lookup, the inner one
   * (states 1..2, handler 0x0042F994) only each pass's draw.
   */
  bool CD3DDevice::DrawPrimitiveList(
    const SD3DVertexRange* const vertexSheetView, std::int32_t* const primitiveType
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    try {
      vertexSheetView->sheet->Func9();

      gpg::gal::EffectTechnique* const technique = GetCurEffect()->mCurrentTechnique.get();
      const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
      for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
        technique->BeginPass(static_cast<int>(passIndex));

        try {
          // The first vertex is the view's base vertex (+0x04), not its start.
          gpg::gal::DrawContext drawContext(
            static_cast<gpg::gal::DrawContext::TOPOLOGY>(*primitiveType),
            static_cast<std::uint32_t>((vertexSheetView->endVertex - vertexSheetView->startVertex) + 1),
            static_cast<std::uint32_t>(vertexSheetView->baseVertex)
          );
          (void)device->DrawPrimitive(&drawContext);
        } catch (const gpg::gal::Error& error) {
          gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
        }

        technique->EndPass();
      }
      technique->EndTechnique();
    } catch (const gpg::gal::Error& error) {
      gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
    return true;
  }

  /**
   * Address: 0x0042FA10 (FUN_0042FA10)
   *
   * CD3DVertexSheet::View const *,CD3DIndexSheet::View const *,D3DPRIMITIVETYPE *
   *
   * What it does:
   * Binds vertex/index views, iterates active effect passes, and submits one
   * indexed primitive draw per pass.
   *
   * Two nested `catch (const gpg::gal::Error&)` blocks (FuncInfo 0x00F18934),
   * both fatal through `gpg::Die`: the outer try (states 0..3, handler
   * 0x0042FB5E) covers everything after the device lookup, the inner one
   * (states 1..2, handler 0x0042FB0E) only each pass's draw.
   */
  bool CD3DDevice::DrawTriangleList(
    const SD3DVertexRange* const vertexSheetView,
    const SD3DIndexRange* const indexSheetView,
    std::int32_t* const primitiveType
  )
  {
    const int vertexCount = (vertexSheetView->endVertex - vertexSheetView->startVertex) + 1;
    if (vertexCount == 0) {
      return true;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    try {
      vertexSheetView->sheet->Func9();
      indexSheetView->sheet->SetBufferIndices();

      gpg::gal::EffectTechnique* const technique = GetCurEffect()->mCurrentTechnique.get();
      const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
      for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
        technique->BeginPass(static_cast<int>(passIndex));

        try {
          gpg::gal::DrawIndexedContext drawContext(
            static_cast<gpg::gal::DrawContext::TOPOLOGY>(*primitiveType),
            static_cast<std::uint32_t>(vertexSheetView->startVertex),
            static_cast<std::uint32_t>(vertexCount),
            static_cast<std::uint32_t>(indexSheetView->indexCount),
            static_cast<std::uint32_t>(indexSheetView->startIndex),
            vertexSheetView->baseVertex
          );
          (void)device->DrawIndexedPrimitive(&drawContext);
        } catch (const gpg::gal::Error& error) {
          gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
        }

        technique->EndPass();
      }
      technique->EndTechnique();
    } catch (const gpg::gal::Error& error) {
      gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
    return true;
  }

  /**
   * Address: 0x0042FCF0 (FUN_0042FCF0)
   *
   * bool,bool
   *
   * What it does:
   * Forwards color-write toggles to the active GAL backend when ready.
   */
  void CD3DDevice::SetColorWriteState(const bool colorWrite0, const bool colorWrite1)
  {
    if (!gpg::gal::Device::IsReady()) {
      return;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    (void)device->SetColorWriteState(colorWrite0, colorWrite1);
  }

  /**
   * Address: 0x0042FD40 (FUN_0042FD40)
   *
   * CD3DEffect *
   *
   * What it does:
   * Stores one active effect pointer for subsequent technique selection/draw.
   */
  bool CD3DDevice::SetCurEffect(CD3DEffect* const effect)
  {
    mCurEffect = effect;
    return effect != nullptr;
  }

  /**
   * Address: 0x0042FD10 (FUN_0042FD10)
   *
   * const char *
   *
   * What it does:
   * Resolves one effect by name from device resources and sets it as current.
   */
  bool CD3DDevice::SelectFxFile(const char* const fxFileName)
  {
    ID3DDeviceResources* const resources = GetResources();
    CD3DEffect* const effect = resources != nullptr ? resources->FindEffect(fxFileName) : nullptr;
    return SetCurEffect(effect);
  }

  /**
   * Address: 0x0042FD60 (FUN_0042FD60)
   *
   * const char *
   *
   * What it does:
   * Selects one technique on the currently active effect.
   */
  bool CD3DDevice::SelectTechnique(const char* const techniqueName)
  {
    CD3DEffect* const effect = GetCurEffect();
    if (effect == nullptr) {
      return false;
    }

    effect->SetTechnique(techniqueName);
    return true;
  }

  /**
   * Address: 0x0042FD80 (FUN_0042FD80)
   *
   * What it does:
   * Returns the currently selected effect pointer from runtime state.
   */
  CD3DEffect* CD3DDevice::GetCurEffect()
  {
    return mCurEffect;
  }

  /**
   * Address: 0x0042FD90 (FUN_0042FD90)
   *
   * What it does:
   * Returns the active backend render-thread identifier.
   */
  int CD3DDevice::GetCurThreadId()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    return device->GetCurThreadId();
  }

  /**
   * Address: 0x0042FDA0 (FUN_0042FDA0)
   *
   * CD3DDynamicTextureSheet *,CD3DDynamicTextureSheet *,RECT const *,RECT const *
   *
   * What it does:
   * Copies one source texture sheet surface region into destination texture sheet.
   */
  void CD3DDevice::UpdateSurface(
    CD3DDynamicTextureSheet* const sourceSheet,
    CD3DDynamicTextureSheet* const destinationSheet,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    ID3DTextureSheet::TextureHandle destinationTexture{};
    destinationSheet->GetTexture(destinationTexture);
    ID3DTextureSheet::TextureHandle sourceTexture{};
    sourceSheet->GetTexture(sourceTexture);

    device->UpdateSurface(sourceTexture, destinationTexture, sourceRect, destinationRect);
  }

  /**
   * Address: 0x0042FE90 (FUN_0042FE90)
   *
   * CD3DDynamicTextureSheet **,CD3DDynamicTextureSheet **
   *
   * What it does:
   * Forwards sheet handles to `UpdateSurface` with default whole-surface rectangles.
   */
  void CD3DDevice::UpdateSurface2(
    CD3DDynamicTextureSheet** const sourceSheet, CD3DDynamicTextureSheet** const destinationSheet
  )
  {
    UpdateSurface(*sourceSheet, *destinationSheet, nullptr, nullptr);
  }

  /**
   * Address: 0x0042FEB0 (FUN_0042FEB0)
   *
   * moho::ID3DRenderTarget *,moho::ID3DRenderTarget *,RECT const *,RECT const *
   *
   * What it does:
   * Resolves source/destination render-target surfaces and forwards one
   * rectangle blit to backend `StretchRect`.
   */
  void CD3DDevice::SetViewRect(
    ID3DRenderTarget* const sourceRenderTarget,
    ID3DRenderTarget* const destinationRenderTarget,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    ID3DRenderTarget::SurfaceHandle destinationSurface{};
    destinationRenderTarget->GetSurface(destinationSurface);
    ID3DRenderTarget::SurfaceHandle sourceSurface{};
    sourceRenderTarget->GetSurface(sourceSurface);

    // Slot 18 (`[vtbl+0x48]` at 0x0042FF13) on the base device, with the two
    // surface handles passed by reference.
    device->StretchRect(sourceSurface, destinationSurface, sourceRect, destinationRect);
  }

  /**
   * Address: 0x0042FFA0 (FUN_0042FFA0)
   *
   * moho::ID3DRenderTarget **,moho::ID3DRenderTarget **
   *
   * What it does:
   * Dereferences render-target lanes and forwards to `SetViewRect`.
   */
  void CD3DDevice::SetViewRect2(
    ID3DRenderTarget** const sourceRenderTarget, ID3DRenderTarget** const destinationRenderTarget
  )
  {
    SetViewRect(*sourceRenderTarget, *destinationRenderTarget, nullptr, nullptr);
  }

  /**
   * Address: 0x0042FFC0 (FUN_0042FFC0)
   *
   * moho::ID3DRenderTarget *,moho::ID3DTextureSheet *
   *
   * What it does:
   * Resolves source render-target and destination texture lanes, then forwards
   * one backend `CreateRenderTarget` copy.
   */
  void CD3DDevice::SetViewRenderTarget(
    ID3DRenderTarget* const sourceRenderTarget, ID3DTextureSheet* const destinationTextureSheet
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();

    ID3DTextureSheet::TextureHandle destinationTexture{};
    destinationTextureSheet->GetTexture(destinationTexture);
    ID3DRenderTarget::SurfaceHandle sourceSurface{};
    sourceRenderTarget->GetSurface(sourceSurface);

    device->GetRenderTargetData(sourceSurface, destinationTexture);
  }

  /**
   * Address: 0x004300B0 (FUN_004300B0)
   *
   * moho::ID3DRenderTarget **,moho::ID3DTextureSheet **
   *
   * What it does:
   * Dereferences source/destination lanes and forwards to
   * `SetViewRenderTarget`.
   */
  void CD3DDevice::SetViewRenderTarget2(
    ID3DRenderTarget** const sourceRenderTarget, ID3DTextureSheet** const destinationTextureSheet
  )
  {
    SetViewRenderTarget(*sourceRenderTarget, *destinationTextureSheet);
  }

  /**
   * Address: 0x004300E0 (FUN_004300E0)
   *
   * What it does:
   * Clears active render targets/depth/stencil with opaque black, and swallows
   * a gal::Error if the device refuses.
   *
   * The catch is not defensive padding - it is in the shipped binary and it is
   * load-bearing. `__ehfuncinfo` at 0x00EC2D50 describes one try block with one
   * handler whose type is `.?AVError@gal@gpg@@` and whose adjectives are 0x9
   * (const + reference) with dispCatchObj 0, i.e. `catch (const gal::Error&)`
   * with an unnamed parameter; the handler funclet at 0x00430158 does nothing
   * but return the address of the epilogue.
   *
   * It matters because this is called from the frame's WM_SIZE handler, which
   * runs between frames. The swapchain is created with EnableAutoDepthStencil
   * = 0 (GetHeadParameters, 0x008E82B0), so the only depth-stencil is whatever
   * the last render pass bound - and a UI-only pass binds none. Clearing Z and
   * stencil with no depth-stencil surface attached is D3DERR_INVALIDCALL, so
   * on that path this throw is the expected outcome, not an error.
   */
  void CD3DDevice::Clear()
  {
    if (!gpg::gal::Device::IsReady()) {
      return;
    }

    try {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      (void)device->BeginScene();
      device->Clear(true, true, true, 0xFF000000u, 1.0f, 0);
      device->EndScene();
    } catch (const gpg::gal::Error&) {
    }
  }

  /**
   * Address: 0x004300D0 (FUN_004300D0)
   *
   * bool
   *
   * What it does:
   * Stores one clear-enable state byte on the device object.
   */
  bool CD3DDevice::Clear2(const bool clear)
  {
    mClearEnabled = clear ? 1u : 0u;
    return clear;
  }

  /**
   * Address: 0x00430F90 (FUN_00430F90, Moho::CD3DDevice::Paint)
   *
   * What it does:
   * Presents one device frame when the device/runtime viewport is active, then
   * dispatches either clear or viewport render callback.
   *
   * Everything after the device lookup runs under
   * `catch (const gpg::gal::Error&)` (FuncInfo 0x00F0EB3C: one try block over
   * state 0, adjectives 9, catch object at ebp-0x14, handler 0x00431097). The
   * handler warns "%s(%d) %s" (0x00E0196C), clears the scene-open byte at +0x18
   * and leaves through the normal epilogue. This is how retail survives a
   * restore from minimized: `TestCooperativeLevel` can still answer D3D_OK
   * while `Present` (0x008ED640) already fails with D3DERR_DEVICELOST and
   * throws from DeviceD3D9.cpp line 937; the next paint then sees
   * D3DERR_DEVICENOTRESET and resets through `InitContext`.
   */
  void CD3DDevice::Paint()
  {
    if (mInitialized == 0 || !gpg::gal::Device::IsReady() || mViewport == nullptr) {
      return;
    }

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    try {
      const int coop = device->TestCooperativeLevel();
      if (coop == 2) {
        return;
      }
      if (coop == 1) {
        gpg::gal::DeviceContext* const context = device->GetDeviceContext();
        (void)InitContext(context);
      }

      device->Present();
      (void)AddToStatCounter(EnsureEngineIntStat(sEngineStatRenderPresentCount, "Render_PresentCount"), 1);

      if (mClearEnabled != 0) {
        Clear();
      } else {
        mViewport->D3DWindowOnDeviceRender();
      }
    } catch (const gpg::gal::Error& error) {
      gpg::Warnf("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
      mSceneStarted = 0;
    }
  }

  /**
   * Address: 0x00430590 (FUN_00430590, ?D3D_GetDevice@Moho@@YAPAVCD3DDevice@1@XZ)
   *
   * What it does:
   * Returns the global D3D-device singleton used by render/bootstrap paths.
   */
  CD3DDevice* D3D_GetDevice()
  {
    static CD3DDevice sDevice;
    return &sDevice;
  }

  /**
   * Address: 0x004305F0 (FUN_004305F0, ?REN_Init@Moho@@YAXXZ)
   *
   * What it does:
   * Enumerates `/fonts/*.ttf`, loads each font file into memory, and registers
   * successful payloads with `AddFontMemResourceEx`.
   */
  void REN_Init()
  {
    FILE_EnsureWaitHandleSet();
    FWaitHandleSet* waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> fontFiles{};
    waitHandleSet->mHandle->EnumerateFiles("/fonts", "*.ttf", true, &fontFiles);

    for (const msvc8::string& fontFile : fontFiles) {
      gpg::Logf("adding font file %s", fontFile.c_str());

      FILE_EnsureWaitHandleSet();
      waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
        continue;
      }

      msvc8::string mountedPath{};
      (void)waitHandleSet->mHandle->FindFile(&mountedPath, fontFile.c_str(), nullptr);
      if (mountedPath.empty()) {
        continue;
      }

      gpg::MemBuffer<char> fontBytes = DISK_ReadFile(mountedPath.c_str());
      if (fontBytes.mBegin == nullptr) {
        const msvc8::string diskError = DISK_GetLastError();
        gpg::Warnf("D3D_InitFonts: %s", diskError.c_str());
        continue;
      }

      DWORD loadedFontCount = 0;
      const DWORD byteSize = static_cast<DWORD>(fontBytes.mEnd - fontBytes.mBegin);
      if (::AddFontMemResourceEx(fontBytes.mBegin, byteSize, nullptr, &loadedFontCount) == 0) {
        gpg::Warnf("D3D_InitFonts: Error loading font %s", mountedPath.c_str());
      }
    }
  }

  /**
   * Address: 0x007FA100 (FUN_007FA100)
   *
   * What it does:
   * Jump-only adapter lane that forwards directly into `REN_Init()`.
   */
  [[maybe_unused]] void REN_InitAdapterA()
  {
    REN_Init();
  }

  /**
   * Address: 0x00430900 (FUN_00430900, ?D3D_Init@Moho@@YA_NXZ)
   *
   * What it does:
   * Runs render-font bootstrap and reports success.
   */
  bool D3D_Init()
  {
    REN_Init();
    return true;
  }

  /**
   * Address: 0x00430910 (FUN_00430910, ?D3D_Exit@Moho@@YAXXZ)
   *
   * What it does:
   * Tears down D3D singleton lanes (index sheets + world particles) and calls
   * device destroy on the global D3D device.
   */
  void D3D_Exit()
  {
    sIndexSheet.reset();
    DestroyWorldParticlesSingleton();
    DestroySharedTrailQuadIndexSheet();

    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      device->Destroy();
    }
  }

  /**
   * Address: 0x007FA2C0 (FUN_007FA2C0, Moho::REN_Frame)
   *
   * int gameTick, float simDeltaSeconds, float frameSeconds
   *
   * What it does:
   * Updates render timing globals and publishes `Frame_Time` / `Frame_FPS`
   * stat counters.
   */
  void REN_Frame(const int gameTick, const float simDeltaSeconds, const float frameSeconds)
  {
    sDeltaFrame = simDeltaSeconds;

    const float weightedFrameSeconds = (sWeightedFrameRate * 0.9f) + (frameSeconds * 0.1f);
    const float frameTimeMs = weightedFrameSeconds * 1000.0f;
    const float frameFps = 1.0f / weightedFrameSeconds;

    sCurGameTick = gameTick;
    sWeightedFrameRate = weightedFrameSeconds;

    if (sEngineStatFrameTime == nullptr) {
      if (EngineStats* const engineStats = GetEngineStats(); engineStats != nullptr) {
        sEngineStatFrameTime = engineStats->GetItem3("Frame_Time");
        if (sEngineStatFrameTime != nullptr) {
          (void)sEngineStatFrameTime->Release(0);
        }
      }
    }
    PublishFloatStat(sEngineStatFrameTime, frameTimeMs);

    if (sEngineStatFrameFps == nullptr) {
      if (EngineStats* const engineStats = GetEngineStats(); engineStats != nullptr) {
        sEngineStatFrameFps = engineStats->GetItem3("Frame_FPS");
        if (sEngineStatFrameFps != nullptr) {
          (void)sEngineStatFrameFps->Release(0);
        }
      }
    }
    PublishFloatStat(sEngineStatFrameFps, frameFps);
  }

  float REN_GetSimDeltaSeconds()
  {
    return sDeltaFrame;
  }

  float REN_GetWeightedFrameSeconds()
  {
    return sWeightedFrameRate;
  }

  int REN_GetGameTick()
  {
    return sCurGameTick;
  }
} // namespace moho
