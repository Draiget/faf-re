#include "CD3DDevice.h"

#include <Windows.h>
#include <d3d9.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <unordered_map>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/MeshFormatter.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/backends/d3d9/CubeRenderTargetD3D9.hpp"
#include "gpg/gal/backends/d3d9/DepthStencilTargetD3D9.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"
#include "moho/app/WxRuntimeTypes.h"
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
  gpg::gal::MeshFormatter* sCurHardwareVertexFormatter = nullptr;

  [[nodiscard]] std::int32_t FloatToBits(const float value) noexcept
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return static_cast<std::int32_t>(bits);
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

  struct CD3DDeviceEventListenerRuntime
  {
    virtual void Receive(const moho::SD3DDeviceEvent& event) = 0;

    moho::Broadcaster mListenerLink{}; // +0x04
  };

  static_assert(
    offsetof(CD3DDeviceEventListenerRuntime, mListenerLink) == 0x04,
    "CD3DDeviceEventListenerRuntime::mListenerLink offset must be 0x04"
  );

  /**
   * Address: 0x00431D80 (FUN_00431D80)
   *
   * struct_DeviceExitEvent *,Moho::Broadcaster *
   *
   * What it does:
   * Moves one device-listener ring into a temporary pending head, re-links each
   * listener back to the owner ring, and dispatches one device event.
   */
  [[nodiscard]] moho::Broadcaster* DispatchDeviceEventToListeners(
    const moho::SD3DDeviceEvent& event,
    moho::Broadcaster* const listenerHead
  )
  {
    moho::Broadcaster pending{};
    if (listenerHead == nullptr || listenerHead->ListIsSingleton()) {
      return static_cast<moho::Broadcaster*>(pending.mNext);
    }

    listenerHead->move_nodes_to(pending);

    for (auto* pendingNode = pending.pop_back(); pendingNode != nullptr; pendingNode = pending.pop_back()) {
      auto* const node = static_cast<moho::Broadcaster*>(pendingNode);
      listenerHead->push_front(node);

      auto* const listener = moho::Broadcaster::owner_from_member<
        CD3DDeviceEventListenerRuntime,
        moho::Broadcaster,
        &CD3DDeviceEventListenerRuntime::mListenerLink>(node);
      if (listener != nullptr) {
        listener->Receive(event);
      }
    }

    return static_cast<moho::Broadcaster*>(pending.mNext);
  }

  /**
   * Address: 0x00430D50 (FUN_00430D50, sub_430D50)
   *
   * What it does:
   * Resets one device broadcaster node to singleton self-links during
   * constructor-lane initialization (vftable reset is compiler-managed).
   */
  [[nodiscard]] moho::Broadcaster* ResetDeviceBroadcasterSelfLinks(moho::Broadcaster* const broadcaster)
  {
    if (broadcaster == nullptr) {
      return nullptr;
    }

    broadcaster->mPrev = broadcaster;
    broadcaster->mNext = broadcaster;
    return broadcaster;
  }

  /**
   * Address: 0x00430D70 (FUN_00430D70, sub_430D70)
   *
   * What it does:
   * Detaches one device broadcaster node from its current ring and restores
   * singleton self-links.
   */
  [[nodiscard]] moho::Broadcaster* UnlinkAndResetDeviceBroadcaster(moho::Broadcaster* const broadcaster)
  {
    if (broadcaster == nullptr) {
      return nullptr;
    }

    broadcaster->ListUnlink();
    return broadcaster;
  }

  struct OutputContextD3D9RuntimeView
  {
    void* vtable = nullptr;                                        // +0x00
    boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9> cubeTarget;  // +0x04
    std::int32_t face = 0;                                         // +0x0C
    boost::shared_ptr<gpg::gal::RenderTargetD3D9> renderTarget;    // +0x10
    boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9> depthStencil; // +0x18
  };

  static_assert(
    sizeof(OutputContextD3D9RuntimeView) == sizeof(gpg::gal::OutputContext),
    "OutputContextD3D9RuntimeView size must match gpg::gal::OutputContext"
  );
  static_assert(
    offsetof(OutputContextD3D9RuntimeView, renderTarget) == 0x10,
    "OutputContextD3D9RuntimeView::renderTarget offset must be 0x10"
  );
  static_assert(
    offsetof(OutputContextD3D9RuntimeView, depthStencil) == 0x18,
    "OutputContextD3D9RuntimeView::depthStencil offset must be 0x18"
  );

  struct DrawPrimitiveContextRuntime
  {
    std::uint32_t pad00 = 0U;               // +0x00
    std::uint32_t topologyToken = 0U;       // +0x04
    std::uint32_t primitiveCountInput = 0U; // +0x08
    std::uint32_t startVertex = 0U;         // +0x0C
  };

  static_assert(
    sizeof(DrawPrimitiveContextRuntime) == 0x10,
    "DrawPrimitiveContextRuntime size must be 0x10"
  );

  struct DrawIndexedPrimitiveContextRuntime
  {
    std::uint32_t pad00 = 0U;               // +0x00
    std::uint32_t topologyToken = 0U;       // +0x04
    std::uint32_t minVertexIndex = 0U;      // +0x08
    std::uint32_t vertexCount = 0U;         // +0x0C
    std::uint32_t primitiveCountInput = 0U; // +0x10
    std::uint32_t startIndex = 0U;          // +0x14
    std::int32_t baseVertexIndex = 0;       // +0x18
  };

  static_assert(
    sizeof(DrawIndexedPrimitiveContextRuntime) == 0x1C,
    "DrawIndexedPrimitiveContextRuntime size must be 0x1C"
  );

  [[nodiscard]] gpg::gal::OutputContext BuildOutputContext(
    const moho::ID3DRenderTarget::SurfaceHandle& renderTarget,
    const moho::ID3DDepthStencil::SurfaceHandle& depthStencil
  )
  {
    gpg::gal::OutputContext context{};
    auto& runtime = reinterpret_cast<OutputContextD3D9RuntimeView&>(context);
    runtime.renderTarget = renderTarget;
    runtime.depthStencil = depthStencil;
    return context;
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
      if (effect != nullptr && effect->mEffect.px != nullptr) {
        (void)effect->mEffect.px->OnLost();
      }
    }

    using VertexSheetList = moho::TDatList<moho::CD3DVertexSheet, void>;
    using IndexSheetList = moho::TDatList<moho::CD3DIndexSheet, void>;
    using RenderTargetList = moho::TDatList<moho::CD3DRenderTarget, void>;
    using DepthStencilList = moho::TDatList<moho::CD3DDepthStencil, void>;
    using DynamicTextureSheetList = moho::TDatList<moho::CD3DDynamicTextureSheet, void>;

    for (auto* node = resources.mVertexSheet2.mLink.mNext; node != &resources.mVertexSheet2.mLink; node = node->mNext) {
      auto* const vertexSheet =
        VertexSheetList::template owner_from_member_node<moho::CD3DVertexSheet, &moho::CD3DVertexSheet::mLink>(node);
      if (vertexSheet == nullptr) {
        continue;
      }

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

    for (auto* node = resources.mIndexSheet2.mLink.mNext; node != &resources.mIndexSheet2.mLink; node = node->mNext) {
      auto* const indexSheet =
        IndexSheetList::template owner_from_member_node<moho::CD3DIndexSheet, &moho::CD3DIndexSheet::mLink>(node);
      if (indexSheet != nullptr) {
        indexSheet->mBuffer.reset();
      }
    }

    for (auto* node = resources.mRenderTarget.mLink.mNext; node != &resources.mRenderTarget.mLink; node = node->mNext) {
      auto* const renderTarget =
        RenderTargetList::template owner_from_member_node<moho::CD3DRenderTarget, &moho::CD3DRenderTarget::mLink>(
          node);
      if (renderTarget != nullptr) {
        renderTarget->mSurface.reset();
      }
    }

    for (auto* node = resources.mDepthStencil.mLink.mNext; node != &resources.mDepthStencil.mLink; node = node->mNext) {
      auto* const depthStencil =
        DepthStencilList::template owner_from_member_node<moho::CD3DDepthStencil, &moho::CD3DDepthStencil::mLink>(
          node);
      if (depthStencil != nullptr) {
        depthStencil->mSurface.reset();
      }
    }

    for (auto* node = resources.mTextureSheet.mLink.mNext; node != &resources.mTextureSheet.mLink; node = node->mNext) {
      auto* const dynamicSheet = DynamicTextureSheetList::template owner_from_member_node<
        moho::CD3DDynamicTextureSheet,
        &moho::CD3DDynamicTextureSheet::mLink>(node);
      if (dynamicSheet != nullptr) {
        dynamicSheet->mTexture.reset();
      }
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
    auto& runtime = reinterpret_cast<moho::CWorldParticlesRuntimeView&>(moho::sWorldParticles);
    moho::ParticleBufferPoolNodeRuntime* const head = runtime.allParticleBuffers.head;
    if (head == nullptr) {
      return;
    }

    for (moho::ParticleBufferPoolNodeRuntime* node = head->next; node != nullptr && node != head; node = node->next) {
      if (node->value != nullptr) {
        node->value->Reset();
      }
    }
  }

  struct CD3DDeviceRuntimeView
  {
    void* mVTable = nullptr;                                     // +0x00
    std::uint8_t mUnknown004To00B[0x08]{};                       // +0x04
    std::uint8_t mClearEnabled = 0;                              // +0x0C
    std::uint8_t mInitialized = 0;                               // +0x0D
    std::uint8_t mUnknown00ETo00F[0x02]{};                       // +0x0E
    moho::WRenViewport* mViewport = nullptr;                     // +0x10
    std::uint8_t mShowingCursor = 0;                             // +0x14
    std::uint8_t mDrawViewportBackground = 0;                    // +0x15
    std::uint8_t mSoftwareVP = 0;                                // +0x16
    std::uint8_t mDirectDebug = 0;                               // +0x17
    std::uint8_t mSceneStarted = 0;                              // +0x18
    std::uint8_t mUnknown019To213[0x1FB]{};                      // +0x19
    boost::shared_ptr<moho::ID3DRenderTarget> mReaderWriterLocks1[2]; // +0x214
    boost::shared_ptr<moho::ID3DDepthStencil> mReaderWriterLocks2[2]; // +0x224
    boost::shared_ptr<void> mWriterLockContext1;                 // +0x234
    boost::shared_ptr<void> mWriterLockContext2;                 // +0x23C
    boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9> mRenderTarget; // +0x244
    boost::shared_ptr<moho::CD3DDepthStencil> mDepthStencil;     // +0x24C
    moho::CD3DEffect* mCurEffect = nullptr;                      // +0x254
    gpg::gal::CursorContext mCursorContext;                      // +0x258

    [[nodiscard]] static CD3DDeviceRuntimeView* FromDevice(moho::CD3DDevice* const device) noexcept
    {
      using DeviceRuntimeMap = std::unordered_map<const moho::CD3DDevice*, std::unique_ptr<CD3DDeviceRuntimeView>>;
      static DeviceRuntimeMap* const runtimeByDevice = new DeviceRuntimeMap();

      auto it = runtimeByDevice->find(device);
      if (it == runtimeByDevice->end()) {
        auto runtime = std::make_unique<CD3DDeviceRuntimeView>();
        runtime->mClearEnabled = 0;
        runtime->mInitialized = 0;
        runtime->mShowingCursor = 1;
        runtime->mDrawViewportBackground = 1;
        runtime->mSceneStarted = 0;
        const auto inserted = runtimeByDevice->emplace(device, std::move(runtime));
        it = inserted.first;
      }

      return it->second.get();
    }

    [[nodiscard]] static const CD3DDeviceRuntimeView* FromDevice(const moho::CD3DDevice* const device) noexcept
    {
      return FromDevice(const_cast<moho::CD3DDevice*>(device));
    }
  };

  static_assert(
    offsetof(CD3DDeviceRuntimeView, mClearEnabled) == 0x0C,
    "CD3DDeviceRuntimeView::mClearEnabled offset must be 0x0C"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mInitialized) == 0x0D,
    "CD3DDeviceRuntimeView::mInitialized offset must be 0x0D"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mViewport) == 0x10,
    "CD3DDeviceRuntimeView::mViewport offset must be 0x10"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mShowingCursor) == 0x14,
    "CD3DDeviceRuntimeView::mShowingCursor offset must be 0x14"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mSoftwareVP) == 0x16,
    "CD3DDeviceRuntimeView::mSoftwareVP offset must be 0x16"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mDirectDebug) == 0x17,
    "CD3DDeviceRuntimeView::mDirectDebug offset must be 0x17"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mSceneStarted) == 0x18,
    "CD3DDeviceRuntimeView::mSceneStarted offset must be 0x18"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mReaderWriterLocks1) == 0x214,
    "CD3DDeviceRuntimeView::mReaderWriterLocks1 offset must be 0x214"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mReaderWriterLocks2) == 0x224,
    "CD3DDeviceRuntimeView::mReaderWriterLocks2 offset must be 0x224"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mWriterLockContext1) == 0x234,
    "CD3DDeviceRuntimeView::mWriterLockContext1 offset must be 0x234"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mWriterLockContext2) == 0x23C,
    "CD3DDeviceRuntimeView::mWriterLockContext2 offset must be 0x23C"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mRenderTarget) == 0x244,
    "CD3DDeviceRuntimeView::mRenderTarget offset must be 0x244"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mDepthStencil) == 0x24C,
    "CD3DDeviceRuntimeView::mDepthStencil offset must be 0x24C"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mCurEffect) == 0x254,
    "CD3DDeviceRuntimeView::mCurEffect offset must be 0x254"
  );
  static_assert(
    offsetof(CD3DDeviceRuntimeView, mCursorContext) == 0x258,
    "CD3DDeviceRuntimeView::mCursorContext offset must be 0x258"
  );

  void ReleaseHeadWriterLocks(CD3DDeviceRuntimeView& runtime, const std::size_t headIndex)
  {
    if (auto* const renderTarget =
          static_cast<moho::CD3DRenderTarget*>(runtime.mReaderWriterLocks1[headIndex].get());
        renderTarget != nullptr) {
      renderTarget->mSurface.reset();
    }
    runtime.mReaderWriterLocks1[headIndex].reset();

    if (auto* const depthStencil =
          static_cast<moho::CD3DDepthStencil*>(runtime.mReaderWriterLocks2[headIndex].get());
        depthStencil != nullptr) {
      depthStencil->mSurface.reset();
    }
    runtime.mReaderWriterLocks2[headIndex].reset();
  }

  /**
   * Address: 0x0042E902 (FUN_0042E750 tail helper lane)
   *
   * What it does:
   * Rebinds the device cursor context to one default-constructed state and
   * releases the previous cursor-control shared lane.
   */
  void ResetCursorContextAfterDeviceDestroy(gpg::gal::CursorContext& cursorContext)
  {
    const gpg::gal::CursorContext resetContext{};
    cursorContext.hotspotX_ = resetContext.hotspotX_;
    cursorContext.hotspotY_ = resetContext.hotspotY_;
    cursorContext.pixelSource_ = resetContext.pixelSource_;

    if (resetContext.cursorControl_ != cursorContext.cursorControl_) {
      if (resetContext.cursorControl_ != nullptr) {
        resetContext.cursorControl_->add_ref_copy();
      }
      if (cursorContext.cursorControl_ != nullptr) {
        cursorContext.cursorControl_->release();
      }
      cursorContext.cursorControl_ = resetContext.cursorControl_;
    }
  }

  class CD3DDeviceSingleton final : public moho::CD3DDevice
  {
  public:
    /**
     * Address: 0x00430C20 (FUN_00430C20, ??0CD3DDevice@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes singleton device runtime lanes, broadcaster links, and
     * resource ownership used by the global D3D device object.
     */
    CD3DDeviceSingleton()
    {
      (void)ResetDeviceBroadcasterSelfLinks(static_cast<moho::Broadcaster*>(this));

      CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
      runtime->mShowingCursor = 1;
      runtime->mDrawViewportBackground = 1;
      runtime->mClearEnabled = 0;
      runtime->mInitialized = 0;
      runtime->mSceneStarted = 0;
      runtime->mSoftwareVP = (moho::d3d_ForceSoftwareVP || moho::d3d_ForceDirect3DDebugEnabled) ? 1u : 0u;
      runtime->mDirectDebug = moho::d3d_ForceDirect3DDebugEnabled ? 1u : 0u;
      runtime->mViewport = nullptr;
      runtime->mCurEffect = nullptr;
      mResources.SetDevice(this);
    }

    /**
     * Address: 0x00430DF0 (FUN_00430DF0, ??1CD3DDevice@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down singleton-owned runtime lanes and unlinks device broadcaster
     * list ownership before global-device destruction completes.
     */
    ~CD3DDeviceSingleton() override
    {
      CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
      runtime->mWriterLockContext1.reset();
      runtime->mWriterLockContext2.reset();
      runtime->mRenderTarget.reset();
      runtime->mDepthStencil.reset();
      runtime->mReaderWriterLocks1[0].reset();
      runtime->mReaderWriterLocks1[1].reset();
      runtime->mReaderWriterLocks2[0].reset();
      runtime->mReaderWriterLocks2[1].reset();
      runtime->mViewport = nullptr;
      runtime->mSceneStarted = 0;
      runtime->mInitialized = 0;
      runtime->mDrawViewportBackground = 1;
      runtime->mSoftwareVP = 0;
      runtime->mDirectDebug = 0;
      runtime->mCurEffect = nullptr;
      (void)UnlinkAndResetDeviceBroadcaster(static_cast<moho::Broadcaster*>(this));
    }

    [[nodiscard]] moho::ID3DDeviceResources* GetResources() override
    {
      return &mResources;
    }

    /**
     * Address: 0x0042E1E0 (FUN_0042E1E0)
     *
     * What it does:
     * Rebinds one GAL device-context payload, rebuilds per-head writer locks,
     * recreates tracked device resources, and re-emits init callbacks/events.
     */
    bool InitContext(gpg::gal::DeviceContext* const context) override
    {
      if (context == nullptr) {
        return false;
      }

      CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
      runtime->mInitialized = 0;

      auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
      const int headCount = context->GetHeadCount();
      const std::size_t lockHeadCount =
        std::min(static_cast<std::size_t>(headCount), std::size(runtime->mReaderWriterLocks1));

      if (runtime->mViewport != nullptr) {
        reinterpret_cast<moho::WD3DViewport*>(runtime->mViewport)->D3DWindowOnDeviceExit();
      }

      const moho::SD3DDeviceEvent deviceExitEvent{1u, false, {0u, 0u, 0u}};
      (void)DispatchDeviceEventToListeners(deviceExitEvent, static_cast<moho::Broadcaster*>(this));
      ResetResourcesForContextTransition(mResources, false);
      ResetWorldParticleBuffers();

      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        ReleaseHeadWriterLocks(*runtime, headIndex);
      }

      if (device != nullptr) {
        (void)device->Func9(context);
      }

      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        if (device == nullptr) {
          break;
        }

        const auto* const outputContext =
          reinterpret_cast<const OutputContextD3D9RuntimeView*>(device->GetHead2(static_cast<unsigned int>(headIndex)));
        if (outputContext == nullptr) {
          continue;
        }

        runtime->mReaderWriterLocks1[headIndex].reset(
          new moho::CD3DRenderTarget(this, outputContext->renderTarget)
        );
        runtime->mReaderWriterLocks2[headIndex].reset(
          new moho::CD3DDepthStencil(this, outputContext->depthStencil)
        );
      }

      (void)mResources.InitResources(false);

      if (runtime->mViewport != nullptr) {
        reinterpret_cast<moho::WD3DViewport*>(runtime->mViewport)->D3DWindowOnDeviceInit();
      }

      const moho::SD3DDeviceEvent deviceInitEvent{0u, false, {0u, 0u, 0u}};
      (void)DispatchDeviceEventToListeners(deviceInitEvent, static_cast<moho::Broadcaster*>(this));

      for (int headIndex = 1; headIndex < headCount; ++headIndex) {
        const gpg::gal::Head& head = context->GetHead(static_cast<unsigned int>(headIndex));
        ::ShowWindow(static_cast<HWND>(head.mWindow), SW_SHOWNORMAL);
      }

      if (runtime->mCursorContext.pixelSource_ != nullptr && device != nullptr) {
        device->SetCursor(&runtime->mCursorContext);
      }

      runtime->mInitialized = 1;
      return runtime->mInitialized != 0;
    }

    /**
     * Address: 0x0042E750 (FUN_0042E750)
     *
     * What it does:
     * Emits device-exit callbacks/events, tears down tracked resources and
     * per-head writer locks, resets cursor context lanes, and dispatches backend
     * destroy.
     */
    void Destroy() override
    {
      CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
      runtime->mInitialized = 0;
      if (runtime->mViewport != nullptr) {
        reinterpret_cast<moho::WD3DViewport*>(runtime->mViewport)->D3DWindowOnDeviceExit();
      }

      const moho::SD3DDeviceEvent deviceExitEvent{1u, true, {0u, 0u, 0u}};
      (void)DispatchDeviceEventToListeners(deviceExitEvent, static_cast<moho::Broadcaster*>(this));
      ResetResourcesForContextTransition(mResources, true);
      mResources.ClearCachedVertexFormats();

      auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
      int headCount = 0;
      if (device != nullptr) {
        if (gpg::gal::DeviceContext* const context = device->GetDeviceContext(); context != nullptr) {
          headCount = context->GetHeadCount();
        }
      }

      const std::size_t lockHeadCount =
        std::min(static_cast<std::size_t>(headCount), std::size(runtime->mReaderWriterLocks1));
      for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
        ReleaseHeadWriterLocks(*runtime, headIndex);
      }

      ResetCursorContextAfterDeviceDestroy(runtime->mCursorContext);

      if (device != nullptr) {
        gpg::gal::Device::DestroyInstance();
      }
    }

  private:
    moho::CD3DDeviceResources mResources{};
  };
} // namespace

namespace moho
{
  /**
   * Address: 0x0042DBE0 (FUN_0042DBE0)
   *
   * What it does:
   * Owns the deleting-destructor entrypoint for the D3D device wrapper.
   */
  CD3DDevice::~CD3DDevice() = default;

  /**
   * Address: 0x0042DBF0 (FUN_0042DBF0)
   *
   * What it does:
   * Returns the active GAL D3D9 backend pointer when the global device is ready.
   */
  gpg::gal::DeviceD3D9* CD3DDevice::GetDeviceD3D9()
  {
    if (!gpg::gal::Device::IsReady()) {
      return nullptr;
    }
    return static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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
    CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
    runtime->mViewport = viewport;

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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

    const int headCount = context->GetHeadCount();
    bool supportsAdvancedShadowFidelity = true;
    if (headCount > 0) {
      for (int headIndex = 0; headIndex < headCount; ++headIndex) {
        const gpg::gal::Head& head = context->GetHead(static_cast<unsigned int>(headIndex));
        const bool headSupportsShadow = context->mSupportsFloat16 || head.antialiasingHigh != 0u || head.antialiasingLow != 0u;
        supportsAdvancedShadowFidelity = supportsAdvancedShadowFidelity && headSupportsShadow;
      }
    }

    if (context->mPixelShaderProfile > 5) {
      moho::graphics_FidelitySupported = 2;
      moho::shadow_FidelitySupported = supportsAdvancedShadowFidelity ? 3 : 1;
    } else {
      moho::graphics_FidelitySupported = 1;
      moho::shadow_FidelitySupported = supportsAdvancedShadowFidelity ? 2 : 1;
    }

    const std::size_t lockHeadCount =
      std::min(static_cast<std::size_t>(headCount), std::size(runtime->mReaderWriterLocks1));
    for (std::size_t headIndex = 0U; headIndex < lockHeadCount; ++headIndex) {
      ReleaseHeadWriterLocks(*runtime, headIndex);

      const auto* const outputContext =
        reinterpret_cast<const OutputContextD3D9RuntimeView*>(device->GetHead2(static_cast<unsigned int>(headIndex)));
      if (outputContext == nullptr) {
        continue;
      }

      runtime->mReaderWriterLocks1[headIndex].reset(
        new moho::CD3DRenderTarget(this, outputContext->renderTarget)
      );
      runtime->mReaderWriterLocks2[headIndex].reset(
        new moho::CD3DDepthStencil(this, outputContext->depthStencil)
      );
    }

    runtime->mRenderTarget.reset();
    runtime->mDepthStencil.reset(new moho::CD3DDepthStencil());

    if (auto* const resources = static_cast<moho::CD3DDeviceResources*>(GetResources()); resources != nullptr) {
      (void)resources->InitResources(true);
    }

    runtime->mDrawViewportBackground = 0u;
    const moho::SD3DDeviceEvent deviceInitEvent{0u, true, {0u, 0u, 0u}};
    (void)DispatchDeviceEventToListeners(deviceInitEvent, static_cast<moho::Broadcaster*>(this));

    if (runtime->mViewport != nullptr) {
      reinterpret_cast<moho::WD3DViewport*>(runtime->mViewport)->D3DWindowOnDeviceInit();
    }
    runtime->mInitialized = 1u;
  }

  /**
   * Address: 0x0042E9D0 (FUN_0042E9D0)
   *
   * What it does:
   * Returns the currently bound render viewport pointer.
   */
  WRenViewport* CD3DDevice::GetViewport()
  {
    return CD3DDeviceRuntimeView::FromDevice(this)->mViewport;
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    gpg::gal::DeviceContext* const context = device->GetDeviceContext();
    return static_cast<int>(context->GetHead(headIndex).mHeight);
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

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

      if (auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
          device != nullptr && outSheet.get() != nullptr) {
        ID3DTextureSheet::TextureHandle destinationTexture{};
        outSheet->GetTexture(destinationTexture);

        ID3DTextureSheet::TextureHandle sourceTexture{};
        sourceTextureSheet->GetTexture(sourceTexture);

        gpg::gal::TextureD3D9* sourceRaw = sourceTexture.get();
        gpg::gal::TextureD3D9* destinationRaw = destinationTexture.get();
        if (sourceRaw != nullptr && destinationRaw != nullptr) {
          device->UpdateSurface(&sourceRaw, &destinationRaw, nullptr, nullptr);
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
   * int,int,boost::shared_ptr<moho::ID3DTextureSheet>
   *
   * What it does:
   * Resolves one cursor-pixel source payload, updates cursor context lanes, and
   * forwards the resulting context to the active GAL device.
   */
  bool CD3DDevice::SetCursor(
    const int hotspotX, const int hotspotY, const boost::shared_ptr<ID3DTextureSheet> cursorTexture
  )
  {
    if (!gpg::gal::Device::IsReady() || cursorTexture.get() == nullptr) {
      return false;
    }

    ID3DTextureSheet::TextureHandle pixelSource{};
    cursorTexture->GetTexture(pixelSource);
    if (pixelSource.get() == nullptr) {
      return false;
    }

    auto* const view = CD3DDeviceRuntimeView::FromDevice(this);
    view->mCursorContext.hotspotX_ = hotspotX;
    view->mCursorContext.hotspotY_ = hotspotY;

    const auto rawPixelSource = boost::SharedPtrRawFromSharedBorrow(pixelSource);
    boost::SharedCountPair currentCursorSource{
      view->mCursorContext.pixelSource_,
      view->mCursorContext.cursorControl_
    };
    const boost::SharedCountPair newCursorSource{
      reinterpret_cast<void*>(rawPixelSource.px), rawPixelSource.pi
    };
    boost::AssignWeakPairFromShared(&currentCursorSource, &newCursorSource);
    view->mCursorContext.pixelSource_ =
      static_cast<gpg::gal::CursorPixelSourceRuntime*>(currentCursorSource.px);
    view->mCursorContext.cursorControl_ = currentCursorSource.pi;

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    device->SetCursor(&view->mCursorContext);
    return true;
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
      auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
      result = device->ShowCursor(show);
      CD3DDeviceRuntimeView::FromDevice(this)->mShowingCursor = show ? 1u : 0u;
    }
    return result;
  }

  [[nodiscard]] bool CD3DDevice::IsCursorPixelSourceReady() const
  {
    return CD3DDeviceRuntimeView::FromDevice(this)->mCursorContext.pixelSource_ != nullptr;
  }

  [[nodiscard]] bool CD3DDevice::IsCursorShowing() const
  {
    return CD3DDeviceRuntimeView::FromDevice(this)->mShowingCursor != 0;
  }

  [[nodiscard]] bool CD3DDevice::ShouldDrawViewportBackground() const
  {
    return CD3DDeviceRuntimeView::FromDevice(this)->mDrawViewportBackground != 0;
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
    const auto& source = CD3DDeviceRuntimeView::FromDevice(this)->mReaderWriterLocks1[static_cast<std::size_t>(index)];
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
    const auto& source = CD3DDeviceRuntimeView::FromDevice(this)->mReaderWriterLocks2[static_cast<std::size_t>(index)];
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
    return CopyRetainedHandle(CD3DDeviceRuntimeView::FromDevice(this)->mWriterLockContext1, outHandle);
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
    return CopyRetainedHandle(CD3DDeviceRuntimeView::FromDevice(this)->mWriterLockContext2, outHandle);
  }

  /**
   * Address: 0x0042EF40 (FUN_0042EF40)
   *
   * boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9> &
   *
   * What it does:
   * Copies one active cube render-target handle from runtime state.
   */
  boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9>&
  CD3DDevice::GetRenderTarget(boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9>& outTarget)
  {
    return CopyRetainedHandle(CD3DDeviceRuntimeView::FromDevice(this)->mRenderTarget, outTarget);
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
    return CopyRetainedHandle(CD3DDeviceRuntimeView::FromDevice(this)->mDepthStencil, outDepthStencil);
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
    CD3DDeviceRuntimeView* const view = CD3DDeviceRuntimeView::FromDevice(this);
    if (view->mSceneStarted != 0) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    ID3DRenderTarget::SurfaceHandle renderSurface{};
    renderTarget->GetSurface(renderSurface);
    ID3DDepthStencil::SurfaceHandle depthSurface{};
    depthStencil->GetSurface(depthSurface);

    gpg::gal::OutputContext outputContext = BuildOutputContext(renderSurface, depthSurface);
    device->ClearTarget(&outputContext);
    (void)device->BeginScene();
    device->Clear(clear, clear, clear, static_cast<std::uint32_t>(color), zValue, stencil);
    view->mSceneStarted = 1;
  }

  /**
   * Address: 0x0042EFA0 (FUN_0042EFA0)
   *
   * What it does:
   * Begins one backend scene only when scene state is not active.
   */
  void CD3DDevice::BeginScene()
  {
    CD3DDeviceRuntimeView* const view = CD3DDeviceRuntimeView::FromDevice(this);
    if (view->mSceneStarted != 0) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    (void)device->BeginScene();
    view->mSceneStarted = 1;
  }

  /**
   * Address: 0x0042F360 (FUN_0042F360)
   *
   * What it does:
   * Ends active backend scene and clears local scene-active state.
   */
  void CD3DDevice::EndScene()
  {
    CD3DDeviceRuntimeView* const view = CD3DDeviceRuntimeView::FromDevice(this);
    if (view->mSceneStarted == 0) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    device->EndScene();
    view->mSceneStarted = 0;
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    ID3DRenderTarget::SurfaceHandle renderSurface{};
    renderTarget->GetSurface(renderSurface);
    ID3DDepthStencil::SurfaceHandle depthSurface{};
    depthStencil->GetSurface(depthSurface);

    gpg::gal::OutputContext outputContext = BuildOutputContext(renderSurface, depthSurface);
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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
   */
  bool CD3DDevice::DrawIndexedSheetPrimitive(
    ID3DVertexSheet* const vertexSheet, ID3DIndexSheet* const indexSheet, std::int32_t* const primitiveType
  )
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    vertexSheet->Func9();
    indexSheet->SetBufferIndices();

    gpg::gal::EffectTechniqueD3D9* const technique = GetCurEffect()->mCurrentTechnique.px;
    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));

      DrawIndexedPrimitiveContextRuntime drawContext{};
      drawContext.topologyToken = static_cast<std::uint32_t>(*primitiveType);
      drawContext.minVertexIndex = static_cast<std::uint32_t>(vertexSheet->Func5());
      drawContext.vertexCount = indexSheet->GetSize();
      drawContext.primitiveCountInput = 0U;
      drawContext.startIndex = 0U;
      drawContext.baseVertexIndex = 0;

      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
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
   */
  bool CD3DDevice::DrawPrimitiveList(
    const CD3DVertexSheetViewRuntime* const vertexSheetView, std::int32_t* const primitiveType
  )
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    vertexSheetView->sheet->Func9();

    gpg::gal::EffectTechniqueD3D9* const technique = GetCurEffect()->mCurrentTechnique.px;
    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));

      DrawPrimitiveContextRuntime drawContext{};
      drawContext.topologyToken = static_cast<std::uint32_t>(*primitiveType);
      drawContext.primitiveCountInput =
        static_cast<std::uint32_t>((vertexSheetView->endVertex - vertexSheetView->baseVertex) + 1);
      drawContext.startVertex = static_cast<std::uint32_t>(vertexSheetView->startVertex);

      (void)device->DrawPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
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
   */
  bool CD3DDevice::DrawTriangleList(
    const CD3DVertexSheetViewRuntime* const vertexSheetView,
    const CD3DIndexSheetViewRuntime* const indexSheetView,
    std::int32_t* const primitiveType
  )
  {
    const int vertexCount = (vertexSheetView->endVertex - vertexSheetView->startVertex) + 1;
    if (vertexCount == 0) {
      return true;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    vertexSheetView->sheet->Func9();
    indexSheetView->sheet->SetBufferIndices();

    gpg::gal::EffectTechniqueD3D9* const technique = GetCurEffect()->mCurrentTechnique.px;
    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));

      DrawIndexedPrimitiveContextRuntime drawContext{};
      drawContext.topologyToken = static_cast<std::uint32_t>(*primitiveType);
      drawContext.minVertexIndex = static_cast<std::uint32_t>(vertexSheetView->startVertex);
      drawContext.vertexCount = static_cast<std::uint32_t>(vertexCount);
      drawContext.primitiveCountInput = static_cast<std::uint32_t>(indexSheetView->indexCount);
      drawContext.startIndex = static_cast<std::uint32_t>(indexSheetView->startIndex);
      drawContext.baseVertexIndex = vertexSheetView->baseVertex;

      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
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

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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
    CD3DDeviceRuntimeView::FromDevice(this)->mCurEffect = effect;
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
    return CD3DDeviceRuntimeView::FromDevice(this)->mCurEffect;
  }

  /**
   * Address: 0x0042FD90 (FUN_0042FD90)
   *
   * What it does:
   * Returns the active backend render-thread identifier.
   */
  int CD3DDevice::GetCurThreadId()
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    ID3DTextureSheet::TextureHandle destinationTexture{};
    destinationSheet->GetTexture(destinationTexture);
    ID3DTextureSheet::TextureHandle sourceTexture{};
    sourceSheet->GetTexture(sourceTexture);

    gpg::gal::TextureD3D9* sourceRaw = sourceTexture.get();
    gpg::gal::TextureD3D9* destinationRaw = destinationTexture.get();
    device->UpdateSurface(&sourceRaw, &destinationRaw, sourceRect, destinationRect);
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    ID3DRenderTarget::SurfaceHandle destinationSurface{};
    destinationRenderTarget->GetSurface(destinationSurface);
    ID3DRenderTarget::SurfaceHandle sourceSurface{};
    sourceRenderTarget->GetSurface(sourceSurface);

    gpg::gal::RenderTargetD3D9* sourceRaw = sourceSurface.get();
    gpg::gal::RenderTargetD3D9* destinationRaw = destinationSurface.get();
    device->StretchRect(&sourceRaw, &destinationRaw, sourceRect, destinationRect);
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
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    ID3DTextureSheet::TextureHandle destinationTexture{};
    destinationTextureSheet->GetTexture(destinationTexture);
    ID3DRenderTarget::SurfaceHandle sourceSurface{};
    sourceRenderTarget->GetSurface(sourceSurface);

    gpg::gal::RenderTargetD3D9* sourceRaw = sourceSurface.get();
    device->CreateRenderTarget(&sourceRaw, &destinationTexture);
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
   * Clears active render targets/depth/stencil with opaque black.
   */
  void CD3DDevice::Clear()
  {
    if (!gpg::gal::Device::IsReady()) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    (void)device->BeginScene();
    device->Clear(true, true, true, 0xFF000000u, 1.0f, 0);
    device->EndScene();
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
    CD3DDeviceRuntimeView::FromDevice(this)->mClearEnabled = clear ? 1u : 0u;
    return clear;
  }

  /**
   * Address: 0x00430F90 (FUN_00430F90, Moho::CD3DDevice::Paint)
   *
   * What it does:
   * Presents one device frame when the device/runtime viewport is active, then
   * dispatches either clear or viewport render callback.
   */
  void CD3DDevice::Paint()
  {
    CD3DDeviceRuntimeView* const runtime = CD3DDeviceRuntimeView::FromDevice(this);
    if (runtime->mInitialized == 0 || !gpg::gal::Device::IsReady() || runtime->mViewport == nullptr) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
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

    if (runtime->mClearEnabled != 0) {
      Clear();
    } else {
      reinterpret_cast<moho::WD3DViewport*>(runtime->mViewport)->D3DWindowOnDeviceRender();
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
    static CD3DDeviceSingleton sDevice{};
    return &sDevice;
  }

  /**
   * Address: 0x008E7C50 (FUN_008E7C50, func_CreateTexture)
   *
   * What it does:
   * Pulls the active GAL device singleton and forwards one texture-create
   * request into its virtual `CreateTexture` lane.
   */
  boost::shared_ptr<gpg::gal::TextureD3D9>& CreateTextureOnActiveDevice(
    boost::shared_ptr<gpg::gal::TextureD3D9>& outTexture,
    const gpg::gal::TextureContext& context
  )
  {
    outTexture.reset();
    if (gpg::gal::Device* const device = gpg::gal::Device::GetInstance(); device != nullptr) {
      if (auto* const d3d9Device = dynamic_cast<gpg::gal::DeviceD3D9*>(device); d3d9Device != nullptr) {
        (void)d3d9Device->CreateTexture(&outTexture, &context);
      }
    }
    return outTexture;
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
    cleanup_D3DIndexSheet();
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

  int REN_GetGameTick()
  {
    return sCurGameTick;
  }

  /**
   * Address: 0x008E7540 (FUN_008E7540, func_ResetHarwareVertexFormatter)
   *
   * What it does:
   * Clears the current hardware-vertex formatter cache pointer.
   */
  void REN_ResetHardwareVertexFormatter() noexcept
  {
    sCurHardwareVertexFormatter = nullptr;
  }
} // namespace moho
