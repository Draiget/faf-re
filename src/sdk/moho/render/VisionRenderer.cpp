#include "moho/render/VisionRenderer.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

#include "gpg/core/containers/FastVector.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/vision/VisionDB.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Box2.h"
#include "Wm3Circle2.h"
#include "Wm3Vector2.h"

namespace
{
  constexpr std::uint32_t kVisionSegmentCount = 45u;
  constexpr std::uint32_t kVisionVertexCount = (kVisionSegmentCount * 2u) + 2u; // 92
  constexpr std::uint32_t kVisionIndexCount = kVisionSegmentCount * 12u;         // 540
  constexpr float kVisionAngleStep = 0.13962634f;                                 // 2*pi/45

  /**
   * Capacity, in whole `Wm3::Circle2f` instances, of the dynamic per-instance
   * vertex buffer allocated by `VisionRenderer::Init` (`width_ = 12288` at
   * 0x0081C1E6) and used as the batch size limit by `RenderFogOfWar`
   * (`cmp eax, 3000h` at 0x0081C9DF) and the ring wrap point in
   * `LockVisionInstanceRange` (`cmp ecx, 3000h` at 0x0081CCB6).
   */
  constexpr std::uint32_t kVisionInstanceRingCapacity = 0x3000u;

  /** `D3DPT_TRIANGLELIST`, pushed as the topology token at 0x0081CAB8. */
  constexpr int kTriangleListTopology = 4;

  /**
   * Raw GAL lock-flag tokens the shipped ring allocator passes: 4 on the append
   * path (`push 4` at 0x0081CCCD) and 1 on the wrap path (`push 1` at
   * 0x0081CD15). `gpg::gal::MohoD3DLockFlags` (gpg/gal/D3D9Utils.h) currently
   * names 0x4 `ReadOnly` and 0x2 `NoOverwrite`, which cannot be right for a
   * write-mapped dynamic ring - the append lock has to be NOOVERWRITE. The raw
   * tokens are reproduced verbatim here; correcting the enum's bit assignment
   * belongs to the owner of that header.
   */
  constexpr auto kVisionRingAppendLock = static_cast<gpg::gal::MohoD3DLockFlags>(4u);
  constexpr auto kVisionRingWrapLock = static_cast<gpg::gal::MohoD3DLockFlags>(1u);

  /**
   * Inline capacity of the per-frame circle accumulator: the shipped body binds
   * `capacity_` to `inlineVec_ + 3000 bytes` (0x0081C7BF / 0x0081C7F0), i.e. 250
   * `Wm3::Circle2f` slots before the first heap growth.
   */
  constexpr std::size_t kVisibleCircleInlineCapacity = 250u;

  /**
   * Cached `"Vision_Total"` engine-stat slot (`sEngineStat_Vision_Total`,
   * 0x010C77A8), resolved lazily on the first fog-of-war frame.
   */
  moho::StatItem* sEngineStatVisionTotal = nullptr;

  /**
   * Address: 0x0081CCB0 (FUN_0081CCB0, sub_81CCB0)
   *
   * IDA signature:
   * bool __userpurge sub_81CCB0@<al>(int *a1@<ebx>, int a2@<edi>,
   *         unsigned int a3@<esi>, _DWORD *a4);
   *
   * What it does:
   * Sub-allocates `circleCount` instance slots from the vision renderer's
   * dynamic vertex buffer, appending behind the ring cursor while the request
   * fits and otherwise discarding the whole buffer and restarting at slot 0.
   * Reports the mapped pointer and the slot the batch starts at.
   */
  [[nodiscard]] bool LockVisionInstanceRange(
    moho::VisionRenderer& renderer,
    const std::uint32_t circleCount,
    Wm3::Circle2f*& outMapped,
    std::uint32_t& outBaseInstance
  )
  {
    constexpr std::uint32_t kCircleStride = 12u; // sizeof(Wm3::Circle2f)

    const std::uint32_t cursor = renderer.mInstanceRingCursor;
    if ((cursor + circleCount) < kVisionInstanceRingCapacity) {
      outMapped = static_cast<Wm3::Circle2f*>(
        renderer.mVertexBuffer2->Lock(kCircleStride * cursor, kCircleStride * circleCount, kVisionRingAppendLock)
      );
      if (outMapped == nullptr) {
        return false;
      }

      outBaseInstance = renderer.mInstanceRingCursor;
      renderer.mInstanceRingCursor += circleCount;
      return true;
    }

    if (circleCount > kVisionInstanceRingCapacity) {
      return false;
    }

    renderer.mInstanceRingCursor = circleCount;
    outBaseInstance = 0u;
    outMapped = static_cast<Wm3::Circle2f*>(
      renderer.mVertexBuffer2->Lock(0u, kCircleStride * circleCount, kVisionRingWrapLock)
    );
    return outMapped != nullptr;
  }
}

namespace moho
{
  /**
   * Address: 0x007D0460 (FUN_007D0460, func_GetVisionEffect)
   *
   * IDA signature:
   * boost::shared_ptr_EffectD3D9 *__usercall func_GetVisionEffect@<eax>(
   *         boost::shared_ptr_EffectD3D9 *a1@<esi>);
   *
   * What it does:
   * Resolves one `"vision"` D3D effect from device resources and returns its
   * base GAL effect handle.
   */
  boost::shared_ptr<gpg::gal::EffectD3D9> AcquireVisionBaseEffect()
  {
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    CD3DEffect* const effect = resources->FindEffect("vision");
    return effect->GetBaseEffect();
  }

  /**
   * Address: 0x0081BF10 (FUN_0081BF10, Moho::VisionRenderer::VisionRenderer)
   */
  VisionRenderer::VisionRenderer()
    : mIndexCount(0)
    , mVertexCount(0)
    , mGeometry()
    , mInstanceRingCursor(0)
    , mVertexBuffer2()
    , mFrame()
  {}

  /**
   * Address: 0x0081BF70 (FUN_0081BF70, Moho::VisionRenderer::dtr)
   * Address: 0x0081BF90 (FUN_0081BF90, Moho::VisionRenderer::~VisionRenderer)
   */
  VisionRenderer::~VisionRenderer()
  {
    ResetRenderResources();
  }

  /**
   * Address: 0x0081C550 (FUN_0081C550, sub_81C550)
   */
  void VisionRenderer::ResetRenderResources() noexcept
  {
    mFrame.ResetTransientResources();
    mGeometry.Reset();
    mVertexBuffer2.reset();
    mIndexCount = 0;
    mVertexCount = 0;
  }

  /**
   * Address: 0x0081C0C0 (FUN_0081C0C0, Moho::VisionRenderer::Init)
   */
  void VisionRenderer::Init()
  {
    ResetRenderResources();

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    if (!device) {
      return;
    }

    device->CreateVertexFormat(&mGeometry.mVertexFormat, 18u);

    mVertexCount = kVisionVertexCount;
    mIndexCount = kVisionIndexCount;

    gpg::gal::VertexBufferContext vertexBuffer1Context{};
    vertexBuffer1Context.width_ = mVertexCount;
    vertexBuffer1Context.height_ = 12u;
    vertexBuffer1Context.type_ = 2u;
    vertexBuffer1Context.usage_ = 1u;
    device->CreateVertexBuffer(&mGeometry.mVertexBuffer, &vertexBuffer1Context);

    gpg::gal::VertexBufferContext vertexBuffer2Context{};
    vertexBuffer2Context.width_ = kVisionInstanceRingCapacity;
    vertexBuffer2Context.height_ = 12u;
    vertexBuffer2Context.type_ = 3u;
    vertexBuffer2Context.usage_ = 2u;
    device->CreateVertexBuffer(&mVertexBuffer2, &vertexBuffer2Context);

    mInstanceRingCursor = 0;

    gpg::gal::IndexBufferContext indexBufferContext{};
    indexBufferContext.format_ = 1u;
    indexBufferContext.size_ = mIndexCount;
    indexBufferContext.type_ = 1u;
    device->CreateIndexBuffer(&mGeometry.mIndexBuffer, &indexBufferContext);

    if (mGeometry.mVertexBuffer) {
      float* const vertexData = static_cast<float*>(
        mGeometry.mVertexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0))
      );
      if (vertexData) {
        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const float angle = static_cast<float>(i) * kVisionAngleStep;
          const float cosValue = std::cos(angle);
          const float sinValue = std::sin(angle);

          // Vertical extents come from the map's own height range, published
          // by Sim::Create_exxt. The binary loads them here rather than using
          // immediates: `movss xmm2, ds:patch_maxMapHeight` at 0x0081C38A and
          // `movss xmm1, ds:patch_minMapHeight` at 0x0081C3C1.
          const float upperCapHeight = moho::patch_maxMapHeight;
          const float lowerCapHeight = moho::patch_minMapHeight;

          const std::uint32_t topBase = i * 3u;
          vertexData[topBase + 0u] = cosValue;
          vertexData[topBase + 1u] = upperCapHeight;
          vertexData[topBase + 2u] = sinValue;

          const std::uint32_t bottomBase = (kVisionSegmentCount * 3u) + (i * 3u);
          vertexData[bottomBase + 0u] = cosValue;
          vertexData[bottomBase + 1u] = lowerCapHeight;
          vertexData[bottomBase + 2u] = sinValue;
        }

        const std::uint32_t topCenterBase = (kVisionSegmentCount * 2u) * 3u;
        vertexData[topCenterBase + 0u] = 0.0f;
        vertexData[topCenterBase + 1u] = moho::patch_maxMapHeight;
        vertexData[topCenterBase + 2u] = 0.0f;

        const std::uint32_t bottomCenterBase = topCenterBase + 3u;
        vertexData[bottomCenterBase + 0u] = 0.0f;
        vertexData[bottomCenterBase + 1u] = moho::patch_minMapHeight;
        vertexData[bottomCenterBase + 2u] = 0.0f;
      }

      mGeometry.mVertexBuffer->Unlock();
    }

    if (mGeometry.mIndexBuffer) {
      std::int16_t* const indexData = mGeometry.mIndexBuffer->Lock(
        0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0)
      );
      if (indexData) {
        std::uint32_t outIndex = 0u;

        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const std::uint16_t next = static_cast<std::uint16_t>((i + 1u) % kVisionSegmentCount);
          const std::uint16_t current = static_cast<std::uint16_t>(i);
          const std::uint16_t currentBottom = static_cast<std::uint16_t>(i + kVisionSegmentCount);
          const std::uint16_t nextBottom = static_cast<std::uint16_t>(next + kVisionSegmentCount);

          indexData[outIndex++] = static_cast<std::int16_t>(current);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(nextBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
        }

        for (std::uint32_t i = 0; i < kVisionSegmentCount; ++i) {
          const std::uint16_t next = static_cast<std::uint16_t>((i + 1u) % kVisionSegmentCount);
          const std::uint16_t current = static_cast<std::uint16_t>(i);
          const std::uint16_t nextBottom = static_cast<std::uint16_t>(next + kVisionSegmentCount);
          const std::uint16_t currentBottom = static_cast<std::uint16_t>(i + kVisionSegmentCount);

          indexData[outIndex++] = static_cast<std::int16_t>(next);
          indexData[outIndex++] = static_cast<std::int16_t>(90u);
          indexData[outIndex++] = static_cast<std::int16_t>(current);
          indexData[outIndex++] = static_cast<std::int16_t>(nextBottom);
          indexData[outIndex++] = static_cast<std::int16_t>(91u);
          indexData[outIndex++] = static_cast<std::int16_t>(currentBottom);
        }
      }

      mGeometry.mIndexBuffer->Unlock();
    }
  }

  /**
   * Address: 0x0081C660 (FUN_0081C660, func_ren_FogOfWar)
   *
   * IDA signature:
   * HWND *__userpurge func_ren_FogOfWar@<eax>(Moho::CWldSession *a1@<ecx>,
   *         Moho::VisionRenderer *a2, unsigned int idx, Moho::GeomCamera3 *cam,
   *         float amt, int a6);
   *
   * What it does:
   * Renders one fog-of-war frame: gathers every visible vision circle whose
   * interpolated footprint overlaps the terrain area the camera frustum covers,
   * publishes the count as the `Vision_Total` engine stat, stencils the circles
   * through the `"CastVision"` technique in ring-buffer sized batches, and
   * composites the stencil with the renderer's `"Vision"` frame pass.
   */
  void RenderFogOfWar(
    CWldSession& session,
    VisionRenderer& renderer,
    const unsigned int headIndex,
    const GeomCamera3& camera,
    const float interpolant
  )
  {
    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const gpg::gal::Head& head = device->GetDeviceContext()->GetHead(headIndex);

    const boost::shared_ptr<gpg::gal::EffectD3D9> effect = AcquireVisionBaseEffect();
    const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique("CastVision");

    // `CWldSession::mVisionDb` (+0x3C8) is still declared with the placeholder
    // skeleton `moho::VisionDb` from moho/misc/VisionDb.h; the recovered layout
    // is `moho::VisionDB` in moho/vision/VisionDB.h. Both model the same
    // 0x24-byte binary object - collapsing the duplicate belongs to the owner of
    // moho/misc/VisionDb.h, so the cast stands in for it here.
    VisionDB& visionDb = reinterpret_cast<VisionDB&>(session.mVisionDb);
    const CHeightField* const heightField = session.GetSTIMap()->mHeightField.get();

    // Terrain footprint of the camera's far frustum solid, flattened to the XZ
    // plane: the box the vision tree is queried with is axis-aligned, so the two
    // axes are the unit basis vectors the shipped body caches in a guarded
    // function-local static (`dword_1104458` guard at 0x0081C731).
    const Wm3::AxisAlignedBox3f terrainFootprint = heightField->ConvexIntersection(camera.solid2);

    static const Wm3::Vector2f kUnitBoxAxes[2] = {Wm3::Vector2f{1.0f, 0.0f}, Wm3::Vector2f{0.0f, 1.0f}};

    Wm3::Box2f footprintBox;
    footprintBox.Center.x = (terrainFootprint.Min.x + terrainFootprint.Max.x) * 0.5f;
    footprintBox.Center.y = (terrainFootprint.Min.z + terrainFootprint.Max.z) * 0.5f;
    footprintBox.Axis[0] = kUnitBoxAxes[0];
    footprintBox.Axis[1] = kUnitBoxAxes[1];
    footprintBox.Extent[0] = terrainFootprint.Max.x - footprintBox.Center.x;
    footprintBox.Extent[1] = terrainFootprint.Max.z - footprintBox.Center.y;

    gpg::fastvector_n<Wm3::Circle2f, kVisibleCircleInlineCapacity> visibleCircles;
    visionDb.TryAdd(visibleCircles, visionDb.rootNode_, footprintBox, interpolant);

    const auto visibleCircleCount = static_cast<std::int32_t>(visibleCircles.size());

    if (sEngineStatVisionTotal == nullptr) {
      EngineStats* const engineStats = GetEngineStats();
      sEngineStatVisionTotal = engineStats->GetItem("Vision_Total", true);
      static_cast<void>(sEngineStatVisionTotal->Release(0));
    }
    static_cast<void>(sEngineStatVisionTotal->SetInt(&visibleCircleCount));

    device->Clear(false, false, true, 0xFFFFFFFFu, 1.0f, 0);

    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> viewMatrix = effect->SetMatrix("viewMatrix");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> projMatrix = effect->SetMatrix("projMatrix");
    viewMatrix->SetMatrix4x4(&camera.view);
    projMatrix->SetMatrix4x4(&camera.projection);

    // Stream 0 carries the shared cylinder geometry, replayed once per circle:
    // its stream frequency is the instance count. Stream 1 is bound per batch
    // below with the circle payload itself.
    device->SetVertexDeclaration(renderer.mGeometry.mVertexFormat);
    device->SetVertexBuffer(0u, renderer.mGeometry.mVertexBuffer, visibleCircleCount, 0);
    device->SetBufferIndices(renderer.mGeometry.mIndexBuffer);

    for (std::int32_t emitted = 0; emitted < visibleCircleCount;) {
      std::int32_t batchSize = visibleCircleCount - emitted;
      if (batchSize >= static_cast<std::int32_t>(kVisionInstanceRingCapacity)) {
        batchSize = static_cast<std::int32_t>(kVisionInstanceRingCapacity);
      }
      if (batchSize < 0) {
        batchSize = 0;
      }

      Wm3::Circle2f* mappedInstances = nullptr;
      std::uint32_t baseInstance = 0u;
      if (LockVisionInstanceRange(
            renderer, static_cast<std::uint32_t>(batchSize), mappedInstances, baseInstance
          )) {
        std::memcpy(
          mappedInstances,
          visibleCircles.begin() + emitted,
          sizeof(Wm3::Circle2f) * static_cast<std::size_t>(batchSize)
        );
        static_cast<void>(renderer.mVertexBuffer2->Unlock());

        device->SetVertexBuffer(1u, renderer.mVertexBuffer2, 1, static_cast<int>(baseInstance));

        const int passCount = technique->BeginTechnique();
        for (int pass = 0; pass < passCount; ++pass) {
          technique->BeginPass(pass);

          const gpg::gal::DrawIndexedContext draw{
            kTriangleListTopology,
            static_cast<int>(renderer.mVertexCount),
            static_cast<int>(renderer.mIndexCount),
            0,
            0
          };
          static_cast<void>(device->DrawIndexedPrimitive(&draw));

          technique->EndPass();
        }
        technique->EndTechnique();
      }

      emitted += batchSize;
    }

    const auto headWidth = static_cast<std::int32_t>(head.mWidth);
    const auto headHeight = static_cast<std::int32_t>(head.mHeight);

    renderer.mFrame.InitTransformedVerts(static_cast<float>(headWidth), static_cast<float>(headHeight));
    // 0x0081CB59 constructs the name in place over `mFrame.mName`; "Vision" is
    // short enough to stay in the string's inline buffer, so a plain assignment
    // reproduces the resulting state without leaking.
    renderer.mFrame.mName = "Vision";
    renderer.mFrame.Render(headWidth, headHeight);
  }
} // namespace moho
