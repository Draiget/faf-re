#include "moho/render/RangeRenderer.h"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string_view>

#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/RangeExtractor.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/RangeRendererStartupRegistrations.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/VisibilityRect.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  using RangeExtractionPayloadVector = msvc8::vector<moho::SRangeExtractionPayload>;

  constexpr std::uint32_t kRangeRingSegmentCount = 45u;
  constexpr std::uint32_t kRangeVertexCount = kRangeRingSegmentCount * 4u; // 180
  constexpr std::uint32_t kRangeIndexCount = kRangeRingSegmentCount * 24u; // 1080

  constexpr std::uint32_t kPrimaryVertexStrideBytes = 20u;
  constexpr std::uint32_t kDynamicVertexCapacity = 1000u;
  constexpr std::uint32_t kDynamicVertexStrideBytes = 16u;

  constexpr float kRangeAngleStepRadians = 0.13962634f; // 2*pi/45
  /**
   * Address: 0x007EC320 (FUN_007EC320, func_GetRangeEffect)
   *
   * What it does:
   * Resolves one `"range"` D3D effect from device resources and returns
   * its base GAL effect handle.
   */
  [[nodiscard, maybe_unused]] boost::shared_ptr<gpg::gal::EffectD3D9> AcquireRangeRingBaseEffect()
  {
    moho::ID3DDeviceResources* const resources = moho::D3D_GetDevice()->GetResources();
    moho::CD3DEffect* const effect = resources->FindEffect("range");
    return effect->GetBaseEffect();
  }

  /**
   * Address: 0x007F03D0 (FUN_007F03D0, sub_7F03D0)
   *
   * `sub_7F03D0`'s only real caller in this binary is `RangeRenderer::Render`
   * (0x007EEAA3) - byte-verified via the namespace callgraph index, which
   * lists exactly one code xref to this address. A prior recovery pass
   * attributed this address to a `fastvector_n<SRangeExtractionPayload,20>`
   * copy helper, citing no caller evidence; that shape does not match the one
   * real call site, which snapshots `CameraImpl::GetArmyUnitsInFrustum()`'s
   * cached `CameraFrustumUserEntityList` (stride
   * `sizeof(CameraUserEntityWeakRef) == 0x08`) into a `Render`-local buffer
   * before building `func_ExtractRanges`'s candidate-pool view. Retyped here
   * per that evidence; the struct's total inline-capacity span (0x140 bytes)
   * is unchanged from the original recovery, only the element stride/count
   * (0x08 * 40, not 0x10 * 20).
   */
  struct CameraFrustumWeakRefSnapshotBuffer
  {
    moho::CameraFrustumUserEntityList mView;           // +0x00
    moho::CameraUserEntityWeakRef mInlineStorage[40];  // +0x10

    /**
     * Address: inlined at 0x007EEB13..0x007EEB52 in `RangeRenderer::Render`
     * (FUN_007EEA00) - the detach walk followed by the guarded
     * `operator delete[]` at 0x007EEB4D.
     *
     * Every snapshotted element is spliced into the intrusive weak-link chain
     * of the entity it tracks. This buffer lives on `Render`'s stack, so those
     * chains must be unspliced before the frame unwinds or the camera's next
     * frustum-cache rebuild walks a chain into a dead stack frame.
     */
    ~CameraFrustumWeakRefSnapshotBuffer() noexcept { mView.DetachAndRelease(); }
  };
  static_assert(sizeof(CameraFrustumWeakRefSnapshotBuffer) == 0x150, "CameraFrustumWeakRefSnapshotBuffer size must be 0x150");

  /**
   * Address: 0x007F03D0 (FUN_007F03D0, sub_7F03D0)
   *
   * What it does:
   * Rebinds one `fastvector_n<CameraUserEntityWeakRef,40>` snapshot buffer to
   * inline storage, then assigns the camera's current frustum weak-ref list
   * into it via `CameraFrustumUserEntityList::AssignRange` (FUN_007F20E0),
   * which relinks each copied weak-ref into the new storage's owner chains
   * and spills to heap when the source list exceeds inline capacity.
   *
   * The buffer holds a real `CameraFrustumUserEntityList` header followed by
   * its inline element block - the same 0x150 shape the camera's own three
   * frustum lanes use - so the lane's whole machinery applies to it unchanged,
   * destructor included. A prior version of this
   * function used a raw `std::memcpy`, which is wrong for this element type:
   * each `CameraUserEntityWeakRef` is spliced into its tracked entity's
   * intrusive weak-link chain, and a byte copy leaves that chain still
   * pointing at the old (about-to-be-discarded) storage instead of the
   * fresh snapshot.
   */
  CameraFrustumWeakRefSnapshotBuffer* SnapshotCameraFrustumWeakRefs(
    CameraFrustumWeakRefSnapshotBuffer* const destination,
    const moho::CameraFrustumUserEntityList& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    constexpr std::size_t kInlineCount = 40u;
    moho::CameraUserEntityWeakRef* const inlineStart = &destination->mInlineStorage[0];
    destination->mView.mStart = inlineStart;
    destination->mView.mFinish = inlineStart;
    destination->mView.mCapacity = inlineStart + kInlineCount;
    destination->mView.mInlineOrigin = inlineStart;

    auto* const assignedEnd = destination->mView.AssignRange(source);
    (void)assignedEnd;

    return destination;
  }

  struct RangeRingGeometryBuildState
  {
    float innerThicknessOffset;
    float outerThicknessOffset;
    RangeExtractionPayloadVector* fillPayloads;
    RangeExtractionPayloadVector* edgePayloads;
  };

#if defined(_M_IX86)
  static_assert(sizeof(RangeRingGeometryBuildState) == 0x10, "RangeRingGeometryBuildState size must be 0x10");
#endif

  /**
   * Address: 0x007EDC80 (FUN_007EDC80, sub_7EDC80)
   *
   * What it does:
   * Expands one source range entry into render payload lanes:
   * - 1 fill ring payload
   * - 2 edge ring payloads (inner and outer edge)
   */
  void BuildRingPayloadEntry(
    RangeRingGeometryBuildState& state,
    const moho::SRangeExtractionPayload& sourcePayload
  )
  {
    moho::SRangeExtractionPayload fillPayload = sourcePayload;
    fillPayload.innerRadius =
      (sourcePayload.innerRadius <= 0.0f) ? 0.0f : (sourcePayload.innerRadius + state.innerThicknessOffset);
    fillPayload.outerRadius = sourcePayload.outerRadius - state.outerThicknessOffset;
    state.fillPayloads->push_back(fillPayload);

    moho::SRangeExtractionPayload innerEdgePayload = sourcePayload;
    innerEdgePayload.outerRadius = sourcePayload.innerRadius + state.innerThicknessOffset;
    state.edgePayloads->push_back(innerEdgePayload);

    moho::SRangeExtractionPayload outerEdgePayload = sourcePayload;
    outerEdgePayload.innerRadius = sourcePayload.outerRadius - state.outerThicknessOffset;
    outerEdgePayload.outerRadius = sourcePayload.outerRadius;
    state.edgePayloads->push_back(outerEdgePayload);
  }

  /**
   * Address: 0x007F32E0 (FUN_007F32E0, sub_7F32E0)
   *
   * What it does:
   * Builds fill + edge payload vectors for one half-open input entry range.
   */
  void BuildRingPayloadBuffers(
    RangeRingGeometryBuildState& state,
    const moho::SRangeExtractionPayload* entryBegin,
    const moho::SRangeExtractionPayload* entryEnd
  )
  {
    for (const moho::SRangeExtractionPayload* entry = entryBegin; entry != entryEnd; ++entry) {
      BuildRingPayloadEntry(state, *entry);
    }
  }

  struct RangeDynamicVertexAllocatorVTable
  {
    std::uint8_t reserved_00[0x08];
    int(__thiscall* lockRange)(void* self, int offsetBytes, unsigned int sizeBytes, int lockMode); // +0x08
  };

  struct RangeDynamicVertexAllocatorRuntime
  {
    RangeDynamicVertexAllocatorVTable* vtable; // +0x00
  };

  struct RangeDynamicVertexReservationStateRuntime
  {
    std::uint8_t reserved_00[0x40];
    std::uint32_t activeVertexCount;                 // +0x40
    RangeDynamicVertexAllocatorRuntime* allocator;   // +0x44
  };

  static_assert(
    offsetof(RangeDynamicVertexReservationStateRuntime, activeVertexCount) == 0x40,
    "RangeDynamicVertexReservationStateRuntime::activeVertexCount offset must be 0x40"
  );
  static_assert(
    offsetof(RangeDynamicVertexReservationStateRuntime, allocator) == 0x44,
    "RangeDynamicVertexReservationStateRuntime::allocator offset must be 0x44"
  );

  /**
   * Address: 0x007EEDC0 (FUN_007EEDC0)
   *
   * What it does:
   * Reserves one contiguous dynamic ring-vertex slice (16-byte stride) inside
   * a 1000-vertex arena, either by appending after current occupancy or by
   * resetting/relocking the arena when append would overflow.
   */
  bool ReserveDynamicRingVertexSliceRuntime(
    const std::uint32_t requestedVertexCount,
    int* const outVertexWriteBase,
    RangeDynamicVertexReservationStateRuntime* const state,
    std::uint32_t* const outPreviousVertexCount
  ) noexcept
  {
    if (outVertexWriteBase == nullptr || state == nullptr || state->allocator == nullptr || state->allocator->vtable == nullptr ||
        state->allocator->vtable->lockRange == nullptr) {
      return false;
    }

    constexpr std::uint32_t kDynamicVertexLimit = 1000u;
    constexpr std::uint32_t kDynamicVertexStrideBytes = 16u;
    constexpr int kLockModeDiscard = 1;
    constexpr int kLockModeNoOverwrite = 4;

    const std::uint32_t used = state->activeVertexCount;
    if (used + requestedVertexCount < kDynamicVertexLimit) {
      const int writeBase = state->allocator->vtable->lockRange(
        state->allocator, static_cast<int>(used * kDynamicVertexStrideBytes), requestedVertexCount * kDynamicVertexStrideBytes,
        kLockModeNoOverwrite
      );
      *outVertexWriteBase = writeBase;
      if (writeBase != 0) {
        if (outPreviousVertexCount != nullptr) {
          *outPreviousVertexCount = used;
        }
        state->activeVertexCount = used + requestedVertexCount;
        return true;
      }
      return false;
    }

    if (requestedVertexCount > kDynamicVertexLimit) {
      return false;
    }

    state->activeVertexCount = requestedVertexCount;
    if (outPreviousVertexCount != nullptr) {
      *outPreviousVertexCount = 0u;
    }

    const int writeBase = state->allocator->vtable->lockRange(
      state->allocator, 0, requestedVertexCount * kDynamicVertexStrideBytes, kLockModeDiscard
    );
    *outVertexWriteBase = writeBase;
    return writeBase != 0;
  }

  constexpr std::int32_t kTriangleListPrimitiveToken = 4; // D3DPT_TRIANGLELIST
  constexpr std::uint32_t kDynamicVertexBatchLimit = 1000u;

  /**
   * The "frame" effect's shader-variable slot for the fill/burn ring color.
   * Follows the same lazy-register idiom as `CRenFrame.cpp`'s
   * `DEFINE_FRAME_SHADER_VAR_GETTER` family (register-on-first-use static,
   * bound into the "frame" effect group - the effect `CRenFrame::Render`
   * selects for the "RangeMask" / "RangeFill" / "RangeBurn" technique passes
   * below).
   *
   * The name is `rangeColor`, spelled as `gamedata/effects/frame.fx` declares
   * it (`float4 rangeColor = float4(0.2,0.2,0.2,0.2);`, line 25, consumed by
   * `RangeBurn`'s `RangePS(rangeColor)`). A previous pass guessed "RangeColor"
   * from the surrounding `FrameTexture1..4` siblings; shader variable lookup is
   * case-sensitive, so that never resolved and every ring burned with the
   * shader's own default instead of its profile color.
   */
  [[nodiscard]] moho::ShaderVar& GetFrameRangeColorShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static const bool registered = (moho::RegisterShaderVar("rangeColor", &shaderVar, "frame"), true);
    (void)registered;
    return shaderVar;
  }

  /**
   * Address: 0x007EF9B0 (FUN_007EF9B0, func_Draw_Rings)
   *
   * IDA signature (LTCG-reshaped; `retn 8` pops exactly 2 stack dwords beyond
   * the ecx register argument - the seven-argument `char a3, int a4..a8`
   * shape Hex-Rays printed is a decompiler stack-tracking artifact, the same
   * family as the "positive sp value" warning on `RangeRenderer::Render`):
   * void __usercall func_Draw_Rings(GeomCamera3 *cameraView@<ecx>, unsigned int vertexCount,
   *                                  int dynamicStreamStartVertex);
   *
   * `edi` (RangeRenderer* rangeRenderer) is never reloaded between
   * `func_RenderRings` setting it up (0x007EF791) and this call - LTCG left it
   * live across the call instead of re-pushing it. Modelled here as an
   * explicit parameter rather than relying on caller register state.
   *
   * What it does:
   * Draws one batch of range-ring geometry through the "range" effect's
   * "Cast" technique: binds the camera's projection matrix (view matrix
   * variable is fetched but never rewritten here - the device already carries
   * it), binds the renderer's static ring-template vertex/index buffers on
   * stream 0 and its dynamic per-batch vertex buffer on stream 1 (offset by
   * `dynamicStreamStartVertex`, the vertex index `ReserveDynamicRingVertexSliceRuntime`
   * returned for this batch), and issues one indexed draw per technique pass.
   */
  void DrawRangeRingBatch(
    const moho::GeomCamera3& cameraView,
    moho::RangeRenderer& rangeRenderer,
    const std::uint32_t vertexCount,
    const int dynamicStreamStartVertex
  )
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    boost::shared_ptr<gpg::gal::EffectD3D9> effect = AcquireRangeRingBaseEffect();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> castTechnique = effect->SetTechnique("Cast");
    boost::shared_ptr<gpg::gal::EffectVariableD3D9> viewMatrixVar = effect->SetMatrix("viewMatrix");
    boost::shared_ptr<gpg::gal::EffectVariableD3D9> projMatrixVar = effect->SetMatrix("projMatrix");

    // `range.fx` declares both `viewMatrix` and `projMatrix` as its own globals,
    // so both have to be pushed - the device's matrices are a different effect's
    // state and do not reach this one. The binary does exactly that at
    // 0x007EFA4D..0x007EFA65: two calls through vtable slot 5 (+0x14) of the
    // variable handles, `[camera+0x5C]` (GeomCamera3::view) first and
    // `[camera+0x1C]` (::projection) second. An earlier pass read the first of
    // those as `EffectD3D9::OnReset()` and dropped the view matrix, which left
    // `viewMatrix` at whatever the effect loaded with and transformed every ring
    // out of frame.
    viewMatrixVar->SetMatrix4x4(&cameraView.view);
    projMatrixVar->SetMatrix4x4(&cameraView.projection);

    device->SetVertexDeclaration(rangeRenderer.mGeometry.mVertexFormat);
    // Stream 0 (static ring-template geometry) is bound with an indexed-data
    // frequency of `vertexCount` - this batch's instance count - matching the
    // standard D3D9 hardware-instancing idiom for a per-vertex template stream
    // shared across many instances. Stream 1 (this batch's dynamic per-instance
    // data) steps once per instance (frequency 1) starting at
    // `dynamicStreamStartVertex`.
    constexpr std::uint32_t kD3DStreamSourceIndexedData = 0x40000000u;
    device->SetVertexBuffer(
      0, rangeRenderer.mGeometry.mVertexBuffer, static_cast<int>(kD3DStreamSourceIndexedData | vertexCount), 0
    );
    device->SetVertexBuffer(1, rangeRenderer.mDynamicVertexBuffer, 1, dynamicStreamStartVertex);
    device->SetBufferIndices(rangeRenderer.mGeometry.mIndexBuffer);

    const int passCount = castTechnique->BeginTechnique();
    for (int pass = 0; pass < passCount; ++pass) {
      castTechnique->BeginPass(pass);
      gpg::gal::DrawIndexedContext drawContext(
        kTriangleListPrimitiveToken, static_cast<int>(rangeRenderer.mVertexCount),
        static_cast<int>(rangeRenderer.mIndexCount), 0, 0
      );
      device->DrawIndexedPrimitive(&drawContext);
      castTechnique->EndPass();
    }
    castTechnique->EndTechnique();
  }

  /**
   * Address: 0x007EF5A0 (FUN_007EF5A0, func_RenderRings)
   *
   * IDA signature (LTCG-reshaped __fastcall; param roles resolved from
   * `RangeRenderer::Render`'s three call sites plus `func_RenderBuildRings`
   * and `sub_7EF420`, all of which pass the exact same slot shapes):
   * void __fastcall func_RenderRings(
   *     RangeRingRadiusParams *outerRingParams@<ecx>, CameraImpl *camera@<edx>,
   *     RangeRenderer *rangeRenderer, unsigned int headIndex, RangeRingColor *ringColor,
   *     RangeRingRadiusParams *innerRingParams, RangeExtractionPayloadVector *ringEntries);
   *
   * `ringEntries` (the stack-passed last parameter, "i" in the decompile) is a
   * pre-filled accumulator: every caller extracts candidate ranges into it
   * before this call (`func_ExtractRanges`, `sub_7EF280`, `sub_7EF420`,
   * `func_RenderBuildRings`). This function reads its element count from
   * `{_Myfirst,_Mylast}` directly (0x007EF5C4-DC) and bails when empty.
   *
   * What it does:
   * - resolves the playable-map span (max of width/height from the terrain's
   *   playable rect) and the camera's zoom ratio
   *   (`CameraGetTargetZoom() / GetMaxZoom()`)
   * - derives inner/outer ring thickness offsets from the profile's radius
   *   params, the `range_InnerThicknessCoeff`/`range_OuterThicknessCoeff`
   *   console variables, the map span and the zoom ratio (matches
   *   `BuildRingPayloadEntry`'s formula exactly - re-verified against this
   *   function's own raw asm at 0x007EF678-6D6)
   * - expands every source entry into 1 fill payload + 2 edge payloads
   *   (`BuildRingPayloadBuffers`)
   * - draws the fill payloads in batches of up to 1000 dynamic vertices, each
   *   batch locked via `ReserveDynamicRingVertexSliceRuntime` and drawn via
   *   `DrawRangeRingBatch`, then runs the renderer's "RangeMask" frame pass
   * - draws the edge payloads (2x the fill count, inner+outer edge per source
   *   entry) the same way, then runs "RangeFill" (gated on `range_Fill`) and
   *   "RangeBurn", pushing `ringColor` into the `shaderVarFrameRangeColor`-
   *   equivalent shader variable before the burn pass
   * - clears the device target/stencil once at the end
   */
  void RenderRingBatch(
    const moho::RangeRingRadiusParams& outerRingParams,
    const moho::CameraImpl& camera,
    moho::RangeRenderer& rangeRenderer,
    const unsigned int headIndex,
    const moho::RangeRingColor& ringColor,
    const moho::RangeRingRadiusParams& innerRingParams,
    const RangeExtractionPayloadVector& ringEntries
  )
  {
    const std::uint32_t ringCount = static_cast<std::uint32_t>(ringEntries.size());
    if (ringCount == 0u) {
      return;
    }

    moho::IWldTerrainRes* const terrainRes = moho::REN_GetTerrainRes();
    if (terrainRes == nullptr) {
      return;
    }

    moho::VisibilityRect playableRect{};
    (void)terrainRes->GetPlayableMapRect(playableRect);
    const std::int32_t widthSpan = playableRect.maxX - playableRect.minX;
    const std::int32_t heightSpan = playableRect.maxZ - playableRect.minZ;
    const float playableMapSpan = static_cast<float>(widthSpan < heightSpan ? heightSpan : widthSpan);

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    gpg::gal::DeviceContext* const deviceContext = device->GetDeviceContext();
    const gpg::gal::Head& head = deviceContext->GetHead(headIndex);

    const moho::GeomCamera3& cameraView = camera.CameraGetView();
    const float zoomScale = camera.CameraGetTargetZoom() / camera.GetMaxZoom();

    const float innerThicknessOffset =
      (((innerRingParams.thicknessScalar * moho::range_InnerThicknessCoeff) * playableMapSpan) -
       innerRingParams.radius) *
        zoomScale +
      innerRingParams.radius;
    const float outerThicknessOffset =
      (((outerRingParams.thicknessScalar * moho::range_OuterThicknessCoeff) * playableMapSpan) -
       outerRingParams.radius) *
        zoomScale +
      outerRingParams.radius;

    RangeExtractionPayloadVector fillPayloads;
    RangeExtractionPayloadVector edgePayloads;
    RangeRingGeometryBuildState buildState{innerThicknessOffset, outerThicknessOffset, &fillPayloads, &edgePayloads};
    BuildRingPayloadBuffers(buildState, ringEntries.begin(), ringEntries.end());

    // `ReserveDynamicRingVertexSliceRuntime`'s state parameter is the same
    // `{activeVertexCount@+0x40, allocator@+0x44}` lane the binary reads
    // straight out of the `RangeRenderer` object at those exact offsets
    // (`RangeRenderer::mDynamicRingVertexCount`/`mDynamicVertexBuffer` per the
    // header's own static_asserts) - this is that function's own documented
    // aliasing contract, not new offset magic introduced here.
    auto* const dynamicState = reinterpret_cast<RangeDynamicVertexReservationStateRuntime*>(&rangeRenderer);

    const auto drawBatched = [&](const RangeExtractionPayloadVector& payloads) {
      const std::uint32_t totalCount = static_cast<std::uint32_t>(payloads.size());
      std::uint32_t drawn = 0u;
      while (drawn < totalCount) {
        const std::uint32_t remaining = totalCount - drawn;
        const std::uint32_t batchCount = remaining < kDynamicVertexBatchLimit ? remaining : kDynamicVertexBatchLimit;

        int lockedWritePtr = 0;
        std::uint32_t previousVertexCount = 0u;
        if (ReserveDynamicRingVertexSliceRuntime(batchCount, &lockedWritePtr, dynamicState, &previousVertexCount)) {
          std::memcpy(
            reinterpret_cast<void*>(lockedWritePtr), payloads.begin() + drawn,
            sizeof(moho::SRangeExtractionPayload) * batchCount
          );
          rangeRenderer.mDynamicVertexBuffer->Unlock();
          DrawRangeRingBatch(cameraView, rangeRenderer, batchCount, static_cast<int>(previousVertexCount));
        }
        drawn += batchCount;
      }
    };

    drawBatched(fillPayloads);

    rangeRenderer.mFrame.InitTransformedVerts(static_cast<float>(head.mWidth), static_cast<float>(head.mHeight));
    rangeRenderer.mFrame.mName.assign_owned("RangeMask");
    rangeRenderer.mFrame.Render(static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));

    drawBatched(edgePayloads);

    if (moho::range_Fill) {
      rangeRenderer.mFrame.mName.assign_owned("RangeFill");
      rangeRenderer.mFrame.Render(static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));
    }

    if (GetFrameRangeColorShaderVar().Exists()) {
      GetFrameRangeColorShaderVar().mEffectVariable->SetMem(4u, &ringColor.r);
    }

    rangeRenderer.mFrame.mName.assign_owned("RangeBurn");
    rangeRenderer.mFrame.Render(static_cast<int>(head.mWidth), static_cast<int>(head.mHeight));

    device->Clear(false, false, true, 0xFFFFFFFFu, 1.0f, 0);
  }

  void WriteRingBandVertex(
    float* const vertexData,
    const std::uint32_t vertexIndex,
    const float x,
    const float y,
    const float z,
    const float lane0,
    const float lane1
  )
  {
    const std::uint32_t base = vertexIndex * 5u;
    vertexData[base + 0u] = x;
    vertexData[base + 1u] = y;
    vertexData[base + 2u] = z;
    vertexData[base + 3u] = lane0;
    vertexData[base + 4u] = lane1;
  }

  std::uint32_t AppendRingStripIndices(
    std::uint32_t writeIndex,
    std::int16_t* const indexData,
    const std::uint16_t start,
    const std::uint16_t end,
    const std::uint16_t ringOffset,
    const bool usePrimaryWinding
  )
  {
    if (!indexData || start >= end) {
      return writeIndex;
    }

    for (std::uint16_t current = start; current < end; ++current) {
      const std::uint16_t currentOpposite = static_cast<std::uint16_t>(current + ringOffset);
      const std::int32_t candidateNextSigned =
        static_cast<std::int32_t>(currentOpposite) + (1 - static_cast<std::int32_t>(ringOffset));
      const std::uint16_t candidateNext = static_cast<std::uint16_t>(candidateNextSigned);
      const std::uint16_t next = (candidateNext != end) ? candidateNext : start;
      const std::uint16_t nextOpposite = static_cast<std::uint16_t>(next + ringOffset);

      if (usePrimaryWinding) {
        indexData[writeIndex++] = static_cast<std::int16_t>(current);
        indexData[writeIndex++] = static_cast<std::int16_t>(currentOpposite);
        indexData[writeIndex++] = static_cast<std::int16_t>(next);
        indexData[writeIndex++] = static_cast<std::int16_t>(nextOpposite);
        indexData[writeIndex++] = static_cast<std::int16_t>(next);
        indexData[writeIndex++] = static_cast<std::int16_t>(currentOpposite);
      } else {
        indexData[writeIndex++] = static_cast<std::int16_t>(next);
        indexData[writeIndex++] = static_cast<std::int16_t>(currentOpposite);
        indexData[writeIndex++] = static_cast<std::int16_t>(current);
        indexData[writeIndex++] = static_cast<std::int16_t>(currentOpposite);
        indexData[writeIndex++] = static_cast<std::int16_t>(next);
        indexData[writeIndex++] = static_cast<std::int16_t>(nextOpposite);
      }
    }

    return writeIndex;
  }

  [[nodiscard]] moho::RangeRingColor DecodePackedRgbaColor(const std::uint32_t packedColor) noexcept
  {
    constexpr float kByteToFloat = 0.0039209998f;
    return {
      static_cast<float>((packedColor >> 16u) & 0xFFu) * kByteToFloat,
      static_cast<float>((packedColor >> 8u) & 0xFFu) * kByteToFloat,
      static_cast<float>(packedColor & 0xFFu) * kByteToFloat,
      static_cast<float>((packedColor >> 24u) & 0xFFu) * kByteToFloat,
    };
  }

  /**
   * Shared blueprint gate used by `func_RenderBuildRings` and `sub_7EF420`
   * before either checks a profile's own category filter. Both binary bodies
   * test the candidate blueprint against two named categories ("AllMilitary"
   * then "AllIntel") ahead of the profile-specific
   * `EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)` check;
   * IDA's decompile renders those two tests as calls into
   * `std::operator<(basic_string,basic_string)` (`__imp_??$?MDU?$char_traits...`),
   * which is almost certainly an `/OPT:ICF`-folded byte-identical body shared
   * with an unrelated string comparison rather than a literal string compare
   * of "AllMilitary"/"AllIntel" against something - the surrounding operands
   * (a blueprint-relative category bitset, an inline bit index) don't fit a
   * string-comparison call shape. Reconstructed here using the already-typed,
   * already-recovered `EntityCategoryLookupResolver::GetEntityCategory(name)`
   * + `EntityCategory::HasBlueprint` pair, which matches the surrounding
   * category-membership semantics exactly.
   */
  [[nodiscard]] bool ProfileParticipatesInPerUnitPasses(const moho::SRangeRenderProfile& profile) noexcept
  {
    // The two combination profiles ("Combine Military" / "Combine Intel") are
    // aggregates of the other profiles' categories: they exist for the
    // frustum-wide pass and must not draw a second ring over a unit that its
    // own profile already covered.
    //
    // The binary tests exactly this, once per profile and before it touches
    // the selection at all: `std::string::compare(0, npos, "AllMilitary", 11)`
    // at 0x007EF2C9 and `("AllIntel", 8)` at 0x007EF2E5, both on the profile's
    // own name at `[profile+0x14]`, each jumping to the function's exit when
    // the compare returns equal. An earlier pass read those two as category
    // membership tests against the *blueprint* and required a unit to be in
    // both AllMilitary and AllIntel at once - which essentially nothing is, so
    // every per-unit pass rejected every unit and no selected-unit or
    // hovered-unit ring was ever drawn.
    return profile.mExtractorName != "AllMilitary" && profile.mExtractorName != "AllIntel";
  }

  /**
   * Address: 0x007EEE50 (FUN_007EEE50, func_RenderBuildRings)
   *
   * IDA signature:
   * Moho::UserEntity *__thiscall func_RenderBuildRings(
   *     Moho::CWldSession *this, Moho::RangeRenderer *renderer,
   *     RangeExtractionPayloadVector *scratchPayload, Moho::CameraImpl *camera,
   *     unsigned int headIndex);
   *
   * Callsite evidence: sole caller is `RangeRenderer::Render` (0x007EEA5B),
   * gated on `range_RenderBuild` at both the caller and this recovery.
   *
   * What it does:
   * Resolves the current build-placement cursor snapshot
   * (`GetLeftMouseButtonAction`); when the cursor is in build/build-anchored
   * mode with a live preview blueprint, walks every registered range profile
   * and - for each whose extractor resolves and whose category filter (plus
   * the shared `BlueprintPassesRangeVisibilityGate`) accepts the preview
   * blueprint - extracts one range at the cursor's world position and draws
   * it immediately with `profile.mBuildRingColor`.
   */
  void RenderBuildRingsUnderCursor(
    moho::CWldSession& session,
    RangeExtractionPayloadVector& scratchPayload,
    moho::RangeRenderer& rangeRenderer,
    const moho::CameraImpl& camera,
    const unsigned int headIndex
  )
  {
    moho::CommandModeData modeData{};
    (void)session.GetLeftMouseButtonAction(&modeData, &session.GetCursorInfo(), 0);

    if (modeData.mMode != moho::COMMOD_Build && modeData.mMode != moho::COMMOD_BuildAnchored) {
      return;
    }
    if (modeData.mBlueprint == nullptr) {
      return;
    }

    const auto* const blueprint = static_cast<const moho::RUnitBlueprint*>(modeData.mBlueprint);
    const Wm3::Vector3f& cursorWorldPos = session.GetCursorInfo().mMouseWorldPos;

    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }
      if (!ProfileParticipatesInPerUnitPasses(profile)) {
        continue;
      }
      if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      moho::SRangeExtractionPayload payload{};
      if (!extractor->Range(&payload, blueprint, cursorWorldPos)) {
        continue;
      }

      scratchPayload.clear();
      scratchPayload.push_back(payload);
      RenderRingBatch(
        profile.mOuterRingParams, camera, rangeRenderer, headIndex, profile.mBuildRingColor, profile.mInnerRingParams,
        scratchPayload
      );
    }
  }

  /**
   * The concrete weapon profiles that together make up what a player reads as
   * "attack range".
   *
   * "AllMilitary" is deliberately not one of them. It is a combine profile and
   * `CombinedMilitaryExtractor` implements only `Extract`; its `Range`
   * (blueprint + centre) override returns false, so it yields nothing for a
   * position that has no unit on it. Its *colours* are still the red the
   * range-overlay menu gives military ranges - see `FindMilitaryStyleProfile`.
   */
  [[nodiscard]] bool IsAttackRangeProfile(const moho::SRangeRenderProfile& profile)
  {
    return profile.mExtractorName == "DirectFire"
      || profile.mExtractorName == "IndirectFire"
      || profile.mExtractorName == "AntiAir"
      || profile.mExtractorName == "AntiNavy";
  }

  /**
   * The profile whose colours are the red players read as "attack range":
   * "AllMilitary", falling back to "DirectFire".
   *
   * Both carry the same `NormalColor` ff2c2c (`rangeoverlayparams.lua` lines 56
   * and 105), so the fallback is the same red rather than an approximation of
   * it. It exists because the combine profiles are the ones a UI mod is most
   * likely to have re-registered, and without it a missing "AllMilitary" sent
   * the ring to whichever weapon profile happened to win - IndirectFire's
   * yellow f2f029, AntiAir's cyan 29def2 or AntiNavy's green 7af229.
   *
   * Only styling is ever borrowed: the radius and the ring geometry always come
   * from the concrete weapon profile that produced them, so thickness stays
   * paired with its own profile.
   */
  [[nodiscard]] const moho::SRangeRenderProfile* FindMilitaryStyleProfile(
    const moho::RangeRenderer& rangeRenderer
  )
  {
    const moho::SRangeRenderProfile* directFire = nullptr;
    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {
      if (profile.mExtractorName == "AllMilitary") {
        return &profile;
      }
      if (profile.mExtractorName == "DirectFire") {
        directFire = &profile;
      }
    }
    return directFire;
  }

  /**
   * The reclaim gate's own footprint measure: the *whole* footprint rather than
   * its half-extent, exactly as `MaxFootprintExtent` in
   * `CUnitReclaimTask.cpp:82` computes it.
   */
  [[nodiscard]] float MaxFootprintExtent(const moho::SFootprint& footprint) noexcept
  {
    return static_cast<float>(
      (footprint.mSizeX >= footprint.mSizeZ) ? static_cast<int>(footprint.mSizeX)
                                             : static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * One entity's footprint extent, read from the same place the gate reads it.
   *
   * `Entity::GetFootprint` (0x00678880) returns `BluePrint->mFootprint` - an
   * `SFootprint` held **by value** on the *entity* blueprint (+0xD8), so it can
   * never be absent. `RUnitBlueprint::Physics.ResolvedFootprint` is a different
   * thing and is genuinely null for real units: probing a live session, the
   * selected `MaxBuildDistance = 5` unit resolved it to `nullptr`, which
   * silently dropped the entire self-extent term and understated the ring by a
   * whole footprint. Reading the entity blueprint fixes that and costs nothing.
   *
   * It also means props and wrecks measure correctly - they carry an
   * `REntityBlueprint` but no `RUnitBlueprint` - which matters because a wreck
   * is what a reclaim order usually targets.
   *
   * The one thing this cannot see is the gate's alt-footprint swap
   * (`mUseAltFootprint`, Entity.h:1478): those flags live on the sim `Entity`,
   * not on the client mirror this pass runs against. It affects only units that
   * carry a second footprint at all, and it is the default footprint that is
   * wrong to omit.
   */
  [[nodiscard]] float ReclaimFootprintExtentOf(const moho::UserEntity& entity) noexcept
  {
    const moho::REntityBlueprint* const entityBlueprint = entity.mParams.mBlueprint;
    return (entityBlueprint != nullptr) ? MaxFootprintExtent(entityBlueprint->mFootprint) : 0.0f;
  }

  /**
   * `FallbackReclaimFootprint()`'s 2x2 (`CUnitReclaimTask.cpp:87-97`): the
   * footprint the reclaim gate measures against when it has no target entity.
   */
  constexpr float kFallbackReclaimFootprintExtent = 2.0f;

  /**
   * Keeps whichever of the running best and the candidate is the better answer
   * to "what is this unit's attack range".
   *
   * Direct fire wins outright when the unit has any, because that is what a
   * player means by the phrase; otherwise the widest of the remaining
   * categories stands in, so an artillery piece or a pure AA unit still gets a
   * ring. That is a strict weak ordering, so the winner does not depend on the
   * order candidates are offered in - which is what lets the multi-unit pass
   * walk profile-major and the single-unit pass walk profile-only.
   */
  void KeepWiderAttackRing(
    const moho::SRangeRenderProfile*& bestProfile,
    moho::SRangeExtractionPayload& bestPayload,
    const moho::SRangeRenderProfile& candidateProfile,
    const moho::SRangeExtractionPayload& candidatePayload
  )
  {
    const bool candidateIsDirect = candidateProfile.mExtractorName == "DirectFire";
    const bool bestIsDirect = bestProfile != nullptr && bestProfile->mExtractorName == "DirectFire";

    if (bestProfile == nullptr
        || (candidateIsDirect && !bestIsDirect)
        || (candidateIsDirect == bestIsDirect && candidatePayload.outerRadius > bestPayload.outerRadius)) {
      bestProfile = &candidateProfile;
      bestPayload = candidatePayload;
    }
  }

  /**
   * NOT A RECOVERED FUNCTION - there is no body for this in the shipped image
   * and no `Address:` can be cited for it. Additive extension, gated on
   * `range_RenderSelectedAtCursor`, which the loader leaves false.
   *
   * The engine already draws real ring geometry at the cursor, but only for a
   * building being placed: `RenderBuildRingsUnderCursor` takes its blueprint
   * from the build-preview command mode. This does the same for the current
   * selection, so a UI mod can answer "what would this unit cover if it stood
   * there" with the profile's own colours and zoom-scaled thickness.
   *
   * Exactly one ring is drawn, no matter how many profiles are registered: the
   * "Miscellaneous" / OVERLAYMISC profile, which the menu calls "Build Range".
   *
   * It used to draw the selection's widest weapon ring alongside it. That was
   * wrong: this pass is what the Shift modifier raises, and Shift's whole job is
   * the build/assist radius - weapon range belongs to Alt, which has its own two
   * passes. The stray attack ring put a red circle under the cursor whenever
   * Shift was held over an armed selection, including the tiny red dot a unit
   * with a minimum range draws at its inner edge, and there was no way to ask
   * for the assist radius without it.
   *
   * Across a multi-unit selection the widest payload wins, so a mixed group
   * shows the reach of whichever unit reaches furthest rather than a stack of
   * overlapping rings.
   */
  void RenderSelectionRingsUnderCursor(
    moho::CWldSession& session,
    RangeExtractionPayloadVector& scratchPayload,
    moho::RangeRenderer& rangeRenderer,
    const moho::CameraImpl& camera,
    const float alpha,
    const unsigned int headIndex
  )
  {
    const moho::UserArmy* const focusArmy = session.GetFocusUserArmy();
    if (focusArmy == nullptr) {
      return;
    }

    msvc8::vector<moho::UserUnit*> selectedUnits;
    session.GetSelectionUnits(selectedUnits);
    if (selectedUnits.empty()) {
      return;
    }

    const Wm3::Vector3f& cursorWorldPos = session.GetCursorInfo().mMouseWorldPos;

    // Widest assist payload seen, with the profile whose colours and ring
    // thickness should draw it.
    const moho::SRangeRenderProfile* assistProfile = nullptr;
    moho::SRangeExtractionPayload assistPayload{};

    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {
      if (profile.mExtractorName != "Miscellaneous") {
        continue;
      }

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }

      for (moho::UserUnit* const unit : selectedUnits) {
        if (unit == nullptr || unit->mArmy != focusArmy) {
          continue;
        }

        const moho::RUnitBlueprint* const blueprint = static_cast<moho::IUnit*>(unit)->GetBlueprint();
        if (blueprint == nullptr) {
          continue;
        }
        if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
          continue;
        }

        // `Extract` (live entity), not `Range` (blueprint). The blueprint lists
        // every weapon the unit *could* have, including unbuilt upgrades: a UEF
        // ACU's blueprint carries TacMissile and TacNukeMissile at
        // MaxRadius 256 - the full width of a 256-cell map - beside its actual
        // 22-range gun. Reading the blueprint therefore drew a ring over the
        // whole map for a commander that cannot fire a missile at all. The
        // stock per-unit passes use `Extract` for exactly this reason;
        // `Range` is only right for a building being placed, which has no live
        // weapons yet.
        //
        // The centre is then moved to the cursor, which is the whole point of
        // this pass: same radii the unit's own rings would show, drawn where
        // the unit would be standing.
        moho::SRangeExtractionPayload payload{};
        if (!extractor->Extract(&payload, unit, alpha)) {
          continue;
        }
        payload.centerX = cursorWorldPos.x;
        payload.centerZ = cursorWorldPos.z;

        // The payload's inner/outer are the ring *band*, not two independent
        // circles: `BuildRingPayloadEntry` emits the inner edge ring
        // unconditionally and only special-cases `innerRadius <= 0` for the
        // fill. Left exactly as the extractor built it.

        if (assistProfile == nullptr || payload.outerRadius > assistPayload.outerRadius) {
          assistPayload = payload;
          assistProfile = &profile;
        }
      }
    }

    if (assistProfile == nullptr) {
      return;
    }

    scratchPayload.clear();
    scratchPayload.push_back(assistPayload);
    RenderRingBatch(
      assistProfile->mOuterRingParams, camera, rangeRenderer, headIndex, assistProfile->mBuildRingColor,
      assistProfile->mInnerRingParams, scratchPayload
    );
  }

  /**
   * NOT A RECOVERED FUNCTION - there is no body for this in the shipped image
   * and no `Address:` can be cited for it. Additive extension, gated on
   * `range_RenderReclaimAtCursor`, which the loader leaves false.
   *
   * Draws the selection's *reclaim* reach at the cursor. This is deliberately
   * not the build-range overlay radius: `CUnitReclaimTask`'s TASKSTATE_Waiting
   * gate (CUnitReclaimTask.cpp:509-562) rejects a target when
   *
   *   rawDistance - MaxFootprintExtent(self) - MaxFootprintExtent(target)
   *     > Economy.MaxBuildDistance
   *
   * and `MaxFootprintExtent` is `max(mSizeX, mSizeZ)` (same file, line 82) --
   * the *whole* footprint, not its half-extent. Measured centre to centre the
   * reach is therefore
   *
   *   MaxBuildDistance + selfExtent + targetExtent
   *
   * so a 5x5 factory reaches 10 before the target is even counted, where a 1x1
   * engineer reaches 6, even though neither blueprint sets `MaxBuildDistance`
   * and both take the engine default of 5 (RUnitBlueprint.cpp:558). Crediting
   * two whole footprints rather than two half-extents is original engine
   * behaviour; it is reproduced here as-is and deliberately not corrected.
   *
   * **Both** extents are credited, which is the difference between this ring and
   * the reach a player actually gets. An earlier version credited only the
   * reclaimer and so understated every real order - the target term is never
   * zero in practice, because the gate substitutes `FallbackReclaimFootprint()`
   * (2x2, CUnitReclaimTask.cpp:87-97) when it has no target entity at all. That
   * 2 is what this ring credits, as a constant - see the comment at the term
   * itself for why it is not read from whatever is under the cursor.
   *
   * One term of the gate is deliberately not modelled: while the reclaimer is
   * in `UNITSTATE_Patrolling` the limit widens to
   * `max(MaxBuildDistance, AI.GuardScanRadius)` (CUnitReclaimTask.cpp:556-559).
   * That is auto-reclaim on a patrol route, not an order a player places by
   * cursor, and the unit-state bit is not on the client mirror this pass reads.
   *
   * The ring borrows the "Miscellaneous" / OVERLAYMISC profile, which the menu
   * calls "Build Range", for its geometry and colour, so thickness still scales
   * with zoom exactly as the engine's own rings do.
   */
  void RenderReclaimRingUnderCursor(
    moho::CWldSession& session,
    RangeExtractionPayloadVector& scratchPayload,
    moho::RangeRenderer& rangeRenderer,
    const moho::CameraImpl& camera,
    const unsigned int headIndex
  )
  {
    const moho::UserArmy* const focusArmy = session.GetFocusUserArmy();
    if (focusArmy == nullptr) {
      return;
    }

    msvc8::vector<moho::UserUnit*> selectedUnits;
    session.GetSelectionUnits(selectedUnits);
    if (selectedUnits.empty()) {
      return;
    }

    const moho::SRangeRenderProfile* buildRangeProfile = nullptr;
    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {
      if (profile.mExtractorName == "Miscellaneous") {
        buildRangeProfile = &profile;
        break;
      }
    }
    if (buildRangeProfile == nullptr) {
      return;
    }

    // The target half of the gate's two footprint credits, held at the engine's
    // own no-target value rather than read from whatever is under the cursor.
    //
    // Reading the hovered entity made this term exact for that one target, but
    // the ring is a property of the *selection*, and sizing it from the cursor
    // made it pulse: every tree swept over has its own footprint, most of them
    // smaller than the 2x2 the gate falls back to, so crossing a forest made the
    // ring shrink and grow for reclaims nobody had asked about. Resting on the
    // very factory that was selected was worse still - it credited that
    // factory's own 5x5 for an order TASKSTATE_Preparing rejects outright
    // (`targetEntity == mUnit`, CUnitReclaimTask.cpp:517-522).
    //
    // `FallbackReclaimFootprint()` is the honest constant here: it is exactly
    // what the gate measures against for "reclaim at this position", which is
    // what a bare cursor is. A real target adds its own extent on top of this at
    // order time, so the ring never overstates a reclaim that can happen.
    const float targetExtent = kFallbackReclaimFootprintExtent;

    // Widest reach across the selection, so a mixed group shows the unit that
    // reaches furthest rather than a stack of overlapping rings - same rule the
    // selection pass above uses.
    float widestReach = 0.0f;
    for (moho::UserUnit* const unit : selectedUnits) {
      if (unit == nullptr || unit->mArmy != focusArmy) {
        continue;
      }

      const moho::RUnitBlueprint* const blueprint = static_cast<moho::IUnit*>(unit)->GetBlueprint();
      if (blueprint == nullptr) {
        continue;
      }

      // A unit with no build distance cannot reclaim at all; the task's own
      // gate would reject every target.
      const float maxBuildDistance = blueprint->Economy.MaxBuildDistance;
      if (maxBuildDistance <= 0.0f) {
        continue;
      }

      const float reach = maxBuildDistance + ReclaimFootprintExtentOf(*unit) + targetExtent;
      if (reach > widestReach) {
        widestReach = reach;
      }
    }

    if (widestReach <= 0.0f) {
      return;
    }

    const Wm3::Vector3f& cursorWorldPos = session.GetCursorInfo().mMouseWorldPos;

    moho::SRangeExtractionPayload payload{};
    payload.centerX = cursorWorldPos.x;
    payload.centerZ = cursorWorldPos.z;
    payload.innerRadius = 0.0f;
    payload.outerRadius = widestReach;

    // Geometry from the "Miscellaneous" profile, so thickness still scales with
    // zoom exactly as every other ring does - but the military red for the
    // colour, not that profile's own b09200.
    //
    // This is an Alt ring, and Alt's two rings are one answer: how far this
    // selection reaches, and how far the thing under it shoots. Drawing the
    // reach in the "Build Range" yellow made it read as the Shift ring instead,
    // and with a factory selected it is the *only* ring Alt puts up - a factory
    // carries no weapons, so the hovered-attack pass has nothing to draw
    // alongside it.
    const moho::SRangeRenderProfile* const militaryStyle = FindMilitaryStyleProfile(rangeRenderer);
    const moho::SRangeRenderProfile& style =
      (militaryStyle != nullptr) ? *militaryStyle : *buildRangeProfile;

    scratchPayload.clear();
    scratchPayload.push_back(payload);
    RenderRingBatch(
      buildRangeProfile->mOuterRingParams, camera, rangeRenderer, headIndex, style.mBuildRingColor,
      buildRangeProfile->mInnerRingParams, scratchPayload
    );
  }

  /**
   * NOT A RECOVERED FUNCTION - there is no body for this in the shipped image
   * and no `Address:` can be cited for it. Additive extension, gated on
   * `range_RenderHoveredAttack`, which the loader leaves false.
   *
   * Draws the attack range of whatever unit the cursor is over, at that unit's
   * own position. It is the hover counterpart of the selection pass above: that
   * one answers "what would my selection cover if it stood here", this one
   * answers "how far does *that* thing shoot".
   *
   * Two deliberate differences from the engine's own hovered-unit pass
   * (`RenderHighlightedUnitRange`, 0x007EF420), which this does not replace and
   * does not change:
   *
   *  - **One ring, not one per profile.** The retail pass draws every profile
   *    the hovered unit matches, so a unit with direct fire, AA and intel puts
   *    three or four rings up at once. This picks the single widest weapon
   *    profile (`KeepWiderAttackRing`) and draws only that, because it is meant
   *    to be readable while a modifier is held.
   *  - **Any army, not just the focus army.** The retail pass returns early
   *    unless `GetFocusUserArmy() == hoveredEntity->mArmy`. A player hovering a
   *    unit they have not selected is usually asking about a threat, so that
   *    filter is not applied here. Nothing is revealed that the client cannot
   *    already see: an entity the player has no intel on is not hovered in the
   *    first place, and the radius comes from the unit's *live* weapons via
   *    `Extract`. Restoring the retail restriction is a one-line change - see
   *    the commented gate below.
   *
   * The centre is the unit's own, straight from the extractor, and is not moved
   * to the cursor: the unit is under the cursor already, and its real ring is
   * the truthful one.
   */
  void RenderHoveredUnitAttackRange(
    moho::CWldSession& session,
    RangeExtractionPayloadVector& scratchPayload,
    moho::RangeRenderer& rangeRenderer,
    const moho::CameraImpl& camera,
    const float alpha,
    const unsigned int headIndex
  )
  {
    moho::UserEntity* const hoveredEntity = session.GetHoveredUserEntity();
    if (hoveredEntity == nullptr) {
      return;
    }

    moho::UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    // Retail's own hovered pass gates on ownership here:
    //   if (session.GetFocusUserArmy() != hoveredEntity->mArmy) { return; }
    // Deliberately absent - see the block comment above.

    const moho::RUnitBlueprint* const blueprint = static_cast<moho::IUnit*>(hoveredUnit)->GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    const moho::SRangeRenderProfile* attackProfile = nullptr;
    moho::SRangeExtractionPayload attackPayload{};

    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {
      if (!IsAttackRangeProfile(profile)) {
        continue;
      }

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }
      if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      // `Extract` (live entity), not `Range` (blueprint), for the same reason
      // the selection pass gives: a blueprint lists every weapon the unit
      // *could* have, upgrades included, so a UEF ACU would draw its unbuilt
      // TacNukeMissile's MaxRadius 256 - the full width of a 256-cell map -
      // instead of the 22-range gun it actually carries.
      moho::SRangeExtractionPayload payload{};
      if (!extractor->Extract(&payload, hoveredEntity, alpha)) {
        continue;
      }

      KeepWiderAttackRing(attackProfile, attackPayload, profile, payload);
    }

    if (attackProfile == nullptr) {
      return;
    }

    // Geometry from the profile that produced the radius, colour from
    // "AllMilitary" so the ring reads as attack range whichever weapon category
    // won.
    //
    // The *normal* colour lane, ff2c2c - not the rollover lane's ff6363. The
    // three lanes are not three shades of one colour to pick freely between:
    // `RangeBurn` writes `rangeColor` into the target verbatim
    // (`gamedata/effects/frame.fx`: `RangePS` returns its uniform, and the pass
    // is `SrcBlend = one; DestBlend = zero`), so the lane chosen *is* the pixel.
    // Dumped from a live "AllMilitary" profile, the two lanes decode to
    // (1.000, 0.173, 0.173) and (1.000, 0.388, 0.388) - RGB(255,44,44) against
    // RGB(255,99,99), which is the difference between a red ring and a pink one.
    // Rollover exists to brighten a ring the per-unit pass has already drawn in
    // the normal colour; this ring is on its own while a modifier is held, so
    // lightening it had nothing to lighten and only washed the red out to a
    // salmon pink. The sibling cursor pass above already draws its attack ring
    // from `mBuildRingColor` for the same reason.
    const moho::SRangeRenderProfile* const militaryStyle = FindMilitaryStyleProfile(rangeRenderer);
    const moho::SRangeRenderProfile& style = (militaryStyle != nullptr) ? *militaryStyle : *attackProfile;

    scratchPayload.clear();
    scratchPayload.push_back(attackPayload);
    RenderRingBatch(
      attackProfile->mOuterRingParams, camera, rangeRenderer, headIndex, style.mBuildRingColor,
      attackProfile->mInnerRingParams, scratchPayload
    );
  }

  /**
   * Address: 0x007EF280 (FUN_007EF280, sub_7EF280)
   *
   * IDA signature:
   * void __thiscall sub_7EF280(
   *     Moho::CWldSession *this, RangeExtractionPayloadVector *outPayloads,
   *     const Moho::SRangeRenderProfile *profile, float alpha);
   *
   * Callsite evidence: sole caller is `RangeRenderer::Render` (0x007EEB78,
   * inside the `mRangeProfiles` tree walk), gated on `range_RenderSelected`
   * per `RangeRendererStartupRegistrations.h`'s reader map and re-confirmed
   * at both the caller and this recovery.
   *
   * What it does:
   * For the current focus army's selected units, extracts one range per unit
   * whose blueprint passes the profile's category filter (plus the shared
   * `BlueprintPassesRangeVisibilityGate`) and appends it to `outPayloads`.
   * Unlike `func_RenderBuildRings`/`sub_7EF420`, this does not draw
   * immediately - `RangeRenderer::Render` batches every accepted unit for one
   * profile into a single `RenderRingBatch` call using
   * `profile.mSelectedRingColor`.
   */
  void RenderSelectedUnitsRange(
    const moho::CWldSession& session, RangeExtractionPayloadVector& outPayloads,
    const moho::SRangeRenderProfile& profile, const float alpha
  )
  {
    outPayloads.clear();
    if (!moho::range_RenderSelected) {
      return;
    }

    if (!ProfileParticipatesInPerUnitPasses(profile)) {
      return;
    }

    moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
    if (extractor == nullptr) {
      return;
    }

    const moho::UserArmy* const focusArmy = session.GetFocusUserArmy();
    if (focusArmy == nullptr) {
      return;
    }

    msvc8::vector<moho::UserUnit*> selectedUnits;
    session.GetSelectionUnits(selectedUnits);

    for (moho::UserUnit* const unit : selectedUnits) {
      if (unit == nullptr || unit->mArmy != focusArmy) {
        continue;
      }

      auto* const iunit = static_cast<moho::IUnit*>(unit);
      const moho::RUnitBlueprint* const blueprint = iunit->GetBlueprint();
      if (blueprint == nullptr) {
        continue;
      }
      if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      moho::SRangeExtractionPayload payload{};
      if (extractor->Extract(&payload, unit, alpha)) {
        outPayloads.push_back(payload);
      }
    }
  }

  /**
   * Address: 0x007EF420 (FUN_007EF420, sub_7EF420)
   *
   * IDA signature:
   * int __userpurge sub_7EF420(
   *     Moho::CWldSession *session@<eax>, Moho::RangeRenderer *renderer,
   *     RangeExtractionPayloadVector *scratchPayload, Moho::CameraImpl *camera,
   *     float alpha, unsigned int headIndex);
   *
   * Callsite evidence: sole caller is `RangeRenderer::Render`. The call site
   * (0x007EEBCE) sits inside `RangeRenderer::Render`'s own byte range
   * (0x007EEA00-0x007EEC70) but the namespace callgraph index attributes its
   * owning chunk to `sub_128E217` - an IDA chunk-boundary artifact from this
   * function's SEH-heavy layout, not a real separate caller (verified by
   * reading the call byte directly out of `FUN_007EEA00.asm`). Gated on
   * `range_RenderHighlighted` per `RangeRendererStartupRegistrations.h`'s
   * reader map and re-confirmed here.
   *
   * What it does:
   * Resolves the currently-hovered unit (`CWldSession::GetHoveredUserEntity`);
   * when it belongs to the focus army, walks every registered range profile
   * and - for each whose extractor resolves and whose category filter (plus
   * the shared visibility gate) accepts the hovered unit's blueprint -
   * extracts one range for that unit and draws it immediately with
   * `profile.mHighlightedRingColor`.
   */
  void RenderHighlightedUnitRange(
    moho::CWldSession& session, RangeExtractionPayloadVector& scratchPayload, moho::RangeRenderer& rangeRenderer,
    const moho::CameraImpl& camera, const float alpha, const unsigned int headIndex
  )
  {
    if (!moho::range_RenderHighlighted) {
      return;
    }

    moho::UserEntity* const hoveredEntity = session.GetHoveredUserEntity();
    if (hoveredEntity == nullptr) {
      return;
    }

    moho::UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    if (session.GetFocusUserArmy() != hoveredEntity->mArmy) {
      return;
    }

    auto* const iunit = static_cast<moho::IUnit*>(hoveredUnit);
    const moho::RUnitBlueprint* const blueprint = iunit->GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    for (const auto& [extractorName, profile] : rangeRenderer.mRangeProfiles) {

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }
      if (!ProfileParticipatesInPerUnitPasses(profile)) {
        continue;
      }
      if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      moho::SRangeExtractionPayload payload{};
      if (!extractor->Extract(&payload, hoveredEntity, alpha)) {
        continue;
      }

      scratchPayload.clear();
      scratchPayload.push_back(payload);
      RenderRingBatch(
        profile.mOuterRingParams, camera, rangeRenderer, headIndex, profile.mHighlightedRingColor,
        profile.mInnerRingParams, scratchPayload
      );
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007EDD60 (FUN_007EDD60, Moho::RangeRenderer::RangeRenderer)
   */
  RangeRenderer::RangeRenderer()
    : mRangeProfiles{}
    , mVisibleProfiles{}
    , mIndexCount(0u)
    , mVertexCount(0u)
    , mGeometry{}
    , mDynamicRingVertexCount(0u)
    , mDynamicVertexBuffer{}
    , mFrame{}
  {
  }

  /**
   * Address: 0x007EDE00 (FUN_007EDE00, Moho::RangeRenderer::dtr)
   * Address: 0x007EDE50 (FUN_007EDE50, Moho::RangeRenderer::~RangeRenderer)
   */
  RangeRenderer::~RangeRenderer()
  {
    mVisibleProfiles.clear();
    ResetRenderResources();
  }

  /**
   * Address: 0x007EE430 (FUN_007EE430, sub_7EE430)
   */
  void RangeRenderer::ResetRenderResources() noexcept
  {
    mFrame.ResetTransientResources();
    mDynamicVertexBuffer.reset();
    mGeometry.Reset();
    mDynamicRingVertexCount = 0u;
    mIndexCount = 0u;
    mVertexCount = 0u;
  }

  /**
   * Address: 0x007EDFE0 (FUN_007EDFE0, Moho::RangeRenderer::Init)
   */
  void RangeRenderer::Init()
  {
    ResetRenderResources();

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    if (!device) {
      return;
    }

    device->CreateVertexFormat(&mGeometry.mVertexFormat, 17u);

    mVertexCount = kRangeVertexCount;
    mIndexCount = kRangeIndexCount;

    gpg::gal::VertexBufferContext primaryVertexBufferContext{};
    primaryVertexBufferContext.vertexCount_ = mVertexCount;
    primaryVertexBufferContext.stride_ = kPrimaryVertexStrideBytes;
    primaryVertexBufferContext.type_ = 2u;
    primaryVertexBufferContext.usage_ = 1u;
    device->CreateVertexBuffer(&mGeometry.mVertexBuffer, &primaryVertexBufferContext);

    gpg::gal::VertexBufferContext dynamicVertexBufferContext{};
    dynamicVertexBufferContext.vertexCount_ = kDynamicVertexCapacity;
    dynamicVertexBufferContext.stride_ = kDynamicVertexStrideBytes;
    dynamicVertexBufferContext.type_ = 3u;
    dynamicVertexBufferContext.usage_ = 2u;
    device->CreateVertexBuffer(&mDynamicVertexBuffer, &dynamicVertexBufferContext);
    mDynamicRingVertexCount = 0u;

    gpg::gal::IndexBufferContext indexBufferContext{};
    indexBufferContext.format_ = 1u;
    indexBufferContext.size_ = mIndexCount;
    indexBufferContext.type_ = 1u;
    device->CreateIndexBuffer(&mGeometry.mIndexBuffer, &indexBufferContext);

    if (mGeometry.mVertexBuffer) {
      float* const vertexData =
        static_cast<float*>(mGeometry.mVertexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0)));

      if (vertexData) {
        for (std::uint32_t i = 0u; i < kRangeRingSegmentCount; ++i) {
          const float angle = static_cast<float>(i) * kRangeAngleStepRadians;
          const float x = std::cos(angle);
          const float z = std::sin(angle);

          // Vertical extents come from the map's own height range, published by
          // Sim::Create_exxt — the binary loads them here, not immediates:
          // `movss xmm2, ds:patch_maxMapHeight` at 0x007EE2B8 for the upper band
          // and `ds:patch_minMapHeight` at 0x007EE336 for the lower one.
          const float upperBandHeight = moho::patch_maxMapHeight;
          const float lowerBandHeight = moho::patch_minMapHeight;

          WriteRingBandVertex(vertexData, i, x, upperBandHeight, z, 1.0f, 0.0f);
          WriteRingBandVertex(vertexData, i + kRangeRingSegmentCount, x, upperBandHeight, z, 0.0f, 1.0f);
          WriteRingBandVertex(vertexData, i + (kRangeRingSegmentCount * 2u), x, lowerBandHeight, z, 1.0f, 0.0f);
          WriteRingBandVertex(vertexData, i + (kRangeRingSegmentCount * 3u), x, lowerBandHeight, z, 0.0f, 1.0f);
        }
      }

      mGeometry.mVertexBuffer->Unlock();
    }

    if (mGeometry.mIndexBuffer) {
      std::int16_t* const indexData = mGeometry.mIndexBuffer->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));

      if (indexData) {
        std::uint32_t writeIndex = 0u;
        writeIndex = AppendRingStripIndices(writeIndex, indexData, 0u, 45u, 45u, true);
        writeIndex = AppendRingStripIndices(writeIndex, indexData, 90u, 135u, 45u, true);
        writeIndex = AppendRingStripIndices(writeIndex, indexData, 0u, 45u, 90u, false);
        writeIndex = AppendRingStripIndices(writeIndex, indexData, 45u, 90u, 90u, true);
      }

      mGeometry.mIndexBuffer->Unlock();
    }
  }

  /**
   * Address: 0x007EEA00 (FUN_007EEA00, Moho::RangeRenderer::Render)
   *
   * IDA signature (compiler-invented register convention, `retn 0Ch`):
   * void __usercall Render(CWldSession *session@<ecx>, CameraImpl *camera@<ebx>,
   *                        RangeRenderer *renderer, unsigned headIndex, float alpha);
   *
   * See the declaration's own evidence block for the camera-type / callsite
   * proof; re-verified here against the full raw disassembly (0x007EEA00-
   * 0x007EEC70 - the real body runs past the 0x007EEB55 boundary IDA's own
   * function-chunk metadata reports, into a chunk it mis-attributes to
   * `sub_128E217`; every instruction in that tail was read directly out of
   * `FUN_007EEA00.asm` and cross-checked against this function's own callee
   * list).
   *
   * What it does:
   * - if `range_RenderBuild`, runs the build-placement preview pass
   *   (`RenderBuildRingsUnderCursor`)
   * - for each currently-visible profile (`mVisibleProfiles`, set by
   *   `MoveCategories`), snapshots the camera's frustum weak-ref list
   *   (`SnapshotCameraFrustumWeakRefs`), extracts one range per accepted
   *   candidate (`func_ExtractRanges`) and draws the batch with
   *   `profile.mBuildRingColor`
   * - for each registered profile in `mRangeProfiles` (not just the visible
   *   subset), runs the selected-units pass (`RenderSelectedUnitsRange`) and
   *   draws the batch with `profile.mSelectedRingColor`
   * - runs the highlighted/hovered-unit pass (`RenderHighlightedUnitRange`)
   *
   * Not yet wired: the binary's final pass (0x007EEBD3-EC48) submits the
   * current selection's axis-aligned bounds as one more ring
   * (`sub_7EF1C0`, called with a fixed thin-ring color/radius) before the
   * device-clear at the end. `sub_7EF1C0` reads `UserArmy`-relative fields at
   * +0x1BC..+0x1D0 that have no named accessor in `moho/sim/UserArmy.h` yet
   * (that header is owned by a concurrently active recovery pass, not this
   * file); recovering `sub_7EF1C0` here would require adding raw offset
   * reads to a class this file does not own, which the reconstruction
   * fidelity contract forbids. Left `blocked` with
   * `blocker_type=needs_layout` pending named `UserArmy` selection-bounds
   * fields - see the recovery report for exact field offsets/sizes gathered
   * from the binary.
   */
  void RangeRenderer::Render(
    CWldSession* const worldSession, CameraImpl* const camera, const unsigned int viewportHeadIndex,
    const float alpha
  )
  {
    if (worldSession == nullptr || camera == nullptr) {
      return;
    }

    RangeExtractionPayloadVector scratchPayload;

    if (range_RenderBuild) {
      RenderBuildRingsUnderCursor(*worldSession, scratchPayload, *this, *camera, viewportHeadIndex);
    }

    // NOT IN THE ORIGINAL BINARY - additive, and false unless a mod sets it.
    //
    // While this is on it *replaces* the three per-unit passes below rather
    // than adding to them: the point of drawing at the cursor is to preview
    // coverage at a position, and leaving the unit's own rings up at the same
    // time gives two sets of rings for one answer.
    if (range_RenderSelectedAtCursor) {
      RenderSelectionRingsUnderCursor(*worldSession, scratchPayload, *this, *camera, alpha, viewportHeadIndex);
      return;
    }

    // NOT IN THE ORIGINAL BINARY - additive, and both false unless a mod sets
    // them. Like the pass above these replace the three per-unit passes rather
    // than adding to them, so what a held modifier puts up is the only thing on
    // screen while it is held.
    //
    // The two are independent flags and compose: a mod that raises both - which
    // is what "Alt, with something selected" does - gets the selection's reclaim
    // reach at the cursor *and* the attack range of the unit under it, which are
    // answers to two different questions and are drawn in two different colours.
    if (range_RenderReclaimAtCursor || range_RenderHoveredAttack) {
      if (range_RenderReclaimAtCursor) {
        RenderReclaimRingUnderCursor(*worldSession, scratchPayload, *this, *camera, viewportHeadIndex);
      }
      if (range_RenderHoveredAttack) {
        RenderHoveredUnitAttackRange(*worldSession, scratchPayload, *this, *camera, alpha, viewportHeadIndex);
      }
      return;
    }

    if (!mVisibleProfiles.empty()) {
      CameraFrustumUserEntityList* const frustumList = camera->GetArmyUnitsInFrustum();
      if (frustumList != nullptr) {
        CameraFrustumWeakRefSnapshotBuffer candidateSnapshot{};
        (void)SnapshotCameraFrustumWeakRefs(&candidateSnapshot, *frustumList);
        const SRangeProfileWeakRefCandidatePoolView candidatePool{
          candidateSnapshot.mView.mStart, candidateSnapshot.mView.mFinish
        };

        for (SRangeRenderProfile& profile : mVisibleProfiles) {
          scratchPayload.clear();
          func_ExtractRanges(candidatePool, alpha, profile, scratchPayload);
          RenderRingBatch(
            profile.mOuterRingParams, *camera, *this, viewportHeadIndex, profile.mBuildRingColor,
            profile.mInnerRingParams, scratchPayload
          );
        }
      }
    }

    for (const auto& [extractorName, profile] : mRangeProfiles) {
      RenderSelectedUnitsRange(*worldSession, scratchPayload, profile, alpha);
      RenderRingBatch(
        profile.mOuterRingParams, *camera, *this, viewportHeadIndex, profile.mSelectedRingColor,
        profile.mInnerRingParams, scratchPayload
      );
    }

    RenderHighlightedUnitRange(*worldSession, scratchPayload, *this, *camera, alpha, viewportHeadIndex);
  }

  /**
   * Address: 0x007EE950 (FUN_007EE950, Moho::RangeRenderer::MoveCategories)
   *
   * What it does:
   * Rebuilds visible range profiles by resolving each category key through the
   * range-profile tree and appending matching profile values in caller order.
   */
  void RangeRenderer::MoveCategories(const msvc8::vector<msvc8::string>& categories)
  {
    mVisibleProfiles.clear();

    for (const msvc8::string& category : categories) {
      const SRangeRenderProfileMap::const_iterator match = mRangeProfiles.find(category);
      if (match == mRangeProfiles.end()) {
        continue;
      }

      mVisibleProfiles.push_back(match->second);
    }
  }

  /**
   * Address: 0x007EE5A0 (FUN_007EE5A0, sub_7EE5A0)
   *
   * What it does:
   * Finds-or-inserts one range-profile entry by extractor key in
   * `RangeRenderer::mRangeProfiles`, then writes category mask, packed ring
   * colors, and inner/outer ring radius lanes into the destination payload.
   */
  void ApplyRangeProfileFilterToRenderer(
    const std::uint32_t highlightedColorPacked,
    const EntityCategorySet* const categoryFilter,
    RangeRenderer* const rangeRenderer,
    const std::string_view extractorName,
    const std::uint32_t buildColorPacked,
    const std::uint32_t selectedColorPacked,
    const RangeRingRadiusParams& innerRingParams,
    const RangeRingRadiusParams& outerRingParams
  )
  {
    if (rangeRenderer == nullptr || categoryFilter == nullptr) {
      return;
    }

    msvc8::string extractorKey{};
    extractorKey.assign_owned(extractorName);

    SRangeRenderProfile profile{};
    profile.mExtractorName.assign_owned(extractorKey.view());
    profile.mCategoryFilter.mUniverse = categoryFilter->mUniverse;
    profile.mCategoryFilter.mReserved04 = 0u;
    profile.mCategoryFilter.mBits.mFirstWordIndex = categoryFilter->mBits.mFirstWordIndex;
    profile.mCategoryFilter.mBits.mReservedMetaWord = 0u;
    (void)gpg::FastVectorN2RebindAndCopy(&profile.mCategoryFilter.mBits.mWords, &categoryFilter->mBits.mWords);
    profile.mBuildRingColor = DecodePackedRgbaColor(buildColorPacked);
    profile.mSelectedRingColor = DecodePackedRgbaColor(selectedColorPacked);
    profile.mHighlightedRingColor = DecodePackedRgbaColor(highlightedColorPacked);
    profile.mInnerRingParams = innerRingParams;
    profile.mOuterRingParams = outerRingParams;

    rangeRenderer->mRangeProfiles[extractorKey] = profile;
  }

  /**
   * Address: 0x007EF0B0 (FUN_007EF0B0, Moho::func_ExtractRanges)
   * Mangled: (n/a — free function)
   *
   * IDA signature:
   * void __stdcall func_ExtractRanges(
   *     std::map_string_RangeExtractor::_Node *arg0,  // candidate-pool fastvector view
   *     float arg4,                                   // alpha
   *     std::string *a1,                              // profile (SRangeRenderProfile*)
   *     std::map_string_RangeExtractor::_Node *a2);   // output ring-payload fastvector view
   *
   * What it does:
   * Per-visible-profile extraction pass for `RangeRenderer::Render` Phase 2.
   * Resolves the registered range extractor by the profile's extractor name,
   * walks the pre-collected candidate selection-weak-ref pool, gates each
   * candidate by live-unit checks, applies the profile's category filter,
   * invokes the extractor's `Extract` virtual, and appends successful
   * payloads to the output ring extraction payload vector.
   */
  void func_ExtractRanges(
    const SRangeProfileWeakRefCandidatePoolView& candidatePool,
    const float interpolationAlpha,
    const SRangeRenderProfile& profile,
    SRangeExtractionPayloadVector& outRingPayloadVector
  )
  {
    // Resolve the extractor for this profile. The binary emits a clear-then-
    // find iterator sequence (FUN_007F0C50 followed by FUN_007F01D0); the
    // recovered `GetRangeExtractor(name)` wraps the same logic in one typed
    // free function and returns nullptr when no mapping exists, which mirrors
    // the binary's "iterator == _Myhead -> bail" lane.
    RangeExtractor* const extractor = GetRangeExtractor(profile.mExtractorName);
    if (extractor == nullptr) {
      return;
    }

    // Walk the candidate pool of 8-byte selection-weak-ref records. Each
    // record's `mOwnerLinkSlot` points into the owning UserEntity at the
    // `mIUnitChainHead` (+0x08) slot, so `mOwnerLinkSlot - 0x08` recovers the
    // owning `UserEntity*`. The binary's `(char *)i + 8` step iterates the
    // pool with 8-byte stride matching `sizeof(SSelectionWeakRefUserEntity)`.
    static_assert(
      sizeof(SSelectionWeakRefUserEntity) == 0x08,
      "func_ExtractRanges weak-ref candidate pool stride must remain 8 bytes"
    );

    const auto* const begin = static_cast<const SSelectionWeakRefUserEntity*>(candidatePool.begin);
    const auto* const end = static_cast<const SSelectionWeakRefUserEntity*>(candidatePool.end);
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    // UserEntity::mIUnitChainHead sits at +0x08. `offsetof` on UserEntity is
    // not a usable constant expression here (UserEntity is non-standard-layout:
    // it derives from the polymorphic WeakObject), so the offset is taken as the
    // documented recovery contract literal. The actual layout is enforced by the
    // `static_assert(offsetof(UserEntity, mIUnitChainHead) == 0x08)` in UserEntity.h.
    constexpr std::uintptr_t kSelectionOwnerLinkOffset = 0x08;

    for (const SSelectionWeakRefUserEntity* candidate = begin; candidate != end; ++candidate) {
      void* const ownerLinkSlot = candidate->mOwnerLinkSlot;
      if (ownerLinkSlot == nullptr) {
        continue;
      }

      // Skip the synthetic shape-match sentinel the original binary excludes
      // explicitly: the IDA-decompiled condition `Left != (... *)8` rejects
      // weak-ref entries whose link slot lies entirely within the first
      // selection-owner-link offset of address space (a guard against
      // null-derived owner pointers).
      const std::uintptr_t rawLink = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
      if (rawLink < kSelectionOwnerLinkOffset) {
        continue;
      }

      UserEntity* const userEntity =
        reinterpret_cast<UserEntity*>(rawLink - kSelectionOwnerLinkOffset);
      if (userEntity->IsBeingBuilt()) {
        continue;
      }

      UserUnit* const userUnit = userEntity->IsUserUnit();
      if (userUnit == nullptr) {
        continue;
      }

      IUnit* const iunitBridge = static_cast<IUnit*>(userUnit);
      if (iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
      if (blueprint == nullptr) {
        continue;
      }

      if (!EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      SRangeExtractionPayload payload{};
      if (extractor->Extract(&payload, userEntity, interpolationAlpha)) {
        outRingPayloadVector.push_back(payload);
      }
    }
  }
} // namespace moho
