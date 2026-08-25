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
   * Address: 0x007F0310 (FUN_007F0310, sub_7F0310)
   *
   * What it does:
   * Appends one ring extraction payload (`worldX`, `worldZ`, `innerRadius`,
   * `outerRadius`) to the active payload vector, growing storage when needed.
   *
   * This is stock engine code with eight direct callers, byte-verified as
   * `E8 rel32` call sites: 0x007EDCD6, 0x007EDD12 and 0x007EDD52 (in
   * `sub_7EDC80`), 0x007EEFB4 (`func_RenderBuildRings`), 0x007EF19E
   * (`func_ExtractRanges`), 0x007EF26D, 0x007EF3D2 and 0x007EF551.
   */
  [[nodiscard]] moho::SRangeExtractionPayload* AppendRangeExtractionPayload(
    RangeExtractionPayloadVector& payloads,
    const moho::SRangeExtractionPayload& payload
  )
  {
    payloads.push_back(payload);
    return payloads.end();
  }

  /**
   * Address: 0x007F39B0 (FUN_007F39B0)
   *
   * What it does:
   * Writes one repeated range-extraction payload lane into `count` contiguous
   * destination entries.
   */
  [[maybe_unused]] moho::SRangeExtractionPayload* FillRangeExtractionPayloadSpan(
    moho::SRangeExtractionPayload* destination,
    const moho::SRangeExtractionPayload* const sourcePayload,
    std::uint32_t count
  )
  {
    while (count != 0u) {
      if (destination != nullptr && sourcePayload != nullptr) {
        *destination = *sourcePayload;
        ++destination;
      }
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x007F33B0 (FUN_007F33B0)
   *
   * What it does:
   * Register-shape adapter lane for `FillRangeExtractionPayloadSpan(...)`.
   */
  [[maybe_unused]] moho::SRangeExtractionPayload* FillRangeExtractionPayloadSpanAdapterA(
    moho::SRangeExtractionPayload* const destination,
    const moho::SRangeExtractionPayload* const sourcePayload,
    const std::uint32_t count
  )
  {
    return FillRangeExtractionPayloadSpan(destination, sourcePayload, count);
  }

  /**
   * Address: 0x007F0D20 (FUN_007F0D20)
   *
   * What it does:
   * Alias lane of `FillRangeExtractionPayloadSpan`; fills `count` entries with
   * one repeated payload value and returns one-past-end destination.
   */
  [[maybe_unused]] moho::SRangeExtractionPayload* FillRangeExtractionPayloadSpanLaneB(
    moho::SRangeExtractionPayload* const destination,
    const moho::SRangeExtractionPayload& payloadValue,
    const std::uint32_t count
  )
  {
    return FillRangeExtractionPayloadSpan(destination, &payloadValue, count);
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
    moho::CameraUserEntityWeakRef* mStart;                      // +0x00
    moho::CameraUserEntityWeakRef* mFinish;                     // +0x04
    moho::CameraUserEntityWeakRef* mCapacity;                   // +0x08
    moho::CameraUserEntityWeakRef* mOriginalStart;               // +0x0C
    moho::CameraUserEntityWeakRef mInlineStorage[40];            // +0x10
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
   * `CameraFrustumWeakRefSnapshotBuffer`'s first four fields are
   * layout-identical to `CameraFrustumUserEntityList` (same `{begin, end,
   * capacityEnd, inlineOrigin}` header, just named `mOriginalStart` here),
   * so `AssignRange` -- and the `InsertRange`/`GrowAndInsertRange` machinery
   * it calls on the grow path -- apply unchanged. A prior version of this
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
    destination->mStart = inlineStart;
    destination->mFinish = inlineStart;
    destination->mCapacity = inlineStart + kInlineCount;
    destination->mOriginalStart = inlineStart;

    static_assert(
      sizeof(moho::CameraFrustumUserEntityList) == 0x10,
      "CameraFrustumWeakRefSnapshotBuffer's header must alias CameraFrustumUserEntityList's four pointer fields"
    );
    auto& destinationView = *reinterpret_cast<moho::CameraFrustumUserEntityList*>(destination);
    auto* const assignedEnd = destinationView.AssignRange(source);
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
    (void)AppendRangeExtractionPayload(*state.fillPayloads, fillPayload);

    moho::SRangeExtractionPayload innerEdgePayload = sourcePayload;
    innerEdgePayload.outerRadius = sourcePayload.innerRadius + state.innerThicknessOffset;
    (void)AppendRangeExtractionPayload(*state.edgePayloads, innerEdgePayload);

    moho::SRangeExtractionPayload outerEdgePayload = sourcePayload;
    outerEdgePayload.innerRadius = sourcePayload.outerRadius - state.outerThicknessOffset;
    outerEdgePayload.outerRadius = sourcePayload.outerRadius;
    (void)AppendRangeExtractionPayload(*state.edgePayloads, outerEdgePayload);
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

  /**
   * Address: 0x007EE860 (FUN_007EE860, sub_7EE860)
   *
   * What it does:
   * Resets one range-profile payload lane by freeing heap-backed category-word
   * storage (if active), rebinding to inline storage, and tidying the extractor
   * string back to empty SSO state.
   */
  [[maybe_unused]] std::int32_t ResetRangeRenderProfileTransientState(moho::SRangeRenderProfile* const profile) noexcept
  {
    profile->mCategoryFilter.mBits.mWords.ResetStorageToInline();
    profile->mExtractorName.tidy(true, 0u);
    return 0;
  }

  /**
   * Address: 0x007F3C80 (FUN_007F3C80, sub_7F3C80)
   *
   * What it does:
   * Thunk lane that forwards one range-profile reset call into
   * `FUN_007EE860` behavior.
   */
  [[maybe_unused]] std::int32_t ResetRangeRenderProfileTransientStateThunkA(
    moho::SRangeRenderProfile* const profile
  ) noexcept
  {
    return ResetRangeRenderProfileTransientState(profile);
  }

  /**
   * Address: 0x007F3DC0 (FUN_007F3DC0, sub_7F3DC0)
   *
   * What it does:
   * Secondary thunk lane forwarding into `FUN_007EE860` profile-reset
   * behavior.
   */
  [[maybe_unused]] std::int32_t ResetRangeRenderProfileTransientStateThunkB(
    moho::SRangeRenderProfile* const profile
  ) noexcept
  {
    return ResetRangeRenderProfileTransientState(profile);
  }

  /**
   * Address: 0x007F39E0 (FUN_007F39E0, sub_7F39E0)
   * Address: 0x007F1470 (FUN_007F1470) - linker-emitted __thiscall
   *          calling-convention trampoline into this body; no separate
   *          logic of its own.
   *
   * What it does:
   * Destroys one half-open range of `SRangeRenderProfile` lanes by resetting
   * each profile's transient string/category-word storage back to empty inline
   * state.
   */
  [[maybe_unused]] void DestroyRangeRenderProfileTransientStateRange(
    moho::SRangeRenderProfile* const begin,
    moho::SRangeRenderProfile* const end
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || begin == end) {
      return;
    }

    for (moho::SRangeRenderProfile* it = begin; it != end; ++it) {
      (void)ResetRangeRenderProfileTransientState(it);
    }
  }

  /**
   * Address: 0x007EE8B0 (FUN_007EE8B0, ??0struct_a1@@QAE@@Z)
   *
   * What it does:
   * Copies one initialized range-profile payload lane, including extractor
   * string text, category-word set runtime lanes, and ring color/radius values.
   */
  [[maybe_unused]] moho::SRangeRenderProfile* CopyRangeRenderProfileTransientState(
    moho::SRangeRenderProfile* const destination,
    const moho::SRangeRenderProfile* const source
  )
  {
    destination->mExtractorName.assign_owned(source->mExtractorName.view());
    destination->mCategoryFilter.mUniverse = source->mCategoryFilter.mUniverse;
    destination->mCategoryFilter.mBits.mFirstWordIndex = source->mCategoryFilter.mBits.mFirstWordIndex;
    destination->mCategoryFilter.mBits.mWords.ResetFrom(source->mCategoryFilter.mBits.mWords);
    destination->mBuildRingColor = source->mBuildRingColor;
    destination->mSelectedRingColor = source->mSelectedRingColor;
    destination->mHighlightedRingColor = source->mHighlightedRingColor;
    destination->mInnerRingParams = source->mInnerRingParams;
    destination->mOuterRingParams = source->mOuterRingParams;
    return destination;
  }

  /**
   * Address: 0x007F3330 (FUN_007F3330, range-profile uninitialized copy helper)
   *
   * What it does:
   * Copy-constructs one half-open `SRangeRenderProfile` range into contiguous
   * destination storage and returns one-past-last written element.
   */
  [[maybe_unused]] [[nodiscard]] moho::SRangeRenderProfile* CopyConstructRangeRenderProfileRange(
    const moho::SRangeRenderProfile* sourceBegin,
    const moho::SRangeRenderProfile* sourceEnd,
    moho::SRangeRenderProfile* destination
  )
  {
    while (sourceBegin != sourceEnd) {
      new (destination) moho::SRangeRenderProfile{};
      (void)CopyRangeRenderProfileTransientState(destination, sourceBegin);
      ++destination;
      ++sourceBegin;
    }
    return destination;
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
   * "range" effect shader-variable slot for the fill/burn ring color. Follows
   * the same lazy-register idiom as `CRenFrame.cpp`'s `DEFINE_FRAME_SHADER_VAR_GETTER`
   * family (register-on-first-use static, bound into the "frame" effect group -
   * this is the same effect `CRenFrame::Render` selects for the "RangeMask" /
   * "RangeFill" / "RangeBurn" technique passes below). The exact HLSL variable
   * name is not independently byte-verified (IDA's own symbol for the binary
   * global is `shaderVarFrameRangeColor`, matching this getter's naming
   * convention); "RangeColor" is the best-evidence name given the surrounding
   * `FrameTexture1..4`/`BlurScale`/`GlowCopyScale` siblings.
   */
  [[nodiscard]] moho::ShaderVar& GetFrameRangeColorShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static const bool registered = (moho::RegisterShaderVar("RangeColor", &shaderVar, "frame"), true);
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
    [[maybe_unused]] boost::shared_ptr<gpg::gal::EffectVariableD3D9> viewMatrixVar = effect->SetMatrix("viewMatrix");
    boost::shared_ptr<gpg::gal::EffectVariableD3D9> projMatrixVar = effect->SetMatrix("projMatrix");

    // The binary's OnReset dispatch (EffectD3D9 vtable slot 5, +0x14) passes
    // `&cameraView.view` as an extra argument that the currently recovered
    // `EffectD3D9::OnReset()` does not declare (0-arg). `EffectD3D9.hpp` is
    // outside this file's ownership; calling the 0-arg form here is the best
    // typed call available without reintroducing raw vtable dispatch. Flagged
    // for a follow-up EffectD3D9 pass.
    effect->OnReset();
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

  struct RangeProfileMapNodeRuntimeView
  {
    moho::SRangeRenderCategoryTreeNode* mLeft;   // +0x00
    moho::SRangeRenderCategoryTreeNode* mParent; // +0x04
    moho::SRangeRenderCategoryTreeNode* mRight;  // +0x08
    std::uint8_t mUnknown0CTo13[0x08]{};         // +0x0C
    msvc8::string mKey;                          // +0x14
    moho::SRangeRenderProfile mValue;            // +0x30
  };
  static_assert(
    offsetof(RangeProfileMapNodeRuntimeView, mKey) == 0x14,
    "RangeProfileMapNodeRuntimeView::mKey offset must be 0x14"
  );
  static_assert(
    offsetof(RangeProfileMapNodeRuntimeView, mValue) == 0x30,
    "RangeProfileMapNodeRuntimeView::mValue offset must be 0x30"
  );

  struct RangeProfileMapInsertSeed
  {
    msvc8::string mKey;                // +0x00
    std::uint32_t mReserved1C = 0u;    // +0x1C
    moho::SRangeRenderProfile mValue;  // +0x20
  };
  static_assert(offsetof(RangeProfileMapInsertSeed, mReserved1C) == 0x1C, "RangeProfileMapInsertSeed::mReserved1C offset must be 0x1C");
  static_assert(offsetof(RangeProfileMapInsertSeed, mValue) == 0x20, "RangeProfileMapInsertSeed::mValue offset must be 0x20");
  static_assert(sizeof(RangeProfileMapInsertSeed) == 0xA8, "RangeProfileMapInsertSeed size must be 0xA8");

  [[nodiscard]] const RangeProfileMapNodeRuntimeView* AsRangeProfileNodeView(
    const moho::SRangeRenderCategoryTreeNode* const node
  ) noexcept
  {
    return reinterpret_cast<const RangeProfileMapNodeRuntimeView*>(node);
  }

  [[nodiscard]] RangeProfileMapNodeRuntimeView* AsRangeProfileNodeViewMutable(
    moho::SRangeRenderCategoryTreeNode* const node
  ) noexcept
  {
    return reinterpret_cast<RangeProfileMapNodeRuntimeView*>(node);
  }

  /**
   * Address: 0x007F13A0 (FUN_007F13A0, sub_7F13A0)
   *
   * What it does:
   * Returns the lower-bound candidate node for one category key in the
   * range-profile tree (head sentinel when no candidate exists).
   */
  [[nodiscard]] const moho::SRangeRenderCategoryTreeNode* FindRangeProfileLowerBoundNodeByCategory(
    const moho::SRangeRenderCategoryTree& tree,
    const std::string_view categoryName
  ) noexcept
  {
    const moho::SRangeRenderCategoryTreeNode* const head = tree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    const moho::SRangeRenderCategoryTreeNode* candidate = head;
    const moho::SRangeRenderCategoryTreeNode* node = head->mParent;
    while (node != head && node->mIsSentinel == 0u) {
      const std::string_view nodeKey = AsRangeProfileNodeView(node)->mKey.view();
      if (nodeKey < categoryName) {
        node = node->mRight;
      } else {
        candidate = node;
        node = node->mLeft;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x007F0ED0 (FUN_007F0ED0, sub_7F0ED0)
   *
   * What it does:
   * Rebinds destination profile category-word storage to inline mode and copies
   * source profile lanes into destination.
   */
  [[maybe_unused]] moho::SRangeRenderProfile* RebindAndCopyRangeRenderProfile(
    moho::SRangeRenderProfile* const destination,
    const moho::SRangeRenderProfile* const source
  )
  {
    destination->mExtractorName.tidy(true, 0u);
    destination->mExtractorName.assign_owned(source->mExtractorName.view());
    destination->mCategoryFilter.mUniverse = source->mCategoryFilter.mUniverse;
    destination->mCategoryFilter.mBits.mFirstWordIndex = source->mCategoryFilter.mBits.mFirstWordIndex;
    (void)gpg::FastVectorN2RebindAndCopy(&destination->mCategoryFilter.mBits.mWords, &source->mCategoryFilter.mBits.mWords);
    destination->mBuildRingColor = source->mBuildRingColor;
    destination->mSelectedRingColor = source->mSelectedRingColor;
    destination->mHighlightedRingColor = source->mHighlightedRingColor;
    destination->mInnerRingParams = source->mInnerRingParams;
    destination->mOuterRingParams = source->mOuterRingParams;
    return destination;
  }

  /**
   * Address: 0x007F0DD0 (FUN_007F0DD0, sub_7F0DD0)
   *
   * What it does:
   * Initializes one map insert-seed payload from source key/profile lanes.
   */
  [[maybe_unused]] RangeProfileMapInsertSeed* CopyRangeProfileMapInsertSeed(
    RangeProfileMapInsertSeed* const destination,
    const RangeProfileMapInsertSeed* const source
  )
  {
    destination->mKey.tidy(true, 0u);
    destination->mKey.assign_owned(source->mKey.view());
    (void)RebindAndCopyRangeRenderProfile(&destination->mValue, &source->mValue);
    return destination;
  }

  [[nodiscard]] const moho::SRangeRenderCategoryTreeNode* FindRangeProfileNodeByCategory(
    const moho::SRangeRenderCategoryTree& tree,
    const std::string_view categoryName
  ) noexcept
  {
    const moho::SRangeRenderCategoryTreeNode* const candidate = FindRangeProfileLowerBoundNodeByCategory(tree, categoryName);
    if (candidate == nullptr) {
      return nullptr;
    }

    const moho::SRangeRenderCategoryTreeNode* const head = tree.mHead;
    if (candidate == head) {
      return nullptr;
    }

    const std::string_view candidateKey = AsRangeProfileNodeView(candidate)->mKey.view();
    if (candidateKey < categoryName || categoryName < candidateKey) {
      return nullptr;
    }

    return candidate;
  }

  /**
   * Address: 0x007F2050 (FUN_007F2050, sub_7F2050)
   *
   * What it does:
   * Advances one range-profile RB-tree iterator slot to its in-order successor
   * using the sentinel lane at `+0xB9`.
   */
  [[maybe_unused]] moho::SRangeRenderCategoryTreeNode* AdvanceRangeProfileTreeIterator(
    const std::uint32_t /*unusedRegisterLane*/,
    moho::SRangeRenderCategoryTreeNode** const iteratorSlot
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* result = *iteratorSlot;
    if (result->mIsSentinel == 0u) {
      moho::SRangeRenderCategoryTreeNode* parentOrRight = result->mRight;
      if (parentOrRight->mIsSentinel != 0u) {
        for (result = result->mParent; result->mIsSentinel == 0u; result = result->mParent) {
          if (*iteratorSlot != result->mRight) {
            break;
          }
          *iteratorSlot = result;
        }
        *iteratorSlot = result;
      } else {
        result = parentOrRight->mLeft;
        if (parentOrRight->mLeft->mIsSentinel == 0u) {
          do {
            parentOrRight = result;
            result = result->mLeft;
          } while (result->mIsSentinel == 0u);
        }
        *iteratorSlot = parentOrRight;
      }
    }
    return result;
  }

  [[nodiscard]] moho::SRangeRenderCategoryTreeNode* FindRangeProfileTreeLeftmostNode(
    moho::SRangeRenderCategoryTreeNode* node
  ) noexcept
  {
    while (node->mLeft->mIsSentinel == 0u) {
      node = node->mLeft;
    }
    return node;
  }

  [[nodiscard]] moho::SRangeRenderCategoryTreeNode* FindRangeProfileTreeRightmostNode(
    moho::SRangeRenderCategoryTreeNode* node
  ) noexcept
  {
    while (node->mRight->mIsSentinel == 0u) {
      node = node->mRight;
    }
    return node;
  }

  void RotateRangeProfileTreeNodeLeft(
    moho::SRangeRenderCategoryTree& tree,
    moho::SRangeRenderCategoryTreeNode* const node
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* const rotated = node->mRight;
    node->mRight = rotated->mLeft;
    if (rotated->mLeft->mIsSentinel == 0u) {
      rotated->mLeft->mParent = node;
    }

    rotated->mParent = node->mParent;
    if (node == tree.mHead->mParent) {
      tree.mHead->mParent = rotated;
    } else if (node == node->mParent->mLeft) {
      node->mParent->mLeft = rotated;
    } else {
      node->mParent->mRight = rotated;
    }

    rotated->mLeft = node;
    node->mParent = rotated;
  }

  void RotateRangeProfileTreeNodeRight(
    moho::SRangeRenderCategoryTree& tree,
    moho::SRangeRenderCategoryTreeNode* const node
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* const rotated = node->mLeft;
    node->mLeft = rotated->mRight;
    if (rotated->mRight->mIsSentinel == 0u) {
      rotated->mRight->mParent = node;
    }

    rotated->mParent = node->mParent;
    if (node == tree.mHead->mParent) {
      tree.mHead->mParent = rotated;
    } else if (node == node->mParent->mRight) {
      node->mParent->mRight = rotated;
    } else {
      node->mParent->mLeft = rotated;
    }

    rotated->mRight = node;
    node->mParent = rotated;
  }

  struct RangeProfileNodeLookupResult
  {
    moho::SRangeRenderCategoryTreeNode* mNode = nullptr;
    bool mInsertOnLeft = false;
    bool mShouldInsert = false;
  };
  static_assert(sizeof(RangeProfileNodeLookupResult) == 0x08, "RangeProfileNodeLookupResult size must be 0x08");

  [[nodiscard]] bool RangeProfileKeyLess(
    const msvc8::string& lhs,
    const msvc8::string& rhs
  ) noexcept
  {
    return lhs.view() < rhs.view();
  }

  [[nodiscard]] bool RangeProfileKeyLess(
    const std::string_view lhs,
    const msvc8::string& rhs
  ) noexcept
  {
    return lhs < rhs.view();
  }

  [[nodiscard]] bool RangeProfileKeyLess(
    const msvc8::string& lhs,
    const std::string_view rhs
  ) noexcept
  {
    return lhs.view() < rhs;
  }

  void FixupAfterRangeProfileInsert(
    moho::SRangeRenderCategoryTree& tree,
    moho::SRangeRenderCategoryTreeNode* node
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* const head = tree.mHead;
    while (node != head->mParent && node->mParent->mColor == 0u) {
      moho::SRangeRenderCategoryTreeNode* const parent = node->mParent;
      moho::SRangeRenderCategoryTreeNode* const grand = parent->mParent;
      if (parent == grand->mLeft) {
        moho::SRangeRenderCategoryTreeNode* const uncle = grand->mRight;
        if (uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
        } else {
          if (node == parent->mRight) {
            node = parent;
            RotateRangeProfileTreeNodeLeft(tree, node);
          }
          node->mParent->mColor = 1u;
          grand->mColor = 0u;
          RotateRangeProfileTreeNodeRight(tree, grand);
        }
      } else {
        moho::SRangeRenderCategoryTreeNode* const uncle = grand->mLeft;
        if (uncle->mColor == 0u) {
          parent->mColor = 1u;
          uncle->mColor = 1u;
          grand->mColor = 0u;
          node = grand;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            RotateRangeProfileTreeNodeRight(tree, node);
          }
          node->mParent->mColor = 1u;
          grand->mColor = 0u;
          RotateRangeProfileTreeNodeLeft(tree, grand);
        }
      }
    }

    head->mParent->mColor = 1u;
  }

  [[nodiscard]] moho::SRangeRenderCategoryTreeNode* InsertRangeProfileNodeAtLookup(
    moho::SRangeRenderCategoryTree* const tree,
    const RangeProfileNodeLookupResult& lookup,
    const msvc8::string& key
  )
  {
    if (tree == nullptr || tree->mHead == nullptr) {
      return nullptr;
    }

    if (!lookup.mShouldInsert) {
      return lookup.mNode;
    }

    if (tree->mSize >= 0x1FFFFFFFu) {
      throw std::length_error("map/set<T> too long");
    }

    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    auto* const runtimeNode = new RangeProfileMapNodeRuntimeView{};
    runtimeNode->mKey.assign_owned(key.view());

    auto* const inserted = reinterpret_cast<moho::SRangeRenderCategoryTreeNode*>(runtimeNode);
    inserted->mLeft = head;
    inserted->mRight = head;
    inserted->mParent = lookup.mNode;
    inserted->mColor = 0u;
    inserted->mIsSentinel = 0u;

    if (lookup.mNode == head) {
      head->mParent = inserted;
    } else if (lookup.mInsertOnLeft) {
      lookup.mNode->mLeft = inserted;
    } else {
      lookup.mNode->mRight = inserted;
    }

    ++tree->mSize;
    FixupAfterRangeProfileInsert(*tree, inserted);

    moho::SRangeRenderCategoryTreeNode* const root = head->mParent;
    if (root != nullptr && root->mIsSentinel == 0u) {
      head->mLeft = FindRangeProfileTreeLeftmostNode(root);
      head->mRight = FindRangeProfileTreeRightmostNode(root);
    } else {
      head->mLeft = head;
      head->mRight = head;
    }

    return inserted;
  }

  /**
   * Address: 0x007F1010 (FUN_007F1010, sub_7F1010)
   *
   * What it does:
   * Resolves the fallback insert location for one range-profile category key:
   * returns an exact-match node when present, otherwise returns one parent/side
   * insertion slot derived from lower-bound tree search.
   */
  [[nodiscard]] RangeProfileNodeLookupResult ResolveRangeProfileInsertSiteFallback(
    moho::SRangeRenderCategoryTree* const tree,
    const msvc8::string& key
  ) noexcept
  {
    RangeProfileNodeLookupResult out{};
    if (tree == nullptr || tree->mHead == nullptr) {
      return out;
    }

    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    if (tree->mSize == 0u) {
      out.mNode = head;
      out.mInsertOnLeft = true;
      out.mShouldInsert = true;
      return out;
    }

    const moho::SRangeRenderCategoryTreeNode* const lowerBound =
      FindRangeProfileLowerBoundNodeByCategory(*tree, key.view());
    if (lowerBound == nullptr) {
      out.mNode = head;
      out.mInsertOnLeft = true;
      out.mShouldInsert = true;
      return out;
    }

    if (lowerBound == head) {
      out.mNode = head->mRight;
      if (out.mNode == nullptr || out.mNode == head || out.mNode->mIsSentinel != 0u) {
        out.mNode = head;
      }
      out.mInsertOnLeft = false;
      out.mShouldInsert = true;
      return out;
    }

    const auto* const lowerView = AsRangeProfileNodeView(lowerBound);
    if (!RangeProfileKeyLess(lowerView->mKey, key) && !RangeProfileKeyLess(key, lowerView->mKey)) {
      out.mNode = const_cast<moho::SRangeRenderCategoryTreeNode*>(lowerBound);
      out.mInsertOnLeft = false;
      out.mShouldInsert = false;
      return out;
    }

    out.mNode = const_cast<moho::SRangeRenderCategoryTreeNode*>(lowerBound);
    out.mInsertOnLeft = true;
    out.mShouldInsert = true;
    return out;
  }

  /**
   * Address: 0x007F05A0 (FUN_007F05A0, sub_7F05A0)
   *
   * What it does:
   * Applies one lower-bound hint to resolve a map node-or-insert slot for
   * range-profile keys, and falls back to full-tree insert-site resolution when
   * the hint cannot prove adjacency ownership.
   */
  [[nodiscard]] RangeProfileNodeLookupResult ResolveRangeProfileInsertSiteWithHint(
    moho::SRangeRenderCategoryTree* const tree,
    moho::SRangeRenderCategoryTreeNode* const hint,
    const msvc8::string& key
  ) noexcept
  {
    if (tree == nullptr || tree->mHead == nullptr) {
      return {};
    }

    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    if (tree->mSize == 0u) {
      return {head, true, true};
    }

    moho::SRangeRenderCategoryTreeNode* const rightMost = head->mRight;
    if (hint == nullptr || hint == head || hint->mIsSentinel != 0u) {
      if (rightMost == head || rightMost->mIsSentinel != 0u || RangeProfileKeyLess(AsRangeProfileNodeView(rightMost)->mKey, key)) {
        return {rightMost == head ? head : rightMost, false, true};
      }
      return ResolveRangeProfileInsertSiteFallback(tree, key);
    }

    const auto* const hintView = AsRangeProfileNodeView(hint);
    if (!RangeProfileKeyLess(hintView->mKey, key) && !RangeProfileKeyLess(key, hintView->mKey)) {
      return {hint, false, false};
    }

    if (RangeProfileKeyLess(key, hintView->mKey) && hint->mLeft->mIsSentinel != 0u) {
      return {hint, true, true};
    }
    if (RangeProfileKeyLess(hintView->mKey, key) && hint->mRight->mIsSentinel != 0u) {
      return {hint, false, true};
    }

    return ResolveRangeProfileInsertSiteFallback(tree, key);
  }

  /**
   * Address: 0x007EFD00 (FUN_007EFD00, sub_7EFD00)
   *
   * What it does:
   * Finds one range-profile map entry by extractor-name key and returns its
   * profile payload; when no entry exists, inserts a default node and returns
   * the newly created payload lane.
   */
  [[nodiscard]] moho::SRangeRenderProfile* FindOrInsertRangeProfileByExtractorName(
    moho::SRangeRenderCategoryTree* const tree,
    const msvc8::string& extractorName
  )
  {
    if (tree == nullptr || tree->mHead == nullptr) {
      return nullptr;
    }

    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    moho::SRangeRenderCategoryTreeNode* const hint =
      const_cast<moho::SRangeRenderCategoryTreeNode*>(FindRangeProfileLowerBoundNodeByCategory(*tree, extractorName.view()));

    if (hint != nullptr && hint != head && hint->mIsSentinel == 0u) {
      const auto* const hintView = AsRangeProfileNodeView(hint);
      if (!RangeProfileKeyLess(hintView->mKey, extractorName) && !RangeProfileKeyLess(extractorName, hintView->mKey)) {
        return &AsRangeProfileNodeViewMutable(hint)->mValue;
      }
    }

    const RangeProfileNodeLookupResult lookup = ResolveRangeProfileInsertSiteWithHint(tree, hint, extractorName);
    moho::SRangeRenderCategoryTreeNode* const node = InsertRangeProfileNodeAtLookup(tree, lookup, extractorName);
    return (node != nullptr) ? &AsRangeProfileNodeViewMutable(node)->mValue : nullptr;
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

  void DestroyRangeProfileNodeTransientStorage(
    moho::SRangeRenderCategoryTreeNode* const node
  ) noexcept
  {
    auto* const runtimeNode = AsRangeProfileNodeViewMutable(node);
    runtimeNode->mValue.mCategoryFilter.mBits.mWords.ResetStorageToInline();
    runtimeNode->mValue.mExtractorName.tidy(true, 0u);
    runtimeNode->mKey.tidy(true, 0u);
  }

  /**
   * Address: 0x007F2210 (FUN_007F2210, sub_7F2210)
   * Address: 0x007F2670 (FUN_007F2670, this method's left-rotation rebalance
   * step -- classic `_Lrotate` shape (promote right child, relink parent,
   * fix up the promoted node's left-child parent pointer), one of the
   * rotation calls in the color-fixup loop below the transplant. Sentinel
   * test at `+0xB9`, matching this node's `mIsSentinel` offset.)
   *
   * What it does:
   * Erases one range-profile map node from the RB-tree, preserves iterator
   * successor output, rebalances colors/links, and destroys node payload lanes.
   */
  [[maybe_unused]] moho::SRangeRenderCategoryTreeNode** EraseRangeProfileTreeNode(
    moho::SRangeRenderCategoryTree* const tree,
    moho::SRangeRenderCategoryTreeNode** const outNext,
    moho::SRangeRenderCategoryTreeNode* const nodeToErase
  )
  {
    if (nodeToErase->mIsSentinel != 0u) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    moho::SRangeRenderCategoryTreeNode* nextNode = nodeToErase;
    (void)AdvanceRangeProfileTreeIterator(0u, &nextNode);

    moho::SRangeRenderCategoryTreeNode* replacement = nullptr;
    moho::SRangeRenderCategoryTreeNode* fixupParent = nullptr;

    if (nodeToErase->mLeft->mIsSentinel != 0u) {
      replacement = nodeToErase->mRight;
    transplant_simple:
      fixupParent = nodeToErase->mParent;
      if (replacement->mIsSentinel == 0u) {
        replacement->mParent = fixupParent;
      }

      if (tree->mHead->mParent == nodeToErase) {
        tree->mHead->mParent = replacement;
      } else if (fixupParent->mLeft == nodeToErase) {
        fixupParent->mLeft = replacement;
      } else {
        fixupParent->mRight = replacement;
      }

      if (tree->mHead->mLeft == nodeToErase) {
        tree->mHead->mLeft = (replacement->mIsSentinel != 0u) ? fixupParent : FindRangeProfileTreeLeftmostNode(replacement);
      }
      if (tree->mHead->mRight == nodeToErase) {
        tree->mHead->mRight = (replacement->mIsSentinel != 0u) ? fixupParent : FindRangeProfileTreeRightmostNode(replacement);
      }
    } else if (nodeToErase->mRight->mIsSentinel != 0u) {
      replacement = nodeToErase->mLeft;
      goto transplant_simple;
    } else {
      moho::SRangeRenderCategoryTreeNode* const successor = nextNode;
      replacement = successor->mRight;
      if (successor == nodeToErase) {
        fixupParent = successor;
      } else {
        fixupParent = successor->mParent;
        if (replacement->mIsSentinel == 0u) {
          replacement->mParent = fixupParent;
        }
        fixupParent->mLeft = replacement;
        successor->mRight = nodeToErase->mRight;
        nodeToErase->mRight->mParent = successor;
      }

      successor->mLeft = nodeToErase->mLeft;
      nodeToErase->mLeft->mParent = successor;

      if (tree->mHead->mParent == nodeToErase) {
        tree->mHead->mParent = successor;
      } else if (nodeToErase->mParent->mLeft == nodeToErase) {
        nodeToErase->mParent->mLeft = successor;
      } else {
        nodeToErase->mParent->mRight = successor;
      }

      successor->mParent = nodeToErase->mParent;
      const std::uint8_t successorColor = successor->mColor;
      successor->mColor = nodeToErase->mColor;
      nodeToErase->mColor = successorColor;
    }

    if (nodeToErase->mColor == 1u) {
      if (replacement != tree->mHead->mParent) {
        do {
          if (replacement->mColor != 1u) {
            break;
          }

          moho::SRangeRenderCategoryTreeNode* sibling = fixupParent->mLeft;
          if (replacement == fixupParent->mLeft) {
            sibling = fixupParent->mRight;
            if (sibling->mColor == 0u) {
              sibling->mColor = 1u;
              fixupParent->mColor = 0u;
              RotateRangeProfileTreeNodeLeft(*tree, fixupParent);
              sibling = fixupParent->mRight;
            }
            if (sibling->mIsSentinel != 0u) {
              goto rebalance_propagate;
            }
            if (sibling->mLeft->mColor != 1u || sibling->mRight->mColor != 1u) {
              if (sibling->mRight->mColor == 1u) {
                sibling->mLeft->mColor = 1u;
                sibling->mColor = 0u;
                RotateRangeProfileTreeNodeRight(*tree, sibling);
                sibling = fixupParent->mRight;
              }
              sibling->mColor = fixupParent->mColor;
              fixupParent->mColor = 1u;
              sibling->mRight->mColor = 1u;
              RotateRangeProfileTreeNodeLeft(*tree, fixupParent);
              break;
            }
          } else {
            if (sibling->mColor == 0u) {
              sibling->mColor = 1u;
              fixupParent->mColor = 0u;
              RotateRangeProfileTreeNodeRight(*tree, fixupParent);
              sibling = fixupParent->mLeft;
            }
            if (sibling->mIsSentinel != 0u) {
              goto rebalance_propagate;
            }
            if (sibling->mRight->mColor != 1u || sibling->mLeft->mColor != 1u) {
              if (sibling->mLeft->mColor == 1u) {
                sibling->mRight->mColor = 1u;
                sibling->mColor = 0u;
                RotateRangeProfileTreeNodeLeft(*tree, sibling);
                sibling = fixupParent->mLeft;
              }
              sibling->mColor = fixupParent->mColor;
              fixupParent->mColor = 1u;
              sibling->mLeft->mColor = 1u;
              RotateRangeProfileTreeNodeRight(*tree, fixupParent);
              break;
            }
          }
          sibling->mColor = 0u;
        rebalance_propagate:
          replacement = fixupParent;
          const bool reachedRoot = (fixupParent == tree->mHead->mParent);
          fixupParent = fixupParent->mParent;
          if (reachedRoot) {
            break;
          }
        } while (true);
      }
      replacement->mColor = 1u;
    }

    DestroyRangeProfileNodeTransientStorage(nodeToErase);
    ::operator delete(nodeToErase);
    if (tree->mSize != 0u) {
      --tree->mSize;
    }

    *outNext = nextNode;
    return outNext;
  }

  void DestroyRangeProfileNodesRecursive(
    moho::SRangeRenderCategoryTreeNode* node
  ) noexcept;

  /**
   * Address: 0x007F1120 (FUN_007F1120, sub_7F1120)
   *
   * What it does:
   * Erases one half-open range of range-profile tree nodes and returns the
   * iterator slot that follows the erased range.
   */
  [[maybe_unused]] moho::SRangeRenderCategoryTreeNode** EraseRangeProfileTreeRange(
    moho::SRangeRenderCategoryTree* const tree,
    moho::SRangeRenderCategoryTreeNode** const outIterator,
    moho::SRangeRenderCategoryTreeNode* beginNode,
    moho::SRangeRenderCategoryTreeNode* const endNode
  )
  {
    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    if (beginNode == head->mLeft && endNode == head) {
      DestroyRangeProfileNodesRecursive(head->mParent);
      head->mParent = head;
      tree->mSize = 0u;
      head->mLeft = head;
      head->mRight = head;
      *outIterator = head->mLeft;
      return outIterator;
    }

    if (beginNode != endNode) {
      do {
        moho::SRangeRenderCategoryTreeNode* const eraseNode = beginNode;
        (void)AdvanceRangeProfileTreeIterator(0u, &beginNode);
        moho::SRangeRenderCategoryTreeNode* unusedNextSlot = nullptr;
        (void)EraseRangeProfileTreeNode(tree, &unusedNextSlot, eraseNode);
      } while (beginNode != endNode);
    }

    *outIterator = beginNode;
    return outIterator;
  }

  /**
   * Address: 0x007EFE60 (FUN_007EFE60, sub_7EFE60)
   *
   * What it does:
   * Releases one range-profile tree head by erasing every node through the
   * range-erase lane, deleting the head sentinel, and zeroing `{head,size}`.
   */
  [[maybe_unused]] std::int32_t ReleaseRangeProfileTreeStorageViaEraseRange(
    moho::SRangeRenderCategoryTree* const tree
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* unusedIterator = nullptr;
    (void)EraseRangeProfileTreeRange(tree, &unusedIterator, tree->mHead->mLeft, tree->mHead);
    ::operator delete(tree->mHead);
    tree->mHead = nullptr;
    tree->mSize = 0u;
    return 0;
  }

  /**
   * Address: 0x007F2E60 (FUN_007F2E60, sub_7F2E60)
   *
   * What it does:
   * Destroys one range-profile tree subtree in right-recursive / left-linear
   * order and releases key/profile transient storage for each node.
   */
  void DestroyRangeProfileNodesRecursive(
    moho::SRangeRenderCategoryTreeNode* node
  ) noexcept
  {
    moho::SRangeRenderCategoryTreeNode* previous = node;
    for (; previous != nullptr && previous->mIsSentinel == 0u; previous = node) {
      DestroyRangeProfileNodesRecursive(previous->mRight);
      node = previous->mLeft;

      DestroyRangeProfileNodeTransientStorage(previous);
      ::operator delete(previous);
    }
  }

  /**
   * Address: 0x007EDE20 (FUN_007EDE20, sub_7EDE20)
   *
   * What it does:
   * Releases one range-profile RB-tree storage lane by erasing all entries,
   * deleting the tree head sentinel, and zeroing `{head,size}`.
   */
  std::int32_t ReleaseRangeProfileTreeStorage(moho::SRangeRenderCategoryTree* const tree) noexcept
  {
    if (tree == nullptr) {
      return 0;
    }

    moho::SRangeRenderCategoryTreeNode* const head = tree->mHead;
    if (head != nullptr) {
      DestroyRangeProfileNodesRecursive(head->mParent);
      ::operator delete(head);
    }

    tree->mHead = nullptr;
    tree->mSize = 0u;
    return 0;
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
  [[nodiscard]] bool BlueprintPassesRangeVisibilityGate(
    const moho::CWldSession& session, const moho::RUnitBlueprint& blueprint
  ) noexcept
  {
    const moho::EntityCategoryLookupResolver* const resolver = session.GetCategoryLookupResolver();
    if (resolver == nullptr) {
      return false;
    }

    const moho::CategoryWordRangeView* const allMilitary = resolver->GetEntityCategory("AllMilitary");
    if (allMilitary == nullptr || !moho::EntityCategory::HasBlueprint(&blueprint, allMilitary)) {
      return false;
    }

    const moho::CategoryWordRangeView* const allIntel = resolver->GetEntityCategory("AllIntel");
    return allIntel != nullptr && moho::EntityCategory::HasBlueprint(&blueprint, allIntel);
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

    for (moho::SRangeRenderCategoryTreeNode* node = rangeRenderer.mRangeProfiles.mHead->mLeft;
         node != rangeRenderer.mRangeProfiles.mHead; (void)AdvanceRangeProfileTreeIterator(0u, &node)) {
      const moho::SRangeRenderProfile& profile = AsRangeProfileNodeView(node)->mValue;

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }
      if (!BlueprintPassesRangeVisibilityGate(session, *blueprint)) {
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
      (void)AppendRangeExtractionPayload(scratchPayload, payload);
      RenderRingBatch(
        profile.mOuterRingParams, camera, rangeRenderer, headIndex, profile.mBuildRingColor, profile.mInnerRingParams,
        scratchPayload
      );
    }
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
      if (!BlueprintPassesRangeVisibilityGate(session, *blueprint)) {
        continue;
      }
      if (!moho::EntityCategory::HasBlueprint(blueprint, &profile.mCategoryFilter)) {
        continue;
      }

      moho::SRangeExtractionPayload payload{};
      if (extractor->Extract(&payload, unit, alpha)) {
        (void)AppendRangeExtractionPayload(outPayloads, payload);
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

    for (moho::SRangeRenderCategoryTreeNode* node = rangeRenderer.mRangeProfiles.mHead->mLeft;
         node != rangeRenderer.mRangeProfiles.mHead; (void)AdvanceRangeProfileTreeIterator(0u, &node)) {
      const moho::SRangeRenderProfile& profile = AsRangeProfileNodeView(node)->mValue;

      moho::RangeExtractor* const extractor = moho::GetRangeExtractor(profile.mExtractorName);
      if (extractor == nullptr) {
        continue;
      }
      if (!BlueprintPassesRangeVisibilityGate(session, *blueprint)) {
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
      (void)AppendRangeExtractionPayload(scratchPayload, payload);
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
    InitRangeProfileTree(mRangeProfiles);
  }

  /**
   * Address: 0x007EDE00 (FUN_007EDE00, Moho::RangeRenderer::dtr)
   * Address: 0x007EDE50 (FUN_007EDE50, Moho::RangeRenderer::~RangeRenderer)
   */
  RangeRenderer::~RangeRenderer()
  {
    DestroyRangeRenderProfileTransientStateRange(mVisibleProfiles.begin(), mVisibleProfiles.end());
    mVisibleProfiles.clear();
    ResetRenderResources();
    DestroyRangeProfileTree(mRangeProfiles);
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
    primaryVertexBufferContext.width_ = mVertexCount;
    primaryVertexBufferContext.height_ = kPrimaryVertexStrideBytes;
    primaryVertexBufferContext.type_ = 2u;
    primaryVertexBufferContext.usage_ = 1u;
    device->CreateVertexBuffer(&mGeometry.mVertexBuffer, &primaryVertexBufferContext);

    gpg::gal::VertexBufferContext dynamicVertexBufferContext{};
    dynamicVertexBufferContext.width_ = kDynamicVertexCapacity;
    dynamicVertexBufferContext.height_ = kDynamicVertexStrideBytes;
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

    if (!mVisibleProfiles.empty()) {
      CameraFrustumUserEntityList* const frustumList = camera->GetArmyUnitsInFrustum();
      if (frustumList != nullptr) {
        CameraFrustumWeakRefSnapshotBuffer candidateSnapshot{};
        (void)SnapshotCameraFrustumWeakRefs(&candidateSnapshot, *frustumList);
        const SRangeProfileWeakRefCandidatePoolView candidatePool{candidateSnapshot.mStart, candidateSnapshot.mFinish};

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

    for (SRangeRenderCategoryTreeNode* node = mRangeProfiles.mHead->mLeft; node != mRangeProfiles.mHead;
         (void)AdvanceRangeProfileTreeIterator(0u, &node)) {
      const SRangeRenderProfile& profile = AsRangeProfileNodeView(node)->mValue;
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
    DestroyRangeRenderProfileTransientStateRange(mVisibleProfiles.begin(), mVisibleProfiles.end());
    mVisibleProfiles.clear();

    for (const msvc8::string& category : categories) {
      const SRangeRenderCategoryTreeNode* const match = FindRangeProfileNodeByCategory(mRangeProfiles, category.view());
      if (match == nullptr) {
        continue;
      }

      mVisibleProfiles.push_back(AsRangeProfileNodeView(match)->mValue);
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
    const CategoryWordRangeView* const categoryFilter,
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

    if (SRangeRenderProfile* const destination =
          FindOrInsertRangeProfileByExtractorName(&rangeRenderer->mRangeProfiles, extractorKey);
        destination != nullptr) {
      (void)CopyRangeRenderProfileTransientState(destination, &profile);
    }
  }

  /**
   * The head allocation below is FUN_007F26D0's checked-allocate-and-
   * default-init emission (`sub_7F3670(1)`, the 192-byte lane already
   * cited on `AllocateCheckedElementBlock` in Vector.cpp): allocates
   * `sizeof(SRangeRenderCategoryTreeNode)` (192 bytes, mIsSentinel@+0xB9,
   * matching this type's own static_assert), zero-inits, sets
   * color@+0xB8=1/isNil@+0xB9=0. This function then overwrites isNil to 1
   * and self-links left/parent/right to promote the fresh node into the
   * sentinel head -- the same buy_head()-equivalent inline promotion
   * pattern already documented on CAiFormationInstance.cpp's
   * InitializeDefaultFormationLaneEntry for a different hand-rolled tree.
   */
  void RangeRenderer::InitRangeProfileTree(
    SRangeRenderCategoryTree& tree
  )
  {
    tree.mMeta00 = 0u;
    tree.mHead = static_cast<SRangeRenderCategoryTreeNode*>(::operator new(sizeof(SRangeRenderCategoryTreeNode)));
    std::memset(tree.mHead, 0, sizeof(SRangeRenderCategoryTreeNode));
    tree.mHead->mIsSentinel = 1u;
    tree.mHead->mLeft = tree.mHead;
    tree.mHead->mParent = tree.mHead;
    tree.mHead->mRight = tree.mHead;
    tree.mSize = 0u;
  }

  void RangeRenderer::DestroyRangeProfileTree(
    SRangeRenderCategoryTree& tree
  )
  {
    (void)ReleaseRangeProfileTreeStorage(&tree);
    tree.mMeta00 = 0u;
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
