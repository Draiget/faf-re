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
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/RangeExtractor.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"

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
  constexpr float kRangeMaxMapHeight = 256.0f;
  constexpr float kRangeMinMapHeight = -256.0f;
  constexpr std::size_t kRangeRingHullSampleCount = 24u;

  struct RangeRingHullSampleDirection
  {
    float cosTheta;
    float sinTheta;
  };

  static_assert(sizeof(RangeRingHullSampleDirection) == 0x08, "RangeRingHullSampleDirection size must be 0x08");

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

  // Applied from FAForever/FA-Binary-Patches PR #150 ("Add range ring hull cull
  // for dense crowd FPS recovery"), by M3RT1N99 (Apr 9-10, 2026).
  // Why: range-ring setup/render cost scales with unit count, while dense
  // interior rings are fully hidden by neighbors and add no visible outline.
  // This 24-sample outer-circle coverage test keeps only boundary/isolated rings.
  constexpr std::array<RangeRingHullSampleDirection, kRangeRingHullSampleCount> kRangeRingHullSampleDirections = {{
    {1.00000000f, 0.00000000f},   {0.96592583f, 0.25881905f},   {0.86602540f, 0.50000000f},
    {0.70710677f, 0.70710677f},   {0.50000000f, 0.86602540f},   {0.25881905f, 0.96592583f},
    {0.00000000f, 1.00000000f},   {-0.25881905f, 0.96592583f},  {-0.50000000f, 0.86602540f},
    {-0.70710677f, 0.70710677f},  {-0.86602540f, 0.50000000f},  {-0.96592583f, 0.25881905f},
    {-1.00000000f, 0.00000000f},  {-0.96592583f, -0.25881905f}, {-0.86602540f, -0.50000000f},
    {-0.70710677f, -0.70710677f}, {-0.50000000f, -0.86602540f}, {-0.25881905f, -0.96592583f},
    {0.00000000f, -1.00000000f},  {0.25881905f, -0.96592583f},  {0.50000000f, -0.86602540f},
    {0.70710677f, -0.70710677f},  {0.86602540f, -0.50000000f},  {0.96592583f, -0.25881905f},
  }};

  [[nodiscard]] bool IsRingSampleCoveredByEntry(
    const moho::SRangeExtractionPayload& entry,
    const float sampleX,
    const float sampleZ
  )
  {
    const float dx = entry.centerX - sampleX;
    const float dz = entry.centerZ - sampleZ;
    const float distanceSquared = (dx * dx) + (dz * dz);
    const float outerRadius = entry.outerRadius;
    if (distanceSquared > (outerRadius * outerRadius)) {
      return false;
    }

    const float innerRadius = entry.innerRadius;
    if (innerRadius > 0.0f && distanceSquared < (innerRadius * innerRadius)) {
      return false;
    }

    return true;
  }

  [[nodiscard]] bool IsFullyCoveredByKeptEntries(
    const moho::SRangeExtractionPayload& candidate,
    const RangeExtractionPayloadVector& entries,
    const std::size_t keptCount
  )
  {
    if (keptCount == 0u) {
      return false;
    }

    for (const RangeRingHullSampleDirection sampleDirection : kRangeRingHullSampleDirections) {
      const float sampleX = candidate.centerX + (candidate.outerRadius * sampleDirection.cosTheta);
      const float sampleZ = candidate.centerZ + (candidate.outerRadius * sampleDirection.sinTheta);

      bool sampleCovered = false;
      for (std::size_t keptIndex = 0u; keptIndex < keptCount; ++keptIndex) {
        if (IsRingSampleCoveredByEntry(entries[keptIndex], sampleX, sampleZ)) {
          sampleCovered = true;
          break;
        }
      }

      if (!sampleCovered) {
        return false;
      }
    }

    return true;
  }

  /**
   * Applied patch behavior:
   * FAForever/FA-Binary-Patches PR #150 (M3RT1N99), hooked at 0x007EF5E2 in
   * `func_RenderRings` (0x007EF5A0), before the render loops consume the ring
   * payload vector.
   */
  [[maybe_unused]] std::uint32_t CullRangeRingClusterHullInPlace(
    RangeExtractionPayloadVector& ringEntries,
    const bool enabled
  )
  {
    const std::size_t originalCount = ringEntries.size();
    if (!enabled || originalCount <= 4u) {
      return static_cast<std::uint32_t>(originalCount);
    }

    std::size_t writeIndex = 0u;
    for (std::size_t readIndex = 0u; readIndex < originalCount; ++readIndex) {
      const moho::SRangeExtractionPayload candidate = ringEntries[readIndex];
      const bool fullyCovered = IsFullyCoveredByKeptEntries(candidate, ringEntries, writeIndex);
      if (fullyCovered) {
        continue;
      }

      ringEntries[writeIndex] = candidate;
      ++writeIndex;
    }

    ringEntries.resize(writeIndex);
    return static_cast<std::uint32_t>(writeIndex);
  }

  /**
   * Address: 0x007F0310 (FUN_007F0310, sub_7F0310)
   *
   * What it does:
   * Appends one ring extraction payload (`worldX`, `worldZ`, `innerRadius`,
   * `outerRadius`) to the active payload vector, growing storage when needed.
   * This helper lane is part of FAF's hull-cull range-ring patch path
   * (xref: `patch_Moho::CNetUDPConnector::Entry`), not the stock engine lane.
   */
  [[maybe_unused, nodiscard]] moho::SRangeExtractionPayload* AppendRangeExtractionPayload(
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

  struct RangeExtractionFastVectorN20RuntimeView
  {
    moho::SRangeExtractionPayload* mStart;         // +0x00
    moho::SRangeExtractionPayload* mFinish;        // +0x04
    moho::SRangeExtractionPayload* mCapacity;      // +0x08
    moho::SRangeExtractionPayload* mOriginalStart; // +0x0C
    moho::SRangeExtractionPayload mInlineStorage[20]; // +0x10
  };
  static_assert(sizeof(RangeExtractionFastVectorN20RuntimeView) == 0x150, "RangeExtractionFastVectorN20RuntimeView size must be 0x150");

  /**
   * Address: 0x007F03D0 (FUN_007F03D0, sub_7F03D0)
   *
   * What it does:
   * Rebinds one `fastvector_n<SRangeExtractionPayload,20>` lane to inline
   * storage and copies source payload entries, spilling to heap when source
   * exceeds inline capacity.
   */
  [[maybe_unused]] RangeExtractionFastVectorN20RuntimeView* CopyRangeExtractionFastVectorN20(
    RangeExtractionFastVectorN20RuntimeView* const destination,
    const RangeExtractionFastVectorN20RuntimeView& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    constexpr std::size_t kInlineCount = 20u;
    moho::SRangeExtractionPayload* const inlineStart = &destination->mInlineStorage[0];
    destination->mStart = inlineStart;
    destination->mFinish = inlineStart;
    destination->mCapacity = inlineStart + kInlineCount;
    destination->mOriginalStart = inlineStart;

    const moho::SRangeExtractionPayload* const sourceStart = source.mStart;
    const moho::SRangeExtractionPayload* const sourceFinish = source.mFinish;
    if (sourceStart == nullptr || sourceFinish == nullptr || sourceFinish <= sourceStart) {
      return destination;
    }

    const std::size_t sourceCount = static_cast<std::size_t>(sourceFinish - sourceStart);
    moho::SRangeExtractionPayload* writeStart = inlineStart;
    if (sourceCount > kInlineCount) {
      writeStart = static_cast<moho::SRangeExtractionPayload*>(::operator new[](sourceCount * sizeof(*writeStart)));
      destination->mStart = writeStart;
      destination->mFinish = writeStart;
      destination->mCapacity = writeStart + sourceCount;
    }

    std::memcpy(writeStart, sourceStart, sourceCount * sizeof(*writeStart));
    destination->mFinish = writeStart + sourceCount;
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

  /**
   * Address: 0x007EF5A0 (FUN_007EF5A0, func_RenderRings)
   *
   * What it does:
   * Recovers the geometry-preparation lane used by range-ring rendering:
   * - applies FAF hull-cull compaction from PR #150
   * - computes zoom-scaled inner/outer thickness offsets
   * - expands source ring entries into fill + edge payload buffers
   *
   * Notes:
   * The downstream dynamic-buffer draw/stencil frame passes remain in the
   * unrecovered tail lane of FUN_007EF5A0.
   */
  [[maybe_unused]] std::uint32_t PrepareRenderRingsGeometryPass(
    RangeExtractionPayloadVector& ringEntries,
    const moho::RangeRingRadiusParams& innerRingParams,
    const moho::RangeRingRadiusParams& outerRingParams,
    const float playableMapSpan,
    const float zoomScale,
    const float innerThicknessCoeff,
    const float outerThicknessCoeff,
    RangeExtractionPayloadVector& outFillPayloads,
    RangeExtractionPayloadVector& outEdgePayloads
  )
  {
    const std::uint32_t ringCount = CullRangeRingClusterHullInPlace(ringEntries, true);
    outFillPayloads.clear();
    outEdgePayloads.clear();
    if (ringCount == 0u) {
      return 0u;
    }

    const float innerThicknessOffset =
      (((innerRingParams.thicknessScalar * innerThicknessCoeff) * playableMapSpan) - innerRingParams.radius) *
        zoomScale +
      innerRingParams.radius;
    const float outerThicknessOffset =
      (((outerRingParams.thicknessScalar * outerThicknessCoeff) * playableMapSpan) - outerRingParams.radius) *
        zoomScale +
      outerRingParams.radius;

    RangeRingGeometryBuildState buildState{
      innerThicknessOffset,
      outerThicknessOffset,
      &outFillPayloads,
      &outEdgePayloads,
    };

    BuildRingPayloadBuffers(buildState, ringEntries.begin(), ringEntries.end());
    return ringCount;
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
  [[maybe_unused]] bool ReserveDynamicRingVertexSliceRuntime(
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

          WriteRingBandVertex(vertexData, i, x, kRangeMaxMapHeight, z, 1.0f, 0.0f);
          WriteRingBandVertex(vertexData, i + kRangeRingSegmentCount, x, kRangeMaxMapHeight, z, 0.0f, 1.0f);
          WriteRingBandVertex(vertexData, i + (kRangeRingSegmentCount * 2u), x, kRangeMinMapHeight, z, 1.0f, 0.0f);
          WriteRingBandVertex(vertexData, i + (kRangeRingSegmentCount * 3u), x, kRangeMinMapHeight, z, 0.0f, 1.0f);
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
} // namespace moho
