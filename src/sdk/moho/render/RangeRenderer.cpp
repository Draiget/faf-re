#include "moho/render/RangeRenderer.h"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "moho/misc/RangeExtractor.h"

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
    if (tree.mHead) {
      ::operator delete(tree.mHead);
    }

    tree.mHead = nullptr;
    tree.mSize = 0u;
    tree.mMeta00 = 0u;
  }
} // namespace moho
