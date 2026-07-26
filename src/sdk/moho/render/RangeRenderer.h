#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "boost/shared_ptr.h"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/misc/RangeExtractor.h"
#include "moho/render/CRenFrame.h"
#include "moho/render/RenderGeometryBuffers.h"

namespace moho
{
  class CWldSession;
  class CameraImpl;

  struct RangeRingColor
  {
    float r; // +0x00
    float g; // +0x04
    float b; // +0x08
    float a; // +0x0C
  };
  static_assert(sizeof(RangeRingColor) == 0x10, "RangeRingColor size must be 0x10");

  struct RangeRingRadiusParams
  {
    float radius;          // +0x00
    float thicknessScalar; // +0x04
  };
  static_assert(sizeof(RangeRingRadiusParams) == 0x08, "RangeRingRadiusParams size must be 0x08");

  /**
   * Profile payload consumed by the three ring-render passes
   * (build/selected/highlighted) and by extract/submit chains.
   */
  struct SRangeRenderProfile
  {
    msvc8::string mExtractorName;                  // +0x00
    std::uint32_t mReserved1C = 0u;                // +0x1C
    CategoryWordRangeView mCategoryFilter;         // +0x20
    RangeRingColor mBuildRingColor;                // +0x48
    RangeRingColor mSelectedRingColor;             // +0x58
    RangeRingColor mHighlightedRingColor;          // +0x68
    RangeRingRadiusParams mInnerRingParams;        // +0x78
    RangeRingRadiusParams mOuterRingParams;        // +0x80
  };

  static_assert(offsetof(SRangeRenderProfile, mExtractorName) == 0x00, "SRangeRenderProfile::mExtractorName");
  static_assert(offsetof(SRangeRenderProfile, mCategoryFilter) == 0x20, "SRangeRenderProfile::mCategoryFilter");
  static_assert(offsetof(SRangeRenderProfile, mBuildRingColor) == 0x48, "SRangeRenderProfile::mBuildRingColor");
  static_assert(offsetof(SRangeRenderProfile, mSelectedRingColor) == 0x58, "SRangeRenderProfile::mSelectedRingColor");
  static_assert(
    offsetof(SRangeRenderProfile, mHighlightedRingColor) == 0x68, "SRangeRenderProfile::mHighlightedRingColor"
  );
  static_assert(offsetof(SRangeRenderProfile, mInnerRingParams) == 0x78, "SRangeRenderProfile::mInnerRingParams");
  static_assert(offsetof(SRangeRenderProfile, mOuterRingParams) == 0x80, "SRangeRenderProfile::mOuterRingParams");
  static_assert(sizeof(SRangeRenderProfile) == 0x88, "SRangeRenderProfile size must be 0x88");

  /**
   * RB-tree entry value lane used by the range-profile registry tree.
   * Prefix ownership remains unresolved and is kept as an explicit typed byte lane.
   */
  struct SRangeRenderCategoryEntry
  {
    std::uint8_t mRuntimeMetadata00[0x24]; // +0x00
    SRangeRenderProfile mProfile;          // +0x24
  };
  static_assert(offsetof(SRangeRenderCategoryEntry, mProfile) == 0x24, "SRangeRenderCategoryEntry::mProfile");
  static_assert(sizeof(SRangeRenderCategoryEntry) == 0xAC, "SRangeRenderCategoryEntry size must be 0xAC");

  struct SRangeRenderCategoryTreeNode
  {
    SRangeRenderCategoryTreeNode* mLeft;   // +0x00
    SRangeRenderCategoryTreeNode* mParent; // +0x04
    SRangeRenderCategoryTreeNode* mRight;  // +0x08
    SRangeRenderCategoryEntry mEntry;      // +0x0C
    std::uint8_t mColor;                   // +0xB8
    std::uint8_t mIsSentinel;              // +0xB9
    std::uint8_t mPadBA[2];                // +0xBA
  };
  static_assert(offsetof(SRangeRenderCategoryTreeNode, mEntry) == 0x0C, "SRangeRenderCategoryTreeNode::mEntry");
  static_assert(offsetof(SRangeRenderCategoryTreeNode, mIsSentinel) == 0xB9, "SRangeRenderCategoryTreeNode::mIsSentinel");
  static_assert(sizeof(SRangeRenderCategoryTreeNode) == 0xBC, "SRangeRenderCategoryTreeNode size must be 0xBC");

  struct SRangeRenderCategoryTree
  {
    std::uint32_t mMeta00;                  // +0x00
    SRangeRenderCategoryTreeNode* mHead;    // +0x04
    std::uint32_t mSize;                    // +0x08
  };
  static_assert(sizeof(SRangeRenderCategoryTree) == 0x0C, "SRangeRenderCategoryTree size must be 0x0C");
  static_assert(offsetof(SRangeRenderCategoryTree, mHead) == 0x04, "SRangeRenderCategoryTree::mHead");
  static_assert(offsetof(SRangeRenderCategoryTree, mSize) == 0x08, "SRangeRenderCategoryTree::mSize");

  /**
   * VFTABLE: 0x00E3F918
   * COL:     0x00E9843C
   */
  class RangeRenderer
  {
  public:
    /**
     * Address: 0x007EDD60 (FUN_007EDD60, Moho::RangeRenderer::RangeRenderer)
     *
     * What it does:
     * Initializes range-render profile containers and render resource ownership lanes.
     */
    RangeRenderer();

    /**
     * Address: 0x007EDE00 (FUN_007EDE00, Moho::RangeRenderer::dtr)
     * Address: 0x007EDE50 (FUN_007EDE50, Moho::RangeRenderer::~RangeRenderer)
     *
     * What it does:
     * Tears down render resources and range-profile tree ownership state.
     */
    virtual ~RangeRenderer();

    /**
     * Address: 0x007EDFE0 (FUN_007EDFE0, Moho::RangeRenderer::Init)
     *
     * What it does:
     * Builds static ring geometry buffers and uploads range ring index topology.
     */
    void Init();

    /**
     * Address: 0x007EEA00 (FUN_007EEA00, Moho::RangeRenderer::Render)
     *
     * IDA signature (compiler-invented register convention, `retn 0Ch`):
     * void __usercall Render(CWldSession *session@<ecx>, CameraImpl *camera@<ebx>,
     *                        RangeRenderer *renderer, unsigned headIndex, float alpha);
     *
     * The camera parameter is `CameraImpl`, not `Cartographic`. EBX is never
     * written in the body (inbound register argument) and is dispatched at
     * `+0x08` (0x007EEA87) and `+0xA4` (0x007EEA90), then forwarded as the EDX
     * register argument of `func_RenderRings` where `+0x08`, `+0x4C` and `+0x50`
     * are used. `??_7CameraImpl@Moho@@6B@` (0x00E3C474) holds 0x007A6A00
     * (`CameraGetView`, slot 2), 0x007A6CA0 (`CameraGetTargetZoom`, slot 19),
     * 0x007A7310 (`GetMaxZoom`, slot 20) and 0x007A7910
     * (`GetArmyUnitsInFrustum`, slot 41) at exactly those offsets. Both callers
     * load EBX from `IRenderWorldView::GetCamera()`: `Moho::Cartographic::Render`
     * at 0x007D183F-0x007D1A2C and `Moho::WRenViewport::Render` at
     * 0x007F940E-0x007F944B.
     *
     * No body is recovered yet; the render chain below it is still blocked on
     * the `sWldMap` and `shaderVarFrameRangeColor` globals.
     */
    void Render(CWldSession* worldSession, CameraImpl* camera, unsigned int viewportHeadIndex, float alpha);

    /**
     * Address: 0x007EE950 (FUN_007EE950, Moho::RangeRenderer::MoveCategories)
     *
     * What it does:
     * Rebuilds the visible-profile vector from category-name keys using the
     * profile map tree.
     */
    void MoveCategories(const msvc8::vector<msvc8::string>& categories);

    /**
     * Address: 0x007EE430 (FUN_007EE430, sub_7EE430)
     *
     * What it does:
     * Releases dynamic/static ring geometry resources and resets runtime counters.
     */
    void ResetRenderResources() noexcept;

  private:
    static void InitRangeProfileTree(SRangeRenderCategoryTree& tree);
    static void DestroyRangeProfileTree(SRangeRenderCategoryTree& tree);

  public:
    SRangeRenderCategoryTree mRangeProfiles;                           // +0x04
    msvc8::vector<SRangeRenderProfile> mVisibleProfiles;              // +0x14
    std::uint32_t mIndexCount;                                        // +0x20
    std::uint32_t mVertexCount;                                       // +0x24
    RenderGeometryBuffers mGeometry;                                  // +0x28
    std::uint32_t mDynamicRingVertexCount;                            // +0x40
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDynamicVertexBuffer; // +0x44
    CRenFrame mFrame;                                                 // +0x4C
  };

  static_assert(offsetof(RangeRenderer, mRangeProfiles) == 0x04, "RangeRenderer::mRangeProfiles");
  static_assert(offsetof(RangeRenderer, mVisibleProfiles) == 0x10, "RangeRenderer::mVisibleProfiles");
  static_assert(offsetof(RangeRenderer, mIndexCount) == 0x20, "RangeRenderer::mIndexCount");
  static_assert(offsetof(RangeRenderer, mVertexCount) == 0x24, "RangeRenderer::mVertexCount");
  static_assert(offsetof(RangeRenderer, mGeometry) == 0x28, "RangeRenderer::mGeometry");
  static_assert(
    offsetof(RangeRenderer, mDynamicRingVertexCount) == 0x40, "RangeRenderer::mDynamicRingVertexCount"
  );
  static_assert(offsetof(RangeRenderer, mDynamicVertexBuffer) == 0x44, "RangeRenderer::mDynamicVertexBuffer");
  static_assert(offsetof(RangeRenderer, mFrame) == 0x4C, "RangeRenderer::mFrame");
  static_assert(sizeof(RangeRenderer) == 0x94, "RangeRenderer size must be 0x94");

  /**
   * Address: 0x007EE5A0 (FUN_007EE5A0, sub_7EE5A0)
   *
   * What it does:
   * Finds-or-inserts one range-profile map entry by extractor name, copies one
   * category-filter payload, and stores packed build/selected/highlight colors
   * plus inner/outer ring radius parameters.
   */
  void ApplyRangeProfileFilterToRenderer(
    std::uint32_t highlightedColorPacked,
    const CategoryWordRangeView* categoryFilter,
    RangeRenderer* rangeRenderer,
    std::string_view extractorName,
    std::uint32_t buildColorPacked,
    std::uint32_t selectedColorPacked,
    const RangeRingRadiusParams& innerRingParams,
    const RangeRingRadiusParams& outerRingParams
  );

  /**
   * Address: 0x007EF0B0 (FUN_007EF0B0, Moho::func_ExtractRanges)
   *
   * Opaque candidate-pool view: a contiguous half-open range of
   * `SSelectionWeakRefUserEntity` records, modeled as `(begin, end)` raw
   * pointer pair to match the original fastvector view shape used by
   * `RangeRenderer::Render`.
   */
  struct SRangeProfileWeakRefCandidatePoolView
  {
    const void* begin;   // start of weak-ref record range (8 bytes per entry)
    const void* end;     // one-past-last weak-ref record
  };

  /**
   * Output ring extraction payload vector accepted by `func_ExtractRanges`.
   * The binary appends one entry per successfully extracted candidate using
   * `AppendRangeExtractionPayload` lane behavior.
   */
  using SRangeExtractionPayloadVector = msvc8::vector<SRangeExtractionPayload>;

  /**
   * Address: 0x007EF0B0 (FUN_007EF0B0, Moho::func_ExtractRanges)
   *
   * What it does:
   * Per-visible-profile extraction pass: resolves the registered range
   * extractor for the profile's extractor name, iterates over a pre-collected
   * pool of candidate selection weak-refs to user entities, gates each
   * candidate by typed live-unit checks (not-being-built, is-user-unit, not
   * dead/destroy-queued, blueprint present), filters by the profile's
   * category set, and appends successful extractor payloads to the output
   * ring extraction payload vector.
   */
  void func_ExtractRanges(
    const SRangeProfileWeakRefCandidatePoolView& candidatePool,
    float interpolationAlpha,
    const SRangeRenderProfile& profile,
    SRangeExtractionPayloadVector& outRingPayloadVector
  );
} // namespace moho
