#include "moho/render/tess/CTesselator.h"

#include <bit>
#include <array>
#include <cstddef>

namespace moho
{
  extern float ren_ShoreErrorCoeff;
  extern float ren_maxViewError;
  extern bool ren_ErrorCache;

  namespace
  {
    struct ITesselatorRuntimeView
    {
      void* mVtable = nullptr;
    };
    static_assert(sizeof(ITesselatorRuntimeView) == 0x04, "ITesselatorRuntimeView size must be 0x04");

    class ITesselatorVTableProbe
    {
    public:
      virtual ~ITesselatorVTableProbe() = default;
    };

    [[nodiscard]] void* RecoveredITesselatorVTable() noexcept
    {
      static ITesselatorVTableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }

    void WriteITesselatorVTable(ITesselatorRuntimeView* const object) noexcept
    {
      object->mVtable = RecoveredITesselatorVTable();
    }

    /**
     * Address: 0x0080B9A0 (FUN_0080B9A0)
     *
     * IDA signature:
     * void __thiscall sub_80B9A0(_DWORD *this)
     *
     * What it does:
     * Writes the `ITesselator` base-interface vtable lane in-place.
     */
    [[maybe_unused]] void InitializeITesselatorVTableThiscall(ITesselatorRuntimeView* const object) noexcept
    {
      WriteITesselatorVTable(object);
    }

    /**
     * Address: 0x0080EBA0 (FUN_0080EBA0)
     *
     * IDA signature:
     * _DWORD *__usercall sub_80EBA0@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Alias lane that writes the same `ITesselator` base-interface vtable and
     * returns the same object pointer.
     */
    [[maybe_unused]] ITesselatorRuntimeView* InitializeITesselatorVTableReturnLane(
      ITesselatorRuntimeView* const object
    ) noexcept
    {
      WriteITesselatorVTable(object);
      return object;
    }

    enum IntersectionResult : int
    {
      kSplit = 1,
      kAccept = 2,
      kReject = 3,
    };

    constexpr std::size_t kRectLookupMask = 0x1FFu;
    constexpr std::size_t kRectLimit = 65000u;

    [[nodiscard]] std::size_t LookupIndex(const std::int32_t x, const std::int32_t z) noexcept
    {
      const std::size_t maskedX = static_cast<std::size_t>(x) & kRectLookupMask;
      const std::size_t maskedZ = static_cast<std::size_t>(z) & kRectLookupMask;
      return maskedZ | (maskedX << 9u);
    }

    /**
     * Address: 0x00472340 (FUN_00472340)
     *
     * What it does:
     * Selects one AABB corner from `{Min, Max}` using a three-bit axis mask.
     */
    [[nodiscard]]
    Wm3::Vector3f SelectAabbCornerByMask(const Wm3::AxisAlignedBox3f& bounds, const std::uint32_t axisMask)
    {
      const Wm3::Vector3f* const extrema[2] = {&bounds.Min, &bounds.Max};

      Wm3::Vector3f out{};
      out.x = extrema[(axisMask >> 0u) & 1u]->x;
      out.y = extrema[(axisMask >> 1u) & 1u]->y;
      out.z = extrema[(axisMask >> 2u) & 1u]->z;
      return out;
    }

    [[nodiscard]] int MostSignificantBitIndexOrMinusOne(const std::uint32_t value) noexcept
    {
      if (value == 0u) {
        return -1;
      }
      return static_cast<int>(std::bit_width(value) - 1u);
    }

    [[nodiscard]] int AbsoluteValue(const int value) noexcept
    {
      return (value < 0) ? -value : value;
    }

    [[nodiscard]] int HeightFieldTierCount(const CHeightField& field) noexcept
    {
      if (field.mGrids.begin() == nullptr) {
        return 0;
      }
      return static_cast<int>(field.mGrids.end() - field.mGrids.begin());
    }

    /**
     * Address: 0x0080C5D0 (FUN_0080C5D0, func_Tesselate)
     *
     * What it does:
     * Recursively resolves one query rectangle against one split-work node and
     * returns matching range/min-max lanes for either full-tile coverage or
     * exact tile match.
     */
    [[nodiscard]] bool FindSplitWorkRange(
      const CTesselator& tesselator,
      const std::int32_t nodeIndex,
      const std::int32_t tileX,
      const std::int32_t tileZ,
      const std::int32_t level,
      const std::int32_t queryX,
      const std::int32_t queryZ,
      const std::int32_t querySize,
      std::int32_t* const outRangeStart,
      std::int32_t* const outRangeCount,
      std::int32_t* const outMinValue,
      std::int32_t* const outMaxValue
    )
    {
      if (tesselator.mSplitWorkQueue.start_ == nullptr) {
        return false;
      }

      const CTesselator::SplitWorkNode& node = tesselator.mSplitWorkQueue.start_[nodeIndex];
      const std::int32_t shift = level & 0x1F;
      const std::int32_t tileOriginX = tileX << shift;
      const std::int32_t tileOriginZ = tileZ << shift;
      const std::int32_t tileSpan = 1 << shift;

      if (tileSpan < querySize) {
        if (
          queryX <= tileOriginX && (queryX + querySize) >= (tileOriginX + tileSpan) && queryZ <= tileOriginZ
          && (queryZ + querySize) >= (tileOriginZ + tileSpan)
        ) {
          *outRangeStart = node.rangeStart;
          *outRangeCount = node.rangeCount;
          *outMinValue = node.minValue;
          *outMaxValue = node.maxValue;
          return true;
        }
        return false;
      }

      if (tileSpan == querySize && tileOriginX == queryX && tileOriginZ == queryZ) {
        *outRangeStart = node.rangeStart;
        *outRangeCount = node.rangeCount;
        *outMinValue = node.minValue;
        *outMaxValue = node.maxValue;
        return true;
      }

      if (
        node.childTopLeftIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childTopLeftIndex,
          2 * tileX,
          2 * tileZ,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      if (
        node.childTopRightIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childTopRightIndex,
          2 * tileX + 1,
          2 * tileZ,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      if (
        node.childBottomLeftIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childBottomLeftIndex,
          2 * tileX,
          2 * tileZ + 1,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      return (
        node.childBottomRightIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childBottomRightIndex,
          2 * tileX + 1,
          2 * tileZ + 1,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      );
    }
  } // namespace

  /**
   * Address: 0x0080BAA0 (??0CTesselator@Moho@@QAE@@Z)
   * Mangled: ??0CTesselator@Moho@@QAE@@Z
   *
   * What it does:
   * Binds the source heightfield and initializes all inline fastvector
   * storage lanes used by terrain tessellation.
   */
  CTesselator::CTesselator(CHeightField* const field)
    : mField(field)
  {
  }

  /**
   * Address: 0x0080BB70 (FUN_0080BB70, ??1CTesselator@Moho@@QAE@@Z)
   * Mangled: ??1CTesselator@Moho@@QAE@@Z
   *
   * What it does:
   * Releases heap-backed storage for all FastVectorN lanes and rebinds each
   * lane to inline storage metadata.
   */
  CTesselator::~CTesselator()
  {
    mScratch.ResetStorageToInline();
    mRectIndices.ResetStorageToInline();
    mSplitWorkQueue.ResetStorageToInline();
    mCollisionRectLut.ResetStorageToInline();
    mRectCache.ResetStorageToInline();
    mGeomSolid.planes_.ResetStorageToInline();
  }

  /**
   * Address: 0x0080E020 (FUN_0080E020, Moho::CTesselator::GetIntersectionResult)
   *
   * What it does:
   * Builds one tier-cell AABB, optionally clips it against active frustum
   * planes, then compares tier max error against view-scaled threshold.
   */
  int CTesselator::GetIntersectionResult(
    const int x,
    const int z,
    const int tier,
    std::uint32_t* const activePlaneMask
  )
  {
    const int cellX = x << tier;
    const int cellZ = z << tier;
    if (cellX < 0 || cellZ < 0) {
      return kReject;
    }

    if (cellX >= (mField->width - 1) || cellZ >= (mField->height - 1)) {
      return kReject;
    }

    const Wm3::Vector2f tierBounds = mField->GetTierBounds(x, z, tier);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = static_cast<float>(cellX);
    bounds.Min.y = tierBounds.x;
    bounds.Min.z = static_cast<float>(cellZ);
    bounds.Max.x = static_cast<float>(cellX + (1 << tier));
    bounds.Max.y = tierBounds.y;
    bounds.Max.z = static_cast<float>(cellZ + (1 << tier));

    const float waterElevation = mWaterElevation;
    const bool crossesWaterSurface = (waterElevation >= tierBounds.x) && (tierBounds.y >= waterElevation);

    if (*activePlaneMask != 0u) {
      float clippedMaxY = tierBounds.y;
      if (waterElevation > clippedMaxY) {
        clippedMaxY = waterElevation;
      }
      bounds.Max.y = clippedMaxY;

      if (!mGeomSolid.Intersects(bounds, activePlaneMask)) {
        return kReject;
      }

      bounds.Max.y = tierBounds.y;
    }

    const Wm3::Vector3f testCorner = SelectAabbCornerByMask(bounds, mCornerSelectionMask);
    const float tierMaxError = mField->GetTierMaxError(tier, x, z);
    const float shoreErrorCoeff = crossesWaterSurface ? ren_ShoreErrorCoeff : 1.0f;

    const Vector4f& row1 = mCam->viewport.r[1];
    const float projectedDepth =
      (row1.z * testCorner.z) + (row1.y * testCorner.y) + (row1.x * testCorner.x) + row1.w;

    const float maxAllowedError = shoreErrorCoeff * projectedDepth * ren_maxViewError;
    return (tierMaxError < maxAllowedError) ? kAccept : kSplit;
  }

  /**
   * Address: 0x0080BEC0 (FUN_0080BEC0, Moho::CTesselator::Tesselate)
   *
   * What it does:
   * Searches split-work quadtree lanes for query coverage and accumulates
   * matching range/min-max outputs.
   */
  bool CTesselator::Tesselate(
    const std::int32_t queryX,
    const std::int32_t queryZ,
    const std::int32_t querySize,
    std::int32_t* const outRangeStart,
    std::uint32_t* const outRangeCount,
    std::int32_t* const outMinValue,
    std::int32_t* const outMaxValue
  )
  {
    *outRangeStart = 0;
    *outRangeCount = 0;

    if (mRectIndices.start_ == mRectIndices.end_) {
      return false;
    }

    const std::int32_t widthMinusOne = mField->width - 1;
    const std::int32_t heightMinusOne = mField->height - 1;
    const std::int32_t widthBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(widthMinusOne));
    const std::int32_t heightBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(heightMinusOne));
    const std::int32_t tierBias = AbsoluteValue(widthBit - heightBit);

    std::int32_t gridColumns = widthMinusOne / heightMinusOne;
    if (gridColumns < 1) {
      gridColumns = 1;
    }

    std::int32_t gridRows = heightMinusOne / widthMinusOne;
    if (gridRows < 1) {
      gridRows = 1;
    }

    std::int32_t tileX = 0;
    std::int32_t outerToken = 0;
    while (outerToken < gridColumns) {
      std::int32_t tileZ = 0;
      if (gridRows > 0) {
        std::int32_t rectIndexOffset = tileX;
        do {
          const std::int32_t rootNodeIndex = mRectIndices.start_[rectIndexOffset];
          if (rootNodeIndex != -1) {
            std::int32_t foundRangeStart = widthMinusOne;
            std::int32_t foundRangeCount = 0;
            std::int32_t foundMin = 0;
            std::int32_t foundMax = 0;

            const std::int32_t tierCount = HeightFieldTierCount(*mField);
            if (
              FindSplitWorkRange(
                *this,
                rootNodeIndex,
                tileX,
                tileZ,
                tierCount - tierBias,
                queryX,
                queryZ,
                querySize,
                &foundRangeStart,
                &foundRangeCount,
                &foundMin,
                &foundMax
              )
            ) {
              if (*outRangeCount == 0u) {
                *outRangeStart = foundRangeStart;
                *outRangeCount = static_cast<std::uint32_t>(foundRangeCount);
                *outMinValue = foundMin;
                *outMaxValue = foundMax;
              } else {
                std::int32_t ignoredRangeStart = foundRangeStart;
                std::int32_t appendedRangeCount = foundRangeCount;
                std::int32_t appendedMin = foundMin;
                std::int32_t appendedMax = foundMax;

                (void)FindSplitWorkRange(
                  *this,
                  rootNodeIndex,
                  tileX,
                  tileZ,
                  tierCount - tierBias,
                  queryX,
                  queryZ,
                  querySize,
                  &ignoredRangeStart,
                  &appendedRangeCount,
                  &appendedMin,
                  &appendedMax
                );

                *outRangeCount += static_cast<std::uint32_t>(appendedRangeCount);
                if (*outMinValue >= appendedMin) {
                  *outMinValue = appendedMin;
                }
                if (*outMaxValue < appendedMax) {
                  *outMaxValue = appendedMax;
                }
              }
            }
          }

          ++tileZ;
          ++rectIndexOffset;
        } while (tileZ < gridRows);
      }

      tileX = ++outerToken;
    }

    return *outRangeCount > 0u;
  }

  /**
   * Address: 0x0080BA30 (FUN_0080BA30, Moho::CTesselator::GetData)
   *
   * What it does:
   * Reads one cached index from the 512x512 lookup ring and validates that the
   * pointed rect still matches `(x,z)`.
   */
  std::int16_t CTesselator::GetData(const std::int32_t z, const std::int32_t x) const
  {
    if (mRectCache.start_ == nullptr) {
      return -1;
    }

    const std::uint16_t index = mLookup[LookupIndex(x, z)];
    const Rect16& rect = mRectCache.start_[index];
    if (static_cast<std::int32_t>(rect.xPos) != x || static_cast<std::int32_t>(rect.zPos) != z) {
      return -1;
    }

    return static_cast<std::int16_t>(index);
  }

  /**
   * Address: 0x0080D2F0 (FUN_0080D2F0)
   *
   * IDA signature:
   * void __userpurge sub_80D2F0(Moho::CTesselator *this@<eax>, int i0, int i1, int i2);
   *
   * What it does:
   * Appends three 16-bit collision-triangle indices `{i0, i1, i2}` to the
   * tesselator's `mCollisionRectLut` FastVectorN lane in a single helper.
   * The binary inlines three copies of the `gpg::FastVectorN<u16, 25>::push_back`
   * tail: when `end == capacity`, grow via the shared move-words helper;
   * otherwise store `index` at `end` and advance `end` by two bytes.
   *
   * Placed alongside `EmitCollisionQuad` because both callsites push triangle
   * windings into the same collision index lane; `EmitCollisionQuad` invokes
   * this helper twice to publish its six-index quad winding.
   */
  void CTesselator::AppendCollisionTriangleIndices(
    const std::uint16_t i0,
    const std::uint16_t i1,
    const std::uint16_t i2
  )
  {
    mCollisionRectLut.PushBack(i0);
    mCollisionRectLut.PushBack(i1);
    mCollisionRectLut.PushBack(i2);
  }

  /**
   * Address: 0x0080C120 (FUN_0080C120, Moho::CTesselator::Func9)
   *
   * What it does:
   * Quantizes four corner points into rect-cache entries and emits one
   * two-triangle winding into the collision index lane.
   */
  std::uint16_t* CTesselator::EmitCollisionQuad(
    const Wm3::Vector3f* const corners,
    std::int32_t* const outIndexStart,
    std::uint32_t* const outIndexCount,
    std::int32_t* const outRectStart,
    std::uint32_t* const outLastRectIndex
  )
  {
    static constexpr float kHeightScale = 128.0f;
    std::array<std::uint16_t, 4> cornerIndices{};

    *outRectStart = static_cast<std::int32_t>(mRectCache.Size());
    for (std::size_t i = 0; i < cornerIndices.size(); ++i) {
      const Wm3::Vector3f& corner = corners[i];
      Rect16 rect{};
      rect.xPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.x));
      rect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.y * kHeightScale));
      rect.zPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.z));
      rect.zSize = 1u;
      cornerIndices[i] = AddRect(rect);
    }

    *outIndexStart = static_cast<std::int32_t>(mCollisionRectLut.Size());
    *outIndexCount = 6u;
    *outLastRectIndex = cornerIndices[3];

    // Publish the two-triangle winding `{c2, c1, c0}` + `{c1, c2, c3}` via the
    // shared triple-append helper recovered from 0x0080D2F0.
    AppendCollisionTriangleIndices(cornerIndices[2], cornerIndices[1], cornerIndices[0]);
    AppendCollisionTriangleIndices(cornerIndices[1], cornerIndices[2], cornerIndices[3]);

    return (mCollisionRectLut.end_ != nullptr) ? (mCollisionRectLut.end_ - 1) : nullptr;
  }

  /**
   * Address: 0x0080C850 (FUN_0080C850, Moho::CTesselator::AddRect)
   *
   * What it does:
   * Appends one quantized height rect to the cache vector (bounded to 65000
   * entries) and updates the lookup map index for its `(x,z)` key.
   */
  std::uint16_t CTesselator::AddRect(const Rect16& rect)
  {
    const std::size_t count = mRectCache.Size();
    if (count >= kRectLimit) {
      return static_cast<std::uint16_t>(count - 1u);
    }

    mRectCache.PushBack(rect);
    const std::uint16_t result = static_cast<std::uint16_t>(count);
    mLookup[LookupIndex(rect.xPos, rect.zPos)] = result;
    return result;
  }

  /**
   * Address: 0x0080D230 (FUN_0080D230, Moho::CTesselator::GetIndexAt)
   *
   * What it does:
   * Computes scaled terrain coordinates for one tessellation cell, uses the
   * cache when enabled, and inserts a new rect from clamped heightfield sample
   * when the lookup misses.
   */
  std::uint16_t CTesselator::GetIndexAt(const std::int32_t size, const std::int32_t x, const std::int32_t z)
  {
    const std::int32_t scale = 1 << size;
    const std::int32_t gx = x * scale;
    const std::int32_t gz = z * scale;

    if (ren_ErrorCache) {
      const std::int16_t cached = GetData(gz, gx);
      if (cached != -1) {
        return static_cast<std::uint16_t>(cached);
      }
    }

    const std::int32_t width = mField->width;
    std::int32_t clampedX = width - 1;
    if (gx < clampedX) {
      clampedX = gx;
    }
    if (clampedX < 0) {
      clampedX = 0;
    }

    std::int32_t clampedZ = mField->height - 1;
    if (gz < clampedZ) {
      clampedZ = gz;
    }
    if (clampedZ < 0) {
      clampedZ = 0;
    }

    const std::uint16_t terrainWord = mField->data[clampedX + (clampedZ * width)];
    const float quantizedHeight = static_cast<float>(terrainWord) * 0.0078125f * 128.0f;

    Rect16 rect{};
    rect.xPos = static_cast<std::uint16_t>(gx);
    rect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(quantizedHeight));
    rect.zPos = static_cast<std::uint16_t>(gz);
    rect.zSize = 1u;
    return AddRect(rect);
  }

  /**
   * Address: 0x0080E9E0 (FUN_0080E9E0, Moho::CTesselator::CollectDataInRect)
   *
   * What it does:
   * Descends one adaptive tessellation lane while split criteria are met and
   * appends leaf index ids into `outIndices`.
   */
  std::uint16_t* CTesselator::CollectDataInRect(
    gpg::fastvector<std::uint16_t>* const outIndices,
    const std::int32_t tier,
    std::uint32_t* const activePlaneMask,
    const std::int32_t x,
    const std::int32_t z,
    const std::int32_t w,
    const std::int32_t h,
    const std::int32_t xsize,
    const std::int32_t zsize,
    const std::int32_t xoff,
    const std::int32_t zoff
  )
  {
    const std::uint8_t tierByte = static_cast<std::uint8_t>(tier);
    if (tier > 0 && GetIntersectionResult(x, z, tier, activePlaneMask) == kSplit) {
      std::uint32_t childPlaneMask = *activePlaneMask;
      const std::int32_t doubledXSize = 2 * xsize;
      const std::int32_t doubledZSize = 2 * zsize;

      CollectDataInRect(
        outIndices,
        tier - 1,
        &childPlaneMask,
        w + (2 * x),
        h + (2 * z),
        w,
        h,
        doubledXSize,
        doubledZSize,
        xoff,
        zoff
      );

      childPlaneMask = *activePlaneMask;
      return CollectDataInRect(
        outIndices,
        tier - 1,
        &childPlaneMask,
        w + (2 * x) + xoff,
        h + (2 * z) + zoff,
        w,
        h,
        xoff + doubledXSize,
        zoff + doubledZSize,
        xoff,
        zoff
      );
    }

    const std::uint16_t index = GetIndexAt(static_cast<std::int32_t>(tierByte), xsize + xoff, zoff + zsize);
    outIndices->PushBack(index);
    return outIndices->end_ - 1;
  }
} // namespace moho
