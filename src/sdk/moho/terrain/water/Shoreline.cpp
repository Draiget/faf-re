#include "moho/terrain/water/Shoreline.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/terrain/water/ShoreCell.h"
#include "moho/terrain/water/WaterSurface.h"
#include "platform/Platform.h"

namespace
{
  using ShoreCellRef = boost::shared_ptr<moho::ShoreCell>;

  /**
   * Address: 0x00813DB0 (FUN_00813DB0, boost::shared_ptr_ShoreCell::shared_ptr_ShoreCell)
   *
   * What it does:
   * Constructs one `shared_ptr<ShoreCell>` from one raw shoreline-cell pointer lane.
   */
  ShoreCellRef* ConstructSharedShoreCellFromRaw(ShoreCellRef* const outShoreCell, moho::ShoreCell* const shoreCell)
  {
    return ::new (outShoreCell) ShoreCellRef(shoreCell);
  }

  struct ShoreCorner3
  {
    float x;
    float y;
    float z;
  };

  using ShoreCellMaskBuilder = void (*)(
    moho::ShoreCell& cell,
    float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  );

  constexpr float kPointBias = 0.1f;
  constexpr float kSpatialPadding = 2.0f;
  constexpr float kSpatialWaterPadding = 1.0f;
  constexpr std::int32_t kSpatialRoutingMask = 0x800;
  constexpr float kNoWaterElevation = -10000.0f;
  constexpr float kHeightfieldSampleScale = 0.0078125f;
  constexpr std::uint32_t kShorelineVertexSheetUsageToken = 1U;
  constexpr std::int32_t kShorelineVertexSheetVertexCount = 0x3000;
  constexpr std::int32_t kShorelineVertexFormatToken = 0;

  moho::StatItem* sEngineStatShorelineTotalCellsStage1 = nullptr;
  moho::StatItem* sEngineStatShorelineTotalCellsStage2 = nullptr;

  struct ShorelineSpatialDbRuntimeView
  {
    void* mDebugProxy;             // +0x00
    void** mShardsBegin;           // +0x04
    void** mShardsEnd;             // +0x08
    void** mShardsCapacity;        // +0x0C
    std::uint8_t mShardData[0x60]; // +0x10
    std::int32_t mWidth;           // +0x70
    std::int32_t mHeight;          // +0x74
    std::int32_t mWidthBy16;       // +0x78
    std::int32_t mHeightBy16;      // +0x7C
    std::int32_t mSizeClass;       // +0x80
    std::uint8_t mPad84_87[0x04];  // +0x84
    void* mMapHead;                // +0x88
    std::int32_t mMapSize;         // +0x8C
  };
  static_assert(sizeof(ShorelineSpatialDbRuntimeView) == 0x90, "ShorelineSpatialDbRuntimeView size must be 0x90");

  [[nodiscard]] ShorelineSpatialDbRuntimeView& GetShorelineSpatialDbRuntimeView(moho::Shoreline& shoreline) noexcept
  {
    return *reinterpret_cast<ShorelineSpatialDbRuntimeView*>(&shoreline.mSpatialDbEntry);
  }

  void EnsureShorelineTotalCellsStat(moho::StatItem*& slot)
  {
    if (slot != nullptr) {
      return;
    }

    moho::EngineStats* const stats = moho::GetEngineStats();
    if (stats == nullptr) {
      return;
    }

    slot = stats->GetItem("Shoreline_TotalCells", true);
    if (slot != nullptr) {
      (void)slot->Release(0);
    }
  }

  void StoreStatCounter(moho::StatItem* const slot, const std::int32_t value)
  {
    if (slot == nullptr) {
      return;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&slot->mPrimaryValueBits);
    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, static_cast<long>(value), observed) != observed);
  }

  void InitializeShorelineSpatialDbGrid(moho::Shoreline& shoreline, const std::int32_t width, const std::int32_t height)
  {
    ShorelineSpatialDbRuntimeView& runtime = GetShorelineSpatialDbRuntimeView(shoreline);
    if (runtime.mWidth == width && runtime.mHeight == height) {
      return;
    }

    runtime.mWidth = width;
    runtime.mHeight = height;
    runtime.mWidthBy16 = (width <= 0) ? 0 : ((width + 0x0F) >> 4);
    runtime.mHeightBy16 = (height <= 0) ? 0 : ((height + 0x0F) >> 4);

    const std::int32_t maxExtent = std::max(width, height);
    if (maxExtent <= 0) {
      runtime.mSizeClass = 0;
    } else if (maxExtent <= 0x100) {
      runtime.mSizeClass = 1;
    } else if (maxExtent <= 0x400) {
      runtime.mSizeClass = 2;
    } else {
      runtime.mSizeClass = 3;
    }

    if (runtime.mShardsBegin != nullptr) {
      for (std::int32_t index = 0; index < 16; ++index) {
        runtime.mShardsBegin[index] = nullptr;
      }
      runtime.mShardsEnd = runtime.mShardsBegin;
    }
  }

  [[nodiscard]] float ReadHeightSampleMeters(
    const moho::TerrainHeightFieldRuntimeView* const heightField,
    const std::int32_t sampleX,
    const std::int32_t sampleZ
  )
  {
    if (heightField == nullptr || heightField->data == nullptr || heightField->width <= 0 || heightField->height <= 0) {
      return 0.0f;
    }

    const std::int32_t clampedX = std::clamp(sampleX, 0, heightField->width - 1);
    const std::int32_t clampedZ = std::clamp(sampleZ, 0, heightField->height - 1);
    const std::int32_t sampleIndex = clampedX + (clampedZ * heightField->width);
    return static_cast<float>(heightField->data[sampleIndex]) * kHeightfieldSampleScale;
  }

  [[nodiscard]] moho::ShoreCellPoint2 InterpolateToWater(
    const ShoreCorner3& first,
    const ShoreCorner3& second,
    const float waterElevation
  )
  {
    const float t = (waterElevation - first.y) / (second.y - first.y);
    return {
      first.x + ((second.x - first.x) * t),
      first.z + ((second.z - first.z) * t)
    };
  }

  void UpdateShoreCellCentroid(moho::ShoreCell& cell, const std::int32_t pointCount)
  {
    float sumX = 0.0f;
    float sumZ = 0.0f;
    for (std::int32_t i = 0; i < pointCount; ++i) {
      sumX += cell.mPoints[i].x;
      sumZ += cell.mPoints[i].z;
    }

    const float invCount = 1.0f / static_cast<float>(pointCount);
    cell.mCenterX = sumX * invCount;
    cell.mCenterZ = sumZ * invCount;
  }

  void ResetShoreCell(moho::ShoreCell& cell)
  {
    cell.mType = 0;
    cell.mPad06 = 0;
    cell.mCenterX = 0.0f;
    cell.mCenterZ = 0.0f;

    for (moho::ShoreCellPoint2& point : cell.mPoints) {
      point.x = 0.0f;
      point.z = 0.0f;
    }

    cell.mSpatialDbEntry.db = nullptr;
    cell.mSpatialDbEntry.entry = 0;
    cell.mBounds.Min.x = 0.0f;
    cell.mBounds.Min.y = 0.0f;
    cell.mBounds.Min.z = 0.0f;
    cell.mBounds.Max.x = 0.0f;
    cell.mBounds.Max.y = 0.0f;
    cell.mBounds.Max.z = 0.0f;
  }

  /**
   * Address: 0x00811350 (FUN_00811350, shoreline_func_0)
   *
   * What it does:
   * Reserved shoreline mask lane (no cell geometry emitted).
   */
  void BuildShoreCellMask0(
    moho::ShoreCell&,
    float,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&
  )
  {}

  /**
   * Address: 0x00811360 (FUN_00811360, shoreline_func_1)
   *
   * What it does:
   * Builds one 5-point shoreline polygon for mask type 1.
   */
  void BuildShoreCellMask1(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 3;
    cell.mPoints[0] = {corner01.x, corner01.z + kPointBias};
    cell.mPoints[1] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[2] = {corner11.x + kPointBias, corner11.z + kPointBias};
    cell.mPoints[3] = InterpolateToWater(corner00, corner10, waterElevation);
    cell.mPoints[4] = {corner10.x + kPointBias, corner10.z};
    UpdateShoreCellCentroid(cell, 5);
  }

  /**
   * Address: 0x00811530 (FUN_00811530, shoreline_func_2)
   *
   * What it does:
   * Builds one 5-point shoreline polygon for mask type 2.
   */
  void BuildShoreCellMask2(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 3;
    cell.mPoints[0] = {corner01.x - kPointBias, corner01.z + kPointBias};
    cell.mPoints[1] = {corner00.x - kPointBias, corner00.z};
    cell.mPoints[2] = {corner11.x, corner11.z + kPointBias};
    cell.mPoints[3] = InterpolateToWater(corner00, corner10, waterElevation);
    cell.mPoints[4] = InterpolateToWater(corner10, corner11, waterElevation);
    UpdateShoreCellCentroid(cell, 5);
  }

  /**
   * Address: 0x00811710 (FUN_00811710, shoreline_func_3)
   *
   * What it does:
   * Builds one 4-point shoreline polygon for mask type 3.
   */
  void BuildShoreCellMask3(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 2;
    cell.mPoints[0] = {corner01.x, corner01.z + kPointBias};
    cell.mPoints[1] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[2] = {corner11.x, corner11.z + kPointBias};
    cell.mPoints[3] = InterpolateToWater(corner10, corner11, waterElevation);
    UpdateShoreCellCentroid(cell, 4);
  }

  /**
   * Address: 0x008118A0 (FUN_008118A0, shoreline_func_4)
   *
   * What it does:
   * Builds one 5-point shoreline polygon for mask type 4.
   */
  void BuildShoreCellMask4(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 3;
    cell.mPoints[0] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[1] = {corner00.x, corner00.z - kPointBias};
    cell.mPoints[2] = InterpolateToWater(corner01, corner11, waterElevation);
    cell.mPoints[3] = {corner10.x + kPointBias, corner10.z - kPointBias};
    cell.mPoints[4] = {corner11.x + kPointBias, corner11.z};
    UpdateShoreCellCentroid(cell, 5);
  }

  /**
   * Address: 0x00811A80 (FUN_00811A80, shoreline_func_5)
   *
   * What it does:
   * Builds one 4-point shoreline polygon for mask type 5.
   */
  void BuildShoreCellMask5(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 2;
    cell.mPoints[0] = InterpolateToWater(corner01, corner11, waterElevation);
    cell.mPoints[1] = InterpolateToWater(corner00, corner10, waterElevation);
    cell.mPoints[2] = {corner11.x + kPointBias, corner11.z};
    cell.mPoints[3] = {corner10.x + kPointBias, corner10.z};
    UpdateShoreCellCentroid(cell, 4);
  }

  /**
   * Address: 0x00811C20 (FUN_00811C20, shoreline_func_6)
   *
   * What it does:
   * Reserved shoreline mask lane (no cell geometry emitted).
   */
  void BuildShoreCellMask6(
    moho::ShoreCell&,
    float,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&
  )
  {}

  /**
   * Address: 0x00811C30 (FUN_00811C30, shoreline_func_7)
   *
   * What it does:
   * Builds one 3-point shoreline polygon for mask type 7.
   */
  void BuildShoreCellMask7(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3&,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 1;
    cell.mPoints[0] = InterpolateToWater(corner01, corner11, waterElevation);
    cell.mPoints[1] = InterpolateToWater(corner10, corner11, waterElevation);
    cell.mPoints[2] = {corner11.x + kPointBias, corner11.z + kPointBias};
    UpdateShoreCellCentroid(cell, 3);
  }

  /**
   * Address: 0x00811D90 (FUN_00811D90, shoreline_func_8)
   *
   * What it does:
   * Builds one 5-point shoreline polygon for mask type 8.
   */
  void BuildShoreCellMask8(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 3;
    cell.mPoints[0] = {corner01.x - kPointBias, corner01.z};
    cell.mPoints[1] = {corner00.x - kPointBias, corner00.z - kPointBias};
    cell.mPoints[2] = InterpolateToWater(corner01, corner11, waterElevation);
    cell.mPoints[3] = {corner10.x, corner10.z - kPointBias};
    cell.mPoints[4] = InterpolateToWater(corner10, corner11, waterElevation);
    UpdateShoreCellCentroid(cell, 5);
  }

  /**
   * Address: 0x00811F70 (FUN_00811F70, shoreline_func_9)
   *
   * What it does:
   * Reserved shoreline mask lane (no cell geometry emitted).
   */
  void BuildShoreCellMask9(
    moho::ShoreCell&,
    float,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&
  )
  {}

  /**
   * Address: 0x00811F80 (FUN_00811F80, shoreline_func_10)
   *
   * What it does:
   * Builds one 4-point shoreline polygon for mask type 10.
   */
  void BuildShoreCellMask10(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 2;
    cell.mPoints[0] = {corner01.x - kPointBias, corner01.z};
    cell.mPoints[1] = {corner00.x - kPointBias, corner00.z};
    cell.mPoints[2] = InterpolateToWater(corner01, corner11, waterElevation);
    cell.mPoints[3] = InterpolateToWater(corner00, corner10, waterElevation);
    UpdateShoreCellCentroid(cell, 4);
  }

  /**
   * Address: 0x00812120 (FUN_00812120, shoreline_func_11)
   *
   * What it does:
   * Builds one 3-point shoreline polygon for mask type 11.
   */
  void BuildShoreCellMask11(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3&,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 1;
    cell.mPoints[0] = {corner01.x - kPointBias, corner01.z + kPointBias};
    cell.mPoints[1] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[2] = InterpolateToWater(corner01, corner11, waterElevation);
    UpdateShoreCellCentroid(cell, 3);
  }

  /**
   * Address: 0x00812280 (FUN_00812280, shoreline_func_12)
   *
   * What it does:
   * Builds one 4-point shoreline polygon for mask type 12.
   */
  void BuildShoreCellMask12(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 2;
    cell.mPoints[0] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[1] = {corner00.x, corner00.z - kPointBias};
    cell.mPoints[2] = InterpolateToWater(corner10, corner11, waterElevation);
    cell.mPoints[3] = {corner10.x, corner10.z - kPointBias};
    UpdateShoreCellCentroid(cell, 4);
  }

  /**
   * Address: 0x00812410 (FUN_00812410, shoreline_func_13)
   *
   * What it does:
   * Builds one 3-point shoreline polygon for mask type 13.
   */
  void BuildShoreCellMask13(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3&,
    const ShoreCorner3& corner11
  )
  {
    cell.mType = 1;
    cell.mPoints[0] = InterpolateToWater(corner00, corner10, waterElevation);
    cell.mPoints[1] = {corner10.x + kPointBias, corner10.z - kPointBias};
    cell.mPoints[2] = InterpolateToWater(corner10, corner11, waterElevation);
    UpdateShoreCellCentroid(cell, 3);
  }

  /**
   * Address: 0x00812570 (FUN_00812570, shoreline_func_14)
   *
   * What it does:
   * Builds one 3-point shoreline polygon for mask type 14.
   */
  void BuildShoreCellMask14(
    moho::ShoreCell& cell,
    const float waterElevation,
    const ShoreCorner3& corner00,
    const ShoreCorner3& corner10,
    const ShoreCorner3& corner01,
    const ShoreCorner3&
  )
  {
    cell.mType = 1;
    cell.mPoints[0] = InterpolateToWater(corner00, corner01, waterElevation);
    cell.mPoints[1] = {corner00.x - kPointBias, corner00.z - kPointBias};
    cell.mPoints[2] = InterpolateToWater(corner00, corner10, waterElevation);
    UpdateShoreCellCentroid(cell, 3);
  }

  /**
   * Address: 0x008126D0 (FUN_008126D0, shoreline_func_15)
   *
   * What it does:
   * Reserved shoreline mask lane (no cell geometry emitted).
   */
  void BuildShoreCellMask15(
    moho::ShoreCell&,
    float,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&,
    const ShoreCorner3&
  )
  {}

  constexpr std::array<ShoreCellMaskBuilder, 16> kShoreCellMaskBuilders = {
    &BuildShoreCellMask0,
    &BuildShoreCellMask1,
    &BuildShoreCellMask2,
    &BuildShoreCellMask3,
    &BuildShoreCellMask4,
    &BuildShoreCellMask5,
    &BuildShoreCellMask6,
    &BuildShoreCellMask7,
    &BuildShoreCellMask8,
    &BuildShoreCellMask9,
    &BuildShoreCellMask10,
    &BuildShoreCellMask11,
    &BuildShoreCellMask12,
    &BuildShoreCellMask13,
    &BuildShoreCellMask14,
    &BuildShoreCellMask15,
  };

  /**
   * Address: 0x00812790 (FUN_00812790, sub_812790)
   *
   * What it does:
   * Registers one generated shoreline cell in shoreline spatial-db lanes and
   * updates its spatial bounds from centroid + water elevation.
   */
  void InitializeShoreCellSpatialEntry(
    moho::ShoreCell& cell,
    moho::SpatialDB_MeshInstance& shorelineSpatialDb,
    moho::TerrainWaterResourceView* const terrainResource
  )
  {
    cell.mSpatialDbEntry.Register(&shorelineSpatialDb, &cell, kSpatialRoutingMask);
    cell.mSpatialDbEntry.UpdateDissolveCutoff(moho::ren_ShorelineCutoff);

    const moho::TerrainMapRuntimeView* const map = terrainResource != nullptr ? terrainResource->mMap : nullptr;
    const float waterElevation = (map != nullptr && map->mWaterEnabled != 0u) ? map->mWaterElevation : kNoWaterElevation;

    cell.mBounds.Min.x = cell.mCenterX - kSpatialPadding;
    cell.mBounds.Min.y = waterElevation - kSpatialWaterPadding;
    cell.mBounds.Min.z = cell.mCenterZ - kSpatialPadding;
    cell.mBounds.Max.x = cell.mCenterX + kSpatialPadding;
    cell.mBounds.Max.y = waterElevation + kSpatialWaterPadding;
    cell.mBounds.Max.z = cell.mCenterZ + kSpatialPadding;
    cell.mSpatialDbEntry.UpdateBounds(cell.mBounds);
  }

  /**
   * Address: 0x008135A0 (FUN_008135A0, sub_8135A0)
   *
   * What it does:
   * Appends one shoreline-cell shared pointer at vector tail, using the
   * in-place lane when capacity is available and growing storage otherwise.
   */
  void AppendShoreCellRef(msvc8::vector<ShoreCellRef>& shorelineCells, const ShoreCellRef& cell)
  {
    shorelineCells.push_back(cell);
  }

  /**
   * Address: 0x00813300 (FUN_00813300, func_CreateShoreCell)
   *
   * What it does:
   * Builds one shoreline cell for the mask type, registers it in spatial-db,
   * and appends it to shoreline cell storage.
   */
  void CreateShoreCellFromMask(
    moho::Shoreline& shoreline,
    moho::TerrainWaterResourceView* const terrainResource,
    const std::int32_t maskType,
    const float baseX,
    const float baseZ,
    const float waterElevation,
    const float height00,
    const float height10,
    const float height01,
    const float height11
  )
  {
    const ShoreCorner3 corner00{baseX, height00, baseZ};
    const ShoreCorner3 corner10{baseX + 2.0f, height10, baseZ};
    const ShoreCorner3 corner01{baseX, height01, baseZ + 2.0f};
    const ShoreCorner3 corner11{baseX + 2.0f, height11, baseZ + 2.0f};

    ShoreCellRef cell(new moho::ShoreCell());
    if (!cell) {
      return;
    }

    ResetShoreCell(*cell);
    if (maskType >= 0 && maskType < static_cast<std::int32_t>(kShoreCellMaskBuilders.size())) {
      kShoreCellMaskBuilders[static_cast<std::size_t>(maskType)](
        *cell,
        waterElevation,
        corner00,
        corner10,
        corner01,
        corner11
      );
    }

    InitializeShoreCellSpatialEntry(*cell, shoreline.mSpatialDbEntry, terrainResource);
    AppendShoreCellRef(shoreline.mCells, cell);
  }

  /**
   * Address: 0x00814040 (FUN_00814040, sub_814040)
   *
   * What it does:
   * Assign-copies one half-open shoreline-cell shared-pointer range into
   * destination storage and returns the new destination end.
   */
  [[nodiscard]] ShoreCellRef* CopyShoreCellRefRange(
    ShoreCellRef* const destination,
    ShoreCellRef* sourceBegin,
    ShoreCellRef* const sourceEnd
  )
  {
    ShoreCellRef* write = destination;
    while (sourceBegin != sourceEnd) {
      *write = *sourceBegin;
      ++sourceBegin;
      ++write;
    }
    return write;
  }

  /**
   * Address: 0x00813DD0 (FUN_00813DD0)
   *
   * What it does:
   * Argument-order adapter that forwards one shoreline-cell shared-pointer
   * range copy into `CopyShoreCellRefRange`.
   */
  [[maybe_unused]] ShoreCellRef* CopyShoreCellRefRangeArgumentOrderAdapter(
    ShoreCellRef* sourceBegin,
    ShoreCellRef* const sourceEnd,
    ShoreCellRef* const destination
  )
  {
    return CopyShoreCellRefRange(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x008140F0 (FUN_008140F0, sub_8140F0)
   *
   * What it does:
   * Releases one half-open shoreline-cell shared-pointer range by resetting each
   * shared owner lane.
   */
  void ReleaseShoreCellRefRange(ShoreCellRef* rangeBegin, ShoreCellRef* const rangeEnd)
  {
    while (rangeBegin != rangeEnd) {
      rangeBegin->reset();
      ++rangeBegin;
    }
  }

  /**
   * Address: 0x00813750 (FUN_00813750, sub_813750)
   *
   * What it does:
   * Erases one half-open shoreline-cell range from the runtime vector by moving
   * tail lanes over the erased range and releasing the trailing stale lanes.
   */
  [[nodiscard]] ShoreCellRef* EraseShoreCellRefRange(
    msvc8::vector<ShoreCellRef>& shorelineCells,
    ShoreCellRef* const eraseBegin,
    ShoreCellRef* const eraseEnd
  )
  {
    if (eraseBegin == eraseEnd) {
      return eraseBegin;
    }

    auto& cellView = msvc8::AsVectorRuntimeView(shorelineCells);
    ShoreCellRef* const previousEnd = cellView.end;
    ShoreCellRef* const newEnd = CopyShoreCellRefRange(eraseBegin, eraseEnd, previousEnd);
    ReleaseShoreCellRefRange(newEnd, previousEnd);
    cellView.end = newEnd;
    return eraseBegin;
  }
} // namespace

namespace moho
{
  bool ren_Shoreline = false;
  float ren_ShorelineCutoff = 0.0f;

  /**
   * Address: 0x008126E0 (FUN_008126E0, ??0ShoreCell@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes one shoreline-cell object by setting `mType` to zero,
   * clearing the embedded spatial-db entry lanes, and zeroing all five
   * shoreline point pairs.
   */
  ShoreCell::ShoreCell()
  {
    mType = 0;

    mSpatialDbEntry.db = nullptr;
    mSpatialDbEntry.entry = 0;

    for (ShoreCellPoint2& point : mPoints) {
      point.x = 0.0f;
      point.z = 0.0f;
    }
  }

  /**
   * Address: 0x00812760 (FUN_00812760)
   *
   * What it does:
   * Runs one null-guard adapter lane that only destroys one
   * `SpatialDB_MeshInstance` when its `db` lane is non-null.
   */
  [[maybe_unused]] SpatialDB_MeshInstance* DestroySpatialDbMeshInstanceIfBoundAdapter(
    SpatialDB_MeshInstance* const entry
  )
  {
    if (entry->db != nullptr) {
      entry->~SpatialDB_MeshInstance();
    }

    return entry;
  }

  /**
   * Address: 0x00812770 (FUN_00812770, sub_812770)
   *
   * What it does:
   * Runs one shoreline-cell teardown lane; the embedded `SpatialDB_MeshInstance`
   * member handles conditional unbind/release during default destruction.
   */
  ShoreCell::~ShoreCell() = default;

  /**
   * Address: 0x00812840 (FUN_00812840, Moho::Shoreline::Shoreline)
   *
   * What it does:
   * Initializes shoreline runtime lanes, including spatial-db entry wrapper,
   * shoreline-cell vector storage, vertex-sheet shared owner, and triangle count.
   */
  Shoreline::Shoreline()
    : mSpatialDbEntry()
    , mUnknown0C_93{}
    , mCells()
    , mVertexSheet()
    , mShorelineTris(0)
  {}

  /**
   * Address: 0x00812E00 (FUN_00812E00, Moho::Shoreline::Destroy)
   *
   * What it does:
   * Releases vertex-sheet ownership, erases shoreline-cell shared-pointer lanes,
   * and clears shoreline triangle-count state.
   */
  void Shoreline::Destroy()
  {
    mVertexSheet.reset();

    auto& cellView = msvc8::AsVectorRuntimeView(mCells);
    (void)EraseShoreCellRefRange(mCells, cellView.begin, cellView.end);

    mShorelineTris = 0;
  }

  /**
   * Address: 0x008129B0 (FUN_008129B0, Moho::Shoreline::Generate)
   *
   * What it does:
   * Rebuilds shoreline cells from terrain-water heightfield masks, recreates
   * shoreline vertex-sheet ownership, and updates shoreline-cell stats.
   */
  void Shoreline::Generate(TerrainWaterResourceView* const terrainResource)
  {
    Destroy();

    EnsureShorelineTotalCellsStat(sEngineStatShorelineTotalCellsStage1);
    StoreStatCounter(sEngineStatShorelineTotalCellsStage1, 0);

    TerrainMapRuntimeView* const map = (terrainResource != nullptr) ? terrainResource->mMap : nullptr;
    if (map == nullptr || map->mWaterEnabled == 0u) {
      return;
    }

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kShorelineVertexFormatToken);
    CD3DVertexSheet* const vertexSheet =
      resources->NewVertexSheet(kShorelineVertexSheetUsageToken, kShorelineVertexSheetVertexCount, vertexFormat);
    mVertexSheet = boost::shared_ptr<ID3DVertexSheet>(static_cast<ID3DVertexSheet*>(vertexSheet));

    const float waterElevation = (map->mWaterEnabled != 0u) ? map->mWaterElevation : kNoWaterElevation;
    TerrainHeightFieldRuntimeView* const heightField = map->mHeightFieldObject;
    if (heightField != nullptr) {
      const std::int32_t width = heightField->width - 1;
      const std::int32_t height = heightField->height - 1;
      InitializeShorelineSpatialDbGrid(*this, width, height);

      for (std::int32_t x = 0; x < width; x += 2) {
        for (std::int32_t z = 0; z < height; z += 2) {
          const float height00 = ReadHeightSampleMeters(heightField, x, z);
          const float height10 = ReadHeightSampleMeters(heightField, x + 2, z);
          const float height01 = ReadHeightSampleMeters(heightField, x, z + 2);
          const float height11 = ReadHeightSampleMeters(heightField, x + 2, z + 2);

          std::int32_t maskType = 0;
          if (height00 >= waterElevation) {
            maskType |= 1;
          }
          if (height10 >= waterElevation) {
            maskType |= 2;
          }
          if (height01 >= waterElevation) {
            maskType |= 4;
          }
          if (height11 >= waterElevation) {
            maskType |= 8;
          }

          if (maskType != 0 && maskType != 6 && maskType != 9 && maskType != 15) {
            CreateShoreCellFromMask(
              *this,
              terrainResource,
              maskType,
              static_cast<float>(x),
              static_cast<float>(z),
              waterElevation,
              height00,
              height10,
              height01,
              height11
            );
          }
        }
      }
    }

    EnsureShorelineTotalCellsStat(sEngineStatShorelineTotalCellsStage2);
    StoreStatCounter(sEngineStatShorelineTotalCellsStage2, static_cast<std::int32_t>(mCells.size()));
    ren_Shoreline = true;
  }

  /**
   * Address: 0x008128D0 (FUN_008128D0, Moho::Shoreline::~Shoreline)
   *
   * What it does:
   * Destroys shoreline runtime state by calling `Destroy`, releasing shoreline
   * cell storage, and tearing down the spatial-db entry wrapper subobject.
   */
  Shoreline::~Shoreline()
  {
    Destroy();
  }

  /**
   * Address: 0x008128B0 (FUN_008128B0, Moho::Shoreline::dtr)
   *
   * What it does:
   * Runs the non-deleting destructor and conditionally frees `this` when the
   * low delete-flag bit is set.
   */
  Shoreline* Shoreline::DeleteWithFlag(const std::uint8_t deleteFlags)
  {
    this->~Shoreline();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }
} // namespace moho
