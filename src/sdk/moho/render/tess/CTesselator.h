#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  class CTesselator
  {
  public:
    struct Rect16
    {
      std::uint16_t xPos;
      std::uint16_t xSize;
      std::uint16_t zPos;
      std::uint16_t zSize;
    };
    static_assert(sizeof(Rect16) == 0x08, "CTesselator::Rect16 size must be 0x08");

    struct SplitWorkNode
    {
      std::int32_t rangeStart;
      std::int32_t rangeCount;
      std::int32_t minValue;
      std::int32_t maxValue;
      std::int32_t childTopLeftIndex;
      std::int32_t childTopRightIndex;
      std::int32_t childBottomLeftIndex;
      std::int32_t childBottomRightIndex;
    };
    static_assert(sizeof(SplitWorkNode) == 0x20, "CTesselator::SplitWorkNode size must be 0x20");

    /**
     * Address: 0x0080BAA0 (??0CTesselator@Moho@@QAE@@Z)
     * Mangled: ??0CTesselator@Moho@@QAE@@Z
     *
     * What it does:
     * Binds the source heightfield and initializes all inline fastvector
     * storage lanes used by terrain tessellation.
     */
    explicit CTesselator(CHeightField* field);

    /**
     * Address: 0x0080BB70 (FUN_0080BB70, ??1CTesselator@Moho@@QAE@@Z)
     * Mangled: ??1CTesselator@Moho@@QAE@@Z
     *
     * What it does:
     * Releases heap-backed storage for all FastVectorN lanes and rebinds them
     * to their inline buffers before unwinding base object state.
     */
    virtual ~CTesselator();

    /**
     * Address: 0x0080E020 (FUN_0080E020, Moho::CTesselator::GetIntersectionResult)
     *
     * int x, int z, int tier, unsigned int* activePlaneMask
     *
     * What it does:
     * Classifies one terrain-tier cell as reject/split/accept for adaptive
     * tesselation by combining frustum intersection and projected error.
     */
    [[nodiscard]] int GetIntersectionResult(int x, int z, int tier, std::uint32_t* activePlaneMask);

    /**
     * Address: 0x0080BEC0 (FUN_0080BEC0, Moho::CTesselator::Tesselate)
     *
     * What it does:
     * Resolves one query rectangle against split-work quadtree lanes and
     * accumulates matching output ranges/min-max lanes.
     */
    [[nodiscard]] bool Tesselate(
      std::int32_t queryX,
      std::int32_t queryZ,
      std::int32_t querySize,
      std::int32_t* outRangeStart,
      std::uint32_t* outRangeCount,
      std::int32_t* outMinValue,
      std::int32_t* outMaxValue
    );

    /**
     * Address: 0x0080BA30 (FUN_0080BA30, Moho::CTesselator::GetData)
     *
     * What it does:
     * Reads one 16-bit cache index from the 512x512 ring map and validates
     * that the pointed rect still belongs to `(x,z)`.
     */
    [[nodiscard]] std::int16_t GetData(std::int32_t z, std::int32_t x) const;

    /**
     * Address: 0x0080C120 (FUN_0080C120, Moho::CTesselator::Func9)
     *
     * What it does:
     * Emits four quantized rect-cache entries from one quad corner array and
     * appends six triangle-index words to the collision index lane.
     */
    std::uint16_t* EmitCollisionQuad(
      const Wm3::Vector3f* corners,
      std::int32_t* outIndexStart,
      std::uint32_t* outIndexCount,
      std::int32_t* outRectStart,
      std::uint32_t* outLastRectIndex
    );

    /**
     * Address: 0x0080D230 (FUN_0080D230, Moho::CTesselator::GetIndexAt)
     *
     * What it does:
     * Returns one rect-cache index for `(x,z)` at `size` scale, inserting a
     * new quantized terrain-height rect when the cache misses.
     */
    [[nodiscard]] std::uint16_t GetIndexAt(std::int32_t size, std::int32_t x, std::int32_t z);

    /**
     * Address: 0x0080E9E0 (FUN_0080E9E0, Moho::CTesselator::CollectDataInRect)
     *
     * What it does:
     * Recursively subdivides one tier cell while frustum/error tests request
     * splitting, and appends the leaf rect indices into `outIndices`.
     */
    std::uint16_t* CollectDataInRect(
      gpg::fastvector<std::uint16_t>* outIndices,
      std::int32_t tier,
      std::uint32_t* activePlaneMask,
      std::int32_t x,
      std::int32_t z,
      std::int32_t w,
      std::int32_t h,
      std::int32_t xsize,
      std::int32_t zsize,
      std::int32_t xoff,
      std::int32_t zoff
    );

  public:
    /**
     * Address: 0x0080C850 (FUN_0080C850, Moho::CTesselator::AddRect)
     *
     * What it does:
     * Appends one rect to the cache vector (bounded to 65000 entries) and
     * updates the 512x512 lookup map with the new index.
     */
    [[nodiscard]] std::uint16_t AddRect(const Rect16& rect);

    /**
     * Address: 0x0080D2F0 (FUN_0080D2F0)
     *
     * What it does:
     * Appends three 16-bit collision-triangle indices to `mCollisionRectLut`
     * in one shared helper; used by `EmitCollisionQuad` to publish the two
     * triangles of a quad winding.
     */
    void AppendCollisionTriangleIndices(std::uint16_t i0, std::uint16_t i1, std::uint16_t i2);

    CHeightField* mField;               // +0x04
    GeomCamera3* mCam;                  // +0x08
    std::uint32_t mWorkFlags;           // +0x0C
    CGeomSolid3 mGeomSolid;             // +0x10
    std::uint32_t mActivePlaneMask;     // +0x80
    std::uint32_t mCornerSelectionMask; // +0x84
    float mWaterElevation;              // +0x88
    std::uint32_t mInitialPlaneMask;    // +0x8C
    gpg::core::FastVectorN<Rect16, 65000> mRectCache;             // +0x90
    gpg::core::FastVectorN<std::uint16_t, 25> mCollisionRectLut;  // +0x7EFE0
    std::uint8_t pad_7F024_7F02F[0x0C];                           // +0x7F024
    gpg::core::FastVectorN<SplitWorkNode, 10000> mSplitWorkQueue; // +0x7F030
    gpg::core::FastVectorN<std::int32_t, 32> mRectIndices;        // +0xCD240
    gpg::core::FastVectorN<std::int32_t, 18> mScratch;            // +0xCD2D0
    std::uint16_t mLookup[0x40000];                               // +0xCD328
  };

  static_assert(offsetof(CTesselator, mRectCache) == 0x90, "CTesselator::mRectCache offset must be 0x90");
  static_assert(
    offsetof(CTesselator, mCollisionRectLut) == 0x7EFE0,
    "CTesselator::mCollisionRectLut offset must be 0x7EFE0"
  );
  static_assert(
    offsetof(CTesselator, mSplitWorkQueue) == 0x7F030,
    "CTesselator::mSplitWorkQueue offset must be 0x7F030"
  );
  static_assert(offsetof(CTesselator, mRectIndices) == 0xCD240, "CTesselator::mRectIndices offset must be 0xCD240");
  static_assert(offsetof(CTesselator, mScratch) == 0xCD2D0, "CTesselator::mScratch offset must be 0xCD2D0");
  static_assert(offsetof(CTesselator, mLookup) == 0xCD328, "CTesselator::mLookup offset must be 0xCD328");
  static_assert(sizeof(CTesselator) == 0x14D328, "CTesselator size must be 0x14D328");
} // namespace moho
