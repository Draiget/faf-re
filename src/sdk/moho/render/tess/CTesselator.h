#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  class IWldTerrainRes;

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
     * Address: 0x0080D2E0 (FUN_0080D2E0, Moho::CTesselator::GetHeightScale)
     *
     * IDA signature:
     * double __thiscall Moho::CTesselator::Func7(CTesselator *this);
     *
     * What it does:
     * Returns the fixed terrain height quantization scale (1/128) bound into the
     * terrain effect's `HeightScale` shader var by the terrain renderers.
     */
    [[nodiscard]] float GetHeightScale() const;

    /**
     * Address: 0x0080BCC0 (FUN_0080BCC0, Moho::CTesselator::GetVec1)
     * Primary vtable slot 2 (vftable @0x00E41BF4).
     *
     * What it does:
     * Hands back the quantized terrain-vertex rect cache. The terrain
     * renderers memcpy it straight into the terrain vertex stream.
     *
     *   mov eax, [ecx+90h] ; retn
     */
    [[nodiscard]] Rect16* GetRectCacheData() const;

    /**
     * Address: 0x0080BCD0 (FUN_0080BCD0, Moho::CTesselator::GetVec2)
     * Primary vtable slot 3 (vftable @0x00E41BF4).
     *
     * What it does:
     * Hands back the triangle-index lane that indexes the rect cache; copied
     * into the terrain index sheet and scanned for the skirt's base vertex.
     *
     *   mov eax, [ecx+7EFE0h] ; retn
     */
    [[nodiscard]] std::uint16_t* GetCollisionIndexData() const;

    /**
     * Address: 0x0080BCE0 (FUN_0080BCE0, Moho::CTesselator::Size1)
     * Primary vtable slot 4 (vftable @0x00E41BF4).
     *
     * What it does:
     * Element count of the rect cache. `Rect16` is 8 bytes, which is the
     * `sar eax, 3` the binary performs on the byte span.
     */
    [[nodiscard]] std::int32_t GetRectCacheCount() const;

    /**
     * Address: 0x0080BCF0 (FUN_0080BCF0, Moho::CTesselator::Size2)
     * Primary vtable slot 5 (vftable @0x00E41BF4).
     *
     * What it does:
     * Element count of the triangle-index lane (`sar eax, 1` - 16-bit
     * elements).
     */
    [[nodiscard]] std::int32_t GetCollisionIndexCount() const;

    /**
     * Address: 0x0080BD00 (FUN_0080BD00, Moho::CTesselator::GetSize2)
     * Primary vtable slot 6 (vftable @0x00E41BF4).
     *
     * What it does:
     * Index at which the terrain skirt's triangle indices start. Note the
     * binary's slot names are crossed over: `GetSize2` answers the *index*
     * mark while `Size2` answers the index *count*.
     */
    [[nodiscard]] std::int32_t GetSkirtIndexStart() const;

    /**
     * Address: 0x0080BD10 (FUN_0080BD10, Moho::CTesselator::GetSize1)
     * Primary vtable slot 7 (vftable @0x00E41BF4).
     *
     * What it does:
     * Rect-cache index at which the terrain skirt's vertices start.
     */
    [[nodiscard]] std::int32_t GetSkirtVertexStart() const;

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
     *
     * `outIndices` is typed as the concrete `FastVectorN<uint16_t, 25>` (not
     * the type-erased `gpg::fastvector<uint16_t>` base) because every real
     * caller (`TesselateLeafCell`'s four edge chains, `TesselateData`'s
     * `edgeIndices`) passes one. `PushBack`/`Reserve` are non-virtual and
     * `FastVectorN` overrides them specifically to avoid freeing its own
     * inline buffer (see FastVector.h) - erasing to the base pointer here
     * silently rebinds every call in this recursion to the base class's
     * unconditional `delete[] start_`, which crashes the instant a chain
     * collects past its 25-slot inline capacity (first reachable once the
     * camera frustum fix let the root tile actually get accepted/split
     * instead of rejected outright).
     */
    std::uint16_t* CollectDataInRect(
      gpg::fastvector_n<std::uint16_t, 25>* outIndices,
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

    /**
     * Address: 0x0080C8D0 (FUN_0080C8D0, Moho::CTesselator::Func1)
     * Primary vtable slot 1 (vftable @0x00E41BF4).
     *
     * What it does:
     * Per-frame tessellation rebuild. Resets every cache lane to empty,
     * derives the view-relative corner-selection mask and the frustum
     * active-plane-clip mask from the camera, refreshes the frustum solid,
     * seeds the rect cache with a water-elevation baseline entry, then walks
     * the heightfield in per-block tiles (`TesselateTile`) and appends a
     * skirt strip along each block's outer edges (`TesselateData`).
     */
    void Rebuild(GeomCamera3* camera, IWldTerrainRes* terrainResource);

    /**
     * Address: 0x0080BD20 (FUN_0080BD20, Moho::CTesselator::Func6)
     * Primary vtable slot 8 (vftable @0x00E41BF4).
     *
     * What it does:
     * Walks the same width/height-ratio tile grid as `Tesselate()`, and for
     * every occupied tile descends `mSplitWorkQueue` to gather every
     * split-work leaf overlapping the query rect
     * `[queryXMin,queryXMax] x [queryZMin,queryZMax]` into
     * `mCollisionRectLut` - either verbatim (cached leaf indices) or clipped
     * against the rect when `ren_ClipDecals` requests it - reporting the
     * touched `mCollisionRectLut` index delta plus the touched `mRectCache`
     * vertex-index range.
     */
    bool CollectClippedCollisionIndicesInRect(
      std::int32_t queryXMin,
      std::int32_t queryZMin,
      std::int32_t queryXMax,
      std::int32_t queryZMax,
      std::int32_t* outBaselineIndexCount,
      std::uint32_t* outAddedIndexCount,
      std::int32_t* outMinRectIndex,
      std::int32_t* outMaxRectIndex
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

    /**
     * Address: 0x0080E200 (FUN_0080E200, sub_80E200)
     *
     * IDA signature:
     * int __thiscall sub_80E200(Moho::CTesselator *this, int x, int z, int teir, unsigned int *a3);
     *
     * What it does:
     * Recursive quadtree tile step. Rejected cells and cells whose intersection
     * test still calls for splitting recurse into four half-size children
     * (or, at the finest split level, emit the child fan directly via
     * `EmitTileSubdivisionFan`); accepted cells and depth-exhausted cells emit
     * their boundary geometry via `TesselateLeafCell`. Every path converges on
     * building one `SplitWorkNode` (collision-index range, its min/max index
     * value, and the four child node indices or -1) and appending it to
     * `mSplitWorkQueue`, returning the new node's index (or -1 when rejected).
     */
    [[nodiscard]] std::int32_t TesselateTile(std::int32_t x, std::int32_t z, std::int32_t tier, std::uint32_t* activePlaneMask);

    /**
     * Shared leaf body for `TesselateTile`'s accept and depth-exhausted paths
     * (binary label `LABEL_14` inside `sub_80E200`, inlined at both entry
     * points rather than split out as its own binary function).
     *
     * What it does:
     * Collects the four cardinal-neighbor boundary index chains (seeding the
     * south/east chains with the west/north chains' last collected index so
     * the four edges join without a crack), then either fans them around one
     * refined center index (when any chain collected more than the trivial
     * two boundary points) or closes the cell with one simple two-triangle
     * quad from the north/south chains alone.
     */
    void TesselateLeafCell(std::int32_t x, std::int32_t z, std::int32_t tier);

    /**
     * Address: 0x0080CF10 (FUN_0080CF10, Moho::CTesselator::TesselateData)
     *
     * What it does:
     * Emits one skirt strip along one edge of a heightfield tile block: seeds
     * a local index chain with the edge's center vertex, collects the edge's
     * boundary indices via `CollectDataInRect`, appends one height-clamped
     * (to `mMinY`) skirt copy of each collected rect via
     * `AppendSkirtSampleRects`, and triangulates the strip between the surface
     * chain and its skirt twin.
     */
    void TesselateData(
      std::int32_t tier,
      std::int32_t x,
      std::int32_t z,
      std::int32_t w,
      std::int32_t h,
      std::int32_t xsize,
      std::int32_t zsize,
      std::int32_t xoff,
      std::int32_t zoff
    );

    CHeightField* mField;               // +0x04
    GeomCamera3* mCam;                  // +0x08
    std::uint32_t mWorkFlags;           // +0x0C
    CGeomSolid3 mGeomSolid;             // +0x10
    std::uint32_t mActivePlaneMask;     // +0x80
    std::uint32_t mCornerSelectionMask; // +0x84
    float mWaterElevation;              // +0x88
    float mMinY;                        // +0x8C
    gpg::core::FastVectorN<Rect16, 65000> mRectCache;             // +0x90
    gpg::core::FastVectorN<std::uint16_t, 25> mCollisionRectLut;  // +0x7EFE0
    std::uint32_t mUnused7F024 = 0u;                              // +0x7F024

    /**
     * Index into `mCollisionRectLut` at which the terrain skirt's indices
     * begin, and the matching `mRectCache` vertex index.
     *
     * Both are snapshots taken by `Tesselate` (0x0080C8D0) once the main
     * terrain surface has been emitted and before the skirt goes in:
     *
     *   0x0080CC8F  call [vtable+0x14]  ; GetCollisionIndexCount()
     *   0x0080CC93  mov  [ebx+7F028h], eax
     *   0x0080CC9E  call [vtable+0x10]  ; GetRectCacheCount()
     *   0x0080CCA0  mov  [ebx+7F02Ch], eax
     *
     * The terrain renderers read them back through GetSkirtIndexStart() /
     * GetSkirtVertexStart() to derive the skirt draw range. They previously
     * sat inside a `pad_7F024_7F02F` blob, which is why the skirt range was
     * never populated.
     */
    std::int32_t mSkirtIndexStart = 0;                            // +0x7F028
    std::int32_t mSkirtVertexStart = 0;                           // +0x7F02C
    gpg::core::FastVectorN<SplitWorkNode, 10000> mSplitWorkQueue; // +0x7F030
    gpg::core::FastVectorN<std::int32_t, 32> mRectIndices;        // +0xCD240

    /**
     * Scratch polygon buffer for the decal/collision clip pipeline
     * (`CollectClippedCollisionIndicesInRect`'s callees): reused every
     * clipped triangle to accumulate the Sutherland-Hodgman clip result
     * before it is fanned back into `mRectCache`/`mCollisionRectLut`.
     *
     * Was previously modelled as `FastVectorN<int32_t, 18>` ("mScratch") -
     * same total byte size (0x48 inline), but the wrong element type. Three
     * independent sites confirm 12-byte (`Vector3f`) elements: the `/12`
     * magic-multiply (`imul 0x2AAAAAABh`) at `FUN_0080D390.asm:0x0080D3B7`
     * sizing a byte-span read from this field's own `start_`/`end_`
     * (`+0xCD2D0`/`+0xCD2D4`); the identical inline-storage check
     * (`start_ == originalVec_`, `+0xC` from field base) in
     * `FUN_0080D940.asm:0x0080DA94`; and the stack-local scratch this field
     * is assigned from in `FUN_0080D530` being copied via
     * `Assign12ByteVectorRange` (`FastVectorInsertLanes.cpp`).
     */
    gpg::core::FastVectorN<Wm3::Vector3f, 6> mClipPolygonScratch; // +0xCD2D0
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
  static_assert(
    offsetof(CTesselator, mClipPolygonScratch) == 0xCD2D0, "CTesselator::mClipPolygonScratch offset must be 0xCD2D0"
  );
  static_assert(offsetof(CTesselator, mLookup) == 0xCD328, "CTesselator::mLookup offset must be 0xCD328");
  static_assert(sizeof(CTesselator) == 0x14D328, "CTesselator size must be 0x14D328");
} // namespace moho
