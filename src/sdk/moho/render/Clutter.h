#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3AxisAlignedBox3.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class CHeightField;
  class MeshRenderer;
  struct GeomCamera3;
  struct RMeshBlueprint;

  struct ClutterRegion;
  struct ClutterRegionKey;
  struct ClutterRegionKeyNode;
  struct ClutterListNode;
  struct ClutterRegionListNode;

  struct ClutterPayloadVTable
  {
    void(__thiscall* destroy)(void* self, int deleteFlag);
  };
  static_assert(sizeof(ClutterPayloadVTable) == 0x4, "ClutterPayloadVTable size must be 0x4");

  struct ClutterPayloadHeader
  {
    ClutterPayloadVTable* vtable; // +0x00
  };
  static_assert(sizeof(ClutterPayloadHeader) == 0x4, "ClutterPayloadHeader size must be 0x4");

  struct ClutterSurfaceElementVTable
  {
    void(__thiscall* destroy)(void* self, int deleteFlag);
  };
  static_assert(sizeof(ClutterSurfaceElementVTable) == 0x4, "ClutterSurfaceElementVTable size must be 0x4");

  struct ClutterSurfaceElement
  {
    ClutterSurfaceElementVTable* vtable; // +0x00
    float selectionWeight; // +0x04
    float uniformScale; // +0x08
    RMeshBlueprint* meshBlueprint; // +0x0C

    /**
     * Address: 0x007D7E00 (FUN_007D7E00, inlined into the tail-destroy loop
     * of `msvc8::vector<ClutterSurfaceElement>::erase(first,last)` --
     * `legacy/containers/Vector.h`)
     * Address: 0x007D7EB0 (FUN_007D7EB0, ??1Surface@Clutter@Moho@@QAE@@Z,
     * inlined into `Surface::~Surface`'s own `mSeeds` teardown sweep, below)
     * Address: 0x007D7920 (unnamed 22-byte register-convention fragment --
     * see the `erase(first,last)` citation in `Vector.h` for detail)
     *
     * What it does:
     * Dispatches through the element's own "poisoned" vtable slot 0 with a
     * delete-flag of 0 (`vtable->destroy(this, 0)`). No source line calls
     * this by name at any of the addresses above -- each is the compiler
     * inlining this one-statement method (and the destructor that forwards
     * to it, below) at its own call site. Reduces to a runtime no-op: every
     * live element's `vtable` is set exactly once, via
     * `ResetClutterSeedVtable`, to `SeedVtableResetToken()`, and
     * `SeedVtableResetTag`'s destructor is defaulted with the delete flag
     * skipping `operator delete` -- but the call itself is real and is part
     * of the type's actual destructor, so it must happen for binary-exact
     * fidelity.
     */
    void DestroyInPlace();

    /**
     * The real destructor's body is exactly `DestroyInPlace()` above -- MSVC
     * inlines a one-statement destructor at each call site rather than
     * emitting a standalone symbol, so there is no separate address to cite
     * here beyond the ones already on `DestroyInPlace()`. Declaring this as
     * a real (non-trivial) destructor, instead of leaving the type
     * implicitly trivial, is what makes `msvc8::vector<ClutterSurfaceElement>`'s
     * existing, unmodified `destroy_range`/`erase`/`clear`/`tidy` machinery
     * (`Vector.h`) emit the per-element call `FUN_007D7E00` and
     * `FUN_007D7EB0` both show -- previously the struct was (wrongly)
     * trivially destructible and that machinery's
     * `if constexpr (!is_trivially_destructible_v<T>)` guard silently
     * skipped the call.
     */
    ~ClutterSurfaceElement();

    /**
     * Address: 0x007D94B0 (FUN_007D94B0, inlined into the tail-shift step of
     * `msvc8::vector<ClutterSurfaceElement>::erase(first,last)` --
     * `legacy/containers/Vector.h`)
     *
     * What it does:
     * Copies the three payload fields (`selectionWeight`, `uniformScale`,
     * `meshBlueprint`) from `rhs` and deliberately leaves `vtable`
     * untouched. Every live element's `vtable` already holds the same
     * `SeedVtableResetToken()` value (`ResetClutterSeedVtable` sets it once;
     * it never changes for the life of the slot), so the original source
     * skips re-copying it on every shift-assign during an erase. Declaring
     * this explicitly (instead of leaving the implicit memberwise copy) is
     * what makes `erase(first,last)`'s per-element
     * `first[i] = std::move(last[i])` shift loop produce this exact 3-field
     * copy instead of copying all four fields -- a user-declared destructor
     * alone already routes `erase` into that loop (it makes the type
     * non-trivially-copyable), but without this operator the loop would
     * fall back to the implicit, all-4-field copy-assignment.
     */
    ClutterSurfaceElement& operator=(const ClutterSurfaceElement& rhs);
  };
  static_assert(sizeof(ClutterSurfaceElement) == 0x10, "ClutterSurfaceElement size must be 0x10");
  static_assert(
    offsetof(ClutterSurfaceElement, selectionWeight) == 0x04,
    "ClutterSurfaceElement::selectionWeight offset must be 0x04"
  );
  static_assert(
    offsetof(ClutterSurfaceElement, uniformScale) == 0x08,
    "ClutterSurfaceElement::uniformScale offset must be 0x08"
  );
  static_assert(
    offsetof(ClutterSurfaceElement, meshBlueprint) == 0x0C,
    "ClutterSurfaceElement::meshBlueprint offset must be 0x0C"
  );

  /**
   * `Moho::Clutter::Surface`. The trailing seed storage (`myProxy_`/
   * `first_`/`last_`/`end_` inside `mSeeds`, entry offsets +0x08/+0x0C/
   * +0x10/+0x14) is byte-identical to `msvc8::vector<ClutterSurfaceElement>`
   * -- confirmed via `Clutter::Clutter`'s real body (`FUN_007D60D0`), which
   * constructs the 256-entry `mSurfaces` array through the compiler-emitted
   * `` `eh vector constructor iterator' `` helper calling `Surface::Surface`
   * (`FUN_007D5CF0`), and `Clutter::~Clutter` (`FUN_007D61E0`), which tears
   * it down through `` `eh vector destructor iterator' `` calling
   * `Surface::~Surface` (`FUN_007D5D10`) -- i.e. `Surface` genuinely has a
   * non-trivial ctor/dtor pair in the original binary, previously modeled
   * here as free functions (`InitializeSurfaceEntry`/
   * `DestroySurfaceEntryWrapper`) called from a hand-written loop instead of
   * real constructor/destructor members.
   */
  struct ClutterSurfaceEntry
  {
    /**
     * Address: 0x007D5CF0 (FUN_007D5CF0, ??0Surface@Clutter@Moho@@QAE@@Z)
     *
     * What it does:
     * Resets the vtable to the poison/reset token and zeroes `density`;
     * `mSeeds` default-constructs itself (empty, no allocation).
     */
    ClutterSurfaceEntry();

    /**
     * Address: 0x007D5D10 (FUN_007D5D10)
     *
     * What it does:
     * Resets the vtable to the poison/reset token; `mSeeds` destroys its
     * live elements and releases its buffer through its own destructor.
     */
    ~ClutterSurfaceEntry();

    void* vtable; // +0x00
    std::int32_t density; // +0x04
    msvc8::vector<ClutterSurfaceElement> mSeeds; // +0x08 (16 bytes: myProxy_/first_/last_/end_)
  };
  static_assert(sizeof(ClutterSurfaceEntry) == 0x18, "ClutterSurfaceEntry size must be 0x18");
  static_assert(offsetof(ClutterSurfaceEntry, density) == 0x04, "ClutterSurfaceEntry::density offset must be 0x04");
  static_assert(
    offsetof(ClutterSurfaceEntry, mSeeds) == 0x08,
    "ClutterSurfaceEntry::mSeeds offset must be 0x08"
  );

  struct ClutterListNode
  {
    ClutterListNode* next; // +0x00
    ClutterListNode* prev; // +0x04
    void* payload; // +0x08
  };
  static_assert(sizeof(ClutterListNode) == 0x0C, "ClutterListNode size must be 0x0C");

  struct ClutterIntrusiveListState
  {
    void* lane00; // +0x00
    ClutterListNode* head; // +0x04
    std::uint32_t size; // +0x08
  };
  static_assert(sizeof(ClutterIntrusiveListState) == 0x0C, "ClutterIntrusiveListState size must be 0x0C");
  static_assert(
    offsetof(ClutterIntrusiveListState, head) == 0x04,
    "ClutterIntrusiveListState::head offset must be 0x04"
  );

  struct ClutterRegionListNode
  {
    ClutterRegionListNode* next; // +0x00
    ClutterRegionListNode* prev; // +0x04
    ClutterRegion* value; // +0x08
  };
  static_assert(sizeof(ClutterRegionListNode) == 0x0C, "ClutterRegionListNode size must be 0x0C");

  struct ClutterRegionListState
  {
    void* lane00; // +0x00
    ClutterRegionListNode* head; // +0x04
    std::uint32_t size; // +0x08
  };
  static_assert(sizeof(ClutterRegionListState) == 0x0C, "ClutterRegionListState size must be 0x0C");
  static_assert(
    offsetof(ClutterRegionListState, head) == 0x04, "ClutterRegionListState::head offset must be 0x04"
  );

  struct ClutterRegionKey
  {
    void* vtable; // +0x00
    std::int32_t mX; // +0x04
    std::int32_t mZ; // +0x08
  };
  static_assert(sizeof(ClutterRegionKey) == 0x0C, "ClutterRegionKey size must be 0x0C");
  static_assert(offsetof(ClutterRegionKey, mX) == 0x04, "ClutterRegionKey::mX offset must be 0x04");
  static_assert(offsetof(ClutterRegionKey, mZ) == 0x08, "ClutterRegionKey::mZ offset must be 0x08");

  struct ClutterRegionKeyNode
  {
    ClutterRegionKeyNode* left; // +0x00
    ClutterRegionKeyNode* parent; // +0x04
    ClutterRegionKeyNode* right; // +0x08
    ClutterRegionKey key; // +0x0C
    std::uint8_t color; // +0x18 (red-black lane)
    std::uint8_t isNil; // +0x19
    std::uint8_t reserved1A[0x2]; // +0x1A
  };
  static_assert(sizeof(ClutterRegionKeyNode) == 0x1C, "ClutterRegionKeyNode size must be 0x1C");
  static_assert(offsetof(ClutterRegionKeyNode, key) == 0x0C, "ClutterRegionKeyNode::key offset must be 0x0C");
  static_assert(offsetof(ClutterRegionKeyNode, color) == 0x18, "ClutterRegionKeyNode::color offset must be 0x18");
  static_assert(offsetof(ClutterRegionKeyNode, isNil) == 0x19, "ClutterRegionKeyNode::isNil offset must be 0x19");

  struct ClutterRegionKeyTreeState
  {
    std::uint32_t comparatorCookie; // +0x00
    ClutterRegionKeyNode* head; // +0x04
    std::uint32_t size; // +0x08
  };
  static_assert(sizeof(ClutterRegionKeyTreeState) == 0x0C, "ClutterRegionKeyTreeState size must be 0x0C");

  struct ClutterRegionMapPayloadVTable
  {
    void(__thiscall* destroy)(void* self, int deleteFlag);
  };
  static_assert(
    sizeof(ClutterRegionMapPayloadVTable) == 0x4, "ClutterRegionMapPayloadVTable size must be 0x4"
  );

  struct ClutterRegionMapPayloadHeader
  {
    ClutterRegionMapPayloadVTable* vtable; // +0x00
  };
  static_assert(
    sizeof(ClutterRegionMapPayloadHeader) == 0x4, "ClutterRegionMapPayloadHeader size must be 0x4"
  );

  struct ClutterRegionMapState
  {
    void* lane00; // +0x00
    ClutterListNode* head; // +0x04
    std::uint32_t size; // +0x08
  };
  static_assert(sizeof(ClutterRegionMapState) == 0x0C, "ClutterRegionMapState size must be 0x0C");

  struct ClutterRegion
  {
    void* vtable; // +0x00
    ClutterRegion* mNext; // +0x04
    ClutterRegion* mPrev; // +0x08
    std::int32_t mX; // +0x0C
    std::int32_t mZ; // +0x10
    Wm3::AxisAlignedBox3f mBox; // +0x14
    ClutterRegionMapState mMap; // +0x2C

    /**
     * Address: 0x007D5EE0 (FUN_007D5EE0, ??0Region@Clutter@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes region links and key coordinates, then allocates one empty
     * region-map list sentinel.
     */
    ClutterRegion();

    /**
     * Address: 0x007D5F20 (FUN_007D5F20, ??1Region@Clutter@Moho@@QAE@@Z)
     *
     * What it does:
     * Resets region runtime payload lanes, clears map-node list storage, then
     * releases the map sentinel allocation.
     */
    ~ClutterRegion();
  };
  static_assert(sizeof(ClutterRegion) == 0x38, "ClutterRegion size must be 0x38");
  static_assert(offsetof(ClutterRegion, mNext) == 0x04, "ClutterRegion::mNext offset must be 0x04");
  static_assert(offsetof(ClutterRegion, mPrev) == 0x08, "ClutterRegion::mPrev offset must be 0x08");
  static_assert(offsetof(ClutterRegion, mX) == 0x0C, "ClutterRegion::mX offset must be 0x0C");
  static_assert(offsetof(ClutterRegion, mZ) == 0x10, "ClutterRegion::mZ offset must be 0x10");
  static_assert(offsetof(ClutterRegion, mBox) == 0x14, "ClutterRegion::mBox offset must be 0x14");
  static_assert(offsetof(ClutterRegion, mMap) == 0x2C, "ClutterRegion::mMap offset must be 0x2C");

  class Clutter
  {
  public:
    /**
     * Address: 0x007D60D0 (FUN_007D60D0, ??0Clutter@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes list sentinels, surface entries, key-tree head sentinel, and
     * zeroes runtime lanes.
     */
    Clutter();

    /**
     * Address: 0x007D61E0 (FUN_007D61E0, ??1Clutter@Moho@@UAE@XZ)
     *
     * What it does:
     * Runs shutdown, releases key-tree head/surface lanes, and frees both list
     * sentinel allocations.
     */
    ~Clutter();

    /**
     * Address: 0x007D62B0 (FUN_007D62B0, ?Initialize@Clutter@Moho@@QAEXXZ)
     *
     * What it does:
     * Thunk lane that reuses `Shutdown()` to reset region/surface state.
     */
    void Initialize();

    /**
     * Address: 0x007D6380 (FUN_007D6380, ?Update@Clutter@Moho@@QAEXPBVGeomCamera3@2@@Z)
     *
     * What it does:
     * Runs one clutter update tick by culling stale regions, then generating
     * new visible region clutter around the active camera.
     */
    void Update(const GeomCamera3* camera);

    /**
     * Address: 0x007D62C0 (FUN_007D62C0, ?Shutdown@Clutter@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears active regions, resets per-surface runtime lanes, and releases
     * both intrusive list caches.
     */
    void Shutdown();

    /**
     * Address: 0x007D63A0 (FUN_007D63A0, ?Clear@Clutter@Moho@@QAEXXZ)
     *
     * What it does:
     * Destroys the current-region chain and resets region-key tree state.
     */
    void Clear();

  public:
    /**
     * Address: 0x007D7080 (FUN_007D7080, ?DestroyRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
     *
     * What it does:
     * Removes one region from active/key lanes, resets region runtime map state,
     * and appends the region to the recycle list lane.
     */
    void DestroyRegion(ClutterRegion* region);

  private:
    /**
     * Address: 0x007D6E10 (FUN_007D6E10, ?UnlinkRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
     *
     * What it does:
     * Detaches one region node from the active doubly-linked chain and updates
     * `mCurRegion` when it points at the removed node.
     */
    void UnlinkRegion(ClutterRegion* region);

    /**
     * Address: 0x007D6410 (FUN_007D6410, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@ABV?$AxisAlignedBox3@M@Wm3@@@Z)
     *
     * What it does:
     * Returns whether one region AABB is both within clutter radius distance
     * from the camera and intersecting the camera frustum-solid lane.
     */
    bool IsVisible(const GeomCamera3* camera, const Wm3::AxisAlignedBox3f& regionBox);

    /**
     * Address: 0x007D64C0 (FUN_007D64C0, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@PBVRegion@12@@Z)
     *
     * What it does:
     * Returns visibility state for one clutter region by delegating to AABB
     * visibility test using the region's box lane.
     */
    bool IsVisible(const GeomCamera3* camera, const ClutterRegion* region);

    /**
     * Address: 0x007D6510 (FUN_007D6510, ?UpdateCurrent@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
     *
     * What it does:
     * Culls active clutter regions that move beyond the configured clutter radius
     * or outside the current camera frustum-solid lane.
     */
    void UpdateCurrent(const GeomCamera3* camera);

    /**
     * Address: 0x007D6640 (FUN_007D6640, ?GenerateNew@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
     *
     * What it does:
     * Scans the camera neighborhood in 2x2 terrain tiles, creates new visible
     * clutter regions, and populates each region from four terrain-type corners.
     */
    void GenerateNew(const GeomCamera3* camera);

    /**
     * Address: 0x007D6E40
     * (FUN_007D6E40, ?CreateRegion@Clutter@Moho@@AAEPAVRegion@12@HHABV?$AxisAlignedBox3@M@Wm3@@@Z)
     *
     * What it does:
     * Acquires one region from the recycle pool (expanding pool blocks on
     * demand), links it into the active chain, stamps coordinates/bounds, and
     * inserts its key into the region-key tree.
     */
    ClutterRegion* CreateRegion(int x, int z, const Wm3::AxisAlignedBox3f& box);

    /**
     * Address: 0x007D7050 (FUN_007D7050, ?UpdateRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@PAVRegion@12@@Z)
     *
     * What it does:
     * Rebinds each mesh-instance payload in one region map to this clutter
     * owner lane.
     */
    void UpdateRegion(const GeomCamera3* camera, ClutterRegion* region);

    /**
     * Address: 0x007D64D0 (FUN_007D64D0, ?IsCluttered@Clutter@Moho@@AAE_NHH@Z)
     *
     * What it does:
     * Checks whether one `(x,z)` region key already exists in the clutter
     * region-key RB-tree lane.
     */
    [[nodiscard]] bool IsCluttered(int x, int z);

    /**
     * Address: 0x007D7150 (FUN_007D7150, ?GetSurface@Clutter@Moho@@AAEABVSurface@12@E@Z)
     *
     * What it does:
     * Lazily resolves one terrain-type clutter table and builds cached density
     * + seed entries for that surface index.
     */
    const ClutterSurfaceEntry& GetSurface(std::uint8_t terrainType);

    /**
     * Address: 0x007D7430 (FUN_007D7430, ?ClutterRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@ABVCHeightField@2@PAVRegion@12@MABVSurface@12@@Z)
     *
     * What it does:
     * Spawns clutter mesh instances for one region based on per-surface
     * density/seed weights and appends them to the region runtime list.
     */
    void PopulateRegionClutter(
      const GeomCamera3* camera,
      const CHeightField& heightField,
      ::moho::ClutterRegion* region,
      float densityScale,
      const ClutterSurfaceEntry& surface
    );

  public:
    std::uint8_t reserved00[0x04]; // +0x00 (vtable lane)
    ClutterIntrusiveListState mList1; // +0x04
    ClutterRegionListState mList2; // +0x10
    std::uint8_t mBuffer[0x100]; // +0x1C
    ClutterSurfaceEntry mSurfaces[256]; // +0x11C
    ClutterRegionKeyTreeState mKeys; // +0x191C
    ClutterRegion* mCurRegion; // +0x1928
  };

  static_assert(offsetof(Clutter, mList1) == 0x04, "Clutter::mList1 offset must be 0x04");
  static_assert(offsetof(Clutter, mList2) == 0x10, "Clutter::mList2 offset must be 0x10");
  static_assert(offsetof(Clutter, mBuffer) == 0x1C, "Clutter::mBuffer offset must be 0x1C");
  static_assert(offsetof(Clutter, mSurfaces) == 0x11C, "Clutter::mSurfaces offset must be 0x11C");
  static_assert(offsetof(Clutter, mKeys) == 0x191C, "Clutter::mKeys offset must be 0x191C");
  static_assert(offsetof(Clutter, mCurRegion) == 0x1928, "Clutter::mCurRegion offset must be 0x1928");
  static_assert(sizeof(Clutter) == 0x192C, "Clutter size must be 0x192C");

  /**
   * Address: 0x007D9400 (FUN_007D9400)
   *
   * What it does:
   * Walks one intrusive list lane and releases node payload storage.
   */
  std::uint8_t ReleaseRegionListPayloads(
    ClutterListNode* begin,
    ClutterListNode* endSentinel,
    std::uint8_t passthrough
  );

  /**
   * Address: 0x007D81C0 (FUN_007D81C0)
   *
   * What it does:
   * Recursively releases one region-key tree subtree using node-isNil sentinels.
   */
  void DestroyRegionKeySubtree(Clutter* owner, ClutterRegionKeyNode* node);

  /**
   * Address: 0x007D5CC0 (FUN_007D5CC0)
   *
   * What it does:
   * Resets one `ClutterRegionKey` vtable lane to the runtime `RegionKey`
   * virtual table token.
   */
  void ResetRegionKeyVtable(ClutterRegionKey* key);

  /**
   * Address: 0x007D5F80 (FUN_007D5F80)
   *
   * What it does:
   * Unlinks one region from the active chain, clears X/Z tags, and releases
   * map payload instances through the mesh-renderer destroy-instance lane.
   */
  ClutterRegionMapState* ResetRegionRuntimeState(ClutterRegion* region);

  /**
   * Address: 0x007D7B90 (FUN_007D7B90)
   *
   * What it does:
   * Counts and erases all key-tree nodes in the `[lower_bound, upper_bound)`
   * range for one `ClutterRegionKey`.
   */
  std::uint32_t EraseRegionKeyRange(
    ClutterRegionKey* key,
    ClutterRegionKeyTreeState* tree
  );

  /**
   * Address: 0x007D8980 (FUN_007D8980)
   *
   * What it does:
   * Allocates one region-list node and initializes `next/prev/value` lanes.
   */
  ClutterRegionListNode* __stdcall AllocateRegionListNode(
    ClutterRegionListNode* next,
    ClutterRegionListNode* prev,
    ClutterRegion* const* valueRef
  );

  /**
   * Address: 0x007D89C0 (FUN_007D89C0)
   *
   * What it does:
   * Increments list size with the original `list<T> too long` overflow guard.
   */
  std::uint32_t IncrementListSizeChecked(ClutterRegionListState* listState);
} // namespace moho
