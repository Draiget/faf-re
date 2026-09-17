#include "moho/render/Clutter.h"

#include "legacy/containers/Vector.h"
#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/mesh/Mesh.h"
#include "moho/math/MathReflection.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <boost/mutex.h>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace
{


  struct RegionRuntimeVtableResetTag
  {
    virtual ~RegionRuntimeVtableResetTag() = default;
  };

  struct DestroyInstanceVtableTag
  {
    virtual ~DestroyInstanceVtableTag() = default;
  };

  struct UpdateInstanceVtableTag
  {
    virtual ~UpdateInstanceVtableTag() = default;
  };

  struct SurfaceVtableResetTag
  {
    virtual ~SurfaceVtableResetTag() = default;
  };

  struct SeedVtableResetTag
  {
    virtual ~SeedVtableResetTag() = default;
  };

  struct DestroyInstanceRuntimeLane
  {
    void* vtable;
    moho::MeshRenderer* instance;
  };

  struct UpdateInstanceRuntimeLane
  {
    void* vtable;
    std::int32_t ownerToken;
  };




  RegionRuntimeVtableResetTag gRegionRuntimeVtableResetTag{};
  DestroyInstanceVtableTag gDestroyInstanceVtableTag{};
  UpdateInstanceVtableTag gUpdateInstanceVtableTag{};
  SurfaceVtableResetTag gSurfaceVtableResetTag{};
  SeedVtableResetTag gSeedVtableResetTag{};

  [[nodiscard]] void* RegionRuntimeVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gRegionRuntimeVtableResetTag);
  }

  [[nodiscard]] void* DestroyInstanceVtableToken()
  {
    return *reinterpret_cast<void**>(&gDestroyInstanceVtableTag);
  }

  [[nodiscard]] void* UpdateInstanceVtableToken()
  {
    return *reinterpret_cast<void**>(&gUpdateInstanceVtableTag);
  }

  /**
   * Address: 0x007D5E30 (FUN_007D5E30)
   *
   * What it does:
   * Initializes one update-instance helper lane with owner token payload.
   */
  [[maybe_unused]] UpdateInstanceRuntimeLane* InitializeUpdateInstanceLane(
    UpdateInstanceRuntimeLane* const outLane,
    const std::int32_t ownerToken
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = UpdateInstanceVtableToken();
    outLane->ownerToken = ownerToken;
    return outLane;
  }

  /**
   * Address: 0x007D5E40 (FUN_007D5E40)
   *
   * What it does:
   * Resets one update-instance helper lane to the `UpdateInstance` vtable.
   */
  [[maybe_unused]] void ResetUpdateInstanceLaneVtable(UpdateInstanceRuntimeLane* const lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    lane->vtable = UpdateInstanceVtableToken();
  }

  /**
   * Address: 0x007D9820 (FUN_007D9820)
   *
   * What it does:
   * Initializes one destroy-instance lane from another lane's payload while
   * restoring the destroy-instance vtable token.
   */
  [[maybe_unused]] DestroyInstanceRuntimeLane* InitializeDestroyInstanceLaneFromSource(
    DestroyInstanceRuntimeLane* const outLane,
    const DestroyInstanceRuntimeLane* const sourceLane
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = DestroyInstanceVtableToken();
    outLane->instance = sourceLane != nullptr ? sourceLane->instance : nullptr;
    return outLane;
  }

  /**
   * Address: 0x007D9830 (FUN_007D9830)
   *
   * What it does:
   * Initializes one update-instance lane from another lane's owner-token
   * payload while restoring the update-instance vtable token.
   */
  [[maybe_unused]] UpdateInstanceRuntimeLane* InitializeUpdateInstanceLaneFromSource(
    UpdateInstanceRuntimeLane* const outLane,
    const UpdateInstanceRuntimeLane* const sourceLane
  ) noexcept
  {
    if (outLane == nullptr) {
      return nullptr;
    }

    outLane->vtable = UpdateInstanceVtableToken();
    outLane->ownerToken = sourceLane != nullptr ? sourceLane->ownerToken : 0;
    return outLane;
  }

  /**
   * Address: 0x007D5EA0 (FUN_007D5EA0)
   *
   * What it does:
   * Resets one destroy-instance helper lane to the `DestroyInstance` vtable.
   */
  void ResetDestroyInstanceLaneVtable(DestroyInstanceRuntimeLane* const lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    lane->vtable = DestroyInstanceVtableToken();
  }

  [[nodiscard]] void* SurfaceVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gSurfaceVtableResetTag);
  }

  [[nodiscard]] void* SeedVtableResetToken()
  {
    return *reinterpret_cast<void**>(&gSeedVtableResetTag);
  }

  [[nodiscard]] moho::RRuleGameRules* GetActiveRules() noexcept
  {
    const moho::CWldSession* const session = moho::WLD_GetActiveSession();
    return session ? session->mRules : nullptr;
  }

  [[nodiscard]] moho::STIMap* GetTerrainTypeMap() noexcept
  {
    const moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (!session || !session->mWldMap || !session->mWldMap->mTerrainRes) {
      return nullptr;
    }

    return session->mWldMap->mTerrainRes->mMap;
  }

  [[nodiscard]] float NextGlobalRandomSignedUnit()
  {
    boost::mutex::scoped_lock randomLock(moho::math_GlobalRandomMutex);
    const std::uint32_t randomWord = moho::math_GlobalRandomStream.twister.NextUInt32();
    constexpr double kInvTwoTo31 = 4.656612873077392578125e-10;
    return static_cast<float>(static_cast<double>(randomWord) * kInvTwoTo31 - 1.0);
  }

  [[nodiscard]] float NextGlobalRandomUnit()
  {
    boost::mutex::scoped_lock randomLock(moho::math_GlobalRandomMutex);
    const std::uint32_t randomWord = moho::math_GlobalRandomStream.twister.NextUInt32();
    constexpr double kInvTwoTo32 = 2.3283064365386962890625e-10;
    return static_cast<float>(static_cast<double>(randomWord) * kInvTwoTo32);
  }

  [[nodiscard]] int AlignDownToEven(const int value) noexcept
  {
    return (value % 2 != 0) ? (value - 1) : value;
  }

  [[nodiscard]] int AlignUpToEven(const int value) noexcept
  {
    return (value % 2 != 0) ? (value + 1) : value;
  }

  [[nodiscard]] float SampleHeightWordAsWorldUnits(
    const moho::CHeightField& heightField,
    const int x,
    const int z
  ) noexcept
  {
    if (heightField.data == nullptr || heightField.width <= 0 || heightField.height <= 0) {
      return 0.0f;
    }

    const int clampedX = std::clamp(x, 0, heightField.width - 1);
    const int clampedZ = std::clamp(z, 0, heightField.height - 1);
    const std::size_t sampleIndex =
      static_cast<std::size_t>(clampedZ) * static_cast<std::size_t>(heightField.width)
      + static_cast<std::size_t>(clampedX);

    constexpr float kHeightWordScale = 0.0078125f;
    return static_cast<float>(heightField.data[sampleIndex]) * kHeightWordScale;
  }

  [[nodiscard]] Wm3::AxisAlignedBox3f BuildRegionBoundsFromHeightField(
    const moho::CHeightField& heightField,
    const int x,
    const int z
  )
  {
    const float h00 = SampleHeightWordAsWorldUnits(heightField, x, z);
    const float h01 = SampleHeightWordAsWorldUnits(heightField, x, z + 2);
    const float h10 = SampleHeightWordAsWorldUnits(heightField, x + 2, z);
    const float h11 = SampleHeightWordAsWorldUnits(heightField, x + 2, z + 2);

    const float minHeight = std::min(std::min(h00, h01), std::min(h10, h11));
    const float maxHeight = std::max(std::max(h00, h01), std::max(h10, h11));

    Wm3::AxisAlignedBox3f regionBounds{};
    regionBounds.Min.x = static_cast<float>(x);
    regionBounds.Min.y = minHeight;
    regionBounds.Min.z = static_cast<float>(z);
    regionBounds.Max.x = static_cast<float>(x + 2);
    regionBounds.Max.y = maxHeight;
    regionBounds.Max.z = static_cast<float>(z + 2);
    return regionBounds;
  }

  [[nodiscard]] std::uint8_t GetTerrainTypeAtOrDefault(
    const moho::STIMap& map,
    const int x,
    const int z
  ) noexcept
  {
    if (map.mTerrainType.data == nullptr || map.mTerrainType.width <= 1 || map.mTerrainType.height <= 1) {
      return 1u;
    }

    const int maxSampleX = map.mTerrainType.width - 1;
    const int maxSampleZ = map.mTerrainType.height - 1;
    if (x < 0 || z < 0 || x >= maxSampleX || z >= maxSampleZ) {
      return 1u;
    }

    const std::size_t terrainIndex =
      static_cast<std::size_t>(z) * static_cast<std::size_t>(map.mTerrainType.width)
      + static_cast<std::size_t>(x);
    return map.mTerrainType.data[terrainIndex];
  }

  /**
   * Address: 0x007D9390 (FUN_007D9390)
   */
  void ApplyDestroyInstanceToRegionPayloads(
    moho::ClutterPayloadList& payloads,
    DestroyInstanceRuntimeLane& destroyLane,
    moho::MeshRenderer* const instance
  )
  {
    for (void* const entry : payloads) {
      auto* const payload = static_cast<moho::ClutterRegionMapPayloadHeader*>(entry);
      payload->vtable->destroy(payload, 1);
    }

    destroyLane.instance = instance;
    ResetDestroyInstanceLaneVtable(&destroyLane);
  }

  /**
   * Address: 0x007D9440 (FUN_007D9440)
   *
   * What it does:
   * Rebinds each region-map mesh instance to the provided clutter owner and
   * refreshes one update-instance helper lane to the update vtable token.
   */
  UpdateInstanceRuntimeLane* BindRegionMeshInstancesToOwner(
    UpdateInstanceRuntimeLane* const lane,
    moho::ClutterPayloadList& payloads,
    const std::int32_t ownerToken
  ) noexcept
  {
    if (lane == nullptr) {
      return nullptr;
    }

    for (void* const entry : payloads) {
      static_cast<moho::MeshInstance*>(entry)->unk24 = ownerToken;
    }

    lane->ownerToken = ownerToken;
    lane->vtable = UpdateInstanceVtableToken();
    return lane;
  }

  [[nodiscard]] moho::ClutterRegion* AllocateRegionPoolBlock()
  {
    constexpr std::uint32_t kRegionPoolCount = 128u;

    auto* const rawStorage = static_cast<std::uint8_t*>(
      ::operator new(sizeof(std::uint32_t) + sizeof(moho::ClutterRegion) * kRegionPoolCount)
    );
    *reinterpret_cast<std::uint32_t*>(rawStorage) = kRegionPoolCount;

    auto* const regionBase =
      reinterpret_cast<moho::ClutterRegion*>(rawStorage + sizeof(std::uint32_t));
    std::uint32_t constructedCount = 0u;

    try {
      for (; constructedCount < kRegionPoolCount; ++constructedCount) {
        ::new (static_cast<void*>(regionBase + constructedCount)) moho::ClutterRegion();
      }
    } catch (...) {
      while (constructedCount > 0u) {
        --constructedCount;
        regionBase[constructedCount].~ClutterRegion();
      }
      ::operator delete(rawStorage);
      throw;
    }

    return regionBase;
  }

  /**
   * Address: 0x007D60C0 (FUN_007D60C0)
   */
  void ResetClutterSeedVtable(moho::ClutterSurfaceElement* const seed)
  {
    seed->vtable = reinterpret_cast<moho::ClutterSurfaceElementVTable*>(SeedVtableResetToken());
  }

  /**
   * Address: 0x007D5FE0 (FUN_007D5FE0)
   */
  moho::ClutterSurfaceElement* InitializeClutterSeedFromBlueprintPath(
    moho::ClutterSurfaceElement* const seed,
    const float selectionWeight,
    const msvc8::string& meshBlueprintId
  )
  {
    ResetClutterSeedVtable(seed);
    seed->selectionWeight = selectionWeight;
    seed->uniformScale = 1.0f;
    seed->meshBlueprint = nullptr;

    moho::RRuleGameRules* const rules = GetActiveRules();
    if (!rules) {
      return seed;
    }

    msvc8::string normalizedPath{};
    gpg::STR_CopyFilename(&normalizedPath, &meshBlueprintId);
    moho::RPropBlueprint* const propBlueprint = rules->GetPropBlueprint(normalizedPath);
    if (!propBlueprint) {
      return seed;
    }

    seed->uniformScale = propBlueprint->Display.UniformScale;
    seed->meshBlueprint = rules->GetMeshBlueprint(propBlueprint->Display.MeshBlueprint);
    return seed;
  }

  /**
   * Address: 0x007D78B0 (FUN_007D78B0)
   *
   * What it does:
   * Appends one seed to a surface's seed vector, growing capacity 1.5x when
   * full. `Moho::Clutter::Surface::mSeeds` is `msvc8::vector<
   * ClutterSurfaceElement>` (`Clutter.h`) -- this call is the natural
   * source-level `insert(pos, value)` the compiler folded to `count=1` at
   * `FUN_007D8620`/`FUN_007D9620` (cited on the canonical
   * `insert(pos,count,value)` member, `Vector.h`). Previously hand-rolled
   * here via `CopyClutterSeedRange`/`CopyClutterSeedValueRange`
   * (0x007D9970/0x007D7F00) reaching directly into the raw begin/end/
   * capacity triple -- collapsed into the canonical template per RULE ONE;
   * those two addresses are now cited on `uninit_fill_n` (`Vector.h`).
   */
  std::uint32_t AppendSurfaceSeed(
    moho::ClutterSurfaceEntry* const surface,
    const moho::ClutterSurfaceElement& seed
  )
  {
    (void)surface->mSeeds.insert(surface->mSeeds.end(), seed);
    return static_cast<std::uint32_t>(surface->mSeeds.size());
  }
} // namespace

namespace moho
{
  float ren_ClutterRadius = 0.0f;

  /**
   * Address: 0x007D7E00 (FUN_007D7E00, inlined into the tail-destroy loop of
   * `msvc8::vector<ClutterSurfaceElement>::erase(first,last)` --
   * `legacy/containers/Vector.h`)
   * Address: 0x007D7EB0 (FUN_007D7EB0, ??1Surface@Clutter@Moho@@QAE@@Z,
   * inlined into `Surface::~Surface`'s own `mSeeds` teardown sweep, below)
   * Address: 0x007D7920 (unnamed 22-byte register-convention fragment --
   * see the `erase(first,last)` citation in `Vector.h` for detail)
   *
   * What it does:
   * Dispatches through the element's own "poisoned" vtable slot 0 with a
   * delete-flag of 0. No source line calls this by name at any of the
   * addresses above -- each is the compiler inlining this one-statement
   * method (and the destructor that forwards to it, below) at its own call
   * site. Reduces to a runtime no-op: every live element's `vtable` is set
   * exactly once, via `ResetClutterSeedVtable`, to `SeedVtableResetToken()`,
   * and `SeedVtableResetTag`'s destructor is defaulted with the delete flag
   * skipping `operator delete` -- but the call itself is real and is part of
   * the type's actual destructor, so it must happen for binary-exact
   * fidelity.
   */
  void ClutterSurfaceElement::DestroyInPlace()
  {
    vtable->destroy(this, 0);
  }

  /**
   * The real destructor's body is exactly `DestroyInPlace()` above -- MSVC
   * inlines a one-statement destructor at each call site rather than
   * emitting a standalone symbol, so there is no separate address to cite
   * beyond the ones already on `DestroyInPlace()`. Declaring this as a real
   * (non-trivial) destructor, instead of leaving the type implicitly
   * trivial, is what makes `msvc8::vector<ClutterSurfaceElement>`'s
   * existing, unmodified `destroy_range`/`erase`/`clear`/`tidy` machinery
   * (`Vector.h`) emit the per-element call `FUN_007D7E00` and `FUN_007D7EB0`
   * both show -- previously the struct was (wrongly) trivially destructible
   * and that machinery's `if constexpr (!is_trivially_destructible_v<T>)`
   * guard silently skipped the call.
   */
  ClutterSurfaceElement::~ClutterSurfaceElement()
  {
    DestroyInPlace();
  }

  /**
   * Address: 0x007D94B0 (FUN_007D94B0, inlined into the tail-shift step of
   * `msvc8::vector<ClutterSurfaceElement>::erase(first,last)` --
   * `legacy/containers/Vector.h`)
   *
   * What it does:
   * Copies the three payload fields (`selectionWeight`, `uniformScale`,
   * `meshBlueprint`) from `rhs` and deliberately leaves `vtable` untouched.
   * Every live element's `vtable` already holds the same
   * `SeedVtableResetToken()` value (`ResetClutterSeedVtable` sets it once;
   * it never changes for the life of the slot), so the original source
   * skips re-copying it on every shift-assign during an erase. Declaring
   * this explicitly (instead of leaving the implicit memberwise copy) is
   * what makes `erase(first,last)`'s per-element
   * `first[i] = std::move(last[i])` shift loop produce this exact 3-field
   * copy instead of copying all four fields -- a user-declared destructor
   * alone already routes `erase` into that loop (it makes the type
   * non-trivially-copyable), but without this operator the loop would fall
   * back to the implicit, all-4-field copy-assignment.
   */
  ClutterSurfaceElement& ClutterSurfaceElement::operator=(const ClutterSurfaceElement& rhs)
  {
    selectionWeight = rhs.selectionWeight;
    uniformScale = rhs.uniformScale;
    meshBlueprint = rhs.meshBlueprint;
    return *this;
  }

  /**
   * Address: 0x007D5EE0 (FUN_007D5EE0, ??0Region@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes region links and key coordinates, then allocates one empty
   * region-map list sentinel.
   */
  ClutterRegion::ClutterRegion()
  {
    vtable = RegionRuntimeVtableResetToken();
    mNext = nullptr;
    mPrev = nullptr;
    mX = -1;
    mZ = -1;
  }

  /**
   * Address: 0x007D5F20 (FUN_007D5F20, ??1Region@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets region runtime links/payloads, clears map-node list storage, then
   * releases the map-list sentinel allocation.
   */
  ClutterRegion::~ClutterRegion()
  {
    vtable = RegionRuntimeVtableResetToken();
    (void)ResetRegionRuntimeState(this);
  }

  /**
   * Address: 0x007D5CF0 (FUN_007D5CF0, ??0Surface@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets the vtable to the poison/reset token and zeroes `density`.
   * `mSeeds` default-constructs itself via member init (empty, no
   * allocation) -- matches the real binary exactly: `Clutter::Clutter`
   * (`FUN_007D60D0`) constructs the 256-entry `mSurfaces` array through the
   * compiler-emitted `` `eh vector constructor iterator' `` helper calling
   * this constructor, rather than an explicit hand-written per-entry loop.
   */
  ClutterSurfaceEntry::ClutterSurfaceEntry()
    : vtable(SurfaceVtableResetToken())
    , density(0)
  {
  }

  /**
   * Address: 0x007D5D10 (FUN_007D5D10)
   * Address: 0x007D7EB0 (FUN_007D7EB0, ??1Surface@Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets the vtable to the poison/reset token; `mSeeds` destroys its live
   * elements and releases its buffer through its own destructor. Confirmed
   * against `FUN_007D7EB0`'s raw disassembly: an inline sweep calling each
   * element's own vtable-slot-0 dispatch, then `operator delete` on the
   * buffer, then zeroing `{first_,last_,end_}` (`myProxy_` deliberately left
   * alone) -- exactly `ClutterSurfaceElement::~ClutterSurfaceElement()`
   * (which forwards to `DestroyInPlace()`) run per live element by
   * `msvc8::vector<ClutterSurfaceElement>`'s own `tidy()`-shaped teardown
   * (`Vector.h`), which reduces to a runtime no-op per element since
   * `ClutterSurfaceElement`'s poisoned vtable resets to
   * `SeedVtableResetTag`'s trivial defaulted destructor -- see
   * `ResetClutterSeedVtable`/`SeedVtableResetToken` above, and
   * `ClutterSurfaceElement::DestroyInPlace`'s own citation (`Clutter.h`) for
   * the full evidence chain. Reached via `Clutter::~Clutter`
   * (`FUN_007D61E0`)'s compiler-emitted
   * `` `eh vector destructor iterator' `` teardown of `mSurfaces`, rather
   * than an explicit hand-written per-entry loop.
   */
  ClutterSurfaceEntry::~ClutterSurfaceEntry()
  {
    vtable = SurfaceVtableResetToken();
  }

  /**
   * Address: 0x007D60D0 (FUN_007D60D0, ??0Clutter@Moho@@QAE@XZ)
   */
  Clutter::Clutter()
  {


    // mSurfaces[256] (moho::ClutterSurfaceEntry, real ctor above) is
    // default-constructed automatically here, matching the real binary's
    // `` `eh vector constructor iterator' `` call in this constructor.

    mCurRegion = nullptr;

    std::memset(mBuffer, 0, sizeof(mBuffer));
  }

  /**
   * Address: 0x007D61E0 (FUN_007D61E0, ??1Clutter@Moho@@UAE@XZ)
   * Address: 0x007D6190 (FUN_007D6190, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   */
  Clutter::~Clutter()
  {
    Shutdown();



    // mSurfaces[256] (moho::ClutterSurfaceEntry, real dtor above) is
    // destroyed automatically as part of this destructor's implicit member
    // teardown, matching the real binary's `` `eh vector destructor
    // iterator' `` call in `~Clutter`.


  }

  /**
   * Address: 0x007D6380 (FUN_007D6380, ?Update@Clutter@Moho@@QAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Runs one clutter update frame by culling stale regions first, then
   * generating new visible region clutter from terrain data.
   */
  void Clutter::Update(const GeomCamera3* const camera)
  {
    UpdateCurrent(camera);
    GenerateNew(camera);
  }

  /**
   * Address: 0x007D6410 (FUN_007D6410, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@ABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * What it does:
   * Returns whether one region AABB is close enough to the camera and inside
   * the camera frustum-solid lane.
   */
  bool Clutter::IsVisible(const GeomCamera3* const camera, const Wm3::AxisAlignedBox3f& regionBox)
  {
    const float centerX = (regionBox.Min.x + regionBox.Max.x) * 0.5f;
    const float centerY = (regionBox.Min.y + regionBox.Max.y) * 0.5f;
    const float centerZ = (regionBox.Min.z + regionBox.Max.z) * 0.5f;

    const float deltaX = centerX - camera->inverseView.r[3].x;
    const float deltaY = centerY - camera->inverseView.r[3].y;
    const float deltaZ = centerZ - camera->inverseView.r[3].z;
    const float centerDistance = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));
    if (centerDistance > ren_ClutterRadius) {
      return false;
    }

    return camera->solid2.Intersects(regionBox);
  }

  /**
   * Address: 0x007D64C0 (FUN_007D64C0, ?IsVisible@Clutter@Moho@@AAE_NPBVGeomCamera3@2@PBVRegion@12@@Z)
   *
   * What it does:
   * Returns visibility state for one clutter region by delegating to AABB
   * visibility test using the region's box lane.
   */
  bool Clutter::IsVisible(const GeomCamera3* const camera, const ClutterRegion* const region)
  {
    return region != nullptr && IsVisible(camera, region->mBox);
  }

  /**
   * Address: 0x007D6510 (FUN_007D6510, ?UpdateCurrent@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Walks the active-region chain and destroys regions that are outside clutter
   * distance radius or no longer intersect the camera frustum solid.
   */
  void Clutter::UpdateCurrent(const GeomCamera3* const camera)
  {
    ClutterRegion* currentRegion = mCurRegion;
    while (currentRegion != nullptr) {
      ClutterRegion* const previousRegion = currentRegion->mPrev;
      if (!IsVisible(camera, currentRegion)) {
        DestroyRegion(currentRegion);
      }

      currentRegion = previousRegion;
    }
  }

  /**
   * Address: 0x007D6640 (FUN_007D6640, ?GenerateNew@Clutter@Moho@@AAEXPBVGeomCamera3@2@@Z)
   *
   * What it does:
   * Scans 2x2 terrain tiles around the camera clutter radius, creates missing
   * visible regions, and populates each region from four sampled terrain types.
   */
  void Clutter::GenerateNew(const GeomCamera3* const camera)
  {
    (void)MeshRenderer::GetInstance();

    if (GetActiveRules() == nullptr) {
      return;
    }

    STIMap* const terrainMap = GetTerrainTypeMap();
    if (terrainMap == nullptr) {
      return;
    }

    CHeightField* const heightField = terrainMap->GetHeightField();
    if (heightField == nullptr) {
      return;
    }

    const float radius = ren_ClutterRadius;
    const float originX = camera->inverseView.r[3].x;
    const float originZ = camera->inverseView.r[3].z;

    const float probeX0 = originX - radius * camera->view.r[0].z;
    const float probeX1 = originX + radius * camera->view.r[0].x;
    const float probeX2 = originX - radius * camera->view.r[0].x;

    const float probeZ0 = originZ - radius * camera->view.r[2].z;
    const float probeZ1 = originZ + radius * camera->view.r[2].x;
    const float probeZ2 = originZ - radius * camera->view.r[2].x;

    const int xBegin = AlignDownToEven(static_cast<int>(std::min(std::min(probeX0, probeX1), probeX2)));
    const int xEnd = AlignUpToEven(static_cast<int>(std::max(std::max(probeX0, probeX1), probeX2)));
    const int zBegin = AlignDownToEven(static_cast<int>(std::min(std::min(probeZ0, probeZ1), probeZ2)));
    const int zEnd = AlignUpToEven(static_cast<int>(std::max(std::max(probeZ0, probeZ1), probeZ2)));

    for (int x = xBegin; x < xEnd; x += 2) {
      for (int z = zBegin; z < zEnd; z += 2) {
        if (IsCluttered(x, z)) {
          continue;
        }

        const Wm3::AxisAlignedBox3f regionBounds = BuildRegionBoundsFromHeightField(*heightField, x, z);
        if (!IsVisible(camera, regionBounds)) {
          continue;
        }

        ClutterRegion* const region = CreateRegion(x, z, regionBounds);
        if (region == nullptr) {
          continue;
        }

        const std::uint8_t terrain00 = GetTerrainTypeAtOrDefault(*terrainMap, x, z);
        const std::uint8_t terrain01 = GetTerrainTypeAtOrDefault(*terrainMap, x, z + 1);
        const std::uint8_t terrain10 = GetTerrainTypeAtOrDefault(*terrainMap, x + 1, z);
        const std::uint8_t terrain11 = GetTerrainTypeAtOrDefault(*terrainMap, x + 1, z + 1);

        const float density00 = static_cast<float>(
                                  (terrain00 == terrain01) + (terrain00 == terrain10) + (terrain00 == terrain11) + 1
                                )
                              * 0.25f;
        const float density01 = static_cast<float>(
                                  (terrain01 == terrain00) + (terrain01 == terrain10) + (terrain01 == terrain11) + 1
                                )
                              * 0.25f;
        const float density10 = static_cast<float>(
                                  (terrain10 == terrain00) + (terrain10 == terrain01) + (terrain10 == terrain11) + 1
                                )
                              * 0.25f;
        const float density11 = static_cast<float>(
                                  (terrain11 == terrain00) + (terrain11 == terrain01) + (terrain11 == terrain10) + 1
                                )
                              * 0.25f;

        PopulateRegionClutter(camera, *heightField, region, density00, GetSurface(terrain00));
        PopulateRegionClutter(camera, *heightField, region, density01, GetSurface(terrain01));
        PopulateRegionClutter(camera, *heightField, region, density10, GetSurface(terrain10));
        PopulateRegionClutter(camera, *heightField, region, density11, GetSurface(terrain11));
      }
    }
  }

  /**
   * Address: 0x007D7050 (FUN_007D7050, ?UpdateRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@PAVRegion@12@@Z)
   *
   * What it does:
   * Rebinds each mesh-instance payload in one region map to this clutter
   * owner lane.
   */
  void Clutter::UpdateRegion(const GeomCamera3* const camera, ClutterRegion* const region)
  {
    (void)camera;

    UpdateInstanceRuntimeLane updateLane{};
    const auto ownerToken = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(this));
    (void)BindRegionMeshInstancesToOwner(&updateLane, region->mMap, ownerToken);
  }

  /**
   * Address: 0x007D64D0 (FUN_007D64D0, ?IsCluttered@Clutter@Moho@@AAE_NHH@Z)
   *
   * What it does:
   * Probes the region-key RB-tree for one exact `(x,z)` key match.
   */
  bool Clutter::IsCluttered(const int x, const int z)
  {
    return mKeys.find(ClutterRegionKey(x, z)) != mKeys.end();
  }

  /**
   * Address: 0x007D9400 (FUN_007D9400)
   */
  std::uint8_t ReleaseRegionListPayloads(
    ClutterRegionList& poolBlocks,
    const std::uint8_t passthrough
  )
  {
    for (ClutterRegion* const block : poolBlocks) {
      auto* const payload = reinterpret_cast<ClutterPayloadHeader*>(block);
      if (!payload) {
        continue;
      }

      auto* const refLane = reinterpret_cast<std::uint32_t*>(payload) - 1;
      if (*refLane != 0u) {
        payload->vtable->destroy(payload, 3);
      } else {
        ::operator delete[](refLane);
      }
    }

    return passthrough;
  }

  /**
   * Address: 0x007D5F80 (FUN_007D5F80)
   */
  ClutterPayloadList* ResetRegionRuntimeState(ClutterRegion* const region)
  {
    region->mPrev = nullptr;
    region->mNext = nullptr;
    region->mZ = -1;
    region->mX = -1;

    DestroyInstanceRuntimeLane destroyLane{};
    ResetDestroyInstanceLaneVtable(&destroyLane);
    destroyLane.instance = nullptr;

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    ApplyDestroyInstanceToRegionPayloads(region->mMap, destroyLane, meshRenderer);
    region->mMap.clear();
    return &region->mMap;
  }

  /**
   * Address: 0x007D7150 (FUN_007D7150, ?GetSurface@Clutter@Moho@@AAEABVSurface@12@E@Z)
   */
  const ClutterSurfaceEntry& Clutter::GetSurface(const std::uint8_t terrainType)
  {
    if (mBuffer[terrainType] != 0u) {
      return mSurfaces[terrainType];
    }

    mBuffer[terrainType] = 1u;
    ClutterSurfaceEntry& surface = mSurfaces[terrainType];

    STIMap* const terrainTypeMap = GetTerrainTypeMap();
    if (!terrainTypeMap) {
      return surface;
    }

    LuaPlus::LuaObject terrainTypeObject = terrainTypeMap->GetTerrainType(terrainType);
    if (!terrainTypeObject.IsTable()) {
      return surface;
    }

    LuaPlus::LuaObject clutterTable = terrainTypeObject["Clutter"];
    if (!clutterTable.IsTable()) {
      return surface;
    }

    surface.density = clutterTable["density"].GetInteger();

    LuaPlus::LuaObject seedsTable = clutterTable["Seeds"];
    if (!seedsTable.IsTable()) {
      return surface;
    }

    for (LuaPlus::LuaTableIterator iter(&seedsTable, 1); !iter.m_isDone; iter.Next()) {
      LuaPlus::LuaObject seedObject(iter.GetValue());
      const char* const meshBlueprintPath = seedObject[2].GetString();
      const float selectionWeight = static_cast<float>(seedObject[1].GetNumber());

      msvc8::string meshBlueprintId(meshBlueprintPath ? meshBlueprintPath : "");
      ClutterSurfaceElement seed{};
      (void)InitializeClutterSeedFromBlueprintPath(&seed, selectionWeight, meshBlueprintId);
      (void)AppendSurfaceSeed(&surface, seed);
      ResetClutterSeedVtable(&seed);
    }

    return surface;
  }

  /**
   * Address: 0x007D7430 (FUN_007D7430, ?ClutterRegion@Clutter@Moho@@AAEXPBVGeomCamera3@2@ABVCHeightField@2@PAVRegion@12@MABVSurface@12@@Z)
   */
  void Clutter::PopulateRegionClutter(
    const GeomCamera3* const camera,
    const CHeightField& heightField,
    ::moho::ClutterRegion* const region,
    const float densityScale,
    const ClutterSurfaceEntry& surface
  )
  {
    (void)camera;
    if (!region) {
      return;
    }

    ClutterSurfaceElement* const seedBegin = surface.mSeeds.begin();
    ClutterSurfaceElement* const seedEnd = surface.mSeeds.end();
    if (!seedBegin || seedEnd <= seedBegin) {
      return;
    }

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    if (!meshRenderer) {
      return;
    }

    const int seedCount = static_cast<int>(seedEnd - seedBegin);
    const int spawnCount = static_cast<int>(static_cast<float>(surface.density) * densityScale);
    if (spawnCount <= 0) {
      return;
    }

    const float regionBaseX = static_cast<float>(region->mX + 1);
    const float regionBaseZ = static_cast<float>(region->mZ + 1);

    for (int spawnIndex = 0; spawnIndex < spawnCount; ++spawnIndex) {
      const float spawnX = regionBaseX + NextGlobalRandomSignedUnit();
      const float spawnZ = regionBaseZ + NextGlobalRandomSignedUnit();
      const float terrainY = heightField.GetElevation(spawnX, spawnZ);
      const float selection = NextGlobalRandomUnit();

      float weightAccumulator = 0.0f;
      for (int seedIndex = 0; seedIndex < seedCount; ++seedIndex) {
        const ClutterSurfaceElement& seed = seedBegin[seedIndex];
        weightAccumulator += seed.selectionWeight;
        if (weightAccumulator <= selection || !seed.meshBlueprint) {
          continue;
        }

        const Wm3::Vec3f scale(seed.uniformScale, seed.uniformScale, seed.uniformScale);
        MeshInstance* const meshInstance =
          meshRenderer->CreateMeshInstance(0, -1, seed.meshBlueprint, scale, false, {});
        if (!meshInstance) {
          break;
        }

        VTransform stance{};
        stance.orient_.w = 1.0f;
        stance.pos_.x = spawnX;
        stance.pos_.y = terrainY;
        stance.pos_.z = spawnZ;
        meshInstance->SetStance(stance, stance);
        meshInstance->unk24 = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&heightField));

        region->mMap.push_back(meshInstance);
        break;
      }
    }
  }

  /**
   * Address: 0x007D6E10 (FUN_007D6E10, ?UnlinkRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
   *
   * What it does:
   * Detaches one region node from the active doubly-linked chain and updates
   * `mCurRegion` when it points at the removed node.
   */
  void Clutter::UnlinkRegion(ClutterRegion* const region)
  {
    if (mCurRegion == region) {
      mCurRegion = region->mNext;
    }

    if (region->mPrev != nullptr) {
      region->mPrev->mNext = region->mNext;
    }

    if (region->mNext != nullptr) {
      region->mNext->mPrev = region->mPrev;
    }
  }

  /**
   * Address: 0x007D6E40
   * (FUN_007D6E40, ?CreateRegion@Clutter@Moho@@AAEPAVRegion@12@HHABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * What it does:
   * Expands the recycle pool in 128-region blocks when needed, takes one
   * recycled region, links it as current, writes coordinates/bounds, and
   * inserts the corresponding key into the region-key tree.
   */
  ClutterRegion* Clutter::CreateRegion(const int x, const int z, const Wm3::AxisAlignedBox3f& box)
  {
    constexpr std::uint32_t kRegionPoolCount = 128u;

    if (mList2.empty()) {
      ClutterRegion* const regionPool = AllocateRegionPoolBlock();
      mList1.push_back(regionPool);

      for (std::uint32_t index = 0; index < kRegionPoolCount; ++index) {
        mList2.push_back(regionPool + index);
      }
    }

    if (mList2.empty()) {
      return nullptr;
    }

    ClutterRegion* const region = mList2.front();
    mList2.pop_front();

    region->mNext = nullptr;
    region->mPrev = mCurRegion;
    if (mCurRegion != nullptr) {
      mCurRegion->mNext = region;
    }
    mCurRegion = region;

    region->mX = x;
    region->mZ = z;
    region->mBox = box;

    (void)mKeys.insert(ClutterRegionKey(x, z));

    return region;
  }

  /**
   * Address: 0x007D7080 (FUN_007D7080, ?DestroyRegion@Clutter@Moho@@AAEXPAVRegion@12@@Z)
   */
  void Clutter::DestroyRegion(ClutterRegion* const region)
  {
    (void)mKeys.erase(ClutterRegionKey(*region));

    UnlinkRegion(region);

    (void)ResetRegionRuntimeState(region);

    mList2.push_back(region);
  }

  /**
   * Address: 0x007D63A0 (FUN_007D63A0, ?Clear@Clutter@Moho@@QAEXXZ)
   */
  void Clutter::Clear()
  {
    ClutterRegion* currentRegion = mCurRegion;
    while (currentRegion) {
      ClutterRegion* const previous = currentRegion->mPrev;
      DestroyRegion(currentRegion);
      currentRegion = previous;
    }
    mCurRegion = nullptr;

    mKeys.clear();
  }

  /**
   * Address: 0x007D62B0 (FUN_007D62B0, ?Initialize@Clutter@Moho@@QAEXXZ)
   *
   * What it does:
   * Forwards to `Shutdown()` (thunk lane in the original binary).
   */
  void Clutter::Initialize()
  {
    Shutdown();
  }

  /**
   * Address: 0x007D62C0 (FUN_007D62C0, ?Shutdown@Clutter@Moho@@QAEXXZ)
   */
  void Clutter::Shutdown()
  {
    Clear();
    std::memset(mBuffer, 0, sizeof(mBuffer));

    for (ClutterSurfaceEntry& surface : mSurfaces) {
      // Address: 0x007D7E00 (FUN_007D7E00, called at 0x007D6300 as
      // `sub_7D7E00(&mSeeds, &scratchOut, mSeeds.first_, mSeeds.last_)` once
      // per loop iteration -- i.e. `erase(begin(),end())`, exactly `clear()`.
      // `msvc8::vector<ClutterSurfaceElement>::erase(first,last)`
      // (`Vector.h`) already models this byte-for-byte; see that member's
      // Doxygen citation for the full shape/evidence, including the second,
      // unnamed call site and why `ClutterSurfaceElement` needed its own
      // destructor/`operator=` (`Clutter.h`) rather than any change here.
      surface.mSeeds.clear();
    }

    mList2.clear();

    // Each entry is a 128-region pool block; release the blocks before the
    // nodes that point at them.
    (void)ReleaseRegionListPayloads(mList1, 0);
    mList1.clear();
  }
} // namespace moho


namespace moho
{
  /**
   * Address: 0x007D5CA0 (FUN_007D5CA0)
   *
   * What it does:
   * Builds one region key from a live region's grid coordinates.
   */
  ClutterRegionKey::ClutterRegionKey(const ClutterRegion& region) noexcept
    : mX(region.mX)
    , mZ(region.mZ)
  {
  }
} // namespace moho
