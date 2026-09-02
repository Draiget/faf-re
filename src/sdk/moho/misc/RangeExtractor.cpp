#include "moho/misc/RangeExtractor.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "legacy/containers/String.h"
#include "moho/collision/CounterIntelExtractor.h"
#include "moho/collision/IntelExtractor.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/CombinedMilitaryExtractor.h"
#include "moho/misc/CountermeasureExtractor.h"
#include "moho/misc/MiscellaneousExtractor.h"
#include "moho/misc/OmniExtractor.h"
#include "moho/misc/RadarExtractor.h"
#include "moho/misc/SonarExtractor.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/core/WeaponExtractor.h"

namespace
{
  using BlueprintExtractorRegistry = std::map<std::string, std::unique_ptr<moho::RangeExtractor>>;

  [[nodiscard]] BlueprintExtractorRegistry& GetBlueprintExtractorRegistry()
  {
    static BlueprintExtractorRegistry registry;
    return registry;
  }

  bool gBlueprintExtractorsInitialized = false;

  struct BlueprintExtractorTreeNodeRuntimeView
  {
    BlueprintExtractorTreeNodeRuntimeView* mLeft;   // +0x00
    BlueprintExtractorTreeNodeRuntimeView* mParent; // +0x04
    BlueprintExtractorTreeNodeRuntimeView* mRight;  // +0x08
    std::uint32_t mUnknown0C = 0u;                  // +0x0C
    msvc8::string mKeyStorage;                      // +0x10
    std::uint8_t mColor = 0u;                       // +0x2C
    std::uint8_t mIsSentinel = 0u;                  // +0x2D
    std::uint8_t mPad2E[2]{};                       // +0x2E
  };
  static_assert(
    offsetof(BlueprintExtractorTreeNodeRuntimeView, mKeyStorage) == 0x10,
    "BlueprintExtractorTreeNodeRuntimeView::mKeyStorage offset must be 0x10"
  );
  static_assert(offsetof(BlueprintExtractorTreeNodeRuntimeView, mColor) == 0x2C, "BlueprintExtractorTreeNodeRuntimeView::mColor offset must be 0x2C");
  static_assert(
    offsetof(BlueprintExtractorTreeNodeRuntimeView, mIsSentinel) == 0x2D,
    "BlueprintExtractorTreeNodeRuntimeView::mIsSentinel offset must be 0x2D"
  );
  static_assert(sizeof(BlueprintExtractorTreeNodeRuntimeView) == 0x30, "BlueprintExtractorTreeNodeRuntimeView size must be 0x30");

  [[nodiscard]] BlueprintExtractorTreeNodeRuntimeView* ResolveBlueprintExtractorTreeHead(
    BlueprintExtractorTreeNodeRuntimeView* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    BlueprintExtractorTreeNodeRuntimeView* parent = node->mParent;
    while (parent != nullptr && parent->mIsSentinel == 0u) {
      node = parent;
      parent = node->mParent;
    }
    return parent;
  }

  /**
   * Address: 0x007F2B00 (FUN_007F2B00, sub_7F2B00)
   *
   * What it does:
   * Performs one left-rotation around `node` in the blueprint-extractor
   * RB-tree, updating parent/head links.
   */
  [[maybe_unused]] BlueprintExtractorTreeNodeRuntimeView* RotateBlueprintExtractorTreeNodeLeft(
    BlueprintExtractorTreeNodeRuntimeView* const node
  ) noexcept
  {
    BlueprintExtractorTreeNodeRuntimeView* const rotated = node->mRight;
    node->mRight = rotated->mLeft;
    if (rotated->mLeft->mIsSentinel == 0u) {
      rotated->mLeft->mParent = node;
    }

    rotated->mParent = node->mParent;

    BlueprintExtractorTreeNodeRuntimeView* const head = ResolveBlueprintExtractorTreeHead(node);
    if (head == nullptr) {
      return rotated;
    }

    if (node == head->mParent) {
      head->mParent = rotated;
      rotated->mLeft = node;
      node->mParent = rotated;
    } else {
      BlueprintExtractorTreeNodeRuntimeView* const parent = node->mParent;
      if (node == parent->mLeft) {
        parent->mLeft = rotated;
      } else {
        parent->mRight = rotated;
      }
      rotated->mLeft = node;
      node->mParent = rotated;
    }

    return rotated;
  }

  /**
   * Address: 0x007F2B60 (FUN_007F2B60, sub_7F2B60)
   *
   * What it does:
   * Performs one right-rotation around `node` in the blueprint-extractor
   * RB-tree, updating parent/head links.
   */
  [[maybe_unused]] BlueprintExtractorTreeNodeRuntimeView* RotateBlueprintExtractorTreeNodeRight(
    BlueprintExtractorTreeNodeRuntimeView* const node
  ) noexcept
  {
    BlueprintExtractorTreeNodeRuntimeView* const rotated = node->mLeft;
    node->mLeft = node->mLeft->mRight;
    if (rotated->mRight->mIsSentinel == 0u) {
      rotated->mRight->mParent = node;
    }

    rotated->mParent = node->mParent;

    BlueprintExtractorTreeNodeRuntimeView* const head = ResolveBlueprintExtractorTreeHead(node);
    if (head == nullptr) {
      return rotated;
    }

    if (node == head->mParent) {
      head->mParent = rotated;
      rotated->mRight = node;
      node->mParent = rotated;
    } else {
      BlueprintExtractorTreeNodeRuntimeView* const parent = node->mParent;
      if (node == parent->mRight) {
        parent->mRight = rotated;
      } else {
        parent->mLeft = rotated;
      }
      rotated->mRight = node;
      node->mParent = rotated;
    }

    return rotated;
  }

  /**
   * Address: 0x007F2FA0 (FUN_007F2FA0, sub_7F2FA0)
   *
   * What it does:
   * Destroys every non-sentinel node in one blueprint-extractor RB-tree
   * subtree using right-recursive / left-linear traversal order.
   */
  [[maybe_unused]] void DestroyBlueprintExtractorTreeNodesRecursive(
    BlueprintExtractorTreeNodeRuntimeView* node
  ) noexcept
  {
    BlueprintExtractorTreeNodeRuntimeView* previous = node;
    for (; previous != nullptr && previous->mIsSentinel == 0u; previous = node) {
      DestroyBlueprintExtractorTreeNodesRecursive(node->mRight);
      node = node->mLeft;
      previous->mKeyStorage.tidy(true, 0u);
      ::operator delete(previous);
    }
  }

  /**
   * Address: 0x007F2AC0 (FUN_007F2AC0, sub_7F2AC0)
   *
   * What it does:
   * Clears one blueprint-extractor RB-tree lane, then resets head links
   * (`parent/left/right`) and size metadata to empty.
   */
  [[maybe_unused]] BlueprintExtractorTreeNodeRuntimeView* ResetBlueprintExtractorTreeStorage(
    BlueprintExtractorTreeNodeRuntimeView* const head,
    std::uint32_t& sizeLane
  ) noexcept
  {
    if (head == nullptr) {
      sizeLane = 0u;
      return nullptr;
    }

    DestroyBlueprintExtractorTreeNodesRecursive(head->mParent);
    head->mParent = head;
    sizeLane = 0u;
    head->mLeft = head;
    head->mRight = head;
    return head;
  }

  /**
   * Address: 0x007F1C50 (FUN_007F1C50, blueprint extractor map lower-bound lane)
   *
   * What it does:
   * Returns one lower-bound iterator for `extractorName` in the global
   * extractor registry map.
   */
  [[nodiscard]] BlueprintExtractorRegistry::iterator FindBlueprintExtractorLowerBound(
    BlueprintExtractorRegistry& registry,
    const std::string& extractorName
  )
  {
    return registry.lower_bound(extractorName);
  }

  /**
   * Address: 0x007F01D0 (FUN_007F01D0)
   *
   * IDA signature:
   * _DWORD *__usercall sub_7F01D0@<eax>(std::string *a1@<eax>, _DWORD *a2@<esi>);
   *
   * What it does:
   * Runs `std::map<std::string, std::unique_ptr<RangeExtractor>>::find`
   * for `extractorName` against `sBlueprintExtractors`: walks to the
   * lower-bound node, then when the pivot is not the end sentinel tests
   * `extractorName < pivot.key`; if that comparison succeeds the lookup
   * returns the end sentinel, otherwise it returns the pivot iterator.
   * The output slot `outIterator` receives either the resolved node or
   * the end sentinel, matching the release binary's `{pivot, isEnd}`
   * triplet used by callers in the range-extractor render and ranges
   * paths.
   */
  BlueprintExtractorRegistry::iterator* FindBlueprintExtractorRegistryEntry(
    BlueprintExtractorRegistry& registry,
    const std::string& extractorName,
    BlueprintExtractorRegistry::iterator* const outIterator
  )
  {
    if (outIterator == nullptr) {
      return nullptr;
    }

    const auto pivot = FindBlueprintExtractorLowerBound(registry, extractorName);
    if (pivot == registry.end() || extractorName < pivot->first) {
      *outIterator = registry.end();
    } else {
      *outIterator = pivot;
    }
    return outIterator;
  }

  /**
   * Address: 0x007F1880 (FUN_007F1880)
   *
   * What it does:
   * Returns the current number of registered blueprint extractor entries.
   */
  [[maybe_unused]] [[nodiscard]] std::size_t GetBlueprintExtractorRegistrySizeLane() noexcept
  {
    return GetBlueprintExtractorRegistry().size();
  }

  /**
   * Address: 0x007F00A0 (FUN_007F00A0, IDA's own demangled name:
   * `std::map_string_RangeExtractor::find`)
   * Address: 0x007F0960 (FUN_007F0960, this `find` emission's insert-if-
   * absent fallback core -- reached when the lower-bound candidate
   * (`sub_7F1C50`, cited above on `FindBlueprintExtractorLowerBound`)
   * doesn't compare equal, matching `operator[]`'s real semantics: find
   * first, then buy/insert a new node holding a default-constructed
   * `std::unique_ptr<RangeExtractor>` on miss)
   *
   * Both are generic Dinkumware `std::_Tree` internals for
   * `BlueprintExtractorRegistry` (`std::map<std::string,
   * std::unique_ptr<RangeExtractor>>`, real `std::map` per this map's own
   * "container substitution note" above -- `unique_ptr` can't live in the
   * project's `msvc8::map`). `registry[blueprintRangeName] =
   * std::move(extractor)` below is `operator[]`'s real source-level
   * invocation, which the compiler expands to exactly this `find`-then-
   * insert-on-miss pair; called 12x from `InitializeBlueprintExtractors`'s
   * `RegisterExtractor` calls (one per registered extractor type),
   * confirmed via `FUN_007F00A0`'s own 12 real callers all owned by
   * `FUN_007ED4B0` (`InitializeBlueprintExtractors`, already recovered
   * above).
   *
   * Address: 0x007F1890 (FUN_007F1890) -- the same instantiation's
   * `_Tree::_Buynode`-shaped node allocate-and-link step: walks
   * `Moho::sBlueprintExtractors._Myhead`'s parent/leftmost-descent chain
   * to find the real insertion point, allocates and links the fresh
   * `pair<const std::string, std::unique_ptr<RangeExtractor>>` node.
   * Called directly from `FUN_007F0960` above (`*a2 =
   * *(DWORD*)sub_7F1890();`), the same `operator[]` insert-on-miss path.
   */
  void RegisterExtractor(
    BlueprintExtractorRegistry& registry,
    const char* const blueprintRangeName,
    std::unique_ptr<moho::RangeExtractor> extractor
  )
  {
    if (!blueprintRangeName || !extractor) {
      return;
    }

    registry[blueprintRangeName] = std::move(extractor);
  }

  [[nodiscard]] std::unique_ptr<moho::RangeExtractor>
  CreateWeaponExtractor(const moho::UnitWeaponRangeCategory rangeCategory)
  {
    auto extractor = std::make_unique<moho::WeaponExtractor>();
    extractor->mRangeCategory = static_cast<std::int32_t>(rangeCategory);
    return extractor;
  }

  void PopulateBlueprintExtractors(BlueprintExtractorRegistry& registry)
  {
    RegisterExtractor(registry, "AllMilitary", std::make_unique<moho::CombinedMilitaryExtractor>());
    RegisterExtractor(registry, "DirectFire", CreateWeaponExtractor(moho::UWRC_DirectFire));
    RegisterExtractor(registry, "IndirectFire", CreateWeaponExtractor(moho::UWRC_IndirectFire));
    RegisterExtractor(registry, "AntiAir", CreateWeaponExtractor(moho::UWRC_AntiAir));
    RegisterExtractor(registry, "AntiNavy", CreateWeaponExtractor(moho::UWRC_AntiNavy));
    RegisterExtractor(registry, "Defense", std::make_unique<moho::CountermeasureExtractor>());
    RegisterExtractor(registry, "Miscellaneous", std::make_unique<moho::MiscellaneousExtractor>());
    RegisterExtractor(registry, "AllIntel", std::make_unique<moho::IntelExtractor>());
    RegisterExtractor(registry, "Radar", std::make_unique<moho::RadarExtractor>());
    RegisterExtractor(registry, "Sonar", std::make_unique<moho::SonarExtractor>());
    RegisterExtractor(registry, "Omni", std::make_unique<moho::OmniExtractor>());
    RegisterExtractor(registry, "CounterIntel", std::make_unique<moho::CounterIntelExtractor>());
  }

  struct ExtractorVtableOnlyRuntimeView
  {
    void* vtable = nullptr; // +0x00
  };
  static_assert(sizeof(ExtractorVtableOnlyRuntimeView) == 0x04, "ExtractorVtableOnlyRuntimeView size must be 0x04");

  struct WeaponExtractorCtorRuntimeView
  {
    void* vtable = nullptr;         // +0x00
    std::int32_t rangeCategory = 0; // +0x04
  };
  static_assert(sizeof(WeaponExtractorCtorRuntimeView) == 0x08, "WeaponExtractorCtorRuntimeView size must be 0x08");
  static_assert(
    offsetof(WeaponExtractorCtorRuntimeView, rangeCategory) == 0x04,
    "WeaponExtractorCtorRuntimeView::rangeCategory offset must be 0x04"
  );

  template <typename RuntimeViewT>
  [[nodiscard]] RuntimeViewT* RebindExtractorVtable(RuntimeViewT* const runtimeView, void* const vtableTag) noexcept
  {
    if (runtimeView != nullptr) {
      runtimeView->vtable = vtableTag;
    }
    return runtimeView;
  }

  [[nodiscard]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointer() noexcept
  {
    return &GetBlueprintExtractorRegistry();
  }

  /**
   * Address: 0x007EC590 (FUN_007EC590)
   *
   * What it does:
   * Rebinds one runtime lane to the base `RangeExtractor` vtable tag.
   */
  /**
   * The sibling emissions of this same vptr fixup, one per class whose
   * constructor or destructor writes a vtable into the lane. They were
   * recovered as seventeen separate free functions, every one of them
   * referenced by nothing (several were literally `return LaneA(view);`).
   *
   * No source line produces these: MSVC writes the vptr as part of ctor/dtor
   * codegen, so there is nothing to call and nothing to invent a caller for.
   * The addresses are kept here so they stay traceable.
   *
   * Address: 0x007EC380  base, void-adapter shape
   * Address: 0x007EC580  base, LaneD secondary
   * Address: 0x007EC860  base
   * Address: 0x007ECBF0  base
   * Address: 0x007EDBD0  base
   * Address: 0x007EDBE0  base
   * Address: 0x007EDBF0  base
   * Address: 0x007EDC00  base
   * Address: 0x007EDC10  base
   * Address: 0x007EDC20  base
   * Address: 0x007EC870  Moho::CountermeasureExtractor
   * Address: 0x007EDAB0  Moho::MiscellaneousExtractor
   * Address: 0x007EDAC0  Moho::IntelExtractor
   * Address: 0x007EDAD0  Moho::RadarExtractor
   * Address: 0x007EDAE0  Moho::SonarExtractor
   * Address: 0x007EDAF0  Moho::OmniExtractor
   * Address: 0x007EDB00  Moho::CounterIntelExtractor
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sRangeExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sRangeExtractorVtableTag);
  }



  /**
   * Address: 0x007EC5A0 (FUN_007EC5A0)
   *
   * What it does:
   * Initializes one weapon-extractor runtime lane by rebinding vtable state and
   * storing the weapon-range category lane at `+0x04`.
   */
  [[maybe_unused]] WeaponExtractorCtorRuntimeView* InitializeWeaponExtractorRangeCategoryLaneA(
    WeaponExtractorCtorRuntimeView* const runtimeView,
    const std::int32_t rangeCategory
  ) noexcept
  {
    static std::uint8_t sWeaponExtractorVtableTag = 0;
    auto* const initialized = RebindExtractorVtable(runtimeView, &sWeaponExtractorVtableTag);
    if (initialized != nullptr) {
      initialized->rangeCategory = rangeCategory;
    }
    return initialized;
  }
















  /**
   * Address: 0x007F1CB0 (FUN_007F1CB0)
   *
   * What it does:
   * Returns the process-global blueprint extractor registry pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneA(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F2CA0 (FUN_007F2CA0)
   *
   * What it does:
   * Secondary lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneB(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F3040 (FUN_007F3040)
   *
   * What it does:
   * Third lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneC(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F32C0 (FUN_007F32C0)
   *
   * What it does:
   * Fourth lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneD(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  struct FactoryCommandQueueRangeView
  {
    std::uint8_t pad_0000_0460[0x460];
    float guardScanRadius;           // +0x460
    float guardReturnRadius;         // +0x464
    float stagingPlatformScanRadius; // +0x468
  };

  static_assert(
    offsetof(FactoryCommandQueueRangeView, guardScanRadius) == 0x460,
    "FactoryCommandQueueRangeView::guardScanRadius offset must be 0x460"
  );
  static_assert(
    offsetof(FactoryCommandQueueRangeView, stagingPlatformScanRadius) == 0x468,
    "FactoryCommandQueueRangeView::stagingPlatformScanRadius offset must be 0x468"
  );
}

namespace moho
{
  /**
   * Address: 0x00A82547 (_purecall slot in abstract base)
   */
  RangeExtractor::~RangeExtractor() = default;

  float RangeExtractor::ResolvePositiveRadius(const float preferredRadius, const float fallbackRadius) noexcept
  {
    return preferredRadius > 0.0f ? preferredRadius : fallbackRadius;
  }

  bool RangeExtractor::StoreRangeAtCenter(
    SRangeExtractionPayload* const outRange,
    const Wm3::Vec3f& center,
    const float outerRadius,
    const float innerRadius
  ) noexcept
  {
    if (!outRange || outerRadius <= 0.0f) {
      return false;
    }

    outRange->centerX = center.x;
    outRange->centerZ = center.z;
    outRange->innerRadius = innerRadius;
    outRange->outerRadius = outerRadius;
    return true;
  }

  bool RangeExtractor::StoreRangeAtEntity(
    SRangeExtractionPayload* const outRange,
    const UserEntity& userEntity,
    const float interpolationAlpha,
    const float outerRadius,
    const float innerRadius
  )
  {
    if (!outRange || outerRadius <= 0.0f) {
      return false;
    }

    const VTransform transform = userEntity.GetInterpolatedTransform(interpolationAlpha);
    outRange->centerX = transform.pos_.x;
    outRange->centerZ = transform.pos_.z;
    outRange->innerRadius = innerRadius;
    outRange->outerRadius = outerRadius;
    return true;
  }

  bool RangeExtractor::TryGetFactoryOverlayRadius(const UserUnit* const userUnit, float* const outRadius) noexcept
  {
    if (!userUnit || !outRadius) {
      return false;
    }

    const UserCommandQueue* const factoryQueue = userUnit->GetFactoryCommandQueue();
    if (factoryQueue == nullptr) {
      *outRadius = 0.0f;
      return false;
    }

    const auto* const commandQueue = reinterpret_cast<const FactoryCommandQueueRangeView*>(factoryQueue);
    const float radius = ResolvePositiveRadius(commandQueue->stagingPlatformScanRadius, commandQueue->guardScanRadius);
    *outRadius = radius;
    return radius > 0.0f;
  }

  bool RangeExtractor::TryGetIntelRanges(
    const UserEntity* const userEntity,
    float* const outOmniRange,
    float* const outRadarRange,
    float* const outSonarRange
  )
  {
    if (!userEntity || !outOmniRange || !outRadarRange || !outSonarRange) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    return userUnit && userUnit->GetIntelRanges(outOmniRange, outRadarRange, outSonarRange);
  }

  bool RangeExtractor::TryGetWeaponRangeByCategory(
    const UserEntity* const userEntity,
    const std::int32_t rangeCategoryFilter,
    float* const outInnerRadius,
    float* const outOuterRadius
  )
  {
    if (!userEntity || !outInnerRadius || !outOuterRadius) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    return userUnit && userUnit->FindWeaponBy(rangeCategoryFilter, outInnerRadius, outOuterRadius);
  }

  /**
   * Address: 0x007ED4B0 (FUN_007ED4B0, Moho::sBlueprintExtractors::sBlueprintExtractors)
   *
   * What it does:
   * Rebuilds the global blueprint range-extractor registry and installs
   * all known extractor instances by blueprint key.
   *
   * Container substitution note: the real binary's tree-erase/clear core
   * for `sBlueprintExtractors` (FUN_007F1990, a `msvc8::map`-shaped
   * `erase(first,last)`/`clear()` walk) is deliberately NOT cited on
   * `registry.clear()` above. `BlueprintExtractorRegistry` holds
   * `std::unique_ptr<moho::RangeExtractor>` values -- a move-only owning
   * smart pointer this project's binary-layout-focused `msvc8::map` has no
   * way to model or store -- so the real `std::map` here is an intentional
   * substitution, not a fidelity gap to migrate away. `FUN_007F1990` marked
   * `skip` for this reason.
   */
  void InitializeBlueprintExtractors()
  {
    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    registry.clear();
    PopulateBlueprintExtractors(registry);
    gBlueprintExtractorsInitialized = true;
  }

  /**
   * Address: 0x007ED9A0 (FUN_007ED9A0, Moho::sBlueprintExtractors::~sBlueprintExtractors)
   *
   * What it does:
   * Destroys the global blueprint range-extractor registry and releases
   * all registered extractor instances.
   */
  void ShutdownBlueprintExtractors()
  {
    if (!gBlueprintExtractorsInitialized) {
      return;
    }

    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    registry.clear();
    gBlueprintExtractorsInitialized = false;
  }

  /**
   * Address: 0x007EDA40 (FUN_007EDA40)
   *
   * msvc8::string const &
   *
   * What it does:
   * Looks up a registered extractor by blueprint range key and returns
   * the associated instance, or `nullptr` when no mapping exists.
   */
  RangeExtractor* GetRangeExtractor(const msvc8::string& extractorName)
  {
    if (!gBlueprintExtractorsInitialized) {
      InitializeBlueprintExtractors();
    }

    if (!extractorName.basic_sanity()) {
      return nullptr;
    }

    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    const std::string rangeKey(extractorName.data(), extractorName.size());

    // Mirror the release binary's `map::find` lane through the recovered
    // helper so the lower-bound + "strictly less than" check sequence
    // observed in FUN_007F01D0 stays invocable by name.
    BlueprintExtractorRegistry::iterator foundEntry{};
    (void)FindBlueprintExtractorRegistryEntry(registry, rangeKey, &foundEntry);
    if (foundEntry == registry.end()) {
      return nullptr;
    }

    return foundEntry->second.get();
  }
} // namespace moho
