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
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sRangeExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sRangeExtractorVtableTag);
  }

  /**
   * Address: 0x007EC380 (FUN_007EC380)
   *
   * What it does:
   * Rebinds one runtime lane to the base `RangeExtractor` vtable tag
   * through a void-return adapter shape.
   */
  [[maybe_unused]] void RebindRangeExtractorBaseVtableVoidAdapter(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    (void)RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EC580 (FUN_007EC580)
   *
   * What it does:
   * Rebinds one runtime lane to the base `RangeExtractor` vtable tag through
   * an explicit return-value adapter lane.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneD_Secondary(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
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
   * Address: 0x007EC860 (FUN_007EC860)
   *
   * What it does:
   * Secondary lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneB(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EC870 (FUN_007EC870)
   *
   * What it does:
   * Rebinds one runtime lane to the `CountermeasureExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindCountermeasureExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sCountermeasureExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sCountermeasureExtractorVtableTag);
  }

  /**
   * Address: 0x007ECBF0 (FUN_007ECBF0)
   *
   * What it does:
   * Third lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneC(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDAB0 (FUN_007EDAB0)
   *
   * What it does:
   * Rebinds one runtime lane to the `MiscellaneousExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindMiscellaneousExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sMiscellaneousExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sMiscellaneousExtractorVtableTag);
  }

  /**
   * Address: 0x007EDAC0 (FUN_007EDAC0)
   *
   * What it does:
   * Rebinds one runtime lane to the `IntelExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindIntelExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sIntelExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sIntelExtractorVtableTag);
  }

  /**
   * Address: 0x007EDAD0 (FUN_007EDAD0)
   *
   * What it does:
   * Rebinds one runtime lane to the `RadarExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRadarExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sRadarExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sRadarExtractorVtableTag);
  }

  /**
   * Address: 0x007EDAE0 (FUN_007EDAE0)
   *
   * What it does:
   * Rebinds one runtime lane to the `SonarExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindSonarExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sSonarExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sSonarExtractorVtableTag);
  }

  /**
   * Address: 0x007EDAF0 (FUN_007EDAF0)
   *
   * What it does:
   * Rebinds one runtime lane to the `OmniExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindOmniExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sOmniExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sOmniExtractorVtableTag);
  }

  /**
   * Address: 0x007EDB00 (FUN_007EDB00)
   *
   * What it does:
   * Rebinds one runtime lane to the `CounterIntelExtractor` vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindCounterIntelExtractorVtableLaneA(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sCounterIntelExtractorVtableTag = 0;
    return RebindExtractorVtable(runtimeView, &sCounterIntelExtractorVtableTag);
  }

  /**
   * Address: 0x007EDBD0 (FUN_007EDBD0)
   *
   * What it does:
   * Fourth lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneD(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDBE0 (FUN_007EDBE0)
   *
   * What it does:
   * Fifth lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneE(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDBF0 (FUN_007EDBF0)
   *
   * What it does:
   * Sixth lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneF(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDC00 (FUN_007EDC00)
   *
   * What it does:
   * Seventh lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneG(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDC10 (FUN_007EDC10)
   *
   * What it does:
   * Eighth lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneH(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
  }

  /**
   * Address: 0x007EDC20 (FUN_007EDC20)
   *
   * What it does:
   * Ninth lane that rebinds one runtime lane to the base `RangeExtractor`
   * vtable tag.
   */
  [[maybe_unused]] ExtractorVtableOnlyRuntimeView* RebindRangeExtractorBaseVtableLaneI(
    ExtractorVtableOnlyRuntimeView* const runtimeView
  ) noexcept
  {
    return RebindRangeExtractorBaseVtableLaneA(runtimeView);
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

    const auto commandQueueWord = static_cast<std::uint32_t>(userUnit->GetFactoryCommandQueue2());
    if (commandQueueWord == 0u) {
      *outRadius = 0.0f;
      return false;
    }

    const auto* const commandQueue =
      reinterpret_cast<const FactoryCommandQueueRangeView*>(static_cast<std::uintptr_t>(commandQueueWord));
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
