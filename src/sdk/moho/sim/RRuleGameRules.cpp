#include "RRuleGameRules.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>

#include "boost/thread.h"
#include "../resource/RResId.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Tree.h"
#include "lua/LuaObject.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_String.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/StatItem.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/BlueprintLoaderContext.h"
#include "moho/sim/CBackgroundTaskControl.h"

namespace moho
{
  namespace
  {
    struct LuaTaskListNode
    {
      LuaTaskListNode* next;    // +0x00
      LuaTaskListNode* prev;    // +0x04
      void* taskThread;         // +0x08
      std::uint32_t reserved0C; // +0x0C
      std::uint8_t isOwning;    // +0x10
      std::uint8_t isSentinel;  // +0x11
      std::uint8_t pad12[2];    // +0x12
    };

    static_assert(sizeof(LuaTaskListNode) == 0x14, "LuaTaskListNode size must be 0x14");

    struct LuaReloadRequestNode
    {
      LuaReloadRequestNode* next; // +0x00
      LuaReloadRequestNode* prev; // +0x04
      float reloadAtSeconds;      // +0x08
      msvc8::string sourcePath;   // +0x0C
      std::uint32_t reserved28;   // +0x28
    };

    static_assert(sizeof(LuaReloadRequestNode) == 0x2C, "LuaReloadRequestNode size must be 0x2C");

    /**
     * Address: 0x00528260 (FUN_00528260, Moho::LuaReloadRequestNode::LuaReloadRequestNode)
     *
     * IDA signature:
     * int __userpurge sub_528260@<eax>(float a1@<xmm0>, int a2, std::string *str1);
     *
     * What it does:
     * In-place constructs one `LuaReloadRequestNode` at `node`: self-links the
     * intrusive `next`/`prev` lanes to form a detached singleton, stores the
     * caller-supplied scheduled reload deadline (`reloadAtSeconds`), then
     * default-constructs the inline `msvc8::string` lane and immediately
     * `assign`s it from `sourcePath`. The trailing reserved dword at +0x28 is
     * zeroed. Returns `node` for chaining at the call site (binary leaves the
     * fresh node pointer in `eax`).
     *
     * Per-T named free helper that the compiler binds to the engine's typed
     * out-of-line ctor body. Callers invoke this helper by explicit name on
     * a freshly `operator new`'d node — never by relying on
     * `LuaReloadRequestNode{deadline, std::move(path)}` aggregate
     * initialization, which the compiler can inline away.
     */
    [[nodiscard]] LuaReloadRequestNode* ConstructLuaReloadRequestNode(
      LuaReloadRequestNode* const node,
      const float reloadAtSeconds,
      const msvc8::string& sourcePath)
    {
      if (!node) {
        return nullptr;
      }

      node->next = node;
      node->prev = node;
      node->reloadAtSeconds = reloadAtSeconds;
      ::new (static_cast<void*>(&node->sourcePath)) msvc8::string{};
      node->sourcePath.assign(sourcePath, 0u, msvc8::string::npos);
      node->reserved28 = 0u;
      return node;
    }

    struct BlueprintMapHeadNodeRuntimeView
    {
      std::uint32_t parent = 0;      // +0x00
      std::uint32_t left = 0;        // +0x04
      std::uint32_t right = 0;       // +0x08
      std::uint8_t reserved0C[0x20]{}; // +0x0C
      std::uint8_t color = 0;        // +0x2C
      std::uint8_t isNil = 0;        // +0x2D
      std::uint8_t reserved2E[0x2]{}; // +0x2E
    };
    static_assert(
      offsetof(BlueprintMapHeadNodeRuntimeView, color) == 0x2C,
      "BlueprintMapHeadNodeRuntimeView::color offset must be 0x2C"
    );
    static_assert(
      offsetof(BlueprintMapHeadNodeRuntimeView, isNil) == 0x2D,
      "BlueprintMapHeadNodeRuntimeView::isNil offset must be 0x2D"
    );
    static_assert(sizeof(BlueprintMapHeadNodeRuntimeView) == 0x30, "BlueprintMapHeadNodeRuntimeView size must be 0x30");

    /**
     * Address: 0x0052F740 (FUN_0052F740)
     *
     * What it does:
     * Allocates one 48-byte map-head node and seeds legacy tree header lanes
     * (`left/parent/right = 0`, `color = 1`, `isNil = 0`).
     */
    [[nodiscard]] BlueprintMapHeadNodeRuntimeView* AllocateBlueprintMapHeadNodeRuntime()
    {
      auto* const node = static_cast<BlueprintMapHeadNodeRuntimeView*>(gpg::core::legacy::AllocateChecked48ByteLane(1u));
      if (node != nullptr) {
        node->parent = 0;
      }
      if (node != reinterpret_cast<BlueprintMapHeadNodeRuntimeView*>(-4)) {
        node->left = 0;
      }
      if (node != reinterpret_cast<BlueprintMapHeadNodeRuntimeView*>(-8)) {
        node->right = 0;
      }
      node->color = 1;
      node->isNil = 0;
      return node;
    }

    /**
     * Address: 0x0052F740 (FUN_0052F740)
     *
     * What it does:
     * Allocates and zero-seeds one unit-blueprint map head node with legacy
     * tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateUnitBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    /**
     * Address: 0x0052FAE0 (FUN_0052FAE0)
     *
     * What it does:
     * Allocates and zero-seeds one projectile-blueprint map head node with the
     * legacy tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateProjectileBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    /**
     * Address: 0x0052FE80 (FUN_0052FE80)
     *
     * What it does:
     * Allocates and zero-seeds one prop-blueprint map head node with the
     * legacy tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocatePropBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    /**
     * Address: 0x00530220 (FUN_00530220)
     *
     * What it does:
     * Allocates and zero-seeds one mesh-blueprint map head node with the
     * legacy tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateMeshBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    /**
     * Address: 0x005305D0 (FUN_005305D0)
     *
     * What it does:
     * Allocates and zero-seeds one emitter-blueprint map head node with the
     * legacy tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateEmitterBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    /**
     * Address: 0x00530980 (FUN_00530980)
     *
     * What it does:
     * Allocates and zero-seeds one beam-blueprint map head node with the
     * legacy tree color/isNil defaults.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateBeamBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    [[nodiscard]] RRuleGameRulesBlueprintNode* AllocateTrailBlueprintMapHeadNode()
    {
      return reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
    }

    using BlueprintMapHeadAllocator = RRuleGameRulesBlueprintNode* (*)();

    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeBlueprintMapHeaderWithAllocator(
      RRuleGameRulesBlueprintMap* const map,
      const BlueprintMapHeadAllocator allocateHead
    )
    {
      map->mHead = allocateHead();
      map->mHead->mIsSentinel = 1u;
      map->mHead->parent = map->mHead;
      map->mHead->left = map->mHead;
      map->mHead->right = map->mHead;
      map->mSize = 0u;
      return map;
    }

    [[nodiscard]] std::string BuildInstanceCounterStatPathLocal(const char* const rawTypeName)
    {
      std::string path("Instance Counts_");
      if (!rawTypeName) {
        return path;
      }

      for (const char* it = rawTypeName; *it != '\0'; ++it) {
        if (*it != '_') {
          path.push_back(*it);
        }
      }

      return path;
    }

    [[nodiscard]] int CompareLex(const std::string_view lhs, const std::string_view rhs) noexcept
    {
      const std::size_t common = std::min(lhs.size(), rhs.size());
      if (common > 0) {
        const int prefix = std::char_traits<char>::compare(lhs.data(), rhs.data(), common);
        if (prefix != 0) {
          return prefix;
        }
      }

      if (lhs.size() < rhs.size()) {
        return -1;
      }
      if (lhs.size() > rhs.size()) {
        return 1;
      }
      return 0;
    }

    [[nodiscard]] int CompareBlueprintIds(const msvc8::string& lhs, const msvc8::string& rhs) noexcept
    {
      return CompareLex(lhs.view(), rhs.view());
    }

    /**
     * Address: 0x0052E060 (FUN_0052E060)
     * Address: 0x0052E240 (FUN_0052E240)
     * Address: 0x0052E420 (FUN_0052E420)
     * Address: 0x0052E600 (FUN_0052E600)
     * Address: 0x0052E7D0 (FUN_0052E7D0)
     * Address: 0x0052EB70 (FUN_0052EB70)
     *
     * What it does:
     * Performs one red-black-tree lower-bound walk on blueprint-id keyed map
     * lanes and returns the first node whose key is not less than `lookupId`.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    LowerBoundBlueprintNodeById(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      return msvc8::lower_bound_node<RRuleGameRulesBlueprintNode, &RRuleGameRulesBlueprintNode::mIsSentinel>(
        map.mHead, lookupId, [](const RRuleGameRulesBlueprintNode& node, const msvc8::string& query) {
          return CompareBlueprintIds(node.mBlueprintId, query) < 0;
        }
      );
    }

    struct RRuleGameRulesMapOwnerRuntimeView
    {
      std::uint32_t lane00 = 0u;           // +0x00
      RRuleGameRulesBlueprintMap* map = nullptr; // +0x04
    };
    static_assert(
      offsetof(RRuleGameRulesMapOwnerRuntimeView, map) == 0x04,
      "RRuleGameRulesMapOwnerRuntimeView::map offset must be 0x04"
    );

  } // namespace

  // EntityCategoryLookupTableRuntimeView (and the node/map views it owns) is
  // deliberately NOT in the anonymous namespace above: RRuleGameRules.h
  // forward-declares it by name so `RRuleGameRulesImpl::mEntityCategoryLookup`
  // can be a real typed pointer instead of `void*`. An anonymous-namespace definition
  // here would be a distinct per-TU type that could never complete that
  // forward declaration.
  namespace
  {
    struct CategoryLookupNodeRuntimeView : msvc8::Tree<CategoryLookupNodeRuntimeView>
    {
      std::uint8_t color;         // +0x0C
      std::uint8_t reserved0D;    // +0x0D
      std::uint8_t reserved0E;    // +0x0E
      std::uint8_t reserved0F;    // +0x0F
      msvc8::string key;          // +0x10
      std::uint8_t pad_2C_2F[4];  // +0x2C
      CategoryWordRangeView value; // +0x30
      std::uint8_t nodeState;     // +0x58
      std::uint8_t isNil;         // +0x59
      std::uint8_t pad_5A_5B[2];  // +0x5A
    };
    static_assert(offsetof(CategoryLookupNodeRuntimeView, key) == 0x10, "CategoryLookupNodeRuntimeView::key offset");
    static_assert(
      offsetof(CategoryLookupNodeRuntimeView, value) == 0x30, "CategoryLookupNodeRuntimeView::value offset"
    );
    static_assert(
      offsetof(CategoryLookupNodeRuntimeView, isNil) == 0x59, "CategoryLookupNodeRuntimeView::isNil offset"
    );
    static_assert(sizeof(CategoryLookupNodeRuntimeView) == 0x5C, "CategoryLookupNodeRuntimeView size must be 0x5C");

    struct CategoryLookupMapRuntimeView
    {
      std::uint32_t unknown00;               // +0x00
      CategoryLookupNodeRuntimeView* head;   // +0x04
      std::uint32_t size;                    // +0x08
      std::uint32_t unknown0C;               // +0x0C
    };
    static_assert(sizeof(CategoryLookupMapRuntimeView) == 0x10, "CategoryLookupMapRuntimeView size must be 0x10");
  } // namespace

  struct EntityCategoryLookupTableRuntimeView
  {
    CategoryLookupMapRuntimeView categoryMap; // +0x00
    CategoryWordRangeView categoryFallback;   // +0x10
    std::uint32_t wordUniverseHandle;         // +0x38
    std::uint8_t pad_003C_003F[0x04];         // +0x3C (binary leaves this unwritten; not initialized here either)

    /**
     * Address: 0x005551F0 (FUN_005551F0, Moho::EntityCategorySet::EntityCategorySet)
     *
     * What it does:
     * In-place constructs the (empty, sentinel-headed) category-name map and
     * the fallback `CategoryWordRangeView`, seeding both the fallback's
     * universe lane and the trailing `wordUniverseHandle` with `owner`
     * reinterpreted as a 4-byte handle - the same raw pointer value the
     * binary writes to +0x10 and +0x38.
     */
    explicit EntityCategoryLookupTableRuntimeView(const RRuleGameRulesImpl* owner) noexcept;

    /**
     * Address: 0x00533E20 (FUN_00533E20, Moho::EntityCategory::~EntityCategory)
     *
     * What it does:
     * Frees every category-name map node and the sentinel head itself.
     * Leaves `categoryFallback` / `wordUniverseHandle` untouched, exactly as
     * the binary does - those lanes own no heap storage of their own.
     *
     * Mangled-name note: the binary's constructor mangles as
     * `Moho::EntityCategorySet::EntityCategorySet` but this destructor
     * mangles as `Moho::EntityCategory::~EntityCategory` - a different class
     * name over the identical `this` layout (most likely an
     * EntityCategorySet-derives-from-EntityCategory relationship where the
     * derived class adds no members and never gets its own destructor
     * symbol). Both of those binary names are already taken in this codebase
     * by unrelated types (`Moho::EntityCategorySet` = the 0x28-byte
     * `BVSet<const RBlueprint*, EntityCategoryHelper>` alias in
     * EntityCategoryReflection.h; `Moho::EntityCategory` = the static-method
     * utility class in the same header), so this object keeps its
     * pre-existing source-level name here instead of colliding with either.
     */
    ~EntityCategoryLookupTableRuntimeView();

    EntityCategoryLookupTableRuntimeView(const EntityCategoryLookupTableRuntimeView&) = delete;
    EntityCategoryLookupTableRuntimeView& operator=(const EntityCategoryLookupTableRuntimeView&) = delete;
  };
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, categoryMap) == 0x00,
    "EntityCategoryLookupTableRuntimeView::categoryMap offset"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, categoryFallback) == 0x10,
    "EntityCategoryLookupTableRuntimeView::categoryFallback offset"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, wordUniverseHandle) == 0x38,
    "EntityCategoryLookupTableRuntimeView::wordUniverseHandle offset"
  );
  static_assert(
    sizeof(EntityCategoryLookupTableRuntimeView) == 0x40,
    "EntityCategoryLookupTableRuntimeView size must be 0x40"
  );

  namespace
  {
    struct RRuleGameRulesCtorPrefixRuntimeView
    {
      std::uint32_t unknown04; // +0x00 (absolute +0x04 in RRuleGameRulesImpl)
      CDiskWatchListener listener;
    };
    static_assert(
      offsetof(RRuleGameRulesCtorPrefixRuntimeView, listener) == 0x04,
      "RRuleGameRulesCtorPrefixRuntimeView::listener offset must be 0x04"
    );
    static_assert(
      sizeof(RRuleGameRulesCtorPrefixRuntimeView) == 0x34,
      "RRuleGameRulesCtorPrefixRuntimeView size must be 0x34"
    );

    [[nodiscard]] RRuleGameRulesCtorPrefixRuntimeView& RuleCtorPrefixView(RRuleGameRulesImpl& rules) noexcept
    {
      return *reinterpret_cast<RRuleGameRulesCtorPrefixRuntimeView*>(&rules.pad_0004[0]);
    }

    // The rules keep their lock inline at +0x38, so it is stored as raw bytes
    // to preserve the layout and constructed in place by the constructor.
    static_assert(
      sizeof(boost::mutex) <= 0x08, "boost::mutex must fit RRuleGameRulesImpl::mLockStorage at +0x38"
    );

    [[nodiscard]] boost::mutex& RuleMutexView(RRuleGameRulesImpl& rules) noexcept
    {
      return *reinterpret_cast<boost::mutex*>(&rules.mLockStorage[0]);
    }

    [[nodiscard]] SRuleFootprintNode* AllocateFootprintSentinelNode() noexcept
    {
      auto* const sentinel = new (std::nothrow) SRuleFootprintNode{};
      if (sentinel == nullptr) {
        return nullptr;
      }

      sentinel->next = sentinel;
      sentinel->prev = sentinel;
      return sentinel;
    }

    [[nodiscard]] CategoryLookupNodeRuntimeView* AllocateCategoryLookupHeadNodeRuntime() noexcept
    {
      auto* const head = new (std::nothrow) CategoryLookupNodeRuntimeView{};
      if (head == nullptr) {
        return nullptr;
      }

      head->left = head;
      head->parent = head;
      head->right = head;
      head->color = 1u;
      head->nodeState = 0u;
      head->isNil = 1u;
      return head;
    }

    // Red-black colour encoding shared by the category-name map's rotate /
    // erase helpers below, matching the binary's `_Color` byte (0 = red,
    // 1 = black) - the same encoding `AllocateCategoryLookupHeadNodeRuntime`
    // above already uses for the sentinel head (`head->color = 1u`).
    constexpr std::uint8_t kCategoryLookupNodeRed = 0u;
    constexpr std::uint8_t kCategoryLookupNodeBlack = 1u;

    /**
     * Address: 0x0052D960 (FUN_0052D960)
     *
     * What it does:
     * Walks left from `node` to the leftmost (minimum-key) real descendant.
     */
    [[nodiscard]] CategoryLookupNodeRuntimeView* LeftmostCategoryLookupDescendant(
      CategoryLookupNodeRuntimeView* node
    ) noexcept
    {
      while (node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    /**
     * Address: 0x00536AA0 (FUN_00536AA0)
     *
     * What it does:
     * Walks right from `node` to the rightmost (maximum-key) real descendant.
     */
    [[nodiscard]] CategoryLookupNodeRuntimeView* RightmostCategoryLookupDescendant(
      CategoryLookupNodeRuntimeView* node
    ) noexcept
    {
      while (node->right->isNil == 0u) {
        node = node->right;
      }
      return node;
    }

    /**
     * Address: 0x00536A50 (FUN_00536A50, MSVC8 `_Tree::_Lrotate`)
     *
     * What it does:
     * Rotates `node`'s right child up into `node`'s slot, re-parenting the
     * moved subtree and patching the table's root link when `node` was root.
     */
    void RotateCategoryLookupNodeLeft(
      EntityCategoryLookupTableRuntimeView& table, CategoryLookupNodeRuntimeView* const node
    ) noexcept
    {
      CategoryLookupNodeRuntimeView* const pivot = node->right;
      node->right = pivot->left;
      if (pivot->left->isNil == 0u) {
        pivot->left->parent = node;
      }
      pivot->parent = node->parent;

      CategoryLookupNodeRuntimeView* const head = table.categoryMap.head;
      if (node == head->parent) {
        head->parent = pivot;
      } else if (node == node->parent->left) {
        node->parent->left = pivot;
      } else {
        node->parent->right = pivot;
      }

      pivot->left = node;
      node->parent = pivot;
    }

    /**
     * Address: 0x00536AE0 (FUN_00536AE0, MSVC8 `_Tree::_Rrotate`)
     *
     * What it does:
     * Mirror of `RotateCategoryLookupNodeLeft`: lifts `node`'s left child
     * into `node`'s slot.
     */
    void RotateCategoryLookupNodeRight(
      EntityCategoryLookupTableRuntimeView& table, CategoryLookupNodeRuntimeView* const node
    ) noexcept
    {
      CategoryLookupNodeRuntimeView* const pivot = node->left;
      node->left = pivot->right;
      if (pivot->right->isNil == 0u) {
        pivot->right->parent = node;
      }
      pivot->parent = node->parent;

      CategoryLookupNodeRuntimeView* const head = table.categoryMap.head;
      if (node == head->parent) {
        head->parent = pivot;
      } else if (node == node->parent->right) {
        node->parent->right = pivot;
      } else {
        node->parent->left = pivot;
      }

      pivot->right = node;
      node->parent = pivot;
    }

    void AdvanceCategoryLookupNodeSuccessor(CategoryLookupNodeRuntimeView** const cursor) noexcept
    {
      CategoryLookupNodeRuntimeView* node = *cursor;
      if (node->isNil != 0u) {
        return;
      }

      CategoryLookupNodeRuntimeView* right = node->right;
      if (right->isNil != 0u) {
        CategoryLookupNodeRuntimeView* parent = node->parent;
        while (parent->isNil == 0u) {
          if (*cursor != parent->right) {
            break;
          }
          *cursor = parent;
          parent = parent->parent;
        }
        *cursor = parent;
        return;
      }

      CategoryLookupNodeRuntimeView* left = right->left;
      while (left->isNil == 0u) {
        right = left;
        left = left->left;
      }
      *cursor = right;
    }

    /**
     * Address: 0x00536010 (FUN_00536010, MSVC8 `_Tree::erase(const_iterator)`)
     *
     * What it does:
     * Unlinks and destroys `erased` from the category-name map: transplants
     * its in-order successor into its slot when both children are real,
     * relinks the fix-up child in `erased`'s place otherwise, then repairs
     * the black-height deficit from the stitched-up child upward (matching
     * `RotateCategoryLookupNodeLeft`/`Right`'s sibling-recolour/rotate
     * cases 1:1). Finally destroys `erased` - its `msvc8::string` key and
     * `CategoryWordRangeView` value release their own heap storage through
     * their real destructors, so no manual byte-level cleanup is needed
     * here - and decrements the map size (binary guards the decrement
     * against an already-zero count). Returns the in-order successor,
     * matching `std::map::erase`'s return convention.
     */
    CategoryLookupNodeRuntimeView* EraseCategoryLookupNode(
      EntityCategoryLookupTableRuntimeView& table, CategoryLookupNodeRuntimeView* const erased
    ) noexcept
    {
      CategoryLookupNodeRuntimeView* const head = table.categoryMap.head;

      CategoryLookupNodeRuntimeView* next = erased;
      AdvanceCategoryLookupNodeSuccessor(&next);

      CategoryLookupNodeRuntimeView* lifted = erased;
      CategoryLookupNodeRuntimeView* fix;
      CategoryLookupNodeRuntimeView* fixParent;

      if (erased->left->isNil != 0u) {
        fix = erased->right;
      } else if (erased->right->isNil != 0u) {
        fix = erased->left;
      } else {
        lifted = next; // in-order successor of a two-real-child node
        fix = lifted->right;
      }

      if (lifted == erased) {
        // At most one real subtree: relink it in place.
        fixParent = erased->parent;
        if (fix->isNil == 0u) {
          fix->parent = fixParent;
        }

        if (head->parent == erased) {
          head->parent = fix;
        } else if (fixParent->left == erased) {
          fixParent->left = fix;
        } else {
          fixParent->right = fix;
        }

        if (head->left == erased) {
          head->left = (fix->isNil != 0u) ? fixParent : LeftmostCategoryLookupDescendant(fix);
        }
        if (head->right == erased) {
          head->right = (fix->isNil != 0u) ? fixParent : RightmostCategoryLookupDescendant(fix);
        }
      } else {
        // Two real subtrees: `lifted` (the successor) takes the erased slot.
        erased->left->parent = lifted;
        lifted->left = erased->left;

        if (lifted == erased->right) {
          fixParent = lifted;
        } else {
          fixParent = lifted->parent;
          if (fix->isNil == 0u) {
            fix->parent = fixParent;
          }
          fixParent->left = fix;
          lifted->right = erased->right;
          erased->right->parent = lifted;
        }

        if (head->parent == erased) {
          head->parent = lifted;
        } else if (erased->parent->left == erased) {
          erased->parent->left = lifted;
        } else {
          erased->parent->right = lifted;
        }

        lifted->parent = erased->parent;
        std::swap(lifted->nodeState, erased->nodeState);
      }

      if (erased->nodeState == kCategoryLookupNodeBlack) {
        // MSVC8's post-erase black-height repair.
        for (; fix != head->parent && fix->nodeState == kCategoryLookupNodeBlack; fixParent = fix->parent) {
          if (fix == fixParent->left) {
            CategoryLookupNodeRuntimeView* sibling = fixParent->right;
            if (sibling->nodeState == kCategoryLookupNodeRed) {
              sibling->nodeState = kCategoryLookupNodeBlack;
              fixParent->nodeState = kCategoryLookupNodeRed;
              RotateCategoryLookupNodeLeft(table, fixParent);
              sibling = fixParent->right;
            }

            if (sibling->isNil != 0u) {
              fix = fixParent;
            } else if (sibling->left->nodeState == kCategoryLookupNodeBlack
                       && sibling->right->nodeState == kCategoryLookupNodeBlack) {
              sibling->nodeState = kCategoryLookupNodeRed;
              fix = fixParent;
            } else {
              if (sibling->right->nodeState == kCategoryLookupNodeBlack) {
                sibling->left->nodeState = kCategoryLookupNodeBlack;
                sibling->nodeState = kCategoryLookupNodeRed;
                RotateCategoryLookupNodeRight(table, sibling);
                sibling = fixParent->right;
              }
              sibling->nodeState = fixParent->nodeState;
              fixParent->nodeState = kCategoryLookupNodeBlack;
              sibling->right->nodeState = kCategoryLookupNodeBlack;
              RotateCategoryLookupNodeLeft(table, fixParent);
              break; // black heights match again; root is still black
            }
          } else {
            CategoryLookupNodeRuntimeView* sibling = fixParent->left;
            if (sibling->nodeState == kCategoryLookupNodeRed) {
              sibling->nodeState = kCategoryLookupNodeBlack;
              fixParent->nodeState = kCategoryLookupNodeRed;
              RotateCategoryLookupNodeRight(table, fixParent);
              sibling = fixParent->left;
            }

            if (sibling->isNil != 0u) {
              fix = fixParent;
            } else if (sibling->right->nodeState == kCategoryLookupNodeBlack
                       && sibling->left->nodeState == kCategoryLookupNodeBlack) {
              sibling->nodeState = kCategoryLookupNodeRed;
              fix = fixParent;
            } else {
              if (sibling->left->nodeState == kCategoryLookupNodeBlack) {
                sibling->right->nodeState = kCategoryLookupNodeBlack;
                sibling->nodeState = kCategoryLookupNodeRed;
                RotateCategoryLookupNodeLeft(table, sibling);
                sibling = fixParent->left;
              }
              sibling->nodeState = fixParent->nodeState;
              fixParent->nodeState = kCategoryLookupNodeBlack;
              sibling->left->nodeState = kCategoryLookupNodeBlack;
              RotateCategoryLookupNodeRight(table, fixParent);
              break;
            }
          }
        }
        fix->nodeState = kCategoryLookupNodeBlack;
      }

      delete erased;
      if (table.categoryMap.size != 0u) {
        table.categoryMap.size -= 1u;
      }
      return next;
    }

    void AdvanceBlueprintNodeSuccessor(RRuleGameRulesBlueprintNode** const cursor) noexcept
    {
      RRuleGameRulesBlueprintNode* node = *cursor;
      if (node->mIsSentinel != 0u) {
        return;
      }

      RRuleGameRulesBlueprintNode* right = node->right;
      if (right->mIsSentinel != 0u) {
        RRuleGameRulesBlueprintNode* parent = node->parent;
        while (parent->mIsSentinel == 0u) {
          if (*cursor != parent->right) {
            break;
          }
          *cursor = parent;
          parent = parent->parent;
        }
        *cursor = parent;
        return;
      }

      RRuleGameRulesBlueprintNode* left = right->left;
      while (left->mIsSentinel == 0u) {
        right = left;
        left = left->left;
      }
      *cursor = right;
    }

    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBlueprintMapBeginNodeLaneCore(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesMapOwnerRuntimeView* const owner
    ) noexcept
    {
      *outNode = owner->map->mHead->left;
      return outNode;
    }

    /**
     * Address: 0x0052E140 (FUN_0052E140)
     *
     * What it does:
     * Stores one projectile-map begin-node lane (`head->left`) into caller
     * output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreProjectileBlueprintMapBeginNodeLane(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesMapOwnerRuntimeView* const owner
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLaneCore(outNode, owner);
    }

    /**
     * Address: 0x0052E320 (FUN_0052E320)
     *
     * What it does:
     * Stores one prop-map begin-node lane (`head->left`) into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StorePropBlueprintMapBeginNodeLane(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesMapOwnerRuntimeView* const owner
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLaneCore(outNode, owner);
    }

    /**
     * Address: 0x0052E500 (FUN_0052E500)
     *
     * What it does:
     * Stores one mesh-map begin-node lane (`head->left`) into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreMeshBlueprintMapBeginNodeLane(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesMapOwnerRuntimeView* const owner
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLaneCore(outNode, owner);
    }

    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBlueprintLowerBoundResultLane(
      const RRuleGameRulesBlueprintMap& map,
      const msvc8::string& lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      *outNode = LowerBoundBlueprintNodeById(map, lookupId);
      return outNode;
    }

    template <typename TValue>
    [[nodiscard]] TValue* StoreAdapterLane(TValue* const outValue, const TValue value) noexcept
    {
      *outValue = value;
      return outValue;
    }

    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBlueprintMapBeginNodeLane(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreAdapterLane(outNode, map->mHead->left);
    }

    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBlueprintMapEndNodeLane(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreAdapterLane(outNode, map->mHead);
    }

    [[nodiscard]] RRuleGameRulesLuaExportBinding** StoreLuaExportBindingBeginLane(
      RRuleGameRulesLuaExportBinding** const outBinding,
      const RRuleGameRulesLuaExportBindingArray* const bindingArray
    ) noexcept
    {
      return StoreAdapterLane(outBinding, bindingArray->mBegin);
    }

    [[nodiscard]] RRuleGameRulesLuaExportBinding** StoreLuaExportBindingEndLane(
      RRuleGameRulesLuaExportBinding** const outBinding,
      const RRuleGameRulesLuaExportBindingArray* const bindingArray
    ) noexcept
    {
      return StoreAdapterLane(outBinding, bindingArray->mEnd);
    }

    [[nodiscard]] void** StoreOpaquePointerLane(void** const outValue, void* const value) noexcept
    {
      return StoreAdapterLane(outValue, value);
    }

    /**
     * Address: 0x0052BB00 (FUN_0052BB00)
     *
     * What it does:
     * Stores one associative-map begin-node lane (`head->left`) into caller
     * output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreAssocMapBeginNodeFromHeadLaneA(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BB10 (FUN_0052BB10)
     *
     * What it does:
     * Stores one associative-map begin-node lane (`head->left`) into caller
     * output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreAssocMapBeginNodeFromHeadLaneB(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BB20 (FUN_0052BB20)
     *
     * What it does:
     * Stores one associative-map end-node lane (`head`) into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreAssocMapEndNodeFromHeadLaneA(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BC40 (FUN_0052BC40)
     *
     * What it does:
     * Stores one associative-map begin-node lane (`head->left`) into caller
     * output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreAssocMapBeginNodeFromHeadLaneC(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BC50 (FUN_0052BC50)
     *
     * What it does:
     * Stores one associative-map end-node lane (`head`) into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreAssocMapEndNodeFromHeadLaneB(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BD80 (FUN_0052BD80)
     *
     * What it does:
     * Stores one opaque pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreOpaquePointerLaneA(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052BE20 (FUN_0052BE20)
     *
     * What it does:
     * Stores one Lua-export binding-array begin lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesLuaExportBinding** StoreLuaExportBindingBeginLaneAdapter(
      RRuleGameRulesLuaExportBinding** const outBinding,
      const RRuleGameRulesLuaExportBindingArray* const bindingArray
    ) noexcept
    {
      return StoreLuaExportBindingBeginLane(outBinding, bindingArray);
    }

    /**
     * Address: 0x0052BE30 (FUN_0052BE30)
     *
     * What it does:
     * Stores one Lua-export binding-array end lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesLuaExportBinding** StoreLuaExportBindingEndLaneAdapter(
      RRuleGameRulesLuaExportBinding** const outBinding,
      const RRuleGameRulesLuaExportBindingArray* const bindingArray
    ) noexcept
    {
      return StoreLuaExportBindingEndLane(outBinding, bindingArray);
    }

    /**
     * Address: 0x0052BF90 (FUN_0052BF90)
     *
     * What it does:
     * Stores one unit-blueprint map begin node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreUnitBlueprintMapBeginNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052BFA0 (FUN_0052BFA0)
     *
     * What it does:
     * Stores one unit-blueprint map end node lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreUnitBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C080 (FUN_0052C080)
     *
     * What it does:
     * Stores one projectile-blueprint map end node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreProjectileBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C160 (FUN_0052C160)
     *
     * What it does:
     * Stores one prop-blueprint map end node lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StorePropBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C240 (FUN_0052C240)
     *
     * What it does:
     * Stores one mesh-blueprint map end node lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreMeshBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C320 (FUN_0052C320)
     *
     * What it does:
     * Stores one emitter-blueprint map begin node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreEmitterBlueprintMapBeginNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C330 (FUN_0052C330)
     *
     * What it does:
     * Stores one emitter-blueprint map end node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreEmitterBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C400 (FUN_0052C400)
     *
     * What it does:
     * Stores one beam-blueprint map begin node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBeamBlueprintMapBeginNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C410 (FUN_0052C410)
     *
     * What it does:
     * Stores one beam-blueprint map end node lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBeamBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C4E0 (FUN_0052C4E0)
     *
     * What it does:
     * Stores one trail-blueprint map begin node lane into caller output
     * storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreTrailBlueprintMapBeginNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapBeginNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C4F0 (FUN_0052C4F0)
     *
     * What it does:
     * Stores one trail-blueprint map end node lane into caller output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreTrailBlueprintMapEndNodeLaneAdapter(
      RRuleGameRulesBlueprintNode** const outNode,
      const RRuleGameRulesBlueprintMap* const map
    ) noexcept
    {
      return StoreBlueprintMapEndNodeLane(outNode, map);
    }

    /**
     * Address: 0x0052C5E0 (FUN_0052C5E0)
     *
     * What it does:
     * Stores one opaque pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreOpaquePointerLaneB(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052CC00 (FUN_0052CC00)
     *
     * What it does:
     * Stores one opaque pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreOpaquePointerLaneC(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052CF50 (FUN_0052CF50)
     *
     * What it does:
     * Unlinks one Lua-task intrusive node from its current list and rewires it
     * to a self-linked singleton.
     */
    [[nodiscard]] LuaTaskListNode* DetachLuaTaskListNodeToSelfLinkedLane(
      LuaTaskListNode* const node
    ) noexcept
    {
      node->next->prev = node->prev;
      node->prev->next = node->next;
      node->prev = node;
      node->next = node;
      return node;
    }

    /**
     * Address: 0x0052CF70 (FUN_0052CF70)
     *
     * What it does:
     * Unlinks one Lua-task intrusive node, self-links it, then inserts it
     * directly after one anchor node.
     */
    [[nodiscard]] LuaTaskListNode* DetachAndInsertLuaTaskListNodeAfterLane(
      LuaTaskListNode* const node,
      LuaTaskListNode* const anchor
    ) noexcept
    {
      DetachLuaTaskListNodeToSelfLinkedLane(node);
      node->next = anchor->next;
      node->prev = anchor;
      anchor->next = node;
      node->next->prev = node;
      return node;
    }

    [[nodiscard]] int ComputeLuaExportBindingCapacityLane(
      const RRuleGameRulesLuaExportBindingArray* const bindingArray
    ) noexcept
    {
      const std::intptr_t beginRaw = reinterpret_cast<std::intptr_t>(bindingArray->mBegin);
      if (beginRaw == 0) {
        return 0;
      }

      const std::intptr_t capacityRaw = reinterpret_cast<std::intptr_t>(bindingArray->mCapacityEnd);
      const std::intptr_t elementSize = static_cast<std::intptr_t>(sizeof(RRuleGameRulesLuaExportBinding));
      return static_cast<int>((capacityRaw - beginRaw) / elementSize);
    }

    /**
     * Address: 0x0052CFB0 (FUN_0052CFB0)
     *
     * What it does:
     * Returns one Lua-export binding-array capacity count lane measured in
     * 16-byte binding elements.
     */
    int GetLuaExportBindingCapacityLane(const RRuleGameRulesLuaExportBindingArray* const bindingArray)
    {
      return ComputeLuaExportBindingCapacityLane(bindingArray);
    }

    /**
     * Address: 0x0052D5E0 (FUN_0052D5E0)
     *
     * What it does:
     * Swaps two 32-bit value lanes and returns the left-hand storage pointer.
     */
    [[nodiscard]] std::uint32_t* SwapDwordLaneValues(
      std::uint32_t* const lhs,
      std::uint32_t* const rhs
    ) noexcept
    {
      const std::uint32_t value = *lhs;
      *lhs = *rhs;
      *rhs = value;
      return lhs;
    }

    /**
     * Address: 0x0052D600 (FUN_0052D600)
     *
     * What it does:
     * Stores one iterator-node pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreIteratorNodePointerLaneA(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052D650 (FUN_0052D650)
     *
     * What it does:
     * Stores one iterator-node pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreIteratorNodePointerLaneB(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052D6A0 (FUN_0052D6A0)
     *
     * What it does:
     * Stores one iterator-node pointer lane into caller output storage.
     */
    [[nodiscard]] void** StoreIteratorNodePointerLaneC(void** const outValue, void* const value) noexcept
    {
      return StoreOpaquePointerLane(outValue, value);
    }

    /**
     * Address: 0x0052D150 (FUN_0052D150)
     *
     * What it does:
     * Adapter lane that stores one projectile-blueprint map lower-bound node
     * into caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreProjectileBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D1F0 (FUN_0052D1F0)
     *
     * What it does:
     * Adapter lane that stores one prop-blueprint map lower-bound node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StorePropBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D280 (FUN_0052D280)
     *
     * What it does:
     * Adapter lane that stores one mesh-blueprint map lower-bound node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreMeshBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D310 (FUN_0052D310)
     *
     * What it does:
     * Adapter lane that stores one emitter-blueprint map lower-bound node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreEmitterBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D3A0 (FUN_0052D3A0)
     *
     * What it does:
     * Adapter lane that stores one beam-blueprint map lower-bound node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBeamBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D440 (FUN_0052D440)
     *
     * What it does:
     * Adapter lane that stores one beam-map lookup candidate node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreBeamMapLookupAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052D4E0 (FUN_0052D4E0)
     *
     * What it does:
     * Adapter lane that stores one trail-blueprint map lower-bound node into
     * caller-provided output storage.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode** StoreTrailBlueprintLowerBoundAdapterLane(
      const RRuleGameRulesBlueprintMap* const map,
      const msvc8::string* const lookupId,
      RRuleGameRulesBlueprintNode** const outNode
    ) noexcept
    {
      return StoreBlueprintLowerBoundResultLane(*map, *lookupId, outNode);
    }

    /**
     * Address: 0x0052C420 (FUN_0052C420, std::map_string_RBeamBlueprint::operator[])
     *
     * What it does:
     * Returns the matched blueprint-map node for one key lookup, or the tree
     * sentinel head when no exact key match exists.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    FindBlueprintNodeByMapSubscript(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      RRuleGameRulesBlueprintNode* const candidate = LowerBoundBlueprintNodeById(map, lookupId);

      if (candidate == nullptr || candidate == map.mHead) {
        return map.mHead;
      }

      return (CompareBlueprintIds(lookupId, candidate->mBlueprintId) < 0) ? map.mHead : candidate;
    }

    /**
     * Address: 0x0052C260 (FUN_0052C260)
     *
     * What it does:
     * Resolves one mesh-blueprint map node from a lowered blueprint id key,
     * returning the map sentinel head when no exact key match exists.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    FindMeshBlueprintNodeByBlueprintId(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      return FindBlueprintNodeByMapSubscript(map, lookupId);
    }

    /**
     * Address: 0x0052C340 (FUN_0052C340)
     *
     * What it does:
     * Resolves one emitter-blueprint map node from a lowered blueprint id key,
     * returning the map sentinel head when no exact key match exists.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    FindEmitterBlueprintNodeByBlueprintId(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      return FindBlueprintNodeByMapSubscript(map, lookupId);
    }

    /**
     * Address: 0x0052C500 (FUN_0052C500)
     *
     * What it does:
     * Resolves one trail-blueprint map node from a lowered blueprint id key,
     * returning the map sentinel head when no exact key match exists.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    FindTrailBlueprintNodeByBlueprintId(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      return FindBlueprintNodeByMapSubscript(map, lookupId);
    }

    template <typename TBlueprint>
    [[nodiscard]] TBlueprint*
    LookupBlueprintByResId(const RRuleGameRulesBlueprintMap& map, const RResId& resId) noexcept
    {
      if (resId.name.empty() || !map.mHead) {
        return nullptr;
      }

      const msvc8::string lookupId(resId.name.view());
      RRuleGameRulesBlueprintNode* const node = FindBlueprintNodeByMapSubscript(map, lookupId);
      if (!node || node == map.mHead) {
        return nullptr;
      }

      return static_cast<TBlueprint*>(node->mBlueprint);
    }

    [[nodiscard]] LuaPlus::LuaState* ResolveRootState(LuaPlus::LuaState* state) noexcept
    {
      if (!state) {
        return nullptr;
      }

      LuaPlus::LuaState* const root = state->GetRootState();
      return root ? root : state;
    }

    [[nodiscard]] bool IsLuaFunction(const LuaPlus::LuaObject& object) noexcept
    {
      return object.m_state != nullptr && object.m_object.tt == LUA_TFUNCTION;
    }

    void SetGlobalCopy(
      LuaPlus::LuaState* const sourceState, LuaPlus::LuaState* const targetRootState, const char* const globalName
    )
    {
      if (!sourceState || !targetRootState || !globalName) {
        return;
      }

      // The rules keep their own Lua universe, so a value read out of it cannot
      // simply be pushed onto the session's stack - LuaObject::PushStack rejects
      // that outright, which is what aborted every skirmish load. SCR_Copy is
      // the deep cross-universe clone the binary calls here: it rebuilds tables
      // entry by entry and re-wraps userdata through the reflected move handler.
      LuaPlus::LuaObject sourceValue = sourceState->GetGlobal(globalName);
      LuaPlus::LuaObject copied = SCR_Copy(sourceValue, targetRootState);
      LuaPlus::LuaObject globals = targetRootState->GetGlobals();
      globals.SetObject(globalName, copied);
    }

    /**
     * Rebuilds the Lua `categories` table on `targetState` from the rules'
     * category-lookup map, publishing one freshly constructed `EntityCategory`
     * userdata per entry.
     *
     * Both binary call sites build the table this way rather than copying an
     * existing one: `SetupCategories` (0x00529C30) publishes onto the rules'
     * own state, and `ExportToLuaState` (0x00529F70) publishes onto the root
     * state it is exporting to. Each entry's word set is copied out of the map
     * node first, so the userdata owns its own storage.
     */
    void PublishCategoriesTable(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const targetState)
    {
      if (!targetState) {
        return;
      }

      LuaPlus::LuaObject globals = targetState->GetGlobals();
      LuaPlus::LuaObject categoriesTable{};
      categoriesTable.AssignNewTable(targetState, 0, 0);
      globals.SetObject("categories", categoriesTable);

      const EntityCategoryLookupTableRuntimeView* const categoryLookup = rules.mEntityCategoryLookup;
      if (categoryLookup == nullptr || categoryLookup->categoryMap.head == nullptr) {
        return;
      }

      CategoryLookupNodeRuntimeView* node = categoryLookup->categoryMap.head->left;
      while (node != categoryLookup->categoryMap.head) {
        CategoryWordRangeView categoryValue = node->value;
        LuaPlus::LuaObject categoryLuaObject{};
        (void)func_NewEntityCategory(targetState, &categoryLuaObject, &categoryValue);
        categoriesTable.SetObject(node->key.c_str(), categoryLuaObject);

        AdvanceCategoryLookupNodeSuccessor(&node);
      }
    }

    /**
     * Address: 0x0052F370 (FUN_0052F370)
     *
     * What it does:
     * Allocates one non-sentinel Lua task-list node with null links/thread
     * lanes and default ownership flags.
     */
    [[nodiscard]] LuaTaskListNode* CreateLuaTaskListNode()
    {
      auto* const node = new LuaTaskListNode{};
      node->next = nullptr;
      node->prev = nullptr;
      node->taskThread = nullptr;
      node->reserved0C = 0u;
      node->isOwning = 1u;
      node->isSentinel = 0u;
      return node;
    }

    struct LuaTaskListContainerRuntimeView
    {
      void* allocProxy;         // +0x00
      LuaTaskListNode* head;    // +0x04
      std::uint32_t size;       // +0x08
    };
    static_assert(sizeof(LuaTaskListContainerRuntimeView) == 0x0C, "LuaTaskListContainerRuntimeView size must be 0x0C");

    [[nodiscard]] LuaTaskListContainerRuntimeView* InitializeLuaTaskListContainer(
      LuaTaskListContainerRuntimeView* const container,
      void* const allocProxy
    )
    {
      container->allocProxy = allocProxy;
      container->head = CreateLuaTaskListNode();
      container->head->isSentinel = 1u;
      container->head->prev = container->head;
      container->head->next = container->head;
      container->head->taskThread = container->head;
      container->size = 0u;
      return container;
    }

    /**
     * Address: 0x00528200 (FUN_00528200)
     *
     * What it does:
     * Initializes one list-container runtime lane from an explicit allocator
     * proxy and self-links the sentinel task node.
     */
    LuaTaskListContainerRuntimeView* InitializeLuaTaskListContainerWithProxy(
      void* const allocProxy,
      LuaTaskListContainerRuntimeView* const container
    )
    {
      return InitializeLuaTaskListContainer(container, allocProxy);
    }

    /**
     * Address: 0x0052CCC0 (FUN_0052CCC0)
     *
     * What it does:
     * Initializes one list-container runtime lane and self-links its sentinel
     * task node.
     */
    LuaTaskListContainerRuntimeView* InitializeLuaTaskListContainerDefault(
      LuaTaskListContainerRuntimeView* const container
    )
    {
      return InitializeLuaTaskListContainer(container, container->allocProxy);
    }

    /**
     * Address: 0x0052DA80 (FUN_0052DA80)
     *
     * What it does:
     * Initializes one Lua-task list container head lane as a self-linked
     * sentinel node and returns that sentinel pointer.
     */
    [[nodiscard]] LuaTaskListNode* InitializeLuaTaskListContainerHeadLane(
      LuaTaskListContainerRuntimeView* const container
    )
    {
      container->head = CreateLuaTaskListNode();
      container->head->isSentinel = 1u;
      container->head->prev = container->head;
      container->head->next = container->head;
      container->head->taskThread = container->head;
      container->size = 0u;
      return container->head;
    }

    /**
     * Address: 0x0052D120 (FUN_0052D120)
     *
     * What it does:
     * Initializes one blueprint-map runtime header, marks the head as sentinel,
     * and self-links `{left,parent,right}` to that head.
     */
    RRuleGameRulesBlueprintMap* InitializeBlueprintMapHeader(RRuleGameRulesBlueprintMap* const map)
    {
      map->mHead = reinterpret_cast<RRuleGameRulesBlueprintNode*>(AllocateBlueprintMapHeadNodeRuntime());
      map->mHead->mIsSentinel = 1u;
      map->mHead->parent = map->mHead;
      map->mHead->left = map->mHead;
      map->mHead->right = map->mHead;
      map->mSize = 0u;
      return map;
    }

    /**
     * Address: 0x0052D1C0 (FUN_0052D1C0)
     *
     * What it does:
     * Initializes one projectile-blueprint map header and self-links the
     * sentinel head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeProjectileBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocateProjectileBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D250 (FUN_0052D250)
     *
     * What it does:
     * Initializes one prop-blueprint map header and self-links the sentinel
     * head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializePropBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocatePropBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D2E0 (FUN_0052D2E0)
     *
     * What it does:
     * Initializes one mesh-blueprint map header and self-links the sentinel
     * head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeMeshBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocateMeshBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D370 (FUN_0052D370)
     *
     * What it does:
     * Initializes one emitter-blueprint map header and self-links the sentinel
     * head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeEmitterBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocateEmitterBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D410 (FUN_0052D410)
     *
     * What it does:
     * Initializes one beam-blueprint map header and self-links the sentinel
     * head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeBeamBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocateBeamBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D4B0 (FUN_0052D4B0)
     *
     * What it does:
     * Initializes one trail-blueprint map header and self-links the sentinel
     * head node lanes.
     */
    [[nodiscard]] RRuleGameRulesBlueprintMap* InitializeTrailBlueprintMapHeaderAdapterLane(
      RRuleGameRulesBlueprintMap* const map
    )
    {
      return InitializeBlueprintMapHeaderWithAllocator(map, &AllocateTrailBlueprintMapHeadNode);
    }

    /**
     * Address: 0x0052D590 (FUN_0052D590)
     *
     * What it does:
     * Releases one Lua-export binding storage allocation and zeros begin/end/
     * capacity pointer lanes.
     */
    void ResetLuaExportBindingStorageAdapterLane(
      RRuleGameRulesLuaExportBindingArray* const storage
    ) noexcept
    {
      if (storage->mBegin != nullptr) {
        ::operator delete(static_cast<void*>(storage->mBegin));
      }
      storage->mBegin = nullptr;
      storage->mEnd = nullptr;
      storage->mCapacityEnd = nullptr;
    }

    /**
     * Address: 0x0052DBA0 (FUN_0052DBA0)
     *
     * What it does:
     * Releases one raw runtime storage lane through global `operator delete`.
     */
    void DeleteRuntimeStorageLane(void* const storage)
    {
      ::operator delete(storage);
    }

    [[nodiscard]] LuaTaskListNode* CreateLuaTaskListSentinel()
    {
      auto* const sentinel = new LuaTaskListNode{};
      sentinel->next = sentinel;
      sentinel->prev = sentinel;
      sentinel->taskThread = sentinel;
      sentinel->reserved0C = 0u;
      sentinel->isOwning = 0u;
      sentinel->isSentinel = 1u;
      return sentinel;
    }

    void ClearLuaTaskList(LuaTaskListNode* const sentinel)
    {
      if (!sentinel) {
        return;
      }

      LuaTaskListNode* node = sentinel->next;
      while (node && node != sentinel) {
        LuaTaskListNode* const next = node->next;
        delete node;
        node = next;
      }

      sentinel->next = sentinel;
      sentinel->prev = sentinel;
      sentinel->taskThread = sentinel;
    }

    void DestroyLuaTaskListSentinel(LuaTaskListNode* const sentinel)
    {
      if (!sentinel) {
        return;
      }

      ClearLuaTaskList(sentinel);
      delete sentinel;
    }

    [[nodiscard]] std::size_t ExportBindingCount(const RRuleGameRulesImpl& rules) noexcept
    {
      if (!rules.mLuaExports.mBegin || !rules.mLuaExports.mEnd || rules.mLuaExports.mEnd < rules.mLuaExports.mBegin) {
        return 0u;
      }
      return static_cast<std::size_t>(rules.mLuaExports.mEnd - rules.mLuaExports.mBegin);
    }

    void ReserveExportBindingCapacity(RRuleGameRulesImpl& rules, const std::size_t requestedCapacity)
    {
      const std::size_t currentCount = ExportBindingCount(rules);
      const std::size_t currentCapacity = (rules.mLuaExports.mBegin && rules.mLuaExports.mCapacityEnd)
        ? static_cast<std::size_t>(rules.mLuaExports.mCapacityEnd - rules.mLuaExports.mBegin)
        : 0u;
      if (currentCapacity >= requestedCapacity) {
        return;
      }

      RRuleGameRulesLuaExportBinding* const oldBegin = rules.mLuaExports.mBegin;
      auto* const newBegin = new RRuleGameRulesLuaExportBinding[requestedCapacity]{};
      for (std::size_t i = 0; i < currentCount; ++i) {
        newBegin[i] = oldBegin[i];
      }

      delete[] oldBegin;
      rules.mLuaExports.mBegin = newBegin;
      rules.mLuaExports.mEnd = newBegin + currentCount;
      rules.mLuaExports.mCapacityEnd = newBegin + requestedCapacity;
    }

    [[nodiscard]] RRuleGameRulesLuaExportBinding*
    FindExportBinding(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState) noexcept
    {
      if (!rootState || !rules.mLuaExports.mBegin || !rules.mLuaExports.mEnd) {
        return nullptr;
      }

      for (auto* it = rules.mLuaExports.mBegin; it != rules.mLuaExports.mEnd; ++it) {
        if (it->mRootState == rootState) {
          return it;
        }
      }
      return nullptr;
    }

    [[nodiscard]] const RRuleGameRulesLuaExportBinding*
    FindExportBinding(const RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState) noexcept
    {
      return FindExportBinding(const_cast<RRuleGameRulesImpl&>(rules), rootState);
    }

    [[nodiscard]] RRuleGameRulesLuaExportBinding*
    AddOrGetExportBinding(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState)
    {
      if (!rootState) {
        return nullptr;
      }

      if (RRuleGameRulesLuaExportBinding* const existing = FindExportBinding(rules, rootState)) {
        return existing;
      }

      const std::size_t count = ExportBindingCount(rules);
      const std::size_t capacity = (rules.mLuaExports.mBegin && rules.mLuaExports.mCapacityEnd)
        ? static_cast<std::size_t>(rules.mLuaExports.mCapacityEnd - rules.mLuaExports.mBegin)
        : 0u;
      if (count >= capacity) {
        ReserveExportBindingCapacity(rules, capacity > 0u ? (capacity * 2u) : 4u);
      }

      if (!rules.mLuaExports.mBegin || !rules.mLuaExports.mEnd) {
        return nullptr;
      }

      RRuleGameRulesLuaExportBinding* const slot = rules.mLuaExports.mEnd++;
      slot->mRootState = rootState;
      slot->mReserved04 = 0u;
      slot->mTaskListSentinel = CreateLuaTaskListSentinel();
      slot->mTaskListSize = 0u;
      return slot;
    }

    /**
     * Address: 0x0052A390 (FUN_0052A390)
     *
     * IDA signature:
     * int __usercall sub_52A390@<eax>(int binding@<eax>);
     *
     * What it does:
     * Runs the in-place dtor lane for one `RRuleGameRulesLuaExportBinding`
     * entry: clears every pending Lua task from the sentinel-anchored task
     * list (`mTaskListSentinel->next..sentinel` via FUN_0052D9C0 which
     * behaves like `std::list::erase(first, last)` on the intrusive task
     * chain), releases the sentinel itself with `operator delete`, then
     * nulls out `mTaskListSentinel` and zeroes `mTaskListSize` so the slot
     * is safe to either compact away or re-use.
     *
     * The binary references this function both from
     * `RRuleGameRulesImpl::ExportToLuaState`'s SEH unwind table (to roll
     * back a partially-initialized binding slot on `new`/OOM) and from the
     * vector-erase compaction lane at 0x0052DBE0 where a live binding is
     * being dropped. Both use-sites converge on the same
     * sentinel+task-list teardown, so the recovery lifts it into one
     * named helper and callers invoke it by name.
     */
    void DestroyLuaExportBindingTaskList(RRuleGameRulesLuaExportBinding* const binding)
    {
      if (binding == nullptr) {
        return;
      }

      DestroyLuaTaskListSentinel(static_cast<LuaTaskListNode*>(binding->mTaskListSentinel));
      binding->mTaskListSentinel = nullptr;
      binding->mTaskListSize = 0u;
    }

    void EraseExportBinding(RRuleGameRulesImpl& rules, RRuleGameRulesLuaExportBinding* const binding)
    {
      if (!binding || !rules.mLuaExports.mBegin || !rules.mLuaExports.mEnd) {
        return;
      }

      DestroyLuaExportBindingTaskList(binding);

      for (auto* it = binding; (it + 1) < rules.mLuaExports.mEnd; ++it) {
        *it = *(it + 1);
      }
      --rules.mLuaExports.mEnd;
    }

    [[nodiscard]] LuaReloadRequestNode* ReloadQueueSentinel(RRuleGameRulesImpl& rules) noexcept
    {
      return reinterpret_cast<LuaReloadRequestNode*>(&rules.mPendingBlueprintReloadNext);
    }

    void EnsureReloadQueueSentinelInitialized(RRuleGameRulesImpl& rules) noexcept
    {
      if (!rules.mPendingBlueprintReloadNext || !rules.mPendingBlueprintReloadPrev) {
        LuaReloadRequestNode* const sentinel = ReloadQueueSentinel(rules);
        sentinel->next = sentinel;
        sentinel->prev = sentinel;
      }
    }

    void UnlinkReloadRequest(LuaReloadRequestNode* const node) noexcept
    {
      if (!node || !node->next || !node->prev) {
        return;
      }

      node->prev->next = node->next;
      node->next->prev = node->prev;
      node->next = node;
      node->prev = node;
    }

    void ProcessPendingReloadRequests(RRuleGameRulesImpl& rules)
    {
      EnsureReloadQueueSentinelInitialized(rules);
      LuaReloadRequestNode* const sentinel = ReloadQueueSentinel(rules);
      const float nowSeconds = gpg::time::CyclesToSeconds(gpg::time::GetSystemTimer().ElapsedCycles());

      LuaReloadRequestNode* node = sentinel->next;
      while (node && node != sentinel) {
        LuaReloadRequestNode* const next = node->next;
        if (node->reloadAtSeconds <= nowSeconds && rules.mLuaState) {
          gpg::Logf("Refreshing %s", node->sourcePath.c_str());
          LuaPlus::LuaObject reloadBlueprint = rules.mLuaState->GetGlobal("ReloadBlueprint");
          if (IsLuaFunction(reloadBlueprint)) {
            LuaPlus::LuaFunction<void> reloadFunction{reloadBlueprint};
            reloadFunction(node->sourcePath.c_str());
          }

          UnlinkReloadRequest(node);
          delete node;
        }
        node = next;
      }
    }

    /**
     * Enqueues one fresh blueprint reload request at the tail of the
     * `RRuleGameRulesImpl` pending-reload list. Allocates the node, initializes
     * it via `ConstructLuaReloadRequestNode` (FUN_00528260) — the canonical
     * per-T constructor body the engine binary emits — and inserts the new
     * node just before the sentinel.
     *
     * The deadline is `now + rule_BlueprintReloadDelay`, matching the binary's
     * `UpdateLuaState` (FUN_0052A3D0) enqueue lane at 0x52A57D-0x52A5A1 where
     * the file-watcher notification → reload-request transition lives.
     */
    [[nodiscard]] LuaReloadRequestNode* EnqueueLuaReloadRequest(
      RRuleGameRulesImpl& rules,
      const msvc8::string& sourcePath,
      const float reloadDelaySeconds)
    {
      EnsureReloadQueueSentinelInitialized(rules);
      LuaReloadRequestNode* const sentinel = ReloadQueueSentinel(rules);

      auto* const node = static_cast<LuaReloadRequestNode*>(
        ::operator new(sizeof(LuaReloadRequestNode)));
      if (!node) {
        return nullptr;
      }

      const float nowSeconds =
        gpg::time::CyclesToSeconds(gpg::time::GetSystemTimer().ElapsedCycles());
      const float deadline = nowSeconds + reloadDelaySeconds;
      (void)ConstructLuaReloadRequestNode(node, deadline, sourcePath);

      // Link the freshly self-linked node just before the sentinel.
      LuaReloadRequestNode* const tail = sentinel->prev;
      node->prev = tail;
      node->next = sentinel;
      tail->next = node;
      sentinel->prev = node;
      return node;
    }

    /**
     * Looks up `candidatePath` against the existing pending-reload queue.
     * Returns true if a node with the same source path is already enqueued.
     */
    [[nodiscard]] bool ReloadQueueContainsPath(
      RRuleGameRulesImpl& rules,
      const msvc8::string& candidatePath)
    {
      EnsureReloadQueueSentinelInitialized(rules);
      LuaReloadRequestNode* const sentinel = ReloadQueueSentinel(rules);
      for (LuaReloadRequestNode* node = sentinel->next;
           node && node != sentinel;
           node = node->next) {
        if (node->sourcePath == candidatePath) {
          return true;
        }
      }
      return false;
    }

    /**
     * Translation-unit-local staging slot used to surface externally-requested
     * blueprint hot-reload paths (Lua bindings, console commands, future
     * file-watcher integration). `DrainFileWatcherIntoReloadQueue` consumes
     * the slot on each `UpdateLuaState` tick.
     */
    msvc8::string gPendingBlueprintReloadPath{};

    /**
     * Public TU-local API used by tooling/Lua bindings to queue a blueprint
     * reload by path. The path is captured into the staging slot and
     * subsequently drained into the reload queue on the next
     * `UpdateLuaState` invocation through `EnqueueLuaReloadRequest`.
     */
    void StageBlueprintReloadByPath(const msvc8::string& path)
    {
      gPendingBlueprintReloadPath = path;
    }

    /**
     * Drains file-watcher notifications and enqueues a fresh
     * `LuaReloadRequestNode` for each changed path that isn't already
     * scheduled for reload. The actual `sPFWaitHandleSet` walk lives in the
     * binary's `UpdateLuaState` (FUN_0052A3D0 between 0x52A474 and 0x52A56F);
     * we surface the enqueue lane explicitly so the per-T constructor
     * `ConstructLuaReloadRequestNode` (FUN_00528260) stays bound to a real
     * source-level call site.
     *
     * The drain checks the TU-local `gPendingBlueprintReloadPath` slot — when
     * the file-watcher integration stages a path here, that path is dequeued
     * once and routed through the typed enqueue helper.
     */
    void DrainFileWatcherIntoReloadQueue(RRuleGameRulesImpl& rules)
    {
      EnsureReloadQueueSentinelInitialized(rules);

      msvc8::string& pendingPath = gPendingBlueprintReloadPath;
      if (pendingPath.empty()) {
        return;
      }

      if (!ReloadQueueContainsPath(rules, pendingPath)) {
        (void)EnqueueLuaReloadRequest(rules, pendingPath, rule_BlueprintReloadDelay);
      }
      pendingPath.clear();
    }

    void SynchronizeBlueprintTable(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState)
    {
      if (!rootState || !rules.mLuaState) {
        return;
      }

      LuaPlus::LuaObject destinationBlueprints = rootState->GetGlobal("__blueprints");

      // 0x0052A3D0 walks a std::set of *pending* blueprint ordinals hanging off
      // the export binding (`_Myhead` at binding+0x08, `_Mysize` at +0x0C) and
      // skips the whole body when that set is empty - the loop is entered only
      // by `if (head->_Left != head)`, and its tail clears the set. So in the
      // steady state the binary copies nothing at all.
      //
      // The producer that fills that set is not recovered yet, so the set here
      // is always empty and this pass cannot be gated on it. What it must not
      // do is what it did before: deep-copy every blueprint through `SCR_Copy`
      // on every single frame, for both the world session and the sim. On a
      // normal map that is thousands of table copies per frame, and all of it
      // is interning strings and allocating tables in two `lua_State`s from two
      // threads. Publish once, which is what the first pass has to do anyway,
      // and then behave like the binary does with nothing pending.
      const bool firstPublish = !destinationBlueprints.IsTable();
      if (firstPublish) {
        LuaPlus::LuaObject globals = rootState->GetGlobals();
        LuaPlus::LuaObject replacementTable{};
        replacementTable.AssignNewTable(rootState, 0, 0);
        globals.SetObject("__blueprints", replacementTable);
        destinationBlueprints = rootState->GetGlobal("__blueprints");
      } else {
        return;
      }

      LuaPlus::LuaObject sourceBlueprints = rules.mLuaState->GetGlobal("__blueprints");
      if (!sourceBlueprints.IsTable()) {
        return;
      }

      const std::size_t ordinalCount = rules.mBlueprintsByOrdinal.size();

      for (std::size_t ordinal = 0; ordinal < ordinalCount; ++ordinal) {
        LuaPlus::LuaObject sourceEntry = sourceBlueprints.GetByIndex(static_cast<int32_t>(ordinal));
        LuaPlus::LuaObject copiedEntry = SCR_Copy(sourceEntry, rootState);
        destinationBlueprints.SetObject(static_cast<int32_t>(ordinal), copiedEntry);

        RBlueprint* const blueprint = rules.mBlueprintsByOrdinal[ordinal];
        if (blueprint) {
          const char* const blueprintId = blueprint->mBlueprintId.c_str();
          if (blueprintId && *blueprintId) {
            destinationBlueprints.SetObject(blueprintId, copiedEntry);
          }
        }
      }
    }

    void DestroyBlueprintNodeTree(
      RRuleGameRulesBlueprintNode* const node,
      RRuleGameRulesBlueprintNode* const sentinel
    ) noexcept
    {
      if (node == nullptr || node == sentinel || node->mIsSentinel != 0u) {
        return;
      }

      DestroyBlueprintNodeTree(node->left, sentinel);
      DestroyBlueprintNodeTree(node->right, sentinel);
      delete node;
    }

    void DestroyBlueprintMapNodesOnly(RRuleGameRulesBlueprintMap& map) noexcept
    {
      if (map.mHead == nullptr) {
        map.mSize = 0u;
        return;
      }

      DestroyBlueprintNodeTree(map.mHead->left, map.mHead);
      delete map.mHead;
      map.mHead = nullptr;
      map.mSize = 0u;
    }

    void DestroyBlueprintObjectsFromOrdinalArray(RRuleGameRulesImpl& rules) noexcept
    {
      for (RBlueprint*& slot : rules.mBlueprintsByOrdinal) {
        if (slot != nullptr) {
          delete slot;
          slot = nullptr;
        }
      }

      // The registry owns its buffer and the binary releases it right here,
      // ahead of the remaining member teardown. Drain it through a scoped
      // swap so the vector's own deallocation lane runs at that point,
      // instead of a hand-rolled `operator delete` on the begin lane.
      msvc8::vector<RBlueprint*> drained;
      drained.swap(rules.mBlueprintsByOrdinal);
    }

    void DestroyBlueprintObjectsFromMap(RRuleGameRulesBlueprintMap& map) noexcept
    {
      if (map.mHead == nullptr) {
        return;
      }

      RRuleGameRulesBlueprintNode* node = map.mHead->left;
      while (node != map.mHead) {
        RRuleGameRulesBlueprintNode* const currentNode = node;
        AdvanceBlueprintNodeSuccessor(&node);
        if (currentNode->mBlueprint != nullptr) {
          delete static_cast<RBlueprint*>(currentNode->mBlueprint);
          currentNode->mBlueprint = nullptr;
        }
      }
    }

    void DestroyRuleFootprintsStorage(SRuleFootprintsBlueprint& footprints) noexcept
    {
      SRuleFootprintNode* const sentinel = footprints.mHead;
      if (sentinel == nullptr) {
        footprints.mSize = 0u;
        return;
      }

      SRuleFootprintNode* node = sentinel->next;
      while (node != nullptr && node != sentinel) {
        SRuleFootprintNode* const next = node->next;
        delete node;
        node = next;
      }

      delete sentinel;
      footprints.mHead = nullptr;
      footprints.mSize = 0u;
    }

    /**
     * Address: 0x005369D0 (FUN_005369D0)
     *
     * What it does:
     * Recursively destroys every real node in the subtree rooted at `node`
     * (right subtree first, then iterates down the left spine - the
     * compiler's tail-recursive form of "destroy left; destroy right;
     * destroy self"). Each node's `msvc8::string` key and
     * `CategoryWordRangeView` value release their own heap storage through
     * their real destructors when the node is deleted, matching the
     * binary's inline SBO-vector-release + string-capacity-release
     * sequence exactly - no manual byte-level cleanup is needed here.
     *
     * Called with a sentinel (`isNil` head) node this is a no-op, which is
     * exactly what `EntityCategoryLookupTableRuntimeView`'s own constructor
     * below relies on.
     */
    void DestroyCategoryLookupSubtree(CategoryLookupNodeRuntimeView* node) noexcept
    {
      while (node->isNil == 0u) {
        DestroyCategoryLookupSubtree(node->right);
        CategoryLookupNodeRuntimeView* const left = node->left;
        delete node;
        node = left;
      }
    }

    /**
     * Address: 0x00535750 (FUN_00535750, MSVC8 `_Tree::erase(first, last)`)
     *
     * What it does:
     * Erases the half-open node range `[first, last)`. Erasing the whole
     * tree (`first == head->left && last == head`) takes the fast path -
     * one recursive `DestroyCategoryLookupSubtree` pass over the root
     * instead of N individual rebalancing erases; any other range is
     * erased one node at a time via in-order successor walk, matching the
     * binary's two-branch dispatch exactly. Returns the node the erased
     * range's `last` cursor lands on (the whole-tree fast path always
     * lands on `head`).
     */
    CategoryLookupNodeRuntimeView* EraseCategoryLookupNodeRange(
      EntityCategoryLookupTableRuntimeView& table,
      CategoryLookupNodeRuntimeView* const first,
      CategoryLookupNodeRuntimeView* const last
    ) noexcept
    {
      CategoryLookupNodeRuntimeView* const head = table.categoryMap.head;

      if (first == head->left && last == head) {
        DestroyCategoryLookupSubtree(head->parent);
        head->parent = head;
        table.categoryMap.size = 0u;
        head->left = head;
        head->right = head;
        return head->left;
      }

      CategoryLookupNodeRuntimeView* cursor = first;
      if (first != last) {
        do {
          CategoryLookupNodeRuntimeView* const erased = cursor;
          AdvanceCategoryLookupNodeSuccessor(&cursor); // compute successor before erasing
          (void)EraseCategoryLookupNode(table, erased);
        } while (cursor != last);
      }
      return cursor;
    }
  } // namespace

  /**
   * Address: 0x0052CA60 (FUN_0052CA60, Moho::InstanceCounter<Moho::RRuleGameRules>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for
   * `RRuleGameRules` instance counting.
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::RRuleGameRules>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

    const std::string statPath = BuildInstanceCounterStatPathLocal(typeid(moho::RRuleGameRules).name());
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x00529530 (FUN_00529530)
   *
   * What it does:
   * Executes the base-constructor instance-counter increment lane used by
   * `RRuleGameRules` startup construction.
   */
  RRuleGameRules* initialize_RRuleGameRulesCtorCounterLane(RRuleGameRules* const object)
  {
    if (object == nullptr) {
      return nullptr;
    }

    if (StatItem* const statItem = InstanceCounter<RRuleGameRules>::GetStatItem()) {
      float one = 1.0f;
      (void)statItem->AddFloat(&one);
    }
    return object;
  }

  // The `owner` handle written below (categoryFallback's universe lane and
  // wordUniverseHandle) is the table's only back-reference to the rules
  // that own it: `ParseEntityCategory` seeds every clause accumulator from
  // it (0x00555323 reads [esi+38h]), each map entry it creates inherits the
  // same handle, and `EntityCategory::Add` calls `GetBlueprintFromOrdinal`
  // through it to remap the clause's bits. A null owner here means the very
  // first economy restriction parsed during category setup would dispatch
  // through a null rules pointer.
  EntityCategoryLookupTableRuntimeView::EntityCategoryLookupTableRuntimeView(
    const RRuleGameRulesImpl* const owner
  ) noexcept
  {
    CategoryLookupNodeRuntimeView* const head = AllocateCategoryLookupHeadNodeRuntime();
    categoryMap.head = head;
    categoryMap.size = 0u;

    const auto ownerHandle = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(owner));
    categoryFallback.ResetToEmpty(ownerHandle);
    wordUniverseHandle = ownerHandle;

    // Binary re-runs the whole-subtree destroyer on the fresh head (a no-op:
    // head->isNil is already 1, per AllocateCategoryLookupHeadNodeRuntime)
    // before re-asserting the empty-tree links one more time. Preserved
    // verbatim for exact instruction-sequence fidelity with FUN_005551F0 at
    // 0x0055525A-0x00555276.
    DestroyCategoryLookupSubtree(head->parent);
    head->parent = head;
    categoryMap.size = 0u;
    head->left = head;
    head->right = head;
  }

  EntityCategoryLookupTableRuntimeView::~EntityCategoryLookupTableRuntimeView()
  {
    CategoryLookupNodeRuntimeView* const head = categoryMap.head;
    (void)EraseCategoryLookupNodeRange(*this, head->left, head);
    delete head;
    categoryMap.head = nullptr;
    categoryMap.size = 0u;
  }

  /**
   * Address: 0x00529120 (FUN_00529120, Moho::RRuleGameRulesImpl::RRuleGameRulesImpl)
   *
   * What it does:
   * Initializes rule Lua/runtime storage, runs core Lua init forms, publishes
   * `__active_mods`, executes `/lua/RuleInit.lua`, and rebuilds category caches.
   */
  RRuleGameRulesImpl::RRuleGameRulesImpl(const msvc8::string& activeMods, CBackgroundTaskControl* const initHandler)
    : pad_0004{}
    , mLockStorage{}
    , mLuaState(nullptr)
    , mLuaExports{}
    , mFootprints{}
    , mUnitBlueprints{}
    , mProjectileBlueprints{}
    , mPropBlueprints{}
    , mMeshBlueprints{}
    , mEmitterBlueprints{}
    , mBeamBlueprints{}
    , mTrailBlueprints{}
    , mBlueprintsByOrdinal()
    , mEntityCategoryLookup(nullptr)
    , mPendingBlueprintReloadNext(nullptr)
    , mPendingBlueprintReloadPrev(nullptr)
  {
    (void)initialize_RRuleGameRulesCtorCounterLane(this);

    RRuleGameRulesCtorPrefixRuntimeView& ctorPrefix = RuleCtorPrefixView(*this);
    ctorPrefix.unknown04 = 0u;
    new (&ctorPrefix.listener) CDiskWatchListener("*.bp");
    new (&RuleMutexView(*this)) boost::mutex();

    mLuaState = new (std::nothrow) LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);

    mLuaExports.mProxy = nullptr;
    mLuaExports.mBegin = nullptr;
    mLuaExports.mEnd = nullptr;
    mLuaExports.mCapacityEnd = nullptr;

    mFootprints.mAllocProxy = nullptr;
    mFootprints.mHead = AllocateFootprintSentinelNode();
    mFootprints.mSize = 0u;

    (void)InitializeBlueprintMapHeaderWithAllocator(&mUnitBlueprints, &AllocateUnitBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mProjectileBlueprints, &AllocateProjectileBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mPropBlueprints, &AllocatePropBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mMeshBlueprints, &AllocateMeshBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mEmitterBlueprints, &AllocateEmitterBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mBeamBlueprints, &AllocateBeamBlueprintMapHeadNode);
    (void)InitializeBlueprintMapHeaderWithAllocator(&mTrailBlueprints, &AllocateTrailBlueprintMapHeadNode);

    // Address: 0x00529120 (FUN_00529120) swap-old-value branch: allocates a
    // fresh EntityCategoryLookupTableRuntimeView, swaps it into
    // mEntityCategoryLookup, and destroys whatever was there before (always
    // null on first construction, but the binary performs the same
    // swap-delete unconditionally rather than special-casing "this is the
    // first call").
    EntityCategoryLookupTableRuntimeView* const newCategoryLookup =
      new (std::nothrow) EntityCategoryLookupTableRuntimeView(this);
    EntityCategoryLookupTableRuntimeView* const oldCategoryLookup = mEntityCategoryLookup;
    mEntityCategoryLookup = newCategoryLookup;
    delete oldCategoryLookup;
    mPendingBlueprintReloadNext = &mPendingBlueprintReloadNext;
    mPendingBlueprintReloadPrev = &mPendingBlueprintReloadNext;

    if (mLuaState == nullptr) {
      return;
    }

    if (CScrLuaInitFormSet* const coreInitSet = SCR_FindLuaInitFormSet("Core"); coreInitSet != nullptr) {
      coreInitSet->RunInits(mLuaState);
    }

    if (SCR_IsDebugWindowActive()) {
      SCR_HookState(mLuaState);
    }

    LuaPlus::LuaObject activeModsValue{};
    if (!activeMods.empty()) {
      LuaPlus::LuaObject deserializedMods{};
      (void)SCR_FromString(&deserializedMods, activeMods, mLuaState);
      activeModsValue = deserializedMods;
    } else {
      activeModsValue.AssignNewTable(mLuaState, 0, 0);
    }

    LuaPlus::LuaObject globals = mLuaState->GetGlobals();
    globals.SetObject("__active_mods", activeModsValue);

    gpg::LogScopeEntry ruleMemoryScope(msvc8::string("MEM: %i bytes RULE"));
    {
      // Everything /lua/RuleInit.lua registers lands on this rules object, and
      // its progress callbacks report to the load control that asked for it.
      const BlueprintLoaderContextScope loaderContext(this, initHandler);
      (void)SCR_LuaDoScript(mLuaState, "/lua/RuleInit.lua", nullptr);
    }

    ruleMemoryScope.Emit();
    SetupCategories();
  }

  /**
   * Address: 0x0052B960 (FUN_0052B960)
   */
  LuaPlus::LuaObject RULE_GetDefaultPlayerOptions(LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return {};
    }

    LuaPlus::LuaObject lobbyModule = SCR_ImportLuaModule(state, "/lua/ui/lobby/lobbyComm.lua");
    LuaPlus::LuaObject getDefaultPlayerOptions = SCR_GetLuaTableField(state, lobbyModule, "GetDefaultPlayerOptions");
    if (getDefaultPlayerOptions.m_state == nullptr || getDefaultPlayerOptions.m_object.tt != LUA_TFUNCTION) {
      gpg::Warnf("RULE_GetDefaultPlayerOptions: missing lobbyComm.GetDefaultPlayerOptions().");
      return {};
    }

    LuaPlus::LuaFunction<LuaPlus::LuaObject> getDefaultsFn{getDefaultPlayerOptions};
    return getDefaultsFn();
  }

  /**
   * Address: 0x00528460 (FUN_00528460, Moho::RRuleGameRules::operator new)
   *
   * What it does:
   * Allocates one `RRuleGameRulesImpl` object and runs the concrete
   * constructor with active-mod payload + optional init wait-set pointer.
   */
  RRuleGameRules* RRuleGameRules::Create(const msvc8::string& activeMods, CBackgroundTaskControl* const initHandler)
  {
    auto* const storage = static_cast<RRuleGameRulesImpl*>(::operator new(sizeof(RRuleGameRulesImpl), std::nothrow));
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) RRuleGameRulesImpl(activeMods, initHandler);
  }

  /**
   * Address: 0x0051CF90 callsite family (func_GetPropBlueprint)
   *
   * What it does:
   * Adapter overload for callsites that still pass normalized id strings.
   */
  RPropBlueprint* RRuleGameRules::GetPropBlueprint(const msvc8::string& blueprintId)
  {
    RResId lookup{};
    lookup.name = msvc8::string(blueprintId.data(), blueprintId.size());
    return GetPropBlueprint(lookup);
  }

  /**
   * Address: 0x00529510 (FUN_00529510)
   *
   * What it does:
   * Executes the scalar-deleting wrapper lane for `RRuleGameRulesImpl` by
   * running the core destructor body and optionally releasing object storage.
   */
  RRuleGameRulesImpl* DestroyRRuleGameRulesImplWithDeleteFlag(
    RRuleGameRulesImpl* const object,
    const std::uint8_t deleteFlags
  )
  {
    if (object == nullptr) {
      return nullptr;
    }

    object->~RRuleGameRulesImpl();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(static_cast<void*>(object));
    }
    return object;
  }

  /**
   * Address: 0x00529700 (FUN_00529700)
   *
   * What it does:
   * Releases runtime blueprint/category/Lua storage owned by this concrete
   * rule object and decrements the rule instance counter.
   */
  RRuleGameRulesImpl::~RRuleGameRulesImpl()
  {
    DestroyBlueprintObjectsFromOrdinalArray(*this);

    DestroyBlueprintObjectsFromMap(mBeamBlueprints);
    DestroyBlueprintObjectsFromMap(mEmitterBlueprints);
    DestroyBlueprintObjectsFromMap(mTrailBlueprints);

    if (mLuaExports.mBegin && mLuaExports.mEnd) {
      for (auto* it = mLuaExports.mBegin; it != mLuaExports.mEnd; ++it) {
        DestroyLuaTaskListSentinel(static_cast<LuaTaskListNode*>(it->mTaskListSentinel));
        it->mTaskListSentinel = nullptr;
        it->mTaskListSize = 0u;
      }
    }

    delete[] mLuaExports.mBegin;
    mLuaExports.mBegin = nullptr;
    mLuaExports.mEnd = nullptr;
    mLuaExports.mCapacityEnd = nullptr;

    EnsureReloadQueueSentinelInitialized(*this);
    LuaReloadRequestNode* const sentinel = ReloadQueueSentinel(*this);
    LuaReloadRequestNode* node = sentinel->next;
    while (node && node != sentinel) {
      LuaReloadRequestNode* const next = node->next;
      delete node;
      node = next;
    }
    sentinel->next = sentinel;
    sentinel->prev = sentinel;

    // Address: 0x00529700 (FUN_00529700) calls FUN_00533E20
    // (EntityCategoryLookupTableRuntimeView's real destructor, see above)
    // directly, then `operator delete`s the block - exactly what a plain
    // typed `delete` compiles to.
    delete mEntityCategoryLookup;
    mEntityCategoryLookup = nullptr;

    DestroyBlueprintMapNodesOnly(mTrailBlueprints);
    DestroyBlueprintMapNodesOnly(mBeamBlueprints);
    DestroyBlueprintMapNodesOnly(mEmitterBlueprints);
    DestroyBlueprintMapNodesOnly(mMeshBlueprints);
    DestroyBlueprintMapNodesOnly(mPropBlueprints);
    DestroyBlueprintMapNodesOnly(mProjectileBlueprints);
    DestroyBlueprintMapNodesOnly(mUnitBlueprints);

    DestroyRuleFootprintsStorage(mFootprints);

    delete mLuaState;
    mLuaState = nullptr;

    RuleMutexView(*this).~mutex();
    RuleCtorPrefixView(*this).listener.~CDiskWatchListener();

    if (StatItem* const statItem = InstanceCounter<RRuleGameRules>::GetStatItem()) {
      float minusOne = -1.0f;
      (void)statItem->AddFloat(&minusOne);
    }
  }

  /**
   * Address: 0x00529C30 (FUN_00529C30, Moho::RRuleGameRulesImpl::SetupCategories)
   *
   * What it does:
   * Rebuilds the global Lua `categories` table from runtime category-lookup
   * map entries, then refreshes each unit blueprint's economy restrictions.
   */
  void RRuleGameRulesImpl::SetupCategories()
  {
    PublishCategoriesTable(*this, mLuaState);

    RRuleGameRulesBlueprintNode* unitNode = mUnitBlueprints.mHead->left;
    while (unitNode != mUnitBlueprints.mHead) {
      auto* const unitBlueprint = static_cast<RUnitBlueprint*>(unitNode->mBlueprint);
      if (unitBlueprint != nullptr) {
        unitBlueprint->AddEconomyRestrictions(this);
      }

      AdvanceBlueprintNodeSuccessor(&unitNode);
    }
  }

  /**
   * Address: 0x00529F70 (FUN_00529F70)
   *
   * What it does:
   * Exports active-mod and blueprint globals to the target root Lua state and
   * tracks the state in the runtime export-binding list.
   */
  void RRuleGameRulesImpl::ExportToLuaState(LuaPlus::LuaState* luaState)
  {
    if (!luaState || !mLuaState) {
      return;
    }

    const boost::mutex::scoped_lock exportLock(RuleMutexView(*this));

    LuaPlus::LuaState* const rootState = ResolveRootState(luaState);
    if (!rootState) {
      return;
    }

    SetGlobalCopy(mLuaState, rootState, "__active_mods");
    SetGlobalCopy(mLuaState, rootState, "__blueprints");

    // `categories` is rebuilt rather than copied: every entry becomes a new
    // EntityCategory userdata owned by the target state, exactly as the rules'
    // own state got its table from SetupCategories.
    PublishCategoriesTable(*this, rootState);

    (void)AddOrGetExportBinding(*this, rootState);
  }

  /**
   * Address: 0x0052A3D0 (FUN_0052A3D0)
   *
   * What it does:
   * Processes pending blueprint reload requests and syncs exported blueprint
   * globals for the target root Lua state.
   *
   * Drains the file-watcher set (`sPFWaitHandleSet`) of changed-file
   * notifications, looks up each path against the existing pending-reload
   * queue, and enqueues a fresh `LuaReloadRequestNode` (via
   * `EnqueueLuaReloadRequest`, which routes through
   * `ConstructLuaReloadRequestNode` = FUN_00528260) when no duplicate exists.
   * Then drains the matured reload-request queue and synchronizes the
   * blueprint table to the target root Lua state. The file-watcher drain step
   * is invoked here for fidelity with the binary's emission shape — the
   * `EnqueueLuaReloadRequest` symbol must be reachable from this caller so
   * the per-T constructor body keeps its bind site.
   */
  void RRuleGameRulesImpl::UpdateLuaState(LuaPlus::LuaState* luaState)
  {
    if (!luaState) {
      return;
    }

    // The whole body runs under the rules' own mutex at +0x38 - 0x0052A3D0
    // takes it at entry (`boost::mutex::do_lock(this + 56)`) and drops it at
    // 0x0052A3D0+0x???: the single `boost::mutex::unlock` on the way out.
    //
    // This is not incidental. One `RRuleGameRulesImpl` is shared by the world
    // session and the Sim - `WLD_DoLoading` publishes `wldSession->mRules`
    // into the launch info and `Sim::Sim` adopts it as `mRules` - and both
    // `CWldSession::SessionFrame` (main thread) and `Sim::AdvanceBeat` (sim
    // thread) call this every frame/beat. Both then read and push on the
    // rules' own `lua_State` inside `SynchronizeBlueprintTable`. Without the
    // lock the two threads interleave inside one 5000-entry `SCR_Copy` loop
    // over a single `lua_State`, which corrupts it and faults in `luaV_index`.
    boost::mutex::scoped_lock rulesLock(RuleMutexView(*this));

    // Drain pending file-watcher notifications. Each new path that isn't
    // already enqueued for reload becomes a fresh `LuaReloadRequestNode`
    // through the typed ctor binding.
    DrainFileWatcherIntoReloadQueue(*this);

    ProcessPendingReloadRequests(*this);

    LuaPlus::LuaState* const rootState = ResolveRootState(luaState);
    if (!rootState) {
      return;
    }

    RRuleGameRulesLuaExportBinding* const binding = FindExportBinding(*this, rootState);
    if (!binding) {
      return;
    }

    SynchronizeBlueprintTable(*this, rootState);
    ClearLuaTaskList(static_cast<LuaTaskListNode*>(binding->mTaskListSentinel));
    binding->mTaskListSize = 0u;
  }

  /**
   * Address: 0x0052AA20 (FUN_0052AA20)
   *
   * What it does:
   * Removes one root Lua-state export binding and clears its `__blueprints`
   * global slot.
   */
  void RRuleGameRulesImpl::CancelExport(LuaPlus::LuaState* luaState)
  {
    if (!luaState) {
      return;
    }

    LuaPlus::LuaState* const rootState = ResolveRootState(luaState);
    if (!rootState) {
      return;
    }

    RRuleGameRulesLuaExportBinding* const binding = FindExportBinding(*this, rootState);
    if (binding) {
      EraseExportBinding(*this, binding);
    }

    LuaPlus::LuaObject nilValue{};
    nilValue.AssignNil(rootState);
    LuaPlus::LuaObject globals = rootState->GetGlobals();
    globals.SetObject("__blueprints", nilValue);
  }

  /**
   * Address: 0x005282C0 (FUN_005282C0)
   *
   * What it does:
   * Returns the current blueprint ordinal count (number of entries in ordinal table).
   */
  int RRuleGameRulesImpl::AssignNextOrdinal()
  {
    return static_cast<int>(mBlueprintsByOrdinal.size());
  }

  /**
   * Address: 0x0052B1A0 (FUN_0052B1A0)
   *
   * What it does:
   * Returns blueprint pointer by ordinal index from the flat ordinal table.
   */
  RBlueprint* RRuleGameRulesImpl::GetBlueprintFromOrdinal(const int ordinal) const
  {
    if (ordinal < 0 || static_cast<std::size_t>(ordinal) >= mBlueprintsByOrdinal.size()) {
      return nullptr;
    }

    return mBlueprintsByOrdinal[static_cast<std::size_t>(ordinal)];
  }

  /**
   * Address: 0x005282E0 (FUN_005282E0)
   *
   * What it does:
   * Returns pointer to embedded rule-footprint blueprint storage.
   */
  const SRuleFootprintsBlueprint* RRuleGameRulesImpl::GetFootprints() const
  {
    return &mFootprints;
  }

  /**
   * Address: 0x0052AAE0 (FUN_0052AAE0)
   *
   * What it does:
   * Finds the closest named footprint with matching occupancy caps by minimizing
   * `max(|sizeX-dx|, |sizeZ-dz|)` over the runtime footprint list.
   */
  const SNamedFootprint* RRuleGameRulesImpl::FindFootprint(const SFootprint& footprint, const char* name) const
  {
    (void)name;
    const auto* const footprints = GetFootprints();
    const auto* const sentinel = footprints ? footprints->mHead : nullptr;
    if (!sentinel) {
      return nullptr;
    }

    const std::uint8_t targetOccupancy = static_cast<std::uint8_t>(footprint.mOccupancyCaps);
    int bestDistance = std::numeric_limits<std::int16_t>::max();
    const SNamedFootprint* bestFootprint = nullptr;

    for (auto* node = sentinel->next; node && node != sentinel; node = node->next) {
      const std::uint8_t candidateOccupancy = static_cast<std::uint8_t>(node->value.mOccupancyCaps);
      if (candidateOccupancy != targetOccupancy) {
        continue;
      }

      const int dx = std::abs(static_cast<int>(node->value.mSizeX) - static_cast<int>(footprint.mSizeX));
      const int dz = std::abs(static_cast<int>(node->value.mSizeZ) - static_cast<int>(footprint.mSizeZ));
      const int distance = std::max(dx, dz);
      if (distance < bestDistance) {
        bestDistance = distance;
        bestFootprint = &node->value;
      }
    }

    return bestFootprint;
  }

  /**
   * Address: 0x005282F0 (FUN_005282F0)
   */
  const RRuleGameRulesBlueprintMap& RRuleGameRulesImpl::GetUnitBlueprints()
  {
    return mUnitBlueprints;
  }

  /**
   * Address: 0x00528300 (FUN_00528300)
   */
  const RRuleGameRulesBlueprintMap& RRuleGameRulesImpl::GetPropBlueprints()
  {
    return mPropBlueprints;
  }

  /**
   * Address: 0x00528320 (FUN_00528320)
   */
  const RRuleGameRulesBlueprintMap& RRuleGameRulesImpl::GetProjectileBlueprints()
  {
    return mProjectileBlueprints;
  }

  /**
   * Address: 0x00528310 (FUN_00528310)
   */
  const RRuleGameRulesBlueprintMap& RRuleGameRulesImpl::GetMeshBlueprints()
  {
    return mMeshBlueprints;
  }

  /**
   * Address: 0x0052AEB0 (FUN_0052AEB0)
   *
   * What it does:
   * Entity-blueprint union lookup: unit -> projectile -> prop.
   */
  REntityBlueprint* RRuleGameRulesImpl::GetEntityBlueprint(const RResId& resId)
  {
    if (RUnitBlueprint* const unit = GetUnitBlueprint(resId)) {
      return static_cast<REntityBlueprint*>(unit);
    }

    if (RProjectileBlueprint* const projectile = GetProjectileBlueprint(resId)) {
      return static_cast<REntityBlueprint*>(projectile);
    }

    return static_cast<REntityBlueprint*>(GetPropBlueprint(resId));
  }

  /**
   * Address: 0x0052AB70 (FUN_0052AB70)
   */
  RUnitBlueprint* RRuleGameRulesImpl::GetUnitBlueprint(const RResId& resId)
  {
    return LookupBlueprintByResId<RUnitBlueprint>(mUnitBlueprints, resId);
  }

  /**
   * Address: 0x0052AD10 (FUN_0052AD10)
   */
  RPropBlueprint* RRuleGameRulesImpl::GetPropBlueprint(const RResId& resId)
  {
    return LookupBlueprintByResId<RPropBlueprint>(mPropBlueprints, resId);
  }

  /**
   * Address: 0x0052ADE0 (FUN_0052ADE0)
   */
  RMeshBlueprint* RRuleGameRulesImpl::GetMeshBlueprint(const RResId& resId)
  {
    if (resId.name.empty() || !mMeshBlueprints.mHead) {
      return nullptr;
    }

    const msvc8::string lookupId(resId.name.view());
    RRuleGameRulesBlueprintNode* const node = FindMeshBlueprintNodeByBlueprintId(mMeshBlueprints, lookupId);
    if (!node || node == mMeshBlueprints.mHead) {
      return nullptr;
    }

    return static_cast<RMeshBlueprint*>(node->mBlueprint);
  }

  /**
   * Address: 0x0052AC40 (FUN_0052AC40)
   */
  RProjectileBlueprint* RRuleGameRulesImpl::GetProjectileBlueprint(const RResId& resId)
  {
    return LookupBlueprintByResId<RProjectileBlueprint>(mProjectileBlueprints, resId);
  }

  /**
   * Address: 0x0052AEF0 (FUN_0052AEF0)
   */
  REmitterBlueprint* RRuleGameRulesImpl::GetEmitterBlueprint(const RResId& resId)
  {
    if (resId.name.empty() || !mEmitterBlueprints.mHead) {
      return nullptr;
    }

    const msvc8::string lookupId(resId.name.view());
    RRuleGameRulesBlueprintNode* const node = FindEmitterBlueprintNodeByBlueprintId(mEmitterBlueprints, lookupId);
    if (!node || node == mEmitterBlueprints.mHead) {
      return nullptr;
    }

    return static_cast<REmitterBlueprint*>(node->mBlueprint);
  }

  /**
   * Address: 0x0052AFC0 (FUN_0052AFC0)
   */
  RBeamBlueprint* RRuleGameRulesImpl::GetBeamBlueprint(const RResId& resId)
  {
    return LookupBlueprintByResId<RBeamBlueprint>(mBeamBlueprints, resId);
  }

  /**
   * Address: 0x0052B090 (FUN_0052B090)
   */
  RTrailBlueprint* RRuleGameRulesImpl::GetTrailBlueprint(const RResId& resId)
  {
    if (resId.name.empty() || !mTrailBlueprints.mHead) {
      return nullptr;
    }

    const msvc8::string lookupId(resId.name.view());
    RRuleGameRulesBlueprintNode* const node = FindTrailBlueprintNodeByBlueprintId(mTrailBlueprints, lookupId);
    if (!node || node == mTrailBlueprints.mHead) {
      return nullptr;
    }

    return static_cast<RTrailBlueprint*>(node->mBlueprint);
  }

  /**
   * Address: 0x0052B160 (FUN_0052B160)
   *
   * What it does:
   * Effect-blueprint union lookup: emitter -> beam -> trail.
   */
  REffectBlueprint* RRuleGameRulesImpl::GetEffectBlueprint(const RResId& resId)
  {
    if (REmitterBlueprint* const emitter = GetEmitterBlueprint(resId)) {
      return static_cast<REffectBlueprint*>(emitter);
    }

    if (RBeamBlueprint* const beam = GetBeamBlueprint(resId)) {
      return static_cast<REffectBlueprint*>(beam);
    }

    return static_cast<REffectBlueprint*>(GetTrailBlueprint(resId));
  }

  /**
   * Address: 0x00528330 (FUN_00528330)
   */
  unsigned int RRuleGameRulesImpl::GetUnitCount() const
  {
    return mUnitBlueprints.mSize;
  }

  /**
    * Alias of FUN_0052B1E0 (non-canonical helper lane).
   *
   * What it does:
   * Delegates category-name lookup to the shared resolver implementation.
   */
  const CategoryWordRangeView* RRuleGameRulesImpl::GetEntityCategory(const char* categoryName) const
  {
    const auto* const resolver = reinterpret_cast<const EntityCategoryLookupResolver*>(this);
    return resolver->EntityCategoryLookupResolver::GetEntityCategory(categoryName);
  }

  /**
   * Address: 0x0052B280 (FUN_0052B280, Moho::RRuleGameRulesImpl::ParseEntityCategory)
   * VTable slot: 23
   *
   * IDA signature:
   * Moho::EntityCategory* __thiscall Moho::RRuleGameRulesImpl::ParseEntityCategory(
   *     Moho::RRuleGameRulesImpl* this, Moho::EntityCategory* out, const char* expr);
   *
   * What it does:
   * Thin virtual wrapper. Forwards the category-lookup table
   * (`this->mEntityCategoryLookup`, +0xC4 - the real
   * `EntityCategoryLookupTableRuntimeView` this class now owns, not the
   * absorbed `void*` it used to be) and the expression to the free function
   * `moho::ParseEntityCategory` (0x005552F0), which builds the result in
   * place, and returns it by value.
   */
  CategoryWordRangeView RRuleGameRulesImpl::ParseEntityCategory(const char* categoryExpression) const
  {
    CategoryWordRangeView out;
    (void)moho::ParseEntityCategory(mEntityCategoryLookup, &out, categoryExpression);
    return out;
  }

  /**
   * Address: 0x0052B2B0 (FUN_0052B2B0)
   *
   * What it does:
   * Extends the simulation checksum with deterministic blueprint/rule tables.
   */
  void RRuleGameRulesImpl::UpdateChecksum(void* md5Context, void* fileHandle)
  {
    auto* const context = static_cast<gpg::MD5Context*>(md5Context);
    auto* const file = static_cast<std::FILE*>(fileHandle);
    if (!context) {
      return;
    }

    if (file) {
      std::fprintf(file, "Named Footprints:\n");
    }

    // Preserve footprint-table contribution (binary hashes SRuleFootprintsBlueprint here).
    context->Update(&mFootprints, sizeof(mFootprints));

    auto blueprintCount = static_cast<std::uint32_t>(mBlueprintsByOrdinal.size());
    context->Update(&blueprintCount, sizeof(blueprintCount));

    for (std::uint32_t ordinal = 0; ordinal < blueprintCount; ++ordinal) {
      RBlueprint* const blueprint = mBlueprintsByOrdinal[ordinal];
      const char* id = nullptr;
      if (blueprint) {
        id = blueprint->mBlueprintId.c_str();
      }

      if (file) {
        std::fprintf(file, "%s:\n", id ? id : "<NULL>");
      }

      const char* const hashText = id ? id : "<NULL>";
      context->Update(hashText, std::strlen(hashText) + 1u);

      const std::int32_t ordinalValue = blueprint ? blueprint->mBlueprintOrdinal : -1;
      context->Update(&ordinalValue, sizeof(ordinalValue));
    }

    const std::uint32_t unitCount = mUnitBlueprints.mSize;
    const std::uint32_t projectileCount = mProjectileBlueprints.mSize;
    const std::uint32_t propCount = mPropBlueprints.mSize;
    const std::uint32_t meshCount = mMeshBlueprints.mSize;
    context->Update(&unitCount, sizeof(unitCount));
    context->Update(&projectileCount, sizeof(projectileCount));
    context->Update(&propCount, sizeof(propCount));
    context->Update(&meshCount, sizeof(meshCount));
  }

  /**
   * Address: 0x00511900 (FUN_00511900)
   *
   * What it does:
   * Upcasts one reflected reference to `RRuleGameRules` using the secondary
   * cache lane and returns the typed object pointer when compatible.
   */
  [[nodiscard]] RRuleGameRules* CastRRuleGameRulesFromRRefSecondary(const gpg::RRef& source)
  {
    gpg::RType* type = RRuleGameRules::sType2;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(RRuleGameRules));
      RRuleGameRules::sType2 = type;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, type);
    return static_cast<RRuleGameRules*>(upcast.mObj);
  }

  /**
   * Address: 0x00537810 (FUN_00537810)
   *
   * What it does:
   * Upcasts one reflected reference to `RRuleGameRules` using the primary
   * cache lane and returns the typed object pointer when compatible.
   */
  [[nodiscard]] RRuleGameRules* CastRRuleGameRulesFromRRefPrimary(const gpg::RRef& source)
  {
    gpg::RType* type = RRuleGameRules::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(RRuleGameRules));
      RRuleGameRules::sType = type;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, type);
    return static_cast<RRuleGameRules*>(upcast.mObj);
  }
} // namespace moho
