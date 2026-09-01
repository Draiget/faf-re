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
#include "gpg/core/containers/String.h"
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

  // EntityCategoryLookupTableRuntimeView used to own a hand-rolled RB-tree
  // reimplementation here (CategoryLookupNodeRuntimeView/
  // CategoryLookupMapRuntimeView, a per-TU duplicate of the exact same
  // hand-rolled-tree anti-pattern Sim.cpp's CategoryLookupMapView/
  // CategoryLookupNodeView had -- see commit 5bf090ef for that sibling fix).
  // Migrated to a real `msvc8::map<msvc8::string, CategoryLookupValue>`; the
  // full type (shared with Sim.cpp, which reaches into the same live object
  // through `RRuleGameRulesImpl::mEntityCategoryLookup`) now lives in
  // RRuleGameRules.h instead of being forward-declared there and redefined
  // here, per the CLAUDE.md duplicate-layout contract. The tree-walk helper
  // functions that used to follow this comment (AllocateCategoryLookupHeadNodeRuntime,
  // LeftmostCategoryLookupDescendant, RightmostCategoryLookupDescendant,
  // RotateCategoryLookupNodeLeft/Right, AdvanceCategoryLookupNodeSuccessor,
  // EraseCategoryLookupNode, DestroyCategoryLookupSubtree,
  // EraseCategoryLookupNodeRange) are gone too -- their binary addresses
  // (FUN_00556DE0, FUN_0052D960, FUN_00536AA0, FUN_00536A50/FUN_00536AE0,
  // FUN_0052CC30, FUN_00536010, FUN_005369D0, FUN_00535750) are now cited on
  // RbTree.h's `buy_head`/`rb_min`/`rb_max`/`rotate_left`/`rotate_right`/
  // `rb_increment`/`erase_node`/`destroy_subtree`/`erase_range` members,
  // which already implement this exact instantiation's shape with zero
  // template changes (independently re-verified against the raw decompiles
  // for this migration, not just re-cited from the Sim.cpp precedent).

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

    template <typename TValue>
    [[nodiscard]] TValue* StoreAdapterLane(TValue* const outValue, const TValue value) noexcept
    {
      *outValue = value;
      return outValue;
    }

    [[nodiscard]] void** StoreOpaquePointerLane(void** const outValue, void* const value) noexcept
    {
      return StoreAdapterLane(outValue, value);
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
     * Address: 0x0052AC40 (FUN_0052AC40, Moho::RRuleGameRulesImpl::GetProjectileBlueprint)
     * and its whole sibling family - FUN_0052AB70 (GetUnitBlueprint),
     * FUN_0052AD10 (GetPropBlueprint), FUN_0052ADE0 (GetMeshBlueprint),
     * FUN_0052AEF0 (GetEmitterBlueprint), FUN_0052AFC0 (GetBeamBlueprint),
     * FUN_0052B090 (GetTrailBlueprint). All seven are the same body over a
     * different map; shared search primitive at 0x0052C0A0 (`sub_52C0A0`, a
     * plain `std::string::operator<` tree search - confirmed ground truth, no
     * hidden normalization).
     *
     * What it does:
     * Looks up a blueprint by its registered resource id. The primary lookup
     * is byte-for-byte ground truth: the map is keyed by whatever
     * `ResolveNormalizedBlueprintId` (Sim.cpp) computed at registration time
     * (`gpg::STR_ToLower` only - slash direction is whatever the Lua source
     * string used, forward-slash for every current blueprint kind), and
     * `sub_52C0A0`'s tree search is a raw lexicographic compare with no
     * normalization of its own - confirmed by reading both ground-truth
     * bodies directly.
     *
     * Ground-truth-faithful fallback:
     * `cfunc_EntityCreateProjectileL` (0x0068A110) builds its lookup key via
     * `gpg::STR_InitFilename`/`STR_CanonizeFilename`, which - also confirmed
     * ground truth, same call sequence in FUN_0068A110 - produces lowercase
     * BACKSLASH form. `CEffectManagerImpl`'s `LookupEmitterBlueprint` /
     * `LookupTrailBlueprint` build their keys the identical way, so the
     * emitter and trail lookups miss for exactly the same reason - confirmed
     * live: a `/map SCMP_009` run warns "Failed to create emitter as you
     * passed in an invalid blueprint name /effects/emitters/
     * teleport_ring_01_emit.bp" on every commander warp-in, which then makes
     * `unitteleport01_script.lua(61)`'s `ScaleEmitter` call fail on the nil
     * return. That is a genuine, reproducible mismatch against the
     * forward-slash map key for any nested-path blueprint id (e.g.
     * `/effects/entities/UnitTeleport01/UnitTeleport01_proj.bp`, confirmed
     * live via `/spewbp` against the registered key and the "Invalid
     * blueprint" warning): every individual function on both sides matches
     * its own ground truth exactly, so this is a latent defect in the
     * original engine that 2007-era content apparently never exercised, not
     * a recovery error - current FAF content does exercise it, and an
     * uncaught error here kills the calling Lua coroutine
     * (`LuaState::Error` is an `__imp_*` LuaPlus import; a Lua error inside a
     * forked thread's `lua_resume` does not return to the caller - confirmed
     * against `CLuaTask.cpp`), permanently blocking `CommandUnit.lua`'s
     * warp-in reveal (`ShowBone`/`SetBlockCommandQueue(false)`).
     *
     * The retry below is strictly additive: it only runs after the primary,
     * ground-truth lookup has already failed, and it can only turn an
     * existing failure into a success - it never changes the result of a
     * lookup that already succeeds, so it carries none of the blast-radius
     * risk of changing the shared registration key itself (see
     * `ResolveNormalizedBlueprintId`, Sim.cpp - do not touch that function
     * for this bug; a prior attempt to do so broke AI brain builder-list
     * lookups that depend on its forward-slash-preserving output).
     */
    template <typename TBlueprint>
    [[nodiscard]] TBlueprint*
    LookupBlueprintByResId(const RRuleGameRulesBlueprintMap& map, const RResId& resId) noexcept
    {
      if (resId.name.empty()) {
        return nullptr;
      }

      if (const auto found = map.find(msvc8::string(resId.name.view())); found != map.end()) {
        return static_cast<TBlueprint*>(found->second);
      }

      msvc8::string slashNormalized(resId.name.view());
      gpg::STR_NormalizeFilenameLowerSlash(slashNormalized);

      const auto fallbackFound = map.find(slashNormalized);
      if (fallbackFound == map.end()) {
        return nullptr;
      }

      return static_cast<TBlueprint*>(fallbackFound->second);
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
      if (categoryLookup == nullptr) {
        return;
      }

      // `categoryMap.begin()`/`end()` is `rb_tree::leftmost()`/`header()` --
      // the same `head->left` / `head` walk this loop used to do by hand,
      // now through the real container's own iterator (RbTree.h `rb_iterator`).
      for (const auto& [categoryName, categoryValue] : categoryLookup->mCategoryMap) {
        CategoryWordRangeView categoryValueCopy = categoryValue;
        LuaPlus::LuaObject categoryLuaObject{};
        (void)func_NewEntityCategory(targetState, &categoryLuaObject, &categoryValueCopy);
        categoriesTable.SetObject(categoryName.c_str(), categoryLuaObject);
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
     * Address: 0x0052DBA0 (FUN_0052DBA0)
     *
     * What it does:
     * Releases one raw runtime storage lane through global `operator delete`.
     */
    void DeleteRuntimeStorageLane(void* const storage)
    {
      ::operator delete(storage);
    }

    /**
     * Returns the live export-binding count. Trivial forwarding wrapper kept
     * as a named helper (rather than inlining `.size()` at each call site)
     * because `AddOrGetExportBinding` and `ReserveExportBindingCapacity`
     * both already spelled it out this way before the `mMaps` migration --
     * no address of its own; the binary computes this inline at each of its
     * own call sites rather than as a separate out-of-line symbol.
     */
    [[nodiscard]] std::size_t ExportBindingCount(const RRuleGameRulesImpl& rules) noexcept
    {
      return rules.mMaps.size();
    }

    /**
     * Grows `mMaps` to at least `requestedCapacity` live-binding slots.
     *
     * No address of its own (the binary inlines this as part of
     * `ExportToLuaState`'s own capacity check ahead of its `insert` call,
     * cited in full on `legacy/containers/Vector.h`'s `insert(pos, count,
     * value)` member as `FUN_0052DBE0`). Delegates entirely to
     * `msvc8::vector<T>::reserve()`, which is the fix for a genuine
     * behavioral divergence the previous hand-rolled body had: it allocated
     * via `new RRuleGameRulesLuaExportBinding[requestedCapacity]{}`
     * (default-constructing every slot up to the full new capacity, not
     * just the live prefix) and *assigned* the live elements into those
     * already-live slots, whereas the real binary's growth path -- and this
     * member's own `reserve()`/`reallocate_to()` -- allocates raw,
     * unconstructed memory and only *constructs* exactly the live prefix
     * into it (see the divergence note on `RRuleGameRulesImpl::mMaps`,
     * RRuleGameRules.h, for the full evidence trail: `FUN_0052D590`'s and
     * `FUN_00536DF0`'s raw disassembly both show a scalar `operator
     * delete`, never `delete[]`, which only pairs with a real vector's
     * raw-allocate/exact-construct shape).
     */
    void ReserveExportBindingCapacity(RRuleGameRulesImpl& rules, const std::size_t requestedCapacity)
    {
      rules.mMaps.reserve(requestedCapacity);
    }

    [[nodiscard]] RRuleGameRulesLuaExportBinding*
    FindExportBinding(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState) noexcept
    {
      if (!rootState) {
        return nullptr;
      }

      for (auto& binding : rules.mMaps) {
        if (binding.mRootState == rootState) {
          return &binding;
        }
      }
      return nullptr;
    }

    [[nodiscard]] const RRuleGameRulesLuaExportBinding*
    FindExportBinding(const RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState) noexcept
    {
      return FindExportBinding(const_cast<RRuleGameRulesImpl&>(rules), rootState);
    }

    /**
     * Address: 0x0052DBE0 (FUN_0052DBE0, `msvc8::vector<
     * RRuleGameRulesLuaExportBinding>::insert(pos, count, value)`, cited in
     * full on that member in `legacy/containers/Vector.h`) -- the "not
     * found" path below now calls this method by name instead of hand-
     * rolling the append (bump `mEnd`, write fields, `.clear()` the
     * already-live default-constructed set). That hand-rolled shape only
     * worked because the previous `RRuleGameRulesLuaExportBindingArray`
     * model over-constructed its spare capacity; `insert(end(), 1, value)`
     * is the real API and the real binary's own call, confirmed reachable
     * from `RRuleGameRulesImpl::ExportToLuaState` (`FUN_00529F70`) at `call
     * sub_52DBE0`, 0x0052A31D.
     */
    [[nodiscard]] RRuleGameRulesLuaExportBinding*
    AddOrGetExportBinding(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState)
    {
      if (!rootState) {
        return nullptr;
      }

      if (RRuleGameRulesLuaExportBinding* const existing = FindExportBinding(rules, rootState)) {
        return existing;
      }

      RRuleGameRulesLuaExportBinding freshBinding{};
      freshBinding.mRootState = rootState;
      // `mPendingBlueprintOrdinals` is already a freshly default-constructed
      // empty `msvc8::set<uint32_t>` via `RRuleGameRulesLuaExportBinding{}`'s
      // member init -- no separate `.clear()` needed.

      // `insert`'s own internal `cur+count <= capacity()` check subsumes the
      // old hand-rolled "count >= capacity, so reserve" guard; growth (when
      // needed) goes through `recommended_capacity()`'s real 1.5x policy
      // instead of the previous hand-rolled `capacity*2` guess.
      return rules.mMaps.insert(rules.mMaps.end(), 1, freshBinding);
    }

    /**
     * Address: 0x0052BEE0 (FUN_0052BEE0) + 0x00536DA0 (FUN_00536DA0) --
     * `msvc8::vector<RRuleGameRulesLuaExportBinding>::erase(iterator)`'s
     * real emission for this element type, cited in full on that method in
     * `legacy/containers/Vector.h`. The binary keeps this method's shift
     * LOOP inlined directly into `RRuleGameRulesImpl::CancelExport`
     * (`FUN_0052AA20`) rather than as a separate out-of-line `erase`
     * symbol -- `FUN_0052BEE0` is the per-slot shift-assign step that loop
     * calls, not the whole method -- but the source-level operation
     * `CancelExport` performs is unambiguously "erase this one binding",
     * which this method already models exactly (shift the tail down via
     * `RRuleGameRulesLuaExportBinding`'s implicit `operator=`, decrement
     * `last_`, destroy the vacated slot via its implicit destructor -- see
     * the address citations on that struct's declaration in
     * RRuleGameRules.h).
     */
    void EraseExportBinding(RRuleGameRulesImpl& rules, RRuleGameRulesLuaExportBinding* const binding)
    {
      if (!binding) {
        return;
      }

      rules.mMaps.erase(binding);
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
      // The binary deletes the pointed-to blueprints and nulls each lane but
      // leaves the nodes in place; the map's own destructor tears the tree
      // down afterwards.
      for (auto& entry : map) {
        if (entry.second != nullptr) {
          delete static_cast<RBlueprint*>(entry.second);
          entry.second = nullptr;
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

  // The `owner` handle written below (mCategoryFallback's universe lane and
  // mWordUniverseHandle) is the table's only back-reference to the rules
  // that own it: `ParseEntityCategory` seeds every clause accumulator from
  // it (0x00555323 reads [esi+38h]), each map entry it creates inherits the
  // same handle, and `EntityCategory::Add` calls `GetBlueprintFromOrdinal`
  // through it to remap the clause's bits. A null owner here means the very
  // first economy restriction parsed during category setup would dispatch
  // through a null rules pointer.
  //
  // Mangled-name note: the binary's constructor mangles as
  // `Moho::EntityCategorySet::EntityCategorySet` but the destructor this
  // class no longer declares explicitly (see below) mangled as
  // `Moho::EntityCategory::~EntityCategory` - a different class name over
  // the identical `this` layout (most likely an
  // EntityCategorySet-derives-from-EntityCategory relationship where the
  // derived class adds no members and never got its own destructor symbol).
  // Both of those binary names are already taken in this codebase by
  // unrelated types (`Moho::EntityCategorySet` = the 0x28-byte
  // `BVSet<const RBlueprint*, EntityCategoryHelper>` alias in
  // EntityCategoryReflection.h; `Moho::EntityCategory` = the static-method
  // utility class in the same header), so this object keeps its
  // pre-existing source-level name instead of colliding with either.
  //
  // EH note: `FUN_005551F0`'s unwind funclet at 0x00BA0453 (FUN_00533FD0)
  // runs only if construction throws after the category map is live but
  // before the word-range fallback is - it re-derives the same
  // `erase(first,last)`-then-`operator delete`-the-head tail
  // `~EntityCategoryLookupTableRuntimeView`'s implicit destructor performs
  // via `mCategoryMap`'s own real destructor (`RbTree.h`'s `erase_range`/
  // `~rb_tree` members). Per RULE ONE an unwind funclet target maps to no
  // source line of its own, so it is cited here rather than written as a
  // separate function.
  EntityCategoryLookupTableRuntimeView::EntityCategoryLookupTableRuntimeView(
    const RRuleGameRulesImpl* const owner
  ) noexcept
  {
    // `mCategoryMap`'s sentinel head is already live at this point (member
    // default-initialization runs before this body, real `msvc8::map`
    // default ctor -> `RbTree.h` `buy_head()`, cited FUN_00556DE0). The
    // binary re-runs the whole-subtree destroyer on the fresh (already
    // empty) head before re-asserting the empty-tree links one more time -
    // an inert second pass, preserved here as an explicit `clear()` call
    // (RbTree.h `clear()` member, also cited FUN_005551F0) for exact
    // instruction-sequence fidelity with FUN_005551F0 at
    // 0x0055525A-0x00555276 rather than silently dropped as dead code.
    mCategoryMap.clear();

    const auto ownerHandle = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(owner));
    mCategoryFallback.ResetToEmpty(ownerHandle);
    mWordUniverseHandle = ownerHandle;
  }

  // No explicit destructor: `mCategoryMap` (`msvc8::map<msvc8::string,
  // CategoryLookupValue>`) and `mCategoryFallback` (`CategoryWordRangeView`)
  // are both real typed members, so implicit member destruction already runs
  // their own real destructors in reverse declaration order - exactly
  // matching FUN_00533E20's (`Moho::EntityCategory::~EntityCategory`) two
  // real pieces of work: `mCategoryMap`'s teardown is `RbTree.h`'s
  // `~rb_tree()` emission for this instantiation (cited there, erase_range +
  // free the head), and the leading `mSet.mUsed` inline-vector release the
  // raw decompile shows ahead of it is `CategoryWordRangeView`'s own
  // destructor body, inlined into FUN_00533E20 by the compiler - not
  // hand-written source of this class at all (RULE ONE: "member
  // destructors... the source body says nothing; MSVC emits it"). A prior
  // recovery pass wrote this class's destructor by hand as an explicit
  // function precisely reproducing `~rb_tree()`'s shape over the old
  // hand-rolled tree view; removing it in favor of the implicit destructor
  // does not change behavior, it removes a hand-transcription of
  // compiler-emitted glue.

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
    , mMaps{}
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

    // `mMaps{}` in the member-init list above already default-constructs a
    // real, empty `msvc8::vector<RRuleGameRulesLuaExportBinding>` (null
    // proxy/first_/last_/end_) -- no separate field-by-field reset needed
    // now that it is a real vector rather than a hand-rolled pointer quad.

    mFootprints.mAllocProxy = nullptr;
    mFootprints.mHead = AllocateFootprintSentinelNode();
    mFootprints.mSize = 0u;

    // Each map builds its own sentinel head in its constructor; the binary
    // open-codes that seven times here, once per table, through a per-table
    // head allocator.

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

    // No manual teardown here: `mMaps` (now a real `msvc8::vector<
    // RRuleGameRulesLuaExportBinding>`) is destroyed by ordinary implicit
    // member destruction after this body returns, exactly matching
    // `FUN_00529700`'s own instruction sequence -- its recorded evidence
    // ("FUN_00529700 dtor direct mMaps teardown at 0x00529A9B-0x00529ABF...
    // call FUN_00536DF0(mBegin,mEnd), delete mBegin" -- scalar, not
    // `delete[]`) is the per-element destroy loop (`FUN_00536DF0`,
    // `skip`-classified as compiler-emitted glue) followed by a raw
    // `operator delete` on the buffer, which is precisely what
    // `msvc8::vector<T>::~vector()` (`destroy_range` + `operator delete`,
    // `legacy/containers/Vector.h`) already does. Same pattern already used
    // just below for the seven blueprint maps.
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

    // Each map's destructor frees its own nodes and sentinel head; the
    // binary open-codes that teardown seven times here, in reverse
    // declaration order, which is what member destruction does anyway.

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

    for (const auto& entry : mUnitBlueprints) {
      auto* const unitBlueprint = static_cast<RUnitBlueprint*>(entry.second);
      if (unitBlueprint != nullptr) {
        unitBlueprint->AddEconomyRestrictions(this);
      }
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
    binding->mPendingBlueprintOrdinals.clear();
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
    return LookupBlueprintByResId<RMeshBlueprint>(mMeshBlueprints, resId);
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
    return LookupBlueprintByResId<REmitterBlueprint>(mEmitterBlueprints, resId);
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
    return LookupBlueprintByResId<RTrailBlueprint>(mTrailBlueprints, resId);
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
    return mUnitBlueprints.size();
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

    const std::uint32_t unitCount = mUnitBlueprints.size();
    const std::uint32_t projectileCount = mProjectileBlueprints.size();
    const std::uint32_t propCount = mPropBlueprints.size();
    const std::uint32_t meshCount = mMeshBlueprints.size();
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
