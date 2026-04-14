#include "RRuleGameRules.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <typeinfo>

#include "../resource/RResId.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Tree.h"
#include "lua/LuaObject.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

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
     * Address: 0x0052C420 (FUN_0052C420, std::map_string_RBeamBlueprint::operator[])
     *
     * What it does:
     * Returns the matched blueprint-map node for one key lookup, or the tree
     * sentinel head when no exact key match exists.
     */
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    FindBlueprintNodeByMapSubscript(const RRuleGameRulesBlueprintMap& map, const msvc8::string& lookupId) noexcept
    {
      RRuleGameRulesBlueprintNode* const candidate =
        msvc8::lower_bound_node<RRuleGameRulesBlueprintNode, &RRuleGameRulesBlueprintNode::mIsSentinel>(
          map.mHead, lookupId, [](const RRuleGameRulesBlueprintNode& node, const msvc8::string& query) {
          return CompareBlueprintIds(node.mBlueprintId, query) < 0;
        }
        );

      if (candidate == nullptr || candidate == map.mHead) {
        return map.mHead;
      }

      return (CompareBlueprintIds(lookupId, candidate->mBlueprintId) < 0) ? map.mHead : candidate;
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

    [[nodiscard]] LuaPlus::LuaObject
    CopyLuaObjectToState(const LuaPlus::LuaObject& source, LuaPlus::LuaState* const targetState)
    {
      if (!targetState || !targetState->GetCState()) {
        return {};
      }

      LuaPlus::LuaObject copy{};
      lua_State* const lstate = targetState->GetCState();
      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(source).PushStack(lstate);
      copy = LuaPlus::LuaObject(LuaPlus::LuaStackObject(targetState, -1));
      lua_settop(lstate, savedTop);
      return copy;
    }

    void SetGlobalCopy(
      LuaPlus::LuaState* const sourceState, LuaPlus::LuaState* const targetRootState, const char* const globalName
    )
    {
      if (!sourceState || !targetRootState || !globalName) {
        return;
      }

      LuaPlus::LuaObject sourceValue = sourceState->GetGlobal(globalName);
      LuaPlus::LuaObject copied = CopyLuaObjectToState(sourceValue, targetRootState);
      LuaPlus::LuaObject globals = targetRootState->GetGlobals();
      globals.SetObject(globalName, copied);
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

    void EraseExportBinding(RRuleGameRulesImpl& rules, RRuleGameRulesLuaExportBinding* const binding)
    {
      if (!binding || !rules.mLuaExports.mBegin || !rules.mLuaExports.mEnd) {
        return;
      }

      DestroyLuaTaskListSentinel(static_cast<LuaTaskListNode*>(binding->mTaskListSentinel));
      binding->mTaskListSentinel = nullptr;
      binding->mTaskListSize = 0u;

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

    void SynchronizeBlueprintTable(RRuleGameRulesImpl& rules, LuaPlus::LuaState* const rootState)
    {
      if (!rootState || !rules.mLuaState) {
        return;
      }

      LuaPlus::LuaObject destinationBlueprints = rootState->GetGlobal("__blueprints");
      if (!destinationBlueprints.IsTable()) {
        LuaPlus::LuaObject globals = rootState->GetGlobals();
        LuaPlus::LuaObject replacementTable{};
        replacementTable.AssignNewTable(rootState, 0, 0);
        globals.SetObject("__blueprints", replacementTable);
        destinationBlueprints = rootState->GetGlobal("__blueprints");
      }

      LuaPlus::LuaObject sourceBlueprints = rules.mLuaState->GetGlobal("__blueprints");
      if (!sourceBlueprints.IsTable()) {
        return;
      }

      const std::size_t ordinalCount = (rules.mBlueprintByOrdinalBegin && rules.mBlueprintByOrdinalEnd &&
                                        rules.mBlueprintByOrdinalEnd >= rules.mBlueprintByOrdinalBegin)
        ? static_cast<std::size_t>(rules.mBlueprintByOrdinalEnd - rules.mBlueprintByOrdinalBegin)
        : 0u;

      for (std::size_t ordinal = 0; ordinal < ordinalCount; ++ordinal) {
        LuaPlus::LuaObject sourceEntry = sourceBlueprints.GetByIndex(static_cast<int32_t>(ordinal));
        LuaPlus::LuaObject copiedEntry = CopyLuaObjectToState(sourceEntry, rootState);
        destinationBlueprints.SetObject(static_cast<int32_t>(ordinal), copiedEntry);

        RBlueprint* const blueprint = rules.mBlueprintByOrdinalBegin[ordinal];
        if (blueprint) {
          const char* const blueprintId = blueprint->mBlueprintId.c_str();
          if (blueprintId && *blueprintId) {
            destinationBlueprints.SetObject(blueprintId, copiedEntry);
          }
        }
      }
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
   * Releases reconstructed Lua export/reload runtime helpers owned by this
   * wrapper implementation.
   */
  RRuleGameRulesImpl::~RRuleGameRulesImpl()
  {
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

    LuaPlus::LuaState* const rootState = ResolveRootState(luaState);
    if (!rootState) {
      return;
    }

    SetGlobalCopy(mLuaState, rootState, "__active_mods");
    SetGlobalCopy(mLuaState, rootState, "__blueprints");
    SetGlobalCopy(mLuaState, rootState, "categories");

    (void)AddOrGetExportBinding(*this, rootState);
  }

  /**
   * Address: 0x0052A3D0 (FUN_0052A3D0)
   *
   * What it does:
   * Processes pending blueprint reload requests and syncs exported blueprint
   * globals for the target root Lua state.
   */
  void RRuleGameRulesImpl::UpdateLuaState(LuaPlus::LuaState* luaState)
  {
    if (!luaState) {
      return;
    }

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
    if (!mBlueprintByOrdinalBegin) {
      return 0;
    }

    return static_cast<int>(mBlueprintByOrdinalEnd - mBlueprintByOrdinalBegin);
  }

  /**
   * Address: 0x0052B1A0 (FUN_0052B1A0)
   *
   * What it does:
   * Returns blueprint pointer by ordinal index from the flat ordinal table.
   */
  RBlueprint* RRuleGameRulesImpl::GetBlueprintFromOrdinal(const int ordinal) const
  {
    if (ordinal < 0 || !mBlueprintByOrdinalBegin) {
      return nullptr;
    }

    const std::ptrdiff_t count = mBlueprintByOrdinalEnd - mBlueprintByOrdinalBegin;
    if (ordinal >= count) {
      return nullptr;
    }

    return mBlueprintByOrdinalBegin[ordinal];
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
    return mUnitBlueprints.mSize;
  }

  /**
   * Address: 0x0052B1E0 (FUN_0052B1E0)
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
   * Address: 0x0052B280 (FUN_0052B280)
   *
   * What it does:
   * Delegates category expression parsing to the shared resolver implementation.
   */
  CategoryWordRangeView RRuleGameRulesImpl::ParseEntityCategory(const char* categoryExpression) const
  {
    const auto* const resolver = reinterpret_cast<const EntityCategoryLookupResolver*>(this);
    return resolver->EntityCategoryLookupResolver::ParseEntityCategory(categoryExpression);
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

    std::uint32_t blueprintCount = 0u;
    if (mBlueprintByOrdinalBegin && mBlueprintByOrdinalEnd && mBlueprintByOrdinalEnd >= mBlueprintByOrdinalBegin) {
      blueprintCount = static_cast<std::uint32_t>(mBlueprintByOrdinalEnd - mBlueprintByOrdinalBegin);
    }
    context->Update(&blueprintCount, sizeof(blueprintCount));

    for (std::uint32_t ordinal = 0; ordinal < blueprintCount; ++ordinal) {
      RBlueprint* const blueprint = mBlueprintByOrdinalBegin[ordinal];
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
} // namespace moho
