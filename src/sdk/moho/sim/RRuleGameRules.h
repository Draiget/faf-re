#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"

namespace LuaPlus
{
  class LuaState;
  class LuaObject;
}

namespace gpg
{
  class RType;
}

namespace moho
{
  struct CBackgroundTaskControl;

  struct RResId;

  struct RBlueprint;
  struct REntityBlueprint;
  struct RUnitBlueprint;
  struct RPropBlueprint;
  struct RMeshBlueprint;
  struct RProjectileBlueprint;
  struct REmitterBlueprint;
  struct RBeamBlueprint;
  struct RTrailBlueprint;
  struct REffectBlueprint;

  /**
   * Real binary object constructed at `RRuleGameRulesImpl::mEntityCategoryLookup`.
   * Full layout + ctor/dtor live in RRuleGameRules.cpp (internal to this TU);
   * only a pointer to it escapes into the class layout below.
   */
  struct EntityCategoryLookupTableRuntimeView;

  struct RRuleGameRulesBlueprintNode : msvc8::Tree<RRuleGameRulesBlueprintNode>
  {
    msvc8::string mBlueprintId; // +0x0C
    void* mBlueprint;           // +0x28
    std::uint8_t mColor;        // +0x2C
    std::uint8_t mIsSentinel;   // +0x2D
    std::uint8_t pad_2E[2];
  };

  static_assert(sizeof(RRuleGameRulesBlueprintNode) == 0x30, "RRuleGameRulesBlueprintNode size must be 0x30");
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mBlueprintId) == 0x0C,
    "RRuleGameRulesBlueprintNode::mBlueprintId offset must be 0x0C"
  );
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mBlueprint) == 0x28,
    "RRuleGameRulesBlueprintNode::mBlueprint offset must be 0x28"
  );
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mIsSentinel) == 0x2D,
    "RRuleGameRulesBlueprintNode::mIsSentinel offset must be 0x2D"
  );

  /**
   * Each blueprint table is `std::map<std::string, TBlueprint*>`. The mapped
   * lane is stored untyped and cast at each use -- one node shape serves all
   * seven tables -- so a `void*` mapped type is the faithful model.
   *
   * Node arithmetic closes: links 0x0C plus a
   * `pair<const msvc8::string, void*>` of 0x20 puts colour/nil at
   * +0x2C/+0x2D and the node at 0x30. The key order is the default
   * `std::less` -- the binary compares through `CompareLex`, which is
   * `char_traits::compare` over the common prefix then length, and
   * `msvc8::string::operator<` is `compare(rhs.view()) < 0`.
   */
  using RRuleGameRulesBlueprintMap = msvc8::map<msvc8::string, void*>;

  static_assert(sizeof(RRuleGameRulesBlueprintMap) == 0x0C, "RRuleGameRulesBlueprintMap size must be 0x0C");

  /**
   * One per-target-LuaState export binding tracked by `RRuleGameRulesImpl::
   * mMaps` (real IDA-recovered field name -- see `ExportToLuaState`,
   * 0x00529F70, which reads/writes `this->mMaps` directly).
   *
   * Layout is confirmed independently from three call sites:
   *   - `ExportToLuaState` (0x0052A28A-0x0052A2AF) constructs a fresh
   *     binding: `mRootState` = the target root state, then `sub_52F370`
   *     buys a red-black-tree header node and self-links its three
   *     pointers with `_Isnil=1` at `[node+0x11]` -- byte-for-byte
   *     `msvc8::detail::rb_tree<...>::buy_head()` (RbTree.h).
   *   - `func_Add__blueprints` (0x00529B30) walks every existing binding
   *     ([`mMaps.mBegin`, `mMaps.mEnd`)) and calls `func_MapInsert` /
   *     `FUN_0052BC60` on `binding + 4` for each newly registered
   *     blueprint's ordinal -- `FUN_0052BC60` is
   *     `msvc8::detail::rb_tree<uint32_t...>::insert_unique` byte-for-byte
   *     (lower-bound descent, `where == leftmost()` fast path, else
   *     `rb_decrement` probe -- see the citation on `insert_unique` in
   *     RbTree.h). `FUN_0052DB50`'s node-buy stores only 4 bytes at
   *     `node+0x0C` (the ordinal itself, no paired pointer), so the
   *     embedded container is `msvc8::set<uint32_t>`, not
   *     `msvc8::map<uint32_t, RBlueprint*>`.
   *   - `FUN_0052A390` destroys one binding's set by erasing the full
   *     range and deleting the header node -- exactly `msvc8::set<uint32_t>
   *     >`'s own destructor (`rb_tree::~rb_tree`).
   *
   * The embedded node is 0x14 bytes with `_Isnil` at +0x11
   * (0x0D + sizeof(uint32_t)), the same shape already precedented by
   * `Moho::SPeer::establishedUids` (`msvc8::set<int32_t>`, RbTree.h
   * `buy_head` citation block).
   *
   * A previous pass modeled this same memory as an intrusive doubly-linked
   * "Lua task list" (`mReserved04` / `mTaskListSentinel` / `mTaskListSize`,
   * with a `LuaTaskListNode` of the same 0x14-byte shape). That model
   * happened to match the byte layout -- a self-linked 3-pointer header
   * looks identical whether it anchors a list or an empty tree -- but had
   * no per-function address citation of its own and directly contradicted
   * the genuine `_Insert` / `_Lrotate` / `_Rrotate` / `_Buynode` bodies at
   * 0x0052CD30 / 0x0052DAB0 / 0x0052DB00 / 0x0052DB50 that this binding's
   * set is actually built from. Corrected here; see RRuleGameRules.cpp for
   * the replacement wiring.
   */
  struct RRuleGameRulesLuaExportBinding
  {
    LuaPlus::LuaState* mRootState;                       // +0x00
    msvc8::set<std::uint32_t> mPendingBlueprintOrdinals; // +0x04 (proxy_@+04, head_@+08, size_@+0C)
  };

  static_assert(sizeof(RRuleGameRulesLuaExportBinding) == 0x10, "RRuleGameRulesLuaExportBinding size must be 0x10");
  static_assert(
    offsetof(RRuleGameRulesLuaExportBinding, mPendingBlueprintOrdinals) == 0x04,
    "RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals offset must be 0x04"
  );

  struct RRuleGameRulesLuaExportBindingArray
  {
    void* mProxy;                                 // +0x00
    RRuleGameRulesLuaExportBinding* mBegin;       // +0x04
    RRuleGameRulesLuaExportBinding* mEnd;         // +0x08
    RRuleGameRulesLuaExportBinding* mCapacityEnd; // +0x0C
  };

  static_assert(
    sizeof(RRuleGameRulesLuaExportBindingArray) == 0x10, "RRuleGameRulesLuaExportBindingArray size must be 0x10"
  );
  static_assert(
    offsetof(RRuleGameRulesLuaExportBindingArray, mBegin) == 0x04,
    "RRuleGameRulesLuaExportBindingArray::mBegin offset must be 0x04"
  );

  /**
   * VFTABLE: 0x00E1610C
   * COL:  0x00E6A514
   */
  class RRuleGameRules
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sType2;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00528080 (FUN_00528080)
     * Slot: 0
     */
    virtual ~RRuleGameRules() = default;

    /**
     * Address: 0x00528460 (FUN_00528460, Moho::RRuleGameRules::operator new)
     *
     * What it does:
     * Allocates one `RRuleGameRulesImpl` object and runs the concrete
     * constructor with active-mod payload plus the background-task control that
     * blueprint loading reports progress to (null when nothing is watching).
     */
    [[nodiscard]] static RRuleGameRules* Create(const msvc8::string& activeMods, CBackgroundTaskControl* initHandler);

    /**
     * Address: 0x00529F70 (FUN_00529F70)
     * Slot: 1
     */
    virtual void ExportToLuaState(LuaPlus::LuaState*) = 0;

    /**
     * Address: 0x0052A3D0 (FUN_0052A3D0)
     * Slot: 2
     */
    virtual void UpdateLuaState(LuaPlus::LuaState*) = 0;

    /**
     * Address: 0x0052AA20 (FUN_0052AA20)
     * Slot: 3
     */
    virtual void CancelExport(LuaPlus::LuaState*) = 0;

    /**
     * Address: 0x005282C0 (FUN_005282C0)
     * Slot: 4
     */
    virtual int AssignNextOrdinal() = 0;

    /**
     * Address: 0x0052B1A0 (FUN_0052B1A0)
     * Slot: 5
     */
    virtual RBlueprint* GetBlueprintFromOrdinal(int ordinal) const = 0;

    /**
     * Address: 0x005282E0 (FUN_005282E0)
     * Slot: 6
     */
    virtual const SRuleFootprintsBlueprint* GetFootprints() const = 0;

    /**
     * Address: 0x0052AAE0 (FUN_0052AAE0)
     * Slot: 7
     */
    virtual const SNamedFootprint* FindFootprint(const SFootprint& footprint, const char* name) const = 0;

    /**
     * Address: 0x005282F0 (FUN_005282F0)
     * Slot: 8
     */
    virtual const RRuleGameRulesBlueprintMap& GetUnitBlueprints() = 0;

    /**
     * Address: 0x00528300 (FUN_00528300)
     * Slot: 9
     */
    virtual const RRuleGameRulesBlueprintMap& GetPropBlueprints() = 0;

    /**
     * Address: 0x00528320 (FUN_00528320)
     * Slot: 10
     */
    virtual const RRuleGameRulesBlueprintMap& GetProjectileBlueprints() = 0;

    /**
     * Address: 0x00528310 (FUN_00528310)
     * Slot: 11
     */
    virtual const RRuleGameRulesBlueprintMap& GetMeshBlueprints() = 0;

    /**
     * Address: 0x0052AEB0 (FUN_0052AEB0)
     * Slot: 12
     */
    virtual REntityBlueprint* GetEntityBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052AB70 (FUN_0052AB70)
     * Slot: 13
     */
    virtual RUnitBlueprint* GetUnitBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052AD10 (FUN_0052AD10)
     * Slot: 14
     */
    virtual RPropBlueprint* GetPropBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052ADE0 (FUN_0052ADE0)
     * Slot: 15
     */
    virtual RMeshBlueprint* GetMeshBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052AC40 (FUN_0052AC40)
     * Slot: 16
     */
    virtual RProjectileBlueprint* GetProjectileBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052AEF0 (FUN_0052AEF0)
     * Slot: 17
     */
    virtual REmitterBlueprint* GetEmitterBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052AFC0 (FUN_0052AFC0)
     * Slot: 18
     */
    virtual RBeamBlueprint* GetBeamBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052B090 (FUN_0052B090)
     * Slot: 19
     */
    virtual RTrailBlueprint* GetTrailBlueprint(const RResId&) = 0;

    /**
     * Address: 0x0052B160 (FUN_0052B160)
     * Slot: 20
     */
    virtual REffectBlueprint* GetEffectBlueprint(const RResId&) = 0;

    /**
     * Address: 0x00528330 (FUN_00528330)
     * Slot: 21
     */
    virtual unsigned int GetUnitCount() const = 0;

    /**
     * Address: 0x0052B1E0 (FUN_0052B1E0)
     * Slot: 22
     */
    virtual const CategoryWordRangeView* GetEntityCategory(const char*) const = 0;

    /**
     * Address: 0x0052B280 (FUN_0052B280)
     * Slot: 23
     */
    virtual CategoryWordRangeView ParseEntityCategory(const char*) const = 0;

    /**
     * Address: 0x0052B2B0 (FUN_0052B2B0)
     * Slot: 24
     */
    virtual void UpdateChecksum(void* md5Context, void* fileHandle) = 0;

    /**
     * Address: 0x0051CF90 callsite family (func_GetPropBlueprint)
     *
     * What it does:
     * Adapter overload for callsites that still pass a normalized string id.
     */
    RPropBlueprint* GetPropBlueprint(const msvc8::string& blueprintId);
  };

  /**
   * VFTABLE: 0x00E16174
   * COL:  0x00E6A444
   *
   * Recovered concrete runtime rules object used by session/sim pointers.
   */
  class RRuleGameRulesImpl : public RRuleGameRules
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00529120 (FUN_00529120, Moho::RRuleGameRulesImpl::RRuleGameRulesImpl)
     *
     * What it does:
     * Initializes rule Lua/runtime storage, runs core Lua init forms, loads
     * `/lua/RuleInit.lua`, and rebuilds category caches.
     */
    RRuleGameRulesImpl(const msvc8::string& activeMods, CBackgroundTaskControl* initHandler);

    /**
     * Address: 0x00529700 (FUN_00529700)
     *
     * What it does:
     * Releases runtime blueprint/category/Lua storage owned by this concrete
     * rule object and decrements the rule instance counter.
     */
    ~RRuleGameRulesImpl() override;

    /**
     * Address: 0x00529F70 (FUN_00529F70)
     */
    void ExportToLuaState(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x0052A3D0 (FUN_0052A3D0)
     */
    void UpdateLuaState(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x0052AA20 (FUN_0052AA20)
     */
    void CancelExport(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x005282C0 (FUN_005282C0)
     */
    int AssignNextOrdinal() override;

    /**
     * Address: 0x0052B1A0 (FUN_0052B1A0)
     */
    RBlueprint* GetBlueprintFromOrdinal(int ordinal) const override;

    /**
     * Address: 0x005282E0 (FUN_005282E0)
     */
    const SRuleFootprintsBlueprint* GetFootprints() const override;

    /**
     * Address: 0x0052AAE0 (FUN_0052AAE0)
     */
    const SNamedFootprint* FindFootprint(const SFootprint& footprint, const char* name) const override;

    /**
     * Address: 0x005282F0 (FUN_005282F0)
     */
    const RRuleGameRulesBlueprintMap& GetUnitBlueprints() override;

    /**
     * Address: 0x00528300 (FUN_00528300)
     */
    const RRuleGameRulesBlueprintMap& GetPropBlueprints() override;

    /**
     * Address: 0x00528320 (FUN_00528320)
     */
    const RRuleGameRulesBlueprintMap& GetProjectileBlueprints() override;

    /**
     * Address: 0x00528310 (FUN_00528310)
     */
    const RRuleGameRulesBlueprintMap& GetMeshBlueprints() override;

    /**
     * Address: 0x0052AEB0 (FUN_0052AEB0)
     */
    REntityBlueprint* GetEntityBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AB70 (FUN_0052AB70)
     */
    RUnitBlueprint* GetUnitBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AD10 (FUN_0052AD10)
     */
    RPropBlueprint* GetPropBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052ADE0 (FUN_0052ADE0)
     */
    RMeshBlueprint* GetMeshBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AC40 (FUN_0052AC40)
     */
    RProjectileBlueprint* GetProjectileBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AEF0 (FUN_0052AEF0)
     */
    REmitterBlueprint* GetEmitterBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AFC0 (FUN_0052AFC0)
     */
    RBeamBlueprint* GetBeamBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052B090 (FUN_0052B090)
     */
    RTrailBlueprint* GetTrailBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052B160 (FUN_0052B160)
     */
    REffectBlueprint* GetEffectBlueprint(const RResId& resId) override;

    /**
     * Address: 0x00528330 (FUN_00528330)
     */
    unsigned int GetUnitCount() const override;

    /**
     * Address: 0x0052B1E0 (FUN_0052B1E0)
     */
    const CategoryWordRangeView* GetEntityCategory(const char* categoryName) const override;

    /**
     * Address: 0x0052B280 (FUN_0052B280)
     */
    CategoryWordRangeView ParseEntityCategory(const char* categoryExpression) const override;

    /**
     * Address: 0x0052B2B0 (FUN_0052B2B0)
     */
    void UpdateChecksum(void* md5Context, void* fileHandle) override;

    /**
     * Address: 0x00529C30 (FUN_00529C30, Moho::RRuleGameRulesImpl::SetupCategories)
     *
     * What it does:
     * Rebuilds global Lua `categories` userdata table from runtime category
     * lookup storage and refreshes per-unit economy restriction caches.
     */
    void SetupCategories();

  public:
    std::uint8_t pad_0004[0x34];                      // +0x04
    std::uint8_t mLockStorage[0x08];                  // +0x38
    LuaPlus::LuaState* mLuaState;                     // +0x40
    /**
     * Array of per-target-LuaState export bindings. Real field name per
     * IDA's own decompilation of `ExportToLuaState` (`this->mMaps`,
     * 0x00529F70) and `func_Add__blueprints`'s `rules->mMaps` walk
     * (0x00529B30) -- see `RRuleGameRulesLuaExportBinding` above for the
     * per-element layout evidence. Previously modeled under the name
     * `mLuaExports`; renamed here to match the binary-recovered name.
     */
    RRuleGameRulesLuaExportBindingArray mMaps;        // +0x44
    SRuleFootprintsBlueprint mFootprints;             // +0x54
    RRuleGameRulesBlueprintMap mUnitBlueprints;       // +0x60
    RRuleGameRulesBlueprintMap mProjectileBlueprints; // +0x6C
    RRuleGameRulesBlueprintMap mPropBlueprints;       // +0x78
    RRuleGameRulesBlueprintMap mMeshBlueprints;       // +0x84
    RRuleGameRulesBlueprintMap mEmitterBlueprints;    // +0x90
    RRuleGameRulesBlueprintMap mBeamBlueprints;       // +0x9C
    RRuleGameRulesBlueprintMap mTrailBlueprints;      // +0xA8
    /**
     * Blueprint registry indexed by ordinal (the order `RegisterUnitBlueprint`
     * and friends first saw each blueprint). The binary hands `rules + 0xB4`
     * straight to `msvc8::vector<RBlueprint*>::push_back` — see the
     * `add ecx, 0B4h` at 0x00531FE9 in `func_CreateRUnitBlueprint` — so the
     * `{proxy, first, last, end}` quad at +0xB4..+0xC0 is one whole legacy
     * vector object, not four independent lanes.
     */
    msvc8::vector<RBlueprint*> mBlueprintsByOrdinal;  // +0xB4
    /**
     * Real ground-truth object is `Moho::EntityCategorySet`/`EntityCategory`
     * (the mangled ctor/dtor names differ - see the address block on
     * `EntityCategoryLookupTableRuntimeView` in RRuleGameRules.cpp for why).
     * Field keeps its established source-level name: `EntityCategorySet` and
     * `EntityCategory` are both already taken in this codebase by unrelated
     * types, and this exact field name is referenced by name from
     * RUnitBlueprint.cpp and Sim.cpp (owned by other concurrent recovery
     * passes), so only the type changes here - `void*` to the real pointee -
     * not the identifier.
     */
    EntityCategoryLookupTableRuntimeView* mEntityCategoryLookup; // +0xC4
    void* mPendingBlueprintReloadNext;                // +0xC8
    void* mPendingBlueprintReloadPrev;                // +0xCC
  };

  static_assert(offsetof(RRuleGameRulesImpl, mLuaState) == 0x40, "RRuleGameRulesImpl::mLuaState offset must be 0x40");
  static_assert(
    offsetof(RRuleGameRulesImpl, mMaps) == 0x44, "RRuleGameRulesImpl::mMaps offset must be 0x44"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mFootprints) == 0x54, "RRuleGameRulesImpl::mFootprints offset must be 0x54"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mUnitBlueprints) == 0x60, "RRuleGameRulesImpl::mUnitBlueprints offset must be 0x60"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mProjectileBlueprints) == 0x6C,
    "RRuleGameRulesImpl::mProjectileBlueprints offset must be 0x6C"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mPropBlueprints) == 0x78, "RRuleGameRulesImpl::mPropBlueprints offset must be 0x78"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mMeshBlueprints) == 0x84, "RRuleGameRulesImpl::mMeshBlueprints offset must be 0x84"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mEmitterBlueprints) == 0x90,
    "RRuleGameRulesImpl::mEmitterBlueprints offset must be 0x90"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mBeamBlueprints) == 0x9C, "RRuleGameRulesImpl::mBeamBlueprints offset must be 0x9C"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mTrailBlueprints) == 0xA8, "RRuleGameRulesImpl::mTrailBlueprints offset must be 0xA8"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mBlueprintsByOrdinal) == 0xB4,
    "RRuleGameRulesImpl::mBlueprintsByOrdinal offset must be 0xB4"
  );
  static_assert(
    sizeof(msvc8::vector<RBlueprint*>) == 0x10, "msvc8::vector<RBlueprint*> size must be 0x10"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mEntityCategoryLookup) == 0xC4,
    "RRuleGameRulesImpl::mEntityCategoryLookup offset must be 0xC4"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mPendingBlueprintReloadNext) == 0xC8,
    "RRuleGameRulesImpl::mPendingBlueprintReloadNext offset must be 0xC8"
  );
  static_assert(sizeof(RRuleGameRulesImpl) == 0xD0, "RRuleGameRulesImpl size must be 0xD0");

  /**
   * Address: 0x0052B960 (FUN_0052B960, ?RULE_GetDefaultPlayerOptions@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   *
   * What it does:
   * Imports `/lua/ui/lobby/lobbyComm.lua` and returns `GetDefaultPlayerOptions()` result.
   */
  [[nodiscard]] LuaPlus::LuaObject RULE_GetDefaultPlayerOptions(LuaPlus::LuaState* state);
} // namespace moho
