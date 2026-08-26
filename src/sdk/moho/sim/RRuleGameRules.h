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

  // Forward declaration needed here (rather than only at its full definition
  // further below) because `EntityCategoryLookupTableRuntimeView`'s
  // constructor takes a `const RRuleGameRulesImpl*` parameter -- a pointer
  // to an incomplete type is a legal declaration.
  class RRuleGameRulesImpl;

  /**
   * `CategoryWordRangeView` given 8-byte alignment for exactly one purpose:
   * matching the binary's node layout for the category-lookup map's tree
   * embedded in `RRuleGameRulesImpl::mEntityCategoryLookup`
   * (`EntityCategoryLookupTableRuntimeView::mCategoryMap` below). Direct
   * evidence this node is 8-byte-aligned, not the usual 4-byte
   * `msvc8::detail::rb_node<V>` shape -- independently re-verified against
   * the raw IDA decompiles for every address cited below, not merely
   * re-stated from the sibling `Sim.cpp` recovery this type was promoted
   * from:
   *
   *   - `buy_node`'s emission for this instantiation (`FUN_005569C0`, cited
   *     on `RbTree.h`'s `buy_node` member) places the value at `node+0x10`,
   *     not the usual `node+0x0C`.
   *   - `erase_node`'s emission (`FUN_00536010`, cited on `RbTree.h`'s
   *     `erase_node` member) reads/writes colour at `[node+0x58]` (decimal
   *     88, `*((_BYTE*)v3+88)`) and `isNil` at `[node+0x59]` (decimal 89,
   *     `*(_BYTE*)(a2+89)`) throughout its transplant-and-rebalance body,
   *     confirmed directly against the raw decompile.
   *   - `destroy_subtree`'s emission (`FUN_005369D0`) tears each node down
   *     as `_Myval.helper.first` (the `msvc8::string` key, at the usual
   *     string-capacity-release shape) and `_Myval.helper.second.mSet.mUsed`
   *     (the `CategoryWordRangeView` value's inline-SBO bit-vector release) --
   *     IDA's own `helper` struct naming is this instantiation's
   *     `pair<const msvc8::string, CategoryWordRangeView>` value_type, with
   *     `.first`/`.second` exactly matching the key/value split.
   *
   * All of this reproduces automatically, with the existing
   * `rb_node<V>`/`rb_tree<Traits>` templates completely unmodified, once the
   * value type is given `alignas(8)` (verified by compiling the layout in
   * isolation with this project's MSVC toolchain -- see the commit that
   * first introduced this type in `Sim.cpp` for the compiler-verification
   * detail: `alignas` on a member overrides `RbTree.h`'s
   * `#pragma pack(push, 4)` for that member). `CategoryLookupValue` is that
   * `alignas(8)` wrapper.
   *
   * Promoted here from `Sim.cpp`'s anonymous namespace, where it was
   * previously a second, per-TU-only definition of this exact same binary
   * object (internal linkage, so it could never actually be the same type
   * as anything declared in this header). `RRuleGameRulesImpl::
   * mEntityCategoryLookup` is a `new`'d/`delete`d owning pointer whose real
   * owner is `RRuleGameRules.cpp`; `Sim.cpp` only reaches into the same live
   * object (via this pointer) to register blueprint category membership.
   * Giving both translation units one shared definition here, instead of
   * two independently maintained layout copies reached by
   * `reinterpret_cast`, is the CLAUDE.md duplicate-layout contract: "pick a
   * single owning reconstructed definition."
   */
  struct alignas(8) CategoryLookupValue : CategoryWordRangeView
  {
  };
  static_assert(sizeof(CategoryLookupValue) == 0x28, "CategoryLookupValue size must be 0x28");
  static_assert(alignof(CategoryLookupValue) == 8, "CategoryLookupValue alignment must be 8");

  /**
   * The category-name -> category-word-range map embedded in
   * `RRuleGameRulesImpl::mEntityCategoryLookup` (+0xC4, see
   * `EntityCategoryLookupResolver::GetEntityCategory`). Address evidence for
   * the tree operations this instantiation reaches is cited on
   * `msvc8::detail::rb_tree`'s `insert_unique`/`insert_at`/`buy_node`/
   * `rb_decrement`/`find_node` members (insert/lookup side, reached from
   * `Sim.cpp`'s `AddCategoryMemberBit`) and its `buy_head`/`rb_min`/
   * `rb_max`/`rb_increment`/`rotate_left`/`rotate_right`/`erase_node`/
   * `destroy_subtree`/`erase_range`/`~rb_tree`/`clear` members
   * (construction/destruction side, reached from `RRuleGameRules.cpp`'s
   * `EntityCategoryLookupTableRuntimeView` constructor and implicit
   * destructor) in `RbTree.h`.
   *
   * `EntityCategoryLookupResolver.cpp` independently models the read-only
   * half of this exact tree as a lighter `CategoryNameMapView`/`Tree.h` view
   * (no owning insert/erase, since that file only ever looks values up);
   * all three recoveries agree on the node layout (key@+0x10, value@+0x30,
   * colour@+0x58, isNil@+0x59) -- corroborating evidence from three
   * independently recovered call sites for the same binary object.
   */
  using CategoryLookupMap = msvc8::map<msvc8::string, CategoryLookupValue>;
  static_assert(sizeof(CategoryLookupMap) == 0x0C, "CategoryLookupMap size must be 0x0C");

  /**
   * Real binary object constructed at `RRuleGameRulesImpl::mEntityCategoryLookup`
   * (+0xC4). Ctor lives in RRuleGameRules.cpp; the layout is complete here
   * (rather than forward-declared) so `Sim.cpp`'s
   * `RegisterBlueprintCategoryMembership`/`AddCategoryMemberBit` can operate
   * on the same real object through this typed pointer instead of a second,
   * `reinterpret_cast`-punned struct duplicating this layout (the previous
   * shape of that duplication -- `Sim.cpp`'s now-removed
   * `EntityCategoryLookupTableView` -- is why this type carries a `Runtime`
   * in its name here but that one didn't; both named the identical binary
   * object).
   */
  struct EntityCategoryLookupTableRuntimeView
  {
    CategoryLookupMap mCategoryMap; // +0x00 (0x0C: {proxy, head, size})
    /// Never read or written by any call site traced across either recovery
    /// pass that has touched this type (the map header itself is only ever
    /// touched at +0x00/+0x04/+0x08). Kept as an explicit gap rather than
    /// folded into an assumed alignment: unlike the tree node's alignment
    /// gap above, nothing pins this one to an alignment requirement of
    /// `CategoryWordRangeView` itself (that type is 4-byte aligned
    /// everywhere else it is used as a plain value).
    std::uint32_t mCategoryMapReserved0C;    // +0x0C
    CategoryWordRangeView mCategoryFallback; // +0x10
    std::uint32_t mWordUniverseHandle;       // +0x38
    std::uint8_t pad_003C_003F[0x04];        // +0x3C (binary leaves this unwritten; not initialized here either)

    /**
     * Address: 0x005551F0 (FUN_005551F0, Moho::EntityCategorySet::EntityCategorySet)
     *
     * IDA signature:
     * Moho::EntityCategorySet *__userpurge Moho::EntityCategorySet::EntityCategorySet@<eax>(
     *   Moho::RRuleGameRulesImpl *rules@<edi>, Moho::EntityCategorySet *this);
     *
     * What it does:
     * In-place constructs the (empty, sentinel-headed) category-name map and
     * the fallback `CategoryWordRangeView`, seeding both the fallback's
     * universe lane and the trailing `mWordUniverseHandle` with `owner`
     * reinterpreted as a 4-byte handle - the same raw pointer value the
     * binary writes to +0x10 and +0x38 (IDA types both writes as the plain
     * `RRuleGameRulesImpl*` pointer rather than a bit-cast integer, but the
     * two are bit-identical on this 32-bit ABI, so the pre-existing
     * `uint32_t` field typing is kept here - only the field names changed
     * in this pass, not their type or behavior).
     *
     * `mCategoryMap`'s sentinel head is default-constructed implicitly
     * (member init, before this body runs) - the binary's own
     * `buy_head()`-equivalent allocate-then-self-link sequence, cited on
     * `RbTree.h`'s `buy_head` member (`FUN_00556DE0`). The redundant
     * `mCategoryMap.clear()` call below preserves an otherwise-inert second
     * destroy-and-reset pass the binary performs on the (already empty)
     * fresh tree - cited on `RbTree.h`'s `clear()` member - kept verbatim
     * for exact instruction-sequence fidelity with FUN_005551F0 at
     * 0x0055525A-0x00555276 rather than silently dropped as dead code.
     *
     * EH note: `FUN_005551F0`'s unwind funclet at 0x00BA0453 runs only if
     * construction throws after the category map is live but before the
     * word-range fallback is - it re-derives the same
     * `erase(first,last)`-then-`operator delete`-the-head tail this type's
     * (now implicit) destructor performs, cited on `RbTree.h`'s
     * `erase_range`/`~rb_tree` members. Per RULE ONE an unwind funclet
     * target maps to no source line of its own, so it is cited here rather
     * than written as a separate function.
     */
    explicit EntityCategoryLookupTableRuntimeView(const RRuleGameRulesImpl* owner) noexcept;

    /**
     * No explicit destructor: `mCategoryMap` (`msvc8::map<msvc8::string,
     * CategoryLookupValue>`) and `mCategoryFallback` (`CategoryWordRangeView`)
     * are both real typed members now, so implicit member destruction runs
     * their own real destructors automatically - exactly matching
     * `FUN_00533E20`'s (`Moho::EntityCategory::~EntityCategory`) two real
     * pieces of work: `mCategoryMap`'s teardown is `RbTree.h`'s `~rb_tree()`
     * emission for this instantiation (cited there), and the leading
     * `mSet.mUsed` inline-vector release the raw decompile shows ahead of it
     * is `CategoryWordRangeView::~CategoryWordRangeView()`'s own body,
     * inlined into this destructor by the compiler - not hand-written
     * source of this class at all (RULE ONE: "member destructors... the
     * source body says nothing; MSVC emits it"). A prior recovery pass
     * wrote this class's destructor by hand as an explicit function
     * precisely reproducing `~rb_tree()`'s shape; removing it in favor of
     * the implicit one does not change behavior, it removes a
     * hand-transcription of compiler-emitted glue.
     */
    EntityCategoryLookupTableRuntimeView(const EntityCategoryLookupTableRuntimeView&) = delete;
    EntityCategoryLookupTableRuntimeView& operator=(const EntityCategoryLookupTableRuntimeView&) = delete;
  };
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, mCategoryMap) == 0x00,
    "EntityCategoryLookupTableRuntimeView::mCategoryMap offset"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, mCategoryFallback) == 0x10,
    "EntityCategoryLookupTableRuntimeView::mCategoryFallback offset"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableRuntimeView, mWordUniverseHandle) == 0x38,
    "EntityCategoryLookupTableRuntimeView::mWordUniverseHandle offset"
  );
  static_assert(
    sizeof(EntityCategoryLookupTableRuntimeView) == 0x40,
    "EntityCategoryLookupTableRuntimeView size must be 0x40"
  );

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
   *     ([`mMaps.begin()`, `mMaps.end()`)) and calls `func_MapInsert` /
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
   *
   * No explicit destructor or copy-assignment operator declared -- both are
   * compiler-emitted (RULE ONE: "member destructors... the source body says
   * nothing; MSVC emits it") and both are confirmed real, distinct binary
   * emissions rather than assumptions:
   *   - Implicit destructor = `FUN_0052A390` (`_callgraph_index.sqlite`
   *     confirms its only two real callers are `FUN_00529F70`
   *     (`ExportToLuaState`) and `FUN_0052DBE0` (`msvc8::vector<
   *     RRuleGameRulesLuaExportBinding>::insert`) -- both are the EH-unwind
   *     cleanup for a local `RRuleGameRulesLuaExportBinding` temporary
   *     (`ExportToLuaState`'s freshly-built binding value, `insert`'s own
   *     `const T localValue(value)`) being torn down on a mid-construction
   *     throw. `msvc8::detail::rb_tree<uint32_t>::~rb_tree()` (RbTree.h)
   *     supplies `mPendingBlueprintOrdinals`'s half; `mRootState` is
   *     trivially destructible.
   *   - Implicit copy-assignment operator = `FUN_00536DA0` and
   *     `FUN_00537420` -- two non-ICF-folded emissions of the identical
   *     compiled body (different register allocation from being inlined at
   *     two different call sites: `msvc8::vector<...>::erase(iterator)`'s
   *     tail-shift loop and `insert(pos,count,value)`'s in-place tail-shift
   *     branch, respectively), both cited in full on `legacy/containers/
   *     Vector.h`'s `erase(iterator)` and `insert(pos,count,value)`
   *     members. Per slot: raw-copies `mRootState`, then runs
   *     `mPendingBlueprintOrdinals`'s own `rb_tree::operator=` (erase the
   *     destination's live tree via `erase_range`, deep-clone the source
   *     tree via `copy_from`), guarded by the compiler-inserted `this !=
   *     &other` self-assignment check.
   * Both are reached automatically once real code invokes
   * `msvc8::vector<RRuleGameRulesLuaExportBinding>`'s own erase/insert/
   * destructor -- no bespoke per-element free function is needed or
   * written for either.
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

  // `RRuleGameRulesLuaExportBindingArray` used to duplicate `msvc8::vector<T>`'s
  // own private layout here ({proxy, begin, end, capacityEnd}, byte-for-byte
  // identical to Vector.h's `myProxy_@0/first_@4/last_@8/end_@0xC`) as a
  // hand-rolled struct with hand-rolled pointer-triplet accessors in
  // RRuleGameRules.cpp -- exactly the CLAUDE.md "Duplicate layout contract"
  // violation ("Do not keep duplicated class/struct layouts that model the
  // same binary object in multiple headers"). `RRuleGameRulesImpl::mMaps`
  // below is now a real `msvc8::vector<RRuleGameRulesLuaExportBinding>`; see
  // that field's own doc comment for the growth/allocation divergence this
  // migration fixed (the hand-rolled model over-constructed its spare
  // capacity and paired it with `delete[]`, which the real binary's
  // `operator delete`-based teardown -- confirmed independently from
  // `FUN_0052D590`'s and `FUN_00536DF0`'s raw disassembly -- never did).

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
     * Vector of per-target-LuaState export bindings. Real field name per
     * IDA's own decompilation of `ExportToLuaState` (`this->mMaps`,
     * 0x00529F70) and `func_Add__blueprints`'s `rules->mMaps` walk
     * (0x00529B30) -- see `RRuleGameRulesLuaExportBinding` above for the
     * per-element layout evidence. Previously modeled under the name
     * `mLuaExports`; renamed here to match the binary-recovered name.
     *
     * Real `msvc8::vector<RRuleGameRulesLuaExportBinding>`, not a
     * hand-rolled pointer-triplet struct (see the removed
     * `RRuleGameRulesLuaExportBindingArray` note above). Migrating this
     * field surfaced a genuine behavioral divergence in the growth path
     * that was hand-rolled around it (`ReserveExportBindingCapacity`,
     * RRuleGameRules.cpp, now fixed to call `reserve()`):
     *   - The old code allocated with `new RRuleGameRulesLuaExportBinding[
     *     requestedCapacity]{}`, which default-*constructs* every slot up
     *     to the full new capacity (not just the live prefix), then
     *     *assigned* (`newBegin[i] = oldBegin[i]`) the live elements into
     *     those already-live slots, and freed the old buffer with
     *     `delete[]`.
     *   - The real binary never does this. `FUN_0052D590`'s raw
     *     disassembly (`if (*(a1+4)) operator delete(*(a1+4)); *(a1+4) =
     *     *(a1+8) = *(a1+12) = 0;`) and `FUN_00536DF0`'s recorded evidence
     *     ("FUN_00529700 dtor direct mMaps teardown ... call
     *     FUN_00536DF0(mBegin,mEnd), delete mBegin" -- singular, scalar
     *     `operator delete`, never `delete[]`) both confirm the real
     *     vector allocates raw, unconstructed memory via `operator new`
     *     and only *constructs* (copy, since MSVC8/VS2005 predates move
     *     semantics) exactly the live element count into it -- exactly
     *     `legacy/containers/Vector.h`'s already-existing `reallocate_to`/
     *     `reserve()` shape. `[size(), capacity())` is genuinely raw
     *     memory in the real object, never a run of live default-
     *     constructed elements. The hand-rolled growth policy
     *     (`capacity>0 ? capacity*2 : 4`, in the removed
     *     `AddOrGetExportBinding`) was also wrong on its own terms --
     *     `msvc8::vector<T>::recommended_capacity()` grows 1.5x
     *     (`cur + cur/2`), not 2x. Both divergences are fixed by routing
     *     growth through the real `reserve()`/`insert()` API instead of
     *     hand-rolling it.
     */
    msvc8::vector<RRuleGameRulesLuaExportBinding> mMaps; // +0x44
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
    sizeof(msvc8::vector<RRuleGameRulesLuaExportBinding>) == 0x10,
    "msvc8::vector<RRuleGameRulesLuaExportBinding> size must be 0x10"
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
