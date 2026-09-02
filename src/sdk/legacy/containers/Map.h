#pragma once
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

#include "legacy/containers/RbTree.h"

#pragma pack(push, 4)

namespace msvc8
{
    /**
     * \brief Owning MSVC8-layout `std::map`.
     *
     * All red-black mechanics live in `detail::rb_tree` (RbTree.h), which this
     * container shares with `msvc8::set`; the only difference between the two is
     * the traits' key extractor - `set` extracts the value itself, `map` extracts
     * `value_type::first`.
     *
     * Layout is the shipped 12-byte `{proxy, _Myhead, _Mysize}` triplet with the
     * comparator empty-base-optimised away. That footprint is confirmed by
     * `Moho::CCommandDB`, whose command map occupies +0x04..+0x0F with the id
     * pool starting at +0x10 (`CommandDbMapRuntime` in CCommandDb.cpp).
     *
     * Iterator stepping is documented (and address-annotated) on
     * `detail::rb_increment` / `detail::rb_decrement`.
     *
     * Note: this container used to be a non-owning inspection facade with an
     * `adopt(header, size)` factory. Adopting foreign tree memory is unsound now
     * that the container frees what it holds, so `adopt` and the raw-header
     * constructor are gone; nothing in `src/sdk/**` referenced them.
     */
    template<class Key, class T, class Less = std::less<Key>>
    class map
    {
        using traits = detail::rb_map_traits<Key, T, Less>;
        using tree_type = detail::rb_tree<traits>;
        using node_type = typename tree_type::node_type;

    public:
        using key_type = Key;
        using mapped_type = T;
        using value_type = std::pair<const Key, T>;
        using key_compare = Less;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = value_type&;
        using const_reference = const value_type&;

        using iterator = detail::rb_iterator<traits, false>;
        using const_iterator = detail::rb_iterator<traits, true>;

        // ---- ctor / dtor ------------------------------------------------------

        map() noexcept {}
        explicit map(const key_compare& comp) : tree_(comp) {}

        /**
         * MSVC8 `_Tree::_Tree(const _Myt&)`: a fresh empty tree plus a `_Copy`
         * walk of the source, shared with `msvc8::set` through `rb_tree`.
         */
        map(const map& o) : tree_(o.tree_) {}
        map& operator=(const map& o)
        {
            tree_ = o.tree_;
            return *this;
        }
        map(map&& o) noexcept : tree_(std::move(o.tree_)) {}
        map& operator=(map&& o) noexcept
        {
            tree_ = std::move(o.tree_);
            return *this;
        }

        // ---- observers --------------------------------------------------------

        [[nodiscard]] key_compare key_comp() const { return tree_.key_comp(); }

        [[nodiscard]] size_type size() const noexcept { return tree_.size(); }
        /**
         * Address: 0x006E15A0 (FUN_006E15A0, `msvc8::map<Moho::CmdId,
         * Moho::CUnitCommand*>::empty` -- `Moho::CCommandDb::commands` in
         * `CCommandDb.h`. `return map->size == 0u;`, matching `tree_.empty()`
         * exactly. Re-homed here from a bespoke free function in
         * `CCommandDb.cpp` (`IsCommandMapEmptyBySize`) during the
         * `CommandDbMapNodeRuntime` hand-rolled-tree migration; no direct
         * caller confirmed in this pass (`incoming_xrefs` empty in this
         * sweep) beyond this member's own generic API surface, which
         * `ValidateCommandMapEmptyOrDie` (`CCommandDb.cpp`) now calls as
         * `commands.empty()`.)
         */
        [[nodiscard]] bool empty() const noexcept { return tree_.empty(); }

        /** Header sentinel pointer (for low-level diagnostics). */
        [[nodiscard]] const void* header_ptr() const noexcept { return tree_.header(); }

        /** Checks the header self-link invariants (non-exhaustive). */
        [[nodiscard]] bool basic_sanity() const noexcept
        {
            const node_type* const head = tree_.header();
            if (head == nullptr || head->isNil == 0) {
                return false;
            }
            const bool emptyTree = head->parent == head && head->left == head && head->right == head;
            return emptyTree ? tree_.size() == 0 : tree_.size() != 0;
        }

        // ---- iteration --------------------------------------------------------

        /**
         * Address: 0x0052D120 (FUN_0052D120)  Address: 0x0052D1C0 (FUN_0052D1C0)
         * Address: 0x0052D250 (FUN_0052D250)  Address: 0x0052D2E0 (FUN_0052D2E0)
         * Address: 0x0052D370 (FUN_0052D370)  Address: 0x0052D410 (FUN_0052D410)
         * Address: 0x0052D4B0 (FUN_0052D4B0)
         *
         * The map-header initialisers for the seven `RRuleGameRulesImpl` blueprint
         * tables: seat the sentinel head, self-link it and zero the size. The
         * binary open-codes this once per table where the constructor now does it.
         */
        /**
         * Address: 0x006E1580 (FUN_006E1580, `msvc8::map<Moho::CmdId,
         * Moho::CUnitCommand*>::begin` -- `Moho::CCommandDb::commands` in
         * `CCommandDb.h`. `*outNode = map->head->left; return outNode;` --
         * the store-into-hidden-return-pointer form MSVC8 uses for a
         * non-trivial-return-type accessor, matching `iterator(tree_.
         * leftmost())`'s single-field write. Re-homed here from a bespoke
         * free function in `CCommandDb.cpp` (`StoreCommandMapBeginNode`)
         * during the `CommandDbMapNodeRuntime` hand-rolled-tree migration;
         * no direct caller confirmed in this pass (`incoming_xrefs` empty in
         * this sweep) beyond this member's own generic API surface, which
         * every range-for loop over `commands` in `CCommandDb.cpp` now
         * uses.)
         */
        [[nodiscard]] iterator begin() noexcept { return iterator(tree_.leftmost()); }
        [[nodiscard]] const_iterator begin() const noexcept { return const_iterator(tree_.leftmost()); }
        [[nodiscard]] const_iterator cbegin() const noexcept { return begin(); }

        [[nodiscard]] iterator end() noexcept { return iterator(tree_.header()); }
        [[nodiscard]] const_iterator end() const noexcept { return const_iterator(tree_.header()); }
        [[nodiscard]] const_iterator cend() const noexcept { return end(); }

        // ---- lookup -----------------------------------------------------------

        /**
         * Address: 0x0083A950 (FUN_0083A950, sub_83A950) --
         * `UiKeyActionMap`/`msvc8::map<UiKeyMask, msvc8::string>::find` --
         * `gUiKeyActionMap` (`moho/ui/UiRuntimeTypes.cpp:1394`), isNil@+0x2D
         * (see the sibling instantiation's `lower_bound_node` citation in
         * `RbTree.h` for the full node-layout derivation). `find_node`'s
         * nil-or-key-greater verify step is inlined into this emission
         * rather than called out separately; the lower-bound descent itself
         * remains out-of-line as `FUN_0083B050` (cited on `lower_bound_node`,
         * `RbTree.h`). Return type `iterator` uses MSVC8's hidden-return-
         * pointer ABI for non-trivial-return-type accessors (matching
         * `begin()`'s `FUN_006E1580` citation above): `edi`=hidden output
         * slot, `esi`=`&key`. Sole confirmed caller in this sweep is
         * `Moho::CUIKeyHandler::OnKeyDown` (FUN_00838D10,
         * `moho/ui/UiRuntimeTypes.h`/`.cpp`), which looks up the packed
         * shift/ctrl/alt/keycode chord and runs the bound command string
         * through `Moho::CON_Execute` on a hit.
         */
        /**
         * Address: 0x006ADD30 (FUN_006ADD30, func_hasArmorType -- IDA's own
         * inferred name; not a real "has type" predicate, see below) --
         * `msvc8::map<msvc8::string, float>::find` -- `Unit::
         * ArmorMultipliers` in `moho/unit/core/Unit.h`, isNil@+0x2D. Same
         * fused shape as `FUN_0083A950` above: `find_node`'s nil-or-key-
         * greater verify step is inlined into this emission (via
         * `std::operator<<char>`, the `msvc8::string` less-than compare)
         * rather than called out separately, while the lower-bound descent
         * itself remains out-of-line as `lower_bound_node`'s emission for
         * this instantiation (`FUN_006AFBF0`, cited in `RbTree.h`). Three
         * confirmed real callers, all in `Unit.cpp`: `Unit::
         * ProcessArmorOnDamage` (0x006A9D60, `ArmorMultipliers.find(...)` in
         * the recovered combat-math body), `Unit::GetArmorMult` (0x006A9E10,
         * same pattern), and `cfunc_UnitGetArmorMultL` (0x006C4200) via
         * `Unit::GetArmorMult`. Previously `recovered` with an address
         * annotation attached to `IsArmorMapSentinel` -- a trivial
         * null-or-isNil predicate that does not implement this function's
         * documented lower-bound-then-verify behavior at all (a
         * mis-attribution, not a real recovery of this address); that
         * helper is deleted and this member's real call sites (`.find()`)
         * are the recovery now (DB-integrity fix).
         */
        [[nodiscard]] iterator find(const key_type& k) { return iterator(tree_.find_node(k)); }
        [[nodiscard]] const_iterator find(const key_type& k) const { return const_iterator(tree_.find_node(k)); }

        /**
         * `rb_tree::count` (RbTree.h) carries this method's real address
         * (0x004DB770, a `msvc8::set<msvc8::string>` instantiation -- the
         * same shared `_Tree::count` member `map` and `set` both compile
         * down to) -- see that citation for the full evidence trail,
         * including why the general equal-range-based shape (not a
         * `find`+ternary shortcut) is what the binary actually emits.
         */
        [[nodiscard]] size_type count(const key_type& k) const { return tree_.count(k); }

        [[nodiscard]] iterator lower_bound(const key_type& k) { return iterator(tree_.lower_bound_node(k)); }
        [[nodiscard]] const_iterator lower_bound(const key_type& k) const
        {
            return const_iterator(tree_.lower_bound_node(k));
        }

        [[nodiscard]] iterator upper_bound(const key_type& k) { return iterator(tree_.upper_bound_node(k)); }
        [[nodiscard]] const_iterator upper_bound(const key_type& k) const
        {
            return const_iterator(tree_.upper_bound_node(k));
        }

        /**
         * `rb_tree::equal_range` (RbTree.h) carries this method's real
         * addresses (0x00A59E20/0x00A59E80, a `msvc8::set<std::uint32_t>`
         * instantiation -- the same shared `_Tree::equal_range` member `map`
         * and `set` both compile down to) -- see that citation for the full
         * evidence trail.
         */
        [[nodiscard]] std::pair<iterator, iterator> equal_range(const key_type& k)
        {
            const std::pair<node_type*, node_type*> range = tree_.equal_range(k);
            return {iterator(range.first), iterator(range.second)};
        }
        [[nodiscard]] std::pair<const_iterator, const_iterator> equal_range(const key_type& k) const
        {
            const std::pair<node_type*, node_type*> range = tree_.equal_range(k);
            return {const_iterator(range.first), const_iterator(range.second)};
        }

        /** Reference to the mapped value; asserts when the key is missing. */
        [[nodiscard]] mapped_type& at(const key_type& k)
        {
            node_type* const n = tree_.find_node(k);
            assert(!detail::rb_is_nil(n) && "msvc8::map::at: key not found");
            return n->value.second;
        }
        [[nodiscard]] const mapped_type& at(const key_type& k) const
        {
            const node_type* const n = tree_.find_node(k);
            assert(!detail::rb_is_nil(n) && "msvc8::map::at: key not found");
            return n->value.second;
        }

        /** Mapped value pointer, or nullptr when the key is absent. */
        [[nodiscard]] mapped_type* try_get(const key_type& k) noexcept
        {
            node_type* const n = tree_.find_node(k);
            return detail::rb_is_nil(n) ? nullptr : std::addressof(n->value.second);
        }
        [[nodiscard]] const mapped_type* try_get(const key_type& k) const noexcept
        {
            const node_type* const n = tree_.find_node(k);
            return detail::rb_is_nil(n) ? nullptr : std::addressof(n->value.second);
        }

        // ---- modifiers --------------------------------------------------------

        /** Destroys every node and restores the empty header links. */
        void clear() noexcept { tree_.clear(); }

        /**
         * Address: 0x007E3CF0 (FUN_007E3CF0, std::map<Moho::MeshBatchKey, std::vector<Moho::MeshInstance*>>::insert)
         *
         * IDA signature:
         * _Pairib *__userpurge insert@<eax>(_Tree *this@<ebx>, const value_type *val@<esi>, _Pairib *result);
         *
         * What it does:
         * Links a copy of `v` into the tree when its key is absent and reports
         * `true`; otherwise returns a cursor on the colliding node and `false`.
         */
        std::pair<iterator, bool> insert(const value_type& v)
        {
            const std::pair<node_type*, bool> result = tree_.insert_unique(v);
            return {iterator(result.first), result.second};
        }

        /** Hinted unique insert; a useless hint costs one extra comparison. */
        iterator insert(const_iterator hint, const value_type& v) { return iterator(tree_.insert_hint(hint, v)); }

        template<class... Args>
        std::pair<iterator, bool> emplace(Args&&... args)
        {
            const std::pair<node_type*, bool> result = tree_.emplace_unique(std::forward<Args>(args)...);
            return {iterator(result.first), result.second};
        }

        /**
         * Address: 0x007E2C60 (FUN_007E2C60, std::map<MeshBatchKey, vector<MeshInstance*>>::operator[])
         * Address: 0x005A0040 (FUN_005A0040, std::map<uint, Moho::RUnitBlueprint*>::operator[])
         * Address: 0x00718360 (FUN_00718360, std::map<uint32, cellIndex>::operator[])
         * Address: 0x0083A9D0 (FUN_0083A9D0, msvc8::map<UiKeyMask,bool>::operator[] --
         * verified via the returned offset (`v1+16`): node header 12 + key
         * uint32 4 = 16, matching the pair<UiKeyMask,bool>'s mapped_type
         * offset exactly. Emitted via gUiKeyRepeatMap[keyMask] = true in
         * AddUiKeyMapEntries, UiRuntimeTypes.cpp)
         * Address: 0x00685750 (FUN_00685750, `std::map_uint_IdPool::find2` --
         * `msvc8::map<std::uint32_t, moho::IdPool>::operator[]`,
         * `CEntityDb::mIdPoolTree` in `EntityDb.h`. Matches this member
         * exactly: calls `find` (this instantiation's `lower_bound_node`
         * emission), and on a miss (`result == head || key < result->key`)
         * default-constructs a fresh `IdPool` and inserts it via
         * `std::map_uint_IdPool::insert` (`FUN_006864E0`, cited on
         * `insert_hint` in RbTree.h) -- the same lower-bound-then-hinted-
         * insert shape this member performs. Reached from `Moho::EntityDB::
         * DoReserveId`/`ReleaseId` (`FUN_00684480`/`FUN_00684690`) in the
         * binary; the current recovery reaches the same instantiation from
         * `CEntityDb::MemberSerialize`'s `mIdPoolTree[familySourceBits]`
         * -- `DoReserveId`/`ReleaseId` themselves still route id allocation
         * through a separate `gRuntimePools` runtime cache rather than this
         * member directly, a known follow-up documented in the EntityDb.cpp
         * `MemberSerialize`/`MemberDeserialize` citations.)
         * Address: 0x007B27D0 (FUN_007B27D0, `msvc8::map<std::uint32_t,
         * msvc8::set<std::uint32_t>>::operator[]` -- confirmed via raw
         * `.asm`: real `this`=ecx (thiscall), descend loop testing isNil at
         * `[node+0x1D]` (29 decimal, this instantiation's outer 32-byte
         * node) updating the candidate only on left turns (`lower_bound`'s
         * shape, not `insert_unique`'s unconditional descend). On a miss,
         * builds the `value_type(k, mapped_type())` temporary -- the bare
         * `mapped_type()` sub-expression first (`sub_7B4A50`, already-cited
         * `alloc_raw()`, RbTree.h, plus an inlined self-link/`isNil=1`/
         * `size_=0` at byte offset 0x11 -- the *inner*
         * `msvc8::set<std::uint32_t>`'s isNil offset -- exactly
         * `buy_head()` inlined, not a separate call), then `sub_7B3500`
         * (this same instantiation's *copy* constructor, RbTree.h -- not a
         * default ctor: it copy-constructs the pair's `.second` from the
         * just-built bare temporary, since C++03 `pair(const key_type&,
         * const mapped_type&)` has no move path) for the `mapped_type()`
         * temporary proper -- then `sub_7B2DF0` (`insert_hint`, RbTree.h,
         * matched by its empty/leftmost/rightmost/predecessor-successor
         * branch structure and its isNil check at the *outer* offset)
         * inserts it, and `sub_7B3E00` (already-cited `erase_range` for
         * `msvc8::set<std::uint32_t>`) tears down the scratch temporaries in
         * reverse construction order -- `FUN_007B2940`/`FUN_007B2970`/
         * `FUN_007B36A0` are this teardown's three real-binary addresses
         * (two SEH-unwind funclets for the two temporaries, one the copy
         * constructor's own exception-cleanup); full citations on
         * `~rb_tree()`/`rb_tree(const rb_tree&)` in RbTree.h.
         * Builds `CON_ANI_DumpSkeleton`'s per-parent-bone dedup map, keyed
         * by parent-bone-pointer, each entry holding the set of that
         * parent's already-visited child-bone pointers -- `dedupTree[
         * parentPtr]` inside the per-bone walk loop (CAniSkel.cpp, not yet
         * recovered).)
         *
         * IDA signature:
         * mapped_type *__thiscall operator[](const key_type *key, _Tree *this);
         *
         * What it does:
         * Locates the lower bound for `k`; when that cursor is `end()` or holds a
         * greater key, inserts `value_type(k, mapped_type())` at the located gap.
         * Returns a reference to the mapped value either way.
         */
        /**
         * Address: 0x006ADBF0 (FUN_006ADBF0) -- `msvc8::map<msvc8::string,
         * float>::operator[]` -- `Unit::ArmorMultipliers` in `moho/unit/
         * core/Unit.h`, isNil@+0x2D. IDA's own inferred listing name for
         * this address is `std::map_string_float::find` -- WRONG: `find()`
         * never mutates, but this emission constructs a fresh key copy and
         * calls the hinted-insert internal (`insert_hint`'s emission for
         * this instantiation, `FUN_006AEDD0`, cited in `RbTree.h`) whenever
         * the lower-bound miss, then returns `&result->second` (a raw
         * `float*`/`mapped_type&`, trivial ABI, not the hidden-pointer
         * `iterator` convention `find()`'s own emission above uses) --
         * exactly this member's find-then-conditional-insert-then-return-
         * reference shape, not `find()`'s read-only shape. Three confirmed
         * real callers, all in `Unit.cpp`: `Unit::InitializeArmor`
         * (0x006A7B90, `ArmorMultipliers[damageTypeName] = armorMultiplier`
         * seeding entries from blueprint armor definitions), an
         * owner=<none> inlined chunk at 0x006A9DF6 (inside one of the two
         * recovered callers above), and `cfunc_UnitAlterArmorL` (0x006C4000,
         * the Lua `Unit:AlterArmor(damageTypeName, multiplier)` setter,
         * `unit->ArmorMultipliers[armorTypeName] = armorMultiplier`).
         * Previously marked `external_dependency` with a generic bulk-tag
         * note ("STL template instantiation / codec helper - external") --
         * wrong on two counts: this is a real engine-instantiated map
         * (`Unit`'s own armor data, not a generic/third-party codec), and
         * per RULE ONE its recovery is this member's own call sites in
         * `Unit.cpp`, not a hand-rolled free function or an external tag
         * (DB-integrity fix).
         *
         * Address: 0x008A7C80 (FUN_008A7C80, sub_8A7C80) -- `msvc8::map<
         * msvc8::string, moho::TerrainEnvironmentLookupEntry>::operator[]`
         * -- `Moho::CWldTerrainRes::mEnvLookup` (`TerrainRuntimeView`/
         * `TerrainVisualResourceRuntimeView` in `moho/sim/CWldMap.cpp`),
         * isNil@+0x4D (0x50-byte node: 12-byte link triplet + 28-byte
         * `msvc8::string` key + 0x24-byte `TerrainEnvironmentLookupEntry`
         * value + color/isNil). IDA's own inferred listing name for this
         * address is `std::map_string_shared_ptr_RD3DTextureResource::
         * find` -- WRONG on two counts, the same misnomer already
         * documented on `FUN_006ADBF0` above: `find()` never mutates, but
         * this emission's lower-bound-miss path default-constructs a fresh
         * `TerrainEnvironmentLookupEntry` and calls the hinted-insert
         * internal (`insert_hint`'s emission for this instantiation,
         * `FUN_008A8590`, cited in `RbTree.h`); and the mapped type IDA's
         * heuristic inferred (`shared_ptr<RD3DTextureResource>`) is only
         * one field of the real 0x24-byte `TerrainEnvironmentLookupEntry`
         * value (`{msvc8::string mEnvironmentName; boost::shared_ptr<
         * RD3DTextureResource> mTexture;}`), confirmed by this emission's
         * own default-value construction (`v8.mName` empty-SSO-init,
         * `v8.mTex.obj`/`.count.pi_` zeroed) and by its caller overwriting
         * both `v9->mName` and `v9->mTex` fields unconditionally. Matches
         * this member's find-then-conditional-insert-then-return-reference
         * shape exactly: `where = lower_bound(k)` (`FUN_008A8FE0`, cited in
         * `RbTree.h`), `where == end() || comp(k, where->first)` miss test,
         * `insert(hint, value_type(k, mapped_type()))` on a miss
         * (`FUN_008A8590`), `return where->second`. Sole real caller is
         * `IWldTerrainRes::AddEnvLookup` (0x008A1380, `CWldMap.cpp`):
         * `mEnvLookup[environmentKey] = TerrainEnvironmentLookupEntry(
         * texturePath, texture)`, which always resolves the D3D texture
         * handle first (0x008A1323-0x008A1331) then reaches this member to
         * get-or-default-construct the slot before overwriting both its
         * fields -- exactly this member's role, on both the cache-hit and
         * cache-miss paths alike. `Moho::CWldTerrainRes::Reset`
         * (FUN_008A6220) is a second real caller (per this token's own
         * `.xrefs.txt`), reinstating the single `<default>` environment
         * entry after `ClearEnvLookup`; the current recovery performs that
         * same assignment via `view->mEnvLookup[defaultEnvironmentKey] =
         * defaultEnvironment;` in `CWldTerrainRes::Reset`'s body.
         *
         * Prior to this pass, `AddEnvLookup`'s recovered source reached
         * `mEnvLookup` through a bespoke, fully duplicated hand-rolled
         * red-black tree (`InsertTerrainEnvironmentNode` and ~20 sibling
         * free functions in `CWldMap.cpp`, deleted here) that never called
         * this member, or any other real binary function on this call
         * chain, at all -- functionally equivalent (both are find-or-
         * default-insert-then-overwrite), but zero of `FUN_008A7C80`,
         * `FUN_008A8590`, and their own callee chain had any citation
         * anywhere in `src/sdk`. This entry, and `mEnvLookup`'s migration
         * onto this template, is that recovery.
         *
         * Address: 0x00879120 (FUN_00879120, sub_879120) -- `msvc8::map<
         * std::uint32_t, Moho::CWldTerrainDecal*>::operator[]` --
         * `Moho::CDecalManager::mDecalGroupLookupByDecalIndex`
         * (`moho/terrain/splat/CWldSplat.h`), isNil@+0x15 (same
         * instantiation cited on `insert_hint`/`insert_unique`/`insert_at`/
         * `rb_decrement`/`rb_increment`/`find_node`/`equal_range`/
         * `~rb_tree()`, `RbTree.h`). Register-traced field for field: fully
         * inlined `lower_bound` descent (tracking the best `>=` candidate),
         * a `where == end() || comp(k, where->first)` miss test, and on a
         * miss a hinted insert (`insert_hint`'s emission for this
         * instantiation, `FUN_00879B10`, `RbTree.h`) of a fresh
         * `{k, mapped_type()}` pair built on the caller's stack -- exactly
         * this member's shape, with `where->second` returned as `&node->
         * value+0x10`. Sole real caller is `CDecalManager::LoadDecal`'s
         * `mDecalGroupLookupByDecalIndex[decalIndex] = loaded;`
         * (`CWldSplat.cpp`). Re-homed here from a hand-rolled
         * `ResolveLookupValueSlotForKey` free function that walked a
         * duplicate `DecalGroupLookupNode`/`...Tree` struct pair, found or
         * linked a new node with **no rotation/recolor step at all**
         * (a plain unbalanced-BST insert, not this member's real
         * self-balancing algorithm -- the same missing-rebalance shape
         * documented on `AudioMap1CategoryNode` in
         * `.memory/project_audiomap1_missing_rebalance_bug.md`), and
         * returned a raw `std::uint32_t*` the caller had to null-check and
         * write through by hand -- all now replaced by this member's own
         * `operator[]`.
         * Address: 0x00879450 (FUN_00879450, sub_879450) -- the sibling
         * `msvc8::map<std::uint32_t, Moho::CDecalGroup*>::operator[]`
         * emission for `Moho::CDecalManager::mDecalGroupLookupBySplatIndex`,
         * same shape, calling that tree's own `insert_hint`
         * (`FUN_00879F60`, `RbTree.h`). Sole real caller is
         * `CDecalManager::LoadDecalGroup`'s
         * `mDecalGroupLookupBySplatIndex[*group->GetIndex()] = group;`
         * (`CWldSplat.cpp`).
         */
        mapped_type& operator[](const key_type& k)
        {
            iterator where = lower_bound(k);
            if (where == end() || tree_.key_comp()(k, where->first)) {
                where = insert(const_iterator(where), value_type(k, mapped_type()));
            }
            return where->second;
        }

        /**
         * Unlinks the node under `pos`, frees it and returns a cursor on the
         * following element.
         *
         * Address: 0x0057DA50 (FUN_0057DA50, sub_57DA50) --
         * `SBuildStructurePositionMap`/`msvc8::map<Wm3::Vector2i,
         * SBuildReserveInfo>::erase(const_iterator)`
         * (`moho::CAiBrain::mBuildStructureMap`, `CAiBrain.h:68/266`).
         * Reached from `EraseBuildReservation` (`CAiBrain.cpp:1417`,
         * already recovered: `map.erase(position)`), which is itself
         * called mid-walk from `CanBuildStructureAt`'s (`FUN_0057CBB0`)
         * Stage 3 reservation scan -- a genuinely mid-iteration erase, not
         * a whole-range destructor call, so (unlike the RRuleGameRules/
         * WriteArchive cases elsewhere in this file) this instantiation's
         * `_SECURE_SCL` checked-iterator guard is on a REACHED code path;
         * it just never trips, since `position` is always a live, valid
         * cursor from the enclosing walk.
         */
        iterator erase(const_iterator pos) { return iterator(tree_.erase_node(pos.node())); }

        /**
         * Address: 0x0083AA70 (FUN_0083AA70, sub_83AA70) -- CORRECTED: was
         * mislabeled `UiKeyActionMap`/`msvc8::map<UiKeyMask, msvc8::string>`
         * here despite already noting `isNil@+0x15` -- that offset belongs
         * to `UiKeyRepeatMap`, not `UiKeyActionMap` (which is isNil@+0x2D;
         * see `FUN_0083A640` cited on `erase(const_iterator)` above). This
         * is NOT actually `UiKeyRepeatMap::erase(const key_type&)`'s own
         * symbol: the compiled body is `erase_node`'s emission for this
         * instantiation (cited under that member in `RbTree.h`) with the
         * `find_node` descent inlined directly into `RemoveUiKeyMapEntries`
         * (`FUN_00839270`, `gUiKeyRepeatMap.erase(keyMask)`,
         * `UiRuntimeTypes.cpp:1466`) instead of compiled as a separate
         * `erase(key)` symbol -- this instantiation simply never got one.
         * Kept here only as a record of that fact; it is not evidence for
         * this method's own code shape. The `out_of_range` guard `erase_node`
         * carries is unreachable at that inlined call site since `n` is
         * always either nil (short-circuited before the call) or a
         * genuinely-found, valid node.
         *
         * The general shape below -- `find`+conditional-`erase_node` is
         * itself a reasonable-looking but non-canonical shortcut valid only
         * because a `map`'s keys are unique. Real MSVC8 `_Tree::erase(const
         * key_type&)` is shared machinery between `map`/`set`/`multimap`/
         * `multiset` and can't assume uniqueness, so it is always the
         * general `equal_range`+count+`erase_range` shape -- confirmed
         * directly against the decompiled body of a `msvc8::set<
         * std::uint32_t>` instantiation (0x00A65B60/0x00A65C10, cited on
         * `rb_tree::erase(const key_type&)` in `RbTree.h`). `map`/`set`
         * both delegate to that one shared member now instead of each
         * hand-rolling their own shortcut.
         */
        size_type erase(const key_type& k) { return tree_.erase(k); }

        /**
         * Erases `[first, last)` and returns a cursor on the first survivor.
         *
         * The whole-tree fast path and the `erase(_First++)` walk both live on
         * `rb_tree::erase_range` - see the address block there. Re-implementing
         * the walk here would lose the fast path the shipped bodies take.
         */
        iterator erase(const_iterator first, const_iterator last)
        {
            return iterator(tree_.erase_range(first.node(), last.node()));
        }

        void swap(map& other) noexcept { tree_.swap(other.tree_); }

    private:
        tree_type tree_;
    };

    // --------- Convenience: ensure 32-bit pointer size assumed ----------
    static_assert(sizeof(map<void*, void*>) == 0x0C, "msvc8::map size should be 0x0C");

} // namespace msvc8

#pragma pack(pop)
