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

        [[nodiscard]] iterator find(const key_type& k) { return iterator(tree_.find_node(k)); }
        [[nodiscard]] const_iterator find(const key_type& k) const { return const_iterator(tree_.find_node(k)); }

        [[nodiscard]] size_type count(const key_type& k) const { return find(k) != end() ? 1u : 0u; }

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

        [[nodiscard]] std::pair<iterator, iterator> equal_range(const key_type& k)
        {
            return {lower_bound(k), upper_bound(k)};
        }
        [[nodiscard]] std::pair<const_iterator, const_iterator> equal_range(const key_type& k) const
        {
            return {lower_bound(k), upper_bound(k)};
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
         * `CEntityDb::MemberDeserialize`'s `mIdPoolTree[familySourceBits]`
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
         * builds the `value_type(k, mapped_type())` temporary --
         * `sub_7B4A50` (already-cited `alloc_raw()`, RbTree.h) plus an
         * inlined empty-set head-ify at byte offset 0x11 (the *inner*
         * `msvc8::set<std::uint32_t>`'s isNil offset) for the raw node, then
         * `sub_7B3500` (a full `msvc8::set<std::uint32_t>` default-ctor
         * emission) for the `mapped_type()` temporary proper -- then
         * `sub_7B2DF0` (`insert_hint`, RbTree.h, matched by its empty/
         * leftmost/rightmost/predecessor-successor branch structure and its
         * isNil check at the *outer* offset) inserts it, and `sub_7B3E00`
         * (already-cited `erase_range` for `msvc8::set<std::uint32_t>`)
         * tears down the scratch temporaries in reverse construction order.
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
         * is `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::erase(const
         * key_type&)` (`gUiKeyRepeatMap`, `moho/ui/UiRuntimeTypes.cpp:
         * 1395`). `find_node`-then-conditionally-`erase_node` shape
         * matching this member exactly (`RemoveUiKeyMapEntries`'s
         * `gUiKeyRepeatMap.erase(keyMask)`, `UiRuntimeTypes.cpp:1466` --
         * not `:1465`, which is the sibling `gUiKeyActionMap.erase(keyMask)`
         * call the mislabeled version pointed at instead -- already
         * recovered). The compiled body is FUN_0083AA70's own `erase_node`
         * shape with the `find_node` descent inlined directly into
         * `RemoveUiKeyMapEntries` (`FUN_00839270`) rather than compiled as
         * a separate `erase(key)` symbol for this instantiation; the real
         * canonical home and full evidence trail is `erase_node`'s
         * citation for this same address in `RbTree.h`. The `out_of_range`
         * guard this compiles in (via `erase_node`'s own `_SECURE_SCL`
         * checked-iterator machinery, see this file's `~rb_tree()` note in
         * `RbTree.h`) is unreachable here since `n` is always either nil
         * (short-circuited before the call) or a genuinely-found, valid
         * node.)
         */
        size_type erase(const key_type& k)
        {
            node_type* const n = tree_.find_node(k);
            if (detail::rb_is_nil(n)) {
                return 0;
            }
            (void)tree_.erase_node(n);
            return 1;
        }

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
