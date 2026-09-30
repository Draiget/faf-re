#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

#include "legacy/containers/RbTree.h"

#ifndef MSVC8_SET_NOEXCEPT
#  define MSVC8_SET_NOEXCEPT noexcept
#endif

#pragma pack(push, 4)

namespace msvc8
{
    /**
     * \brief Owning MSVC8-layout `std::set`.
     *
     * All red-black mechanics live in `detail::rb_tree` (RbTree.h), which this
     * container shares with `msvc8::map`; the key extractor is the identity, so
     * `value_type` is the key itself.
     *
     * Layout is the shipped 12-byte `{proxy, _Myhead, _Mysize}` triplet with the
     * comparator empty-base-optimised away.
     */
    template<class Key, class Less = std::less<Key>>
    class set
    {
        using traits = detail::rb_set_traits<Key, Less>;
        using tree_type = detail::rb_tree<traits>;

    public:
        // -------- public aliases --------
        using key_type = Key;
        using value_type = Key;
        using size_type = std::uint32_t;
        using difference_type = std::ptrdiff_t;
        using key_compare = Less;
        using value_compare = Less;
        using reference = const value_type&;
        using const_reference = const value_type&;

        /** Set elements are immutable, so both cursors are the const iterator. */
        using const_iterator = detail::rb_iterator<traits, true>;
        using iterator = const_iterator;

        // -------- ctor/dtor --------
        set() MSVC8_SET_NOEXCEPT {}
        explicit set(const key_compare& comp) : tree_(comp) {}

        /**
         * Address: 0x00822C50 (FUN_00822C50 -- `set(first, last)` for
         *   `msvc8::set<moho::WeakSet<moho::UserEntity>::Entry>`, the source a
         *   `WeakSet` walk: `_Init` (the head bought through 0x007B08D0,
         *   isNil=1, self-linked, count zero), then per element the `Entry` the
         *   source's `T*` converts to, `insert` 0x007AEDC0, `~Entry`, and the
         *   source's pruning `++`. Caller the `WeakSet` copy constructor
         *   0x00822210.)
         * Address: 0x00831310 (FUN_00831310 -- the same body for
         *   `WeakSet<moho::UserUnit>::Entry`, inserting through 0x00822420;
         *   callers `UserArmy::GetIdleEngineers`/`GetIdleFactories` (0x008B2550 /
         *   0x008B25C0), `EstimateEdgeTravelTicks` (0x00826C50) and
         *   `ISSUE_IncreaseCommandCount` (0x008B0C80), each copying a set.)
         *
         * What it does:
         * VC8's `_Tree(_Iter _First, _Iter _Last)`: an empty tree, then
         * `insert(_First, _Last)`.
         */
        template<class InputIt>
        set(InputIt first, InputIt last)
        {
            insert(first, last);
        }

        /**
         * Address: 0x008C5B10 (FUN_008C5B10, msvc8::set<msvc8::string>::set(const set&))
         *
         * What it does:
         * Stands a fresh empty tree up and copies every key across through
         * `_Copy` (FUN_008C5D50). `UserUnit::AddToSelectionSet` uses it to
         * snapshot a unit's selection-set names before mutating the target's.
         */
        set(const set& o) : tree_(o.tree_) {}
        set& operator=(const set& o)
        {
            tree_ = o.tree_;
            return *this;
        }
        set(set&& o) MSVC8_SET_NOEXCEPT : tree_(std::move(o.tree_)) {}
        set& operator=(set&& o) MSVC8_SET_NOEXCEPT
        {
            tree_ = std::move(o.tree_);
            return *this;
        }

        // -------- iterators --------
        [[nodiscard]] iterator begin() const MSVC8_SET_NOEXCEPT { return iterator(tree_.leftmost()); }
        [[nodiscard]] iterator end() const MSVC8_SET_NOEXCEPT { return iterator(tree_.header()); }
        [[nodiscard]] iterator cbegin() const MSVC8_SET_NOEXCEPT { return begin(); }
        [[nodiscard]] iterator cend() const MSVC8_SET_NOEXCEPT { return end(); }

        // -------- capacity --------
        [[nodiscard]] bool empty() const MSVC8_SET_NOEXCEPT { return tree_.empty(); }
        [[nodiscard]] size_type size() const MSVC8_SET_NOEXCEPT { return tree_.size(); }

        [[nodiscard]] key_compare key_comp() const { return tree_.key_comp(); }
        [[nodiscard]] value_compare value_comp() const { return tree_.key_comp(); }

        // -------- lookup --------
        /**
         * Address: 0x008C5B90 (FUN_008C5B90, msvc8::set<msvc8::string>::find)
         *
         * What it does:
         * Runs the `_Lbound` descent and confirms the landed key is not ordered
         * after the probe, returning `end()` when the key is absent.
         * Address: 0x008D5020 (FUN_008D5020 -- `find` -- that lower bound plus the equivalence check, returning the header on a miss for `msvc8::set<moho::Resolution>` (the adapter-mode dedup tree in moho/misc/StartupHelpers.cpp, node 0x20, element 0x10 at node+0x0C, isNil@+0x1D); callers 0x008D21E0, 0x008D26D0; formerly `ResolveAdapterModeSortInsertionAnchor` in moho/misc/StartupHelpers.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x007D7C20 (FUN_007D7C20 -- `find` -- lower bound plus the `key < candidate` check, returning the header on a miss for `msvc8::set<moho::ClutterRegionKey, moho::ClutterRegionKeyLess>` (`Clutter::mKeys` at +0x191C; node 0x1C, the 0x0C key at node+0x0C, colour/nil at +0x18/+0x19); callers 0x007D64D0 (unreached); formerly `FindRegionKeyExactOrHead` in moho/render/Clutter.cpp (RULE ONE), removed 2026-09-10.)
         */
        [[nodiscard]] iterator find(const key_type& k) const { return iterator(tree_.find_node(k)); }

        /**
         * `rb_tree::count` (RbTree.h) carries this method's real address
         * (0x004DB770, `msvc8::set<msvc8::string>`) -- see that citation
         * for the full evidence trail, including why the general
         * equal-range-based shape (not a `find`+ternary shortcut) is what
         * the binary actually emits.
         */
        [[nodiscard]] size_type count(const key_type& k) const { return tree_.count(k); }

        /**
         * Address: 0x004AD790 (FUN_004AD790 -- `lower_bound` for `msvc8::set<moho::PrefetchRequestRuntime, PrefetchRequestLess>` (the prefetch-request tree, node 0x50, value 0x40, isNil@+0x4D); callers 0x004AB780, 0x004AC9B0; formerly `LowerBoundPrefetchRequestEntry_004AD790` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-10.)
         */
        [[nodiscard]] iterator lower_bound(const key_type& k) const { return iterator(tree_.lower_bound_node(k)); }
        /**
         * Address: 0x004AD800 (FUN_004AD800 -- `upper_bound` for `msvc8::set<moho::PrefetchRequestRuntime, PrefetchRequestLess>` (the prefetch-request tree, node 0x50, value 0x40, isNil@+0x4D); callers 0x004AB780, 0x004AC9C0; formerly `UpperBoundPrefetchRequestEntry_004AD800` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-10.)
         */
        [[nodiscard]] iterator upper_bound(const key_type& k) const { return iterator(tree_.upper_bound_node(k)); }

        /**
         * `rb_tree::equal_range` (RbTree.h) carries this method's real
         * addresses (0x00A59E20/0x00A59E80, `msvc8::set<std::uint32_t>`) --
         * see that citation for the full evidence trail.
         */
        [[nodiscard]] std::pair<iterator, iterator> equal_range(const key_type& k) const
        {
            const std::pair<typename tree_type::node_type*, typename tree_type::node_type*> range =
                tree_.equal_range(k);
            return {iterator(range.first), iterator(range.second)};
        }

        // -------- modifiers --------
        void clear() MSVC8_SET_NOEXCEPT { tree_.clear(); }

        /**
         * Address: 0x004AC890 (FUN_004AC890 -- the caller-side half of that same `insert(value)` for `msvc8::set<moho::PrefetchRequestRuntime, PrefetchRequestLess>` (the prefetch-request tree, node 0x50, value 0x40, isNil@+0x4D); callers 0x004AA220, 0x004AAC20; formerly `FindOrInsertPrefetchRequestEntry` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x004AD5E0 (FUN_004AD5E0 -- `insert(value)` -- lower_bound, then `_Buynode` at that hint when the element is not already there for `msvc8::set<moho::PrefetchRequestRuntime, PrefetchRequestLess>` (the prefetch-request tree, node 0x50, value 0x40, isNil@+0x4D); callers 0x004AC890; formerly `InsertPrefetchRequestEntry_004AD5E0` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-10.)
         */
        std::pair<iterator, bool> insert(const value_type& v)
        {
            const std::pair<typename tree_type::node_type*, bool> result = tree_.insert_unique(v);
            return {iterator(result.first), result.second};
        }

        std::pair<iterator, bool> insert(value_type&& v) { return emplace(std::move(v)); }

        /**
         * Address: 0x00868AF0 (FUN_00868AF0 -- `insert(first, last)` for
         *   `msvc8::set<moho::WeakSet<moho::UserEntity>::Entry>` over a
         *   `gpg::fastvector<moho::UserEntity*>` range: a stack `Entry` per
         *   element, `insert` 0x007AEDC0, `~Entry`; `WeakSet::Add(first, last)`
         *   for `SelectionDragger`'s collected entities.)
         * Address: 0x00868A00 (FUN_00868A00 -- the same over another
         *   `WeakSet<UserEntity>`'s iterators, whose `++` (0x0066ADD0 +
         *   0x0066A330) prunes the source; `SelectionDragger::DragRelease`
         *   0x00863870 merges sets through it.)
         *
         * VC8's `_Tree::insert(_Iter _First, _Iter _Last)`: `insert(*_First)` per
         * element. `*first` may convert to `value_type`; binding that result to a
         * const reference keeps VC8's single `insert(const value_type&)` path
         * (search, then buy the node) rather than the move overload's
         * node-first `emplace`.
         */
        template<class InputIt>
        void insert(InputIt first, const InputIt last)
        {
            for (; first != last; ++first) {
                const value_type& value = *first;
                insert(value);
            }
        }

        template<class... Args>
        std::pair<iterator, bool> emplace(Args&&... args)
        {
            const std::pair<typename tree_type::node_type*, bool> result =
                tree_.emplace_unique(std::forward<Args>(args)...);
            return {iterator(result.first), result.second};
        }

        /**
         * Address: 0x00718410 (FUN_00718410, msvc8::set<Moho::InfluenceMapEntry, Moho::InfluenceMapEntryLess>::erase)
         *
         * What it does:
         * Unlinks the node under `pos`, repairs the black-height deficit, frees
         * the node and returns a cursor on the following element. Emitted via
         * `InfluenceGrid::RemoveEntry`'s `entries.erase(it)`.
         */
        iterator erase(iterator pos) { return iterator(tree_.erase_node(pos.node())); }

        /**
         * `rb_tree::erase(const key_type&)` (RbTree.h) carries this method's
         * real addresses (0x00A65B60/0x00A65C10, `msvc8::set<std::uint32_t>`)
         * -- see that citation for the full evidence trail, including why
         * the general equal-range-based shape (not a `find`+single-`erase`
         * shortcut) is what the binary actually emits.
         * Address: 0x007D7B90 (FUN_007D7B90 -- `erase(const key_type&)` -- count the equal range, then erase it for `msvc8::set<moho::ClutterRegionKey, moho::ClutterRegionKeyLess>` (`Clutter::mKeys` at +0x191C; node 0x1C, the 0x0C key at node+0x0C, colour/nil at +0x18/+0x19); callers 0x007D7080; formerly `EraseRegionKeyRange` in moho/render/Clutter.cpp (RULE ONE), removed 2026-09-10.)
         */
        size_type erase(const key_type& k) { return tree_.erase(k); }

        /**
         * Erases `[first, last)` and returns a cursor on the first survivor.
         *
         * The whole-tree fast path and the `erase(_First++)` walk both live on
         * `rb_tree::erase_range` - see the address block there. The local loop
         * this replaced agreed on the returned cursor, but it had no fast path:
         * clearing a whole tree ran one rebalancing erase per element instead of
         * the single recursive `_Erase` plus header reset the binary performs.
         * Address: 0x004AE2B0 (FUN_004AE2B0 -- `erase(first, last)`, each element's request state released first for `msvc8::set<moho::PrefetchRequestRuntime, PrefetchRequestLess>` (the prefetch-request tree, node 0x50, value 0x40, isNil@+0x4D); callers 0x004A9C00, 0x004A9DD0, 0x004AC870; formerly `ErasePrefetchRequestEntryRange_004AE2B0` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-10.)
         */
        iterator erase(iterator first, iterator last)
        {
            return iterator(tree_.erase_range(first.node(), last.node()));
        }

        void swap(set& other) MSVC8_SET_NOEXCEPT { tree_.swap(other.tree_); }

    private:
        tree_type tree_;
    };

    /**
     * \brief Owning MSVC8-layout `std::multiset`.
     *
     * The same `_Tree` as `set`, instantiated with `_Multi = true`: equivalent
     * keys are allowed and land in insertion order, and the hinted insert takes
     * the non-strict `_Multi` branch that falls back to `insert_equal`. Same
     * 12-byte `{proxy, _Myhead, _Mysize}` head, same node.
     *
     * Unlike `set`, `iterator` hands out `value_type&`, because VC8's did:
     * Dinkumware's `_Tree::iterator` stayed mutable for the set containers until
     * VC10 made it the const iterator, and engine code wrote the non-key half
     * of an element through it. The spatial database does exactly that -- it
     * stores the moved entry's box and owning leaf lane through the entry's
     * iterator (0x00501C10, 0x00502200). Changing the key that way is as
     * undefined here as it was then.
     *
     * `moho::SpatialMap<T>` (moho/mesh/SpatialDb.h) is the instantiation this
     * models; its emissions are cited on these members and on `rb_tree`.
     */
    template<class Key, class Less = std::less<Key>>
    class multiset
    {
        using traits = detail::rb_set_traits<Key, Less>;
        using tree_type = detail::rb_tree<traits>;

    public:
        using key_type = Key;
        using value_type = Key;
        using size_type = std::uint32_t;
        using difference_type = std::ptrdiff_t;
        using key_compare = Less;
        using value_compare = Less;
        using reference = value_type&;
        using const_reference = const value_type&;

        using iterator = detail::rb_iterator<traits, false>;
        using const_iterator = detail::rb_iterator<traits, true>;

        multiset() {}
        explicit multiset(const key_compare& comp) : tree_(comp) {}
        multiset(const multiset& o) : tree_(o.tree_) {}
        multiset& operator=(const multiset& o)
        {
            tree_ = o.tree_;
            return *this;
        }
        multiset(multiset&& o) MSVC8_SET_NOEXCEPT : tree_(std::move(o.tree_)) {}
        multiset& operator=(multiset&& o) MSVC8_SET_NOEXCEPT
        {
            tree_ = std::move(o.tree_);
            return *this;
        }

        /**
         * Address: 0x00504380 (FUN_00504380 -- `begin()` through the hidden iterator slot, `_Myhead->_Left`, for `moho::SpatialMap<T>` (moho/mesh/SpatialDb.h); zero callers, no references, a linker-retained copy nothing runs. Formerly `StorePointerSlot04LaneA`'s "dereferencing shape" over `PointerToPointerSlot04RuntimeView` in moho/mesh/Mesh.cpp (RULE THREE), removed 2026-09-29.)
         */
        [[nodiscard]] iterator begin() noexcept { return iterator(tree_.leftmost()); }
        [[nodiscard]] const_iterator begin() const noexcept { return const_iterator(tree_.leftmost()); }

        /**
         * Address: 0x00504390 (FUN_00504390 -- `end()` through the hidden iterator slot, `_Myhead` itself, for `moho::SpatialMap<T>` (moho/mesh/SpatialDb.h); zero callers, no references, a linker-retained copy nothing runs. Formerly `StorePointerSlot04LaneA` over `PointerSlot04RuntimeView` in moho/mesh/Mesh.cpp (RULE THREE), removed 2026-09-29.)
         */
        [[nodiscard]] iterator end() noexcept { return iterator(tree_.header()); }
        [[nodiscard]] const_iterator end() const noexcept { return const_iterator(tree_.header()); }

        [[nodiscard]] bool empty() const MSVC8_SET_NOEXCEPT { return tree_.empty(); }
        [[nodiscard]] size_type size() const MSVC8_SET_NOEXCEPT { return tree_.size(); }
        [[nodiscard]] key_compare key_comp() const { return tree_.key_comp(); }

        /**
         * Always inserts; equivalent keys keep insertion order. See
         * `rb_tree::insert_equal`, which carries the `_Tree::insert` body
         * (0x00504990) this returns `.first` of.
         *
         * Address: 0x00504310 (FUN_00504310 -- `multiset::insert(value)` -- `_Tree::insert` 0x00504990, then `.first` stored through the hidden iterator slot, for `moho::SpatialMap<T>` (moho/mesh/SpatialDb.h); callers 0x00502200 (the entity lane of `SpatialShardData<T>::Insert`, the one of its four inserts MSVC left out of line); formerly `InsertSpatialEntityPayload` in moho/mesh/Mesh.cpp (RULE ONE), removed 2026-09-29.)
         */
        iterator insert(const value_type& v) { return iterator(tree_.insert_equal(v)); }

        /**
         * The `_Multi` hinted insert. See `rb_tree::insert_hint_equal`, which
         * carries the body (0x00504A10).
         *
         * Address: 0x00504330 (FUN_00504330 -- the calling-convention bridge that moves the hidden result slot into `ebx` and tail-calls `insert(where, value)` 0x00504A10, for `moho::SpatialMap<T>` (moho/mesh/SpatialDb.h); zero callers, no references, a linker-retained copy nothing runs.)
         */
        iterator insert(const_iterator hint, const value_type& v)
        {
            return iterator(tree_.insert_hint_equal(hint, v));
        }

        iterator erase(const_iterator pos) { return iterator(tree_.erase_node(pos.node())); }
        iterator erase(const_iterator first, const_iterator last)
        {
            return iterator(tree_.erase_range(first.node(), last.node()));
        }

        void clear() MSVC8_SET_NOEXCEPT { tree_.clear(); }
        void swap(multiset& other) MSVC8_SET_NOEXCEPT { tree_.swap(other.tree_); }

    private:
        tree_type tree_;
    };

    // Size check (x86)
    static_assert(sizeof(set<int>) == 12, "msvc8::set must be 12 bytes on x86");
    static_assert(sizeof(multiset<int>) == 12, "msvc8::multiset must be 12 bytes on x86");

} // namespace msvc8

#pragma pack(pop)
