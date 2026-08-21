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
         */
        iterator erase(const_iterator pos) { return iterator(tree_.erase_node(pos.node())); }

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
