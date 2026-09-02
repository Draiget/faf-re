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

        [[nodiscard]] iterator lower_bound(const key_type& k) const { return iterator(tree_.lower_bound_node(k)); }
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

        std::pair<iterator, bool> insert(const value_type& v)
        {
            const std::pair<typename tree_type::node_type*, bool> result = tree_.insert_unique(v);
            return {iterator(result.first), result.second};
        }

        std::pair<iterator, bool> insert(value_type&& v) { return emplace(std::move(v)); }

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
         */
        iterator erase(iterator first, iterator last)
        {
            return iterator(tree_.erase_range(first.node(), last.node()));
        }

        void swap(set& other) MSVC8_SET_NOEXCEPT { tree_.swap(other.tree_); }

    private:
        tree_type tree_;
    };

    // Size check (x86)
    static_assert(sizeof(set<int>) == 12, "msvc8::set must be 12 bytes on x86");

} // namespace msvc8

#pragma pack(pop)
