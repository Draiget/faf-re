#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

/**
 * \file RbTree.h
 * \brief Shared owning red-black tree used by `msvc8::set` and `msvc8::map`.
 *
 * The MSVC8 (VS2005) Dinkumware `std::_Tree` is the single associative-container
 * engine behind `std::set`, `std::multiset`, `std::map` and `std::multimap`. The
 * shipped engine binary contains many per-instantiation emissions of it; every
 * one of them shares this layout:
 *
 *   container (12 bytes, x86)
 *     +0x00 `_Container_proxy*` allocator/debug proxy word
 *     +0x04 `_Node*`            header sentinel ("nil") node
 *     +0x08 `size_type`         element count
 *   node
 *     +0x00 `_Node*` _Left
 *     +0x04 `_Node*` _Parent
 *     +0x08 `_Node*` _Right
 *     +0x0C `value_type` _Myval
 *     +0x0C+sizeof(value_type)     `char` _Color  (0 = red, 1 = black)
 *     +0x0D+sizeof(value_type)     `char` _Isnil  (1 only for the header)
 *
 * Both are confirmed against the binary:
 *   - the `std::map<gpg::RType*,int>` iterator steps at 0x0094F030/0x0094F090
 *     read `_Left` at +0x00, `_Parent` at +0x04, `_Right` at +0x08 and `_Isnil`
 *     at +0x15 (value_type = 8 bytes);
 *   - `Moho::CCommandDB`'s command-map node is `{l,p,r,key@0x0C,value@0x10,
 *     color@0x14,isnil@0x15}` (see `CommandDbMapNodeRuntime` in CCommandDb.cpp);
 *   - `std::map<Moho::MeshBatchKey, std::vector<Moho::MeshInstance*>>` nodes are
 *     0x30 bytes with `_Color` at +0x2C and `_Isnil` at +0x2D (value_type 0x20).
 *
 * The comparator is empty-base-optimised, matching the binary's 12-byte
 * container footprint: MSVC8 carries the predicate in an empty base of
 * `_Tree_nod`, so a stateless `std::less` or engine predicate costs nothing.
 *
 * Nil handling follows the binary exactly: leaf links point at the header and
 * are recognised through the `_Isnil` byte, never through a pointer comparison
 * against a separately carried header pointer. That is what makes the shipped
 * iterators a single pointer wide.
 */

#ifndef MSVC8_RBTREE_DISABLE_FREE
#define MSVC8_RBTREE_DISABLE_FREE 0
#endif

#pragma pack(push, 4)

namespace msvc8
{
#ifndef MSVC8_CONTAINER_PROXY_DEFINED
#define MSVC8_CONTAINER_PROXY_DEFINED 1
    struct _Container_proxy
    {
        void* _Myfirstiter;
    };
#endif

    namespace detail
    {
        /** Red-black node colours, matching the MSVC8 `_Redbl` encoding. */
        inline constexpr std::uint8_t kRbRed = 0;
        inline constexpr std::uint8_t kRbBlack = 1;

        /**
         * One MSVC8 `_Tree::_Node`.
         *
         * Field order is load bearing: the value payload sits between the link
         * triplet and the colour/nil bytes, which is why node size grows with
         * `sizeof(V)` and the colour byte's address is instantiation dependent.
         */
        template<class V>
        struct rb_node
        {
            rb_node* left;       // +0x00
            rb_node* parent;     // +0x04
            rb_node* right;      // +0x08
            V value;             // +0x0C
            std::uint8_t color;  // +0x0C + sizeof(V)
            std::uint8_t isNil;  // +0x0D + sizeof(V)
        };

        /** True for the header sentinel (and hence for every "null" child link). */
        template<class V>
        [[nodiscard]] constexpr bool rb_is_nil(const rb_node<V>* const n) noexcept
        {
            return n->isNil != 0;
        }

        /**
         * Address: 0x00899F60 (FUN_00899F60, `_Min`)
         *
         * Emitted for the session save-node map - the `map<uint32, string>`
         * whose nodes carry `_Isnil` at +0x2D. The index reports 20 ICF twins:
         * `_Min` is a two-instruction walk whose body is identical for every
         * instantiation that shares this sentinel offset, so the linker folded
         * them onto this one address.
         *
         * IDA signature:
         * _DWORD *__usercall sub_899F60@<eax>(_DWORD *result@<eax>);
         *
         * What it does:
         * Leftmost (smallest) node of the subtree rooted at `n`.
         *
         * The shipped body peels the first `_Left` load before the loop
         * (`mov ecx,[eax]` / `cmp byte ptr [ecx+2Dh],0`), which is the same walk
         * this expresses as a plain while loop. Reached from `erase(const_iterator)`
         * at 0x0089A540 when the erased node was the leftmost one.
         */
        template<class V>
        [[nodiscard]] rb_node<V>* rb_min(rb_node<V>* n) noexcept
        {
            while (!rb_is_nil(n->left)) {
                n = n->left;
            }
            return n;
        }

        /**
         * Address: 0x0089ABB0 (FUN_0089ABB0, `_Max`)
         *
         * Emitted for the session save-node map, and likewise folded across 20
         * ICF twins.
         *
         * IDA signature:
         * int __usercall sub_89ABB0@<eax>(int result@<eax>);
         *
         * What it does:
         * Rightmost (largest) node of the subtree rooted at `n`.
         *
         * Mirror of `rb_min`, stepping `_Right` at +0x08. Reached from
         * `erase(const_iterator)` at 0x0089A540 when the erased node was the
         * rightmost one.
         */
        template<class V>
        [[nodiscard]] rb_node<V>* rb_max(rb_node<V>* n) noexcept
        {
            while (!rb_is_nil(n->right)) {
                n = n->right;
            }
            return n;
        }

        /**
         * Address: 0x0094F090 (FUN_0094F090, std::map<gpg::RType*,int>::iterator _Inc)
         * Address: 0x007E42F0 (FUN_007E42F0, `_Inc` for the mesh batch-bucket map)
         * Address: 0x007B4D90 (FUN_007B4D90, `_Inc` for the
         * `map<EntId, WeakPtr<UserEntity>>`-shaped weak-entity-set node walk --
         * reached from `Moho::UICommandGraph`'s edge-travel-time and
         * draw-node-work-time estimators (CWldSession.cpp) when they iterate a
         * command's targeted `WeakSet<UserEntity>`/`SSelectionSetUserEntity`)
         *
         * IDA signature:
         * _Node *__thiscall operator(_Node **this);
         *
         * What it does:
         * Steps one tree iterator to its in-order successor. With a real right
         * subtree the successor is that subtree's leftmost node; otherwise it is
         * the nearest ancestor whose left subtree contains the node. Landing on
         * the header ends iteration; starting on the header is a no-op.
         *
         * The annotated IDB labels 0x0094F090 `operator--`, but the body is the
         * increment - see `rb_decrement` for the disassembly evidence.
         */
        template<class V>
        /**
         * Address: 0x0049AD20 (FUN_0049AD20, the in-order successor walk for the
         * trail-segment owner pool, `std::set<TrailSegmentBufferRuntime*>`)
         */
        rb_node<V>* rb_increment(rb_node<V>* n) noexcept
        {
            if (rb_is_nil(n)) {
                return n; // ++end() is a no-op in MSVC8, as in the binary
            }

            if (!rb_is_nil(n->right)) {
                return rb_min(n->right);
            }

            rb_node<V>* ancestor = n->parent;
            while (!rb_is_nil(ancestor) && n == ancestor->right) {
                n = ancestor;
                ancestor = ancestor->parent;
            }
            return ancestor;
        }

        /**
         * Address: 0x0094F030 (FUN_0094F030, std::map<gpg::RType*,int>::iterator _Dec)
         * Address: 0x009488D0 (FUN_009488D0, byte-identical sibling `_Dec` emission)
         * Address: 0x00948930 (FUN_00948930, byte-identical sibling `_Dec` emission)
         * Address: 0x007E4FA0 (FUN_007E4FA0, `_Dec` for the mesh batch-bucket map)
         *
         * IDA signature:
         * _Node *__thiscall operator(_Node **this);
         *
         * What it does:
         * Steps one tree iterator to its in-order predecessor. From the header
         * this yields the rightmost element (`--end()`); with a real left subtree
         * it yields that subtree's rightmost node; otherwise the nearest ancestor
         * whose right subtree contains the node.
         *
         * Evidence for the `_Inc`/`_Dec` name swap in the IDB: 0x0094F030 opens
         * with `cmp byte ptr [eax+15h],0 / jz` then `mov eax,[eax+8]`, i.e. on the
         * nil node it moves to `_Right` (rightmost) - only `_Dec` does that - and
         * it closes with the `if (!_Isnil(_Ptr)) _Ptr = _Pnode;` guard that exists
         * only in MSVC8's `_Dec`. 0x0094F090 has neither.
         */
        template<class V>
        rb_node<V>* rb_decrement(rb_node<V>* n) noexcept
        {
            if (rb_is_nil(n)) {
                return n->right; // --end() -> rightmost
            }

            if (!rb_is_nil(n->left)) {
                return rb_max(n->left);
            }

            rb_node<V>* ancestor = n->parent;
            while (!rb_is_nil(ancestor) && n == ancestor->left) {
                n = ancestor;
                ancestor = ancestor->parent;
            }
            // MSVC8 keeps the walked-to node when the walk fell off the front.
            return rb_is_nil(n) ? n : ancestor;
        }

        /**
         * Empty-base carrier for the key comparator.
         *
         * MSVC8 stores the predicate in an empty base of `_Tree_nod`, so a
         * stateless comparator adds nothing to the 12-byte container footprint.
         */
        template<class Compare, bool = std::is_empty_v<Compare> && !std::is_final_v<Compare>>
        class rb_compare_carrier;

        template<class Compare>
        // Public inheritance, deliberately: the empty-base optimisation that keeps
        // the tree at 12 bytes works either way, but a private base makes the
        // derived-to-base conversion in comp() inaccessible whenever Compare is a
        // private nested type of the owning class (e.g.
        // CD3DTextureBatcher::TextureAtlasEntryLess).
        class rb_compare_carrier<Compare, true> : public Compare
        {
        public:
            rb_compare_carrier() = default;
            explicit rb_compare_carrier(const Compare& c) : Compare(c) {}

            [[nodiscard]] const Compare& comp() const noexcept { return *this; }
            [[nodiscard]] Compare& comp() noexcept { return *this; }
        };

        template<class Compare>
        class rb_compare_carrier<Compare, false>
        {
        public:
            rb_compare_carrier() = default;
            explicit rb_compare_carrier(const Compare& c) : comp_(c) {}

            [[nodiscard]] const Compare& comp() const noexcept { return comp_; }
            [[nodiscard]] Compare& comp() noexcept { return comp_; }

        private:
            Compare comp_{};
        };

        /**
         * Bidirectional iterator over an MSVC8 tree.
         *
         * One pointer wide, exactly like the shipped iterator: the binary's
         * step routines take `_Node**` as `this` and never consult a container
         * back-pointer.
         */
        template<class Traits, bool IsConst>
        class rb_iterator
        {
        public:
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = typename Traits::value_type;
            using difference_type = std::ptrdiff_t;
            using node_type = rb_node<value_type>;
            using reference = std::conditional_t<IsConst, const value_type&, value_type&>;
            using pointer = std::conditional_t<IsConst, const value_type*, value_type*>;

            rb_iterator() noexcept = default;
            explicit rb_iterator(node_type* const n) noexcept : node_(n) {}

            /** Implicit non-const to const conversion, as in the standard containers. */
            template<bool OtherConst, class = std::enable_if_t<IsConst && !OtherConst>>
            rb_iterator(const rb_iterator<Traits, OtherConst>& other) noexcept : node_(other.node())
            {
            }

            [[nodiscard]] reference operator*() const noexcept
            {
                assert(node_ != nullptr && !rb_is_nil(node_) && "msvc8 tree iterator: dereferencing end()");
                return node_->value;
            }
            [[nodiscard]] pointer operator->() const noexcept { return std::addressof(**this); }

            rb_iterator& operator++() noexcept
            {
                node_ = rb_increment(node_);
                return *this;
            }
            rb_iterator operator++(int) noexcept
            {
                const rb_iterator copy = *this;
                ++*this;
                return copy;
            }

            rb_iterator& operator--() noexcept
            {
                node_ = rb_decrement(node_);
                return *this;
            }
            rb_iterator operator--(int) noexcept
            {
                const rb_iterator copy = *this;
                --*this;
                return copy;
            }

            [[nodiscard]] node_type* node() const noexcept { return node_; }

            template<bool OtherConst>
            [[nodiscard]] bool operator==(const rb_iterator<Traits, OtherConst>& other) const noexcept
            {
                return node_ == other.node();
            }
            template<bool OtherConst>
            [[nodiscard]] bool operator!=(const rb_iterator<Traits, OtherConst>& other) const noexcept
            {
                return node_ != other.node();
            }

        private:
            node_type* node_ = nullptr;
        };

        /** `msvc8::set` traits: the key is the stored value. */
        template<class Key, class Less>
        struct rb_set_traits
        {
            using key_type = Key;
            using value_type = Key;
            using key_compare = Less;

            [[nodiscard]] static const key_type& key_of(const value_type& v) noexcept { return v; }
        };

        /** `msvc8::map` traits: the key is `value_type::first`. */
        template<class Key, class T, class Less>
        struct rb_map_traits
        {
            using key_type = Key;
            using mapped_type = T;
            using value_type = std::pair<const Key, T>;
            using key_compare = Less;

            [[nodiscard]] static const key_type& key_of(const value_type& v) noexcept { return v.first; }
        };

        /**
         * Owning red-black tree - the single implementation shared by
         * `msvc8::set` and `msvc8::map`.
         *
         * Layout (x86): `{_Container_proxy*, _Node*, size_type}` = 12 bytes, with
         * the comparator empty-base-optimised away.
         */
        template<class Traits>
        class rb_tree : private rb_compare_carrier<typename Traits::key_compare>
        {
            using carrier = rb_compare_carrier<typename Traits::key_compare>;

        public:
            using key_type = typename Traits::key_type;
            using value_type = typename Traits::value_type;
            using key_compare = typename Traits::key_compare;
            using size_type = std::uint32_t;
            using difference_type = std::ptrdiff_t;
            using node_type = rb_node<value_type>;
            using iterator = rb_iterator<Traits, false>;
            using const_iterator = rb_iterator<Traits, true>;

            // ---- lifetime ----------------------------------------------------

            /**
             * Address: 0x007E2C30 (FUN_007E2C30, batch-bucket map `_Tree::_Init`)
             *
             * What it does:
             * Buys the header sentinel, marks it nil, self-links its three
             * pointers and zeroes the size.
             *
             * The shipped body is exactly this ctor with `buy_head` split out:
             * `call sub_7E4B80` (the head-node allocator) then
             * `mov [esi+4], eax` / `mov byte ptr [eax+2Dh], 1` (`_Isnil`) /
             * `[eax+4] = eax` / `[eax] = eax` / `[eax+8] = eax` /
             * `mov dword ptr [esi+8], 0`.
             */
            rb_tree() : proxy_(nullptr), head_(buy_head()), size_(0) {}

            explicit rb_tree(const key_compare& comp) : carrier(comp), proxy_(nullptr), head_(buy_head()), size_(0) {}

            /**
             * MSVC8 `_Tree::_Tree(const _Myt&)`: stands a fresh head sentinel up
             * and then runs `_Copy` over `other`. Observed for
             * `msvc8::set<msvc8::string>` at 0x008C5B10, whose `_Copy` walk is
             * FUN_008C5D50.
             *
             * `_Copy` clones the source's tree shape node for node; inserting the
             * source in ascending order lands the same ordered contents through
             * the rebalancing path already used by every other insert, so no
             * second tree-building mechanic is introduced here.
             */
            /**
             * Address: 0x0070E320 (FUN_0070E320, the blueprint-stat map's copy
             * constructor)
             * Address: 0x0070F810 (FUN_0070F810, the copy driver it calls: clones the
             * subtree, carries the size across and re-seats the extrema. All four of its
             * binary callers -- 0x0070C160, 0x0070CC10, 0x0070E320, 0x0070E3A0 -- are
             * blueprint-stat-map sites.)
             * Address: 0x00710990 (FUN_00710990, the recursive subtree clone underneath
             * it)
             */
            rb_tree(const rb_tree& other)
                : carrier(static_cast<const carrier&>(other)), proxy_(nullptr), head_(buy_head()), size_(0)
            {
                copy_from(other);
            }

            rb_tree& operator=(const rb_tree& other)
            {
                if (this != &other) {
                    clear();
                    static_cast<carrier&>(*this) = static_cast<const carrier&>(other);
                    copy_from(other);
                }
                return *this;
            }

            rb_tree(rb_tree&& other) noexcept
                : carrier(static_cast<carrier&&>(other)), proxy_(nullptr), head_(nullptr), size_(0)
            {
                adopt_from(other);
            }

            rb_tree& operator=(rb_tree&& other) noexcept
            {
                if (this != &other) {
                    clear();
                    free_raw(head_);
                    static_cast<carrier&>(*this) = static_cast<carrier&&>(other);
                    adopt_from(other);
                }
                return *this;
            }

            /**
             * Address: 0x007E2B20 (FUN_007E2B20, batch-bucket map `_Tree::_Tidy`)
             *
             * What it does:
             * Erases every element, releases the header sentinel and clears the
             * header/size lanes.
             *
             * Matches the shipped body: `erase(begin, end)` through
             * `call sub_7E3B70` with `head->left` and `head` pushed as the
             * range, then `operator delete(head)` and
             * `[edi+4] = 0` / `[edi+8] = 0`.
             *
             * `erase_range(leftmost(), header())` below *is* that call - the two
             * pushed operands are `head->left` (`begin()`) and `head` (`end()`),
             * so the range always takes the member's whole-tree fast path. Calling
             * `clear()` here instead would collapse to the same stores but would
             * stop the range member from being emitted at all.
             */
            ~rb_tree()
            {
                erase_range(leftmost(), header());
                free_raw(head_);
                head_ = nullptr;
                size_ = 0;
            }

            // ---- observers ---------------------------------------------------

            [[nodiscard]] const key_compare& key_comp() const noexcept { return this->comp(); }

            /**
             * Address: 0x0052BB20 (FUN_0052BB20)  Address: 0x0052BC50 (FUN_0052BC50)
             * Address: 0x0052BFA0 (FUN_0052BFA0)  Address: 0x0052C080 (FUN_0052C080)
             * Address: 0x0052C160 (FUN_0052C160)  Address: 0x0052C330 (FUN_0052C330)
             * Address: 0x0052C410 (FUN_0052C410)  Address: 0x0052C4F0 (FUN_0052C4F0)
             *
             * The `end()` lane -- the sentinel head itself.
             */
            /**
             * Address: 0x00498060 (FUN_00498060, the trail-segment pool's maximum;
             * emitted again at 0x0087CC20)
             */
            [[nodiscard]] node_type* header() const noexcept { return head_; }
            [[nodiscard]] node_type* root() const noexcept { return head_->parent; }
            /**
             * Address: 0x0052BB00 (FUN_0052BB00)  Address: 0x0052BB10 (FUN_0052BB10)
             * Address: 0x0052BC40 (FUN_0052BC40)  Address: 0x0052BF90 (FUN_0052BF90)
             * Address: 0x0052C240 (FUN_0052C240)  Address: 0x0052C320 (FUN_0052C320)
             * Address: 0x0052C400 (FUN_0052C400)  Address: 0x0052C4E0 (FUN_0052C4E0)
             * Address: 0x0052E140 (FUN_0052E140)  Address: 0x0052E320 (FUN_0052E320)
             * Address: 0x0052E500 (FUN_0052E500)
             *
             * The `head->left` begin lane, emitted once per blueprint table.
             *
             * All belong to the seven `std::map<std::string, TBlueprint*>` tables on `RRuleGameRulesImpl` (+0x60 through +0xA8). One emission per table is why the same member carries six or seven addresses.
             */
            /**
             * Address: 0x00498080 (FUN_00498080, the trail-segment pool's minimum;
             * emitted again at 0x0087CC40)
             */
            [[nodiscard]] node_type* leftmost() const noexcept { return head_->left; }
            [[nodiscard]] node_type* rightmost() const noexcept { return head_->right; }

            [[nodiscard]] size_type size() const noexcept { return size_; }
            [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

            /**
             * MSVC8's `allocator<value_type>::max_size()`.
             *
             * The `_Insert` guard in the binary tests `_Mysize >= max_size() - 1`;
             * 0x007E3F10 compares against 0x07FFFFFE for a 0x20-byte value type,
             * i.e. 0xFFFFFFFF/0x20 - 1.
             */
            [[nodiscard]] static constexpr size_type max_size() noexcept
            {
                constexpr std::uint32_t count = 0xFFFFFFFFu / sizeof(value_type);
                return count != 0u ? count : 1u;
            }

            // ---- lookup ------------------------------------------------------

            /**
             * Address: 0x007E40C0 (FUN_007E40C0, batch-bucket map `_Lbound`)
             *
             * What it does:
             * Returns the first node whose key does not order before `k`, or the
             * header when every stored key orders before it.
             */
            /**
             * Address: 0x0052D150 (FUN_0052D150)  Address: 0x0052D1F0 (FUN_0052D1F0)
             * Address: 0x0052D280 (FUN_0052D280)  Address: 0x0052D310 (FUN_0052D310)
             * Address: 0x0052D3A0 (FUN_0052D3A0)  Address: 0x0052D440 (FUN_0052D440)
             * Address: 0x0052D4E0 (FUN_0052D4E0)
             * Address: 0x0052E060 (FUN_0052E060)  Address: 0x0052E240 (FUN_0052E240)
             * Address: 0x0052E420 (FUN_0052E420)  Address: 0x0052E600 (FUN_0052E600)
             * Address: 0x0052E7D0 (FUN_0052E7D0)  Address: 0x0052EB70 (FUN_0052EB70)
             *
             * The blueprint-id descent. The 0x0052Exxx six are the walk itself, one
             * per table; the 0x0052Dxxx seven are the store-result adapters over it.
             */
            [[nodiscard]] node_type* lower_bound_node(const key_type& k) const
            {
                node_type* found = head_;
                for (node_type* n = root(); !rb_is_nil(n);) {
                    if (this->comp()(Traits::key_of(n->value), k)) {
                        n = n->right;
                    } else {
                        found = n;
                        n = n->left;
                    }
                }
                return found;
            }

            /** First node whose key orders after `k`, or the header. */
            [[nodiscard]] node_type* upper_bound_node(const key_type& k) const
            {
                node_type* found = head_;
                for (node_type* n = root(); !rb_is_nil(n);) {
                    if (this->comp()(k, Traits::key_of(n->value))) {
                        found = n;
                        n = n->left;
                    } else {
                        n = n->right;
                    }
                }
                return found;
            }

            /** Node holding `k`, or the header when absent. */
            /**
             * Address: 0x00594BD0 (FUN_00594BD0, the by-name lookup for
             * `CArmyStats::mNameIndex`; the `[this+0x14]` it opens with is that member's
             * offset in CArmyStats, not a node field)
             * Address: 0x00595130 (FUN_00595130, the same descent emitted a second time)
             */
            /**
             * Address: 0x0052C420 (FUN_0052C420, already labelled
             * `std::map_string_RBeamBlueprint::operator[]` -- the lower-bound-then-verify
             * form `find` compiles to)
             * Address: 0x0052C260 (FUN_0052C260)  Address: 0x0052C340 (FUN_0052C340)
             * Address: 0x0052C500 (FUN_0052C500)
             *
             * The mesh, emitter and trail lookups respectively.
             */
            [[nodiscard]] node_type* find_node(const key_type& k) const
            {
                node_type* const found = lower_bound_node(k);
                if (rb_is_nil(found) || this->comp()(k, Traits::key_of(found->value))) {
                    return head_;
                }
                return found;
            }

            // ---- modifiers ---------------------------------------------------

            /**
             * Address: 0x007E3CF0 (FUN_007E3CF0, batch-bucket map insert(const value_type&))
             *
             * IDA signature:
             * _Pairib *__userpurge insert@<eax>(_Tree *this@<ebx>, const value_type *val@<esi>, _Pairib *result);
             *
             * What it does:
             * Descends to the insertion parent recording the last branch taken,
             * then confirms uniqueness by comparing against the in-order
             * predecessor of the descent result before linking a fresh node.
             * Returns the existing node with `false` when the key is present.
             */
            /**
             * Address: 0x00594E70 (FUN_00594E70, the name-index map's insert-or-assign,
             * which is what `mNameIndex[key] = item` compiles to at its four call sites in
             * CArmyStats)
             * Address: 0x00594C90 (FUN_00594C90, its descent half)
             */
            /**
             * Address: 0x00496000 (FUN_00496000, the trail-segment pool's find-or-insert
             * -- what `ReturnTrailSegmentBufferToOwnerPool` compiles to)
             * Address: 0x00497E50 (FUN_00497E50, its link half)
             */
            std::pair<node_type*, bool> insert_unique(const value_type& v)
            {
                node_type* where = head_;
                bool addLeft = true;
                for (node_type* n = root(); !rb_is_nil(n);) {
                    where = n;
                    addLeft = this->comp()(Traits::key_of(v), Traits::key_of(n->value));
                    n = addLeft ? n->left : n->right;
                }

                node_type* probe = where;
                if (addLeft) {
                    if (where == leftmost()) {
                        return {insert_at(true, where, v), true};
                    }
                    probe = rb_decrement(where);
                }

                if (this->comp()(Traits::key_of(probe->value), Traits::key_of(v))) {
                    return {insert_at(addLeft, where, v), true};
                }
                return {probe, false};
            }

            /**
             * Address: 0x007E3340 (FUN_007E3340, batch-bucket map insert(const_iterator, const value_type&))
             *
             * IDA signature:
             * iterator *__userpurge insert@<eax>(_Tree *this@<ecx>, const value_type *val@<eax>,
             *                                    iterator *result, _Nodeptr hint);
             * (`retn 8` - the two stack dwords are the sret iterator and the hint
             * node; the tree arrives in `ecx` and the value in `eax`.)
             *
             * Hinted unique insert (MSVC8 `_Tree::insert(const_iterator, const value_type&)`).
             *
             * `map::operator[]` passes its `lower_bound` result as the hint, so the
             * common "fill the gap we just located" case links without a second
             * descent; a useless hint falls back to the plain unique insert.
             *
             * The shipped body matches this one branch for branch:
             *   0x007E334D  `cmp [tree+8], 0`                  -> empty tree, link at the header
             *   0x007E3374  `cmp hint, [head]`                 -> hint == leftmost
             *   0x007E33A3  `cmp hint, head`                    -> hint == end(), compare against rightmost
             *   0x007E33F3  `_Dec` then `cmp [before->right].isNil` at 0x007E3411
             *   0x007E344E  `_Inc` then `cmp [at->right].isNil` at 0x007E3477
             *   0x007E34B1  fall back to `insert_unique` and take `.first`
             * Every accepted branch tail calls `_Insert` (0x007E3F10 = `insert_at`)
             * with the `addLeft` flag this function decided.
             */
            /**
             * Address: 0x0070F6C0 (FUN_0070F6C0, the
             * `std::map<const RBlueprint*, float>` instantiation behind
             * `CArmyStatItem::mBlueprintStats`. It is the classic three-way hint check --
             * empty tree, hint == begin, hint == end -- each falling through to the
             * general insert at 0x00710A40, and it is reached from `operator[]`
             * (0x0070E2B0), which is where VC8 puts its only hinted-insert call.)
             */
            node_type* insert_hint(const_iterator hint, const value_type& v)
            {
                if (size_ == 0) {
                    return insert_at(true, head_, v);
                }

                node_type* const at = hint.node();
                if (at == leftmost()) {
                    if (this->comp()(Traits::key_of(v), Traits::key_of(at->value))) {
                        return insert_at(true, at, v);
                    }
                } else if (rb_is_nil(at)) {
                    if (this->comp()(Traits::key_of(rightmost()->value), Traits::key_of(v))) {
                        return insert_at(false, rightmost(), v);
                    }
                } else if (this->comp()(Traits::key_of(v), Traits::key_of(at->value))) {
                    node_type* const before = rb_decrement(at);
                    if (this->comp()(Traits::key_of(before->value), Traits::key_of(v))) {
                        return rb_is_nil(before->right) ? insert_at(false, before, v) : insert_at(true, at, v);
                    }
                } else if (this->comp()(Traits::key_of(at->value), Traits::key_of(v))) {
                    node_type* const after = rb_increment(at);
                    if (rb_is_nil(after) || this->comp()(Traits::key_of(v), Traits::key_of(after->value))) {
                        return rb_is_nil(at->right) ? insert_at(false, at, v) : insert_at(true, after, v);
                    }
                }

                return insert_unique(v).first;
            }

            /**
             * Unique emplace.
             *
             * The value is materialised once into a fresh node before the descent
             * (its key is only reachable through the constructed value) and the
             * node is released again when the key turns out to be present. That
             * ordering is what keeps a forwarded rvalue from being consumed twice.
             */
            template<class... Args>
            std::pair<node_type*, bool> emplace_unique(Args&&... args)
            {
                node_type* const fresh = buy_node(std::forward<Args>(args)...);
                const key_type& k = Traits::key_of(fresh->value);

                node_type* where = head_;
                bool addLeft = true;
                for (node_type* n = root(); !rb_is_nil(n);) {
                    where = n;
                    addLeft = this->comp()(k, Traits::key_of(n->value));
                    n = addLeft ? n->left : n->right;
                }

                const bool linkAtFront = addLeft && where == leftmost();
                if (!linkAtFront) {
                    node_type* const probe = addLeft ? rb_decrement(where) : where;
                    if (!this->comp()(Traits::key_of(probe->value), k)) {
                        free_node(fresh);
                        return {probe, false};
                    }
                }

                if (max_size() - 1u <= size_) {
                    free_node(fresh);
                    throw_too_long();
                }
                link_and_rebalance(addLeft, where, fresh);
                return {fresh, true};
            }

            /**
             * Address: 0x0089A540 (FUN_0089A540, `erase(const_iterator)`)
             * Address: 0x007E4430 (FUN_007E4430, sibling emission)
             *
             * 0x0089A540 is the session save-node map `map<uint32, string>`
             * (`_Isnil` at +0x2D); 0x007E4430 is the same member for the
             * mesh-key map (`_Isnil` at +0x25).
             *
             * IDA signature:
             * int *__stdcall sub_89A540(int this, int *result, int where);
             *
             * What it does:
             * Unlinks and destroys `erased`, returning its in-order successor.
             *
             * This is MSVC8's `_Tree::erase(const_iterator)` transplant plus
             * recolour pass: the successor is lifted into the erased node's slot
             * when both subtrees exist, then the black-height deficit is repaired
             * from the stitched-up child upwards.
             *
             * Both emissions open with the same `_Isnil` guard that throws
             * `out_of_range("invalid map/set<T> iterator")` - the string is built
             * in place, handed to `std::logic_error::logic_error`, and the vftable
             * is then patched to `std::out_of_range` before `_CxxThrowException`.
             * They close with `if (0 < _Mysize) --_Mysize;`, i.e. the shipped
             * decrement is guarded rather than unconditional.
             */
            /**
             * Address: 0x00592920 (FUN_00592920, the blueprint-stat map's
             * erase-with-rebalance; identified by the colour/nil pair it rewrites at
             * `[node+0x14]` / `[node+0x15]`, which pins it to that map's 0x18 node
             * rather than the 0x30 name-index node in the same file.)
             */
            /**
             * Address: 0x00703700 (FUN_00703700, the name-index map's erase with
             * rebalance -- the densest colour/nil traffic in the family, rewriting
             * `[node+0x2C]`/`[node+0x2D]` across every rebalance branch)
             * Address: 0x006FD7C0 (FUN_006FD7C0, the erase-and-advance wrapper that
             * `CArmyStats::Delete`'s erase-while-iterating loop drives)
             * Address: 0x00704A40 (FUN_00704A40, the same lane reached from
             * `~CArmyStats`)
             */
            /**
             * Address: 0x00A633D0 (FUN_00A633D0, unidentified map/set instantiation
             * -- colour/nil pair at `[node+0x10]`/`[node+0x11]`, a smaller node than
             * every other instantiation cited above)
             * Address: 0x00A63690 (FUN_00A63690, sibling emission of the same
             * member for a second, differently-value-typed instantiation in the
             * same address neighbourhood as the `rotate_left`/`insert_at`
             * instantiation cited above -- same colour/nil offsets, same
             * `invalid map/set<T> iterator` throw and guarded `_Mysize` decrement)
             *
             * Neither traced to a named owning class in this pass; the algorithm
             * match (transplant-and-recolour shape, identical throw string,
             * identical guarded decrement) is the evidence.
             */
            node_type* erase_node(node_type* const erased)
            {
                assert(erased != nullptr && "msvc8 tree: erasing a null node");
                if (rb_is_nil(erased)) {
                    throw std::out_of_range("invalid map/set<T> iterator");
                }

                node_type* const next = rb_increment(erased);

                node_type* lifted = erased;
                node_type* fix = nullptr;
                node_type* fixParent = nullptr;

                if (rb_is_nil(erased->left)) {
                    fix = erased->right;
                } else if (rb_is_nil(erased->right)) {
                    fix = erased->left;
                } else {
                    lifted = next; // in-order successor of a two-child node
                    fix = lifted->right;
                }

                if (lifted == erased) {
                    // At most one subtree: relink it in place.
                    fixParent = erased->parent;
                    if (!rb_is_nil(fix)) {
                        fix->parent = fixParent;
                    }

                    if (root() == erased) {
                        head_->parent = fix;
                    } else if (fixParent->left == erased) {
                        fixParent->left = fix;
                    } else {
                        fixParent->right = fix;
                    }

                    if (leftmost() == erased) {
                        head_->left = rb_is_nil(fix) ? fixParent : rb_min(fix);
                    }
                    if (rightmost() == erased) {
                        head_->right = rb_is_nil(fix) ? fixParent : rb_max(fix);
                    }
                } else {
                    // Two subtrees: `lifted` (the successor) takes the erased slot.
                    erased->left->parent = lifted;
                    lifted->left = erased->left;

                    if (lifted == erased->right) {
                        fixParent = lifted;
                    } else {
                        fixParent = lifted->parent;
                        if (!rb_is_nil(fix)) {
                            fix->parent = fixParent;
                        }
                        fixParent->left = fix;
                        lifted->right = erased->right;
                        erased->right->parent = lifted;
                    }

                    if (root() == erased) {
                        head_->parent = lifted;
                    } else if (erased->parent->left == erased) {
                        erased->parent->left = lifted;
                    } else {
                        erased->parent->right = lifted;
                    }

                    lifted->parent = erased->parent;
                    std::swap(lifted->color, erased->color);
                }

                if (erased->color == kRbBlack) {
                    erase_rebalance(fix, fixParent);
                }

                free_node(erased);
                if (size_ > 0) {
                    --size_;
                }
                return next;
            }

            /**
             * Address: 0x00899CA0 (FUN_00899CA0, `erase(iterator, iterator)`)
             * Address: 0x007E3B70 (FUN_007E3B70, sibling emission)
             *
             * 0x00899CA0 is the session save-node map `map<uint32, string>`
             * (`_Isnil` at +0x2D), reached from
             * `Moho::SSessionSaveDataTypeInfo::Destruct` at 0x0089A450 and eight
             * other call sites; 0x007E3B70 is the mesh-key map (`_Isnil` at
             * +0x25), reached from that map's `_Tidy` at 0x007E2B20 - the body
             * this class's destructor is annotated with.
             *
             * IDA signature:
             * _DWORD *__userpurge sub_899CA0@<eax>(int this@<edi>, _DWORD *result,
             *                                      _DWORD *first, _DWORD *last);
             *
             * What it does:
             * Erases the half-open node range `[first, last)` and returns a cursor
             * on the first surviving node.
             *
             * MSVC8 splits this in two. When the range is the whole tree it runs
             * `clear()` inline and answers `begin()`; the shipped bodies show that
             * inlining directly - `cmp first,[head]` / `cmp last,head`, then the
             * recursive `_Erase` call (`sub_89A820` / `sub_7E4DD0`) followed by
             * `head->parent = head`, `_Mysize = 0`, `head->left = head`,
             * `head->right = head` and a load of `head->left` into the return slot.
             *
             * Otherwise it walks one node at a time as `erase(_First++)`: the
             * post-increment's `_Inc` is inlined ahead of the call (the `+0x2D`
             * / `+0x25` sentinel probes at 0x00899CF5 and 0x007E3B95), the *old*
             * cursor is passed to `erase(const_iterator)` and that call's returned
             * iterator is discarded. Recovering it as `first = erase(first)` would
             * drop the second `_Inc` the shipped code performs.
             */
            node_type* erase_range(node_type* const first, node_type* const last)
            {
                if (first == leftmost() && last == header()) {
                    clear();
                    return leftmost();
                }

                iterator cursor(first);
                const iterator stop(last);
                while (cursor != stop) {
                    // `erase(_First++)`: advance first, then erase the old cursor.
                    (void)erase_node((cursor++).node());
                }
                return cursor.node();
            }

            /**
             * Address: 0x007E2D90 (FUN_007E2D90, batch-bucket map `_Tree::clear`)
             *
             * What it does:
             * Destroys every element and restores the empty header links.
             *
             * The shipped body reads the root as `[[esi+4]+4]`, hands it to the
             * recursive `_Erase` walk (`call sub_7E34E0`) and then relinks
             * `head->parent = head` / `head->left = head` / `head->right = head`
             * with `[esi+8] = 0`. It returns nothing.
             */
            /**
             * Address: 0x00592230 (FUN_00592230, the blueprint-stat map's range erase.
             * `CArmyStatItem::~CArmyStatItem` reaches it at 0x00585C39, which is what
             * `clear()` compiles to.)
             * Address: 0x00585BD0 (FUN_00585BD0, the typed teardown wrapper around it)
             */
            /**
             * Address: 0x00704000 (FUN_00704000, the name-index map's teardown)
             * Address: 0x0070DDC0 (FUN_0070DDC0, its typed wrapper)
             */
            /**
             * Address: 0x00497E10 (FUN_00497E10, the trail-segment pool's subtree destroy)
             */
            void clear() noexcept
            {
                destroy_subtree(root());
                head_->parent = head_;
                head_->left = head_;
                head_->right = head_;
                size_ = 0;
            }

            void swap(rb_tree& other) noexcept
            {
                if (this == &other) {
                    return;
                }
                std::swap(static_cast<carrier&>(*this), static_cast<carrier&>(other));
                std::swap(proxy_, other.proxy_);
                std::swap(head_, other.head_);
                std::swap(size_, other.size_);
            }

        private:
            // ---- node storage ------------------------------------------------

            [[noreturn]] static void throw_too_long() { throw std::length_error("map/set<T> too long"); }

            /**
             * Address: 0x007E5740 (FUN_007E5740, batch-bucket map `allocator<_Node>::allocate`)
             *
             * What it does:
             * Allocates storage for `n` nodes, rejecting counts that would
             * overflow the byte size.
             *
             * The shipped body is the MSVC8 allocator: `0xFFFFFFFF / n`
             * compared against `0x30` (the batch-bucket node size), throwing
             * `std::bad_alloc` when the count does not fit, then
             * `lea edx,[ecx+ecx*2] / shl edx,4` (n * 0x30) into `operator new`.
             * This is a *sizing* helper, not a second `_Buynode` emission.
             */
            [[nodiscard]] static node_type* alloc_raw()
            {
                return static_cast<node_type*>(::operator new(sizeof(node_type)));
            }

            static void free_raw(node_type* const n) noexcept
            {
#if !MSVC8_RBTREE_DISABLE_FREE
                ::operator delete(n);
#else
                (void)n;
#endif
            }

            /**
             * Allocates the header sentinel.
             *
             * MSVC8 buys a full node for the header and leaves `_Myval`
             * unconstructed - the colour/nil bytes live behind the value, so a
             * short allocation would place them out of bounds.
             */
            [[nodiscard]] static node_type* buy_head()
            {
                node_type* const h = alloc_raw();
                h->left = h;
                h->parent = h;
                h->right = h;
                h->color = kRbBlack;
                h->isNil = 1;
                return h;
            }

            /**
             * Address: 0x007E4BC0 (FUN_007E4BC0, batch-bucket map `_Buynode`)
             *
             * What it does:
             * Allocates one node, links both children to the header, marks it red
             * and non-nil, then copy/emplace-constructs the value payload,
             * releasing the storage again if that construction throws.
             *
             * The shipped body pins the node layout field for field:
             * `call sub_7E5740` (the node allocator, `alloc_raw` above) then
             * `[esi] = arg_0` (`_Left`), `[esi+4] = arg_4` (`_Parent`),
             * `[esi+8] = arg_8` (`_Right`), `lea ecx,[esi+0Ch]` for the payload
             * copy (`call sub_7E5070`, the `std::pair` copy constructor - see
             * `MeshBatchBucket` in moho/mesh/MeshBatchKey.h), `[esi+2Ch] = 0`
             * (`_Color` = red) and `[esi+2Dh] = 0` (`_Isnil`). It cleans four
             * stack arguments (`retn 10h`).
             *
             * 0x007E5070 and 0x007E5740 are *not* sibling `_Buynode` emissions,
             * as this block used to claim: they are the value copy constructor
             * and the node allocator this function calls.
             */
            template<class... Args>
            /**
             * Address: 0x00711B00 (FUN_00711B00, the blueprint-stat map's node buy --
             * writes the key at `+0x0C`, the float at `+0x10` and the colour/nil pair at
             * `+0x14`/`+0x15`, matching the 0x18 node exactly.)
             */
            /**
             * Address: 0x0052F740 (FUN_0052F740)  Address: 0x0052FAE0 (FUN_0052FAE0)
             * Address: 0x0052FE80 (FUN_0052FE80)  Address: 0x00530220 (FUN_00530220)
             * Address: 0x005305D0 (FUN_005305D0)  Address: 0x00530980 (FUN_00530980)
             *
             * The per-table head-sentinel allocators: one `operator new` of the 0x30
             * node, then self-linked and flagged as the sentinel.
             */
            /**
             * Address: 0x0049A7B0 (FUN_0049A7B0, the trail-segment pool's node allocate
             * and link)
             * Address: 0x0049EC00 (FUN_0049EC00, its node-array allocate)
             */
            [[nodiscard]] node_type* buy_node(Args&&... args)
            {
                node_type* const n = alloc_raw();
                n->left = head_;
                n->parent = head_;
                n->right = head_;
                n->color = kRbRed;
                n->isNil = 0;
                try {
                    ::new (static_cast<void*>(std::addressof(n->value))) value_type(std::forward<Args>(args)...);
                } catch (...) {
                    free_raw(n);
                    throw;
                }
                return n;
            }

            static void free_node(node_type* const n) noexcept
            {
                n->value.~value_type();
                free_raw(n);
            }

            /**
             * Address: 0x0089A820 (FUN_0089A820, `_Erase`)
             * Address: 0x007E4DD0 (FUN_007E4DD0, sibling emission)
             * Address: 0x007E34E0 (FUN_007E34E0, sibling emission)
             *
             * 0x0089A820 is the session save-node map (`_Isnil` at +0x2D),
             * 0x007E4DD0 the mesh-key map (`_Isnil` at +0x25) and 0x007E34E0 the
             * batch-bucket map (`_Isnil` at +0x2D) - the annotated IDB names that
             * last one `std::map_MeshBatchKey_vector_MeshInstance::RemoveAll`,
             * which is a `_Tree::_Erase`, not a separate container operation.
             *
             * IDA signature:
             * void __stdcall sub_89A820(_Node *rootNode);
             *
             * What it does:
             * Destroys every node of the subtree rooted at `rootNode`.
             *
             * MSVC8 recurses on `_Right` only and unrolls the `_Left` descent into
             * the enclosing loop, destroying the node visited on the *previous*
             * turn - all three emissions show that exact shape (`call <self>` on
             * `[node+8]`, `node = [node]`, then the inlined value destructor plus
             * `operator delete` on the carried-over pointer). Recursing on both
             * children would destroy the same set of nodes but is not what the
             * shipped code does, and it doubles the stack depth on left spines.
             */
            void destroy_subtree(node_type* rootNode) noexcept
            {
                for (node_type* n = rootNode; !rb_is_nil(n); rootNode = n) {
                    destroy_subtree(n->right);
                    n = n->left;
                    free_node(rootNode);
                }
            }

            /**
             * MSVC8 `_Tree::_Copy`. Observed for `msvc8::set<msvc8::string>` at
             * FUN_008C5D50, reached from the copy constructor at 0x008C5B10.
             *
             * Walks `other` in ascending key order and re-inserts each value, so
             * the destination ends up with the same ordered contents. Assumes the
             * destination is empty, which both callers guarantee.
             */
            void copy_from(const rb_tree& other)
            {
                for (node_type* n = other.leftmost(); !rb_is_nil(n); n = rb_increment(n)) {
                    (void)insert_unique(n->value);
                }
            }

            void adopt_from(rb_tree& other) noexcept
            {
                proxy_ = other.proxy_;
                head_ = other.head_;
                size_ = other.size_;
                other.proxy_ = nullptr;
                other.head_ = buy_head();
                other.size_ = 0;
            }

            // ---- structure ---------------------------------------------------

            /**
             * Address: 0x007E4AC0 (FUN_007E4AC0, batch-bucket map `_Lrotate`)
             *
             * What it does:
             * Rotates `n`'s right child up into `n`'s slot, re-parenting the moved
             * subtree and patching the header's root link when `n` was the root.
             */
            /**
             * Address: 0x00592E50 (FUN_00592E50, the name-index map's left rotate)
             *
             * These belong to `std::map<std::string, CArmyStatItem*>` -- `CArmyStats::mNameIndex` -- whose node is 0x30. The colour/nil pair they rewrite sits at `[node+0x2C]`/`[node+0x2D]`, which is what separates them from the 0x18 blueprint-stat node in the same file.
             */
            /**
             * Address: 0x00A52800 (FUN_00A52800)
             * Address: 0x00A529D0 (FUN_00A529D0, byte-identical ICF twin of
             * 0x00A52800 -- same rotate_left body, folded to one binary symbol,
             * both call sites reached independently)
             *
             * An unidentified `map<int32_t, T>` instantiation somewhere in the
             * 0x00A5xxxx-0x00A67xxx address neighbourhood (node layout: right@0,
             * parent@+4, left@+8, colour/nil byte@+33, int32 key@+12 -- field
             * order differs from the batch-bucket/name-index instantiations
             * above, but the rotate algorithm is byte-identical). Reached from
             * `insert_at`'s fixup loop (0x00A63950, matches this template's
             * `link_and_rebalance` shape exactly: same `map/set<T> too long`
             * throw, same buy-node-then-fixup structure) through a caller chain
             * (0x00A656A0 -> 0x00A65D00 -> 0x00A66270 -> 0x00A666F0 -> ...) that
             * was not traced to a named owning class in this pass -- the class
             * itself is still unidentified, only the tree-algorithm shape is
             * confirmed.
             */
            /**
             * Address: 0x00498010 (FUN_00498010, the `std::set<TrailSegmentBufferRuntime*>`
             * instantiation behind `CWorldParticles`' trail-segment owner pool)
             */
            /**
             * Address: 0x00A553F0 (FUN_00A553F0)
             * Address: 0x00A55520 (FUN_00A55520, byte-identical sibling emission)
             *
             * Left-rotate lanes for the same two `[node+0x10]`/`[node+0x11]`
             * colour/nil instantiations cited on `erase_node` above, reached
             * from their rebalance-fixup loops (0x00A633D0/0x00A63690).
             */
            void rotate_left(node_type* const n) noexcept
            {
                node_type* const pivot = n->right;
                n->right = pivot->left;
                if (!rb_is_nil(pivot->left)) {
                    pivot->left->parent = n;
                }
                pivot->parent = n->parent;

                if (n == root()) {
                    head_->parent = pivot;
                } else if (n == n->parent->left) {
                    n->parent->left = pivot;
                } else {
                    n->parent->right = pivot;
                }

                pivot->left = n;
                n->parent = pivot;
            }

            /**
             * Address: 0x007E4B30 (FUN_007E4B30, batch-bucket map `_Rrotate`)
             *
             * What it does:
             * Mirror of `rotate_left`: lifts `n`'s left child into `n`'s slot.
             */
            /**
             * Address: 0x00592EE0 (FUN_00592EE0, the name-index map's right rotate)
             */
            /**
             * Address: 0x004980C0 (FUN_004980C0, the same set's right rotate)
             */
            /**
             * Address: 0x00A553A0 (FUN_00A553A0)
             * Address: 0x00A554D0 (FUN_00A554D0, byte-identical sibling emission)
             *
             * Right-rotate lanes for the same two `[node+0x10]`/`[node+0x11]`
             * colour/nil instantiations cited on `erase_node` above, reached
             * from their rebalance-fixup loops (0x00A633D0/0x00A63690).
             */
            void rotate_right(node_type* const n) noexcept
            {
                node_type* const pivot = n->left;
                n->left = pivot->right;
                if (!rb_is_nil(pivot->right)) {
                    pivot->right->parent = n;
                }
                pivot->parent = n->parent;

                if (n == root()) {
                    head_->parent = pivot;
                } else if (n == n->parent->right) {
                    n->parent->right = pivot;
                } else {
                    n->parent->left = pivot;
                }

                pivot->right = n;
                n->parent = pivot;
            }

            /**
             * Address: 0x007E3F10 (FUN_007E3F10, batch-bucket map `_Insert`)
             *
             * IDA signature:
             * _DWORD *__userpurge _Insert@<eax>(_Node *where@<ecx>, _Tree *this@<edi>,
             *                                   iterator *result, char addLeft, const value_type *val);
             *
             * What it does:
             * Rejects the insert when the tree already holds `max_size() - 1`
             * elements, buys the node, links it under `where` on the requested
             * side while maintaining the header's leftmost/rightmost/root links,
             * then repairs the red-red violation upwards and reblackens the root.
             */
            template<class... Args>
            /**
             * Address: 0x00594F80 (FUN_00594F80, the name-index map's recolour-and-rotate
             * fixup after a link -- it writes only the colour byte at `[node+0x2C]`)
             * Address: 0x00594B10 (FUN_00594B10, the link half that precedes it)
             * Address: 0x00A63950 (FUN_00A63950, the link-and-rebalance half for
             * the unidentified `map<int32_t, T>` instantiation cited on
             * `rotate_left` above -- same `map/set<T> too long` throw guard,
             * buy-node call, and fixup loop shape calling `rotate_left`
             * (0x00A52800/0x00A529D0) on both the left- and right-uncle-red
             * branches; owning class not traced in this pass)
             */
            node_type* insert_at(const bool addLeft, node_type* const where, Args&&... args)
            {
                if (max_size() - 1u <= size_) {
                    throw_too_long();
                }
                node_type* const fresh = buy_node(std::forward<Args>(args)...);
                link_and_rebalance(addLeft, where, fresh);
                return fresh;
            }

            void link_and_rebalance(const bool addLeft, node_type* const where, node_type* const fresh) noexcept
            {
                ++size_;

                if (where == head_) {
                    head_->parent = fresh;
                    head_->left = fresh;
                    head_->right = fresh;
                } else if (addLeft) {
                    where->left = fresh;
                    if (where == leftmost()) {
                        head_->left = fresh;
                    }
                } else {
                    where->right = fresh;
                    if (where == rightmost()) {
                        head_->right = fresh;
                    }
                }
                fresh->parent = where;

                for (node_type* n = fresh; n->parent->color == kRbRed;) {
                    node_type* const parent = n->parent;
                    node_type* const grand = parent->parent;

                    if (parent == grand->left) {
                        node_type* const uncle = grand->right;
                        if (uncle->color == kRbRed) {
                            parent->color = kRbBlack;
                            uncle->color = kRbBlack;
                            grand->color = kRbRed;
                            n = grand;
                        } else {
                            if (n == parent->right) {
                                n = parent;
                                rotate_left(n);
                            }
                            n->parent->color = kRbBlack;
                            n->parent->parent->color = kRbRed;
                            rotate_right(n->parent->parent);
                        }
                    } else {
                        node_type* const uncle = grand->left;
                        if (uncle->color == kRbRed) {
                            parent->color = kRbBlack;
                            uncle->color = kRbBlack;
                            grand->color = kRbRed;
                            n = grand;
                        } else {
                            if (n == parent->left) {
                                n = parent;
                                rotate_right(n);
                            }
                            n->parent->color = kRbBlack;
                            n->parent->parent->color = kRbRed;
                            rotate_left(n->parent->parent);
                        }
                    }
                }

                root()->color = kRbBlack;
            }

            /** MSVC8's post-erase black-height repair. */
            void erase_rebalance(node_type* fix, node_type* fixParent) noexcept
            {
                for (; fix != root() && fix->color == kRbBlack; fixParent = fix->parent) {
                    if (fix == fixParent->left) {
                        node_type* sibling = fixParent->right;
                        if (sibling->color == kRbRed) {
                            sibling->color = kRbBlack;
                            fixParent->color = kRbRed;
                            rotate_left(fixParent);
                            sibling = fixParent->right;
                        }

                        if (rb_is_nil(sibling)) {
                            fix = fixParent;
                        } else if (sibling->left->color == kRbBlack && sibling->right->color == kRbBlack) {
                            sibling->color = kRbRed;
                            fix = fixParent;
                        } else {
                            if (sibling->right->color == kRbBlack) {
                                sibling->left->color = kRbBlack;
                                sibling->color = kRbRed;
                                rotate_right(sibling);
                                sibling = fixParent->right;
                            }
                            sibling->color = fixParent->color;
                            fixParent->color = kRbBlack;
                            sibling->right->color = kRbBlack;
                            rotate_left(fixParent);
                            return; // black heights match again; root is still black
                        }
                    } else {
                        node_type* sibling = fixParent->left;
                        if (sibling->color == kRbRed) {
                            sibling->color = kRbBlack;
                            fixParent->color = kRbRed;
                            rotate_right(fixParent);
                            sibling = fixParent->left;
                        }

                        if (rb_is_nil(sibling)) {
                            fix = fixParent;
                        } else if (sibling->right->color == kRbBlack && sibling->left->color == kRbBlack) {
                            sibling->color = kRbRed;
                            fix = fixParent;
                        } else {
                            if (sibling->left->color == kRbBlack) {
                                sibling->right->color = kRbBlack;
                                sibling->color = kRbRed;
                                rotate_left(sibling);
                                sibling = fixParent->left;
                            }
                            sibling->color = fixParent->color;
                            fixParent->color = kRbBlack;
                            sibling->left->color = kRbBlack;
                            rotate_right(fixParent);
                            return;
                        }
                    }
                }

                fix->color = kRbBlack;
            }

            // ---- 12-byte payload (x86); field order is ABI ---------------------
            _Container_proxy* proxy_; // +0x00
            node_type* head_;         // +0x04
            size_type size_;          // +0x08
        };

    } // namespace detail
} // namespace msvc8

#pragma pack(pop)
