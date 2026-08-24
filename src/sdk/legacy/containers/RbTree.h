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
        /**
         * Address: 0x0077CCB0 (FUN_0077CCB0, the decal bucket set's left-chain
         * descent)
         * Address: 0x0077B120 (FUN_0077B120, the start-tick map's)
         */
        /**
         * Address: 0x00592EC0 (FUN_00592EC0, the name-index map's leftmost
         * descent -- CArmyStats::mNameIndex, isNil@+0x2D, node 0x30.
         * Reached from the name-index erase helper FUN_00703700.)
         */
        /**
         * Address: 0x007E4E80 (FUN_007E4E80, the mesh-key map's leftmost
         * descent -- isNil@+0x25, sibling of the erase_node/rotate
         * instantiations already cited above for this map.)
         */
        /**
         * Address: 0x00592320 (FUN_00592320, the blueprint-stat map's
         * leftmost descent -- `std::map<const RBlueprint*, float>`, isNil@
         * +0x15, node 0x18. Reached from the erase-with-rebalance helper
         * FUN_00592920 cited above.)
         */
        /**
         * Address: 0x00830060 (FUN_00830060, `Moho::UICommandGraph::
         * mGraphRuntimeTree`'s leftmost descent -- `map<shared_ptr<
         * CD3DBatchTexture>, vector<CommandGraphEdge*>>`, 0x18-byte
         * value_type (`max_size() - 1 == 0xAAAAAA9` in `erase_node`'s
         * sibling `insert_at` emission FUN_0082E320, cited below), isNil@
         * +0x25 -- byte-identical ICF twin of the mesh-key map's leftmost
         * descent (0x007E4E80 above); confirmed a distinct instantiation
         * via direct call from `erase_node`'s emission FUN_0082FD50.
         * `Moho::UICommandGraph::AddCommandQueueToCommandGraph`'s
         * `mGraphRuntimeTree[texture]` lookup/insert is documented in
         * CWldSession.cpp; that call chain is what reaches this tree.)
         */
        /**
         * Address: 0x006E1F90 (FUN_006E1F90, the command-id map's leftmost
         * descent -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
         * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15.
         * Walks `_Left` (offset 0) while `!_Isnil`, matching this member
         * exactly. Reached from `erase_node`'s emission FUN_006E1670 (cited
         * below) to re-seat `head->left` when the erased node was the
         * tree's leftmost. A prior Sim.cpp recovery pass mis-labelled this
         * address `TreeMinNode` but had it walk the `right` field -- this
         * member's real behaviour, confirmed against the disassembly, is
         * the leftmost (not rightmost) descent.)
         */
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
        /**
         * Address: 0x0077CC90 (FUN_0077CC90, the decal bucket set's right-chain
         * descent)
         * Address: 0x0077B100 (FUN_0077B100, the start-tick map's)
         */
        /**
         * Address: 0x00592EA0 (FUN_00592EA0, the name-index map's rightmost
         * descent -- sibling of `rb_min`'s 0x00592EC0 above, same map.)
         */
        /**
         * Address: 0x007E4E60 (FUN_007E4E60, the mesh-key map's rightmost
         * descent -- sibling of `rb_min`'s 0x007E4E80 above, same map.)
         */
        /**
         * Address: 0x00592300 (FUN_00592300, the blueprint-stat map's
         * rightmost descent -- sibling of `rb_min`'s 0x00592320 above,
         * same map.)
         */
        /**
         * Address: 0x00830920 (FUN_00830920, `Moho::UICommandGraph::
         * mGraphRuntimeTree`'s rightmost descent -- sibling of `rb_min`'s
         * 0x00830060 above, same map. Byte-identical ICF twin of the
         * mesh-key map's rightmost descent (0x007E4E60 above); confirmed a
         * distinct instantiation via direct call from `erase_node`'s
         * emission FUN_0082FD50.)
         */
        /**
         * Address: 0x006E1F70 (FUN_006E1F70, the command-id map's rightmost
         * descent -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
         * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15.
         * Walks `_Right` (offset +8) while `!_Isnil`, matching this member
         * exactly. Reached from `erase_node`'s emission FUN_006E1670 (cited
         * below) to re-seat `head->right` when the erased node was the
         * tree's rightmost. A prior Sim.cpp recovery pass mis-labelled this
         * address `TreeMaxNode` but had it walk the `left` field -- this
         * member's real behaviour, confirmed against the disassembly, is
         * the rightmost (not leftmost) descent.)
         */
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
        /**
         * Address: 0x0077C740 (FUN_0077C740, the decal bucket set's successor walk)
         * Address: 0x0077CE50 (FUN_0077CE50, the start-tick map's)
         */
        /**
         * Address: 0x0082EC10 (FUN_0082EC10, `Moho::UICommandGraph::
         * mGraphRuntimeTree`'s successor walk -- isNil@+0x25, 0x18-byte
         * value_type, byte-identical ICF twin of the mesh-key map's
         * successor walk family. Called at the top of that map's
         * `erase_node` emission (FUN_0082FD50, cited below on `erase_node`)
         * to capture the return iterator before unlinking.)
         */
        /**
         * Address: 0x006878C0 (FUN_006878C0, `_Inc` for `msvc8::map<
         * std::uint32_t, moho::IdPool>` -- `CEntityDb::mIdPoolTree` in
         * `EntityDb.h`. Reached from `EntityDbIdPoolMapTypeInfo::SerSave`'s
         * (binary: `std::map_IdPool::Serialize`, `FUN_00686B10`) range-for
         * walk over the map. Its register-shape adapters `FUN_00685FA0`/
         * `FUN_00686CE0` are sibling emissions of the same walk.)
         */
        /**
         * Address: 0x006E2220 (FUN_006E2220, `std::map_uint_CUnitCommand::
         * Iterator::inc`) -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
         * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15.
         * Matches this member exactly. `FUN_006E1A90`/`FUN_006E1AB0` are two
         * thin `_Node**` slot-pointer wrapper adapters around it (advance
         * `*slot` in place, return `slot`, matching `rb_iterator::
         * operator++()`'s `node_ = rb_increment(node_)` shape one level up
         * through an indirection); `FUN_006E28C0` is the copy-then-advance
         * adapter matching `operator++(int)`'s shape, cited on that member
         * below. All three, plus this address, have zero incoming xrefs in
         * this sweep -- re-homed here from bespoke `AdvanceCommandDbIteratorNode`/
         * `AdvanceCommandDbIteratorSlotLaneA`/`AdvanceCommandDbIteratorSlotLaneB`/
         * `CopyAndAdvanceCommandDbIteratorSlot` free functions in Sim.cpp
         * that hand-walked the same successor step over a
         * `CommandDbMapNodeView` reach-in instead of calling it, matching
         * the same "no direct caller confirmed in this pass" disclosure
         * already recorded for this map's `begin`/`empty`/`lower_bound_node`
         * orphan accessor lanes above.)
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
        /**
         * Address: 0x0077CD80 (FUN_0077CD80, the decal bucket iterator retreat)
         * Address: 0x0077D160 (FUN_0077D160, the start-tick map's; its two
         * register-shape adapters are 0x0077C7A0 and 0x0077CE30)
         */
        /**
         * Address: 0x005364D0 (FUN_005364D0, the predecessor-lookup half of
         * `insert_unique` for RRuleGameRulesBlueprintMap =
         * msvc8::map<msvc8::string,void*>; isNil at +0x2D = 0x0D +
         * sizeof(pair<msvc8::string(28),void*(4)>)=0x20, confirming the
         * node type. Reached from FUN_00534030, the Unit-blueprint insert
         * cited on `insert_unique` above.)
         * Address: 0x00536410 (FUN_00536410, same instantiation, reached
         * from FUN_00534470 -- Emitter-blueprint insert)
         * Address: 0x00536590 (FUN_00536590, reached from FUN_00534250 --
         * Prop-blueprint insert)
         * Address: 0x00536530 (FUN_00536530, reached from FUN_00534140 --
         * Projectile-blueprint insert)
         * Address: 0x005365F0 (FUN_005365F0, reached from FUN_00534360 --
         * Mesh-blueprint insert)
         * Address: 0x00536470 (FUN_00536470, reached from FUN_00534690 --
         * Trail-blueprint insert)
         * Address: 0x005363B0 (FUN_005363B0, reached from FUN_00534580 --
         * Beam-blueprint insert)
         * Address: 0x00712030 (FUN_00712030, the blueprint-stat map's
         * predecessor lookup -- isNil@+0x15, node 0x18. Reached from
         * FUN_0070F6C0/FUN_007108D0, the copy-driver call sites already
         * cited on the copy constructor above.)
         * Address: 0x00556E70 (FUN_00556E70, the predecessor-lookup half of
         * `insert_unique` for the category-lookup map =
         * `msvc8::map<msvc8::string, moho::CategoryLookupValue>`
         * (`Sim.cpp`'s `EntityCategoryLookupTableView::mCategoryMap` --
         * IDA independently types this tree `std::map_string_EntityCategory`
         * at the read-side lookups, FUN_005561C0/FUN_00556220/FUN_00556970).
         * This is the one instantiation in this file whose node does *not*
         * follow the usual "value starts at node+0x0C" shape: `isNil` sits at
         * +0x59, but the value itself starts at +0x10 (confirmed from
         * `buy_node`'s destination address, FUN_005569C0) because
         * `CategoryLookupValue` (Sim.cpp) is 8-byte aligned -- see the
         * evidence block on that type. `rb_node<V>` reproduces the same
         * +0x10/+0x58/+0x59 layout automatically once `V` is
         * `pair<const msvc8::string, CategoryLookupValue>`, with no template
         * change needed here. Reached from `FUN_005560B0`, the insert cited
         * on `insert_unique` below.)
         */
        /**
         * Address: 0x006888E0 (FUN_006888E0, the predecessor-lookup half of
         * `insert_unique` for `msvc8::map<std::uint32_t, moho::IdPool>` --
         * `CEntityDb::mIdPoolTree` in `EntityDb.h`. Reached from
         * `insert_unique`'s emission `FUN_006870D0` and `insert_hint`'s
         * emission `FUN_006864E0`, both cited below.)
         * Address: 0x006E28D0 (FUN_006E28D0, the command-id map's
         * predecessor lookup -- `msvc8::map<Moho::CmdId,
         * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
         * `CCommandDb.h`, isNil@+0x15. This body has three callers total
         * (`incoming_xrefs` in `_callgraph_index.sqlite`); only one,
         * `insert_unique`'s emission for this map (FUN_006E15B0, cited
         * below), is this instantiation's -- the other two belong to
         * different 8-byte-value_type maps that happen to share this exact
         * byte-identical body, the same ICF-adjacent sharing documented
         * throughout this file for `rb_min`/`rb_max`/the rotate family.)
         * Address: 0x008B6950 (FUN_008B6950, sub_8B6950, the predecessor
         * lookup half of `insert_unique` for `msvc8::map<Moho::CmdId,
         * Moho::UserCommandIssueHelper*>` -- `CommandManager::mCommands` in
         * `CommandManager.h`, isNil@+0x15. Reached from `insert_unique`'s
         * emission FUN_008B5DF0, cited on that member. Re-homed here from
         * the same bespoke `InsertCommandNodeFixup` free function in
         * Sim.cpp cited on `insert_unique`/`insert_at` above.)
         */
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
            /**
             * Address: 0x006886A0 (FUN_006886A0, postfix `_Inc` for
             * `msvc8::map<std::uint32_t, moho::IdPool>` -- `CEntityDb::
             * mIdPoolTree` in `EntityDb.h`. Copies the pre-increment cursor
             * out, advances via prefix `operator++` (`FUN_006878C0`, cited
             * on `rb_increment` above), returns the copy -- exactly this
             * member's shape. Sibling of the prefix walk `EntityDbIdPoolMapTypeInfo::
             * SerSave` performs; reached through the same generic
             * `msvc8::map`/`rb_tree` iterator API surface, not a distinct
             * new engine call site.)
             */
            /**
             * Address: 0x006E28C0 (FUN_006E28C0) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. Same copy-then-advance shape as FUN_006886A0
             * above (a separate instantiation): copies `*sourceSlot` into
             * `*outSlot`, advances `*sourceSlot` via `FUN_006E2220`
             * (`rb_increment`, cited above), returns `outSlot`. Zero
             * incoming xrefs in this sweep. Re-homed here from a bespoke
             * `CopyAndAdvanceCommandDbIteratorSlot` free function in Sim.cpp
             * that hand-rolled this same copy-and-advance over a
             * `CommandDbMapNodeView` reach-in instead of calling it.)
             */
            rb_iterator operator++(int) noexcept
            {
                const rb_iterator copy = *this;
                ++*this;
                return copy;
            }

            /**
             * Address: 0x006E2200 (FUN_006E2200) Address: 0x006E27D0
             * (FUN_006E27D0, duplicate emission) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. Both are thin `_Node**` slot-pointer wrapper
             * adapters around `FUN_006E28D0` (`rb_decrement`, cited above),
             * matching this member's `node_ = rb_decrement(node_)` shape one
             * level up through an indirection. Zero incoming xrefs in this
             * sweep. Re-homed here from bespoke
             * `AdvanceCommandDbIteratorCursorSlotLaneA`/`...LaneB` free
             * functions in Sim.cpp that hand-rolled this same predecessor
             * step over a `CommandDbMapNodeView` reach-in instead of calling
             * it -- those two functions actually called the *increment*
             * (successor) walk instead of the real decrement one, a latent
             * mismatch harmless only because neither had a real caller.)
             */
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
             *
             * Address: 0x009471A0 (FUN_009471A0) and 0x00947FE0 (FUN_00947FE0,
             * sibling emission that additionally returns `this` in `eax` --
             * an MSVC ctor-calling-convention variant of the same source line,
             * not a behavioural difference) -- another instantiation of this
             * same allocate/self-link split, isNil@+0x15 (8-byte value_type,
             * node size 0x18: `0x0C` links + 8 value + color + isNil, rounded).
             * Both call a dedicated alloc_raw half (`sub_946F90`/`sub_947030`
             * respectively -- `operator new(0x18)`, zero the three link dwords,
             * `color=1`/`isNil=0`) then perform the self-link and `isNil=1`
             * flag fixup this template's `buy_head()` performs inline, exactly
             * matching the already-cited `FUN_00A583C0`/`FUN_00A5A000` split
             * below on `buy_head()` itself. Neither writes `this->proxy_`
             * (offset +0) -- consistent with `rb_tree()`'s constructor running
             * against storage the caller already zero-initialised (e.g. a
             * `new T()` value-initialisation of the owning object), which
             * makes the redundant `proxy_ = nullptr` store foldable away.
             * Owning field/class not yet pinned down -- this isNil@+0x15,
             * 8-byte-value node shape recurs across many Sim-subsystem
             * containers (see `MapNodeNil21Runtime` and its many instantiation
             * sites in `moho/sim/SimRecoveryRuntime.cpp`); flagged as an open
             * item for whoever narrows the specific owner next.
             */
            /**
             * Address: 0x006E1520 (FUN_006E1520) Address: 0x006E1CF0
             * (FUN_006E1CF0, duplicate emission) Address: 0x006E2390
             * (FUN_006E2390, duplicate emission) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`, isNil@+0x15. All three call `FUN_006E2840`
             * (the raw head-node allocator already cited on `CCommandDb`'s
             * own constructor in `CCommandDb.h` as the `buy_head()` split
             * half), patch `isNil=1`, self-link `parent`/`left`/`right`, and
             * zero `size_` -- exactly this constructor's shape -- without
             * touching `proxy_` at offset 0, matching the "storage already
             * zero-initialised" pattern documented above. Three compiler
             * emissions of the same ctor body for different inlining
             * contexts inside `CCommandDb`'s own methods; zero incoming
             * xrefs in this sweep for any of the three. Re-homed here from
             * bespoke `InitializeCommandDbMapHead`/`InitializeCommandDbMapStorageLaneA`/
             * `...LaneB`/`...LaneC` free functions in Sim.cpp that hand-
             * rolled this same construction over a `CommandDbMapStorageView`/
             * `CCommandDbRuntimeView` reach-in instead of relying on the
             * member's default construction.)
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
            /**
             * Address: 0x0077C1E0 (FUN_0077C1E0, the decal bucket set's copy construct)
             * Address: 0x0077D090 (FUN_0077D090, its recursive subtree clone)
             * Address: 0x0077CBB0 (FUN_0077CBB0, the header-and-extrema copy that
             * finishes it)
             * Address: 0x0077C5B0 (FUN_0077C5B0, the head-sentinel build the copy starts
             * from; emitted again at 0x0077A8B0 and 0x0077B4C0)
             */
            rb_tree(const rb_tree& other)
                : carrier(static_cast<const carrier&>(other)), proxy_(nullptr), head_(buy_head()), size_(0)
            {
                copy_from(other);
            }

            /**
             * Address: 0x0077E280 (FUN_0077E280, the decal bucket set's copy assign)
             */
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
            /**
             * Address: 0x00591ED0 (FUN_00591ED0, the blueprint-stat map's
             * destructor -- `std::map<const RBlueprint*, float>`, node 0x18.
             * Matches the same shape: erase_range via FUN_00592230
             * (cited above), then `operator delete` on the head and zeroed
             * head/size lanes.)
             * Address: 0x0052A390 (FUN_0052A390, the destructor for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * `msvc8::set<uint32_t>`. Erase-range via `sub_52D9C0`
             * (`erase_range`, cited below) then `operator delete` on the
             * head, matching this body exactly. Recovered as
             * `ReleaseExportBindingPendingOrdinals` in RRuleGameRules.cpp --
             * that helper explicitly destroys and reconstructs the member
             * in place rather than relying on `~RRuleGameRulesLuaExportBinding
             * ()` alone, since the binary invokes this both from a live
             * compaction site and from an SEH unwind funclet.)
             * Address: 0x0052CF10 (FUN_0052CF10, the SEH-unwind-path duplicate
             * of the same `mPendingBlueprintOrdinals` teardown -- byte-for-byte
             * the same three steps (`erase_range(leftmost(), header())` via
             * `sub_52D9C0`, `operator delete(head_)`, then `head_=nullptr`/
             * `size_=0` at `[this+4]`/`[this+8]`) but entered with `this` handed
             * in `eax` and moved to `edi` rather than arriving in `ecx`, which
             * is the unwind-funclet calling convention referenced on
             * 0x0052A390 above rather than an ordinary thiscall member-function
             * entry. No separate source line -- this is the compiler-generated
             * unwind-path clone of the same destructor, not a distinct
             * function.)
             */
            /**
             * Address: 0x006843B0 (FUN_006843B0, `Moho::EntityDB::~EntityDB` --
             * `msvc8::map<std::uint32_t, moho::IdPool>`, `CEntityDb::
             * mIdPoolTree` in `EntityDb.h`. Recurses `FUN_00688030`
             * (`destroy_subtree`, cited below) from the tree's actual root
             * (`head->parent`) then releases the sentinel head -- exactly
             * this member's `erase_range(leftmost(), header())` whole-tree
             * fast path followed by `free_raw(head_)`. A prior hand-rolled
             * version of `CEntityDb`'s destructor recursed from
             * `head->left` (leftmost()) instead of the root, which would
             * have destroyed at most one node and leaked the rest; this
             * member does not have that bug. Reached automatically via
             * member destruction, `EntityDb.h`.)
             * Address: 0x006E0A70 (FUN_006E0A70, `Moho::CommandDatabase::
             * ~CommandDatabase` -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. The tail of that function is exactly this
             * member: `sub_6E22D0(&mCommands, iter, mCommands._Myhead->
             * _Left, mCommands._Myhead)` -- `erase_range(leftmost(),
             * header())`'s emission for this instantiation, cited on that
             * member below -- then `operator delete(mCommands._Myhead)` and
             * the `_Myhead=0`/`_Mysize=0` zeroing. `CCommandDb::
             * ~CCommandDb()`'s own hand-written body is only the
             * empty-or-die diagnostic dump; this teardown is reached
             * automatically via member destruction.)
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
            /**
             * Address: 0x0077C020 (FUN_0077C020, outer map lower bound)
             * Address: 0x0077B070 (FUN_0077B070, its store-to-slot adapter)
             * Address: 0x0077C550 (FUN_0077C550, inner bucket lower bound)
             * Address: 0x0077C580 (FUN_0077C580, inner bucket upper bound)
             * Address: 0x0077B5B0 (FUN_0077B5B0, the inner set's equal-range pair)
             * Address: 0x00556970 (FUN_00556970, the category-lookup map's
             * lower bound -- `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `Sim.cpp`'s
             * `EntityCategoryLookupTableView::mCategoryMap`. Already
             * recovered as `Moho::EntityCategorySet::Find` /
             * `FindCategoryLowerBound` in
             * `moho/entity/EntityCategoryLookupResolver.cpp`'s independent
             * read-only view of this same tree; shared between that file's
             * read path and this member's `find_node` (FUN_005561C0, cited
             * below), confirming both recoveries agree on the node layout.)
             * Address: 0x006E23C0 (FUN_006E23C0, the command-id map's raw
             * lower-bound descent) Address: 0x006E1D30 (FUN_006E1D30, its
             * store-into-hidden-return-pointer adapter) -- `msvc8::map<
             * Moho::CmdId, Moho::CUnitCommand*>`, `Moho::CCommandDb::commands`
             * in `CCommandDb.h`. Re-homed here from two bespoke free
             * functions in `CCommandDb.cpp` (`LowerBoundCommandMapNode`,
             * `StoreLowerBoundCommandMapNode`) during the
             * `CommandDbMapNodeRuntime` hand-rolled-tree migration; no
             * direct caller confirmed in this pass (`incoming_xrefs` empty
             * in this sweep for both) -- none of `CCommandDb`'s recovered
             * methods call `lower_bound`/`operator[]` directly, so this
             * emission's real call site remains unidentified.)
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
            /**
             * Address: 0x0077BCD0 (FUN_0077BCD0, the outer map's start-tick lookup)
             */
            /**
             * Address: 0x005561C0 (FUN_005561C0, the category-lookup map's
             * find -- `msvc8::map<msvc8::string, moho::CategoryLookupValue>`,
             * `Sim.cpp`'s `EntityCategoryLookupTableView::mCategoryMap`.
             * Was previously (and incorrectly) marked `external_dependency`
             * in `recovered_progress.json` -- that classification only saw
             * the `std::operator<<char>` (STL string-compare thunk) callee
             * and missed that the function also calls `FUN_00556970`
             * (`Moho::EntityCategorySet::Find`, `lower_bound_node`'s
             * emission for this instantiation, already recovered in
             * `EntityCategoryLookupResolver.cpp`), which is real engine
             * code. Matches this member field for field: `_Lbound` for the
             * candidate, then `rb_is_nil(found) || comp(k, key_of(found))`
             * -- IDA's own type inference names the tree
             * `std::map_string_EntityCategory` here and the node's `_Myval`
             * a `helper` struct whose `.first` is the key string, matching
             * this instantiation's `pair<const msvc8::string,
             * CategoryLookupValue>` `value_type`. Reached from
             * `AddCategoryMemberBit` (FUN_005555C0, Sim.cpp) as
             * `categoryMap.find(categoryName)`; `FUN_00556220`
             * (`std::map_string_EntityCategory::find`, also already recovered
             * in `EntityCategoryLookupResolver.cpp`) is a sibling emission of
             * this same member reached from the read-only lookup path
             * instead.)
             */
            /**
             * Address: 0x006E1940 (FUN_006E1940, sub_6E1940 --
             * `Moho::CCommandDB::RemoveCmd`'s (FUN_006E0EC0, cited below on
             * `erase_node`) and `Moho::Sim::ValidateNewCommandId`'s
             * (FUN_007491C0) find call) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`, isNil@+0x15. Same shape as `find_node`'s
             * generic body with `lower_bound_node`'s descent inlined rather
             * than called out to a separate emission -- opens with the same
             * "descend recording the last branch, `>=` comparison walks
             * left" loop as `lower_bound_node`, then the same
             * nil-or-key-less rejection this member performs. Re-homed here
             * from a bespoke `FindCommandNode` free function in Sim.cpp
             * (four overloads reaching in through `CommandDbMapStorageView`/
             * `CommandDbMapNodeView`/`CCommandDbRuntimeView`) that hand-
             * walked the same real member instead of calling it.
             *
             * `FUN_006E0E90` is a thin wrapper over this same address:
             * calls it, then returns the mapped `CUnitCommand*` value
             * directly (nil-or-absent -> `nullptr`) rather than the node --
             * the same "find, extract mapped value or null" convenience
             * `try_get()` provides, just by-value instead of by-pointer.
             * Zero incoming xrefs in this sweep. Re-homed here from a
             * bespoke `FindCommandByIdRuntimeMap` free function in Sim.cpp.)
             */
            /**
             * Address: 0x008B6160 (FUN_008B6160, `std::map_uint_
             * IssueCommandHelper::find`, called from `struct_CommandManager::
             * FindDataFor`/`NewCommand` FUN_008B5A70, `struct_CommandManager::
             * DeleteCommands` FUN_008B5C20, and `sub_8B5BB0`) --
             * `msvc8::map<Moho::CmdId, Moho::UserCommandIssueHelper*>`,
             * `CommandManager::mCommands` in `CommandManager.h`, isNil@+0x15.
             * Same inlined-lower-bound-then-verify shape as FUN_006E1940
             * above, a separate instantiation (different `T`). Re-homed here
             * from the same bespoke `FindCommandNode` free-function reach-in
             * cited above, called through `CommandIssueMapOf` for this
             * member instead.)
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
            /**
             * Address: 0x0077A930 (FUN_0077A930, the bucket set's find-or-insert -- what
             * `mStartTickBuckets[tick].insert(handle)` compiles to on the inner set)
             * Address: 0x0077A250 (FUN_0077A250, the outer map's `operator[]`, which the
             * same expression compiles to on the outer map)
             */
            /**
             * Address: 0x00534030 (FUN_00534030, RRuleGameRulesBlueprintMap insert --
             * `GetOrCreateRegisteredBlueprint<RUnitBlueprint,...>`'s
             * `map.insert(RRuleGameRulesBlueprintMap::value_type(normalizedId, blueprint))`
             * at Sim.cpp; insert_at half is FUN_005349E0, predecessor lookup is FUN_005364D0)
             * Address: 0x00534140 (FUN_00534140, same map insert, T=RProjectileBlueprint;
             * insert_at FUN_00534B90, predecessor lookup FUN_00536530)
             * Address: 0x00534250 (FUN_00534250, same map insert, T=RPropBlueprint;
             * insert_at FUN_00534D40, predecessor lookup FUN_00536590)
             * Address: 0x00534360 (FUN_00534360, same map insert, T=RMeshBlueprint;
             * insert_at FUN_00534EF0, predecessor lookup FUN_005365F0)
             * Address: 0x00534470 (FUN_00534470, same map insert reached from
             * `GetOrCreateRegisteredEffectBlueprint<REmitterBlueprint,...>`; insert_at
             * FUN_005350A0, predecessor lookup FUN_00536410)
             * Address: 0x00534580 (FUN_00534580, same map insert, T=RBeamBlueprint;
             * insert_at FUN_00535250, predecessor lookup FUN_005363B0)
             * Address: 0x00534690 (FUN_00534690, same map insert, T=RTrailBlueprint;
             * insert_at FUN_00535400, predecessor lookup FUN_00536470)
             *
             * All seven are byte-for-byte the same `insert_unique` shape (descend
             * recording the last branch, confirm uniqueness against the in-order
             * predecessor when the descent bottomed out on a left branch, link via
             * `insert_at`) compiled once per `RRuleGameRulesImpl::Get*Blueprint()`
             * owner even though the map type (`msvc8::map<msvc8::string,void*>`) is
             * identical across all seven call sites -- the 2007 compiler did not
             * fold them despite the shared instantiation.
             */
            /**
             * Address: 0x0052BC60 (FUN_0052BC60, func_MapInsert -- the
             * `msvc8::set<uint32_t>` embedded at `RRuleGameRulesLuaExportBinding::
             * mPendingBlueprintOrdinals`, node 0x14 with `_Isnil` at +0x11
             * (0x0D + sizeof(uint32_t)), matching the same shape as
             * `Moho::SPeer::establishedUids` cited on `buy_head` below).
             * `insert_at` half is FUN_0052CD30, predecessor lookup (`sub_530DD0`)
             * is `rb_decrement`'s sibling emission for this instantiation.
             * Called once per existing binding from `func_Add__blueprints`
             * (0x00529B30, RRuleGameRulesImpl::mMaps loop at
             * 0x00529BF0-0x00529C0B) -- recovered as
             * `RegisterBlueprintInCategoryMaps` in Sim.cpp, which walks
             * `rules->mMaps` and calls `mPendingBlueprintOrdinals.insert(ordinal)`
             * on each binding.
             *
             * The node's value is 4 bytes (just the ordinal -- see the
             * `buy_node` citation below), not the 8-byte
             * `pair<const uint32_t, RBlueprint*>` a `msvc8::map` would need,
             * which is what pins the instantiation to `msvc8::set<uint32_t>`
             * rather than `msvc8::map<uint32_t, RBlueprint*>`.
             */
            /**
             * Address: 0x0082E170 (FUN_0082E170, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s plain unique insert -- descends comparing
             * the owner-based key at `node+4` against the sought key
             * directly (no separate comparator call for the common case;
             * `sub_8309D0` is called only on the tie-break branch, matching
             * the `owner_before`-style `shared_ptr` compare CWldSession.cpp's
             * `AddCommandQueueToCommandGraph` notes describe for
             * `mGraphRuntimeTree`'s `0x008B8D0` comparator), then confirms
             * uniqueness and links via `insert_at` (0x0082E320, cited
             * above). Called from `insert_hint`'s fallback branch,
             * FUN_0082CC80 (cited below), matching this member's own
             * `insert_unique(v).first` tail call.)
             */
            /**
             * Address: 0x005560B0 (FUN_005560B0, the category-lookup map's
             * insert -- `msvc8::map<msvc8::string, moho::CategoryLookupValue>`,
             * `Sim.cpp`'s `EntityCategoryLookupTableView::mCategoryMap`. Opens
             * with the same descend-recording-the-last-branch loop as this
             * member (`v5[10] < 0x10 ? &buf : ptr` is the msvc8::string SSO
             * read at the candidate node's key, `[v5+0x59]` its `isNil`),
             * confirms uniqueness against the in-order predecessor when the
             * descent bottomed out on a left branch (`v6 == head->left` is
             * the `where == leftmost()` fast-out; otherwise `rb_decrement`,
             * FUN_00556E70, cited above), and tail-calls `insert_at`
             * (FUN_005565D0, cited below) either way. Reached from
             * `AddCategoryMemberBit` (FUN_005555C0, Sim.cpp) as
             * `categoryMap.insert(CategoryLookupMap::value_type(categoryName,
             * freshValue))` when `categoryMap.find(categoryName)` (FUN_005561C0,
             * cited on `find_node` below) misses.
             *
             * The node's value does not start at the usual `node+0x0C` --
             * see `CategoryLookupValue`'s citation block in Sim.cpp for the
             * 8-byte-alignment evidence that moves it to `node+0x10` and the
             * colour/nil pair to `node+0x58`/`node+0x59`.)
             */
            /**
             * Address: 0x006870D0 (FUN_006870D0, `msvc8::map<std::uint32_t,
             * moho::IdPool>::insert_unique` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. Matches this member field for field: descends
             * recording the last branch (`addLeft`), fast-paths when the
             * descent bottomed out at `leftmost()`, otherwise confirms
             * uniqueness against the in-order predecessor via
             * `FUN_006888E0` (`rb_decrement`, cited above) before
             * tail-calling `insert_at` (`FUN_00687280`, cited above) either
             * way. Reached from `EntityDbIdPoolMapTypeInfo::SerLoad`'s
             * per-element `map->insert(value_type(key, std::move(pool)))`
             * (binary: `std::map_IdPool::Deserialize`'s per-element
             * `sub_6870D0` call, `FUN_00686990`) -- the map is freshly
             * cleared immediately before, so every insert is unconditional,
             * matching this member's unconditional-insert use here.)
             */
            /**
             * Address: 0x006E15B0 (FUN_006E15B0, the command-id map's unique
             * insert -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
             * `Moho::CCommandDb::commands` in `CCommandDb.h`. Matches this
             * member field for field: descends recording the last branch
             * (`Parent`/`v7`=`addLeft`), the `where == leftmost()` fast path
             * tail-calls `insert_at` (FUN_006E1D60, cited below) directly,
             * otherwise the predecessor check via `rb_decrement`
             * (FUN_006E28D0, cited above) gates a second `insert_at` call or
             * returns the colliding node with `false`. Reached from
             * `AddIssueData` (FUN_006E0DB0) and `MemberDeserialize`
             * (FUN_006E1430), both as `commands.insert(value_type(cmdId,
             * command))`, `CCommandDb.cpp`.)
             */
            /**
             * Address: 0x008B5DF0 (FUN_008B5DF0, sub_8B5DF0, called from
             * `struct_CommandManager::FindDataFor`/`NewCommand` FUN_008B5A70
             * as `insert(value_type(commandId, helper))`) --
             * `msvc8::map<Moho::CmdId, Moho::UserCommandIssueHelper*>`,
             * `CommandManager::mCommands` in `CommandManager.h`. Same shape
             * as FUN_006E15B0 above (a separate instantiation): descends
             * recording the last branch, `where == leftmost()` fast path
             * tail-calls `insert_at` (FUN_008B6310, cited below) directly,
             * otherwise a predecessor check via `rb_decrement` (FUN_008B6950,
             * cited above) gates a second `insert_at` call or returns the
             * colliding node with `false`. Re-homed here from a bespoke
             * `InsertCommandNode`/`InsertCommandNodeFixup` free-function pair
             * in Sim.cpp that hand-rolled unique-insert-plus-fixup over a
             * `CommandDbMapStorageView`/`CommandDbMapNodeView` reach-in
             * instead of calling it.)
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
            /**
             * Address: 0x0082CC80 (FUN_0082CC80, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s hinted insert -- matches this member's
             * branch structure directly: empty-tree fast path straight to
             * `insert_at`, `hint == leftmost()` check, `rb_is_nil(hint)`
             * (== `end()`) check against `rightmost()`, then the
             * decrement/increment straddle checks, each tailing into
             * `insert_at` (0x0082E320, cited above) with the decided
             * `addLeft`, and a final fallback to `insert_unique`
             * (0x0082E170, cited above) taking its `.first`. This is the
             * `map::operator[]`-shaped hinted insert CWldSession.cpp's
             * `AddCommandQueueToCommandGraph` notes already name at this
             * address, for `mGraphRuntimeTree[texture]`'s `lower_bound`
             * result feeding straight back in as the hint. Its own caller,
             * the `lower_bound` descent FUN_0082B8B0, remains unrecovered --
             * `AddCommandQueueToCommandGraph` itself is still blocked on the
             * separate, much larger `LinkCommandGraphEdge` edge-builder.)
             */
            /**
             * Address: 0x006864E0 (FUN_006864E0, `std::map_uint_IdPool::insert`
             * -- `msvc8::map<std::uint32_t, moho::IdPool>`'s hinted insert,
             * `CEntityDb::mIdPoolTree` in `EntityDb.h`. Matches this member's
             * branch structure directly: empty-tree fast path, `hint ==
             * leftmost()` check, `hint == end()` check against `rightmost()`,
             * then the decrement/increment straddle checks (via
             * `FUN_006888E0`, `rb_decrement`, cited above), each falling
             * through to `insert_at` (`FUN_00687280`, cited above) with the
             * decided `addLeft`, and a fallback to `insert_unique`
             * (`FUN_006870D0`, cited above) taking its `.first`. Reached
             * from `CEntityDb::MemberDeserialize`'s
             * `mIdPoolTree[familySourceBits]` (binary: `Moho::EntityDB::
             * DoReserveId`/`ReleaseId`'s `std::map_uint_IdPool::find2`,
             * `FUN_00685750`, cited on `msvc8::map::operator[]` in Map.h --
             * `find2` is this instantiation's `operator[]`: lower-bound then
             * conditional hinted insert).)
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
             * Address: 0x0083A640 (FUN_0083A640, msvc8::map<UiKeyMask,
             * msvc8::string>::erase(const_iterator) -- same `map<uint32,
             * string>` node shape as 0x0089A540 (`_Isnil` at +0x2D). The
             * compiled body constant-folds `this` to the fixed address of
             * the sole call-site global (`gUiKeyActionMap`, since this
             * instantiation has exactly one call site) rather than reading
             * it from the passed tree pointer -- a compiler optimization,
             * not a different operation. Reached from `gUiKeyActionMap.
             * erase(keyMask)`'s inner iterator-erase in
             * RemoveUiKeyMapEntries, UiRuntimeTypes.cpp.)
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
             * Address: 0x00A633D0 (FUN_00A633D0, `std::set<HullTriangle3<float>*>::
             * erase(const_iterator)` -- colour/nil pair at `[node+0x10]`/
             * `[node+0x11]`, a smaller node than every other instantiation cited
             * above since the value_type is a bare 4-byte pointer)
             * Address: 0x00A63690 (FUN_00A63690, sibling emission of the same
             * member for `std::set<HullTriangle3<double>*>` -- same colour/nil
             * offsets, same `invalid map/set<T> iterator` throw and guarded
             * `_Mysize` decrement, byte-for-byte the same node shape since a
             * `HullTriangle3<double>*` is still a 4-byte pointer)
             *
             * Owner identified in a later pass: `Wm3::ConvexHull3<Real>::m_kHull`
             * (`dependencies/WildMagic3p8/Foundation/Containment/Wm3ConvexHull3.h:89`),
             * reached from `m_kHull.erase(pkTri)` in `ConvexHull3<Real>::Update`
             * (`Wm3ConvexHull3.cpp:324`) via the range-erase entry point
             * (`sub_A65320`/`sub_A65430`, `external_dependency` -- WildMagic vendor
             * code, not engine source; see those tokens' recovery notes). Both
             * `sub_A65320` and `sub_A65430` are compiled with checked iterators
             * (Secure SCL), unlike this codebase's own `msvc8::set`/`msvc8::map`
             * instantiations, but this member's own isNil-guard-and-throw shape is
             * identical either way, so the algorithm match alone remains sufficient
             * evidence for the citation.
             */
            /**
             * Address: 0x0077C270 (FUN_0077C270, inner bucket erase with rebalance)
             * Address: 0x0077A9F0 (FUN_0077A9F0, its erase-by-key wrapper -- what
             * `mStartTickBuckets[tick].erase(handle)` compiles to)
             */
            /**
             * Address: 0x0052F0A0 (FUN_0052F0A0, the single-node erase-and-
             * rebalance for `RRuleGameRulesLuaExportBinding::
             * mPendingBlueprintOrdinals` -- `msvc8::set<uint32_t>`. Called
             * once per node from `erase_range`'s (`sub_52D9C0`) walk-one-at-
             * a-time loop, cited below.)
             */
            /**
             * Address: 0x0082FD50 (FUN_0082FD50, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s erase-with-rebalance -- `map<shared_ptr<
             * CD3DBatchTexture>, vector<CommandGraphEdge*>>`, isNil@+0x25,
             * 0x18-byte value_type. Opens with the same `_Isnil` guard
             * throwing `out_of_range("invalid map/set<T> iterator")` seen on
             * the other emissions of this member, captures the successor
             * through `rb_increment` (0x0082EC10, cited above) before
             * unlinking, and its rebalance loop calls `rotate_left`
             * (0x00830010) / `rotate_right` (0x00830080), both cited below,
             * confirming this is the same tree as `insert_at`'s emission
             * FUN_0082E320. `sub_82BEE0` (cited on `free_node` below) is the
             * inlined `value_type::~value_type()` call ahead of `operator
             * delete`. Unique body, no ICF twins -- the node-buy/value-dtor
             * calls it makes are specific to this value_type, so unlike the
             * pure-pointer-arithmetic rotate/walk helpers it does not fold
             * with the mesh-key map's sibling emission.)
             */
            /**
             * Address: 0x007B46A0 (FUN_007B46A0, single-node erase-and-rebalance
             * for the `msvc8::set<std::uint32_t>` instantiation cited on
             * `destroy_subtree` above -- isNil@+0x11, opens with the same
             * `_Isnil` guard throwing `out_of_range("invalid map/set<T>
             * iterator")` byte-for-byte (same string literal, same
             * `std::out_of_range` vftable patch, same `_CxxThrowException`
             * tail) as the other emissions of this member. Called once per
             * node from `erase_range`'s (`FUN_007B3E00`, cited below)
             * walk-one-at-a-time loop.)
             */
            /**
             * Address: 0x00860FB0 (FUN_00860FB0, `msvc8::map<std::int32_t,
             * Moho::ProjectileArcTrack>::erase(const_iterator)` --
             * `ProjectileArcTrack` is a 0xC30-byte value_type (fixed-size
             * sample buffer + scalar fields), landing colour/isNil at
             * `[node+0xC38]`/`[node+0xC39]` (0xC38 = header + 4-byte key +
             * 0xC30 value, 8-aligned) -- decimal 3144/3145 in the raw
             * decompile. Same `_Isnil` guard throwing `out_of_range("invalid
             * map/set<T> iterator")`, same successor-lift-and-rebalance shape
             * as every other emission of this member; operates on a
             * function-local `static` tree (`ProjectileArcTable& ArcTable()`
             * in ProjectileArcRenderer.cpp), which is why the decompile reads
             * `dword_10C4318`/`dword_10C431C` as fixed globals rather than a
             * `this`-relative head. Reached from `arcTable.erase(expiredKey)`
             * in `RenderProjectileArcs` (FUN_008600E0, ProjectileArcRenderer.cpp)
             * via the erase-by-key overload's inner `erase(find(key))` call.)
             */
            /**
             * Address: 0x006E1670 (FUN_006E1670, sub_6E1670) --
             * `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
             * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15.
             * Matches this member exactly: `_Isnil` guard throwing
             * `out_of_range("invalid map/set<T> iterator")`, captures the
             * successor via the map's `Iterator::inc` (`rb_increment`) before
             * unlinking, calls `sub_6E1F90`/`sub_6E1F70` (`rb_min`/`rb_max`,
             * cited above) to re-seat `head->left`/`head->right` only when the
             * erased node was an extremum, and `sub_6E1F20`/`sub_6E1FD0`
             * (`rotate_left`/`rotate_right`, cited above) in the rebalance
             * loop. Reached from `Moho::CCommandDB::RemoveCmd`
             * (FUN_006E0EC0) with three further real callers
             * (`Moho::CUnitCommand::~CUnitCommand`, `Moho::UNIT_IssueCommand`,
             * `Moho::UNIT_IssueFactoryCommand`). Re-homed here from a bespoke
             * `EraseCommandNode` free function in Sim.cpp that hand-rolled
             * this same CLRS-style transplant-and-rescan erase over a
             * `CommandDbMapStorageView`/`CommandDbMapNodeView` reach-in --
             * that hand-rolled version did not match this address's real
             * disassembly (it recomputed both header extrema unconditionally
             * via a full-tree rescan instead of this member's targeted
             * `rb_min`/`rb_max` patch), so it was deleted rather than kept as
             * an alternate-but-equivalent implementation.)
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
            /**
             * Address: 0x0052D9C0 (FUN_0052D9C0, erase-range for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * `msvc8::set<uint32_t>`, `_Isnil` at +0x11. Same two-shape
             * split as the emissions above: the whole-tree fast path calls
             * `sub_52CCF0` on the root (`destroy_subtree`, cited below) when
             * `first == begin() && last == end()`; otherwise it walks
             * `erase(_First++)` with the successor computed inline and
             * `sub_52F0A0` (`erase_node`, cited above) erasing the old
             * cursor each turn. Reached from `FUN_0052A390`
             * (`~rb_tree`, cited above) with `[leftmost(), header())` --
             * always the whole-tree fast path in that caller.)
             * Address: 0x007B3E00 (FUN_007B3E00, erase-range for the sibling
             * `msvc8::set<std::uint32_t>` instantiation cited on
             * `destroy_subtree`/`erase_node` above -- `_Isnil` at +0x11. Same
             * two-shape split: whole-tree fast path calls `sub_7B4D10`
             * (`destroy_subtree`) on the root when `first == begin() && last
             * == end()`; otherwise walks `erase(_First++)` via `sub_7B46A0`
             * (`erase_node`). Reached from three explicit destroy-and-
             * reconstruct helpers in `moho/sim/SimRecoveryRuntime.cpp`
             * (`ClearTreeStorageLaneC21Runtime` 0x007B2940,
             * `ClearEmbeddedSecondaryTreeLaneRuntime` 0x007B2970,
             * `ClearTreeStorageLaneD21Runtime` 0x007B36A0), each calling
             * `.~set()` on its owner lane, always with `[leftmost(),
             * header())` (verified directly against each caller's `.asm` --
             * `mov ecx,[eax]`/push header pair pushed as `first`/`last` before
             * `call sub_7B3E00`) -- always the whole-tree fast path from
             * those three callers, matching `FUN_0052A390`'s sibling shape.
             * Also reached from the same tree's copy machinery on the
             * exception path: `_Copy`'s emission (`FUN_007B4980`) calls this
             * member's `destroy_subtree` half directly (not through
             * `erase_range`) to unwind a partially-copied subtree before
             * rethrowing, and `FUN_007B3EC0` (the copy constructor) is
             * `_Copy`'s only caller -- both currently misclassified
             * `external_dependency` in `recovered_progress.json` pending a
             * dedicated pass; not corrected here since neither is this
             * batch's assigned token, flagged for whoever picks up
             * `FUN_007B4980`/`FUN_007B3EC0` next.)
             */
            /**
             * Address: 0x006E22D0 (FUN_006E22D0, the command-id map's range
             * erase -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
             * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15,
             * node 0x18. Same two-shape split as the emissions above:
             * `first == begin() && last == end()` takes the whole-tree fast
             * path, calling `sub_6E2990` (`destroy_subtree`, cited below);
             * otherwise walks `erase(_First++)`. Reached from
             * `~CommandDatabase` (FUN_006E0A70, cited on `~rb_tree` above)
             * with `[leftmost(), header())` -- always the whole-tree fast
             * path from that caller. `CCommandDb::MemberDeserialize`
             * (FUN_006E1430) does *not* call this member -- a prior recovery
             * pass wired an `erase(begin(), end())` call into that function
             * that the binary's own disassembly does not contain;
             * deserialization only ever runs against a freshly constructed,
             * still-empty map, so removing that fabricated call did not
             * change behaviour.)
             *
             * Address: 0x00947B90 (FUN_00947B90, isNil@+0x15 -- same two-shape
             * split confirmed against the walked callee bodies: the whole-tree
             * fast path calls `sub_9470E0` (recursive delete-all with no
             * rebalancing, matching `destroy_subtree`'s shape exactly) on
             * `header()->parent` (the root), then resets `header()->parent`,
             * `_Mysize` and `header()->left`/`header()->right` to `header()`
             * and returns `leftmost()`; otherwise walks `erase(_First++)` via
             * `sub_947380`, whose body is a full RB-tree single-node
             * erase-with-rebalance (out_of_range throw on an already-nil
             * iterator, unlink, recolour/rotate through sibling helpers,
             * `operator delete` the node, decrement size) matching
             * `erase_node` exactly. Reached from
             * `gpg::gal::StateCache<_D3DRENDERSTATETYPE,unsigned int>::~StateCache`
             * (FUN_00948190, StateCache.cpp) -- its own disassembly at
             * 0x009481AC calls `sub_947B90(&tree_, &cursor, *(*(this+8)),
             * *(this+8))`, i.e. `tree_.erase_range(tree_.begin(), tree_.end())`,
             * followed by an explicit `operator delete` on the pointer that
             * was passed as `last`/`header()`. NOTE FOR A FUTURE STATECACHE
             * PASS: this proves `StateCache<StateT,ValueT>::tree_`'s real
             * layout is a proper header-pointer-owning RB-tree (the header
             * node is separately heap-allocated and must be explicitly
             * freed after the erase), not the currently-modelled
             * `msvc8::EmbeddedTree<>` (`legacy/containers/Tree.h`, embedded
             * by-value head, no-arg `clear()`) that
             * `StateCache_D3DRENDERSTATETYPE.hpp`/`StateCache.cpp` use today
             * -- `~StateCache`'s recovered body currently calls
             * `tree_.clear()`, which is a different, narrower operation than
             * the two-arg `erase_range(begin,end)` + separate header
             * `delete` this address actually performs. Not corrected here
             * (would require retyping `tree_` across all three `StateCache`
             * specialisations, out of scope for this token); flagged for
             * whoever next touches `StateCache`.)
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
            /**
             * Address: 0x0077B4F0 (FUN_0077B4F0, inner bucket range erase)
             * Address: 0x00779B80 (FUN_00779B80, inner bucket storage release)
             * Address: 0x0077B7D0 (FUN_0077B7D0, its typed wrapper)
             * Address: 0x00779240 (FUN_00779240, outer map storage release)
             * Address: 0x0077AC30 (FUN_0077AC30, its typed wrapper)
             */
            /**
             * Address: 0x00687220 (FUN_00687220)
             * Address: 0x00687B90 (FUN_00687B90, mirror emission)
             *
             * `msvc8::map<std::uint32_t, moho::IdPool>::clear` --
             * `CEntityDb::mIdPoolTree` in `EntityDb.h`. Destroys the subtree
             * from the root (`FUN_00688030`, cited on `destroy_subtree`
             * above) then rewires the sentinel head back to self-linked
             * empty form with zero size -- exactly this member's shape.
             */
            /**
             * Address: 0x006E2810 (FUN_006E2810) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. Destroys the subtree from the root via
             * `FUN_006E2990` (`destroy_subtree`, cited above) then rewires
             * `head->parent`/`head->left`/`head->right` back to self-linked
             * empty form with `size=0` -- exactly this member's shape. Zero
             * incoming xrefs in this sweep. Re-homed here from a bespoke
             * `ClearCommandDbMapAndResetHead` free function in Sim.cpp that
             * hand-rolled this same operation over a `CCommandDbRuntimeView`
             * reach-in instead of calling it.)
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
            /**
             * Address: 0x0071D740 (FUN_0071D740, `map<uint32_t,
             * InfluenceMapEntry>::allocator<_Node>::allocate` -- same shape,
             * node size 0x40 (0xFFFFFFFF/n compared against 0x40, then
             * operator new(n<<6)). Reached from `InfluenceGrid::entries`'s
             * node-buy path via FUN_0071C2C0, called from
             * `EraseInfluenceEntryAndAdvance`'s caller chain at
             * CInfluenceMap.cpp. 0x40 = 0x0C header + 0x04 key + 0x2C
             * InfluenceMapEntry value + color/isNil, rounded up -- confirms
             * the map<uint32_t,InfluenceMapEntry> node typing from the
             * rotate_left/rotate_right citations above.)
             */
            /**
             * Address: 0x00688180 (FUN_00688180, `Mangled: std::map_uint_IdPool
             * ::_Node allocator` -- `msvc8::map<std::uint32_t, moho::IdPool>`,
             * `CEntityDb::mIdPoolTree` in `EntityDb.h`. Pure raw allocation:
             * `operator new(sizeof(node_type))` with no field writes of its
             * own -- the caller (`FUN_006881C0`, `buy_node` below) writes
             * every link/value/colour field afterward. Node size 0xCD0 =
             * 0x10 (link triplet + 8-byte-aligned pad, see `IdPool`'s
             * `alignas(8)` citation in IdPool.h) + 0xCB8 (`pair<const
             * uint32_t, IdPool>`, itself 8-byte aligned so its `IdPool`
             * member lands at `node+0x18` rather than `node+0x10`) + 2
             * (colour/isNil) rounded to the type's own 8-byte alignment.
             * Reached from `insert_at`'s emission FUN_00687280, cited
             * below.)
             */
            /**
             * Address: 0x006E28A0 (FUN_006E28A0) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. Thin wrapper over `FUN_006E2D90` (the
             * `operator new(sizeof(node_type))` call proper, matching
             * `buy_node`'s own `sub_6E23F0` allocation path's inner shape),
             * matching this member's role. Zero incoming xrefs in this
             * sweep. Re-homed here from a bespoke
             * `AllocateSingleCommandDbMapNodeStorage` free function in
             * Sim.cpp.)
             */
            [[nodiscard]] static node_type* alloc_raw()
            {
                return static_cast<node_type*>(::operator new(sizeof(node_type)));
            }

            /**
             * Address: 0x006874A0 (FUN_006874A0)
             * Address: 0x00687830 (FUN_00687830, mirror emission)
             *
             * `msvc8::map<std::uint32_t, moho::IdPool>`'s bare node-storage
             * release -- `CEntityDb::mIdPoolTree` in `EntityDb.h`. Plain
             * `operator delete(n)`, matching this member exactly.
             */
            /**
             * Address: 0x006E2080 (FUN_006E2080) Address: 0x006E2470
             * (FUN_006E2470, duplicate emission) -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. Both are plain `::operator delete(n)`
             * one-liners with no value_type-specific behaviour, matching
             * this member exactly. Zero incoming xrefs in this sweep.
             * Re-homed here from bespoke `DeleteCommandDbAllocationLaneA`/
             * `...LaneB` free functions in Sim.cpp.)
             */
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
             *
             * Address: 0x00581330 (FUN_00581330, msvc8::map<Wm3::Vector2i,
             * SBuildReserveInfo>::buy_head -- via alloc_raw's 40-byte lane
             * FUN_00582460, already cited on AllocateCheckedElementBlock in
             * Vector.cpp. Node size 12+sizeof(pair<Vector2i(8),
             * SBuildReserveInfo(16)>)+2 = 38, rounded to 40; isNil@+0x25
             * matches. Reached from `CAiBrain::mBuildStructureMap{}`'s
             * default member-init in CAiBrain.cpp.)
             * Address: 0x007E4B80 (FUN_007E4B80, buy_head for the
             * `Moho::MeshRenderer::meshes` batch-bucket map -- via
             * alloc_raw's already-cited FUN_007E5740 ("batch-bucket map
             * allocator<_Node>::allocate", 0x30=48-byte node). isNil@+0x2D
             * matches the same batch-bucket node shape documented
             * throughout this file. Reached from `meshes()`'s default
             * member-init in `MeshRenderer::MeshRenderer` -- editing that
             * caller's own citation is deferred to whichever pass lands
             * the in-flight MeshBatchBucketTree/msvc8::map conversion
             * currently in progress in Mesh.cpp/MeshBatchKey.*, since this
             * file is under active concurrent edit.)
             * Address: 0x007CAB70 (FUN_007CAB70, buy_head for
             * `Moho::SPeer::establishedUids` -- msvc8::set<int32_t>, node
             * 12+4+2=18 rounded to 20, isNil@+0x11 matches, via alloc_raw's
             * already-cited 20-byte lane FUN_007CC1C0. Reached from
             * `establishedUids()`'s default member-init in SPeer's ctor,
             * SPeer.cpp.)
             * Address: 0x007F2BB0 (FUN_007F2BB0, buy_head for the
             * function-local static `BlueprintExtractorRegistry registry`
             * -- std::map<std::string,unique_ptr<RangeExtractor>>, node
             * 12+sizeof(pair<string(28),ptr(4)>)+2 = 46, rounded to 48;
             * isNil@+0x2D matches the batch-bucket node shape. Reached
             * from `GetBlueprintExtractorRegistry()`'s lazy first-time
             * static-local construction, RangeExtractor.cpp.)
             * Address: 0x0052F370 (FUN_0052F370, buy_head for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals`
             * -- `msvc8::set<uint32_t>`, same 12+4+2=18-rounded-to-20 node
             * shape as `Moho::SPeer::establishedUids` above, isNil@+0x11.
             * The binary splits allocation and self-link across the call
             * site: `ExportToLuaState` (0x0052A28E-0x0052A2AF) calls
             * `sub_52F370` for the raw node, then self-links
             * `left=parent=right=self` and sets `isNil=1` inline -- this
             * template fuses both steps into `buy_head()` itself, matching
             * every other instantiation's citation style in this file.
             * Reached from `AddOrGetExportBinding`'s claim of a fresh
             * binding slot in RRuleGameRules.cpp, via
             * `msvc8::set<uint32_t>`'s default constructor.)
             * Address: 0x00A583C0 (FUN_00A583C0, `alloc_raw` half of buy_head
             * for the "unidentified map<int32_t,T> instantiation" family
             * already cited on `buy_node` below (sibling node-buy
             * FUN_00A58450, 36-byte node, at 0x00A58450 -- immediately
             * adjacent in the binary): `operator new(0x14)`, zeroes the
             * three link dwords, sets byte+0x10=1/byte+0x11=0. Its caller
             * FUN_00A5A000 (4 callers of its own: FUN_00A5A000/
             * FUN_00A5D943/FUN_00A66233/FUN_00A67840) does the self-link and
             * flag fixup this template's `buy_head()` performs inline --
             * `left=parent=right=self`, then overwrites byte+0x11=1 (isNil)
             * -- the same allocate/self-link split already documented for
             * FUN_0052F370 above. Node shape (20 bytes, no value slot) is
             * head-only, matching a `msvc8::set<int32_t>`-style sentinel for
             * the same map whose value-bearing node buy is FUN_00A58450.)
             * Address: 0x00A58370 (FUN_00A58370, another `alloc_raw` half of
             * buy_head for a sibling "unidentified map<int32_t,T>
             * instantiation" -- byte-for-byte the same shape as FUN_00A583C0
             * above (`operator new(0x14)`, zero the three link dwords,
             * byte+0x10=1/byte+0x11=0), but a distinct COMDAT with its own
             * caller family: FUN_00A59FC0 (call at 0x00A59FC3), FUN_00A5D913,
             * FUN_00A66203, and FUN_00A67120 (call at 0x00A671E2) -- none
             * recovered yet, so the owning map/set instantiation is not
             * identified. Same 20-byte headless-node shape as FUN_00A583C0's
             * cluster.)
             */
            /**
             * Address: 0x00684230 (FUN_00684230, `Moho::EntityDB::EntityDB` --
             * `msvc8::map<std::uint32_t, moho::IdPool>`, `CEntityDb::
             * mIdPoolTree` in `EntityDb.h`. The binary inlines buy_head's
             * allocate-then-self-link-then-isNil=1/color=black sequence
             * directly into the owning class's constructor rather than
             * through a named `buy_head` symbol (the raw allocation is
             * `FUN_00688180`, cited on `alloc_raw` above) -- this member
             * fuses those steps into one call, matching every other
             * constructor-inlined instantiation already cited here. Reached
             * from `mIdPoolTree`'s default member-initialization, `EntityDb.h`.)
             */
            /**
             * Address: 0x00685720 (FUN_00685720)
             * Address: 0x006864A0 (FUN_006864A0, sibling emission)
             * Address: 0x00687250 (FUN_00687250, sibling emission)
             *
             * Further `msvc8::map<std::uint32_t, moho::IdPool>` sentinel-head
             * allocate/self-link/isNil=1 emissions -- `CEntityDb::mIdPoolTree`,
             * `EntityDb.h`. Same fused shape as `FUN_00684230` above, emitted
             * at other construction call sites (e.g. placement-new via
             * `EntityDbTypeInfo::CtrRef`/`NewEntityDbTypeLaneRef`, EntityDb.cpp).
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
            /**
             * Address: 0x00A58450 (FUN_00A58450, the unidentified `map<int32_t, T>`
             * instantiation's node buy -- `operator new(0x24)`, writes the three
             * link fields at `+0x00`/`+0x04`/`+0x08`, copy-constructs the 20-byte
             * value at `+0x0C`, colour at `+0x20`, nil at `+0x21`. Reached from
             * `insert_at`'s call site cited above (0x00A63950).)
             */
            /**
             * Address: 0x00581370 (FUN_00581370, `msvc8::map<Wm3::Vector2i,
             * SBuildReserveInfo>::buy_node` -- `CAiBrain::mBuildStructureMap`,
             * the node-buy sibling of `buy_head` (0x00581330, cited above on
             * `alloc_raw`). `_Buynode(_Larg, _Parg, _Rarg, value)` shape:
             * allocates one 40-byte node via the same `alloc_raw` lane
             * (`sub_582460(1)`, already cited on `AllocateCheckedElementBlock`
             * in Vector.cpp), writes `left@+0`/`parent@+4`/`right@+8` straight
             * from its first three arguments (the caller, `_Insert`
             * FUN_00580720, passes the tree's `head_` for both `left` and
             * `right` and the insertion-point `where` node for `parent`),
             * copy-constructs the 24-byte `pair<const Wm3::Vector2i,
             * SBuildReserveInfo>` value in place at `+0x0C` through
             * `sub_5816C0` (the pair's copy ctor -- not independently cited
             * yet), then zeroes `color@+0x24`/`isNil@+0x25` -- matching
             * `buy_head`'s "38, rounded to 40" node-size note exactly. Reached
             * from FUN_00580720's `_Insert`, which is not yet recovered
             * source itself.)
             */
            /**
             * Address: 0x0077CD00 (FUN_0077CD00, inner bucket node allocate)
             * Address: 0x0077C690 (FUN_0077C690, its clone-from-source form)
             * Address: 0x0077CAE0 (FUN_0077CAE0, outer map value node; emitted again at
             * 0x0077DC40)
             */
            /**
             * Address: 0x0052DB50 (FUN_0052DB50, the node buy for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals`
             * -- `msvc8::set<uint32_t>`. `_Buynode(_Larg, _Parg, _Rarg,
             * ordinal, _Color)` shape: allocates via `sub_533620(1)`, writes
             * `left@+0`/`parent@+4`/`right@+8` from its first three
             * arguments directly (parent is the caller's `where` node, not
             * re-parented after the fact the way this template's `buy_node`
             * + `link_and_rebalance` split it), copies the 4-byte ordinal
             * value at `+0x0C` -- confirming a `uint32_t` value_type, not an
             * 8-byte `pair<const uint32_t, RBlueprint*>` -- then writes
             * `color@+0x10` and `isNil=0@+0x11`. Reached from `insert_at`,
             * 0x0052CD30.)
             */
            /**
             * Address: 0x00830110 (FUN_00830110, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s node buy -- allocates one node via
             * `sub_831D10(1)`, writes `left`/`parent`/`right` from its first
             * three arguments (the caller passes `where` for both `left` and
             * `right` initially, matching this template's head-initialised
             * `n->left = n->parent = n->right = head_` before the value is
             * constructed), constructs the 0x18-byte value in place through
             * `sub_830B20` (the `pair<shared_ptr<CD3DBatchTexture>,
             * vector<CommandGraphEdge*>>` value ctor CWldSession.cpp's
             * `AddCommandQueueToCommandGraph` notes name 0x0082D330 for --
             * "retain the texture, default the vector"), then writes
             * `color=0@+0x24`/`isNil=0@+0x25`. Unique body (no ICF twins);
             * reached from `insert_at`'s emission FUN_0082E320 above.)
             */
            /**
             * Address: 0x005569C0 (FUN_005569C0, the category-lookup map's
             * node buy -- `msvc8::map<msvc8::string, moho::CategoryLookupValue>`,
             * `Sim.cpp`'s `EntityCategoryLookupTableView::mCategoryMap`.
             * `recovered_progress.json` already tracks this address `skip`
             * (RULE ONE: compiler emission, no hand-written body) with the
             * note "_Myval at +0x10"; this citation is the instantiation that
             * note refers to. Allocates one 0x60-byte node via `sub_5579D0(1)`
             * (`operator new(0x60 * count)`), writes `left`/`right` to the
             * caller's head argument and `parent` to the caller's `where`,
             * then constructs the value in place at `node+0x10` through
             * `sub_557310` and zeroes `color`/`isNil` at `node+0x58`/
             * `node+0x59`. `sub_557310` (FUN_00557310) is `value_type`'s
             * (`pair<const msvc8::string, CategoryLookupValue>`) implicit
             * *copy* constructor -- it assigns the key via
             * `msvc8::string::assign` and copies the three `CategoryLookupValue`
             * fields (`mUniverse`/`mBits.mFirstWordIndex`/`mBits.mWords`) from
             * its source argument's +0x20/+0x28/+0x30, i.e. from an
             * already-fully-formed `value_type&` -- the same `args` this
             * `buy_node` forwards from `insert_at`'s single `const value_type&`
             * parameter. It is a compiler/template emission with no
             * hand-written body of its own (RULE ONE), exactly like this
             * `buy_node` member; writing `::new (...) value_type(v)` here
             * (already the case, unmodified) is what makes the compiler emit
             * it. The `node+0x10` destination -- not the
             * usual `node+0x0C` -- is the primary evidence for
             * `CategoryLookupValue`'s 8-byte alignment (Sim.cpp citation
             * block). Reached from `insert_at`'s emission (FUN_005565D0,
             * cited above).)
             */
            /**
             * Address: 0x00535CA0 (FUN_00535CA0, the RRuleGameRulesBlueprintMap
             * (`msvc8::map<msvc8::string, void*>`) node buy for the
             * RTrailBlueprint instantiation -- same family as the seven
             * `insert_unique`/predecessor-lookup addresses cited above
             * (0x00534690 / insert_at FUN_00535400 / predecessor lookup
             * FUN_00536470). Allocates one node via `sub_533AD0(1)`
             * (`operator new(count)`), writes `left`/`parent`/`right` from
             * the caller's `where`/`head` arguments, then constructs
             * `value_type` (`pair<const msvc8::string, void*>`) in place at
             * `node+0x0C` from the `const value_type&` argument: the key is
             * built via `msvc8::string::assign(src, 0, 0xFFFFFFFF)` (full
             * copy into the SSO buffer at `node+0x10`, `_Mysize`@+0x20,
             * `_Myres`@+0x24=0xF) and the `void*` value is copied straight
             * from the source pair's `+0x1C` (`.second`) into `node+0x28`,
             * matching the `isNil@+0x2D = 0x0D + sizeof(pair<string(28),
             * void*(4)>)=0x20` node size FUN_005364D0's citation already
             * established for this map type. This is a compiler/template
             * emission of `::new (...) value_type(args...)` with no
             * hand-written body of its own (RULE ONE), exactly like
             * FUN_005569C0 above -- `recovered_progress.json` tracks it
             * `skip` for that reason. Reached from `insert_at`'s emission
             * FUN_00535400, itself reached from `insert_unique`'s emission
             * FUN_00534690 cited above.)
             */
            /**
             * Address: 0x00950430 (FUN_00950430, node buy for an unidentified
             * `msvc8::map<K,V>`/`msvc8::set<T>` instantiation with a 24-byte
             * `value_type` -- `operator new(0x28)` (40 bytes: 12 link dwords
             * + 24-byte value + 2 flag bytes, rounded), `_Buynode(_Larg,
             * _Parg, _Rarg, val, _Color)` shape: `left`/`parent`/`right`
             * written from its first three arguments (the caller passes the
             * same `where` node for both `left` and `right`, matching this
             * template's head-initialised `n->left = n->parent = n->right =
             * head_`), the 24-byte value block-copied (6 dwords) from a
             * `const value_type&` fourth argument, then `color` from a
             * literal-0 fifth argument and `isNil = 0`. Reached from
             * FUN_009512B0, which matches `insert_at`'s shape precisely:
             * checks the tree's size against the `0xAAAAAAA9` max_size
             * bound for a 24-byte-ish node family and throws
             * `std::length_error("map/set<T> too long")` on overflow (the
             * exact message this template's own `insert_at`/`_Xlen` overflow
             * guard uses elsewhere in this file), then calls this node-buy
             * lane, links the fresh node in as the RB-tree insertion target,
             * and rebalances via sub_94FA60/sub_94FAB0 (the tree's rotation
             * helpers). No source-level owner has been pinned down for this
             * specific `K,V` pair beyond the 24-byte value size; documented
             * at the same confidence level as the "unidentified
             * map<int32_t,T> instantiation" family cited on `buy_head`
             * above.)
             */
            /**
             * Address: 0x006881C0 (FUN_006881C0, `msvc8::map<std::uint32_t,
             * moho::IdPool>::_Buynode` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. Allocates via `FUN_00688180` (`alloc_raw`, cited
             * above), writes `left`/`right`=head and `parent`=the caller's
             * `where` (all three from its own arguments rather than a fixed
             * `head_` reread, a compiler optimisation, not a different
             * operation), writes the key at `node+0x10`, copy-constructs the
             * `IdPool` payload at `node+0x18` via `FUN_00686DF0` (already
             * recovered as `CopyIdPoolPayloadForMapLanes`, `IdPool.cpp`), and
             * zeroes `color`/`isNil` at `node+0xCC8`/`node+0xCC9`. The
             * `node+0x18` destination -- not the usual `node+0x0C` -- is the
             * primary evidence for `IdPool`'s `alignas(8)` (see the citation
             * block on that type in IdPool.h); this member's plain `V value;`
             * member declaration reproduces the exact same offset
             * automatically once `IdPool` carries that alignment, with no
             * template change needed. Reached from `insert_at`'s emission
             * FUN_00687280, cited below.)
             */
            /**
             * Address: 0x006E23F0 (FUN_006E23F0, the command-id map's node
             * buy -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
             * `Moho::CCommandDb::commands` in `CCommandDb.h`. Allocates one
             * 0x18-byte node via `sub_6E2D90(1)`, writes `left`/`parent`/
             * `right` from its first three arguments, the 8-byte value
             * (`CmdId` + `CUnitCommand*`) copied from the fourth argument's
             * two words, then `color=0`/`isNil=0` at `+0x14`/`+0x15`. Its
             * only incoming xref is a direct `call` from `insert_at`'s
             * emission FUN_006E1D60, cited below -- a prior recovery pass
             * mis-cited this address as a 4-scalar-argument
             * "priority-queue-node" allocator in
             * `moho/sim/SimRecoveryRuntime.cpp`, which does not match either
             * this real parameter shape or the real (sole) caller; not
             * corrected there in this pass since that file is untouched
             * here, flagged for a follow-up.)
             */
            /**
             * Address: 0x008B67F0 (FUN_008B67F0, sub_8B67F0) --
             * `msvc8::map<Moho::CmdId, Moho::UserCommandIssueHelper*>`,
             * `CommandManager::mCommands` in `CommandManager.h`. Same shape
             * as FUN_006E23F0 above (a separate instantiation): allocates one
             * raw node via `sub_8B6AC0(1)` (`alloc_raw`), writes the key/
             * value pair from its arguments, then `color=0`/`isNil=0`.
             * Reached from `insert_at`'s emission FUN_008B6310, cited below.
             * Re-homed here from the same bespoke `AllocateCommandNode`/
             * `InsertCommandNode` free-function pair in Sim.cpp cited on
             * `insert_unique` above.)
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

            /**
             * Address: 0x0077C6F0 (FUN_0077C6F0, the decal tree node delete lane;
             * emitted again at 0x0077CF50)
             * Address: 0x007E5850 (FUN_007E5850, `value_type::~value_type()` for the
             * mesh-key map -- `moho::MeshRendererMeshCacheEntry` in
             * `moho/mesh/Mesh.h`, `_Isnil` at +0x25 (`sizeof(value_type)` == 0x18,
             * matching `0x0D + 0x18`). Reached from that map's `erase_node`
             * (0x007E4430) and `destroy_subtree` (0x007E4DD0), both already cited
             * above as sibling emissions.
             *
             * The two members are torn down in reverse declaration order, exactly
             * matching a plain `~MeshRendererMeshCacheEntry()`:
             *   - first, the second-declared member's boost control-block pointer
             *     at value+0x14 (`[esi+0x14]`) is released with a lone
             *     `weak_count_` decrement (value+0x14+0x08) followed by a single
             *     dispatch through vtable slot +0x08 (`destroy()`) -- there is no
             *     `use_count_` touch and no `dispose()` call anywhere in that
             *     block. That is `boost::detail::sp_counted_base::weak_release()`
             *     (see `BoostWrappers.h`'s `weak_release()` and the
             *     0x00446FC0/FUN_004229B0 audit note there), not a shared-owner
             *     release. `Mesh.h` currently types that member
             *     `boost::shared_ptr<Mesh>`, which would compile to a two-step
             *     use_count_-then-weak_count_ release (the shape `~MeshKey`
             *     itself shows below) -- this emission proves the shipped field is
             *     `boost::weak_ptr<Mesh>` instead. `Mesh.h`/`Mesh.cpp` are under
             *     concurrent edit by another recovery pass as of this citation, so
             *     the field is not retyped here; this note is the handoff.
             *   - second, the first-declared member (`MeshKey`) is released
             *     in-line with the exact same vtable-restore-plus-shared_ptr-
             *     release body as `Moho::MeshKey::~MeshKey` (0x007DAF60):
             *     `this->__vftable = &MeshKey::vftable`, then the two-step
             *     use_count_/weak_count_ release of `meshMaterial`'s control
             *     block. MSVC inlines the base's destructor body here rather
             *     than calling 0x007DAF60, which is why 0x007DAF60 shows only as
             *     a data ref from this function's SEH unwind funclet
             *     (`mov ecx,[ebp+4]; jmp ??1MeshKey@Moho@@UAE@XZ`), not as a
             *     direct call.
             */
            /**
             * Address: 0x0082BEE0 (FUN_0082BEE0, `value_type::~value_type()`
             * for `Moho::UICommandGraph::mGraphRuntimeTree` --
             * `pair<shared_ptr<CD3DBatchTexture>, vector<CommandGraphEdge*>>`,
             * isNil@+0x25. Inlined ahead of `operator delete(node)` in the
             * `erase_node` emission FUN_0082FD50 (cited above) rather than
             * called out-of-line as a separate `free_node` body -- the
             * generic `n->value.~value_type()` this member already performs
             * covers it. Tears the second-declared member (the
             * `vector<CommandGraphEdge*>`) down first: frees its buffer with
             * `operator delete` when non-null and zeroes the three
             * begin/end/capacity words, then releases the first-declared
             * `shared_ptr<CD3DBatchTexture>`'s control block with the same
             * interlocked use-count/weak-count decrement and vtable
             * `dispose()`/`destroy()` dispatch pair documented for
             * `sp_counted_base::release()` elsewhere in this codebase (see
             * `BoostWrappers.h`'s `weak_release()`/`release()` note and the
             * 0x004229B0 audit). Members are torn down in reverse
             * declaration order, matching a plain compiler-generated
             * `~pair()` -- there is no hand-written source for this
             * function; it is the implicit destructor MSVC emits for the
             * pair once `shared_ptr<T>` and `vector<U*>` are recovered
             * types, exactly like the mesh-key map's 0x007E5850 sibling
             * above.)
             */
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
            /**
             * Address: 0x0052CCF0 (FUN_0052CCF0, the whole-subtree destroy for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * `msvc8::set<uint32_t>`. Reached from `FUN_0052D9C0`
             * (`erase_range`, cited above) with the root
             * (`_Myhead->_Parent`) when `erase_range`'s whole-tree fast path
             * is taken, matching the other three sibling emissions' shape.)
             * Address: 0x00592C00 (FUN_00592C00, the whole-subtree destroy for
             * `CArmyStatItem::mBlueprintStats` -- 8-byte value_type, isNil
             * confirmed at +0x15 (0x0D + 8). Reached from `clear()`
             * (0x00592230, cited above) via `CArmyStatItem::~CArmyStatItem`
             * at 0x00585C39.)
             * Address: 0x00531490 (FUN_00531490, the whole-subtree destroy for
             * `RRuleGameRulesImpl`'s seven blueprint maps -- `RRuleGameRulesBlueprintMap`
             * = `msvc8::map<msvc8::string, void*>` (`moho/sim/RRuleGameRules.h`),
             * isNil confirmed at +0x2D (0x0D + sizeof(pair<string(28), void*(4)>) = 0x2D).
             * The recursed-into left/right lanes match this shape exactly, and the
             * per-node teardown additionally frees the key's heap SSO buffer when
             * `_Myres >= 0x10` before resetting `_Myres=0xF`/`_Mysize=0`/first SSO
             * byte and `operator delete`-ing the node -- the `msvc8::string`
             * destructor inlined ahead of `free_node`'s node release, exactly like
             * the mesh-key map's `value_type::~value_type()` inlining documented on
             * `free_node` below. Reached from `erase_range`'s (`FUN_0052E510`)
             * whole-tree fast path, itself reached implicitly: `mUnitBlueprints`,
             * `mProjectileBlueprints`, `mPropBlueprints`, `mMeshBlueprints`,
             * `mEmitterBlueprints`, `mBeamBlueprints` and `mTrailBlueprints` are
             * direct-value members of `RRuleGameRulesImpl` (`RRuleGameRules.h`), so
             * `~RRuleGameRulesImpl()`'s implicit member teardown -- documented in
             * that destructor's own comment as "each map's destructor frees its own
             * nodes and sentinel head... open-coded seven times" -- instantiates
             * `msvc8::map<msvc8::string, void*>::~map()` for each one, which is
             * this `clear()`/`destroy_subtree` pair. No hand-written call site is
             * needed beyond the member declarations already in `RRuleGameRules.h`.)
             * Address: 0x007B4D10 (FUN_007B4D10, whole-subtree destroy for an
             * `msvc8::set<std::uint32_t>` instantiation -- isNil@+0x11
             * (0x0D + sizeof(std::uint32_t) = 0x11), plain 4-byte value with no
             * heap-owning member, matching a bare `operator delete(node)` release
             * with no inlined value-dtor work. Owning field not yet pinned to a
             * specific class (multiple owners share this exact node shape, e.g.
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` at the
             * unrelated address 0x0052CCF0 above); reached from `erase_range`'s
             * (`FUN_007B3E00`, cited below) whole-tree fast path, itself called
             * directly (`call sub_7B3E00`, hardcoded) from three sibling
             * `msvc8::set<std::uint32_t>` explicit destroy-and-reconstruct helpers
             * in `moho/sim/SimRecoveryRuntime.cpp` --
             * `ClearTreeStorageLaneC21Runtime` (0x007B2940),
             * `ClearEmbeddedSecondaryTreeLaneRuntime` (0x007B2970) and
             * `ClearTreeStorageLaneD21Runtime` (0x007B36A0), each of which calls
             * `.~set()` on its owner lane -- the same explicit-destroy-and-
             * reconstruct idiom as `ReleaseExportBindingPendingOrdinals`
             * (`RRuleGameRules.cpp`) uses for the sibling instantiation above.)
             */
            /**
             * Address: 0x00688030 (FUN_00688030, `msvc8::map<std::uint32_t,
             * moho::IdPool>::_Erase` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. Reached two ways: from this member's own `clear()`
             * (cited above) during `EntityDbIdPoolMapTypeInfo::SerLoad`'s
             * clear-before-repopulate step (binary:
             * `std::map_IdPool::Deserialize`, FUN_00686990), and from
             * `~rb_tree()` (cited above) during `CEntityDb`'s destructor.
             * Confirmed the true argument is `head->parent` (root), not
             * `head->left` (leftmost) -- see the `~rb_tree()` citation's note
             * on the bug that distinction fixes.)
             */
            /**
             * Address: 0x006E2990 (FUN_006E2990, the command-id map's
             * subtree destroy -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`, isNil@+0x15. Self-recursive on the right
             * child (`sub_6E2990(v2[2])`) then loops down the left chain
             * (`v2 = *v2`) deleting each node as it goes -- exactly this
             * member's recurse-right/iterate-left shape. Confirmed the
             * owning instantiation via its sole non-recursive caller:
             * `erase_range`'s emission for this map (FUN_006E22D0, cited
             * above) calls it on the whole-tree fast path. Previously
             * marked `skip` in `recovered_progress.json` pending this
             * migration -- see `CCommandDb.cpp`'s history for the
             * hand-rolled `CommandDbMapNodeRuntime` tree this address used
             * to be (incorrectly) associated with.)
             * Address: 0x00947120 (FUN_00947120, isNil@+0x15 -- the same
             * 8-byte value_type node shape as 0x006E2990 above, but reached
             * from a different subsystem (`CScApp`'s vtable neighbourhood,
             * not `CCommandDb`), so this is a distinct `map`/`set`
             * instantiation with a matching layout rather than the same
             * field. Same recurse-right/iterate-left/`free_node` shape
             * (`call sub_947120` on `[node+8]`, `node=[node]`, delete the
             * carried-over pointer). Both non-recursive callers
             * (`FUN_00947290`, `FUN_00947C50`) are unrecovered in this pass,
             * so the owning `CScApp` member is not yet pinned down -- only
             * the tree-algorithm shape and node size are confirmed, matching
             * the precedent set by the unidentified 0x00A5xxxx-0x00A67xxx
             * rotate instantiation cited under `_Lrotate` below.)
             */
            /**
             * Address: 0x00505EC0 (FUN_00505EC0, whole-subtree destroy for an
             * unidentified `msvc8::map`/`msvc8::set` instantiation with a
             * 40-byte value_type -- isNil@+0x35 (0x0D + 0x28 = 0x35).
             * Recurses on the right child (`sub_505EC0(v2[2])`) then
             * iterates down the left chain (`v2 = *v2`), matching this
             * method's recurse-right/iterate-left shape exactly; no inlined
             * value-destructor work precedes `operator delete`, so the
             * 40-byte value is trivially destructible (same bare-delete
             * shape as FUN_007B4D10 above). Reached from `FUN_00505200`
             * (`EraseSpatialMapRange`, `Mesh.cpp`)'s whole-tree fast path
             * and from an unclassified code chunk at 0x00505CFC; owning
             * member not yet pinned down.)
             */
            /**
             * Address: 0x005317D0 (FUN_005317D0, whole-subtree destroy for
             * another `msvc8::map<msvc8::string, void*>` instantiation --
             * 32-byte value_type (28-byte string key + 4-byte pointer
             * value), isNil@+0x2D (0x0D + sizeof(pair<string(28),
             * void*(4)>) = 0x2D), the identical shape and formula to
             * FUN_00531490's `RRuleGameRulesImpl` blueprint-map citation
             * above: per node, frees the key's heap SSO buffer when
             * `_Myres >= 0x10` (`operator delete((void*)v1[4])`), resets
             * `_Myres=0xF`/`_Mysize=0`/the first SSO byte, then `operator
             * delete`s the node. Recurses right (`sub_5317D0(i[2])`) and
             * iterates left (`i = *i`), matching this method's shape
             * exactly. Distinct COMDAT from FUN_00531490 (a different
             * address, not ICF-folded), so this is either a coincidentally
             * identical sibling `map<string, void*>` member elsewhere or a
             * second instantiation the linker left unfolded; owning member
             * not yet pinned down. Reached from FUN_0052E8B0 (`erase_range`,
             * itself blocked pending this token's recovery) and an
             * unclassified code chunk at 0x0053091C.)
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
            /**
             * Address: 0x0077B0B0 (FUN_0077B0B0, the outer start-tick map)
             * Address: 0x0077C5E0 (FUN_0077C5E0, the inner bucket set)
             *
             * CDecalBuffer's start-tick table is `std::map<unsigned, std::set<CDecalHandle*>>`, so each member is emitted twice -- once for the 0x20 outer node (colour/nil at +0x1C/+0x1D) and once for the 0x14 inner node (+0x10/+0x11).
             */
            /**
             * Address: 0x00719690 (FUN_00719690, `InfluenceGrid::entries`'s
             * left rotate. Reached from `EraseInfluenceEntryAndAdvance`'s
             * `grid.entries.erase(current)` at CInfluenceMap.cpp via
             * FUN_00717EF0, whose own IDA type inference names the node
             * `std::map_uint_InfluenceMapEntry::_Node` -- i.e. the binary's
             * container is `map<uint32_t, InfluenceMapEntry>` keyed by
             * entityId, not the `msvc8::set<InfluenceMapEntry,
             * InfluenceMapEntryLess>` the current `entries` field is typed
             * as (isNil at +0x3D only lines up with a 4-byte key + 0x2C
             * value node, 0x0C+4+0x2C=0x3C/0x3D, not a bare 0x2C value node
             * at 0x38/0x39). The `entries` field type is a follow-up fix;
             * this rotate citation is unaffected since it targets the real
             * physical node regardless of the C++ container tag.)
             */
            /**
             * Address: 0x007E4E10 (FUN_007E4E10, the mesh-key map's left
             * rotate -- `_Isnil` at +0x25, same instantiation as the
             * `erase_node` sibling emission 0x007E4DD0 cited above.)
             */
            /**
             * Address: 0x0052DAB0 (FUN_0052DAB0, the left rotate for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals`
             * -- `msvc8::set<uint32_t>`, node 0x14, `_Isnil` at +0x11,
             * standard field order (`left@0`/`parent@+4`/`right@+8`), unlike
             * the swapped `[node+0x10]`/`[node+0x11]` instantiation cited
             * above. Reached from `insert_at`'s fixup loop, 0x0052CD30.)
             */
            /**
             * Address: 0x00830010 (FUN_00830010, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s left rotate -- isNil@+0x25, 0x18-byte
             * value_type. Byte-identical ICF twin of the mesh-key map's left
             * rotate (0x007E4E10 above) and of FUN_0044BF90/FUN_0057F160
             * (unidentified same-layout instantiations, not traced to an
             * owning class in this pass); this address specifically is
             * confirmed `mGraphRuntimeTree`'s via direct calls from both
             * `insert_at`'s emission FUN_0082E320 and `erase_node`'s
             * emission FUN_0082FD50, both cited above/below.)
             */
            /**
             * Address: 0x006880A0 (FUN_006880A0, `msvc8::map<std::uint32_t,
             * moho::IdPool>::_Lrotate` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. Byte-for-byte this member's shape (pivot =
             * `n->right`; `pivot->left`'s `isNil` probed at its
             * instantiation-specific offset `+0xCC9`, matching `IdPool`'s
             * node layout cited on `buy_node` above). Reached from `insert_at`'s
             * emission FUN_00687280's fixup loop, cited above.)
             */
            /**
             * Address: 0x006E1F20 (FUN_006E1F20, the command-id map's left
             * rotate -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
             * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15,
             * standard field order. Reached from `insert_at`'s fixup loop
             * (FUN_006E1D60, cited below) via a direct `call` within that
             * same function. Byte-identical to `FUN_004AD3F0`
             * (`recovered_progress.json` previously marked this address
             * `skip` as an "ICF twin" of that address and stopped there --
             * ICF folds identical bodies to *one* surviving address at link
             * time, so two functions at genuinely different addresses, each
             * with its own real caller, are two distinct emissions to
             * recover, not one canonical body and a discardable duplicate;
             * corrected to `recovered` here, matching how every other
             * byte-identical rotate sibling in this file is handled, e.g.
             * the mesh-key/`mGraphRuntimeTree` pair cited on this member
             * elsewhere.)
             */
            /**
             * Address: 0x008B64C0 (FUN_008B64C0, `struct_CommandManager::
             * FindDataFor`'s left rotate -- `msvc8::map<Moho::CmdId,
             * Moho::UserCommandIssueHelper*>`, `CommandManager::mCommands` in
             * `CommandManager.h`, isNil@+0x15, standard field order
             * (`result = this->_Right; this->_Right = result->_Left; ...;
             * result->_Left = this;`). Reached from `insert_at`'s emission
             * FUN_008B6310's fixup loop, cited below. Re-homed here from a
             * bespoke `RotateLeft` free function in Sim.cpp that hand-rolled
             * this same rotation over a `CommandDbMapStorageView`/
             * `CommandDbMapNodeView` reach-in instead of calling it.)
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
            /**
             * Address: 0x0077B160 (FUN_0077B160, outer map)
             * Address: 0x0077C640 (FUN_0077C640, inner bucket set)
             */
            /**
             * Address: 0x00719740 (FUN_00719740, `InfluenceGrid::entries`'s
             * right rotate -- same instantiation as `rotate_left`'s
             * 0x00719690 above; see that citation for the map<uint32_t,
             * InfluenceMapEntry> vs. set<InfluenceMapEntry> node-typing note.)
             */
            /**
             * Address: 0x007E4EA0 (FUN_007E4EA0, the mesh-key map's right
             * rotate -- `_Isnil` at +0x25, sibling of `rotate_left`'s
             * 0x007E4E10 above.)
             */
            /**
             * Address: 0x0052DB00 (FUN_0052DB00, the right rotate for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * mirror of `rotate_left`'s 0x0052DAB0 above, same instantiation.)
             */
            /**
             * Address: 0x00830080 (FUN_00830080, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s right rotate -- sibling of `rotate_left`'s
             * 0x00830010 above, same map. Byte-identical ICF twin of the
             * mesh-key map's right rotate (0x007E4EA0 above); confirmed via
             * direct calls from `insert_at`'s emission FUN_0082E320 and
             * `erase_node`'s emission FUN_0082FD50.)
             */
            /**
             * Address: 0x00688120 (FUN_00688120, `msvc8::map<std::uint32_t,
             * moho::IdPool>::_Rrotate` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. Mirror of `rotate_left`'s FUN_006880A0 above,
             * same instantiation. Reached from `insert_at`'s emission
             * FUN_00687280's fixup loop, cited above.)
             */
            /**
             * Address: 0x00A55930 (FUN_00A55930, the right rotate for the same
             * unidentified `map<int32_t, T>` instantiation cited on
             * `rotate_left` above (0x00A52800/0x00A529D0) and on `insert_at`'s
             * link-and-rebalance fixup loop (0x00A63950) -- swapped field
             * order confirmed (`right@0`/`parent@+4`/`left@+8`, isNil byte at
             * +0x21): reads `n->left` at `[edx+8]`, `pivot->right` at `[eax]`,
             * writes `n->left = pivot->right` at `[edx+8]`, the root/
             * parent-side branch at `[ecx+4]`/`[ecx]`/`[ecx+8]` mirroring
             * `rotate_left`'s own root/parent-side branch with right and left
             * swapped, and finishes `pivot->right = n` / `n->parent = pivot`
             * via field 0 and field+4 exactly as this method's generic body
             * does. Reached from `insert_at`'s fixup loop (0x00A63950) via the
             * same caller chain cited there (0x00A656A0 -> 0x00A65D00 ->
             * 0x00A66270 -> 0x00A666F0 -> ...); owning class still not traced
             * in this pass, matching the sibling citation.)
             */
            /**
             * Address: 0x006E1FD0 (FUN_006E1FD0, the command-id map's right
             * rotate -- mirror of `rotate_left`'s FUN_006E1F20 above, same
             * instantiation. Reached from `insert_at`'s fixup loop
             * (FUN_006E1D60, cited below). Also byte-identical to a
             * `resource/ResourceManager.cpp` rotate and previously marked
             * `skip` as its "ICF twin" -- corrected to `recovered` here for
             * the same reason given on `rotate_left`'s FUN_006E1F20 entry
             * above: two distinct addresses, each with its own real caller,
             * are two distinct emissions.)
             */
            /**
             * Address: 0x008B6550 (FUN_008B6550, `struct_CommandManager::
             * FindDataFor`'s right rotate -- `msvc8::map<Moho::CmdId,
             * Moho::UserCommandIssueHelper*>`, `CommandManager::mCommands` in
             * `CommandManager.h`. Mirror of `rotate_left`'s FUN_008B64C0
             * above, same instantiation (`result = this->_Left; this->_Left =
             * result->_Right; ...; result->_Right = this;`). Reached from
             * `insert_at`'s emission FUN_008B6310's fixup loop, cited below.
             * Re-homed here from a bespoke `RotateRight` free function in
             * Sim.cpp that hand-rolled this same rotation over a
             * `CommandDbMapStorageView`/`CommandDbMapNodeView` reach-in
             * instead of calling it.)
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
            /**
             * Address: 0x0077B600 (FUN_0077B600, inner bucket link-and-rebalance)
             * Address: 0x0077BE80 (FUN_0077BE80, outer map link-and-rebalance)
             * Address: 0x0077AF40 (FUN_0077AF40, the outer map's insert-position resolve)
             * Address: 0x0077A3C0 (FUN_0077A3C0, the outer map's insert with
             * rebalance -- the `_Xlen` throw, the rotates at 0x0077B0B0/0x0077B160
             * and the successor at 0x0077CE50 are all reached from it. This was
             * the CreateHandle insert-side left deferred when the CDecalBuffer
             * tree first landed in 90e6ffa.)
             */
            /**
             * Address: 0x0052CD30 (FUN_0052CD30, the link-and-rebalance half of
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals`'s
             * insert -- `msvc8::set<uint32_t>`. Matches this template body
             * field for field: the `_Mysize >= 0x3FFFFFFE` guard throwing
             * `std::length_error("map/set<T> too long")`, the `sub_52DB50`
             * buy-node call, then the red/black fixup loop calling
             * `sub_52DAB0`/`sub_52DB00` (`rotate_left`/`rotate_right`, cited
             * below) on the uncle-red vs. uncle-black branches. Reached from
             * `insert_unique`'s emission at 0x0052BC60, cited above.
             */
            /**
             * Address: 0x0082E320 (FUN_0082E320, `Moho::UICommandGraph::
             * mGraphRuntimeTree`'s combined buy-node/link/rebalance emission
             * -- `map<shared_ptr<CD3DBatchTexture>, vector<CommandGraphEdge*>>`,
             * isNil@+0x25. The `_Mysize >= 0xAAAAAA9` guard is exactly this
             * template's `max_size() - 1u <= size_` for a 0x18-byte
             * value_type (`0xFFFFFFFF / 0x18 - 1 == 0xAAAAAA9`), throwing
             * `std::length_error("map/set<T> too long")`. Buys the node
             * through `sub_830110` (cited on `buy_node` below), links it,
             * then repairs the red-red violation calling `rotate_left`
             * (0x00830010) / `rotate_right` (0x00830080), both cited below.
             * `CWldSession.cpp`'s `AddCommandQueueToCommandGraph` reconstruction
             * notes already name this address `insert_at`, reached via the
             * hinted insert at 0x0082CC80 for `mGraphRuntimeTree[texture]`
             * (VC8 `map::operator[]`); that hinted-insert caller itself
             * remains unrecovered (`AddCommandQueueToCommandGraph` is still
             * blocked on `LinkCommandGraphEdge`), so this member's
             * source-level invocation is the same generic `msvc8::map`/
             * `rb_tree` API surface every other instantiation on this
             * member already uses, not a new engine call site.)
             */
            /**
             * Address: 0x005565D0 (FUN_005565D0, the link-and-rebalance half
             * of the category-lookup map's insert -- `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `Sim.cpp`'s
             * `EntityCategoryLookupTableView::mCategoryMap`. The
             * `*(a2+8) >= 0x38E38E2` guard is this member's
             * `max_size() - 1u <= size_`: `0xFFFFFFFF / 0x48 == 0x38E38E3`
             * (this template's `max_size()` is defined over `value_type`,
             * i.e. the 0x48-byte `pair<const msvc8::string,
             * CategoryLookupValue>`, not the 0x60-byte node including link
             * pointers and colour/nil), minus one is exactly `0x38E38E2` --
             * independent confirmation that `sizeof(value_type) == 0x48` for
             * this instantiation, matching `CategoryLookupValue`'s alignment
             * evidence in Sim.cpp. Buys the node through `sub_5569C0`
             * (`buy_node`, cited below), links it under the caller's
             * `where`/`addLeft`, then repairs the red-red violation with the
             * same rotate-on-uncle-red/recolour-on-uncle-black shape as
             * every other `insert_at` emission in this file, writing
             * colour/nil at `[node+0x58]`/`[node+0x59]` (the offsets that
             * pin this node to the 8-byte-aligned shape -- see
             * `CategoryLookupValue`'s citation block in Sim.cpp). Reached
             * from `insert_unique`'s emission (FUN_005560B0, cited above).)
             */
            /**
             * Address: 0x00687280 (FUN_00687280, `msvc8::map<std::uint32_t,
             * moho::IdPool>::_Insert` -- `CEntityDb::mIdPoolTree` in
             * `EntityDb.h`. The `_Mysize >= 0x1420B4` guard is this member's
             * `max_size() - 1u <= size_` for the 0xCB8-byte `pair<const
             * uint32_t, IdPool>` value_type (`0xFFFFFFFF / 0xCB8 - 1 ==
             * 0x1420B4` exactly -- independent confirmation of the 8-byte-
             * aligned `pair` size derived on `buy_node`'s citation above),
             * throwing `std::length_error("map/set<T> too long")`. Buys the
             * node through `FUN_006881C0` (`buy_node`, cited above), links
             * it under the caller's `where`/`addLeft` in the same three-case
             * shape as `link_and_rebalance` below (`where == head`, `where
             * == leftmost()`, general case), then repairs the red-red
             * violation calling `rotate_left`/`rotate_right`
             * (`FUN_006880A0`/`FUN_00688120`, both cited below). Reached
             * from `insert_unique`'s emission `FUN_006870D0` (cited below)
             * and from `insert_hint`'s emission `FUN_006864E0` (cited
             * below) -- both real paths in this codebase: the former via
             * `EntityDbIdPoolMapTypeInfo::SerLoad`'s per-element
             * `map->insert(...)`, the latter via `CEntityDb::
             * MemberDeserialize`'s `mIdPoolTree[familySourceBits]`.)
             */
            /**
             * Address: 0x006E1D60 (FUN_006E1D60, the command-id map's
             * link-and-rebalance -- `msvc8::map<Moho::CmdId,
             * Moho::CUnitCommand*>`, `Moho::CCommandDb::commands` in
             * `CCommandDb.h`. The `_Mysize >= 0x1FFFFFFE` guard is this
             * member's `max_size() - 1u <= size_` for the 8-byte
             * `pair<const CmdId, CUnitCommand*>` value_type
             * (`0xFFFFFFFF/8 - 1 == 0x1FFFFFFE`), throwing
             * `std::length_error("map/set<T> too long")`. Buys the node
             * through `sub_6E23F0` (`buy_node`, cited above), links it under
             * the caller's `where`/`addLeft`, then repairs the red-red
             * violation calling `sub_6E1F20`/`sub_6E1FD0`
             * (`rotate_left`/`rotate_right`, cited above) on the
             * uncle-red/uncle-black branches. Reached from
             * `insert_unique`'s emission (FUN_006E15B0, cited above), both
             * call sites.)
             */
            /**
             * Address: 0x008B6310 (FUN_008B6310, sub_8B6310) --
             * `msvc8::map<Moho::CmdId, Moho::UserCommandIssueHelper*>`,
             * `CommandManager::mCommands` in `CommandManager.h`. Same shape
             * as FUN_006E1D60 above (a separate instantiation): the
             * `_Mysize >= 0x1FFFFFFE` overflow guard throws
             * `std::length_error("map/set<T> too long")`, buys the node
             * through `sub_8B67F0` (`buy_node`, cited above), links it under
             * the caller's `where`/`addLeft`, then repairs the red-red
             * violation calling `sub_8B64C0`/`sub_8B6550`
             * (`rotate_left`/`rotate_right`, cited above). Reached from
             * `insert_unique`'s emission (FUN_008B5DF0, cited above). Re-
             * homed here from the same bespoke `InsertCommandNodeFixup` free
             * function in Sim.cpp cited on `insert_unique`/`buy_node` above.)
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
