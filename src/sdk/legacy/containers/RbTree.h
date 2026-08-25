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
         *
         * Address: 0x007B4B20 (FUN_007B4B20, sub_7B4B20) -- the ANI_DumpSkeleton
         * outer per-parent-bone dedup map's leftmost descent, `msvc8::map<
         * std::uint32_t, msvc8::set<uint32_t>>` (isNil@+0x1D, same tree
         * cited on `erase_range`/`insert_unique` elsewhere in this file).
         * Walks `_Left` (offset 0) while `!_Isnil` (offset+0x1D), matching
         * this member exactly. Reached from `rb_increment`'s `rb_min(n->
         * right)` call for this same instantiation.
         *
         * Address: 0x00946790 (FUN_00946790, sub_946790) -- `gpg::gal::
         * StateCache<d3d9::RenderState, unsigned int>::tree_`'s leftmost
         * descent, isNil@+0x15. One of this instantiation's "own distinct
         * rotate/min/max helper addresses" already named on `erase_node`
         * (`FUN_00947380` above).
         * Address: 0x00946810 (FUN_00946810, sub_946810) -- `gpg::gal::
         * StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::tree_`'s
         * leftmost descent, isNil@+0x15, byte-identical shape to
         * `FUN_00946790` above -- sibling `StateCache` specialisation with
         * its own distinct helper address (`FUN_009478E0`'s `erase_node`
         * citation above).
         *
         * Address: 0x0052D960 (FUN_0052D960, the category-lookup map's
         * leftmost descent -- `msvc8::map<msvc8::string,
         * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
         * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
         * mCategoryMap` (RRuleGameRules.h/.cpp). `while (!n->left->isNil) n
         * = n->left;`, matching this member exactly (confirmed against the
         * raw decompile: `while (!(*a2)->_Isnil) *a2 = ...`, walking
         * `_Left`). Sole caller per this pass's xref sweep is `erase_node`'s
         * emission for this instantiation (FUN_00536010, cited below) via
         * `rb_min(fix)` when the erased node was the map's leftmost -- the
         * same "constructor-inlined instantiation, only the erase-rebalance
         * path keeps a standalone symbol" shape documented throughout this
         * file. Re-homed here from a hand-rolled
         * `LeftmostCategoryLookupDescendant` free function in
         * RRuleGameRules.cpp that walked a `CategoryLookupNodeRuntimeView*`
         * reach-in instead of calling it.)
         */
        /**
         * Address: 0x006880F0 (FUN_006880F0, `_Min` for `msvc8::map<
         * std::uint32_t, moho::IdPool>` -- `CEntityDb::mIdPoolTree` in
         * `EntityDb.h`. Node layout confirmed against `FUN_006881C0`
         * (`buy_node`, cited above): `IdPool`'s `alignas(8)` (see that
         * type's own citation in `IdPool.h`) forces a 4-byte pad between
         * the link triplet (ends at node+0x0C) and `value_type` (`pair<
         * const uint32_t, IdPool>`), so the pair starts at node+0x10 (key)
         * / node+0x18 (`IdPool`, `sizeof(IdPool)==0xCB0`), landing colour/
         * isNil at node+0xCC8/node+0xCC9 -- exactly the raw `+3272`/`+3273`
         * byte offsets this instantiation's emissions use throughout (`cmp
         * byte ptr [esi+0CC9h], 0` in `FUN_00688030`'s own asm). Walks
         * `_Left` (node+0x00) while `!_Isnil` (node+0xCC9), matching this
         * member exactly. Reached from `erase_node`'s emission for this
         * instantiation (`FUN_00687CC0`, cited below) via `rb_min(fix)`
         * when the erased node was the tree's leftmost.
         */
        /**
         * Address: 0x00A52650 (FUN_00A52650, sub_A52650) -- the same
         * `msvc8::set<std::uint32_t>` instantiation cited on `equal_range`/
         * `erase(const key_type&)`/`erase_node` above (isNil@+0x11). Walks
         * `_Left` (node+0x00) while `!_Isnil` (node+0x11), matching this
         * member exactly. Reached from `erase_node`'s emission for this
         * instantiation (`FUN_00A633D0`, cited above) to re-seat `head->left`
         * when the erased node was the tree's leftmost, and transitively from
         * `Wm3::ConvexHull3<float>::~ConvexHull3()` (0x00A66440) tearing down
         * the `rb_tree` member at `this+0x68`. Owning field/class beyond
         * `ConvexHull3<float>` not yet pinned down.
         * Address: 0x00A526A0 (FUN_00A526A0) -- byte-identical ICF twin of
         * 0x00A52650 (`function_icf_twins`), reached instead from
         * `ConvexHull3<double>`'s sibling `erase_node` emission
         * (`FUN_00A63690`) -- mark `skip "ICF twin of FUN_00A52650"`.
         *
         * Address: 0x00A3A170 (FUN_00A3A170, sub_A3A170) -- a distinct
         * 8-byte-value ("Nil21") tree instantiation, isNil@+0x15. Same walk,
         * one addressing-mode step removed (`__cdecl` locals instead of the
         * `for`-loop shape above; behaviourally identical). Re-homed out of
         * `moho/math/Wm3DistanceFafExtras.cpp`'s `QueryTree` reach-in cluster
         * (`QueryTreeLeftmostNil21LaneC`). This body is an ICF twin of an
         * already-`skip`'d 6-member group anchored at `FUN_008D8C50`
         * (`src/sdk/gpg/core/reflection/Reflection.cpp`, reached from
         * `func_PopTreeNode`) -- cited here on its own confirmed evidence
         * (read directly against its `.c` export, not inferred from the twin
         * group) rather than inheriting that group's skip rationale, which
         * this pass did not verify. Sole caller in this sweep is
         * `FUN_00A3E450` (itself `skip`, chain not resolved in this pass);
         * flagged as a follow-up rather than guessed at. Owning field/class
         * not yet pinned down.
         *
         * Address: 0x00A52BF0 (FUN_00A52BF0, sub_A52BF0) -- a 20-byte-value
         * ("Nil33") tree instantiation, isNil@+0x21. Same walk. Re-homed out
         * of `QueryTreeLeftmostNil33LaneA` in the same `QueryTree` reach-in
         * cluster. Sole caller in this sweep is `FUN_00A63DD0` (currently
         * misfiled `external_dependency` -- its own `vtable_writes` hit for
         * `out_of_range@std` marks it as another `erase_node`-shaped emission,
         * i.e. engine code, not a real external import; not reclassified in
         * this pass). Owning field/class not yet pinned down.
         * Address: 0x00A52D40 (FUN_00A52D40) -- byte-identical ICF twin of
         * 0x00A52BF0, reached from `FUN_00A64110`'s sibling emission; mark
         * `skip "ICF twin of FUN_00A52BF0"`.
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
         *
         * Address: 0x007B4A30 (FUN_007B4A30, sub_7B4A30)
         *
         * `msvc8::set<std::uint32_t>` instantiation, `_Isnil` at +0x11
         * (4-byte value_type) -- the same tree cited on `destroy_subtree`/
         * `erase_node` above. Walks `_Right` (node+0x08) while `!_Isnil`
         * (node+0x11), confirmed against the `.asm`. Called from
         * `erase_node`'s emission for this instantiation (`FUN_007B46A0`,
         * cited above) to re-seat `head->right` when the erased node was
         * the tree's rightmost.
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
         *
         * Address: 0x007B4B00 (FUN_007B4B00, sub_7B4B00) -- the ANI_DumpSkeleton
         * outer per-parent-bone dedup map's rightmost descent, same
         * `msvc8::map<std::uint32_t, msvc8::set<uint32_t>>` instantiation
         * as `rb_min`'s sibling citation `FUN_007B4B20` above (isNil@+0x1D).
         * Walks `_Right` (offset+8) while `!_Isnil`, matching this member
         * exactly. Reached from `rb_decrement`'s `rb_max(n->left)` call for
         * this same instantiation.
         *
         * Address: 0x00946770 (FUN_00946770, sub_946770) -- `gpg::gal::
         * StateCache<d3d9::RenderState, unsigned int>::tree_`'s rightmost
         * descent, isNil@+0x15. One of this instantiation's "own distinct
         * rotate/min/max helper addresses" already named on `erase_node`
         * (`FUN_00947380` above).
         * Address: 0x009467F0 (FUN_009467F0, sub_9467F0) -- `gpg::gal::
         * StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::tree_`'s
         * rightmost descent, isNil@+0x15, byte-identical shape to
         * `FUN_00946770` above -- sibling `StateCache` specialisation with
         * its own distinct helper address (`FUN_009478E0`'s `erase_node`
         * citation above).
         *
         * Address: 0x0057F1B0 (FUN_0057F1B0, sub_57F1B0) -- `Moho::
         * CAiBrain::mBuildStructureMap`'s rightmost descent (isNil@+0x25,
         * the same `msvc8::map<Wm3::Vector2i, SBuildReserveInfo>`
         * instantiation cited on `erase_node`/`buy_node`/`buy_head`
         * elsewhere in this file). Reached from `rb_decrement`'s
         * `rb_max(n->left)` call for this same instantiation.
         *
         * Address: 0x00536AA0 (FUN_00536AA0, the category-lookup map's
         * rightmost descent -- `msvc8::map<msvc8::string,
         * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
         * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
         * mCategoryMap` (RRuleGameRules.h/.cpp). `while (!n->right->isNil) n
         * = n->right;`, matching this member exactly. Sole caller per this
         * pass's xref sweep is `erase_node`'s emission for this
         * instantiation (FUN_00536010, cited below) via `rb_max(fix)` when
         * the erased node was the map's rightmost -- sibling of `rb_min`'s
         * 0x0052D960 citation above, same map. Re-homed here from a
         * hand-rolled `RightmostCategoryLookupDescendant` free function in
         * RRuleGameRules.cpp that walked a `CategoryLookupNodeRuntimeView*`
         * reach-in instead of calling it.)
         */
        /**
         * Address: 0x00688830 (FUN_00688830, `_Max` for `msvc8::map<
         * std::uint32_t, moho::IdPool>` -- `CEntityDb::mIdPoolTree` in
         * `EntityDb.h`, sibling of `rb_min`'s 0x006880F0 citation above
         * (same node layout: colour/isNil at node+0xCC8/node+0xCC9). Walks
         * `_Right` (node+0x08) while `!_Isnil` (node+0xCC9), matching this
         * member exactly. Reached from `erase_node`'s emission for this
         * instantiation (`FUN_00687CC0`, cited below) via `rb_max(fix)`
         * when the erased node was the tree's rightmost.
         *
         * Address: 0x00A52630 (FUN_00A52630, sub_A52630) -- the same
         * `msvc8::set<std::uint32_t>` instantiation cited on `equal_range`/
         * `erase(const key_type&)`/`erase_node`/`rb_min` above (isNil@+0x11).
         * Walks `_Right` (node+0x08) while `!_Isnil` (node+0x11), matching
         * this member exactly. Reached from `erase_node`'s emission for this
         * instantiation (`FUN_00A633D0`, cited above) to re-seat `head->right`
         * when the erased node was the tree's rightmost, and transitively
         * from `Wm3::ConvexHull3<float>::~ConvexHull3()` (0x00A66440).
         * Address: 0x00A52680 (FUN_00A52680) -- byte-identical ICF twin of
         * 0x00A52630, reached instead from `ConvexHull3<double>`'s sibling
         * `erase_node` emission (`FUN_00A63690`) -- mark `skip "ICF twin of
         * FUN_00A52630"`.
         *
         * Address: 0x00A3A240 (FUN_00A3A240, sub_A3A240) -- the same 8-byte-
         * value ("Nil21") tree instantiation cited on `rb_min`'s 0x00A3A170
         * above, isNil@+0x15. Same "ICF twin of an already-`skip`'d
         * Reflection.cpp group, cited here on its own confirmed evidence"
         * situation as that member -- see its note. Owning field/class not
         * yet pinned down.
         *
         * Address: 0x00A52BD0 (FUN_00A52BD0, sub_A52BD0) -- the same 20-byte-
         * value ("Nil33") tree instantiation cited on `rb_min`'s 0x00A52BF0
         * above, isNil@+0x21. Sole caller in this sweep is `FUN_00A63DD0`
         * (see that member's note on its `external_dependency` mis-tag).
         * Owning field/class not yet pinned down.
         * Address: 0x00A52D20 (FUN_00A52D20) -- byte-identical ICF twin of
         * 0x00A52BD0, reached from `FUN_00A64110`'s sibling emission; mark
         * `skip "ICF twin of FUN_00A52BD0"`.
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
         * Address: 0x007B4500 (FUN_007B4500, `operator++()` -- advances via
         * this member (through `sub_7B4D90`) and returns the same slot,
         * matching the prefix-increment shape documented on the
         * `FUN_006E1A90`/`FUN_006E1AB0`/`FUN_007B4570` adapters. DB-integrity
         * fix: `source_paths=null`, boilerplate batch note, zero real
         * citations found in a full `src/sdk` sweep.)
         * Address: 0x007B4BC0 (FUN_007B4BC0, byte-identical duplicate
         * emission of `FUN_007B4500` -- same `operator++()` prefix shape,
         * same `sub_7B4D90` callee, a distinct per-call-site copy. Same
         * DB-integrity provenance as `FUN_007B4500`.)
         * Address: 0x007B4510 (FUN_007B4510, `operator++(int)` -- copies the
         * old node into the return slot, then advances via this member
         * (through `sub_7B4D90`), matching the post-increment shape
         * documented on the `FUN_006E28C0`/`FUN_007B4540` adapters. Same
         * DB-integrity provenance as `FUN_007B4500`.)
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
         * Address: 0x00685FA0 (FUN_00685FA0, first register-shape adapter described above)
         * Address: 0x00686CE0 (FUN_00686CE0, second register-shape adapter described above)
         */
        /**
         * Address: 0x006E2220 (FUN_006E2220, `std::map_uint_CUnitCommand::
         * Iterator::inc`) -- `msvc8::map<Moho::CmdId, Moho::CUnitCommand*>`,
         * `Moho::CCommandDb::commands` in `CCommandDb.h`, isNil@+0x15.
         * Matches this member exactly.
         * Address: 0x006E1A90 (FUN_006E1A90, first of the two thin adapters described below)
         * Address: 0x006E1AB0 (FUN_006E1AB0, second of the two thin adapters described below)
         * `FUN_006E1A90`/`FUN_006E1AB0` are two
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
        /**
         * Address: 0x007B4C40 (FUN_007B4C40, `_Inc` for an unidentified
         * `msvc8::map`/`msvc8::set` instantiation with a 16-byte value_type --
         * isNil@+0x1D (0x0D + 0x10). Same recurse-right-then-climb-parent
         * shape as this member. Byte-identical ICF twin of FUN_005C7A90
         * (cited in CAiReconDBImpl.cpp), FUN_0077CE50 (cited on this member
         * above, CDecalBuffer start-tick table) and FUN_008D6C90 (cited in
         * SimRecoveryRuntime.cpp) -- those three are unrelated instantiations
         * that happen to compile to the same bytes; this citation covers a
         * fourth, distinct 16-byte-value_type instantiation reached from a
         * genuinely checked-iterator erase lane (FUN_007B4040, which throws
         * `std::out_of_range("invalid map/set<T> iterator")` on a nil
         * dereference before calling this). Owning class not yet pinned
         * down -- reached via the CRT static-init array (`__xc_a`) at depth
         * 4, source_paths previously misattributed to CrtRuntimeHelpers.cpp
         * with zero real citation there (DB-integrity fix).
         * Address: 0x007B4540 (FUN_007B4540, `operator++(int)` -- copies the
         * old node into the return slot, then advances via this member,
         * matching the post-increment shape documented on the sibling
         * `FUN_006E28C0` adapter above)
         * Address: 0x007B4570 (FUN_007B4570, `operator++()` -- advances via
         * this member and returns the same slot, matching the prefix-
         * increment shape documented on the `FUN_006E1A90`/`FUN_006E1AB0`
         * adapters above)
         */
        /**
         * Address: 0x007B2D40 (FUN_007B2D40, `_Inc` for the
         * `msvc8::set<std::uint32_t>` instantiation cited on `alloc_raw`/
         * `free_raw`/`buy_head`/`clear`/`destroy_subtree` throughout this
         * file (isNil@+0x11). Same recurse-right-then-climb-parent shape as
         * this member: `if (!isNil(n->right)) return rb_min(n->right);`
         * else climb `parent` while `n == ancestor->right`. Takes an
         * `_Node**` out-parameter slot rather than returning by value
         * (`__fastcall(int, int* slot)`, mutates `*slot` in place and
         * returns it), matching the `FUN_006E1A90`/`FUN_006E1AB0`
         * slot-pointer adapter shape one level up through an indirection --
         * except here the slot mutation is inlined into the walk itself
         * rather than split into a separate adapter. On `isNil(n)` it
         * returns without touching `*slot` at all (no `--end()`-style
         * redirect), matching this member's `if (rb_is_nil(n)) return n;`
         * no-op exactly. DB-integrity fix: this token was previously
         * flipped `blocked` citing a `CrtRuntimeHelpers.cpp` source path
         * the address never appeared in (2026-08-21 citation-audit
         * revert); this is the real source, evidenced by its two real
         * callers below (paired bottom-up recovery, same DB-integrity
         * pass). Owning field not yet pinned to a specific class.
         * Address: 0x007B4BD0 (FUN_007B4BD0, `operator++(int)` -- copies
         * the old node into the return slot, then advances via this
         * member, matching the post-increment shape documented on the
         * `FUN_006E28C0`/`FUN_007B4540` adapters above. DB-integrity fix:
         * `source_paths=null`, boilerplate batch note, zero real citations
         * found in a full `src/sdk` sweep.)
         * Address: 0x007B4DE0 (FUN_007B4DE0, `operator++()` -- advances via
         * this member and returns the same slot, matching the prefix-
         * increment shape documented on the `FUN_006E1A90`/`FUN_006E1AB0`/
         * `FUN_007B4570`/`FUN_007B4500` adapters above. Same DB-integrity
         * provenance as `FUN_007B4BD0`.)
         * Address: 0x0052EE50 (FUN_0052EE50, sub_52EE50) -- another
         * `_Node**` out-parameter-slot instantiation of this member, isNil
         * at `[node+0x11]`, same recurse-right-then-climb-parent shape and
         * same "on `isNil(n)` return without touching `*slot`" no-op path
         * as `FUN_007B2D40` above. Distinct address range from that
         * instantiation's family (0x0052xxxx vs 0x007Bxxxx) -- a separate
         * class sharing the same isNil@0x11 4-byte-value shape, not a
         * sibling emission of it. Three real callers (`FUN_0052D730`,
         * `FUN_0052F0A0`, `FUN_00530DC4`); owning field/class not yet
         * pinned down.
         *
         * Address: 0x0083C2E0 (FUN_0083C2E0, sub_83C2E0) -- CORRECTED: was
         * mislabeled `UiKeyActionMap`/`msvc8::map<UiKeyMask,
         * msvc8::string>` here despite already noting `isNil@+0x15` --
         * that offset belongs to the *other* UI key map. This is
         * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s in-order
         * successor walk (`gUiKeyRepeatMap`, `moho/ui/UiRuntimeTypes.cpp:
         * 1395`; `UiKeyActionMap` is isNil@+0x2D, see `FUN_0083A640` cited
         * on `erase(const_iterator)` above). Two real call sites: this
         * instantiation's `erase_node` (`FUN_0083AA70`, corrected
         * alongside this entry, cited on that member below) via the
         * successor-capture step every `erase_node` emission performs
         * before unlinking, and `insert_hint`'s emission (`FUN_0083B320`,
         * cited below) via its successor-straddle check on a miss-hint.
         *
         * Address: 0x005A19B0 (FUN_005A19B0, sub_5A19B0) --
         * `msvc8::map<uint32_t, moho::RUnitBlueprint*>::operator[]`'s
         * hint-validation increment, isNil@+0x15. Called from the
         * `operator[]` inner helper `FUN_005A08B0`
         * (`moho/ai/CAiBuilderImpl.cpp`) to advance an insertion hint and
         * re-check the key ordering before trusting it. The recovered
         * `AddOrUpdateRebuildNode` absorbs this whole `operator[]`
         * emission (including this increment step) into a direct
         * find-then-insert path -- see the "Absorbs binary helper"
         * comment on `FUN_005A08B0`'s citation there.
         *
         * Address: 0x0052CC30 (FUN_0052CC30, the category-lookup map's
         * successor walk -- `msvc8::map<msvc8::string,
         * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
         * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
         * mCategoryMap` (RRuleGameRules.h/.cpp). Matches this member field
         * for field, confirmed against the raw decompile: real-right-child
         * case descends to `right->left` while `!isNil`; nil-right-child
         * case climbs `parent` while `*cursor == parent->right`, landing on
         * the first ancestor reached from its left subtree. Reached from
         * `erase_node`'s emission for this instantiation (FUN_00536010,
         * cited below) as the successor-capture step every `erase_node`
         * emission performs before unlinking. Re-homed here from a
         * hand-rolled `AdvanceCategoryLookupNodeSuccessor` free function in
         * RRuleGameRules.cpp that walked a `CategoryLookupNodeRuntimeView*`
         * reach-in instead of calling it -- also reached from that file's
         * `PublishCategoriesTable` before the migration, now folded into
         * `mCategoryMap`'s own range-for iteration.)
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
         * Address: 0x0077C7A0 (FUN_0077C7A0, first register-shape adapter
         * described above)
         * Address: 0x0077CE30 (FUN_0077CE30, second register-shape adapter
         * described above)
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
         * Address: 0x008D69D0 (FUN_008D69D0, sub_8D69D0) -- the predecessor
         * lookup half of `insert_unique` for the local `msvc8::rb_tree<
         * moho::Resolution>` dedup tree (see the `insert_unique`/
         * `FUN_008D4F10` and `insert_at`/`FUN_008D5720` citations above),
         * isNil@+0x1D(29). Standard three-way shape (right-child predecessor
         * via `rb_max`-equivalent inline walk, ancestor climb, or direct
         * left-child descent) matching this member exactly.
         */
        /**
         * Address: 0x004E4440 (FUN_004E4440, sub_4E4440)
         *
         * `msvc8::map<CSndParams*, HSndEntityLoop*>`, isNil@+0x15 (8-byte
         * `pair<const CSndParams*, HSndEntityLoop*>` value_type; confirmed
         * against the `.asm`). A thin `_Node**` slot-pointer wrapper adapter
         * around this member -- `if(isNil(*slot)) *slot=(*slot)->right; else
         * if(!isNil((*slot)->left)) *slot=rb_max((*slot)->left); else {
         * ancestor-walk }` -- advancing `*slot` in place and returning the
         * new node, matching the `FUN_006E2200`/`FUN_006E27D0` adapter shape
         * already documented above. Reached from `CSndParams.cpp`'s
         * `_Insert_lower_bound` (`FUN_004E1890`, the per-T canonical-
         * template-helper binding for this map), which uses the predecessor
         * check during hinted/unique insert.
         */
        /**
         * Address: 0x0083C400 (FUN_0083C400, sub_83C400) --
         * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s predecessor
         * lookup (`gUiKeyRepeatMap`, `moho/ui/UiRuntimeTypes.cpp:1395`,
         * isNil@+0x15). Standard three-way shape (right-child predecessor
         * via a `rb_max`-equivalent inline right-spine walk, ancestor climb
         * while descending from a left branch, or direct left-child
         * descent) matching this member exactly. Reached from
         * `insert_hint`'s emission (`FUN_0083B320`, cited below) as the
         * `before = rb_decrement(hint)` straddle check. Currently also
         * carries a second, generic-templated recovery as
         * `RetreatTreeIteratorFlag21RuntimeA`/`RetreatRbIteratorRuntime<
         * RbNodeFlag21Runtime, 0x15u>` in `moho/sim/SimRecoveryRuntime.cpp`
         * -- a per-offset duplicate of this same member; not consolidated
         * in this pass (out of scope), flagged for a follow-up template
         * clean-up.)
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
             * Address: 0x00947FE0 (FUN_00947FE0, the `this`-returning sibling
             * emission described above)
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
             * Address: 0x0070CC10 (FUN_0070CC10, one of the four blueprint-stat-map
             * call sites into FUN_0070F810 described above)
             * Address: 0x0070E3A0 (FUN_0070E3A0, another of the four blueprint-stat-map
             * call sites into FUN_0070F810 described above)
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
             * Address: 0x0077A8B0 (FUN_0077A8B0, first sibling emission of the
             * head-sentinel build described above)
             * Address: 0x0077B4C0 (FUN_0077B4C0, second sibling emission of the
             * head-sentinel build described above)
             */
            /**
             * Address: 0x0052F020 (FUN_0052F020, the copy constructor for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * `msvc8::set<uint32_t>`, the same instantiation already pinned
             * by `buy_head`/`erase_range`/`erase_node`/`destroy_subtree`/
             * `~rb_tree` above. Buys the head sentinel via `sub_52F370`
             * (`buy_head`, already cited on that member -- the exact same
             * instantiation already pinned to this tree), then calls
             * `sub_530EE0` (`copy_from`'s emission for this instantiation,
             * cited below) to deep-clone `other`'s tree into the freshly
             * self-linked empty head. Called from `FUN_0052DBE0`'s
             * (`msvc8::vector<RRuleGameRulesLuaExportBinding>::insert`,
             * `legacy/containers/Vector.h`) unconditional top-of-function
             * `const T localValue(value);` step (VC8 copies `_Val` into a
             * local before touching storage) -- `FUN_0052DBE0` itself
             * copies `localValue.mRootState = value.mRootState` inline at
             * the call site (`mov [ebp+a3],ecx` immediately before `call
             * sub_52F020`, 0x0052DC11/0x0052DC14) and hands this function
             * only the non-trivial member's construction, matching
             * `RRuleGameRulesLuaExportBinding`'s implicit member-wise copy
             * constructor split across an inlined POD-field copy plus one
             * real call for the tree member. Was previously mis-marked
             * `external_dependency` in `recovered_progress.json` on the
             * grounds that its callees were "external runtime" -- both
             * `sub_52F370` and `sub_52CF10` (its SEH-unwind cleanup path)
             * are themselves already `recovered` engine code in this same
             * file, and `sub_530EE0` is corrected to `recovered` engine
             * code alongside this entry; corrected here.)
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
             * Address: 0x00684310 (FUN_00684310, sub_684310) -- the same
             * `mIdPoolTree` instantiation's `~rb_tree()` emission for a
             * *different* caller: `CEntityDb::CEntityDb`'s (0x00684230,
             * `EntityDb.cpp`) SEH unwind funclet, torn down if a
             * later-constructed member (`mRegisteredEntitySets`/
             * `mEntityList`/`mAllUnits`, all declared after `mIdPoolTree` in
             * `EntityDb.h`) throws during construction. Body identical to
             * 0x006843B0's shape one level up (`erase_range(head->left,
             * head)` via `sub_687190`, cited on `erase_range` above, then
             * `operator delete(head)` and zero head/size) -- a compiler-
             * generated EH-path clone, not a distinct source line, matching
             * the same pattern already documented for 0x0052A390/0x0052CF10
             * above. Sole caller confirmed by this pass's xref sweep: a
             * `type=19` (unwind) edge from 0x00684230. `DestroyEntityListRuntime`
             * (`EntityDb.cpp`) previously mis-cited this exact address as
             * `mEntityList`'s node-walk teardown -- corrected there to its
             * real address (0x006874E0) in the same pass as this citation;
             * this address does not touch `mEntityList` at all.
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
            /**
             * Address: 0x00947E00 (FUN_00947E00)  Address: 0x00947E90
             * (FUN_00947E90)  Address: 0x00947F20 (FUN_00947F20)
             *
             * Three byte-for-byte identical `~rb_tree()` emissions
             * (`push ecx`/`push esi`, `erase_range(head->left, head)` via
             * `call sub_947C50`, `operator delete(head)`, zero `head`/`size`
             * at `[this+4]`/`[this+8]`, `pop esi`/`pop ecx`, `retn`) for the
             * same isNil@+0x15, 8-byte-value node shape as `gpg::gal::
             * StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::tree_`'s own
             * confirmed `erase_range` (0x00947C50, cited above) -- these
             * three call that exact address, not a sibling emission of it.
             * Not `StateCache<SamplerState>`'s own destructor bodies (those
             * are `sub_9480D0`/`sub_9481E0`, already cited on `erase_range`
             * above, at different addresses with a different prologue); a
             * distinct class in the same `CScApp`-vtable-neighbourhood
             * region owns at least three more members of this exact tree
             * shape. Each of the three differs from its siblings only in
             * the encoded relative-call displacement to `sub_947C50` (their
             * own addresses differ, so the `E8` operand differs), which is
             * exactly why this era's byte-exact `link.exe` `/OPT:ICF` left
             * them as three separate COMDATs instead of folding them -- the
             * same effect documented on `erase_range`'s 0x00947B90/
             * 0x00947C50 pair above. All three have zero incoming
             * references of any kind anywhere in the binary: `.xrefs.txt`
             * is empty, `_callgraph_index.sqlite`'s `call_edges`/
             * `incoming_xrefs`/`reachable` tables have no rows for any of
             * them, and an exhaustive PE byte-scan (every `E8`/`E9` rel32,
             * `0F 8x` jcc rel32, `EB`/`7x` rel8 and absolute dword reference
             * in every section of `bin/external/ForgedAlliance.exe`,
             * validated against 9 known-called addresses in this same file
             * before trusting a zero result) found none either. Recovered
             * here as additional instantiations of this already-well-
             * evidenced member rather than left as unowned orphans, per the
             * same "zero incoming xrefs in this sweep" precedent already
             * used throughout this file (e.g. 0x006E2810 above); owning
             * class not pinned down.)
             * Address: 0x00947E30 (FUN_00947E30)  Address: 0x00947EC0
             * (FUN_00947EC0)  Address: 0x00947F50 (FUN_00947F50)
             *
             * The same three-way duplicate pattern as the paragraph above,
             * one node-shape sibling over: these call `sub_947D10`
             * (`gpg::gal::StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned
             * int>::tree_`'s confirmed `erase_range`, cited above) instead
             * of `sub_947C50`. Same zero-incoming-reference status,
             * confirmed the same way (xrefs file, callgraph index,
             * exhaustive PE byte-scan). Owning class not pinned down --
             * plausibly the same class as the three addresses above, given
             * both trios sit in the identical `CScApp`-neighbourhood address
             * range and both point at `StateCache`-shaped trees, but nothing
             * in this pass proves that beyond adjacency.)
             */
            /**
             * Address: 0x006FD8B0 (FUN_006FD8B0) -- `Moho::CArmyStats::mNameIndex`'s
             * own `~rb_tree()` for `msvc8::map<msvc8::string, CArmyStatItem*>`
             * (isNil@+0x2D, 0x20-byte value_type, 0x30-byte node -- matches
             * `moho::ArmyNameIndexNode` in `CArmyStats.h` exactly): `erase_range(
             * leftmost(), header())` via `sub_702A70` (cited below), `operator
             * delete(head)`, then zero `head`/`size` -- this member's body
             * instruction for instruction. Its only caller is
             * `Moho::CArmyStats::CArmyStats` (0x006FD7C0, confirmed by that
             * address's own decompiled body: `Moho::CArmyStats *__stdcall
             * Moho::CArmyStats::CArmyStats(...)`) -- specifically that
             * constructor's exception-unwind funclet, not its normal body (the
             * normal path never reaches a member destructor). `~CArmyStats`
             * itself (0x00704A40, confirmed the same way) does NOT call this
             * symbol: its own decompiled body inlines `mNameIndex`'s
             * `erase_range`-then-`delete`-then-zero sequence directly --
             * `sub_702A70((int)v2, (int)a2->mStats._Myhead->_Left, (int)
             * a2->mStats._Myhead)` followed by `operator delete(a2->mStats.
             * _Myhead)` and the zeroing -- rather than calling out to a
             * separate `~rb_tree()` symbol. `CArmyStats.cpp`'s destructor
             * previously called an invented `DestroyNameIndexTree()` helper
             * with no real address behind it (no source line maps to it: this
             * member's automatic destruction in the destructor's compiler-
             * generated epilogue, cited here and on `erase_range` below, is
             * the entire real emission); that call has been removed in favour
             * of letting `mNameIndex`'s real destructor run implicitly, as
             * the binary does.
             * Address: 0x00701570 (FUN_00701570) -- byte-for-byte identical to
             * 0x006FD8B0 above (same `sub_702A70` call, same tail), zero
             * incoming references anywhere in the binary (`.xrefs.txt` empty,
             * `_callgraph_index.sqlite` `call_edges`/`incoming_xrefs` have no
             * rows), per the same "recovered as an additional zero-xref
             * instantiation" precedent used throughout this file (e.g.
             * 0x00947E00/0x00947E90/0x00947F20 above).
             * Address: 0x00702060 (FUN_00702060) -- a fourth `erase_range`
             * caller (cited below) of the same address-neighbourhood and
             * calling shape per the callgraph index; not independently
             * exported/decompiled in this namespace pass.
             */
            /**
             * Address: 0x0052DF70 / 0x0052E150 / 0x0052E330 / 0x0052E510 /
             * 0x0052E6E0 / 0x0052E8B0 / 0x0052EA80 -- seven `~rb_tree()`
             * emissions for `RRuleGameRulesImpl`'s seven `RRuleGameRulesBlueprintMap`
             * (`msvc8::map<msvc8::string, void*>`) members (`mUnitBlueprints`/
             * `mProjectileBlueprints`/`mPropBlueprints`/`mMeshBlueprints`/
             * `mEmitterBlueprints`/`mBeamBlueprints`/`mTrailBlueprints`,
             * `RRuleGameRules.h:511-517`), each inlined at its own call site in
             * `~RRuleGameRulesImpl()` (`0x00529700`, `RRuleGameRules.cpp:1949`,
             * whose own comment already documents "the binary open-codes that
             * teardown seven times here, in reverse declaration order, which is
             * what member destruction does anyway"). isNil@+0x2D (45 decimal),
             * 8-byte `{msvc8::string key; void* value}`-shaped node past the
             * usual 12-byte link triple.
             *
             * Each compiled body is larger than this member's plain
             * `erase_range(leftmost(),header())` because this project's VS2005
             * Release build defines `_SECURE_SCL=1` (see this file's opening
             * `rb_tree` class comment on the `Dbg` field), so every `std::map`/
             * `msvc8::map` erase compiles with checked-iterator validation
             * inline: alongside this member's whole-range fast path (`sub_530FA0`
             * family below, matching `destroy_subtree` exactly), the compiler
             * also emits a walk-and-checked-erase-per-node branch (`sub_52F3F0`
             * family below) that validates the iterator against
             * `out_of_range("invalid map/set<T> iterator")` before erasing.
             * That branch is provably unreachable from every one of these
             * seven call sites: `erase_range`'s own fast-path guard
             * (`first==begin() && last==end()`) is always true for a
             * destructor's `erase(leftmost(),header())` call, so the checked
             * per-node path never executes here. This member's plain
             * `erase_range(leftmost(),header())` -- automatic member
             * destruction in the recovered `~RRuleGameRulesImpl()`, no
             * explicit call needed -- reproduces this instantiation's real,
             * reachable behavior exactly; the checked branch is `_SECURE_SCL`
             * debug instrumentation that never fires on valid input, the same
             * "`Dbg` in Release... not used by anything really" pattern this
             * file's class comment already documents for the checked
             * *iterator* type. Not modeling it does not change behavior.
             *
             * `destroy_subtree` halves (whole-range fast path, matches this
             * member's shape exactly): `0x00530FA0` (for `0x0052DF70`),
             * `0x00531130` (`0x0052E150`), `0x005312E0` (`0x0052E330`),
             * `0x00531490` (`0x0052E510`), `0x00531640` (`0x0052E6E0`),
             * `0x005317D0` (`0x0052E8B0`), `0x00531960` (`0x0052EA80`).
             *
             * Checked-erase-per-node halves (compiled but provably unreached
             * from these seven call sites, per above -- not modeled by this
             * member, cited here only so they are not mistaken for orphans):
             * `0x0052F3F0` (for `0x0052DF70`), `0x0052F7A0` (`0x0052E150`),
             * `0x0052FB40` (`0x0052E330`), `0x0052FEE0` (`0x0052E510`),
             * `0x00530280` (`0x0052E6E0`), `0x00530630` (`0x0052E8B0`),
             * `0x005309E0` (`0x0052EA80`).
             *
             * Address: 0x00533E20 (FUN_00533E20, mangles as
             * `Moho::EntityCategory::~EntityCategory` -- see the
             * mangled-name note on `EntityCategoryLookupTableRuntimeView`'s
             * constructor, RRuleGameRules.cpp) -- the category-lookup map's
             * `~rb_tree()`, `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
             * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
             * mCategoryMap`. Matches this member's body field for field:
             * `erase_range(leftmost(), header())` (`sub_535750`, cited
             * above) then `operator delete` the head then null head/size.
             * The raw decompile shows an additional leading block releasing
             * `mCat.mSet.mUsed`'s heap array (`operator delete[]` when it
             * differs from the SBO's `originalvec`) ahead of this tail --
             * that is `CategoryWordRangeView::~CategoryWordRangeView()`'s
             * own body (the `EntityCategoryLookupTableRuntimeView::
             * mCategoryFallback` member immediately preceding `mCategoryMap`
             * in declaration order... reversed at destruction, so it runs
             * first), inlined by the compiler into this same out-of-line
             * symbol because both members' destructors are called from one
             * enclosing (implicit) `~EntityCategoryLookupTableRuntimeView`.
             * Not this member's own work -- `mCategoryMap`'s own share of
             * FUN_00533E20 is exactly this member's four-statement body, no
             * more. Reached from `RRuleGameRulesImpl::~RRuleGameRulesImpl`
             * (FUN_00529700) as `delete mEntityCategoryLookup;`. Re-homed
             * here from a hand-written
             * `EntityCategoryLookupTableRuntimeView::
             * ~EntityCategoryLookupTableRuntimeView()` body in
             * RRuleGameRules.cpp that reproduced this exact shape by hand
             * over a `CategoryLookupNodeRuntimeView*` reach-in; deleted in
             * favor of the implicit destructor now that `mCategoryMap` is a
             * real typed member (RULE ONE: member destructors are
             * compiler-emitted, not hand-written source).
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
             * Address: 0x0087CC20 (FUN_0087CC20, sibling emission of FUN_00498060 described above)
             */
            /**
             * Address: 0x0083B4B0 (FUN_0083B4B0)  Address: 0x0083AA60 (FUN_0083AA60)
             *
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s `end()` lane
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`). Two
             * calling-convention emissions of the same sentinel-head return,
             * matching the multi-address `end()` pattern documented
             * throughout this member's citation catalog: `FUN_0083B4B0`
             * returns `head_` directly in `eax`; `FUN_0083AA60` stores it
             * through a caller-supplied out-parameter instead. Both are
             * currently duplicated as free-function reach-ins
             * (`ReadSecondaryGlobalPointerValue`/`LoadSecondaryGlobalPointerValue`)
             * in `moho/containers/LegacyContainerRuntime.cpp`, confirmed to
             * have zero callers anywhere in `src/sdk` -- orphans, not
             * consolidated in this pass (out of scope; that file also
             * covers the sibling `UiKeyActionMap` tree and other unrelated
             * sentinel offsets, a larger clean-up than this task).
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
             * Address: 0x0087CC40 (FUN_0087CC40, sibling emission of FUN_00498080 described above)
             */
            /**
             * Address: 0x0083BC30 (FUN_0083BC30, sub_83BC30) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s `head_->left`
             * begin lane -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:
             * 1395`), out-parameter-store shape like the trail-segment
             * pool's minimum above. Currently duplicated as a free-function
             * reach-in (`LoadSecondaryGlobalPointerPointee`) in
             * `moho/containers/LegacyContainerRuntime.cpp` with zero
             * callers anywhere in `src/sdk`; not consolidated in this pass
             * (see the `header()` note above for why).
             */
            [[nodiscard]] node_type* leftmost() const noexcept { return head_->left; }
            [[nodiscard]] node_type* rightmost() const noexcept { return head_->right; }

            /**
             * Address: 0x0083BC40 (FUN_0083BC40, sub_83BC40) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::size()` --
             * `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`), direct
             * `dword_10C3750` return. Currently duplicated as a
             * free-function reach-in (`ReadSecondaryGlobalScalarValue`) in
             * `moho/containers/LegacyContainerRuntime.cpp` with zero
             * callers anywhere in `src/sdk`; not consolidated in this pass
             * (see the `header()` note above for why).
             */
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
            /**
             * Address: 0x0083B440 (FUN_0083B440, sub_83B440) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s lower-bound
             * descent (`gUiKeyRepeatMap`, `moho/ui/UiRuntimeTypes.cpp:1395`,
             * isNil@+0x15), store-into-hidden-return-pointer shape like
             * `FUN_006E1D30` above. Reached from `operator[]`'s emission
             * (`FUN_0083A9D0`, cited in `Map.h`) and `find_node`'s emission
             * (`FUN_0083AD60`, cited below), both real call sites.)
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

            /**
             * Address: 0x00A59E20 (FUN_00A59E20, sub_A59E20) -- `msvc8::set<
             * std::uint32_t>::equal_range` for a distinct instantiation, isNil@
             * +0x11 (4-byte value_type). `this`=ecx=tree, `a2`=hidden struct-
             * return slot for the `pair<iterator,iterator>` (4 dwords), `a3`=
             * `const key_type&`, matching a real `__thiscall` member -- not a
             * free function taking a tree pointer, despite how the decompiler
             * originally rendered it. Owning field/class not yet pinned down
             * (re-homed out of `moho/math/Wm3DistanceFafExtras.cpp`'s `QueryTree`
             * reach-in cluster, which had zero real callers of its own for this
             * address; kept here as the template's generic emission per the
             * "no confirmed engine caller" precedent used throughout this file).
             * Address: 0x00A59E80 (FUN_00A59E80) -- ICF twin of 0x00A59E20
             * (`function_icf_twins`); mark `skip "ICF twin of FUN_00A59E20"`.
             *
             * What it does:
             * The shipped body computes the upper bound first, then the lower
             * bound, each via its own fully inlined descent loop rather than a
             * call to `lower_bound_node`/`upper_bound_node` -- the same two
             * descents those members perform, just inlined into one emission
             * for this instantiation (order is immaterial: the two descents
             * don't share mutable state). Recovered here as the natural 2007
             * source line, `{lower_bound(k), upper_bound(k)}`, which is exactly
             * what Dinkumware's `_Tree::equal_range` compiles to and what this
             * template's `erase(const key_type&)` below already relies on.
             */
            [[nodiscard]] std::pair<node_type*, node_type*> equal_range(const key_type& k) const
            {
                return {lower_bound_node(k), upper_bound_node(k)};
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
             * Address: 0x006E0E90 (FUN_006E0E90, the find-and-extract wrapper
             * described above)
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
            /**
             * Address: 0x00948DF0 (FUN_00948DF0, sub_948DF0)
             * Address: 0x00948E60 (FUN_00948E60, sub_948E60)
             *
             * `gpg::gal::backends::d3d9::StateManagerD3D9`'s sampler-state
             * and texture-stage `CacheValue<>` instantiations respectively
             * (`StateManagerD3D9.cpp`, isNil@+0x15, 8-byte value_type). Same
             * inlined-lower-bound-then-verify shape as FUN_006E1940/
             * FUN_008B6160 above, taking an output-parameter slot
             * (`*outSlot = found`) rather than returning the node directly --
             * the store-into-hidden-return-pointer convention already
             * documented on `lower_bound_node`'s `FUN_006E1D30` adapter.
             * Called at the very start of each instantiation (`this+0x14`
             * into the function), matching `map.find(key)` being the first
             * statement of `CacheValue<>`: FUN_00948DF0 from `FUN_00949CE0`
             * (sampler-state), FUN_00948E60 from `FUN_00949D40`
             * (texture-stage), both already recovered as this template's
             * citation above.
             */
            /**
             * Address: 0x0083AD60 (FUN_0083AD60, sub_83AD60) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::find` --
             * `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`),
             * isNil@+0x15. Lower-bound-then-verify shape matching this
             * member exactly: calls `sub_83B440` (`lower_bound_node`,
             * cited above), then rejects a nil or key-greater candidate
             * back to `header()`. No confirmed engine caller in this
             * sweep; `incoming_xrefs` is empty and no recovered
             * `CUIKeyHandler` method currently calls `find` directly on
             * this map (`AddUiKeyMapEntries`/`RemoveUiKeyMapEntries` use
             * `operator[]`/`erase` instead). Kept here as the template's
             * generic emission for this instantiation, not a per-type
             * duplicate.)
             */
            /**
             * Address: 0x00A5D810 (FUN_00A5D810, sub_A5D810) -- a 20-byte-
             * value ("Nil33") tree instantiation, isNil@+0x21. Confirmed via
             * `.asm`: real `this`=ecx (thiscall), one stack arg = `const
             * key_type&` (dereferenced for the descent's key), one stack arg
             * = a hidden-return-pointer slot the body writes `{node, owner}`
             * into before returning (`retn 8` pops both stack args) -- the
             * same "store-into-hidden-return-pointer adapter" convention as
             * `lower_bound_node`'s `FUN_006E1D30` cited above, just for this
             * member: lower-bound descent (`cursor->key >= *key` walking
             * left, else right) inlined directly rather than calling out to
             * `lower_bound_node`, then the same nil-or-key-less rejection
             * this member performs. Re-homed out of `moho/math/
             * Wm3DistanceFafExtras.cpp`'s `QueryTree` reach-in cluster
             * (`FindExactQueryTreeNodeNil33LaneA`). Sole caller in this sweep
             * is `FUN_00A666F0` (currently misfiled `external_dependency`;
             * not reclassified in this pass). Owning field/class not yet
             * pinned down.
             * Address: 0x00A5D8A0 (FUN_00A5D8A0) -- ICF twin of 0x00A5D810
             * (`function_icf_twins`), reached from `FUN_00A66C00`'s sibling
             * emission; mark `skip "ICF twin of FUN_00A5D810"`.
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
            /**
             * Address: 0x007B26B0 (FUN_007B26B0, `msvc8::set<std::uint32_t>::
             * insert_unique` for the per-parent-bone child-set nested inside
             * `Map.h`'s `msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>>::
             * operator[]` instantiation (cited there as `FUN_007B27D0`) --
             * confirmed via raw `.asm`: `this`=eax is a direct register
             * carry-over of that `operator[]` call's return value (a pointer
             * into the found/created entry's embedded-set control block),
             * `a2`=ebx is the key read once via `mov edx,[ebx]`. Descend loop
             * tests isNil at `[node+0x11]` (17 decimal, matching the flat
             * `msvc8::set<std::uint32_t>` shape already documented throughout
             * this file's other `msvc8::set<std::uint32_t>` instantiations) and updates
             * the candidate every iteration with an explicit `addLeft` flag
             * -- this member's shape, not `lower_bound_node`'s. `where ==
             * leftmost()` fast path tail-calls `insert_at` (`sub_7B2B30`,
             * buys via `sub_7B3660` then runs the standard recolor/rotate
             * climb) directly; otherwise a predecessor check via
             * `sub_7B3FC0` (`rb_decrement`) gates a second `insert_at` call
             * or returns the colliding node with `false`. Inserts the
             * current bone's own pointer (reinterpreted as `uint32_t`) into
             * its parent's just-obtained child-set, `dedupTree[parentPtr]
             * .insert(bonePtr)` inside `CON_ANI_DumpSkeleton`'s per-bone walk
             * loop (CAniSkel.cpp, not yet recovered).)
             */
            /**
             * Address: 0x008D4F10 (FUN_008D4F10, sub_8D4F10) -- local
             * `msvc8::rb_tree<moho::Resolution>::insert_unique` (dedup tree
             * for the raw binary's adapter-mode enumeration -- see the
             * `insert_at`/`FUN_008D5720` citation above for the full
             * "not yet wired, current recovered source uses a linear-scan
             * dedup instead" context). Descend loop compares the 3-int
             * `(width,height,framesPerSecond)` key at node value-offsets
             * +16/+20/+24 (skipping +12, the `Resolution::vftable` slot)
             * against the same fields on the candidate `Resolution` being
             * inserted, isNil test at +0x1D(29) -- confirmed against
             * `insert_at`'s own repeated recoloring of +0x1C(28) throughout
             * its rebalance loop (proof this is color, not isNil, matching
             * the corrected `buy_head`/`FUN_008D6940` citation above).
             * `where==leftmost()` fast path tail-calls `insert_at` directly;
             * otherwise a predecessor check via `sub_8D69D0`
             * (`rb_decrement`, cited below) gates a second `insert_at` call
             * or returns the colliding node with `false`. Its two real
             * callers are `FUN_008D21E0`/`FUN_008D26D0`
             * (`SetupPrimaryAdapterSettings`/`SetupSecondaryAdapterSettings`'s
             * RAW, un-recovered binary bodies).
             */
            /**
             * Address: 0x0083BC50 (FUN_0083BC50, sub_83BC50) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::insert_unique`
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`),
             * isNil@+0x15. Descends recording the last branch (`addLeft`),
             * fast-paths when the descent bottomed out at `leftmost()`
             * (tail-calls `insert_at`/`FUN_0083BDE0`, cited below, with
             * `addLeft=true`), otherwise confirms uniqueness against the
             * candidate directly (no separate `rb_decrement` call in this
             * emission -- the compiler folded the predecessor check into
             * the same descent that produced `where`) before tail-calling
             * `insert_at` either way. Reached from `insert_hint`'s emission
             * (`FUN_0083B320`, cited below) as its final fallback branch --
             * the same `insert_unique(v).first` tail call this member's
             * own C++ source performs. Previously mis-tracked
             * `external_dependency` ("all-external-callees thunk"); its
             * sole real callee, `sub_83BDE0`, is engine code (this
             * template's own `insert_at`), not third-party runtime.)
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
             * Address: 0x007B2DF0 (FUN_007B2DF0, sub_7B2DF0) -- `msvc8::map<
             * std::uint32_t, msvc8::set<std::uint32_t>>::insert_hint` for
             * `CON_ANI_DumpSkeleton`'s per-parent-bone dedup map (isNil@0x1D,
             * the same outer-map instantiation cited on `operator[]` in
             * `Map.h` for `FUN_007B27D0`). Matches this member's full branch
             * structure: empty/leftmost/rightmost checks, predecessor/
             * successor straddle checks, falls through to `insert_at`
             * (`sub_7B2B30`, cited on `insert_unique` above) with the
             * decided `addLeft`, fallback to `insert_unique` taking its
             * `.first`. Called from `operator[]`'s miss path (`FUN_007B27D0`)
             * with the just-descended `hint` and a freshly-built
             * `value_type(parentPtr, mapped_type())` temporary -- exactly
             * this member's documented role. `Moho::CON_ANI_DumpSkeleton`
             * itself (CAniSkel.cpp) is not yet recovered.)
             */
            /**
             * Address: 0x0083B320 (FUN_0083B320, sub_83B320) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::insert_hint`
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`),
             * isNil@+0x15. Matches this member's full branch structure:
             * empty-tree fast path straight to `insert_at` (`size_==0`
             * reads as `!dword_10C3750`), `hint == leftmost()` check,
             * `hint == end()` check against `rightmost()`, then the
             * predecessor/successor straddle checks via `sub_83C400`
             * (`rb_decrement`, cited above) / `sub_83C2E0` (`rb_increment`,
             * cited above), each falling through to `insert_at`
             * (`FUN_0083BDE0`, cited below) with the decided `addLeft`,
             * and a final fallback to `insert_unique` (`FUN_0083BC50`,
             * cited above) taking its `.first`. Reached from `operator[]`'s
             * emission (`FUN_0083A9D0`, `msvc8::map<UiKeyMask,bool>::
             * operator[]`, cited in `Map.h`) passing its own `lower_bound`
             * result as the hint -- the same "fill the gap we just
             * located" usage this member's doc comment above describes --
             * confirmed via `AddUiKeyMapEntries`'s `gUiKeyRepeatMap[keyMask]
             * = true` (`UiRuntimeTypes.cpp:1442`). Was `recovered` with no
             * citation or report at all prior to this pass -- a DB-integrity
             * gap, not a false attribution, but unverifiable either way
             * without one.)
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
             * `[node+0x2C]`/`[node+0x2D]` across every rebalance branch). Two real
             * callers, confirmed via the callgraph index and each address's own
             * decompiled body:
             *   - 0x00702A70, inside this tree's `erase_range` (cited above) --
             *     its per-node walk path erases one node and advances via this
             *     member;
             *   - 0x0070B980, inside `Moho::CArmyStats::Delete` (`CArmyStats
             *     vtable slot 0`, cited on that method in `CArmyStats.cpp`) --
             *     its `for (auto it = mNameIndex.begin(); ...) it =
             *     mNameIndex.erase(it);` walk calls this member directly through
             *     `msvc8::map::erase(iterator)`.
             * DB-integrity fix: this paragraph previously also attributed
             * 0x006FD7C0 and 0x00704A40 to this member ("the erase-and-advance
             * wrapper that CArmyStats::Delete's loop drives" / "the same lane
             * reached from ~CArmyStats"). Both were wrong -- 0x006FD7C0 is
             * confirmed by its own decompiled signature to be
             * `Moho::CArmyStats::CArmyStats(CArmyStats*, CAiBrain*)`, the
             * constructor, not a helper `Delete` calls; and 0x00704A40's own
             * decompiled body (confirmed `Moho::CArmyStats::~CArmyStats`) never
             * calls this member at all -- it inlines `mNameIndex`'s whole-tree
             * `erase_range` directly (cited on `erase_range`/`~rb_tree` above),
             * which is a different member of this same class entirely. Neither
             * claim survived checking the primary decompiled evidence.
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
            /**
             * Address: 0x00947630 (FUN_00947630, sub_947630) --
             * `gpg::gal::StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::tree_`
             * (`StateCache_D3DSAMPLERSTATETYPE.hpp`), isNil@+0x15, 8-byte
             * value_type (4-byte `_D3DSAMPLERSTATETYPE` key + 4-byte
             * `unsigned int` mapped value). Matches this member exactly:
             * `_Isnil` guard throwing `std::out_of_range("invalid map/set<T>
             * iterator")`, captures the successor via `rb_increment`
             * (`sub_946880`) before unlinking, patches `head->left`/
             * `head->right` through this instantiation's own `rb_min`/
             * `rb_max` only when the erased node was an extremum, and
             * rebalances through `sub_946D20`/`sub_946620`
             * (`rotate_left`/`rotate_right`). Single confirmed caller: this
             * instantiation's `erase_range` at 0x00947C50 (`call sub_947630`
             * at 0x00947CEF, cited below on `erase_range`) -- confirmed both
             * via the callgraph index and an exhaustive PE byte-scan (every
             * `E8`/`E9` rel32, `0F 8x` jcc rel32, `EB`/`7x` rel8 and absolute
             * dword reference in every section of
             * `bin/external/ForgedAlliance.exe`; exactly one hit). Corrects a
             * stale `external_dependency` mark that mis-read the leading
             * `std::out_of_range("invalid map/set<T> iterator")` throw-path
             * (Dinkumware's own checked-iterator debug string, reproduced
             * verbatim by every emission of this member -- see 0x006E1670
             * above) as "genuine Dinkumware STL internal, not engine logic";
             * the throw is a two-instruction guard inside an otherwise
             * complete, engine-instantiated single-node erase-with-rebalance
             * body, not an imported CRT routine.)
             * Address: 0x009478E0 (FUN_009478E0, sub_9478E0) --
             * `gpg::gal::StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned
             * int>::tree_` (`StateCache_D3DTEXTURESTAGESTATETYPE.hpp`), the
             * same isNil@+0x15, 8-byte-value_type shape as 0x00947630
             * immediately above -- a third sibling `StateCache` specialisation
             * with its own distinct rotate/min/max helper addresses. Single
             * confirmed caller: this instantiation's `erase_range` at
             * 0x00947D10 (`call sub_9478E0` at 0x00947DAF, cited below on
             * `erase_range`; one PE byte-scan hit). Same stale-
             * `external_dependency` correction as 0x00947630 above.)
             * Address: 0x00947380 (FUN_00947380, sub_947380) -- the fourth
             * sibling: `gpg::gal::StateCache<d3d9::RenderState, unsigned
             * int>::tree_`'s `erase_node`. Same isNil@+0x15, 8-byte-value
             * shape and same out_of_range-guard/rb_increment/rotate
             * structure as 0x00947630/0x009478E0 above, with its own
             * distinct rotate/min/max helper addresses (`sub_946830`,
             * `sub_946790`, `sub_946770`, `sub_946CD0`, `sub_946590`).
             * Single confirmed caller: `erase_range` at 0x00947B90 (`call
             * sub_947380`, already documented on that citation above as
             * "matching erase_node exactly"). Corrects the same
             * `CrtRuntimeHelpers.cpp` DB-integrity misfile as 0x009470E0
             * above.)
             * Address: 0x007B4040 (FUN_007B4040, sub_7B4040) --
             * `msvc8::map<std::uint32_t, msvc8::set<std::uint32_t>>::erase_node`
             * for the outer per-parent-bone dedup map from the
             * `CON_ANI_DumpSkeleton` cluster (isNil@+0x1D, the same
             * instantiation cited on `operator[]` in `Map.h` as
             * `FUN_007B27D0` and on this file's `erase_range` as
             * `FUN_007B3820`). Single confirmed caller:
             * `erase_range`/`FUN_007B3820`'s iterative walk-erase path,
             * already documented there as needing this citation
             * ("`sub_7B4AA0`/`sub_7B4040` would need their own citations
             * too... not yet done" -- landed here). `Moho::
             * CON_ANI_DumpSkeleton` itself (CAniSkel.cpp) remains
             * unrecovered.)
             * Address: 0x00951A40 (FUN_00951A40, sub_951A40) --
             * `gpg::WriteArchive::mObjRefs`'s (`std::map<const void*,
             * TrackedPointerRecord>`, `WriteArchive.cpp:934`, isNil@+0x25)
             * checked-erase-per-node half of its `~map()`/`erase(begin(),
             * end())` emission `FUN_00952300` (already cited above on
             * `~rb_tree()`/`destroy_subtree`). Sole caller is that same
             * emission; same `_SECURE_SCL` provably-unreachable-from-a-
             * full-range-erase situation as the `RRuleGameRulesImpl`
             * blueprint-map cluster resolved earlier this session
             * (`mObjRefs.clear()`, `WriteArchive.cpp:970`, always calls with
             * the full range). Not modeled for the same reason those were
             * skipped -- compiled into the binary, never exercised by the
             * one call site that reaches it.
             *
             * Address: 0x008D6650 (FUN_008D6650, sub_8D6650) -- the local
             * `msvc8::rb_tree<moho::Resolution>` dedup tree's `erase_node`
             * (isNil@+29, color@+28 -- the same instantiation cited on
             * `insert_unique`/`insert_at`/`buy_head`/`rb_decrement`/
             * `erase_range`/`destroy_subtree` elsewhere in this file). Full
             * CLRS transplant-then-fixup shape: throws `std::out_of_range
             * ("invalid map/set<T> iterator")` on a nil erase target (the
             * same `_SECURE_SCL` checked-iterator guard documented
             * throughout this file), captures the successor before
             * unlinking, patches `head->left`/`head->right` through this
             * instantiation's own `rb_min`/`rb_max` when the erased node
             * was an extremum, and rebalances through this instantiation's
             * own `rotate_left`/`rotate_right` realizations `sub_8D61D0`/
             * `sub_8D6230` (cited below on those members). Writes
             * `Resolution::\`vftable'` before `operator delete`, matching
             * `destroy_subtree`'s same vtable-write tell. Reached from this
             * instantiation's `erase_range` (`FUN_008D6080`, cited above)
             * walk path.
             *
             * Address: 0x00711BE0 (FUN_00711BE0, sub_711BE0) -- the local
             * `blueprintKeys` variable's `erase_node` in `Moho::
             * CArmyStats::ArmyXmlStatsNode` (`msvc8::set<const
             * ArmyBlueprintNameView*>`, isNil@+0x11 -- the same
             * instantiation cited on `erase_range`/`destroy_subtree` above
             * as `FUN_00711350`/`FUN_00712090`). Same `out_of_range`
             * checked-iterator guard shape as every other `erase_node`
             * emission in this file. Reached from that `erase_range`'s
             * walk path.
             *
             * Address: 0x00536010 (FUN_00536010, MSVC8 `_Tree::
             * erase(const_iterator)`) -- the category-lookup map's
             * erase-with-rebalance, `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
             * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
             * mCategoryMap` (RRuleGameRules.h/.cpp). Confirmed field-for-field
             * against the raw decompile: `isNil` guard at `[a2+89]` (decimal
             * 89 = 0x59), transplant-then-rebalance shape identical to this
             * member's body, colour/isNil read/written at `[node+88]`/
             * `[node+89]` (0x58/0x59) throughout the rebalance loop -- pins
             * this instantiation's node to the 8-byte-aligned
             * `pair<const msvc8::string, CategoryLookupValue>` shape
             * documented on `CategoryLookupValue` (RRuleGameRules.h). Captures
             * the successor via `rb_increment` (`FUN_0052CC30`, cited above),
             * re-seats `head->left`/`head->right` through this instantiation's
             * own `rb_min`/`rb_max` (`FUN_0052D960`/`FUN_00536AA0`, both
             * cited above) only when the erased node was an extremum, and
             * rebalances through `rotate_left`/`rotate_right`
             * (`FUN_00536A50`/`FUN_00536AE0`, both cited above) -- the same
             * shipped `erase_rebalance` shape this template inlines directly
             * into this member's body, not a separate symbol. Reached from
             * this instantiation's `erase_range` (`FUN_00535750`, cited
             * below) walk-one-at-a-time path; `erase_range` itself is reached
             * only from `~EntityCategoryLookupTableRuntimeView`'s implicit
             * destructor with the whole-tree range, so this member's walk
             * branch is compiled (and reachable -- `insert_at`'s rebalance
             * loop for this instantiation also calls `rotate_left`/
             * `rotate_right` directly, so the rotates are exercised at
             * runtime even where this specific per-node walk branch may not
             * be) but this member's own single-node path is not separately
             * exercised by any currently-known call site. Re-homed here from
             * a hand-rolled `EraseCategoryLookupNode` free function in
             * RRuleGameRules.cpp that performed this identical
             * transplant-and-rebalance over a
             * `CategoryLookupNodeRuntimeView*`/`EntityCategoryLookupTableRuntimeView&`
             * reach-in instead of calling it.)
             *
             * Address: 0x0083AA70 (FUN_0083AA70, sub_83AA70) -- CORRECTED:
             * `Map.h`'s `erase(const key_type&)` citation for this address
             * previously mislabeled it `UiKeyActionMap`/`msvc8::map<
             * UiKeyMask, msvc8::string>` despite already noting
             * `isNil@+0x15` -- that offset is `UiKeyRepeatMap`'s, not
             * `UiKeyActionMap`'s (see the `rotate_left`/`rotate_right`/
             * `rb_increment` corrections alongside this one). This is
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::erase_node`
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`).
             * Full CLRS transplant-then-fixup shape matching this member
             * exactly: throws `std::out_of_range("invalid map/set<T>
             * iterator")` on a nil erase target, captures the successor via
             * `rb_increment` (`FUN_0083C2E0`, corrected and cited above)
             * before unlinking, re-seats `head->left`/`head->right` through
             * this instantiation's own `rb_min`/`rb_max`-equivalent walks
             * (`FUN_0083B530`/`FUN_0083B510`, already `recovered` in
             * `moho/containers/LegacyContainerRuntime.cpp` and correctly
             * attributed there) only when the erased node was an extremum,
             * and rebalances through `rotate_left`/`rotate_right`
             * (`FUN_0083B4C0`/`FUN_0083B570`, both cited above). Called
             * with an already-resolved node/iterator, not a raw key --
             * `RemoveUiKeyMapEntries`'s own binary body (`FUN_00839270`)
             * performs its own inline lower-bound descent and conditional
             * call, matching `Map.h`'s `erase(const key_type&)` shape
             * (`find_node` then conditional `erase_node`) fused into the
             * caller rather than compiled as a separate `erase(key)`
             * symbol for this instantiation -- confirmed via
             * `RemoveUiKeyMapEntries`'s `gUiKeyRepeatMap.erase(keyMask)`,
             * `UiRuntimeTypes.cpp:1466` (not `:1465`, which is the sibling
             * `gUiKeyActionMap.erase(keyMask)` call the mislabeled citation
             * pointed at instead).)
             */
            /**
             * Address: 0x00687CC0 (FUN_00687CC0, `erase(const_iterator)` for
             * `msvc8::map<std::uint32_t, moho::IdPool>` -- `CEntityDb::
             * mIdPoolTree` in `EntityDb.h`. 251-instruction body, unmistakably
             * this member: checked-iterator guard throwing `std::out_of_range(
             * "invalid map/set<T> iterator")` on a nil node (isNil@node+0xCC9,
             * matching `rb_min`'s 0x006880F0 citation above), successor
             * capture via `sub_6878C0` (`rb_increment`, cited above as this
             * instantiation's `_Inc`) before any unlinking, the one-child/
             * two-child relink split (`fix`/`fixParent` bookkeeping matches
             * this member field for field), re-seating `head->left`/
             * `head->right` through this instantiation's own `rb_min`/
             * `rb_max` (`sub_6880F0`/`sub_688830`, both cited above) only
             * when the erased node was an extremum, the black-height
             * rebalance loop calling this instantiation's `_Lrotate`/
             * `_Rrotate` (`sub_6880A0`/`sub_688120`, both already cited on
             * those members below) exactly where `erase_rebalance` does, and
             * finally the node's value teardown before `operator delete`.
             *
             * The value teardown is the one place this emission's shape does
             * not reduce to a bare `n->value.~value_type()` today: `IdPool`/
             * `SimSubRes2` (`IdPool.h`) currently declare no destructors, so
             * `~pair<const uint32_t, IdPool>()` would be non-trivial only via
             * `mReleasedLows`'s implicit `~BVIntSet()` (real `~FastVectorN()`
             * on `mWords`) -- it would NOT reproduce `mSubRes2`'s teardown,
             * because `SimSubRes2::mData` is currently modelled as a plain
             * `SimSubRes3[100]` array, and an implicit `~SimSubRes2()` over
             * that shape would loop all 100 slots unconditionally. The
             * shipped body does not: it calls `struct_CyclicBuffer100_
             * BVIntSet::struct_CyclicBuffer100_BVIntSet` (0x00403E70, already
             * identified and recovered as `SimSubRes2::Reset()` in
             * `IdPool.cpp` -- confirmed byte-identical against that address's
             * own decompile: the bounded `while (mStart != mEnd) PopOldest();`
             * drain, not a blind 100-element pass) on `node+0x40` (`mSubRes2`,
             * landing exactly at the end of `rb_min`'s cited node layout:
             * value starts node+0x10, `IdPool`@node+0x18, `mSubRes2`@
             * `IdPool`+0x28 = node+0x40, sized 0xC88 to land exactly on
             * colour@node+0xCC8), then inlines `mReleasedLows.mWords`'s
             * `~FastVectorN()` release (`node+0x28`..`+0x34`: `if (begin !=
             * &inline) { delete[] begin; begin = &inline; }`, matching
             * `FastVectorN.h`'s already-recovered 0x00401DE0 body) before
             * `operator delete(node)`. `IdPool::IdPool()` (0x00403920)
             * confirms the same asymmetry from the construction side: it
             * never touches `mData`, only `mUnused.mStart`/`mEnd` (see
             * `IdPool.h`'s ctor citation) -- consistent with `mData` being
             * raw, placement-managed storage in the true 2007 source rather
             * than an auto-constructed/destructed array, which `IdPool.h`'s
             * current recovery does not yet model. This citation records the
             * evidence rather than guessing the fix: retyping `SimSubRes2::
             * mData` to raw storage (with `AsBitSet`-style typed access, as
             * `IdPool.cpp` already does for individual slots) would let a
             * bare `n->value.~value_type()` reproduce this exactly, but that
             * change ripples into `Sim.cpp` (`pool.mSubRes2.mData[retireIndex]`
             * as a named `SimSubRes3&`), `CCommandDb.cpp` and
             * `IdPoolTypeInfo.cpp` (`.mSubRes2.Reset()` call sites) and
             * deserves its own verified pass rather than a rushed edit here.
             * The divergence is behaviourally inert either way (a redundant,
             * always-safe 100x SBO check nothing currently exercises), which
             * is why it is flagged rather than blocking this recovery.
             *
             * Reached from `erase_range`'s emission for this instantiation
             * (`FUN_00687190`, cited below) via `erase(_First++)` in its
             * general (non-whole-tree) loop branch -- the same "successor
             * captured, old cursor erased" pattern documented on
             * `rb_increment` throughout this file.
             */
            /**
             * Address: 0x00A633D0 (FUN_00A633D0, sub_A633D0) -- the same
             * `msvc8::set<std::uint32_t>` instantiation cited on `equal_range`/
             * `erase(const key_type&)` above (isNil@+0x11, colour@+0x10).
             * Matches this member field for field: `_Isnil` guard building and
             * throwing `std::out_of_range("invalid map/set<T> iterator")`
             * (`std::logic_error::logic_error` then a vftable patch to
             * `std::out_of_range` before `CxxThrowException`, the same
             * two-step construction this file's other `erase_node` emissions
             * use), successor capture via `sub_A52760(&a3)` (`rb_increment`,
             * matching `node_type* const next = rb_increment(erased);` before
             * any unlinking), the one-child/two-child relink split, re-seating
             * `head->left`/`head->right` through this instantiation's own
             * `rb_min`/`rb_max` (`sub_A52650`/`sub_A52630`, both cited above)
             * only when the erased node was an extremum, the colour swap at
             * node+0x10 for the two-child case, and the black-height rebalance
             * loop (colour checks at +0x10) calling what are almost certainly
             * this instantiation's own `rotate_left`/`rotate_right`
             * (`sub_A553A0`/`sub_A553F0` -- identified but not separately
             * disambiguated/cited in this pass; a follow-up can confirm which
             * is which from their own bodies). Was previously (and
             * incorrectly) marked `recovered` in `recovered_progress.json`
             * with zero source citation anywhere in `src/sdk` -- this
             * citation is that missing source mapping. Reached from
             * `Wm3::ConvexHull3<float>::~ConvexHull3()` (0x00A66440) via
             * `erase_range`'s (0x00A65320, cited above) `erase(_First++)`
             * loop when tearing down the `rb_tree` member at `this+0x68`.
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
             * always the whole-tree fast path in that caller. Also reached
             * from `FUN_00537420`'s inlined `RRuleGameRulesLuaExportBinding
             * ::mPendingBlueprintOrdinals` assignment
             * (`legacy/containers/Vector.h`'s `insert(pos,count,value)`
             * in-place tail-shift loop, cited there) at 0x00537458 --
             * erases the DESTINATION slot's own live tree before
             * `sub_530EE0` (`copy_from`'s emission for this instantiation,
             * cited below) clones the source slot's tree into it; same
             * whole-tree-fast-path shape, `[leftmost(), header())` again. A
             * prior pass on the `Vector.h` citation misread this call as a
             * "copy-construct helper", which is not what `erase_range`
             * does anywhere else in this file; corrected there.)
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
            /**
             * Address: 0x00947C50 (FUN_00947C50, sub_947C50) -- the
             * sampler-state cache's own `erase_range`, following up on the
             * "flagged for whoever next touches `StateCache`" note directly
             * above: a distinct address from 0x00947B90, not an ICF twin of
             * it, because this era's `link.exe` folds identical COMDATs by
             * raw byte comparison, and a body containing a `call` to another
             * per-instantiation address bakes that instantiation's own
             * relative displacement into its bytes -- byte-identical
             * algorithm shapes across sibling node families still occupy
             * separate addresses.
             *
             * Same two-shape split as 0x00947B90: the whole-tree fast path
             * (`first == leftmost() && last == header()`) calls `sub_947120`
             * (`destroy_subtree`, cited below) on the root, relinks
             * `head->parent`/`head->left`/`head->right` to `head` and zeroes
             * size, then returns `leftmost()`; otherwise walks
             * `erase(_First++)` via `sub_947630` (`erase_node`, cited
             * above), computing the in-order successor inline before each
             * erase exactly like this member's walk loop.
             *
             * Five real callers -- confirmed both via the callgraph index and
             * an exhaustive PE byte-scan (every `E8`/`E9` rel32, `0F 8x` jcc
             * rel32, `EB`/`7x` rel8 and absolute dword reference in every
             * section of `bin/external/ForgedAlliance.exe`; no others exist):
             *   - 0x009480E9, inside `sub_9480D0` --
             *     `gpg::gal::StateCache<_D3DSAMPLERSTATETYPE, unsigned
             *     int>`'s non-deleting destructor lane
             *     (`RuntimeDestroySamplerStateCacheTreeOnlyLaneA`,
             *     `StateCache.cpp`);
             *   - 0x009481FC, inside `sub_9481E0` -- the same class's real
             *     destructor (`~StateCache<_D3DSAMPLERSTATETYPE, unsigned
             *     int>`, `StateCache.cpp`). Both inline this member's whole
             *     `erase_range(begin(), end())` call directly rather than
             *     going through a separate `~rb_tree()` symbol -- exactly the
             *     evidence the 0x00947B90 note above says a future
             *     `StateCache` pass needs: `tree_`'s real layout is a proper
             *     header-pointer-owning `msvc8::map<_D3DSAMPLERSTATETYPE,
             *     unsigned int>` (heap-allocated header, explicit `operator
             *     delete` on it after the erase), not `msvc8::EmbeddedTree<>`
             *     -- `StateCache_D3DSAMPLERSTATETYPE.hpp` is retyped to
             *     `msvc8::map` alongside this citation, and both dtors above
             *     drop their `tree_.clear()` call in favour of `tree_`'s own
             *     implicit member destruction, which reproduces this exact
             *     `erase_range` + `free_raw(head_)` sequence;
             *   - 0x00947E12/0x00947EA2/0x00947F32, inside `sub_947E00`/
             *     `sub_947E90`/`sub_947F20` -- three byte-for-byte identical
             *     `~rb_tree()` emissions (this member's `erase_range(
             *     leftmost(), header())` then `operator delete` the header
             *     then zero head/size) for this same isNil@+0x15, 8-byte-
             *     value node shape, cited on `~rb_tree()` below. All three
             *     have zero incoming references of any kind anywhere in the
             *     binary (raw IDA xrefs, callgraph index, and the same
             *     exhaustive PE byte-scan all agree); their owning member is
             *     a `CScApp`-vtable-neighbourhood class distinct from
             *     `StateCache` (reachable via `??_7CScApp@@6B@` like every
             *     other body in this address range, per the callgraph
             *     index's `reachable` table), not pinned down further in
             *     this pass.
             */
            /**
             * Address: 0x00702A70 (FUN_00702A70) -- `Moho::CArmyStats::
             * mNameIndex`'s own `erase_range` for `msvc8::map<msvc8::string,
             * CArmyStatItem*>` (isNil@+0x2D, 0x20-byte value_type, 0x30-byte
             * node -- `moho::ArmyNameIndexNode` in `CArmyStats.h`). Four real
             * callers, all confirmed via the callgraph index:
             *   - 0x006FD8B0/0x00701570 -- two `~rb_tree()` emissions for this
             *     tree, cited on `~rb_tree()` above (one reached from
             *     `CArmyStats::CArmyStats`'s exception-unwind funclet, one a
             *     zero-incoming-reference duplicate);
             *   - 0x00702060 -- not independently exported in this pass;
             *   - 0x00704A40, inside `Moho::CArmyStats::~CArmyStats` itself --
             *     confirmed by that address's own decompiled body, which calls
             *     this member directly and inline rather than through a named
             *     wrapper: `sub_702A70((int)v2, (int)a2->mStats._Myhead->
             *     _Left, (int)a2->mStats._Myhead)` followed by `operator
             *     delete(a2->mStats._Myhead)` and zeroing `_Myhead`/`_Mysize`
             *     -- this member's whole-tree fast path, instruction for
             *     instruction. `~CArmyStats`'s recovered source previously
             *     called an invented `DestroyNameIndexTree()` for this; no
             *     such symbol exists anywhere in the binary; `mNameIndex`'s
             *     automatic member destruction (which reaches this member
             *     implicitly) is the entire real emission.
             */
            /**
             * Address: 0x00947D10 (FUN_00947D10, sub_947D10) -- `gpg::gal::
             * StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>`'s own
             * `erase_range`: a third, distinct emission alongside 0x00947B90
             * (`RenderState`) and 0x00947C50 (`SamplerState`) above, for the
             * same byte-exact-ICF reason. Same two-shape split: whole-tree
             * fast path calls `sub_947160` (`destroy_subtree`, cited below);
             * walk path calls `sub_9478E0` (`erase_node`, cited above).
             *
             * Five real callers (callgraph index + exhaustive PE byte-scan,
             * same method as 0x00947C50 above):
             *   - 0x00948169, inside `sub_948150` --
             *     `RuntimeDestroyTextureStageStateCacheTreeOnlyLaneA`
             *     (`StateCache.cpp`);
             *   - 0x0094824C, inside `sub_948230` -- `~StateCache<
             *     _D3DTEXTURESTAGESTATETYPE, unsigned int>` (`StateCache.
             *     cpp`), the same inlined-`erase_range`-plus-explicit-
             *     `delete`-the-header shape as the Sampler and RenderState
             *     destructors, and retyped to `msvc8::map` in the same pass;
             *   - 0x00947E42/0x00947ED2/0x00947F62, inside `sub_947E30`/
             *     `sub_947EC0`/`sub_947F50` -- three more zero-incoming-
             *     reference `~rb_tree()` emissions for this same node shape,
             *     cited on `~rb_tree()` below.
             */
            /**
             * Address: 0x007B3820 (FUN_007B3820, `msvc8::map<std::uint32_t,
             * msvc8::set<std::uint32_t>>::erase_range` -- the *outer*
             * per-parent-bone dedup map's own `erase_range` (isNil@+0x1D,
             * same 32-byte-node instantiation as `Map.h`'s `operator[]`
             * citation `FUN_007B27D0`). Same two-shape split as the other
             * instantiations in this file: whole-range fast path
             * (`first==begin() && last==end()`) calls a `destroy_subtree`-
             * shaped helper (`sub_7B4AA0`) and resets head/size; walk path
             * does an iterative successor-walk erase via `sub_7B4040`
             * (`erase_node`-shaped, single-node erase-and-rebalance).
             * Reached from `CON_ANI_DumpSkeleton`'s cleanup,
             * `dedupTree.erase(dedupTree.begin(), dedupTree.end())` right
             * before `operator delete`-ing the tree header (CAniSkel.cpp,
             * not yet recovered). `sub_7B4AA0`/`sub_7B4040` would need their
             * own citations as `destroy_subtree`/`erase_node` for this same
             * node shape, not yet done.)
             *
             * Address: 0x00580600 (FUN_00580600, sub_580600) --
             * `Moho::CAiBrain::mBuildStructureMap`'s own `erase_range`
             * (isNil@+0x25, same node instantiation cited on this file's
             * `erase(const_iterator)` entry, `FUN_0057DA50`, in Map.h).
             * Same two-shape split as the other instantiations here:
             * whole-range fast path (`first==leftmost() && last==header()`)
             * calls the already-cited `destroy_subtree` realization
             * `sub_5812C0` and resets head/size; walk path does an
             * iterative successor-walk erase via the already-cited
             * `erase_node` realization `sub_57DA50`.
             *
             * Address: 0x00952240 (FUN_00952240, sub_952240) -- `gpg::
             * WriteArchive::mRefCounts`'s `erase_range` (`msvc8::map<const
             * gpg::RType*, int>`, isNil@+0x15, the same instantiation cited
             * on the sentinel-allocate lane above, WriteArchive.cpp).
             * Reached from `WriteArchive`'s destructor (`FUN_00953150`,
             * `~WriteArchive`, WriteArchive.cpp) via `mRefCounts.clear()`.)
             *
             * Address: 0x007CA050 (FUN_007CA050, sub_7CA050) -- `Moho::
             * SPeer::establishedUids`'s `erase_range` (`msvc8::set<
             * int32_t>`, isNil@+0x11). Reached from `SPeer`'s destructor
             * (`FUN_007C1340`, SPeer.cpp/.h) teardown of
             * `establishedUids`.)
             *
             * Address: 0x00711350 (FUN_00711350, sub_711350) -- the local
             * `blueprintKeys` variable's `erase_range` in `Moho::
             * CArmyStats::ArmyXmlStatsNode` (`msvc8::set<const
             * ArmyBlueprintNameView*>`, isNil@+0x11, 4-byte pointer
             * value_type, CArmyStats.cpp:965). Whole-range fast path calls
             * `sub_712090` (`destroy_subtree`, this same instantiation,
             * cited below); walk path erases node-by-node via `sub_711BE0`
             * (`erase_node`, cited below). Reached from `blueprintKeys`'s
             * automatic (compiler-generated) end-of-scope destruction at
             * the close of `ArmyXmlStatsNode`.)
             *
             * Reached from
             * `CAiBrain::~CAiBrain` (`FUN_0057A1E0`, CAiBrain.cpp) via
             * `DestroyBuildStructureMap` -- confirmed directly from the
             * destructor's own raw decompile, which calls this address as
             * its fourth cleanup step (right after the three `CTaskStage`
             * teardowns `DestroyTaskStageAndDelete` already recovers) with
             * a 3-pointer-argument shape matching `(outIter, first, last)`,
             * not the argument-less `tree_::clear()` the source previously
             * called; IDA mis-typed the `this`/argument registers here as
             * `Moho::CScriptObject`/`LuaPlus::LuaObject` fields from an
             * unrelated class, which is why the raw `.c` export reads as
             * script-object teardown at this call site.)
             *
             * Address: 0x008D6080 (FUN_008D6080, sub_8D6080) -- the local
             * `msvc8::rb_tree<moho::Resolution>` dedup tree's `erase_range`
             * (isNil@+29, the same instantiation cited on `insert_unique`/
             * `insert_at`/`buy_head`/`rb_decrement` elsewhere in this file).
             * Whole-range fast path calls the already-cited-below
             * `destroy_subtree` realization `sub_8D6B70`; walk path erases
             * node-by-node via `sub_8D6650` (`erase_node`, cited below).
             * Five real callers, all in `StartupHelpers.cpp`'s adapter-mode
             * enumeration family: `FUN_008D21E0` (`SetupPrimaryAdapterSettings`,
             * already recovered -- though its CURRENT source uses a
             * simplified `HasMode` linear-scan dedup instead of this tree,
             * a documented follow-up, see the `insert_unique`/`FUN_008D4F10`
             * citation above) plus `FUN_008D26A0`/`FUN_008D26D0`/
             * `FUN_008D4ED0`/`FUN_008D58F0` (sibling adapter-setup
             * functions using the same local-tree pattern, not yet
             * individually traced).
             *
             * Address: 0x0077BD90 (FUN_0077BD90, sub_77BD90) -- CDecalBuffer's
             * start-tick outer table's `erase_range` (`std::map<unsigned,
             * std::set<CDecalHandle*>>`, isNil@+29, 0x20 outer node --
             * see this file's own note on the CDecalBuffer start-tick family
             * elsewhere). Whole-range fast path calls `sub_77CFE0`
             * (`destroy_subtree`, this same instantiation); walk path calls
             * `sub_77A3C0` -- CORRECTED elsewhere in this file from a
             * mis-labeled "insert with rebalance" note to its real role,
             * `erase_node` (see that citation, above the `insert_at`
             * cluster it was previously filed under).
             *
             * Address: 0x00535750 (FUN_00535750, MSVC8 `_Tree::
             * erase(first, last)`) -- the category-lookup map's
             * `erase_range`, `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
             * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
             * mCategoryMap` (RRuleGameRules.h/.cpp). Confirmed against the
             * raw decompile: whole-range fast path
             * (`first==head->left && last==head`) calls `sub_5369D0`
             * (`destroy_subtree`, cited above) on the root, resets the head
             * self-links and zeroes size, returning the (now-self-linked)
             * `head->left`; the walk path advances the cursor via the
             * successor step inlined ahead of each iteration and calls
             * `sub_536010` (`erase_node`, cited above) on the old cursor --
             * matching this member's two-shape split exactly. Sole caller:
             * `~EntityCategoryLookupTableRuntimeView`'s implicit destructor
             * (via `mCategoryMap`'s own destructor, `~rb_tree()` below),
             * always with `[leftmost(), header())` -- i.e. always this
             * member's whole-tree fast path in this instantiation's actual
             * runtime usage; the walk-path branch that calls `erase_node`
             * node-by-node is compiled (this member handles both shapes in
             * one function body) but not separately exercised by any
             * currently-known call site of this specific map. Re-homed here
             * from a hand-rolled `EraseCategoryLookupNodeRange` free
             * function in RRuleGameRules.cpp that performed this identical
             * two-shape dispatch over a
             * `CategoryLookupNodeRuntimeView*`/`EntityCategoryLookupTableRuntimeView&`
             * reach-in instead of calling it.)
             */
            /**
             * Address: 0x00687190 (FUN_00687190, `erase(iterator, iterator)`
             * for `msvc8::map<std::uint32_t, moho::IdPool>` -- `CEntityDb::
             * mIdPoolTree` in `EntityDb.h`. Matches this member's two-shape
             * split exactly: `cmp [first],[head->left] / cmp [last],[head]`
             * gates the whole-tree fast path (`sub_688030` = `destroy_
             * subtree`, cited above, on `head->parent`, then self-link
             * `head`'s three fields and zero size), else `do { successor =
             * rb_increment(cursor) via sub_6878C0; erase_node(cursor) via
             * sub_687CC0; cursor = successor; } while (cursor != last)`
             * (both cited above).
             *
             * Four real callers, all `[leftmost(), header())` -- always the
             * whole-tree fast path:
             *   - `0x006843B0` (`Moho::EntityDB::~EntityDB`, cited in full on
             *     `~rb_tree()` above) -- `mIdPoolTree`'s implicit member
             *     destruction, inlining `~rb_tree()`'s body but keeping this
             *     call out-of-line.
             *   - `0x00684310` (`sub_684310`, cited separately below, right
             *     after `~rb_tree()`) -- `CEntityDb::CEntityDb`'s (0x00684230)
             *     SEH unwind funclet for the already-constructed
             *     `mIdPoolTree` member, should a later member's construction
             *     throw. Sole caller confirmed via this pass's xref sweep
             *     (`type=19` edge from 0x00684230, the same edge-type this
             *     file already uses elsewhere for constructor-unwind
             *     callers, e.g. `j_??0struct_sim_subres2@@QAE@@Z_0`'s
             *     0x00403C50 caller of `SimSubRes2::Reset()`/0x00403E70).
             *   - `0x00685850`/`0x00686660` -- byte-identical siblings of
             *     `0x00684310` (same body: `erase_range(head->left, head)`
             *     then `operator delete(head)` and zero head/size). Both are
             *     already `skip` in `recovered_progress.json`, backed by an
             *     exhaustive PE byte-scan (every rel32/rel8/absolute-dword
             *     reference in `bin/2025.7.1` and `bin/external`) finding
             *     zero incoming references of any kind -- genuinely
             *     unreferenced compiler output (TUs built without `/Gy`/
             *     `/OPT:REF` stripping it), not a source-mapped call site.
             *     Left uncited/uninvoked here to match that verdict; noted
             *     only so a future reader does not mistake the silence for
             *     an unchecked gap.
             *
             * Reached in practice via `mIdPoolTree`'s membership in
             * `CEntityDb` (`EntityDb.h`) -- `~CEntityDb()`'s implicit member
             * destruction (`EntityDb.cpp`) is what triggers `~rb_tree()`,
             * which is what calls this member.
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
             * Address: 0x00A65B60 (FUN_00A65B60, sub_A65B60) -- the same
             * `msvc8::set<std::uint32_t>` instantiation cited on `equal_range`
             * above (isNil@+0x11), erase-by-key. `this`=ecx=tree, one stack arg
             * = `const key_type&`, `retn 4` -- a real `__thiscall` member.
             * Re-homed out of `moho/math/Wm3DistanceFafExtras.cpp`'s `QueryTree`
             * reach-in cluster (`EraseQueryTreeKeyRangeNil17LaneA`), which hand-
             * rolled this exact algorithm as an uncited private RB-tree
             * reimplementation (`QueryTreeCountNodesInRange`/`QueryTreeEraseRange`/
             * `QueryTreeEraseSingleNode`/`QueryTreeRotateLeft`/`QueryTreeRotateRight`,
             * none of which carried an `Address:` citation) instead of calling
             * this shared template.
             * Address: 0x00A65C10 (FUN_00A65C10, sub_A65C10) -- a second, non-
             * ICF-folded real emission of the same member (confirmed distinct
             * from 0x00A65B60 via `_callgraph_index.sqlite`'s `function_icf_twins`
             * view: zero twins recorded for either address).
             *
             * What it does:
             * `equal_range(k)` locates `[first,last)`, then the shipped body
             * calls a checked "how many nodes between these two iterators"
             * counting helper (`sub_A598A0`, stepping via the `rb_increment`-
             * equivalent `sub_A52760`) before erasing the range through
             * `erase_range` (0x00A65320, cited above) -- exactly the classic
             * Dinkumware `_Tree::erase(const key_type&)` shape (necessary
             * because `_Tree` is shared by `set`/`map`/`multiset`/`multimap`
             * and can't assume at most one match). `sub_A598A0`/`sub_A52760`
             * are themselves real addresses, currently misfiled as a blocked
             * token in `moho/misc/CrtRuntimeHelpers.cpp` (out of scope for this
             * pass); the count loop below reconstructs the same observable
             * behavior with `rb_increment`, which is already canonical here,
             * rather than re-citing an unrecovered helper under a new name.
             */
            size_type erase(const key_type& k)
            {
                const std::pair<node_type*, node_type*> range = equal_range(k);
                size_type count = 0;
                for (node_type* n = range.first; n != range.second; n = rb_increment(n)) {
                    ++count;
                }
                (void)erase_range(range.first, range.second);
                return count;
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
            /**
             * Address: 0x00947290 (FUN_00947290, sub_947290) --
             * `gpg::gal::StateCache<_D3DSAMPLERSTATETYPE, unsigned int>`'s
             * tree shape (isNil@+0x15, 8-byte value_type; shares
             * `destroy_subtree` at 0x00947120 with the confirmed
             * `StateCache<SamplerState>` cluster cited on `erase_range`/
             * `erase_node` above). `destroy_subtree(root())` via
             * `sub_947120` then self-links `head->parent`/`head->left`/
             * `head->right` to `head` and zeroes `size_` -- matches this
             * member exactly. Zero incoming references anywhere in the
             * binary (raw IDA xrefs, callgraph index, and an exhaustive PE
             * byte-scan covering every `E8`/`E9` rel32, `0F 8x` jcc rel32,
             * `EB`/`7x` rel8 and absolute dword reference in every section
             * of `bin/external/ForgedAlliance.exe` all agree). Not reached
             * from any of `StateCache<SamplerState>`'s own recovered
             * methods -- those all go through `erase_range` (0x00947C50,
             * above) -- so its owner is a distinct member of the same
             * unidentified `CScApp`-neighbourhood class as the zero-
             * reference `~rb_tree()` emissions cited on `erase_range`
             * above.)
             * Address: 0x009472C0 (FUN_009472C0, sub_9472C0) -- the same
             * shape for `gpg::gal::StateCache<_D3DTEXTURESTAGESTATETYPE,
             * unsigned int>`'s tree family (`destroy_subtree` at
             * 0x00947160, cited on `erase_range` above). Same zero-
             * incoming-reference status as 0x00947290.)
             */
            /**
             * Address: 0x007B4950 (FUN_007B4950, `msvc8::set<std::uint32_t>`'s
             * `clear()` -- isNil@+0x11, the same instantiation cited on
             * `destroy_subtree`/`alloc_raw`/`free_raw`/`buy_head`/
             * `rb_increment` throughout this file. Destroys the subtree from
             * the root via `sub_7B4D10` (`destroy_subtree`, cited above) then
             * self-links `head->parent`/`head->left`/`head->right` back to
             * `head` and zeroes `size` -- matches this member's body
             * instruction for instruction. DB-integrity fix: this token was
             * marked `recovered` with `source_paths=null` and a
             * boilerplate "batch 0x007B**** pass" note that cited nothing;
             * a full `src/sdk` sweep found zero real citations anywhere.
             * Owning field not yet pinned to a specific class -- reached
             * through the same `msvc8::set<std::uint32_t>` neighbourhood as
             * `alloc_raw`/`buy_head`/`rb_increment`'s 0x007B**** citations
             * below, whose only confirmed callers are the three explicit
             * destroy-and-reconstruct helpers in `moho/sim/
             * SimRecoveryRuntime.cpp` cited on `destroy_subtree` above.)
             *
             * Address: 0x005551F0 (FUN_005551F0, `Moho::EntityCategorySet::
             * EntityCategorySet`'s tail, 0x0055525A-0x00555276) -- the
             * category-lookup map's constructor calls this member's exact
             * body on the tree it just default-constructed a few
             * instructions earlier: `destroy_subtree(root())` (a no-op on
             * the fresh, still-empty tree -- cited above) then the same
             * three-self-link-plus-zero-size reset. Confirmed against the
             * raw decompile: this is a second, redundant destroy-and-reset
             * pass over an already-empty tree, distinct from (and following)
             * the buy_head-equivalent allocate-and-self-link sequence cited
             * on `buy_head` below. `EntityCategoryLookupTableRuntimeView`'s
             * constructor (RRuleGameRules.h/.cpp) keeps this as an explicit
             * `mCategoryMap.clear();` call for exact instruction-sequence
             * fidelity with FUN_005551F0, rather than silently dropping it
             * as dead code -- it is behaviorally inert (the tree is already
             * empty) but genuinely present in the binary's instruction
             * stream.
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
            /**
             * Address: 0x00946F90 (FUN_00946F90, sub_946F90)
             *
             * This instantiation's `alloc_raw` half is a value-initializing
             * variant the compiler fused with the neutral-node init:
             * `operator new(0x18)`, zero the three link dwords, `color=1`
             * (black), `isNil=0` -- one step further than this member's own
             * plain `operator new`, but the extra stores are exactly what
             * `buy_head()` needs next. Its caller, `FUN_009471A0` (already
             * recovered, cited on `buy_head` below), performs the
             * self-link-to-head and `isNil=1` fixup that finishes the head
             * sentinel -- the same two-function split documented there for
             * `FUN_00947FE0`'s sibling `sub_947030`. isNil@+0x15, node 0x18
             * (8-byte value_type). Owning field/class not yet pinned down,
             * matching the sibling citation on `buy_head` below.
             *
             * Address: 0x007B4410 (FUN_007B4410, sub_7B4410)
             *
             * Same value-initializing `alloc_raw` shape: `operator new(0x20)`,
             * zero the three link dwords, `color=1`/`isNil=0` at
             * `[eax+0x1C]`/`[eax+0x1D]` (confirmed via `.asm`) -- isNil@+0x1D,
             * node 0x20 (16-byte value_type). Reached from `Moho::
             * ANI_DumpSkeleton` (partial, `FUN_007B22B0`, CAniSkel.cpp),
             * which builds a dedup tree over skeleton bone data while
             * walking the animation hierarchy.
             *
             * Address: 0x0087C990 (FUN_0087C990, sub_87C990)
             *
             * Same shape again: `operator new(0x18)`, zero the three link
             * dwords, `color=1`/`isNil=0` at `[eax+0x10]`/`[eax+0x11]` --
             * isNil@+0x11, node 0x18 (4-byte value_type, e.g. a dedup
             * `set<float>`/`set<uint32_t>`). Reached from `Moho::
             * CDecalManager::RebuildLodHistogram` (CWldSplat.cpp/.h), which
             * dedups the 10-entry decal-area decile histogram.
             *
             * Address: 0x007B4A50 (FUN_007B4A50, sub_7B4A50) -- the
             * `msvc8::set<std::uint32_t>` instantiation cited on `buy_head`/
             * `rb_increment`/`clear`/`destroy_subtree` elsewhere in this
             * file (isNil@+0x11, node 0x14=20 bytes, "12+4+2=18 rounded to
             * 20" -- the same formula as `FUN_007CAB70`/`FUN_0052F370`
             * above). `operator new(20)` via `sub_7B4E50` (the shared
             * checked-20-byte lane, `AllocateChecked20ByteElements` in
             * `Vector.cpp`), zero the three link dwords, `color=1`/
             * `isNil=0` at `[eax+0x10]`/`[eax+0x11]` -- matches this member
             * exactly, with the same "null tests the binary emits after
             * each derived pointer are compiler artifacts that cannot
             * fire" caveat already documented on `WeakEntitySetUserEntity::
             * BuyNode` (WeakEntitySet.h). DB-integrity fix: this token was
             * previously flipped `blocked` citing a `CrtRuntimeHelpers.cpp`
             * source path the address never appeared in (2026-08-21
             * citation-audit revert); this is the real source. Called by
             * this member's fused `buy_head()` emission `FUN_007B3F30`
             * (cited there) for header construction; owning field not yet
             * pinned to a specific class.)
             * Address: 0x00947030 (FUN_00947030, sub_947030) -- another
             * instantiation of this member, 8-byte value_type (node 0x18=24
             * bytes), `color`/`isNil` at `[eax+0x14]`/`[eax+0x15]` --
             * `operator new(0x18)`, zero the three link dwords, `color=1`/
             * `isNil=0`, exactly this member's shape. Called by the
             * `buy_head()`-equivalent ctor emission `FUN_00947FE0` (cited
             * above on `rb_tree()`, "the `this`-returning sibling emission"
             * paragraph) as its dedicated `alloc_raw` half; owning
             * field/class not yet pinned down (isNil@+0x15, 8-byte-value
             * shape recurs across many Sim-subsystem containers per that
             * same paragraph).
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
            /**
             * Address: 0x007B3F90 (FUN_007B3F90, sub_7B3F90) -- the
             * `msvc8::set<std::uint32_t>` instantiation cited on
             * `alloc_raw`/`buy_head`/`rb_increment`/`clear`/
             * `destroy_subtree` throughout this file (isNil@+0x11). Plain
             * `::operator delete(a1)`, matching this member exactly. Zero
             * incoming xrefs in this sweep. DB-integrity fix: this token
             * was marked `recovered` with `source_paths=null` and a
             * boilerplate "batch 0x007B**** pass" note that cited nothing;
             * a full `src/sdk` sweep found zero real citations anywhere.
             * Owning field not yet pinned to a specific class.)
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
            /**
             * Address: 0x0087C3B0 (FUN_0087C3B0, fused allocate/self-link/
             * isNil=1 buy_head for an unidentified `Moho::CDecalManager` map/
             * set member -- writes `left=parent=right=0`, then `isNil@+0x14=1`,
             * `color@+0x15=0`. Sibling FUN_0087C5F0 below is byte-identical
             * except its `alloc_raw` callee, so the two are distinct
             * `CDecalManager` map instantiations, not ICF twins. Both reached
             * from `Moho::CDecalManager::CDecalManager` (0x00877A60); the
             * owning member names are not yet pinned down.)
             * Address: 0x0087C5F0 (FUN_0087C5F0, sibling emission described
             * above -- a second, distinct `CDecalManager` map/set instantiation)
             */
            /**
             * Address: 0x008D6940 (FUN_008D6940, sub_8D6940) -- generic
             * "buy a blank node" half for a local `msvc8::rb_tree<
             * moho::Resolution>` (value_type IS the key -- ordered by
             * `(width,height,framesPerSecond)`, used to dedup adapter
             * display modes; `Resolution` already recovered,
             * `StartupHelpers.h:131-180`, `sizeof==0x10`). Writes
             * `left=parent=right=0`, `color@+0x1C(28)=1`, `isNil@+0x1D(29)=0`
             * -- CORRECTING an earlier mis-read of this same body that had
             * these two fields backwards (proven by `insert_at`'s own
             * rebalance loop, which repeatedly recolors `+28` throughout,
             * and by `insert_unique`'s loop-termination test on `+29`; see
             * those citations below). This is a generic blank-node buy, not
             * head-specific: called directly from `SetupPrimaryAdapterSettings`
             * (0x008D21E0, the RAW un-recovered binary body -- the CURRENT
             * recovered `StartupHelpers.cpp` body is a simplified rewrite
             * that dedups via a linear `HasMode` scan instead of this tree,
             * see the follow-up note on `insert_unique` below), which
             * overwrites `isNil=1` immediately after to promote this
             * specific call's result into the tree's head sentinel; other
             * call sites (via `insert_at`/`FUN_008D5720`'s `sub_8D6280`)
             * leave `isNil=0` for genuine data nodes.)
             */
            /**
             * Address: 0x007B3F30 (FUN_007B3F30, sub_7B3F30) -- the
             * `msvc8::set<std::uint32_t>` instantiation cited on
             * `alloc_raw`/`free_raw`/`rb_increment`/`clear`/`destroy_subtree`
             * throughout this file (isNil@+0x11). `alloc_raw`'s work
             * (buy + link-zero + color=black + isNil=0) is split out into a
             * separate callee (`sub_7B4A50`, cited on `alloc_raw` above)
             * exactly like `FUN_0052F370`'s split documented above; this
             * emission does the rest inline: stores the bought node into the
             * owning container's head slot (`this+4`), flips `isNil@+0x11`
             * to 1, self-links `left=parent=right=self`, and zeroes the
             * owning container's `size` (`this+8`) -- the same
             * constructor-inlined `buy_head()`-plus-container-field pattern
             * already documented on `FUN_00684230` above. DB-integrity fix:
             * this token was marked `recovered` with `source_paths=null`
             * and a boilerplate "batch 0x007B**** pass" note that cited
             * nothing; a full `src/sdk` sweep found zero real citations
             * anywhere. Owning field not yet pinned to a specific class.)
             *
             * Address: 0x00556DE0 (FUN_00556DE0, sub_556DE0) -- the
             * category-lookup map's sentinel-head buy, `msvc8::map<
             * msvc8::string, moho::CategoryLookupValue>`,
             * `RRuleGameRulesImpl::mEntityCategoryLookup`'s
             * `EntityCategoryLookupTableRuntimeView::mCategoryMap`
             * (RRuleGameRules.h/.cpp). A third split shape, distinct from
             * both patterns above: this function allocates the raw node
             * (`alloc_raw()`) *and* sets `color=1(black)`/`isNil=0`, but
             * does NOT self-link `left`/`parent`/`right` -- its sole caller,
             * the map's constructor (`FUN_005551F0`,
             * `Moho::EntityCategorySet::EntityCategorySet`, cited on
             * `clear()` above), does the self-link and overwrites `isNil=1`
             * itself immediately after the call (confirmed against the raw
             * decompile: `v2 = sub_556DE0(); this->mMap._Myhead = v2;
             * v2->_Isnil = 1; ...->_Parent = ...->_Myhead; ...->_Left = ...;
             * ...->_Right = ...;`). This member fuses all three steps
             * (allocate, flag-init, self-link) into one call, matching every
             * other instantiation's citation convention in this file even
             * though the binary happens to split this one three ways rather
             * than two. Re-homed here from a hand-rolled
             * `AllocateCategoryLookupHeadNodeRuntime` free function in
             * RRuleGameRules.cpp that already fused the same three steps by
             * hand over a `CategoryLookupNodeRuntimeView*` reach-in instead
             * of calling this member -- that helper's own citation already
             * carried this exact evidence and disclosure; it is preserved
             * here verbatim now that the real container performs the fusion
             * instead.)
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
             * `sub_5816C0` -- the pair's implicit, compiler-generated copy
             * ctor: copies the 8-byte key, then `SBuildReserveInfo`'s own
             * implicit memberwise copy of `mUnit`/`mCom` (`WeakPtr<Unit>`/
             * `WeakPtr<CUnitCommand>`, `SBuildReserveInfo.h`), each relinked
             * into the new object's storage (`result+2`/`result+4`) rather
             * than left pointing at the source -- matching `WeakPtr<T>`'s
             * intrusive-list-node copy semantics. No explicit source line
             * produces this (neither type declares a copy ctor), per RULE
             * ONE -- then zeroes `color@+0x24`/`isNil@+0x25` -- matching
             * `buy_head`'s "38, rounded to 40" node-size note exactly. Reached
             * from FUN_00580720's `_Insert`, which is not yet recovered
             * source itself.)
             */
            /**
             * Address: 0x0077CD00 (FUN_0077CD00, inner bucket node allocate)
             * Address: 0x0077C690 (FUN_0077C690, its clone-from-source form)
             * Address: 0x0077CAE0 (FUN_0077CAE0, outer map value node; emitted again at
             * 0x0077DC40)
             * Address: 0x0077DC40 (FUN_0077DC40, sibling emission of FUN_0077CAE0 described above)
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
             * Four more siblings of the same `RRuleGameRulesBlueprintMap`
             * (`msvc8::map<msvc8::string, void*>`) node-buy family as
             * FUN_00535CA0 above -- one per registered blueprint type, each
             * byte-identical in shape (allocate one node via that type's own
             * `operator new(1)` wrapper, write left/parent/right from the
             * caller's where/head arguments, `msvc8::string::assign` the key
             * at node+0x0C, copy the source pair's `.second` (+0x1C) into
             * node+0x28, zero color/isNil at +0x2C/+0x2D). Each is reached
             * from its own `insert_at` bridge, cited in the `insert_unique`
             * catalog above (0x00534140/0x00534360/0x00534470/0x00534580):
             *   - Address: 0x005358E0 (FUN_005358E0) -- T=RProjectileBlueprint;
             *     reached from insert_at FUN_00534B90.
             *   - Address: 0x00535A60 (FUN_00535A60) -- T=RMeshBlueprint;
             *     reached from insert_at FUN_00534EF0.
             *   - Address: 0x00535B20 (FUN_00535B20) -- T=REmitterBlueprint's
             *     map (`GetOrCreateRegisteredEffectBlueprint`); reached from
             *     insert_at FUN_005350A0.
             *   - Address: 0x00535BE0 (FUN_00535BE0) -- T=RBeamBlueprint;
             *     reached from insert_at FUN_00535250.
             * Same RULE ONE reasoning as FUN_00535CA0: compiler/template
             * emission of `::new (...) value_type(args...)` with no
             * hand-written body of its own -- tracked `skip` in
             * `recovered_progress.json` for that reason.
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
            /**
             * Address: 0x0083C260 (FUN_0083C260, sub_83C260) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::buy_node` --
             * `gUiKeyRepeatMap` in `moho/ui/UiRuntimeTypes.cpp:1395`
             * (`Moho::CUIKeyHandler`'s per-key "repeat enabled" registry,
             * populated by `AddUiKeyMapEntries`/`FUN_00838FD0` when a Lua
             * key binding's `keyRepeat` flag is true). Allocates one node
             * via `sub_83C6E0(1)` (`alloc_raw`), writes `left`/`parent`/
             * `right` straight from its own arguments (the caller passes
             * `head_` for both `left` and `right` and the insertion-point
             * `where` node for `parent`, the same "compiler optimisation,
             * not a different operation" pattern the IdPool/CommandManager
             * instantiations above document), copies the 8-byte
             * `pair<const UiKeyMask, bool>` value from a `const
             * value_type*` argument (`*a1`/`a1[1]`) to `node+0x0C`/
             * `node+0x10`, then writes `color=0`(red)/`isNil=0` at
             * `node+0x14`/`node+0x15` -- the same `nil-0x15` shape already
             * used to identify this instantiation's rotation helpers
             * (`FUN_0083B4C0`/`FUN_0083B570`, both cited below). Reached
             * from `insert_at`'s emission (`FUN_0083BDE0`, cited below),
             * which calls this member internally rather than receiving an
             * already-built node -- the binary fuses `buy_node` +
             * `link_and_rebalance` into one function for this
             * instantiation, the same fusion `buy_head`'s `FUN_00556DE0`
             * citation above documents for a sibling map. DB-integrity fix:
             * this token was reverted from a false `recovered` status
             * citing `src/sdk/moho/misc/CrtRuntimeHelpers.cpp` (address not
             * present in that file, confirmed by a full-file grep); this
             * catalog is the real home.)
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
             * Address: 0x0077CF50 (FUN_0077CF50, sibling emission of the decal tree
             * node delete lane described above)
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
             * carried-over pointer). Owner now pinned down: this member's
             * two non-recursive callers, `sub_947290` (`clear()`, cited
             * above) and `sub_947C50` (`erase_range`, cited above), are both
             * recovered as `gpg::gal::StateCache<_D3DSAMPLERSTATETYPE,
             * unsigned int>::tree_`'s teardown -- `erase_range` reached from
             * that class's own `~StateCache`/non-deleting-destructor lane in
             * `StateCache.cpp` (real, confirmed callers), `clear()` from a
             * still-unidentified sibling member sharing this same node shape
             * (zero incoming references anywhere in the binary; see the
             * `clear()` citation above). The tree-algorithm shape, node
             * size, and the `StateCache<SamplerState>` half of the ownership
             * are now confirmed; only the `clear()` caller's owning class
             * remains open, matching the precedent set by the unidentified
             * 0x00A5xxxx-0x00A67xxx rotate instantiation cited under
             * `_Lrotate` below.)
             * Address: 0x00947160 (FUN_00947160, sub_947160) -- the sibling
             * emission for `gpg::gal::StateCache<_D3DTEXTURESTAGESTATETYPE,
             * unsigned int>::tree_`, same isNil@+0x15, 8-byte-value shape.
             * Three real callers (callgraph index + exhaustive PE byte-scan):
             * itself (recursive, on the right child), `sub_9472C0`
             * (`clear()`, cited above, unidentified sibling owner) and
             * `sub_947D10` (`erase_range`, cited above, the confirmed
             * `StateCache<TextureStageState>` destructor path).)
             * Address: 0x009470E0 (FUN_009470E0, sub_9470E0) -- the fourth
             * sibling in this address range: `gpg::gal::StateCache<
             * d3d9::RenderState, unsigned int>::tree_`'s `destroy_subtree`.
             * Same isNil@+0x15, 8-byte-value recurse-right/iterate-left/
             * `operator delete` shape. Two real callers: itself (recursive)
             * and `sub_947260` (an unidentified `clear()`-shaped sibling,
             * mirroring `sub_947290`/`sub_9472C0` above but not itself
             * re-verified in this pass) at 0x00947260, plus `sub_947B90`
             * (`erase_range`, the confirmed `StateCache<RenderState>`
             * destructor path -- see that citation above, which already
             * documents this exact call). Corrects a stale DB-integrity
             * revert that had flipped this token to `blocked` citing a
             * `CrtRuntimeHelpers.cpp` source path the address never
             * appeared in; the real source is this member, exactly as the
             * existing 0x00947B90 citation already described before this
             * pass gave the token its own address line.)
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
             * Address: 0x007B4AA0 (FUN_007B4AA0, sub_7B4AA0) -- the outer
             * per-parent-bone dedup map's own `destroy_subtree`
             * (`CON_ANI_DumpSkeleton` cluster, isNil@+0x1D, same
             * instantiation as `erase_node`/`FUN_007B4040` and
             * `erase_range`/`FUN_007B3820` above), reached from
             * `FUN_007B3820`'s whole-tree fast path. Per node: recurses
             * right, iterates left, tears down the embedded per-parent
             * `msvc8::set<uint32_t>` child-set value via `sub_7B3E00`
             * (already-cited `erase_range` for that nested instantiation)
             * before freeing the node -- correcting a prior mis-
             * classification as `external_dependency` (this is genuine
             * engine-instantiated tree teardown, not CRT/imported code).
             * `Moho::CON_ANI_DumpSkeleton` itself (CAniSkel.cpp) remains
             * unrecovered.)
             *
             * Address: 0x008D6B70 (FUN_008D6B70, sub_8D6B70) -- the local
             * `msvc8::rb_tree<moho::Resolution>` dedup tree's own
             * `destroy_subtree` (isNil@+29). Per node: recurses right
             * (`sub_8D6B70(i[2])`), iterates left, writes
             * `Resolution::\`vftable'` into the node's vtable slot before
             * `operator delete` -- matching this member's shape exactly and
             * confirming genuine engine-instantiated teardown (a direct
             * `Resolution::\`vftable'` reference cannot be CRT code).
             * Reached from this instantiation's `erase_range`
             * (`FUN_008D6080`, cited above) whole-range fast path.
             *
             * Address: 0x00712090 (FUN_00712090, sub_712090) -- the local
             * `blueprintKeys` variable's `destroy_subtree` in `Moho::
             * CArmyStats::ArmyXmlStatsNode` (`msvc8::set<const
             * ArmyBlueprintNameView*>`, isNil@+0x11 -- the same
             * instantiation cited on `erase_range` above as
             * `FUN_00711350`). Plain `operator delete` per node, no
             * vtable write (the pointer value_type needs none). Reached
             * from that `erase_range`'s whole-range fast path.
             *
             * Address: 0x0077CFE0 (FUN_0077CFE0, sub_77CFE0) -- CDecalBuffer's
             * start-tick outer table's `destroy_subtree` (`std::map<
             * unsigned, std::set<CDecalHandle*>>`, isNil@+29, the same
             * instantiation cited on `erase_range` above as
             * `FUN_0077BD90`). Per node: recurses right, iterates left,
             * tears down the nested `std::set<CDecalHandle*>` value via
             * `sub_77B4F0` before freeing the node. Reached from that
             * `erase_range`'s whole-range fast path.
             *
             * Address: 0x009470E0 (FUN_009470E0, sub_9470E0) --
             * `gpg::gal::StateCache<_D3DRENDERSTATETYPE, unsigned int>::
             * tree_`'s `destroy_subtree`, isNil@+0x15 -- plain
             * `operator delete` per node (pointer-free value_type, no
             * vtable/nested-container teardown needed), matching the shape
             * `erase_range`'s citation above (`FUN_00947B90`) already
             * described in prose as "recursive delete-all with no
             * rebalancing" without its own Address block. Reached from
             * that same `erase_range`'s whole-tree fast path.
             *
             * Address: 0x005369D0 (FUN_005369D0, sub_5369D0) -- the
             * category-lookup map's `destroy_subtree`, `msvc8::map<
             * msvc8::string, moho::CategoryLookupValue>`,
             * `RRuleGameRulesImpl::mEntityCategoryLookup`'s
             * `EntityCategoryLookupTableRuntimeView::mCategoryMap`
             * (RRuleGameRules.h/.cpp). Recurse-right-then-iterate-left shape
             * matching this member exactly; per node, tears down the value's
             * inline-SBO bit-vector (`_Myval.helper.second.mSet.mUsed`,
             * `CategoryWordRangeView`'s own heap-release when it grew past
             * the SBO) and the key's capacity (`_Myval.helper.first`,
             * `msvc8::string`'s own release) before `operator delete`ing the
             * node -- both inlined directly by the compiler rather than
             * calling separate `~CategoryWordRangeView`/`~string` symbols,
             * confirmed against the raw decompile (IDA's own `helper`
             * struct naming is this instantiation's `pair<const
             * msvc8::string, CategoryWordRangeView>` value_type, `.first`
             * the key / `.second` the value). This member's generic
             * `n->value.~value_type()` in `free_node` (called by
             * `erase_node` above, not by this member directly -- see that
             * member's own body) reproduces the identical net effect through
             * the type system rather than by hand. Called with a sentinel
             * (`isNil` head) node this is a no-op, which is what this
             * instantiation's default-constructed `mCategoryMap` (and this
             * type's constructor, which calls `clear()` on the
             * freshly-built empty tree -- cited on `clear()` below) relies
             * on. Reached from this instantiation's `erase_range`
             * (`FUN_00535750`, cited below) whole-tree fast path. Re-homed
             * here from a hand-rolled `DestroyCategoryLookupSubtree` free
             * function in RRuleGameRules.cpp that recursed over a
             * `CategoryLookupNodeRuntimeView*` reach-in instead of calling
             * it.)
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
            /**
             * Address: 0x00530EE0 (FUN_00530EE0, `copy_from`'s emission for
             * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` --
             * `msvc8::set<uint32_t>`, the same instantiation already pinned
             * by `buy_head`/`erase_range`/`erase_node`/`destroy_subtree`/
             * `~rb_tree`/the copy constructor above. Unlike this template's
             * own `copy_from` (walk `other` ascending, `insert_unique` each
             * value -- see the `msvc8::set<msvc8::string>` note above),
             * this emission is the real MSVC8 `_Tree::_Copy` mechanism:
             * reads `other`'s head pointer (`other_tree+4`), then that
             * head's `_Parent` field -- i.e. `other.root()` -- and calls
             * `sub_531B30` (cited immediately below) to recursively clone
             * the whole subtree node-for-node, preserving `other`'s exact
             * tree shape rather than rebuilding it through repeated
             * inserts. Stores the cloned root at `this->head_->parent`,
             * copies `_Mysize` across verbatim from `other`, then walks
             * from the freshly-cloned root down its left-spine to find
             * `leftmost()` and, separately, down its right-spine to find
             * `rightmost()`, re-seating `header()->left`/`header()->right`
             * (self-referential to `header()` in the empty-tree case).
             * `this` arrives in `eax`; the source tree arrives in `ebx`,
             * inherited un-set from the caller's own live register rather
             * than passed as a normal argument -- both `FUN_0052F020`'s
             * copy-constructor body and `FUN_00537420`'s inlined
             * `operator=` set up `ebx` before falling into this call (the
             * same register-heavy internal convention used elsewhere in
             * this file). Called from `FUN_0052F020` (the copy
             * constructor, cited above) and from `FUN_00537420`
             * (`legacy/containers/Vector.h`'s `insert(pos,count,value)`
             * in-place tail-shift loop, cited there) immediately after
             * that caller's inlined `erase_range` (`sub_52D9C0`) empties
             * the destination slot. Was previously mis-marked
             * `external_dependency` citing a generic "RB-tree-shaped
             * pointer-chasing helper" description and an (also wrong)
             * `FUN_0052F020` external classification as justification;
             * corrected here -- this is genuine, in-binary engine code
             * with two independently-verified real callers, no
             * `__imp_*`/CRT symbol anywhere in its body.)
             * Address: 0x00531B30 (FUN_00531B30, the recursive per-node
             * subtree clone underneath `FUN_00530EE0` -- MSVC8
             * `_Tree::_Copy(_Nodeptr _Rootnode, _Nodeptr _Wherenode)`,
             * `this` in `ecx`. Tests `_Rootnode->_Isnil` (`+0x11`); if nil,
             * returns `_Wherenode` unchanged. Otherwise calls `sub_52DB50`
             * (`buy_node`-with-value, already recovered/cited above) to
             * allocate and copy-construct one new node carrying
             * `_Rootnode`'s value and color, then recurses on
             * `_Rootnode->_Left` and `_Rootnode->_Right` in turn (passing
             * the new node as `_Wherenode`/parent for each), wiring the
             * results into the new node's `_Left`/`_Right`. On exception
             * it calls `sub_52CCF0` (`destroy_subtree`, already recovered/
             * cited above) on the partially-built clone and rethrows --
             * exactly this file's `destroy_subtree` used as the cleanup
             * primitive it already is elsewhere. Sole caller is
             * `FUN_00530EE0` above.)
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
             *
             * Address: 0x00946D20 (FUN_00946D20, sub_946D20) -- `gpg::gal::
             * StateCache<_D3DSAMPLERSTATETYPE, unsigned int>::tree_`'s left
             * rotate, isNil@+0x15. This is the `sub_946D20` this
             * instantiation's `erase_node` citation (`FUN_00947630` above)
             * already names as one of its "own" rebalance helpers. Reached
             * from `insert_at`'s fixup loop for this instantiation.
             * Address: 0x00946D70 (FUN_00946D70, sub_946D70) -- `gpg::gal::
             * StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::tree_`'s
             * left rotate, isNil@+0x15, byte-identical shape to
             * `FUN_00946D20` immediately above -- a sibling `StateCache`
             * specialisation with its own distinct rotate helper address.
             * Reached from `insert_at`'s fixup loop for this instantiation
             * (`FUN_009478E0`'s `erase_node` citation above).
             *
             * Address: 0x008D61D0 (FUN_008D61D0, sub_8D61D0) -- the local
             * `msvc8::rb_tree<moho::Resolution>` dedup tree's left rotate
             * (isNil@+29). Reached from both `insert_at`'s fixup loop and
             * `erase_node`'s fixup loop (`FUN_008D6650`, cited above) for
             * this same instantiation.
             *
             * Address: 0x0094FA60 (FUN_0094FA60, sub_94FA60) -- left rotate
             * for the same "unidentified `msvc8::map<K,V>`/`msvc8::set<T>`
             * instantiation with a 24-byte value_type" the `buy_node`
             * catalog above documents at 0x00950430 -- standard
             * `result=n->right; n->right=result->left; ...` shape, isNil
             * check at `+37`(0x25). Reached from `insert_at`'s fixup loop
             * (`FUN_009512B0`, cited on `buy_node` above) via a direct
             * `call`. Previously reverted to `blocked` in a DB-integrity
             * sweep after a batch worker mis-cited it against
             * `CrtRuntimeHelpers.cpp` with a fabricated note; the real,
             * correct home is this catalog.
             *
             * Three left rotates for the `RRuleGameRulesBlueprintMap`
             * (`msvc8::map<msvc8::string, void*>`) family already
             * documented on `buy_node` above (FUN_005358E0 and siblings) --
             * isNil check at `+45`(0x2D), matching that family's node size:
             *   - Address: 0x00531000 (FUN_00531000) -- reached from the
             *     base blueprint-map `insert_at` bridge FUN_005349E0 (the
             *     `map.insert(RRuleGameRulesBlueprintMap::value_type(...))`
             *     call site in Sim.cpp, cited on `insert_unique` above).
             *   - Address: 0x00531190 (FUN_00531190) -- T=RProjectileBlueprint;
             *     reached from insert_at FUN_00534B90 (paired with the right
             *     rotate FUN_00531220 on `rotate_right` below).
             *   - Address: 0x005316A0 (FUN_005316A0) -- T=REmitterBlueprint's
             *     map; reached from insert_at FUN_005350A0 (paired with the
             *     right rotate FUN_00531710 on `rotate_right` below).
             *
             * Address: 0x00536A50 (FUN_00536A50, the category-lookup map's
             * left rotate -- `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
             * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
             * mCategoryMap` (RRuleGameRules.h/.cpp). Matches this member
             * exactly: `pivot=n->right; n->right=pivot->left; ...;
             * pivot->left=n; n->parent=pivot;`, IDA's own naming tags it
             * `_Tree::_Lrotate`. Reached from two independent fixup loops for
             * this same instantiation -- `insert_at`'s emission (FUN_005565D0,
             * cited above on that member) on the uncle-red rebalance path,
             * and `erase_node`'s emission (FUN_00536010, cited below) on its
             * post-erase black-height repair -- confirming this instantiation
             * exercises both the insert-side and erase-side rebalance
             * machinery at runtime, not just the compiled-but-dead erase
             * path. Re-homed here from a hand-rolled
             * `RotateCategoryLookupNodeLeft` free function in
             * RRuleGameRules.cpp that rotated over a
             * `CategoryLookupNodeRuntimeView*`/`EntityCategoryLookupTableRuntimeView&`
             * reach-in instead of calling it.)
             */
            /**
             * Address: 0x0083B4C0 (FUN_0083B4C0, sub_83B4C0) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s left rotate
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`),
             * isNil@+0x15. Matches this member exactly: `pivot=n->right;
             * n->right=pivot->left; ...; pivot->left=n; n->parent=pivot;`.
             * Reached from `insert_at`'s emission (`FUN_0083BDE0`, cited
             * below) and `erase_node`'s emission (`FUN_0083AA70`, cited
             * below), the same insert-side/erase-side dual-caller shape
             * `rotate_left`'s other instantiations show throughout this
             * file. Currently duplicated as a free-function template
             * instantiation (`RotateOffset15TreeLeftViaSecondaryGlobalHead`)
             * in `moho/containers/LegacyContainerRuntime.cpp` with zero
             * callers anywhere in `src/sdk`; not consolidated in this pass
             * (see the `header()` note above for why).)
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
             *
             * Address: 0x00946590 (FUN_00946590, sub_946590) -- `gpg::gal::
             * StateCache<d3d9::RenderState, unsigned int>::tree_`'s right
             * rotate, isNil@+0x15. One of the "own distinct rotate/min/max
             * helper addresses" this instantiation's `erase_node` citation
             * (`FUN_00947380` above) already names. Reached from `insert_at`'s
             * fixup loop for this same instantiation.
             * Address: 0x009466B0 (FUN_009466B0, sub_9466B0) -- `gpg::gal::
             * StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int>::tree_`'s
             * right rotate, isNil@+0x15, byte-identical shape to
             * `FUN_00946590` immediately above -- a sibling `StateCache`
             * specialisation with its own distinct rotate helper address.
             * Reached from `insert_at`'s fixup loop for this instantiation
             * (`FUN_009478E0`'s `erase_node` citation above).
             *
             * Address: 0x008D6230 (FUN_008D6230, sub_8D6230) -- the local
             * `msvc8::rb_tree<moho::Resolution>` dedup tree's right rotate
             * (isNil@+29). Reached from both `insert_at`'s fixup loop and
             * `erase_node`'s fixup loop (`FUN_008D6650`, cited above) for
             * this same instantiation.
             *
             * Address: 0x0094FAB0 (FUN_0094FAB0, sub_94FAB0) -- right
             * rotate, mirror of `rotate_left`'s FUN_0094FA60 above, same
             * "unidentified 24-byte value_type" instantiation
             * (`result=n->left; n->left=result->right; ...`), isNil check
             * at `+37`. Reached from the same `insert_at` fixup loop
             * (`FUN_009512B0`). A prior pass marked this `skip` reasoning
             * that `FUN_009512B0` "does not actually appear anywhere in
             * src/sdk" -- stale: `FUN_009512B0` is cited on the `buy_node`
             * catalog above (added later in the same session). Corrected
             * to `recovered` here.
             *
             * Four right rotates, same `RRuleGameRulesBlueprintMap` family
             * as the three left rotates cited on `rotate_left` above,
             * isNil@+45:
             *   - Address: 0x00531220 (FUN_00531220) -- T=RProjectileBlueprint;
             *     reached from insert_at FUN_00534B90 (paired with left
             *     rotate FUN_00531190 above).
             *   - Address: 0x005313D0 (FUN_005313D0) -- T=RPropBlueprint;
             *     reached from insert_at FUN_00534D40.
             *   - Address: 0x00531580 (FUN_00531580) -- T=RMeshBlueprint;
             *     reached from insert_at FUN_00534EF0.
             *   - Address: 0x00531710 (FUN_00531710) -- T=REmitterBlueprint's
             *     map; reached from insert_at FUN_005350A0 (paired with left
             *     rotate FUN_005316A0 above).
             *
             * Address: 0x00536AE0 (FUN_00536AE0, the category-lookup map's
             * right rotate -- `msvc8::map<msvc8::string,
             * moho::CategoryLookupValue>`, `RRuleGameRulesImpl::
             * mEntityCategoryLookup`'s `EntityCategoryLookupTableRuntimeView::
             * mCategoryMap` (RRuleGameRules.h/.cpp). Mirror of `rotate_left`'s
             * 0x00536A50 above, same instantiation -- reached from the same
             * two fixup loops (`insert_at`'s FUN_005565D0 and `erase_node`'s
             * FUN_00536010, both cited above/below). Re-homed here from a
             * hand-rolled `RotateCategoryLookupNodeRight` free function in
             * RRuleGameRules.cpp that rotated over a
             * `CategoryLookupNodeRuntimeView*`/`EntityCategoryLookupTableRuntimeView&`
             * reach-in instead of calling it.)
             */
            /**
             * Address: 0x0083B570 (FUN_0083B570, sub_83B570) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>`'s right rotate
             * -- `gUiKeyRepeatMap` (`moho/ui/UiRuntimeTypes.cpp:1395`),
             * isNil@+0x15. Mirror of `rotate_left`'s `FUN_0083B4C0` above,
             * same instantiation: `pivot=n->left; n->left=pivot->right;
             * ...; pivot->right=n; n->parent=pivot;`. Reached from the same
             * two fixup loops as `FUN_0083B4C0` -- `insert_at`'s emission
             * (`FUN_0083BDE0`, cited below) and `erase_node`'s emission
             * (`FUN_0083AA70`, cited below). Currently duplicated as a
             * free-function template instantiation
             * (`RotateOffset15TreeRightViaSecondaryGlobalHead`) in
             * `moho/containers/LegacyContainerRuntime.cpp` with zero
             * callers anywhere in `src/sdk`; not consolidated in this pass
             * (see the `header()` note above for why).)
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
             * Address: 0x0077A3C0 (FUN_0077A3C0, the outer map's `erase_node` --
             * CORRECTED: previously mis-labeled "insert with rebalance" here;
             * this token's own decompile is unmistakably `erase_node`: throws
             * `std::out_of_range("invalid map/set<T> iterator")` on a nil
             * target (the `_SECURE_SCL` checked-iterator guard documented
             * throughout this file, not `_Xlen`), captures the successor via
             * `sub_77CE50` (`rb_increment`), CLRS transplant-then-fixup, and
             * rebalances through the rotates at 0x0077B0B0/0x0077B160 --
             * cited on `erase_node`'s canonical member below, not `insert_at`.
             * Reached from this table's `erase_range` (`FUN_0077BD90`, cited
             * on that member) walk path.)
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
            /**
             * Address: 0x008D5720 (FUN_008D5720, sub_8D5720) -- local
             * `msvc8::rb_tree<moho::Resolution>`'s `insert_at` (dedup tree
             * for `SetupPrimaryAdapterSettings`/`SetupSecondaryAdapterSettings`'s
             * display-mode enumeration, `StartupHelpers.cpp:6841`/`6891`,
             * `color@+0x1C`/`isNil@+0x1D` -- see the corrected `buy_head`
             * citation above, `FUN_008D6940`). `_Mysize >= 0xFFFFFFE`
             * overflow guard (`0xFFFFFFFF/16 - 1`, matching `Resolution`'s
             * `sizeof==0x10`), buys the node WITH its value through
             * `sub_8D6280` (writes `Resolution::vftable` + width/height/fps
             * at node offsets +12/+16/+20/+24, color=0/isNil=0 for a fresh
             * data node -- corrects a prior `external_dependency`
             * mis-classification of `sub_8D6280`; it directly references
             * the engine `Resolution::vftable`, not third-party runtime),
             * links under the caller's `where`/`addLeft`, repairs red-red
             * violations via `sub_8D61D0`/`sub_8D6230`
             * (`rotate_left`/`rotate_right`-shaped, not yet independently
             * cited). Reached from `insert_unique`'s emission
             * (`FUN_008D4F10`, cited below).
             *
             * NOT YET WIRED to a source-level caller: the RAW binary's
             * `SetupPrimaryAdapterSettings` (`FUN_008D21E0`) builds and
             * queries this tree directly to dedup adapter modes in SORTED
             * `(width,height,fps)` order, but the CURRENTLY RECOVERED
             * `StartupHelpers.cpp` body (`CollectAdapterModes`/`HasMode`)
             * dedups via an O(n) linear scan instead, preserving driver-
             * enumeration order rather than producing the binary's sorted
             * order -- same resulting SET of unique modes, different
             * observable ORDER in the startup options UI. An orphaned,
             * already-evidenced `*RuntimeView` reimplementation of this
             * same tree already exists (`AdapterModeSortTreeRuntimeView`
             * family, `StartupHelpers.cpp:~1234-1330`, several
             * `[[maybe_unused]]`) -- per RULE ONE this should be migrated
             * to a real `T=Resolution` instantiation of this template
             * rather than extended; not done in this pass. `sub_8D69D0`
             * (`rb_decrement`, cited below) and `sub_8D5020` (lower_bound,
             * currently cited on the orphaned `ResolveAdapterModeSortInsertionAnchor`)
             * complete this instantiation's primitive set.
             */
            /**
             * Address: 0x0083BDE0 (FUN_0083BDE0, sub_83BDE0) --
             * `UiKeyRepeatMap`/`msvc8::map<UiKeyMask, bool>::insert_at` --
             * `gUiKeyRepeatMap` in `moho/ui/UiRuntimeTypes.cpp:1395`. The
             * `(unsigned)dword_10C3750 >= 0x1FFFFFFE` guard is this
             * member's `max_size() - 1u <= size_` for the 8-byte
             * `pair<const UiKeyMask, bool>` value_type (`0xFFFFFFFF/8 - 1
             * == 0x1FFFFFFE`, the same constant already confirmed for the
             * 8-byte CmdId maps above -- independent confirmation that
             * `bool` is padded to a full 4-byte slot in this pair), throwing
             * `std::length_error("map/set<T> too long")` (built via
             * `std::logic_error::logic_error` then vftable-patched to
             * `std::length_error`, the standard shape documented throughout
             * this file). Buys the node through `sub_83C260` (`buy_node`,
             * cited above), links it under the caller's `where`/`addLeft`
             * in the same `where==head_` / `addLeft` / general three-case
             * shape as `link_and_rebalance` above, then repairs the
             * red-red violation calling `sub_83B4C0`/`sub_83B570`
             * (`rotate_left`/`rotate_right`, both cited below) on the
             * uncle-red/uncle-black branches. Reached from `insert_hint`'s
             * emission (`FUN_0083B320`, cited above) on every accepted
             * branch -- itself reached from `operator[]`'s emission
             * (`FUN_0083A9D0`, cited in `Map.h`) passing its own
             * `lower_bound` result as the hint, confirmed via
             * `AddUiKeyMapEntries`'s `gUiKeyRepeatMap[keyMask] = true`
             * (`UiRuntimeTypes.cpp:1442`). Was `recovered` with no citation,
             * report, or note of any kind prior to this pass -- neither
             * proven false nor verifiable; this catalog entry is the first
             * real evidence trail for it.)
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
