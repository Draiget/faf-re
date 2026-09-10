#pragma once

/**
 * MSVC8-era `std::sort` (Dinkumware introsort), recovered from the Forged
 * Alliance binary.
 *
 * This is not a convenience wrapper over the modern `std::sort`. The 2007
 * implementation has an observable shape the modern one does not: it switches
 * to insertion sort below 32 elements, bounds recursion with an "ideal" budget
 * that decays by 3/4 per level, and falls back to heapsort when that budget
 * runs out. Two sequences that compare equal can therefore come out in a
 * different order than `std::sort` would produce, and the engine's AI build
 * placement iterates the sorted result, so the ordering is load-bearing.
 *
 * Recovered from the `SDepositCandidate` instantiation, where MSVC8 inlined the
 * comparator into every emission:
 *
 *   0x00594890  _Sort               introsort driver
 *   0x005955C0  _Unguarded_partition median-of-3 partition, returns the fat pivot
 *   0x005958C0  _Insertion_sort     small-range fallback
 *   0x00595C40  _Sort_heap          heap drain
 *   0x00595DF0  _Adjust_heap        sift-down
 *
 * The driver's recursion picks the smaller partition to recurse into and loops
 * on the larger, which is what keeps stack depth logarithmic.
 *
 * A third instantiation, `gpg::RField` (20 bytes, `{const char* mName; ...}`,
 * sorted by `mName` via `strcmp`), is what `gpg::RType::Finish()` (Reflection.cpp)
 * uses to index reflected fields, and is the one that actually exercises the
 * `_Median` ninther upgrade the `SBuildTemplateInfo` instantiation's own citation
 * already flagged but this file didn't yet model (see `select_ninther` below):
 *
 *   0x008DD790  _Sort               introsort driver
 *   0x008DAA00  _Unguarded_partition
 *   0x008DA410  _Median              ninther dispatcher (plain `_Med3` <= 41
 *                                    elements, else samples 9 points)
 *   0x008D9EE0  _Med3                median-of-3
 *   0x008D9E20  iter_swap            element swap, 20-byte stride
 *   0x008DB430  _Insertion_sort      small-range fallback
 *   0x008DB2A0  make_heap / 0x008DAF60 _Adjust_heap (sift-down half)
 *   0x008DBF60  sort_heap  / 0x008DB080 _Adjust_heap (settle-upward half)
 */

#include <cstddef>
#include <iterator>
#include <utility>

namespace msvc8
{
    namespace detail
    {
        /** Below this many elements the sort switches to insertion sort. */
        inline constexpr std::ptrdiff_t kInsertionSortMax = 32;

        /**
         * Above this element count (checked against `(last - 1) - first`,
         * i.e. at most 41 elements takes the plain-median3 path), `_Median`
         * upgrades from a single `median3` call to the 9-point "ninther"
         * sampled by `select_ninther` below. Threshold confirmed from
         * `FUN_008DA410`'s `(a3 - a1) / 20 <= 40` guard (`gpg::RField`,
         * 20-byte stride, `a3` passed in already as `last - 1`).
         */
        inline constexpr std::ptrdiff_t kNintherCountLimit = 40;

        /**
         * Address: 0x0089C070 (FUN_0089C070, the swap for
         * `Moho::SBuildTemplateInfo` -- 0x2C bytes of
         * `{Wm3::Vector3f mPos; int mBuildOrder; msvc8::string mBlueprintId;}`.
         * The 0x2C stack temp it opens with is the `T temp = lhs` below; the
         * blueprint-id lane moves through `std::string::assign(str, 0, -1)`
         * three times, once per leg of the three-way exchange.)
         */
        /**
         * Address: 0x008D9E20 (FUN_008D9E20, the swap for `gpg::RField` --
         * 20 bytes, `{const char* mName; RType* mType; int mOffset; int v4;
         * const char* mDesc;}`. Straight-line 5-dword three-way exchange
         * (`temp=lhs; lhs=rhs; rhs=temp` on the raw dword lanes), matching
         * this member exactly for a trivially-copyable element -- no
         * per-field ctor/dtor calls, just raw dword moves. Reached from
         * `_Med3`'s (`FUN_008D9EE0`, cited below) three `iter_swap` calls
         * and from `_Unguarded_partition`'s (`FUN_008DAA00`, cited below)
         * own partition-scan swaps. The real instantiation root is
         * `gpg::RType::Finish()`'s `std::sort(first, last, comp)` over
         * `fields_` (Reflection.cpp, `Address: 0x008DF4A0`). Previously
         * modeled here as a bespoke `SwapFiveDwordLanes` free function in
         * `LegacyContainerFillLanes.cpp` -- a RULE ONE violation once the
         * real `_Sort<RField*>` instantiation chain was identified via
         * `_callgraph_index.sqlite`; removed from there in favor of this
         * citation.)
         */
        /**
         * Address: 0x00575210 (FUN_00575210 -- `iter_swap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp): `T temp = lhs; lhs = rhs; rhs = temp` through the element copy constructor (0x0056CB60) and `operator=` (0x00573340).)
         */
        template <class T>
        void iter_swap_value(T& lhs, T& rhs)
        {
            T temp = lhs;
            lhs = rhs;
            rhs = temp;
        }

        /**
         * Address: 0x00A73B30 (FUN_00A73B30, `_Insertion_sort` for an 8-byte
         * `{float x, y;}` pair -- reached from `_Sort`'s (`FUN_00A740D0`,
         * cited on `sort_impl` below) small-range fallback, `<= 32` elements)
         * Address: 0x00A73BD0 (FUN_00A73BD0, the `double` (8-byte scalar)
         * instantiation, reached from `_Sort`'s (`FUN_00A741A0`, cited below)
         * small-range fallback)
         */
        /**
         * Address: 0x00A72D40 (FUN_00A72D40, `make_heap` for the float-pair
         * instantiation, reached from `_Sort`'s (`FUN_00A740D0`) ideal-budget-
         * exhausted heapsort fallback)
         * Address: 0x00A72E20 (FUN_00A72E20, the `double` instantiation's
         * `make_heap`, reached from `_Sort`'s (`FUN_00A741A0`) same fallback)
         */
        /**
         * Address: 0x00A73E20 (FUN_00A73E20, `sort_heap` for the float-pair
         * instantiation, called right after `make_heap` (`FUN_00A72D40`) in
         * `_Sort`'s (`FUN_00A740D0`) heapsort fallback)
         * Address: 0x00A73E70 (FUN_00A73E70, the `double` instantiation's
         * `sort_heap`, called after `FUN_00A72E20` in `_Sort`'s
         * (`FUN_00A741A0`) same fallback)
         */

        /**
         * Address: 0x00595AC0 (the `_Med3` lane called first from
         *          `_Unguarded_partition`)
         *
         * Orders `*a`, `*b`, `*c` so the median ends up in `*b`.
         */
        /**
         * Address: 0x0089BD10 (FUN_0089BD10, the median pick for the
         * `SBuildTemplateInfo` sort -- opens `cmp eax, 28h`, VC8's
         * `40 < _Count` test that selects the median-of-nine ninther over a
         * plain median-of-three, then drives the swap at 0x0089C070 up to
         * fifteen times. Compares `[node+0x0C]` signed, which is
         * `mBuildOrder`.)
         */
        /**
         * Address: 0x008D9EE0 (FUN_008D9EE0, `_Med3` for the `gpg::RField`
         * sort -- `strcmp(*a2,*a1)`/`strcmp(*a3,*a2)`/`strcmp(*a2,*a1)`
         * against the three `mName` pointers, matching this member exactly
         * (compares `*a`/`*b`/`*c` pairwise, swapping through `iter_swap`
         * at 0x008D9E20 -- cited above -- to land the median in `*b`).
         * Reached with `count <= 41` directly from `_Median`'s (`FUN_008DA410`,
         * cited on `select_ninther` below) simple path, and always as the
         * final "median of the three medians" step of the ninther itself.
         * Previously mis-tagged `external_dependency` ("all-external-callees
         * thunk... no engine references") -- `strcmp` is CRT, but the
         * three-way compare-and-swap control flow orchestrating it is this
         * project's own `_Med3` emission, reached from `gpg::RType::
         * Finish()`'s `std::sort` (Reflection.cpp) -- not third-party
         * runtime. DB-integrity fix, corrected to skip/cited-here.)
         */
        /**
         * Address: 0x005751C0 (FUN_005751C0 -- `_Med3` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp).)
         * Address: 0x0054FC70 (FUN_0054FC70 -- `_Med3` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         */
        template <class T, class Compare>
        void median3(T* const a, T* const b, T* const c, Compare comp)
        {
            if (comp(*b, *a)) {
                iter_swap_value(*a, *b);
            }
            if (comp(*c, *b)) {
                iter_swap_value(*b, *c);
                if (comp(*b, *a)) {
                    iter_swap_value(*a, *b);
                }
            }
        }

        /**
         * Address: 0x008DA410 (FUN_008DA410, `_Median` for the `gpg::RField`
         * sort -- VC8's ninther dispatcher: `<= 41` elements (`(a3-a1)/20 <=
         * 40` against `a3 = last - 1`) falls straight through to a single
         * `median3(first, middle, last - 1, comp)`; above that it samples
         * three medians-of-three spaced `count/8` elements apart from the
         * start, middle, and end of the range, then takes the median of
         * those three medians as the final pivot estimate. Hand-verified
         * against the decompile: `v4 = (count - 1 + 1) / 8`, `_Med3` calls
         * over `[first, first+v4, first+2v4]`, `[middle-v4, middle,
         * middle+v4]`, and `[last-1-2v4, last-1-v4, last-1]`, then a final
         * `_Med3` over the three results, writing the overall median into
         * `*middle`. Reached from `_Unguarded_partition`'s (`FUN_008DAA00`,
         * cited below) pivot-selection step. The `SBuildTemplateInfo`
         * instantiation's own `_Median` (`FUN_0089BD10`, cited above on
         * `median3`) exercises this exact ninther branch too (its citation
         * already named the `40 < _Count` guard) but this template's
         * `unguarded_partition` never modeled the upgrade until this pass --
         * fixed here so every instantiation gets it, per RULE ONE. Was
         * mis-tagged `external_dependency` for the same reason `FUN_008D9EE0`
         * was; corrected.)
         */
        /**
         * Address: 0x00574830 (FUN_00574830 -- `_Median` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp): `count <= 40` falls through to `_Med3`, else the ninther.)
         * Address: 0x0054F8A0 (FUN_0054F8A0 -- `_Median` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         */
        template <class T, class Compare>
        /**
         * Address: 0x0092E050 (FUN_0092E050 -- `_Median` -- median-of-three under 40 elements, the ninther sample ordering above it -- for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092E6E0; formerly `OrderU16PivotSamples` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071F870 (FUN_0071F870 -- `_Median` -- median-of-three under 40 elements, the ninther sample ordering above it -- for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x0071EFA0; formerly `SelectPivotSamplesForFloat4Sort` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         */
        void select_ninther(T* const first, T* const middle, T* const last, Compare comp)
        {
            const std::ptrdiff_t step = (last - first) / 8;
            T* const lastIncl = last - 1;
            T* const nearStart = first + step;
            T* const nearEnd = lastIncl - step;

            median3(first, nearStart, first + 2 * step, comp);
            median3(middle - step, middle, middle + step, comp);
            median3(lastIncl - 2 * step, nearEnd, lastIncl, comp);
            median3(nearStart, middle, nearEnd, comp);
        }

        /**
         * VC8's `_Rotate` for random-access iterators, the body behind
         * `std::rotate`: the gcd-cycle ("juggling") rotation that moves each
         * element once through a chain of `count / gcd(count, shift)`
         * subcycles. `insertion_sort` below is its only caller in this
         * binary, which is why every instantiation sits next to an
         * `_Insertion_sort` emission.
         */
        /**
         * Address: 0x00575690 (FUN_00575690 -- `_Rotate` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp).)
         * Address: 0x005754F0 (FUN_005754F0 -- register bridge into the `_Rotate` at 0x00575690; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x005502C0 (FUN_005502C0 -- `_Rotate` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         * Address: 0x0054FEB0 (FUN_0054FEB0 -- register bridge into the `_Rotate` at 0x005502C0; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         */
        template <class T>
        void rotate_cycles(T* const first, T* const middle, T* const last)
        {
            const std::ptrdiff_t shift = middle - first;
            std::ptrdiff_t count = last - first;
            for (std::ptrdiff_t factor = shift; factor != 0;) {
                // gcd of the shift and the length is the subcycle count.
                const std::ptrdiff_t next = count % factor;
                count = factor;
                factor = next;
            }
            if (count < last - first) {
                for (; 0 < count; --count) {
                    // Rotate one subcycle, starting at `first + count`.
                    T* const hole = first + count;
                    T* next = hole;
                    T value = *hole;
                    T* next1 = (next + shift == last) ? first : next + shift;
                    while (next1 != hole) {
                        *next = *next1;
                        next = next1;
                        next1 = (shift < last - next1) ? next1 + shift : first + (shift - (last - next1));
                    }
                    *next = value;
                }
            }
        }

        /**
         * `std::rotate(first, middle, last)`: VC8 inlines this
         * `first != middle && middle != last` guard at every call site and
         * only then calls the out-of-line `_Rotate` above.
         */
        template <class T>
        /**
         * Address: 0x005F06C0 (FUN_005F06C0 -- `rotate` -- the gcd-cycle form for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005EEDA0, 0x005EFBE0, 0x005F0480; formerly `RotateAttachPointRangeByGcdCycles` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005F0480 (FUN_005F0480 -- an adapter over that rotate for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); zero callers, unreachable; formerly `RotateAttachPointRangeByGcdCyclesAdapter` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EFBE0 (FUN_005EFBE0 -- the guarded adapter over that rotate for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); zero callers, unreachable; formerly `RotateAttachPointRangeByGcdCyclesGuardedAdapter` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         */
        void rotate(T* const first, T* const middle, T* const last)
        {
            if (first != middle && middle != last) {
                rotate_cycles(first, middle, last);
            }
        }

        /**
         * Address: 0x005958C0 (FUN_005958C0, `_Insertion_sort`)
         *
         * What it does:
         * VC8's `_Insertion_sort`: walks forward from the second element and
         * rotates each one back over the run of predecessors that compare
         * greater. An element that compares less than `*first` is rotated
         * straight to the front; otherwise the scan back from the element
         * stops at the first predecessor that does not compare greater and
         * rotates the element into that hole. Both moves are `std::rotate`
         * (`rotate` above), which is how VC8 wrote it: the compiler emits one
         * out-of-line `_Rotate` per element type beside every one of these.
         */
        /**
         * Address: 0x0089C4A0 (FUN_0089C4A0, the `SBuildTemplateInfo` body --
         * recovers the element count with the 2E8BA2E9h divide-by-0x2C magic
         * pair and keeps one 0x2C-byte element in a stack temp as the value
         * being slid into place)
         * Address: 0x0089BBA0 (FUN_0089BBA0, the 45-instruction outer guard
         * MSVC emitted separately, which range-checks and tail-calls the body
         * above)
         */
        /**
         * Address: 0x008DB430 (FUN_008DB430, the `gpg::RField` instantiation
         * -- walks forward from `a1+1`, comparing/sliding each `RField` back
         * over the run of `mName`-greater predecessors via `strcmp`, with the
         * multi-element rotate delegated to `FUN_008DA5D0` rather than
         * inlined (this template folds that rotate into the loop below
         * directly; same observable result). Reached from `_Sort`'s
         * (`FUN_008DD790`, cited on `sort_impl` below) small-range fallback,
         * `<= 32` elements. Was mis-tagged `blocked` (stale, pre-dates
         * `no_block_guard.py`); corrected to skip/cited-here.)
         *
         * Address: 0x008DA5D0 (FUN_008DA5D0, sub_8DA5D0) -- the multi-element
         * rotate `FUN_008DB430` calls out to for this instantiation's `<= 32`
         * shift (0x14-byte `gpg::RField` stride, `(a2-a1)/20` confirms the
         * element count). `.c`-confirmed classic GCD-cycle ("juggling")
         * rotate: computes `gcd(range length, rotation amount)` via Euclid's
         * algorithm, then walks that many independent element cycles,
         * copying through a fixed-size (20-byte) stack temp per cycle step.
         * This template's `insertion_sort` above reproduces the exact same
         * observable shift behavior via the simpler `for (hole = cursor;
         * hole != first; --hole) *hole = *(hole-1);` loop -- a full GCD-
         * cycle rotate and a plain backward-shift loop are behaviorally
         * identical for the "shift a contiguous run by one slot" case
         * `insertion_sort` uses it for (rotation amount always 1 here), so
         * no separate call is needed to reproduce the binary's observable
         * effect; the compiler's choice to keep `FUN_008DA5D0` as a
         * standalone out-of-line general-purpose rotate is a codegen
         * artifact of the shared VC8 STL `_Rotate`/`std::rotate` machinery,
         * not a distinct algorithmic step this instantiation's source needs
         * to name separately. Two of its four real callers
         * (0x008DB073/0x008DB33B) sit in address ranges IDA did not box
         * into named functions -- not chased further this pass.
         */
        /**
         * Address: 0x00574170 (FUN_00574170 -- `_Insertion_sort` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp): rotates on `pred = greater` over the `+0x18` key, the direction `CompareRunScriptCandidateByDistanceSq` reproduces.)
         * Address: 0x0054F290 (FUN_0054F290 -- `_Insertion_sort` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         */
        template <class T, class Compare>
        /**
         * Address: 0x0071F2C0 (FUN_0071F2C0 -- `_Insertion_sort` for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x0071E200; formerly `InsertionSortFloat4LaneRangeByDescendingW` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EEDA0 (FUN_005EEDA0 -- `insertion_sort` -- the small-range tail of `msvc8::sort` for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005ED680; formerly `SortSmallAttachPointRangeByDistance` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         */
        void insertion_sort(T* const first, T* const last, Compare comp)
        {
            if (first == last) {
                return;
            }

            for (T* next = first; ++next != last;) {
                T* next1 = next;
                if (comp(*next, *first)) {
                    // New earliest element: rotate it to the front.
                    rotate(first, next, ++next1);
                } else {
                    // Look for the insertion point after `first`.
                    for (T* first1 = next1; comp(*next, *--first1); next1 = first1) {
                    }
                    rotate(next1, next, next + 1);
                }
            }
        }

        /**
         * Address: 0x00595DF0 (FUN_00595DF0, `_Adjust_heap`)
         *
         * Sifts the value at `hole` down over `count` elements, then settles it
         * upward - the classic Dinkumware two-phase form, which does one
         * comparison per level on the way down instead of two.
         */
        /**
         * Address: 0x0089C170 (FUN_0089C170, the `SBuildTemplateInfo`
         * instantiation -- the sift-down half)
         * Address: 0x0089C350 (FUN_0089C350, VC8's `_Push_heap`, which this
         * template inlines as its settle-upward loop. Recognisable from the
         * `lea eax,[esi-1]; cdq; sub eax,edx; sar edi,1` parent-index
         * computation, i.e. `(hole - 1) / 2`.)
         */
        /**
         * Address: 0x0087E850 (FUN_0087E850, the `Moho::UserEntity*`
         * instantiation used by `CDecalManager::EntitiesInView`/`PropsInView`'s
         * decal-order sort -- `msvc8::sort<UserEntity*, Compare>` falls back to
         * heapsort here, so this single body fuses both the sift-down and the
         * settle-upward phase, matching this template's shape exactly rather
         * than the split `0x0089C170`/`0x0089C350` pair. Compares
         * `[node+0x14]` unsigned (`jnb`), i.e.
         * `UserEntity::mSpatialDbEntry.mEntryId`. Called from `make_heap`
         * (`0x0087E5B0`), `sort_heap` (`0x0087E5F0`), and three inlined
         * single-pop-step callers (`0x0087E8D0`, `0x0087EA70`, `0x0087EB30`).)
         * Address: 0x0087EA30 (FUN_0087EA30, VC8's standalone `_Push_heap` for
         * the same `UserEntity*` instantiation -- structurally identical to
         * the settle-upward loop below (same `(hole - 1) / 2` parent-index
         * math, same `[node+0x14]` unsigned compare), emitted as its own
         * symbol alongside `0x0087E850` but with zero live callers anywhere
         * in the shipped binary (IDA xrefs and the callgraph index both come
         * back empty): the `UserEntity*` collections in `CDecalManager` are
         * always rebuilt with a full `msvc8::sort`, never incrementally
         * pushed. Same citation-only pattern as `0x0089C350` above.)
         * Address: 0x00760590 (FUN_00760590, the 8-byte `DumpUnitsCountEntry`
         * instantiation -- sift-down half only, called recursively from the
         * heapify driver `sub_75FDB0` for `SortDumpUnitsCountEntries`'s
         * descending-population-count sort. Element stride confirmed from
         * `(a2 - a1) >> 3`; recurses into `sub_760720` for the child compare,
         * the same two-way split this template's `comp` calls encode.)
         * Address: 0x008DAF60 (FUN_008DAF60, the `gpg::RField` sift-down
         * half, called from `make_heap`'s `FUN_008DB2A0` -- cited below)
         * Address: 0x008DB080 (FUN_008DB080, the `gpg::RField` settle-
         * upward/pop-step half, called from `sort_heap`'s `FUN_008DBF60`
         * -- cited below). Both were mis-tagged `external_dependency`
         * ("all-external-callees thunk") -- neither has any third-party
         * callee at all; corrected to skip/cited-here, same `_Adjust_heap`
         * split-phase shape as `0x0089C170`/`0x0089C350` above.)
         */
        /**
         * Address: 0x00575280 (FUN_00575280 -- `_Adjust_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp) (sift-down half, hands the hole to the `_Push_heap` at 0x00575500).)
         * Address: 0x00575500 (FUN_00575500 -- `_Push_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp) (settle-upward half).)
         * Address: 0x0054FD90 (FUN_0054FD90 -- `_Adjust_heap` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         * Address: 0x005501E0 (FUN_005501E0 -- `_Push_heap` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         * Address: 0x008DA500 (FUN_008DA500 -- `_Push_heap` for the `gpg::RField` instantiation (the settle-upward half the `_Adjust_heap` at 0x008DAF60 calls).)
         * Address: 0x00595F40 (FUN_00595F40 -- `_Push_heap` for the `SDepositCandidate` instantiation (called from the `_Adjust_heap` at 0x00595DF0).)
         * Address: 0x00A72840 (FUN_00A72840 -- `_Adjust_heap` for the 8-byte `{float, dword}` instantiation (`make_heap` 0x00A72D40 / `sort_heap` 0x00A73E20); its `_Push_heap` half is 0x00A72360.)
         */
        template <class T, class Compare>
        /**
         * Address: 0x00760850 (FUN_00760850 -- `_Push_heap` (settle-upward) for an 8-byte `(id, key)` element ordered by the second dword; callers 0x00760720; formerly `SiftElement8LanePairUpBySecondWordRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00760720 (FUN_00760720 -- `_Adjust_heap` for an 8-byte `(id, key)` element ordered by the second dword; callers 0x00760590, 0x007605E0, 0x007607C7; formerly `SiftElement8LanePairDownThenInsertBySecondWordRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00720010 (FUN_00720010 -- `_Adjust_heap` for a 16-byte float[4] element; callers 0x0071F990, 0x0071FA00, 0x007202E0; formerly `SiftDownFloat4HeapAndFinalizeRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00720250 (FUN_00720250 -- `_Push_heap` (settle-upward) for a 16-byte float[4] element; callers 0x00720010; formerly `InsertFloat4HeapEntryByPromotingParentsRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0084BF30 (FUN_0084BF30 -- `_Adjust_heap` for a 12-byte scored element; callers 0x0084BB20, 0x0084BB90, 0x0084C520; formerly `SiftHeapHoleDownAndReinsertByScoreRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0084C280 (FUN_0084C280 -- `_Push_heap` (settle-upward) for a 12-byte scored element; callers 0x0084BF30; formerly `SiftHeapEntry12ByScoreRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0084C460 (FUN_0084C460 -- `_Push_heap` (settle-upward) for a 12-byte element ordered by `(tie, score)`; callers 0x0084C130; formerly `SiftHeapEntry12ByScoreAndTieRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x007CEDB0 (FUN_007CEDB0 -- `_Push_heap` (settle-upward) for the 24-byte `(priority, LuaObject)` element; callers 0x007CE9D0; formerly `InsertLuaHeapPairRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092D760 (FUN_0092D760 -- `_Adjust_heap` for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092D89F, 0x0092E1C0, 0x0092E2A0; formerly `SiftDownAndInsertU16HeapTail` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005F05E0 (FUN_005F05E0 -- `push_heap`'s sift-up half of `adjust_heap` for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005F0330; formerly `InsertAttachPointIntoMaxHeapWindow` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005F0330 (FUN_005F0330 -- `adjust_heap`'s sift-down half for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005EFAD0, 0x005F0810; formerly `SiftDownAttachPointHeapAndInsert` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         */
        void adjust_heap(T* const first, std::ptrdiff_t hole, const std::ptrdiff_t count, T value, Compare comp)
        {
            const std::ptrdiff_t top = hole;
            std::ptrdiff_t child = 2 * hole + 2;

            for (; child < count; child = 2 * child + 2) {
                if (comp(first[child], first[child - 1])) {
                    --child;
                }
                first[hole] = first[child];
                hole = child;
            }

            if (child == count) {
                first[hole] = first[count - 1];
                hole = count - 1;
            }

            // Settle upward from the hole back toward `top`.
            for (std::ptrdiff_t parent = (hole - 1) / 2;
                 top < hole && comp(first[parent], value);
                 parent = (hole - 1) / 2) {
                first[hole] = first[parent];
                hole = parent;
            }
            first[hole] = value;
        }

        /**
         * Address: 0x0089BED0 (FUN_0089BED0, the `SBuildTemplateInfo`
         * instantiation; drives the sift-down at 0x0089C170)
         */
        /**
         * Address: 0x0087E5B0 (FUN_0087E5B0, the `UserEntity*` instantiation
         * driving the fused sift at 0x0087E850; called from the `msvc8::sort`
         * heapsort fallback for `CDecalManager::EntitiesInView`/`PropsInView`.)
         */
        /**
         * Address: 0x008DB2A0 (FUN_008DB2A0, the `gpg::RField` instantiation
         * -- `for (hole = count/2; hole > 0;) adjust_heap(first, --hole,
         * count, first[hole], comp)`, matching this member's loop exactly
         * (drives the sift-down half at `FUN_008DAF60`, cited above).
         * Reached from `_Sort`'s (`FUN_008DD790`, cited below) ideal-budget-
         * exhausted heapsort fallback. Was mis-tagged `external_dependency`;
         * corrected to skip/cited-here.)
         */
        /**
         * Address: 0x00574A30 (FUN_00574A30 -- `make_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp).)
         * Address: 0x0054F990 (FUN_0054F990 -- `make_heap` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         */
        template <class T, class Compare>
        /**
         * Address: 0x0092E1C0 (FUN_0092E1C0 -- `_Make_heap` for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092E850, 0x0092F4E0; formerly `BuildU16MaxHeapFromRange` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092E850 (FUN_0092E850 -- `_Make_heap`'s two-element guard for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); zero callers, unreachable; formerly `BuildU16HeapIfWideEnough` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071F990 (FUN_0071F990 -- `_Make_heap` for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x0071E200, 0x0071F280; formerly `BuildFloat4MinHeapRangeFromMiddle` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071F280 (FUN_0071F280 -- `_Make_heap`'s two-element guard for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; zero callers, unreachable; formerly `BuildFloat4HeapIfRangeHasMultipleElements` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EFAD0 (FUN_005EFAD0 -- `make_heap` for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005ED680, 0x005EED50; formerly `BuildAttachPointMaxHeap` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EED50 (FUN_005EED50 -- the size-guarded form of `make_heap` for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); zero callers, unreachable; formerly `BuildAttachPointMaxHeapIfMultiElement` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         */
        void make_heap(T* const first, T* const last, Compare comp)
        {
            const std::ptrdiff_t count = last - first;
            if (count < 2) {
                return;
            }
            for (std::ptrdiff_t hole = count / 2; hole > 0;) {
                --hole;
                adjust_heap(first, hole, count, first[hole], comp);
            }
        }

        /**
         * Address: 0x00595C40 (FUN_00595C40, `_Sort_heap`)
         *
         * Repeatedly swaps the root to the back and re-sifts over the shrinking
         * prefix.
         */
        /**
         * Address: 0x0089BF70 (FUN_0089BF70, the `SBuildTemplateInfo`
         * instantiation)
         * Address: 0x0089C440 (FUN_0089C440, VC8's `_Pop_heap`)
         * Address: 0x0089C680 (FUN_0089C680, VC8's `_Pop_heap_hole`, which
         * hands back to the sift-down at 0x0089C170). Both are out-of-line in
         * the binary and inlined here as the three-line pop step in the loop
         * below.)
         */
        /**
         * Address: 0x0087E5F0 (FUN_0087E5F0, the `UserEntity*` instantiation
         * driving the fused sift at 0x0087E850, same call chain as
         * `make_heap`'s `0x0087E5B0`.)
         * Address: 0x0087E8D0, 0x0087EA70, 0x0087EB30 (FUN_0087E8D0,
         * FUN_0087EA70, FUN_0087EB30, three more VC8 emissions of a single
         * pop-and-resift step -- `0x0087EB30` additionally hands the popped
         * root back through an out-param, the shape VC8 used when a caller
         * wants the removed max rather than just draining the heap in place.
         * All three are, like `0x0089C440`/`0x0089C680` above, out-of-line
         * emissions of the exact three-line pop step in the loop below, with
         * no separate callers of their own in the shipped binary.)
         */
        /**
         * Address: 0x008DBF60 (FUN_008DBF60, the `gpg::RField` instantiation
         * -- `for (count = (a2-a1)/20; count > 1; --count) { swap first[0]
         * and first[count-1] into place; adjust_heap(...) }`, matching this
         * member's loop exactly (drives the settle-upward half at
         * `FUN_008DB080`, cited above). Reached from `_Sort`'s
         * (`FUN_008DD790`, cited below) heapsort fallback, right after
         * `make_heap`'s `FUN_008DB2A0`. Was mis-tagged `external_dependency`;
         * corrected to skip/cited-here.)
         */
        /**
         * Address: 0x00574B40 (FUN_00574B40 -- `sort_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp).)
         * Address: 0x0054F9E0 (FUN_0054F9E0 -- `sort_heap` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         * Address: 0x00575950 (FUN_00575950 -- `_Pop_heap_hole` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp): writes the root into the vacated tail slot and re-sifts the displaced value.)
         * Address: 0x00575490 (FUN_00575490 -- `pop_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x00575660 (FUN_00575660 -- `pop_heap` for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x00550280 (FUN_00550280 -- `_Pop_heap`/`_Pop_heap_hole` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x00550450 (FUN_00550450 -- `_Pop_heap`/`_Pop_heap_hole` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp); zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x00A73F50 (FUN_00A73F50 -- thunks into the `{float, dword}`/`double` `sort_heap` bodies at 0x00A73E20/0x00A73E70; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         * Address: 0x00A73F60 (FUN_00A73F60 -- thunks into the `{float, dword}`/`double` `sort_heap` bodies at 0x00A73E20/0x00A73E70; zero callers, no xrefs, unreachable from every seeded root: a linker-retained copy nothing runs.)
         */
        template <class T, class Compare>
        /**
         * Address: 0x007605E0 (FUN_007605E0 -- `_Sort_heap` for an 8-byte `(id, key)` element; callers 0x0075FDB0, 0x00760290; formerly `HeapSortElement8RangeTailPassRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00734210 (FUN_00734210 -- `_Sort_heap` for an 8-byte `(id, key)` element; callers 0x00733B40, 0x00733F50; formerly `HeapSortElement8RangeTailPassRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00733F50 (FUN_00733F50 -- `_Sort_heap` for an 8-byte `(id, key)` element; zero callers, unreachable; formerly `HeapSortElement8RangeTailPassRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x007608A0 (FUN_007608A0 -- `_Pop_heap` for an 8-byte `(id, key)` element; zero callers, unreachable; formerly `PopElement8TailIntoRootAndSiftRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092EC40 (FUN_0092EC40 -- `_Sort_heap` for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092EEE0, 0x0092F4E0; formerly `HeapSortU16Range` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092EEE0 (FUN_0092EEE0 -- the `jmp` thunk into `_Sort_heap` for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); zero callers, unreachable; formerly `HeapSortU16RangeThunk` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092E2A0 (FUN_0092E2A0 -- `_Pop_heap` for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); zero callers, unreachable; formerly `ReplaceU16HeapRootWithTailAndSift` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0092E8E0 (FUN_0092E8E0 -- `_Pop_heap`'s two-element guard for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); zero callers, unreachable; formerly `ReplaceU16HeapRootIfWideEnough` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x007200D0 (FUN_007200D0 -- `_Pop_heap`'s two-element guard for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; zero callers, unreachable; formerly `PopFloat4HeapRootIfRangeHasMultipleElements` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x00720470 (FUN_00720470 -- `_Pop_heap` for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; zero callers, unreachable; formerly `CopyRootAndSiftFloat4HeapWithReplacement` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071FA00 (FUN_0071FA00 -- `_Sort_heap` for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x0071E200, 0x0071F2B0; formerly `PopFloat4MinHeapToTailUntilSingle` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x007202E0 (FUN_007202E0 -- `_Pop_heap` (one root-to-tail step) for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x007200D0 (unreached); formerly `PopFloat4MinHeapRootSingleStepWithFinalize` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071F2B0 (FUN_0071F2B0 -- a register-shape entry into `_Sort_heap` for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; zero callers, unreachable; formerly `PopFloat4HeapToTailAdapter` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005F0810 (FUN_005F0810 -- `pop_heap` -- swap the root to the tail, then sift down for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005EFB50, 0x005F0460, 0x005F0680; formerly `PopAttachPointHeapRootAndInsert` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005F0680 (FUN_005F0680 -- the adapter over that pop for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); zero callers, unreachable; formerly `PopAttachPointHeapRootIntoTailSlotAdapter` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EFB50 (FUN_005EFB50 -- `sort_heap` -- pop until the range is ordered for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); callers 0x005ED680, 0x005EED90; formerly `PopAttachPointHeapRootsIntoSortedTail` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x005EED90 (FUN_005EED90 -- the one-jump thunk into that `sort_heap` for `msvc8::vector<moho::SAttachPoint>` (the transport's attach-point vector, sorted by squared distance); zero callers, unreachable; formerly `PopAttachPointHeapRootsIntoSortedTailThunk` in moho/ai/CAiTransportImpl.cpp (RULE ONE), removed 2026-09-10.)
         */
        void sort_heap(T* const first, T* last, Compare comp)
        {
            for (std::ptrdiff_t count = last - first; count > 1; --count) {
                T value = first[count - 1];
                first[count - 1] = first[0];
                adjust_heap(first, 0, count - 1, value, comp);
            }
        }

        /**
         * Address: 0x005955C0 (FUN_005955C0, `_Unguarded_partition`)
         *
         * What it does:
         * Partitions around the median of first/middle/last and returns the
         * half-open run of elements that compare equal to the pivot, so the
         *
         * Address: 0x0089B9E0 (FUN_0089B9E0, the `Moho::SBuildTemplateInfo`
         * instantiation -- calls the median pick at 0x0089BD10 once and the
         * swap at 0x0089C070 seven times, which is the shape of this
         * function: one pivot selection, then the two scan loops plus the
         * equal-run gathering at each end.)
         * driver can skip that whole block instead of re-sorting it.
         *
         * Address: 0x008DAA00 (FUN_008DAA00, the `gpg::RField` instantiation
         * -- calls the ninther dispatcher at 0x008DA410 once (not a bare
         * `median3`; this instantiation is the one whose real caller,
         * `gpg::RType::Finish()`, sorts large-enough field lists to actually
         * exercise the ninther branch), then runs the same two-scan-loop plus
         * equal-run-gathering shape as `0x0089B9E0` above, with the raw swaps
         * inlined rather than routed through a named `iter_swap` callee.
         * Reached from `_Sort`'s (`FUN_008DD790`, cited below) partition
         * step. Was mis-tagged `blocked` (stale, "no canonical Address:0x
         * body in src/sdk for token" -- not a valid blocker per RULE ONE,
         * compiler-emission glue is supposed to have no separate body);
         * corrected to skip/cited-here.)
         *
         * Address: 0x00A730D0 (FUN_00A730D0, the 8-byte `{float x, y;}` pair
         * instantiation -- pivot pick at `sub_A72CB0` (a bare `median3`, not
         * the ninther: this instantiation's own driver, `FUN_00A740D0` cited
         * on `sort_impl` below, never exercises `select_ninther`'s branch in
         * the surviving call sites), then the same two-scan-loop-plus-
         * equal-run-gathering shape as the instantiations above, with raw
         * 2-dword swaps inlined at each `iter_swap` point.)
         * Address: 0x00A73500 (FUN_00A73500, the `double` (8-byte scalar)
         * instantiation -- same shape as `0x00A730D0`, pivot pick at
         * `sub_A72D90`, swaps widened to 4-dword lanes to move a `double`.)
         * Address: 0x00733D10 (FUN_00733D10, a second 8-byte `{float x, y;}`
         * pair instantiation at a different call site -- pivot pick at
         * `sub_7340C0`, otherwise byte-for-byte the same partition shape as
         * `0x00A730D0`. Distinct instantiation root (different translation
         * unit / comparator capture), same template.)
         * Address: 0x007CD570 (FUN_007CD570, the `LuaPlus::LuaObject`-keyed
         * 24-byte-element instantiation -- pivot pick at `sub_7CE3A0`; unlike
         * the trivially-copyable instantiations above, every `iter_swap`
         * point is a real three-way `LuaObject(temp, lhs); lhs = rhs; rhs =
         * temp;` sequence (explicit ctor/copy-assign/dtor calls, matching
         * this template's generic `iter_swap_value` exactly for a
         * non-trivial `T` rather than the raw-dword swap the trivial
         * instantiations fold it down to). Comparator is inlined 3-way
         * dword compares on the leading key field rather than a named
         * callee -- same algorithm, comparator capture just didn't survive
         * as a separate symbol.)
         */
        /**
         * Address: 0x0054EE30 (FUN_0054EE30 -- `_Unguarded_partition` for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp).)
         */
        template <class T, class Compare>
        /**
         * Address: 0x0092E6E0 (FUN_0092E6E0 -- `_Unguarded_partition` (the three-way split returning both equal-band boundaries) for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092F4E0; formerly `PartitionU16RangeWithEqualBands` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071EFA0 (FUN_0071EFA0 -- `_Unguarded_partition` (the three-way split returning both equal-band boundaries) for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x0071E200; formerly `PartitionFloat4LaneRangeAroundPivot` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         */
        std::pair<T*, T*> unguarded_partition(T* const first, T* const last, Compare comp)
        {
            T* const middle = first + (last - first) / 2;
            if (last - 1 - first > kNintherCountLimit) {
                select_ninther(first, middle, last, comp);
            } else {
                median3(first, middle, last - 1, comp);
            }

            T pivot = *middle;
            T* pivotFirst = middle;
            T* pivotLast = pivotFirst + 1;

            // Widen the equal-run outward from the pivot before scanning.
            while (first < pivotFirst && !comp(*(pivotFirst - 1), pivot) && !comp(pivot, *(pivotFirst - 1))) {
                --pivotFirst;
            }
            while (pivotLast < last && !comp(*pivotLast, pivot) && !comp(pivot, *pivotLast)) {
                ++pivotLast;
            }

            T* greaterFirst = pivotLast;
            T* greaterLast = pivotFirst;

            for (;;) {
                for (; greaterFirst < last; ++greaterFirst) {
                    if (comp(pivot, *greaterFirst)) {
                        continue;
                    }
                    if (comp(*greaterFirst, pivot)) {
                        break;
                    }
                    if (pivotLast++ != greaterFirst) {
                        iter_swap_value(*(pivotLast - 1), *greaterFirst);
                    }
                }

                for (; first < greaterLast; --greaterLast) {
                    if (comp(*(greaterLast - 1), pivot)) {
                        continue;
                    }
                    if (comp(pivot, *(greaterLast - 1))) {
                        break;
                    }
                    if (--pivotFirst != greaterLast - 1) {
                        iter_swap_value(*pivotFirst, *(greaterLast - 1));
                    }
                }

                if (greaterLast == first && greaterFirst == last) {
                    return std::pair<T*, T*>(pivotFirst, pivotLast);
                }

                if (greaterLast == first) {
                    if (pivotLast != greaterFirst) {
                        iter_swap_value(*pivotFirst, *pivotLast);
                    }
                    ++pivotLast;
                    iter_swap_value(*pivotFirst, *greaterFirst);
                    ++pivotFirst;
                    ++greaterFirst;
                } else if (greaterFirst == last) {
                    --greaterLast;
                    --pivotFirst;
                    if (greaterLast != pivotFirst) {
                        iter_swap_value(*greaterLast, *pivotFirst);
                    }
                    --pivotLast;
                    iter_swap_value(*pivotFirst, *pivotLast);
                } else {
                    --greaterLast;
                    iter_swap_value(*greaterFirst, *greaterLast);
                    ++greaterFirst;
                }
            }
        }

        /**
         * Address: 0x00594890 (FUN_00594890, `_Sort`)
         *
         * What it does:
         * The introsort driver. Partitions while the range is large and the
         * recursion budget holds, recursing into the smaller side and looping on
         * the larger. When the budget runs out it switches to heapsort so a
         * pathological input cannot drive it quadratic; small ranges finish with
         * insertion sort.
         */
        /**
         * Address: 0x0089B540 (FUN_0089B540, the `Moho::SBuildTemplateInfo`
         * instantiation. It calls *itself* twice -- the two recursive
         * branches below -- plus the partition at 0x0089B9E0 and all three
         * fallbacks: insertion sort (0x0089BBA0), make_heap (0x0089BED0)
         * and sort_heap (0x0089BF70). That call set is what identifies it
         * as the introsort driver rather than any single phase.)
         */
        /**
         * Address: 0x008DD790 (FUN_008DD790, `std::_Sort<gpg::RField*>` --
         * the `gpg::RField` introsort driver. Same recursive shape as
         * `0x0089B540` above: `a3` (the ideal budget) decays by
         * `a3/2/2 + a3/2` per loop, recurses into the smaller partition half
         * and loops on the larger, falls to `insertion_sort` (`FUN_008DB430`)
         * once the range is `<= 32`, and to `make_heap`+`sort_heap`
         * (`FUN_008DB2A0`+`FUN_008DBF60`) once the ideal budget hits zero
         * with a still-large range. Real instantiation root: `gpg::
         * RType::Finish()`'s `std::sort(first, last, comp)` over `fields_`
         * (Reflection.cpp, `Address: 0x008DF4A0`), sorting reflected field
         * descriptors by `mName`. Correctly identified and marked `skip`
         * ("the programmer-written source line that emits it already exists
         * at the instantiating call site") by an earlier pass; this pass
         * traced the rest of the family beneath it -- `FUN_008DAA00`/
         * `FUN_008DA410`/`FUN_008D9EE0`/`FUN_008D9E20`/`FUN_008DB430`/
         * `FUN_008DB2A0`/`FUN_008DBF60`/`FUN_008DAF60`/`FUN_008DB080` --
         * which were mis-tagged `external_dependency`/`blocked` on the
         * theory that a function whose only non-recursive callees are CRT
         * `strcmp` calls or terminal-status siblings must itself be
         * external. Wrong: the three-way-compare/partition/heap *control
         * flow* is this project's own `_Sort<RField*>` emission: engine
         * code that happens to call CRT primitives, not CRT code itself.)
         *
         * Address: 0x00A740D0 (FUN_00A740D0, the 8-byte `{float x, y;}` pair
         * instantiation. Element stride confirmed from `((char*)a2-(char*)a1)
         * >> 3`; ideal budget decays via the same `a3/2/2 + a3/2` "three
         * quarters" step; partitions through `FUN_00A730D0` (cited on
         * `unguarded_partition` above), falls to `FUN_00A73B30`
         * (`insertion_sort`) under 32 elements, and to `FUN_00A72D40` +
         * `FUN_00A73E20` (`make_heap` + `sort_heap`) once the budget is
         * exhausted -- recurses into whichever partition half is smaller and
         * loops on the larger, same bounded-stack-depth shape as this
         * template. Calls itself recursively at both `sub_A740D0(v9, v4,
         * a3)` and `sub_A740D0(v3, v8, a3)`, the same "call set" signature
         * the `SBuildTemplateInfo`/`gpg::RField` instantiations above were
         * identified by.)
         * Address: 0x00A741A0 (FUN_00A741A0, the `double` (8-byte scalar)
         * instantiation -- same shape as `0x00A740D0` one dword-width wider
         * throughout (`>> 4` stride, `0xFFFFFFF0` masks), partitions through
         * `FUN_00A73500`, falls to `FUN_00A73BD0` / `FUN_00A72E20` +
         * `FUN_00A73E70`.)
         */
        /**
         * Address: 0x005734F0 (FUN_005734F0 -- `_Sort` driver for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp): partition, recurse into the smaller half, heapsort fallback.)
         * Address: 0x0054E4B0 (FUN_0054E4B0 -- `_Sort` driver for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp) (0x0054A32C).)
         */
        template <class T, class Compare>
        /**
         * Address: 0x0092F4E0 (FUN_0092F4E0 -- `_Sort` -- the introsort driver: partition while the budget lasts, `_Insertion_sort` under 32 elements, `_Make_heap` + `_Sort_heap` when the budget runs out -- for the `unsigned short` instantiation of `msvc8::sort` over the packed subcluster node keys (`BuildSubclusterPackedNodeList`, 0x0092FE30); callers 0x0092FC41, 0x0092FE30, 0x009550E0; formerly `IntroSortU16RangeWithBudget` in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-10.)
         * Address: 0x0071E200 (FUN_0071E200 -- `_Sort` -- the introsort driver for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; callers 0x007171D0, 0x0071CA80; formerly `SortFloat4LaneRangeDispatcher` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
         */
        void sort_impl(T* first, T* last, std::ptrdiff_t ideal, Compare comp)
        {
            while (kInsertionSortMax < last - first && ideal > 0) {
                const std::pair<T*, T*> middle = unguarded_partition(first, last, comp);

                // 0x005948E9: ideal = ideal/4 + ideal/2, i.e. three quarters.
                ideal = (ideal / 2) + (ideal / 2 / 2);

                if (middle.first - first < last - middle.second) {
                    sort_impl(first, middle.first, ideal, comp);
                    first = middle.second;
                } else {
                    sort_impl(middle.second, last, ideal, comp);
                    last = middle.first;
                }
            }

            if (kInsertionSortMax < last - first) {
                make_heap(first, last, comp);
                sort_heap(first, last, comp);
            } else if (last - first > 1) {
                insertion_sort(first, last, comp);
            }
        }
    } // namespace detail

    /**
     * MSVC8 `std::sort(first, last, comp)`.
     *
     * The initial recursion budget is `last - first`, matching the 2007 header.
     */
    /**
     * For the `Moho::SBuildTemplateInfo` instantiation this entry point is
     * inlined into its caller -- `CWldSession::GenerateBuildTemplates`
     * (0x00896AA0) calls the driver at 0x0089B540 directly. The whole
     * twelve-body instantiation is catalogued on the members above.
     *
     * For the `gpg::RField` instantiation, this entry point is also inlined
     * into its caller, `gpg::RType::Finish()` (Reflection.cpp), which calls
     * `msvc8::sort(first, last, comp)` directly on `fields_`. The whole
     * nine-body instantiation (`_Sort`/`_Unguarded_partition`/`_Median`/
     * `_Med3`/`iter_swap`/`_Insertion_sort`/`make_heap`/`sort_heap`/
     * `_Adjust_heap` x2) is catalogued on the members above.
     */
    /**
     * Address: 0x00572350 (FUN_00572350 -- `std::sort` entry for the `SFormationRunScriptCandidate` (0x48) instantiation of `CFormationInstance::RunScript`'s sort (CAiFormationInstance.cpp).)
     * Address: 0x0054DDD0 (FUN_0054DDD0 -- `std::sort` entry for the `SAniSkelBoneNameIndex` (8-byte `{const char*, int32}`) instantiation of `CAniSkel::CAniSkel`'s bone-name sort (CAniSkel.cpp): `return _Sort(first, last, (last - first) >> 3, comp)`.)
     */
    template <class T, class Compare>
    /**
     * Address: 0x00595D20 (FUN_00595D20 -- `_Med3` for a float[3] element ordered by lane 2; callers 0x00595AC0; formerly `SortThreeFloat3ByLane2AscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x005F01C0 (FUN_005F01C0 -- `_Med3` for a float[5] element ordered by lane 4; callers 0x005EF990; formerly `SortThreeFloat5ByLane4AscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0071FEE0 (FUN_0071FEE0 -- `_Med3` for a float[4] element ordered by lane 3 descending; callers 0x0071F870; formerly `SortThreeFloat4ByLane3DescendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x007342C0 (FUN_007342C0 -- `_Med3` for a float[2] element ordered by lane 1; callers 0x007340C0; formerly `SortThreeFloat2ByLane1AscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00760690 (FUN_00760690 -- `_Med3` for an `(id, score)` element ordered by score descending; callers 0x007604A0; formerly `SortThreeDwordPairsByScoreDescendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x007604A0 (FUN_007604A0 -- `_Median` (the ninther pivot pick) for an `(id, score)` element ordered by score descending; callers 0x007600A0; formerly `SelectDwordPairScoreDescendingNintherPivotRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0084BE60 (FUN_0084BE60 -- `_Med3` for a float[3] element ordered by lane 1; callers 0x0084BA10; formerly `SortThreeFloat3ByLane1AscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0084C050 (FUN_0084C050 -- `_Med3` for a float[3] element ordered by lane 2 descending, lane 1 ascending; callers 0x0084BC50; formerly `SortThreeFloat3ByLane2DescTieLane1AscRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00A727C0 (FUN_00A727C0 -- `_Med3` for a float[2] element ordered by lane 0; callers 0x00A72CB0 (unreached); formerly `SortThreeFloat2ByLane0AscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00A728C0 (FUN_00A728C0 -- `_Med3` for a 16-byte element ordered by its leading double; callers 0x00A72D90 (unreached); formerly `SortThreeDword4ByDoubleKeyAscendingRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00A72CB0 (FUN_00A72CB0 -- `_Median` (the ninther pivot pick) for a float[2] element; callers 0x00A730D0 (unreached); formerly `SelectFloat2NintherPivotForIntrosortRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x00A72D90 (FUN_00A72D90 -- `_Median` (the ninther pivot pick) for a 16-byte element ordered by its leading double; callers 0x00A73500 (unreached); formerly `SelectDword4NintherPivotForIntrosortRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0071CA80 (FUN_0071CA80 -- `std::sort(first, last, comp)`'s entry (`_Sort(first, last, last - first, comp)`) for the 0x10-byte `moho::SPositionThreat` ordered by descending `threat` -- `CInfluenceMap::GetThreatsAroundPosition`'s `msvc8::sort` over the collected samples; zero callers, unreachable; formerly `SortFloat4LaneRangeDispatcherWithSpanBudget` in moho/sim/CInfluenceMap.cpp (RULE ONE), removed 2026-09-10.)
     */
    void sort(T* const first, T* const last, Compare comp)
    {
        detail::sort_impl(first, last, last - first, comp);
    }
} // namespace msvc8
