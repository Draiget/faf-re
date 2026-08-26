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
        template <class T>
        void iter_swap_value(T& lhs, T& rhs)
        {
            T temp = lhs;
            lhs = rhs;
            rhs = temp;
        }

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
        template <class T, class Compare>
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
         * Address: 0x005958C0 (FUN_005958C0, `_Insertion_sort`)
         *
         * What it does:
         * Walks forward from the second element, sliding each one back over the
         * run of larger predecessors. The first element is special-cased so the
         * inner scan never needs a bounds test.
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
         */
        template <class T, class Compare>
        void insertion_sort(T* const first, T* const last, Compare comp)
        {
            if (first == last) {
                return;
            }

            for (T* cursor = first + 1; cursor != last; ++cursor) {
                T value = *cursor;

                if (comp(value, *first)) {
                    // Smaller than everything placed so far: rotate it to the front.
                    for (T* hole = cursor; hole != first; --hole) {
                        *hole = *(hole - 1);
                    }
                    *first = value;
                    continue;
                }

                T* hole = cursor;
                while (comp(value, *(hole - 1))) {
                    *hole = *(hole - 1);
                    --hole;
                }
                *hole = value;
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
        template <class T, class Compare>
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
        template <class T, class Compare>
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
        template <class T, class Compare>
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
         */
        template <class T, class Compare>
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
         */
        template <class T, class Compare>
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
    template <class T, class Compare>
    void sort(T* const first, T* const last, Compare comp)
    {
        detail::sort_impl(first, last, last - first, comp);
    }
} // namespace msvc8
