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
         * Address: 0x0089C070 (FUN_0089C070, the swap for
         * `Moho::SBuildTemplateInfo` -- 0x2C bytes of
         * `{Wm3::Vector3f mPos; int mBuildOrder; msvc8::string mBlueprintId;}`.
         * The 0x2C stack temp it opens with is the `T temp = lhs` below; the
         * blueprint-id lane moves through `std::string::assign(str, 0, -1)`
         * three times, once per leg of the three-way exchange.)
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
         */
        template <class T, class Compare>
        std::pair<T*, T*> unguarded_partition(T* const first, T* const last, Compare comp)
        {
            T* const middle = first + (last - first) / 2;
            median3(first, middle, last - 1, comp);

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
     */
    template <class T, class Compare>
    void sort(T* const first, T* const last, Compare comp)
    {
        detail::sort_impl(first, last, last - first, comp);
    }
} // namespace msvc8
