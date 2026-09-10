#pragma once

/**
 * MSVC8-era `std::remove` / `std::remove_if`, recovered from the Forged
 * Alliance binary.
 *
 * The 2007 shape is not a compaction loop over the whole range: it finds the
 * first element to drop, and only then starts writing. Everything before the
 * first match is left untouched rather than self-assigned, which is why the
 * binary always emits two bodies per instantiation -- a find pass and a
 * shift pass -- and why the shift pass is entered with `first` already
 * pointing at the hole.
 *
 * That split is observable in the disassembly and is the reason a single
 * "compact the range" helper never matches: the emissions call each other.
 */

#include <cstddef>

namespace msvc8
{
    /**
     * Shifts every element of `(first, last)` that does not equal `value`
     * down over the hole at `first`, and returns the new logical end.
     *
     * This is the second half of `remove` below; MSVC8 emits it as its own
     * body because `remove` tail-calls it after the find pass.
     *
     * Address: 0x007B1B10 (FUN_007B1B10 -- `remove_shift` -- the write pass, entered with the hole already found for `msvc8::vector<moho::CameraImpl*>` (`RCamManager::mCams`); callers 0x007B0DE0, 0x007B15E0; formerly `CompactCameraPointerRangeExcludingNeedle` in moho/render/RCamManager.cpp (RULE ONE), removed 2026-09-11.)
     * Address: 0x007B15E0 (FUN_007B15E0 -- a register-shape bridge into that write pass; zero callers, unreachable; formerly `CompactCameraPointerRangeExcludingNeedleAdapter` in moho/render/RCamManager.cpp (RULE ONE), removed 2026-09-11.)
     */
    template <class ForwardIt, class T>
    ForwardIt remove_shift(ForwardIt hole, ForwardIt first, ForwardIt last, const T& value)
    {
        for (; first != last; ++first) {
            if (!(*first == value)) {
                *hole = *first;
                ++hole;
            }
        }
        return hole;
    }

    /**
     * Address: 0x007B0DE0 (FUN_007B0DE0 -- `remove` for a 4-byte
     * `moho::CameraImpl*` element (`RCamManager::mCams`): scan for the first
     * camera equal to the needle, hand `[match + 1, end)` to the shift pass at
     * 0x007B1B10, and export the new end through the caller's slot. Reached
     * from `RCamManager::ForgetCamera` 0x007AAA90, which is the erase-remove
     * idiom over that vector; formerly `RemoveCameraPointerFromRange` in
     * moho/render/RCamManager.cpp (RULE ONE), removed 2026-09-11.)
     *
     * Finds the first element equal to `value`, then shifts the rest of the
     * range down over it. Returns the new logical end; the caller erases
     * `[result, last)`.
     */
    template <class ForwardIt, class T>
    ForwardIt remove(ForwardIt first, ForwardIt last, const T& value)
    {
        for (; first != last; ++first) {
            if (*first == value) {
                break;
            }
        }

        if (first == last) {
            return first;
        }

        ForwardIt next = first;
        ++next;
        return remove_shift(first, next, last, value);
    }

    /**
     * Shifts every element of `(first, last)` that fails `pred` down over the
     * hole at `first`, and returns the new logical end.
     */
    template <class ForwardIt, class Pred>
    ForwardIt remove_if_shift(ForwardIt hole, ForwardIt first, ForwardIt last, Pred pred)
    {
        for (; first != last; ++first) {
            if (!pred(*first)) {
                *hole = *first;
                ++hole;
            }
        }
        return hole;
    }

    /**
     * The predicate form: same two-pass shape as `remove` above.
     */
    template <class ForwardIt, class Pred>
    ForwardIt remove_if(ForwardIt first, ForwardIt last, Pred pred)
    {
        for (; first != last; ++first) {
            if (pred(*first)) {
                break;
            }
        }

        if (first == last) {
            return first;
        }

        ForwardIt next = first;
        ++next;
        return remove_if_shift(first, next, last, pred);
    }
} // namespace msvc8
