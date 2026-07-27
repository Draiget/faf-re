#pragma once

/**
 * MSVC8-era `stdext::hash_map` (from `<hash_map>`), recovered 1:1 from the
 * Forged Alliance binary.
 *
 * The engine instantiates this container for the A* search node table owned by
 * `Moho::PathQueue::ImplBase` (see `gpg/core/algorithms/AStarSearch.h`). Every
 * structural detail below is pinned by binary evidence rather than by the
 * modern `std::unordered_map` design:
 *
 *   - Elements live in a single sorted `msvc8::list`, not in per-bucket chains.
 *     A bucket is a *window* `[mVec[b], mVec[b + 1])` into that one list, so
 *     adjacent buckets share boundary iterators and an empty bucket is simply a
 *     window whose two boundaries are equal.
 *   - The table uses **linear hashing**: `mMaxidx` buckets are live out of a
 *     `mMask + 1` address space, and `_Grow` splits exactly one bucket per call
 *     instead of rehashing the whole table.
 *   - `hash_value` is the Park-Miller minstd step MSVC8 shipped for integral
 *     keys, reproduced exactly (including the `ldiv` decomposition) because the
 *     bucket assignment - and therefore iteration order - is observable.
 *
 * Layout (verified against `Moho::PathQueue::ImplBase` +0x00..+0x28):
 *
 *   +0x00 : Traits            (empty comparator, padded to 4)
 *   +0x04 : list _Myproxy
 *   +0x08 : list _Myhead      (also the end() sentinel stored in mVec)
 *   +0x0C : list _Mysize
 *   +0x10 : vector _Myproxy
 *   +0x14 : vector _Myfirst
 *   +0x18 : vector _Mylast
 *   +0x1C : vector _Myend
 *   +0x20 : mMask
 *   +0x24 : mMaxidx
 *   sizeof == 0x28
 */

#include <cstddef>
#include <cstdlib>
#include <functional>
#include <utility>

#include "legacy/containers/Vector.h"

namespace msvc8
{
    /**
     * Address: 0x00769560 (inlined into every `_Buckno` call site; also
     *          0x007692F0 and 0x0076AC60)
     *
     * IDA signature:
     * v3 = ldiv(*a2, 127773);
     * v4 = 16807 * v3.rem - 2836 * v3.quot;
     * if (v4 < 0) v4 += 0x7FFFFFFF;
     *
     * What it does:
     * MSVC8's `stdext::hash_value` for integral keys - one step of the
     * Park-Miller "minimal standard" generator using Schrage decomposition so
     * the 32-bit intermediate never overflows.
     */
    [[nodiscard]] inline std::size_t hash_value(long key) noexcept
    {
        const std::ldiv_t parts = std::ldiv(key, 127773L);
        long scrambled = 16807L * parts.rem - 2836L * parts.quot;
        if (scrambled < 0) {
            scrambled += 2147483647L;
        }
        return static_cast<std::size_t>(scrambled);
    }

    /**
     * MSVC8 `stdext::hash_compare`: bundles the hash function and the strict
     * weak ordering used to keep each bucket window sorted.
     *
     * Holds `Pred` by value (an empty `std::less` in every engine
     * instantiation), which is what gives the enclosing `hash_map` its 4-byte
     * leading member.
     */
    template <class Key, class Pred = std::less<Key>>
    class hash_compare
    {
        Pred comp;

    public:
        static constexpr std::size_t bucket_size = 4;
        static constexpr std::size_t min_buckets = 8;

        hash_compare() = default;

        explicit hash_compare(const Pred& pred)
            : comp(pred)
        {
        }

        /** Hashes one key. Found via ADL so user key types can supply their own. */
        [[nodiscard]] std::size_t operator()(const Key& key) const
        {
            return hash_value(key);
        }

        /** Orders two keys inside a bucket window. */
        [[nodiscard]] bool operator()(const Key& lhs, const Key& rhs) const
        {
            return comp(lhs, rhs);
        }
    };

    template <class Key, class T, class Traits = hash_compare<Key>>
    class hash_map
    {
    public:
        using key_type = Key;
        using mapped_type = T;
        using value_type = std::pair<const Key, T>;
        using list_type = list<value_type>;
        using iterator = typename list_type::iterator;
        using const_iterator = typename list_type::const_iterator;
        using size_type = std::size_t;

    private:
        Traits mTraits;            // +0x00
        list_type mList;           // +0x04
        vector<iterator> mVec;     // +0x10
        size_type mMask;           // +0x20
        size_type mMaxidx;         // +0x24

    public:
        hash_map()
            : mMask(1)
            , mMaxidx(1)
        {
            _Init();
        }

        [[nodiscard]] iterator begin() { return mList.begin(); }
        [[nodiscard]] iterator end() { return mList.end(); }
        [[nodiscard]] const_iterator begin() const { return mList.begin(); }
        [[nodiscard]] const_iterator end() const { return mList.end(); }
        [[nodiscard]] size_type size() const { return mList.size(); }
        [[nodiscard]] bool empty() const { return mList.empty(); }

        /**
         * Address: 0x007676A0 + 0x00767C70 (the two halves of the reset lane
         *          emitted at `PathQueue::ImplBase` +0x04 / +0x10)
         *
         * What it does:
         * Drops every element and re-arms the bucket window array so the table
         * is back to its freshly-constructed single-bucket state.
         */
        void clear()
        {
            mList.clear();
            _Init();
            mMask = 1;
            mMaxidx = 1;
        }

        /**
         * Address: 0x00769560 (FUN_00769560) / 0x0076AC60 (FUN_0076AC60)
         *
         * IDA signature:
         * _DWORD *sub_769560(_DWORD *ret@<ebx>, int *key@<edi>, _DWORD *self@<esi>);
         *
         * What it does:
         * Walks the sorted bucket window forward while `node.key < key`, then
         * returns that node when the keys compare equal and `end()` otherwise.
         *
         * The two addresses are separate emissions of the same template body:
         * 0x0076AC60 is the copy inlined for the `PathQueue::ImplBase` node
         * table, 0x00769560 the one reached from `operator[]`.
         */
        [[nodiscard]] iterator find(const key_type& key)
        {
            const size_type bucket = _Buckno(key);
            iterator scan = mVec[bucket];
            const iterator windowEnd = mVec[bucket + 1];

            while (scan != windowEnd) {
                if (!mTraits(scan->first, key)) {
                    // Ordering stops here; only an exact match is a hit.
                    return mTraits(key, scan->first) ? mList.end() : scan;
                }
                ++scan;
            }
            return mList.end();
        }

        /**
         * Address: 0x007692F0 (FUN_007692F0, second half)
         *
         * IDA signature:
         * int __userpurge sub_7692F0@<eax>(_DWORD *self@<edi>, int result, int *value);
         *
         * What it does:
         * Grows the table when the load factor is exceeded, locates the sorted
         * insertion point by scanning the bucket window *backwards* from its end
         * boundary, and links the new node there. Returns `{position, false}`
         * without inserting when an equivalent key is already present.
         */
        std::pair<iterator, bool> insert(const value_type& value)
        {
            if (mMaxidx <= mList.size() / 4) {
                _Grow();
            }

            const size_type bucket = _Buckno(value.first);
            const iterator windowBegin = mVec[bucket];
            iterator where = mVec[bucket + 1];

            if (windowBegin != where) {
                for (;;) {
                    --where;
                    if (!mTraits(value.first, where->first)) {
                        // where->first <= value.first
                        if (!mTraits(where->first, value.first)) {
                            return std::pair<iterator, bool>(where, false);
                        }
                        ++where;
                        break;
                    }
                    if (windowBegin == where) {
                        break;
                    }
                }
            }

            const iterator displaced = where;
            const iterator inserted = mList.insert(where, value);
            _RetargetBucketStarts(bucket, displaced, inserted);
            return std::pair<iterator, bool>(inserted, true);
        }

        /**
         * Address: 0x00768F40 (FUN_00768F40)
         *
         * IDA signature:
         * int __usercall sub_768F40@<eax>(int *key@<eax>, _DWORD *self@<ecx>);
         *
         * What it does:
         * Returns the mapped value for `key`, default-constructing and inserting
         * the element first when the key is absent. The binary's `+ 12` on the
         * return value is the `pair::second` offset inside the list node.
         */
        [[nodiscard]] mapped_type& operator[](const key_type& key)
        {
            const iterator found = find(key);
            if (found != mList.end()) {
                return found->second;
            }
            return insert(value_type(key, mapped_type())).first->second;
        }

    private:
        void _Init()
        {
            mVec.clear();
            mVec.resize(Traits::min_buckets + 1, mList.end());
        }

        /**
         * Maps one key onto a live bucket index.
         *
         * `mMask + 1` is the *address space*, but only `mMaxidx` buckets exist
         * yet; addresses beyond that fold back onto the not-yet-split half of
         * the table. This is what makes the split in `_Grow` incremental.
         */
        [[nodiscard]] size_type _Buckno(const key_type& key) const
        {
            const size_type bucket = mTraits(key) & mMask;
            return (mMaxidx <= bucket) ? bucket - (mMask >> 1) - 1 : bucket;
        }

        /**
         * After a node is linked in front of `displaced`, every bucket boundary
         * that still names `displaced` as its start must be retargeted to the
         * newly-linked node. Empty buckets share boundaries, so the walk
         * continues downward for as long as the entries keep matching.
         */
        void _RetargetBucketStarts(size_type bucket, iterator displaced, iterator replacement)
        {
            if (mVec[bucket] != displaced) {
                return;
            }
            for (;;) {
                mVec[bucket] = replacement;
                if (bucket == 0) {
                    return;
                }
                --bucket;
                if (mVec[bucket] != displaced) {
                    return;
                }
            }
        }

        /**
         * Address: 0x007692F0 (FUN_007692F0, first half)
         *
         * What it does:
         * Publishes one additional bucket. The bucket whose address space is
         * being split is rescanned, and every node that no longer hashes to it
         * is spliced to the list tail where the new bucket window is forming.
         * The bucket array is doubled only when the address space runs out.
         */
        void _Grow()
        {
            const size_type windowCount = mVec.size();
            if (windowCount - 1 > mMaxidx) {
                if (mMask < mMaxidx) {
                    mMask = 2 * mMask + 1;
                }
            } else {
                mMask = 2 * windowCount - 3;
                mVec.resize(2 * windowCount - 1, mList.end());
            }

            const size_type splitBucket = mMaxidx - (mMask >> 1) - 1;
            iterator scan = mVec[splitBucket];

            while (mVec[splitBucket + 1] != scan) {
                if ((mTraits(scan->first) & mMask) == splitBucket) {
                    ++scan;
                    continue;
                }

                iterator next = scan;
                ++next;

                if (next != mList.end()) {
                    _RetargetBucketStarts(splitBucket, scan, next);
                    mList.splice(mList.end(), mList, scan, next);
                    mVec[mMaxidx + 1] = mList.end();
                    scan = mList.end();
                    --scan;
                }

                // The freshly-migrated node becomes the start of every trailing
                // empty bucket window down to the one being split.
                for (size_type index = mMaxidx; index > splitBucket; --index) {
                    if (mVec[index] != mList.end()) {
                        break;
                    }
                    mVec[index] = scan;
                }

                if (next == mList.end()) {
                    break;
                }
                scan = next;
            }

            ++mMaxidx;
        }
    };
} // namespace msvc8
