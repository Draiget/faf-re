#include "BVIntSet.h"
using namespace moho;

BVIntSet::BVIntSet(const BVIntSet& set) {
    mStart = set.mStart;
    mUsed.ResetFrom(set.mUsed);
}

/**
 * Address: 0x004010E0
 *
 * Union [lower, upper) from 'from' into this set.
 */
void BVIntSet::AddFrom(BVIntSet* from, const unsigned int lower, const unsigned int upper)
{
    if (!from || from == this || lower >= upper) {
	    return;
    }

    EnsureBounds(lower, upper);

    // Compute bucket mapping between 'from' and 'this'
    const int offset = static_cast<int>(from->mStart) - static_cast<int>(mStart);
    const size_t b = BucketFor(lower);
    const size_t e = BucketFor(upper);
    const unsigned beginBit = (lower & 31u);
    const unsigned endBit = (upper & 31u);

    if (b == e) {
        // Single bucket: OR only bits [beginBit, endBit)
        const unsigned int m = mask_range(beginBit, endBit);
        if (m) {
            mUsed[b] |= (from->mUsed[b - offset] & m);
        }
        return;
    }

    // First bucket: [beginBit, 32)
    mUsed[b] |= (from->mUsed[b - offset] & mask_range(beginBit, 32));

    // Middle buckets: whole 32 bits
    for (size_t k = b + 1; k < e; ++k) {
        mUsed[k] |= from->mUsed[k - offset];
    }

    // Last bucket: [0, endBit)
    if (endBit != 0) {
        mUsed[e] |= (from->mUsed[e - offset] & mask_range(0, endBit));
    }
}

/**
 * Address: 0x00401670
 *
 * Clear [lower.mVal, upper.mVal); shrink; return {this, min(upper, Max())}.
 */
BVIntSetIndex BVIntSet::ClearRange(const BVIntSetIndex lower, const BVIntSetIndex upper)
{
    if (mUsed.Empty()) {
        return BVIntSetIndex{ this, Max() };
    }

    // Clamp to our representable span [Min, Max)
    const unsigned int lo = std::max(lower.mVal, Min());
    const unsigned int hi = std::min(upper.mVal, Max());
    if (lo < hi) {
        const size_t b0 = BucketFor(lo);
        const size_t b1 = BucketFor(hi);
        const unsigned loBit = (lo & 31u);
        const unsigned hiBit = (hi & 31u);

        if (b0 == b1) {
            // Clear [loBit, hiBit) in a single bucket
            const unsigned int keep = ~mask_range(loBit, hiBit);
            mUsed[b0] &= keep;
        } else {
            // First bucket: keep [0, loBit)
            mUsed[b0] &= mask_range(0, loBit);

            // Middle buckets: zero out completely
            for (size_t k = b0 + 1; k < b1; ++k) {
                mUsed[k] = 0u;
            }

            // Last bucket: keep [hiBit, 32)
            if (hiBit != 0) {
                mUsed[b1] &= ~mask_range(0, hiBit);
            }
            // else hiBit==0: [.., boundary) - end bucket untouched
        }
        Finalize();
    }

    const unsigned int retVal = std::min(upper.mVal, Max());
    return BVIntSetIndex{ this, retVal };
}

/**
 * Address: 0x004017B0
 *
 * Return next present value strictly greater than 'val', or Max() if none.
 */
unsigned int BVIntSet::GetNext(const unsigned int val) const
{
    if (mUsed.Empty()) {
	    return Max();
    }

    // Start strictly after 'val', but not before Min()
    unsigned int cur = std::max(val + 1u, Min());
    if (cur >= Max()) {
	    return Max();
    }

    size_t b = BucketFor(cur);
    if (b >= Buckets()) {
	    return Max();
    }

    unsigned int bits = mUsed[b] >> (cur & 31u);

    // Scan in current bucket
    while (bits == 0u) {
        // Advance to the next bucket
        if (++b >= Buckets()) {
	        return Max();
        }
        bits = mUsed[b];
        cur = FromBucket(b);
    }

    // Find first set bit
    while ((bits & 1u) == 0u) {
        bits >>= 1u;
        ++cur;
    }
    return cur;
}

/**
 * Address: 0x004018A0
 *
 * Trim leading/trailing zero buckets; normalize empty state.
 */
void BVIntSet::Finalize()
{
    const size_t n = Buckets();
    if (n == 0) {
	    return;
    }

    size_t lo = 0;
    size_t hi = n;

    while (lo < hi && mUsed[lo] == 0u) ++lo;
    if (lo == hi) {
        // All zero - reset to empty state
        mUsed.Clear();
        mStart = 0;
        return;
    }
    while (hi > lo && mUsed[hi - 1] == 0u) {
        --hi;
    }

    if (lo == 0 && hi == n) {
        // nothing to trim
	    return;
    }

    // Compact [lo, hi) to the front
    const size_t cnt = hi - lo;
    if (cnt > 0) {
        if (lo != 0) {
            std::memmove(mUsed.begin(), &mUsed[lo], cnt * sizeof(unsigned int));
        }

        constexpr unsigned int fill = 0u;
        mUsed.Resize(cnt, fill);
        mStart += lo;
    }
}

/**
 * Address: 0x00401980
 *
 * Ensure storage covers [lower, upper) values (no-op if lower>=upper).
 */
void BVIntSet::EnsureBounds(const unsigned int lower, const unsigned int upper)
{
    if (lower >= upper) {
	    return;
    }

    constexpr unsigned int fill = 0u;

    const unsigned int reqStart = (lower >> 5);
    const unsigned int reqEnd = ((upper + 31u) >> 5); // exclusive

    if (mUsed.Empty()) {
        if (reqStart < reqEnd) {
            mStart = reqStart;
            mUsed.Resize(reqEnd - reqStart, fill);
        }
        return;
    }

    const size_t oldSize = Buckets();
    const unsigned int curStart = mStart;
    const unsigned int curEnd = curStart + static_cast<unsigned int>(oldSize);

    const int prepend = (reqStart < curStart) ? static_cast<int>(curStart - reqStart) : 0;
    const int append = (reqEnd > curEnd) ? static_cast<int>(reqEnd - curEnd) : 0;

    if (prepend == 0 && append == 0) {
	    return;
    }

    // Grow vector to new size: [prepend] + old + [append]
    const size_t newSize = static_cast<size_t>(prepend + append) + oldSize;
    mUsed.Resize(newSize, fill);

    if (prepend > 0) {
        // Shift old data right by 'prepend' buckets
        const size_t moveCnt = oldSize;
        if (moveCnt > 0) {
            std::memmove(&mUsed[prepend], mUsed.begin(), moveCnt * sizeof(unsigned int));
        }
        // Zero-fill the new leading area (already zeroed by Resize with 'fill', but keep explicit)
        for (size_t i = 0; i < static_cast<size_t>(prepend); ++i) {
	        mUsed[i] = 0u;
        }

        mStart = reqStart;
    }
    // If only append > 0, Resize already appended zeros and mStart is unchanged.
}

/**
 * Address: 0x00401A60
 *
 * Union with entire content of 'from'.
 */
void BVIntSet::AddAllFrom(BVIntSet* from)
{
    if (!from) {
	    return;
    }

    // wraps to Min()
    const unsigned int lo = from->GetNext(std::numeric_limits<unsigned int>::max()); 
    const unsigned int hi = from->Max();
    if (lo < hi) {
        AddFrom(from, lo, hi);
    }
}

/**
 * Address: 0x004036A0
 *
 * Insert a single value; report if newly added.
 */
BVIntSetAddResult BVIntSet::Add(const unsigned int val)
{
    EnsureBounds(val, val + 1u);
    const size_t b = BucketFor(val);
    const unsigned shift = (val & 31u);
    const unsigned int bit = (1u << shift);
    const unsigned int prev = mUsed[b];
    const bool isNew = (prev & bit) == 0u;
    mUsed[b] = prev | bit;
    return BVIntSetAddResult{{this, val}, isNew };
}
