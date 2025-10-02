#pragma once
#include "gpg/core/containers/FastVector.h"
#include "platform/Platform.h"

namespace moho
{
    struct BVIntSet;

    struct BVIntSetIndex
	{
        BVIntSet* mSet;
        unsigned int mVal;
    };

    struct BVIntSetAddResult : BVIntSetIndex
	{
        bool mIsNew;
    };

    struct BVIntSet
    {
        // bucket index of the first 32-values block
        unsigned int mStart;
        // reserved/unknown, keep for layout compatibility
        unsigned int unk;
        // buckets of 32 flags each
        gpg::core::FastVectorN<unsigned int, 2> mUsed{};

        BVIntSet() : mStart(0), unk(0) {}

        /**
         * NOTE: Inlined
         *
         * @param set 
         */
        BVIntSet(const BVIntSet& set);

        /**
         * Number of buckets currently allocated.
         */
        [[nodiscard]] size_t Buckets() const {
	        return mUsed.Size();
        }

        /**
         * Compute bucket index for the given value. Requires EnsureBounds/containment.
         */
        [[nodiscard]] size_t BucketFor(const size_t val) const {
	        return (val >> 5) - mStart;
        }

        /**
         * Convert bucket index to the minimal value in that bucket.
         */
        [[nodiscard]] size_t FromBucket(const size_t bucket) const {
	        return (mStart + bucket) << 5;
        }

        /**
         * Minimal representable value in current storage (inclusive).
         */
        [[nodiscard]] unsigned int Min() const {
	        return FromBucket(0);
        }

        /**
         * Max sentinel (exclusive upper bound); returned when search fails.
         */
        [[nodiscard]] unsigned int Max() const {
	        return FromBucket(Buckets());
        }

        /**
         * Address: 0x004010E0
         *
         * Add values from [lower, upper) from another set into this set. 
         */
        void AddFrom(BVIntSet* from, unsigned int lower, unsigned int upper);

        /**
         * Address: 0x00401670
         *
         * Clear values in [lower.mVal, upper.mVal) and shrink storage. Returns clamped 'upper'.
         */
        BVIntSetIndex ClearRange(BVIntSetIndex lower, BVIntSetIndex upper);

        /**
         * Address: 0x004017B0
         *
         * Find the next present value strictly greater than 'val', or Max() if none.
         */
        [[nodiscard]] unsigned int GetNext(unsigned int val) const;

        /**
         * Address: 0x004018A0
         *
         * Trim leading/trailing zero buckets; possibly empty the set.
         */
        void Finalize();

        /**
         * Address: 0x00401980
         *
         * Ensure storage covers [lower, upper) values; expand left/right as needed. 
         */
        void EnsureBounds(unsigned int lower, unsigned int upper);

        /**
         * Address: 0x00401A60
         *
         * Union with all values from 'from'.
         */
        void AddAllFrom(BVIntSet* from);

        /**
         * Address: 0x004036A0
         *
         * Add single value; returns whether it was newly inserted. 
         */
        BVIntSetAddResult Add(unsigned int val);

    private:
        /**
         * Mask bits in range [loBit, hiBit), both in 0..32.
         */
        MOHO_FORCEINLINE static unsigned int mask_range(const unsigned loBit, const unsigned hiBit) noexcept {
            // handle hiBit==32 without UB
            const unsigned int hi = (hiBit >= 32) ? 0xFFFFFFFFu : ((1u << hiBit) - 1u);
            const unsigned int lo = (loBit == 0) ? 0u : ((1u << loBit) - 1u);
            return hi & ~lo;
        }
    };
    static_assert(sizeof(BVIntSet) == 0x20, "BVIntSet size must be 0x20");
}
