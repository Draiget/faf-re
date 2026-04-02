#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "platform/Platform.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  static_assert(
    sizeof(gpg::core::FastVectorN<unsigned int, 2>) == 0x18,
    "FastVectorN<unsigned int,2> size must be 0x18 for BVIntSet ABI"
  );

  struct BVIntSet;

  struct BVIntSetIndex
  {
    BVIntSet* mOwnerSet; // +0x00
    unsigned int mValue; // +0x04
  };
  static_assert(sizeof(BVIntSetIndex) == 0x8, "BVIntSetIndex size must be 0x8");

  struct BVIntSetAddResult : BVIntSetIndex
  {
    bool mWasInserted;             // +0x08
    std::uint8_t mReserved09[3]{}; // +0x09 (ABI tail bytes; no standalone semantic use observed)
  };
  static_assert(offsetof(BVIntSetAddResult, mWasInserted) == 0x8, "BVIntSetAddResult::mWasInserted offset must be 0x8");
  static_assert(sizeof(BVIntSetAddResult) == 0xC, "BVIntSetAddResult size must be 0xC");

  /**
   * Address: 0x00401050 (FUN_00401050)
   * Address: 0x00401070 (FUN_00401070)
   *
   * What it does:
   * Packs `{owner, value}` into a BVIntSet index pair.
   */
  [[nodiscard]] BVIntSetIndex MakeBVIntSetIndex(BVIntSet* owner, unsigned int value) noexcept;

  /**
   * Address: 0x00401060 (FUN_00401060)
   *
   * What it does:
   * Compares two BVIntSet index values by the value lane.
   */
  [[nodiscard]] bool BVIntSetIndexValueNotEqual(const BVIntSetIndex& lhs, const BVIntSetIndex& rhs) noexcept;

  struct BVIntSet
  {
    static gpg::RType* sType;

    // Word index (32 values per word) of the first represented block.
    unsigned int mFirstWordIndex{0};
    // Legacy metadata dword retained for ABI compatibility.
    unsigned int mReservedMetaWord{0};
    // Packed presence bits in contiguous 32-value words.
    gpg::core::FastVectorN<unsigned int, 2> mWords{};

    BVIntSet() = default;

    /**
     * Copy-constructs the set storage from another BVIntSet.
     */
    BVIntSet(const BVIntSet& set);
    BVIntSet& operator=(const BVIntSet& set);

    /**
     * Number of buckets currently allocated.
     */
    [[nodiscard]] size_t Buckets() const;

    /**
     * Compute bucket index for the given value. Requires EnsureBounds/containment.
     */
    [[nodiscard]] size_t BucketFor(size_t val) const;

    /**
     * Convert bucket index to the minimal value in that bucket.
     */
    [[nodiscard]] size_t FromBucket(size_t bucket) const;

    /**
     * Minimal representable value in current storage (inclusive).
     */
    [[nodiscard]] unsigned int Min() const;

    /**
     * Max sentinel (exclusive upper bound); returned when search fails.
     */
    [[nodiscard]] unsigned int Max() const;

    /**
     * Address: 0x004010A0 (FUN_004010A0)
     *
     * What it does:
     * Returns the first valid iterator/index pair for this set.
     */
    [[nodiscard]] BVIntSetIndex BeginIndex();

    /**
     * Address: 0x004010C0 (FUN_004010C0)
     *
     * What it does:
     * Returns the past-end iterator/index pair for this set.
     */
    [[nodiscard]] BVIntSetIndex EndIndex();

    /**
     * Address: 0x004010E0 (FUN_004010E0)
     * Address: 0x100010A0
     *
     * Add values from [lower, upper) from another set into this set.
     */
    void AddFrom(const BVIntSet* from, unsigned int lower, unsigned int upper);

    /**
     * Address: 0x00401670 (FUN_00401670)
     * Address: 0x10001380
     *
     * Clear values in [lower.mValue, upper.mValue) and shrink storage. Returns clamped 'upper'.
     */
    BVIntSetIndex ClearRange(BVIntSetIndex lower, BVIntSetIndex upper);

    /**
     * Address: 0x00401730 (FUN_00401730)
     * Address: 0x10001440
     *
     * What it does:
     * Counts total set bits across all buckets.
     */
    [[nodiscard]] unsigned int Count() const;

    /**
     * Address: 0x004035F0 (FUN_004035F0, Moho::BVIntSet::Contains)
     *
     * What it does:
     * Returns whether `val` bit is present in this set.
     */
    [[nodiscard]] bool Contains(unsigned int val) const;

    /**
     * Address: 0x004017B0 (FUN_004017B0)
     * Address: 0x100014C0
     *
     * Find the next present value strictly greater than 'val', or Max() if none.
     */
    [[nodiscard]] unsigned int GetNext(unsigned int val) const;

    /**
     * Address: 0x00401830 (FUN_00401830)
     *
     * What it does:
     * Finds the previous present value strictly below `val`.
     */
    [[nodiscard]] unsigned int GetPrev(unsigned int val) const;

    /**
     * Address: 0x004018A0 (FUN_004018A0)
     * Address: 0x100015B0
     *
     * Trim leading/trailing zero buckets; possibly empty the set.
     */
    void Finalize();

    /**
     * Address: 0x00401980 (FUN_00401980)
     * Address: 0x10001690
     *
     * Ensure storage covers [lower, upper) values; expand left/right as needed.
     */
    void EnsureBounds(unsigned int lower, unsigned int upper);

    /**
     * Address: 0x00401A60 (FUN_00401A60)
     *
     * Union with all values from 'from'.
     */
    void AddAllFrom(const BVIntSet* from);

    /**
     * Address: 0x00401A90 (FUN_00401A90)
     * Address: 0x100017A0
     *
     * What it does:
     * Clears all bits present in `from` (`this &= ~from`) and compacts storage.
     */
    void RemoveAllFrom(const BVIntSet* from);

    /**
     * Address: 0x00401AF0 (FUN_00401AF0)
     *
     * What it does:
     * Intersects with `other` (`this &= other`) and compacts to non-zero overlap.
     */
    void IntersectWith(const BVIntSet* other);

    /**
     * Address: 0x00401C50 (FUN_00401C50)
     *
     * What it does:
     * Returns true when start index and bucket payload match exactly.
     */
    [[nodiscard]] bool Equals(const BVIntSet* other) const;

    /**
     * Address: 0x00401CB0 (FUN_00401CB0)
     *
     * What it does:
     * Computes the union of `*this` and `rhs` into `out`.
     */
    [[nodiscard]] BVIntSet* Union(BVIntSet* out, const BVIntSet* rhs) const;

    /**
     * Address: 0x00401E30 (FUN_00401E30)
     *
     * What it does:
     * Computes the symmetric difference of `*this` and `rhs` into `out`.
     */
    [[nodiscard]] BVIntSet* ExclusiveOr(BVIntSet* out, const BVIntSet* rhs) const;

    /**
     * Address: 0x00401F60 (FUN_00401F60)
     *
     * What it does:
     * Computes the intersection of `*this` and `rhs` into `out`, trimming empty edge buckets.
     */
    [[nodiscard]] BVIntSet* Intersect(BVIntSet* out, const BVIntSet* rhs) const;

    /**
     * Address: 0x00402110 (FUN_00402110)
     *
     * What it does:
     * Computes `*this & ~rhs` into `out` and finalizes the result.
     */
    [[nodiscard]] BVIntSet* Subtract(BVIntSet* out, const BVIntSet* rhs) const;

    /**
     * Address: 0x004036A0 (FUN_004036A0)
     *
     * Add single value; returns whether it was newly inserted.
     */
    BVIntSetAddResult Add(unsigned int val);

    /**
     * Address: 0x00403650 (FUN_00403650, sub_403650)
     *
     * Remove single value; returns true iff bit was previously set.
     */
    [[nodiscard]] bool Remove(unsigned int val);

    /**
     * Address: 0x004032A0 (FUN_004032A0, Moho::BVIntSet::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall Moho::BVIntSet::MemberDeserialize(Moho::BVIntSet *a1@<eax>, gpg::ReadArchive *a3@<esi>);
     *
     * What it does:
     * Reads the base word index and packed word vector payload from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004032F0 (FUN_004032F0, Moho::BVIntSet::MemberSerialize)
     *
     * IDA signature:
     * void __usercall Moho::BVIntSet::MemberSerialize(Moho::BVIntSet *a1@<eax>, BinaryWriteArchive *a2@<esi>);
     *
     * What it does:
     * Writes the base word index and packed word vector payload to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  private:
    /**
     * Mask bits in range [loBit, hiBit), both in 0..32.
     */
    [[nodiscard]] static unsigned int MaskRange(unsigned loBit, unsigned hiBit) noexcept;
  };
  static_assert(offsetof(BVIntSet, mFirstWordIndex) == 0x00, "BVIntSet::mFirstWordIndex offset must be 0x00");
  static_assert(offsetof(BVIntSet, mReservedMetaWord) == 0x04, "BVIntSet::mReservedMetaWord offset must be 0x04");
  static_assert(offsetof(BVIntSet, mWords) == 0x08, "BVIntSet::mWords offset must be 0x08");
  static_assert(sizeof(BVIntSet) == 0x20, "BVIntSet size must be 0x20");

  /**
   * Address: 0x00401CA0 (FUN_00401CA0)
   *
   * What it does:
   * Returns whether two sets differ.
   */
  [[nodiscard]] bool operator!=(const BVIntSet& lhs, const BVIntSet& rhs) noexcept;
} // namespace moho
