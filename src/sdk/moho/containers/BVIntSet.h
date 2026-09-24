#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>

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
   * Address: 0x006D3080 (FUN_006D3080 -- the `==` half of the same pair,
   *   `mov ecx,[eax+4] / cmp ecx,[edx+4] / sete al`, reading `mValue` off both
   *   operands exactly as this does with `setne`. Zero callers, unreachable --
   *   every comparison site inlined it and the COMDAT survived; formerly
   *   `BVIntSetIndexValueEqual` over a hand-written view in
   *   moho/containers/BVIntSet.cpp (RULE ONE), removed 2026-09-22.)
   *
   * What it does:
   * Compares two BVIntSet index values by the value lane. The owner lane takes
   * no part: two indices into different sets compare equal when their values
   * match, which is what makes `it != end` terminate a walk whose `end` was
   * built by `EndIndex()` on the same set.
   *
   * Emissions of the same index walk carried by a **0x0C** record rather than
   * by `BVIntSetIndex` alone -- the pair sits at `+0x04`, so the set pointer
   * lands at `+0x04` and the value at `+0x08`, with one further lane ahead of
   * it at `+0x00`:
   *
   * Address: 0x00534940 (FUN_00534940 -- `operator++`:
   *   `mov eax,[esi+8] / mov edi,[esi+4] / call BVIntSet::GetNext /
   *   mov [esi+8],eax / mov eax,esi`, i.e. `mValue = mOwnerSet->GetNext(mValue)`
   *   returning the cursor. Formerly `AdvanceBVIntSetCursorRuntimeView`.)
   * Address: 0x006E7A40 (FUN_006E7A40 -- the same body emitted in a second
   *   translation unit; not an ICF twin of the above only because the `call`
   *   displacement differs. Formerly `AdvanceBVIntSetCursorRuntimeViewSecondary`,
   *   which had been written as a forwarder to the first.)
   * Address: 0x00534970 (FUN_00534970 -- `operator!=` on that record's value
   *   lane, `cmp ecx,[edx+8] / setne al`. Its ICF twin FUN_006E7A70 was
   *   disposed `skip` on 2026-09-10 for the same reason these carry here.
   *   Formerly `BVIntSetCursorValueNotEqualDispatch`.)
   * Address: 0x00534960 (FUN_00534960 -- resolves the value through the lane
   *   at `+0x00`, which is a pointer to a polymorphic object:
   *   `mov ecx,[eax] / mov eax,[ecx] / push [eax+8] / call [eax+0x14]`, a
   *   `__thiscall` through vtable slot 5 taking the value. Formerly
   *   `AdvanceCursorValueViaDispatch`, over a fabricated five-slot interface
   *   invented to give that call a shape.)
   *
   * All four are zero-caller and unreachable from every seeded root; each use
   * site inlined the operator and the linker kept the out-of-line COMDAT. They
   * are recorded here rather than modelled because the owning record is not
   * pinned: the `+0x00` lane's class could not be identified from the binary in
   * this pass, and inventing a type for it is what the removed code did.
   * Whatever it is, the walk itself is this file's `{BVIntSet*, value}` pair,
   * and `BeginIndex`/`EndIndex`/`GetNext` below are the operations it performs.
   */
  [[nodiscard]] bool BVIntSetIndexValueNotEqual(const BVIntSetIndex& lhs, const BVIntSetIndex& rhs) noexcept;

  /**
   * Half-open range of absolute word indices, as returned by
   * `BVIntSet::WordRange()`.
   */
  struct BVIntSetWordRange
  {
    unsigned int mStartWord;
    unsigned int mEndWord;
  };

  struct BVIntSet
  {
    static gpg::RType* sType;

    // Word index (32 values per word) of the first represented block.
    unsigned int mFirstWordIndex{0};
    // Legacy metadata dword retained for ABI compatibility.
    unsigned int mReservedMetaWord{0};
    // Packed presence bits in contiguous 32-value words.
    gpg::core::FastVectorN<unsigned int, 2> mWords{};

    /**
     * Address: 0x00401080 (FUN_00401080)
     *
     * What it does:
     * Empty set: first word 0, word storage bound to its two-word inline
     * window. Formerly `moho::Set::Set` in gpg/core/containers/Set.h, a second
     * layout of this type, removed 2026-09-24.
     */
    BVIntSet() = default;

    /**
     * Address: 0x00401E10 (FUN_00401E10)
     *
     * What it does:
     * Copies the first-word index (+0x00) and the word storage (0x00402220);
     * +0x04 is not copied. Formerly `moho::Set::Set(const Set&)`.
     */
    BVIntSet(const BVIntSet& set);
    BVIntSet& operator=(const BVIntSet& set);

    /**
     * Words currently allocated for the window. Was `Buckets()`: nothing here
     * hashes, and every other name in this file already says "word".
     */
    [[nodiscard]] size_t WordCount() const;

    /**
     * Window-relative index of the word holding `val`,
     * `(val >> 5) - mFirstWordIndex`. The caller must have established
     * containment (`EnsureBounds`) first -- the subtraction underflows for a
     * value below the window. Was `BucketFor()`.
     */
    [[nodiscard]] size_t WordIndexFor(size_t val) const;

    /**
     * First value representable by window-relative word `wordIndex`,
     * `(mFirstWordIndex + wordIndex) << 5`. Was `FromBucket()`.
     */
    [[nodiscard]] size_t FirstValueInWord(size_t wordIndex) const;

    /**
     * The window as a half-open range of absolute word indices,
     * `[mFirstWordIndex, mFirstWordIndex + WordCount())`. Set algebra needs
     * both operands' windows to find their overlap.
     *
     * Was a free `GetWordRange(const BVIntSet&)` in BVIntSet.cpp's anonymous
     * namespace, called nine times -- five of them from members passing
     * `*this`.
     */
    [[nodiscard]] BVIntSetWordRange WordRange() const noexcept;

    /**
     * First value the **window** can represent, `mFirstWordIndex << 5` -- not
     * the smallest member. A set whose only element is 70 still reports 0 here
     * when its window starts at word 0. `GetNext` uses it as a floor.
     *
     * The name says "minimum element" and means "window floor"; renaming it
     * `WindowBegin()` is deferred only because `Max()` below has ~15 call
     * sites across eight files and the pair should move together.
     */
    [[nodiscard]] unsigned int Min() const;

    /**
     * One past the last value the **window** can represent,
     * `(mFirstWordIndex + WordCount()) << 5` -- the end sentinel `GetNext`
     * returns when no further member exists, not the largest member. Every
     * caller in the tree already binds it to a local named `sentinel`, `end`,
     * `endOfSet` or `endOrdinalExclusive`, which is what it is; `WindowEnd()`
     * would say so directly.
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
     * Address: 0x006D3090 (FUN_006D3090, Moho::BVIntSet::Get)
     *
     * What it does:
     * Returns `{this, val}` when the bit exists; otherwise returns `{this, Max()}`.
     */
    [[nodiscard]] BVIntSetIndex Get(unsigned int val) const;

    /**
     * Address: 0x004017B0 (FUN_004017B0)
     * Address: 0x100014C0
     *
     * Find the next present value strictly greater than 'val', or Max() if none.
     */
    [[nodiscard]] unsigned int GetNext(unsigned int val) const;

    /**
     * Invokes `fn(value)` for every value present in the set, in ascending
     * order.
     *
     * This is the canonical walk the binary open-codes at each iteration site
     * as `GetNext(0xFFFFFFFF)` followed by `GetNext(value)` until `Max()` is
     * reached (e.g. `Sim::AdvanceBeat` at 0x0074A261).
     */
    template <class F>
    void ForEachValue(F&& fn) const
    {
      const unsigned int sentinel = Max();
      for (unsigned int value = GetNext(std::numeric_limits<unsigned int>::max()); value != sentinel;
           value = GetNext(value)) {
        fn(value);
      }
    }

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
     * Returns true when start index and wordIndex payload match exactly.
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
  // Four-aligned, and pinned there: `SoundHandleIdPool` is
  // `{BVIntSet mFreeIds; std::uint32_t mNextId;}` at 0x24 (CUserSoundManager.h),
  // which only closes if this record does not round the struct up to eight.
  static_assert(alignof(BVIntSet) == 4, "BVIntSet must be 4-aligned");

  /**
   * Address: 0x00401CA0 (FUN_00401CA0)
   * Address: 0x006D3220 (FUN_006D3220)
   *
   * What it does:
   * Returns whether two sets differ.
   */
  [[nodiscard]] bool operator!=(const BVIntSet& lhs, const BVIntSet& rhs) noexcept;
} // namespace moho
