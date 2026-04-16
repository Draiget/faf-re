#include "BVIntSet.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include "gpg/core/containers/FastVectorUIntReflection.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

using namespace moho;

namespace
{
  constexpr unsigned int kBitsPerWord = 32u;
  constexpr unsigned int kWordShift = 5u;
  constexpr unsigned int kWordBitMask = kBitsPerWord - 1u;

  struct BVIntSetWordRange
  {
    unsigned int mStartWord;
    unsigned int mEndWord;
  };

  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] BVIntSetWordRange GetWordRange(const BVIntSet& set) noexcept
  {
    return {set.mFirstWordIndex, set.mFirstWordIndex + static_cast<unsigned int>(set.Buckets())};
  }

  struct BVIntSetCursorRuntimeView
  {
    std::uint32_t lane00; // +0x00
    BVIntSet* set;        // +0x04
    unsigned int value;   // +0x08
  };
  static_assert(offsetof(BVIntSetCursorRuntimeView, set) == 0x04, "BVIntSetCursorRuntimeView::set offset must be 0x04");
  static_assert(
    offsetof(BVIntSetCursorRuntimeView, value) == 0x08,
    "BVIntSetCursorRuntimeView::value offset must be 0x08"
  );
  static_assert(sizeof(BVIntSetCursorRuntimeView) == 0x0C, "BVIntSetCursorRuntimeView size must be 0x0C");

  struct BVIntSetEmbeddedOwnerRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    BVIntSet set;         // +0x08
  };
  static_assert(
    offsetof(BVIntSetEmbeddedOwnerRuntimeView, set) == 0x08,
    "BVIntSetEmbeddedOwnerRuntimeView::set offset must be 0x08"
  );

  /**
   * Address: 0x006D1940 (FUN_006D1940)
   *
   * What it does:
   * Removes all bits from one embedded `BVIntSet` lane using another owner's
   * embedded set, then returns the source owner lane.
   */
  [[maybe_unused]] [[nodiscard]] BVIntSetEmbeddedOwnerRuntimeView* RemoveAllFromEmbeddedBVIntSetAdapter(
    BVIntSetEmbeddedOwnerRuntimeView* const destinationOwner,
    BVIntSetEmbeddedOwnerRuntimeView* const sourceOwner
  )
  {
    destinationOwner->set.RemoveAllFrom(&sourceOwner->set);
    return sourceOwner;
  }

  /**
   * Address: 0x00534940 (FUN_00534940)
   *
   * What it does:
   * Advances one `{set,value}` cursor by replacing `value` with
   * `set->GetNext(value)` and returns the same cursor object.
   */
  [[maybe_unused]] BVIntSetCursorRuntimeView* AdvanceBVIntSetCursorRuntimeView(
    BVIntSetCursorRuntimeView* const cursor
  ) noexcept
  {
    cursor->value = cursor->set->GetNext(cursor->value);
    return cursor;
  }

  class BVIntSetCursorDispatchRuntimeInterface
  {
  public:
    virtual void Slot00() = 0;
    virtual void Slot04() = 0;
    virtual void Slot08() = 0;
    virtual void Slot0C() = 0;
    virtual unsigned int DispatchValue(unsigned int value) = 0;
  };

  struct BVIntSetCursorDispatchRuntimeView
  {
    BVIntSetCursorDispatchRuntimeInterface* owner = nullptr; // +0x00
    std::uint32_t lane04 = 0u;                               // +0x04
    unsigned int value = 0u;                                 // +0x08
  };
  static_assert(
    offsetof(BVIntSetCursorDispatchRuntimeView, value) == 0x08,
    "BVIntSetCursorDispatchRuntimeView::value offset must be 0x08"
  );

  /**
   * Address: 0x00534960 (FUN_00534960)
   *
   * What it does:
   * Dispatches one cursor-value update through owner virtual slot `+0x14`,
   * passing the embedded value lane.
   */
  [[maybe_unused]] [[nodiscard]] unsigned int AdvanceCursorValueViaDispatch(
    const BVIntSetCursorDispatchRuntimeView* const cursor
  ) noexcept
  {
    return cursor->owner->DispatchValue(cursor->value);
  }

  /**
   * Address: 0x00534970 (FUN_00534970)
   *
   * What it does:
   * Returns whether two cursor dispatch payloads differ in their value lane.
   */
  [[maybe_unused]] [[nodiscard]] bool BVIntSetCursorValueNotEqualDispatch(
    const BVIntSetCursorDispatchRuntimeView& lhs,
    const BVIntSetCursorDispatchRuntimeView& rhs
  ) noexcept
  {
    return lhs.value != rhs.value;
  }

  /**
   * Address: 0x006D3080 (FUN_006D3080)
   *
   * What it does:
   * Returns true when two `{owner, value}` index lanes carry the same value.
   */
  [[maybe_unused]] [[nodiscard]] bool BVIntSetIndexValueEqual(const BVIntSetIndex& lhs, const BVIntSetIndex& rhs) noexcept
  {
    return lhs.mValue == rhs.mValue;
  }

  /**
   * Address: 0x006E7A30 (FUN_006E7A30)
   *
   * What it does:
   * Returns the bit-count for one BVIntSet embedded at offset `+0x08` in an
   * owning runtime view.
   */
  [[maybe_unused]] unsigned int CountEmbeddedBVIntSetLane(
    BVIntSetEmbeddedOwnerRuntimeView* const owner
  ) noexcept
  {
    return owner->set.Count();
  }

  /**
   * Address: 0x006E7A40 (FUN_006E7A40)
   *
   * What it does:
   * Secondary cursor-advance adapter that forwards to
   * `AdvanceBVIntSetCursorRuntimeView`.
   */
  [[maybe_unused]] BVIntSetCursorRuntimeView* AdvanceBVIntSetCursorRuntimeViewSecondary(
    BVIntSetCursorRuntimeView* const cursor
  ) noexcept
  {
    return AdvanceBVIntSetCursorRuntimeView(cursor);
  }

  template <typename WordOp>
  BVIntSet* CopyAndApplyOverlap(
    const BVIntSet& lhs,
    const BVIntSet& rhs,
    BVIntSet* const out,
    const unsigned int outStartWord,
    const unsigned int outWordCount,
    WordOp&& op
  )
  {
    const BVIntSetWordRange lhsRange = GetWordRange(lhs);
    const BVIntSetWordRange rhsRange = GetWordRange(rhs);

    out->mFirstWordIndex = outStartWord;
    out->mWords.ResetStorageToInline();
    out->mWords.Resize(outWordCount, 0u);

    if (lhsRange.mStartWord < lhsRange.mEndWord) {
      std::copy(
        lhs.mWords.start_, lhs.mWords.end_, out->mWords.start_ + (lhsRange.mStartWord - outStartWord)
      );
    }

    const unsigned int overlapStart = std::max(lhsRange.mStartWord, rhsRange.mStartWord);
    const unsigned int overlapEnd = std::min(lhsRange.mEndWord, rhsRange.mEndWord);
    for (unsigned int wordIndex = overlapStart; wordIndex < overlapEnd; ++wordIndex) {
      op(out->mWords[wordIndex - outStartWord], rhs.mWords[wordIndex - rhsRange.mStartWord]);
    }

    return out;
  }

  template <typename CombineFn>
  BVIntSet* BuildTrimmedOverlap(
    const BVIntSet& lhs, const BVIntSet& rhs, BVIntSet* const out, CombineFn&& combine
  )
  {
    const BVIntSetWordRange lhsRange = GetWordRange(lhs);
    const BVIntSetWordRange rhsRange = GetWordRange(rhs);
    const unsigned int overlapStart = std::max(lhsRange.mStartWord, rhsRange.mStartWord);
    unsigned int overlapEnd = std::min(lhsRange.mEndWord, rhsRange.mEndWord);

    out->mWords.ResetStorageToInline();
    if (overlapStart >= overlapEnd) {
      out->mFirstWordIndex = 0u;
      return out;
    }

    unsigned int firstNonZero = overlapStart;
    while (firstNonZero < overlapEnd) {
      if (combine(lhs.mWords[firstNonZero - lhsRange.mStartWord], rhs.mWords[firstNonZero - rhsRange.mStartWord]) != 0u) {
        break;
      }
      ++firstNonZero;
    }

    if (firstNonZero >= overlapEnd) {
      out->mFirstWordIndex = 0u;
      return out;
    }

    while (overlapEnd > firstNonZero) {
      const unsigned int wordIndex = overlapEnd - 1u;
      if (combine(lhs.mWords[wordIndex - lhsRange.mStartWord], rhs.mWords[wordIndex - rhsRange.mStartWord]) != 0u) {
        break;
      }
      --overlapEnd;
    }

    const unsigned int wordCount = overlapEnd - firstNonZero;
    out->mFirstWordIndex = firstNonZero;
    out->mWords.Resize(wordCount, 0u);
    for (unsigned int wordIndex = firstNonZero; wordIndex < overlapEnd; ++wordIndex) {
      out->mWords[wordIndex - firstNonZero] =
        combine(lhs.mWords[wordIndex - lhsRange.mStartWord], rhs.mWords[wordIndex - rhsRange.mStartWord]);
    }

    return out;
  }
} // namespace

gpg::RType* BVIntSet::sType = nullptr;

/**
 * Address: 0x00401050 (FUN_00401050)
 * Address: 0x00401070 (FUN_00401070)
 *
 * What it does:
 * Packs `{owner, value}` into a BVIntSet index pair.
 */
BVIntSetIndex moho::MakeBVIntSetIndex(BVIntSet* const owner, const unsigned int value) noexcept
{
  return BVIntSetIndex{owner, value};
}

/**
 * Address: 0x00401060 (FUN_00401060)
 *
 * What it does:
 * Compares BVIntSet index pairs by value lane only.
 */
bool moho::BVIntSetIndexValueNotEqual(const BVIntSetIndex& lhs, const BVIntSetIndex& rhs) noexcept
{
  return lhs.mValue != rhs.mValue;
}

BVIntSet::BVIntSet(const BVIntSet& set)
{
  mFirstWordIndex = set.mFirstWordIndex;
  mReservedMetaWord = set.mReservedMetaWord;
  mWords.ResetFrom(set.mWords);
}

BVIntSet& BVIntSet::operator=(const BVIntSet& set)
{
  if (this == &set) {
    return *this;
  }

  mFirstWordIndex = set.mFirstWordIndex;
  mReservedMetaWord = set.mReservedMetaWord;
  mWords.ResetFrom(set.mWords);
  return *this;
}

size_t BVIntSet::Buckets() const
{
  return mWords.Size();
}

size_t BVIntSet::BucketFor(const size_t val) const
{
  return (val >> kWordShift) - mFirstWordIndex;
}

size_t BVIntSet::FromBucket(const size_t bucket) const
{
  return (mFirstWordIndex + bucket) << kWordShift;
}

unsigned int BVIntSet::Min() const
{
  return static_cast<unsigned int>(FromBucket(0));
}

unsigned int BVIntSet::Max() const
{
  return static_cast<unsigned int>(FromBucket(Buckets()));
}

/**
 * Address: 0x004010A0 (FUN_004010A0)
 *
 * What it does:
 * Builds the begin iterator/index pair `{this, GetNext(UINT_MAX)}`.
 */
BVIntSetIndex BVIntSet::BeginIndex()
{
  return MakeBVIntSetIndex(this, GetNext(std::numeric_limits<unsigned int>::max()));
}

/**
 * Address: 0x004010C0 (FUN_004010C0)
 *
 * What it does:
 * Builds the end iterator/index pair `{this, 32 * (mFirstWordIndex + wordCount)}`.
 */
BVIntSetIndex BVIntSet::EndIndex()
{
  const unsigned int wordCount = static_cast<unsigned int>(mWords.end_ - mWords.start_);
  return MakeBVIntSetIndex(this, 32u * (mFirstWordIndex + wordCount));
}

/**
 * Address: 0x004010E0 (FUN_004010E0)
 * Address: 0x100010A0
 *
 * What it does:
 * ORs a half-open value range [lower, upper) from `from` into this set.
 */
void BVIntSet::AddFrom(const BVIntSet* from, const unsigned int lower, const unsigned int upper)
{
  if (from == nullptr || from == this || lower == upper) {
    return;
  }

  EnsureBounds(lower, upper);

  const int deltaStart = static_cast<int>(from->mFirstWordIndex) - static_cast<int>(mFirstWordIndex);
  const size_t firstBucket = BucketFor(lower);
  const size_t endBucket = BucketFor(upper);
  const unsigned int lowerBit = (lower & kWordBitMask);
  const unsigned int upperBit = (upper & kWordBitMask);
  const auto sourceBucketFor = [deltaStart](const size_t dstBucket) -> size_t {
    return static_cast<size_t>(static_cast<int>(dstBucket) - deltaStart);
  };

  if (firstBucket == endBucket) {
    const unsigned int mask = MaskRange(lowerBit, upperBit);
    if (mask != 0u) {
      mWords[firstBucket] |= (from->mWords[sourceBucketFor(firstBucket)] & mask);
    }
    return;
  }

  mWords[firstBucket] |= (from->mWords[sourceBucketFor(firstBucket)] & MaskRange(lowerBit, kBitsPerWord));
  for (size_t bucket = firstBucket + 1; bucket < endBucket; ++bucket) {
    mWords[bucket] |= from->mWords[sourceBucketFor(bucket)];
  }

  if (upperBit != 0u) {
    mWords[endBucket] |= (from->mWords[sourceBucketFor(endBucket)] & MaskRange(0, upperBit));
  }
}

/**
 * Address: 0x00401670 (FUN_00401670)
 * Address: 0x10001380
 *
 * What it does:
 * Clears bits in [lower.mValue, upper.mValue), compacts, and returns `{this, min(upper, Max())}`.
 */
BVIntSetIndex BVIntSet::ClearRange(const BVIntSetIndex lower, const BVIntSetIndex upper)
{
  const unsigned int lowerValue = lower.mValue;
  const unsigned int upperValue = upper.mValue;
  const size_t lowerBucket = BucketFor(lowerValue);
  const size_t upperBucket = BucketFor(upperValue);
  const unsigned int lowerBit = (lowerValue & kWordBitMask);
  const unsigned int upperBit = (upperValue & kWordBitMask);

  if (lowerBucket == upperBucket) {
    if (upperBit != lowerBit) {
      mWords[lowerBucket] &= (MaskRange(upperBit, kBitsPerWord) | MaskRange(0, lowerBit));
    }
  } else {
    mWords[lowerBucket] &= MaskRange(0, lowerBit);
    for (size_t bucket = lowerBucket + 1; bucket < upperBucket; ++bucket) {
      mWords[bucket] = 0u;
    }
    if (upperBit != 0u) {
      mWords[upperBucket] &= MaskRange(upperBit, kBitsPerWord);
    }
  }

  Finalize();

  unsigned int nextValue = Max();
  if (upperValue < nextValue) {
    nextValue = upperValue;
  }
  return BVIntSetIndex{this, nextValue};
}

/**
 * Address: 0x00401730 (FUN_00401730)
 * Address: 0x10001440
 *
 * What it does:
 * Returns the number of set bits in the current bucket span.
 */
unsigned int BVIntSet::Count() const
{
  unsigned int count = 0u;
  for (const unsigned int* word = mWords.start_; word != mWords.end_; ++word) {
    count += static_cast<unsigned int>(std::popcount(*word));
  }
  return count;
}

/**
 * Address: 0x004035F0 (FUN_004035F0, Moho::BVIntSet::Contains)
 *
 * What it does:
 * Returns whether `val` bit is set in this set.
 */
bool BVIntSet::Contains(const unsigned int val) const
{
  const unsigned int relativeWord = (val >> kWordShift) - mFirstWordIndex;
  const std::size_t wordCount = static_cast<std::size_t>(mWords.end_ - mWords.start_);
  if (relativeWord >= wordCount) {
    return false;
  }

  const unsigned int word = mWords.start_[relativeWord];
  return ((word >> (val & kWordBitMask)) & 1u) != 0u;
}

/**
 * Address: 0x006D3090 (FUN_006D3090, Moho::BVIntSet::Get)
 *
 * What it does:
 * Returns `{this, val}` when the bit exists; otherwise returns `{this, Max()}`.
 */
BVIntSetIndex BVIntSet::Get(const unsigned int val) const
{
  const unsigned int relativeWord = (val >> kWordShift) - mFirstWordIndex;
  const std::size_t wordCount = static_cast<std::size_t>(mWords.end_ - mWords.start_);
  const unsigned int resolvedValue =
    (relativeWord < wordCount && ((mWords.start_[relativeWord] >> (val & kWordBitMask)) & 1u) != 0u) ? val : Max();
  return MakeBVIntSetIndex(const_cast<BVIntSet*>(this), resolvedValue);
}

/**
 * Address: 0x004017B0 (FUN_004017B0)
 * Address: 0x100014C0
 *
 * What it does:
 * Returns the next set value strictly greater than `val`, or Max() when exhausted.
 */
unsigned int BVIntSet::GetNext(const unsigned int val) const
{
  unsigned int current = val + 1u;
  const unsigned int startValue = Min();
  if (current < startValue) {
    current = startValue;
  }

  size_t bucket = BucketFor(current);
  if (bucket >= Buckets()) {
    return Max();
  }

  unsigned int bits = mWords[bucket] >> (current & kWordBitMask);
  if (bits == 0u) {
    while (++bucket < Buckets()) {
      bits = mWords[bucket];
      if (bits != 0u) {
        current = static_cast<unsigned int>(FromBucket(bucket));
        break;
      }
    }
    if (bits == 0u) {
      return Max();
    }
  }

  current += static_cast<unsigned int>(std::countr_zero(bits));
  return current;
}

/**
 * Address: 0x00401830 (FUN_00401830)
 *
 * What it does:
 * Finds the previous set bit before `val` by walking backward across bucket storage.
 */
unsigned int BVIntSet::GetPrev(const unsigned int val) const
{
  unsigned int result = val - 1u;
  const unsigned int startWord = mFirstWordIndex;
  const unsigned int* const words = mWords.start_;

  unsigned int bitIndex = result & kWordBitMask;
  unsigned int wordIndex = (result >> kWordShift) - startWord;
  unsigned int bits = (0xFFFFFFFEu << bitIndex) & words[wordIndex];
  if (bits == 0u) {
    do {
      bits = words[--wordIndex];
    } while (bits == 0u);

    result = 32u * (startWord + wordIndex) + 31u;
    bitIndex = 31u;
  }

  for (; ((1u << bitIndex) & bits) == 0u; --result) {
    --bitIndex;
  }

  return result;
}

/**
 * Address: 0x004018A0 (FUN_004018A0)
 * Address: 0x100015B0
 *
 * What it does:
 * Trims zero words on both sides and normalizes empty-state storage.
 */
void BVIntSet::Finalize()
{
  size_t first = 0;
  size_t last = Buckets();
  if (last != 0) {
    while (first < last && mWords[first] == 0u) {
      ++first;
    }
    if (first < last && mWords[last - 1] == 0u) {
      while (last > first && mWords[last - 1] == 0u) {
        --last;
      }
    }
  }

  if (first == 0 && last == Buckets()) {
    return;
  }

  if (first == last) {
    mWords.ResetStorageToInline();
    mFirstWordIndex = 0;
    return;
  }

  const size_t keptWords = last - first;
  if (keptWords > 0) {
    std::memmove(mWords.start_, mWords.start_ + first, keptWords * sizeof(unsigned int));
  }

  constexpr unsigned int fillWord = 0u;
  mWords.Resize(keptWords, fillWord);
  mFirstWordIndex += static_cast<unsigned int>(first);
}

/**
 * Address: 0x00401980 (FUN_00401980)
 * Address: 0x10001690
 *
 * What it does:
 * Ensures bucket coverage for [lower, upper) by prepending/appending zero words as needed.
 */
void BVIntSet::EnsureBounds(const unsigned int lower, const unsigned int upper)
{
  constexpr unsigned int fillWord = 0u;
  const unsigned int requiredStart = (lower >> kWordShift);
  const unsigned int requiredEnd = ((upper + kWordBitMask) >> kWordShift);

  if (mWords.start_ == mWords.end_) {
    if (requiredEnd > requiredStart) {
      mFirstWordIndex = requiredStart;
      mWords.Resize(requiredEnd - requiredStart, fillWord);
    }
    return;
  }

  const size_t currentWords = Buckets();
  const unsigned int currentStart = mFirstWordIndex;
  const unsigned int currentEnd = currentStart + static_cast<unsigned int>(currentWords);

  const unsigned int prependWords = (requiredStart < currentStart) ? (currentStart - requiredStart) : 0u;
  const unsigned int appendWords = (requiredEnd > currentEnd) ? (requiredEnd - currentEnd) : 0u;
  if ((prependWords | appendWords) == 0u) {
    return;
  }

  const size_t newWordCount = currentWords + prependWords + appendWords;
  mWords.Resize(newWordCount, fillWord);

  if (prependWords != 0u) {
    const size_t copyWords = currentWords;
    if (copyWords > 0) {
      std::memmove(mWords.start_ + prependWords, mWords.start_, copyWords * sizeof(unsigned int));
    }

    for (size_t index = 0; index < prependWords; ++index) {
      mWords[index] = 0u;
    }
    mFirstWordIndex = requiredStart;
  }
}

/**
 * Address: 0x00401A60 (FUN_00401A60)
 *
 * What it does:
 * Unions all bits from `from` into this set.
 */
void BVIntSet::AddAllFrom(const BVIntSet* from)
{
  if (from == nullptr) {
    return;
  }

  const unsigned int lower = from->GetNext(std::numeric_limits<unsigned int>::max());
  const unsigned int upper = from->Max();
  AddFrom(from, lower, upper);
}

/**
 * Address: 0x00401A90 (FUN_00401A90)
 * Address: 0x100017A0
 *
 * What it does:
 * Clears all bits from this set that are present in `from`, then compacts.
 */
void BVIntSet::RemoveAllFrom(const BVIntSet* from)
{
  if (from == nullptr) {
    return;
  }

  const unsigned int thisStart = mFirstWordIndex;
  const unsigned int fromStart = from->mFirstWordIndex;
  const unsigned int overlapStart = std::max(thisStart, fromStart);
  const unsigned int thisEnd = thisStart + static_cast<unsigned int>(Buckets());
  const unsigned int fromEnd = fromStart + static_cast<unsigned int>(from->Buckets());
  const unsigned int overlapEnd = std::min(thisEnd, fromEnd);

  for (unsigned int bucketWord = overlapStart; bucketWord < overlapEnd; ++bucketWord) {
    mWords[bucketWord - thisStart] &= ~from->mWords[bucketWord - fromStart];
  }

  Finalize();
}

/**
 * Address: 0x00401AF0 (FUN_00401AF0)
 *
 * What it does:
 * Intersects this set with `other` and trims to the non-zero overlap span.
 */
void BVIntSet::IntersectWith(const BVIntSet* other)
{
  if (other == nullptr) {
    mWords.ResetStorageToInline();
    mFirstWordIndex = 0u;
    return;
  }

  const unsigned int thisStart = mFirstWordIndex;
  const unsigned int otherStart = other->mFirstWordIndex;
  const unsigned int overlapStart = std::max(thisStart, otherStart);
  const unsigned int thisEnd = thisStart + static_cast<unsigned int>(Buckets());
  const unsigned int otherEnd = otherStart + static_cast<unsigned int>(other->Buckets());
  unsigned int overlapEnd = std::min(thisEnd, otherEnd);

  if (overlapStart >= overlapEnd) {
    mWords.ResetStorageToInline();
    mFirstWordIndex = 0u;
    return;
  }

  unsigned int firstNonZero = overlapStart;
  while (firstNonZero < overlapEnd) {
    const unsigned int bits = mWords[firstNonZero - thisStart] & other->mWords[firstNonZero - otherStart];
    if (bits != 0u) {
      break;
    }
    ++firstNonZero;
  }

  if (firstNonZero >= overlapEnd) {
    mWords.ResetStorageToInline();
    mFirstWordIndex = 0u;
    return;
  }

  while (overlapEnd > firstNonZero) {
    const unsigned int bucketWord = overlapEnd - 1u;
    const unsigned int bits = mWords[bucketWord - thisStart] & other->mWords[bucketWord - otherStart];
    if (bits != 0u) {
      break;
    }
    --overlapEnd;
  }

  std::size_t dst = 0u;
  for (unsigned int bucketWord = firstNonZero; bucketWord < overlapEnd; ++bucketWord, ++dst) {
    mWords[dst] = mWords[bucketWord - thisStart] & other->mWords[bucketWord - otherStart];
  }

  mFirstWordIndex = firstNonZero;
  constexpr unsigned int fillWord = 0u;
  mWords.Resize(static_cast<std::size_t>(overlapEnd - firstNonZero), fillWord);
}

/**
 * Address: 0x00401C50 (FUN_00401C50)
 *
 * What it does:
 * Compares set base index and all payload words for exact equality.
 */
bool BVIntSet::Equals(const BVIntSet* other) const
{
  if (other == nullptr) {
    return false;
  }

  if (mFirstWordIndex != other->mFirstWordIndex) {
    return false;
  }

  const std::size_t words = Buckets();
  if (words != other->Buckets()) {
    return false;
  }

  for (std::size_t i = 0u; i < words; ++i) {
    if (mWords[i] != other->mWords[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Address: 0x00401CA0 (FUN_00401CA0)
 * Address: 0x006D3220 (FUN_006D3220)
 *
 * What it does:
 * Returns whether two sets differ.
 */
bool moho::operator!=(const BVIntSet& lhs, const BVIntSet& rhs) noexcept
{
  return !lhs.Equals(&rhs);
}

/**
 * Address: 0x00401CB0 (FUN_00401CB0)
 *
 * What it does:
 * Builds the union of `*this` and `rhs` into `out`.
 */
BVIntSet* BVIntSet::Union(BVIntSet* const out, const BVIntSet* const rhs) const
{
  const BVIntSetWordRange lhsRange = GetWordRange(*this);
  const BVIntSetWordRange rhsRange = GetWordRange(*rhs);
  const unsigned int outStartWord = std::min(lhsRange.mStartWord, rhsRange.mStartWord);
  const unsigned int outWordCount = std::max(lhsRange.mEndWord, rhsRange.mEndWord) - outStartWord;

  return CopyAndApplyOverlap(
    *this,
    *rhs,
    out,
    outStartWord,
    outWordCount,
    [](unsigned int& dstWord, const unsigned int rhsWord) {
      dstWord |= rhsWord;
    }
  );
}

/**
 * Address: 0x00401E30 (FUN_00401E30)
 *
 * What it does:
 * Builds the symmetric difference of `*this` and `rhs` into `out`.
 */
BVIntSet* BVIntSet::ExclusiveOr(BVIntSet* const out, const BVIntSet* const rhs) const
{
  const BVIntSetWordRange lhsRange = GetWordRange(*this);
  const BVIntSetWordRange rhsRange = GetWordRange(*rhs);
  const unsigned int outStartWord = std::min(lhsRange.mStartWord, rhsRange.mStartWord);
  const unsigned int outWordCount = std::max(lhsRange.mEndWord, rhsRange.mEndWord) - outStartWord;

  CopyAndApplyOverlap(
    *this,
    *rhs,
    out,
    outStartWord,
    outWordCount,
    [](unsigned int& dstWord, const unsigned int rhsWord) {
      dstWord ^= rhsWord;
    }
  );
  out->Finalize();
  return out;
}

/**
 * Address: 0x00401F60 (FUN_00401F60)
 *
 * What it does:
 * Builds the trimmed intersection of `*this` and `rhs` into `out`.
 */
BVIntSet* BVIntSet::Intersect(BVIntSet* const out, const BVIntSet* const rhs) const
{
  return BuildTrimmedOverlap(
    *this,
    *rhs,
    out,
    [](const unsigned int lhsWord, const unsigned int rhsWord) {
      return lhsWord & rhsWord;
    }
  );
}

/**
 * Address: 0x00402110 (FUN_00402110)
 *
 * What it does:
 * Builds `*this & ~rhs` into `out` and compacts the result.
 */
BVIntSet* BVIntSet::Subtract(BVIntSet* const out, const BVIntSet* const rhs) const
{
  const BVIntSetWordRange lhsRange = GetWordRange(*this);
  CopyAndApplyOverlap(
    *this,
    *rhs,
    out,
    lhsRange.mStartWord,
    lhsRange.mEndWord - lhsRange.mStartWord,
    [](unsigned int& dstWord, const unsigned int rhsWord) {
      dstWord &= ~rhsWord;
    }
  )->Finalize();
  return out;
}

/**
 * Address: 0x004036A0 (FUN_004036A0)
 *
 * What it does:
 * Sets one bit and returns `{this, value, wasInserted}`.
 */
BVIntSetAddResult BVIntSet::Add(const unsigned int val)
{
  EnsureBounds(val, val + 1u);

  const size_t bucket = BucketFor(val);
  const unsigned int shift = (val & kWordBitMask);
  const unsigned int previousWord = mWords[bucket];
  mWords[bucket] = previousWord | (1u << shift);

  const bool wasInserted = ((previousWord >> shift) & 1u) == 0u;
  return BVIntSetAddResult{{this, val}, wasInserted};
}

/**
 * Address: 0x008AA7F0 (FUN_008AA7F0)
 *
 * What it does:
 * Adapts one register-shape add thunk by writing `BVIntSet::Add(val)` into
 * caller-provided result storage and returning that result pointer.
 */
[[maybe_unused]] BVIntSetAddResult* BVIntSetAddThunkWithOutResult(
  BVIntSet* const set,
  const unsigned int val,
  BVIntSetAddResult* const outResult
)
{
  *outResult = set->Add(val);
  return outResult;
}

/**
 * Address: 0x00403650 (FUN_00403650)
 *
 * What it does:
 * Clears one bit, finalizes storage, and reports whether that bit was previously set.
 */
bool BVIntSet::Remove(const unsigned int val)
{
  const size_t bucket = BucketFor(val);
  if (bucket >= Buckets()) {
    return false;
  }

  const unsigned int shift = (val & kWordBitMask);
  const unsigned int previousWord = mWords[bucket];
  mWords[bucket] = previousWord & ~(1u << shift);

  Finalize();
  return ((previousWord >> shift) & 1u) != 0u;
}

/**
 * Address: 0x004032A0 (FUN_004032A0, Moho::BVIntSet::MemberDeserialize)
 *
 * IDA signature:
 * void __usercall Moho::BVIntSet::MemberDeserialize(Moho::BVIntSet *a1@<eax>, gpg::ReadArchive *a3@<esi>);
 *
 * What it does:
 * Reads the base word index and packed word-vector payload from archive.
 */
void BVIntSet::MemberDeserialize(gpg::ReadArchive* const archive)
{
  GPG_ASSERT(archive != nullptr);
  if (!archive) {
    return;
  }

  archive->ReadUInt(&mFirstWordIndex);

  gpg::RType* const vectorType = gpg::ResolveFastVectorUIntType();
  GPG_ASSERT(vectorType != nullptr);
  if (!vectorType) {
    return;
  }

  archive->Read(vectorType, &mWords, NullOwnerRef());
}

/**
 * Address: 0x004032F0 (FUN_004032F0, Moho::BVIntSet::MemberSerialize)
 *
 * IDA signature:
 * void __usercall Moho::BVIntSet::MemberSerialize(Moho::BVIntSet *a1@<eax>, BinaryWriteArchive *a2@<esi>);
 *
 * What it does:
 * Writes the base word index and packed word-vector payload to archive.
 */
void BVIntSet::MemberSerialize(gpg::WriteArchive* const archive) const
{
  GPG_ASSERT(archive != nullptr);
  if (!archive) {
    return;
  }

  archive->WriteUInt(mFirstWordIndex);

  gpg::RType* const vectorType = gpg::ResolveFastVectorUIntType();
  GPG_ASSERT(vectorType != nullptr);
  if (!vectorType) {
    return;
  }

  archive->Write(vectorType, &mWords, NullOwnerRef());
}

unsigned int BVIntSet::MaskRange(const unsigned loBit, const unsigned hiBit) noexcept
{
  const unsigned int upperMask = (hiBit >= kBitsPerWord) ? 0xFFFFFFFFu : ((1u << hiBit) - 1u);
  const unsigned int lowerMask = (loBit == 0u) ? 0u : ((1u << loBit) - 1u);
  return upperMask & ~lowerMask;
}
