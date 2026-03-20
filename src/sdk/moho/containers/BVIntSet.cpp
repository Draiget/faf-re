#include "BVIntSet.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

using namespace moho;

namespace
{
  constexpr unsigned int kBitsPerWord = 32u;
  constexpr unsigned int kWordShift = 5u;
  constexpr unsigned int kWordBitMask = kBitsPerWord - 1u;
} // namespace

gpg::RType* BVIntSet::sType = nullptr;

BVIntSet::BVIntSet(const BVIntSet& set)
{
  mFirstWordIndex = set.mFirstWordIndex;
  mReservedMetaWord = set.mReservedMetaWord;
  mWords.ResetFrom(set.mWords);
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

unsigned int BVIntSet::MaskRange(const unsigned loBit, const unsigned hiBit) noexcept
{
  const unsigned int upperMask = (hiBit >= kBitsPerWord) ? 0xFFFFFFFFu : ((1u << hiBit) - 1u);
  const unsigned int lowerMask = (loBit == 0u) ? 0u : ((1u << loBit) - 1u);
  return upperMask & ~lowerMask;
}
