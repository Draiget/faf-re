#include "BitStorage32.h"

#include <algorithm>
#include <cstddef>

namespace moho
{
  namespace
  {
    [[nodiscard]] constexpr std::uint32_t WordCountForBits(const std::uint32_t bitCount) noexcept
    {
      return (bitCount + 31u) >> 5u;
    }
  } // namespace

  /**
   * Address: 0x00440030/FUN_00440030 and 0x0063F8D0/FUN_0063F8D0 equivalent
   *
   * What it does:
   * Releases word storage and clears all metadata lanes.
   */
  void SBitStorage32::Reset()
  {
    if (mWords != nullptr) {
      ::operator delete(mWords);
    }

    mBitCount = 0;
    mReservedWordBase = 0;
    mWords = nullptr;
    mWordsEnd = nullptr;
    mWordsCapacityEnd = nullptr;
  }

  /**
   * Address: 0x00443150/FUN_00443150 behavior-equivalent shape
   *
   * std::uint32_t,bool
   *
   * What it does:
   * Resizes packed storage for `bitCount` bits and initializes payload words.
   */
  void SBitStorage32::Resize(const std::uint32_t bitCount, const bool setBits)
  {
    const std::uint32_t requiredWordCount = WordCountForBits(bitCount);
    if (requiredWordCount == 0u) {
      Reset();
      return;
    }

    const std::uint32_t currentWordCapacity = (mWords != nullptr && mWordsCapacityEnd != nullptr)
      ? static_cast<std::uint32_t>(mWordsCapacityEnd - mWords)
      : 0u;
    if (currentWordCapacity < requiredWordCount) {
      auto* const words = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * requiredWordCount));
      if (mWords != nullptr) {
        ::operator delete(mWords);
      }

      mWords = words;
      mWordsCapacityEnd = words + requiredWordCount;
    }

    mBitCount = bitCount;
    mReservedWordBase = 0;
    mWordsEnd = mWords + requiredWordCount;

    const std::uint32_t fillWord = setBits ? 0xFFFFFFFFu : 0u;
    std::fill(mWords, mWordsEnd, fillWord);

    const std::uint32_t trailingBits = (bitCount & 31u);
    if (setBits && trailingBits != 0u) {
      mWordsEnd[-1] &= ((1u << trailingBits) - 1u);
    }
  }

  /**
   * Address: 0x00642140/FUN_00642140 behavior-equivalent
   *
   * std::uint32_t
   *
   * What it does:
   * Returns whether one bit is set.
   */
  bool SBitStorage32::TestBit(const std::uint32_t bitIndex) const
  {
    if (mWords == nullptr || bitIndex >= mBitCount) {
      return false;
    }

    const std::uint32_t wordIndex = (bitIndex >> 5u);
    const std::uint32_t bitInWord = (bitIndex & 31u);
    return (mWords[wordIndex] & (1u << bitInWord)) != 0u;
  }

  /**
   * Address: 0x0063EF20/FUN_0063EF20 behavior-equivalent
   *
   * std::uint32_t,bool
   *
   * What it does:
   * Sets or clears one bit.
   */
  void SBitStorage32::SetBit(const std::uint32_t bitIndex, const bool enabled)
  {
    if (mWords == nullptr || bitIndex >= mBitCount) {
      return;
    }

    const std::uint32_t wordIndex = (bitIndex >> 5u);
    const std::uint32_t bitInWord = (bitIndex & 31u);
    const std::uint32_t bitMask = (1u << bitInWord);

    if (enabled) {
      mWords[wordIndex] |= bitMask;
    } else {
      mWords[wordIndex] &= ~bitMask;
    }
  }
} // namespace moho
