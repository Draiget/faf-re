#include "BitStorage32.h"

#include <algorithm>
#include <cstddef>
#include <stdexcept>

namespace moho
{
  namespace
  {
    struct BitCursor32
    {
      std::uint32_t* word;
      std::uint32_t bit;
    };

    [[nodiscard]] constexpr std::uint32_t WordCountForBits(const std::uint32_t bitCount) noexcept
    {
      return (bitCount + 31u) >> 5u;
    }

    /**
     * Address: 0x00443110 (FUN_00443110)
     * Address: 0x00443144 (FUN_00443144, final tail lane)
     *
     * What it does:
     * Clears dynamic word-storage lanes while preserving the base-word metadata lane.
     */
    void ResetStoragePreserveBase(SBitStorage32& storage) noexcept
    {
      storage.mBitCount = 0;
      storage.mWords = nullptr;
      storage.mWordsEnd = nullptr;
      storage.mWordsCapacityEnd = nullptr;
    }

    /**
     * Address: 0x004431F0 (FUN_004431F0)
     *
     * What it does:
     * Builds one `(word,bit)` cursor at storage begin and advances it by `bitOffset`.
     */
    [[nodiscard]] BitCursor32 MakeCursorAtBitOffset(const SBitStorage32& storage, const std::uint32_t bitOffset) noexcept
    {
      BitCursor32 out{storage.mWords, bitOffset & 31u};
      if (out.word != nullptr) {
        out.word += (bitOffset >> 5u);
      }
      return out;
    }

    /**
     * Address: 0x00444130 (FUN_00444130)
     *
     * What it does:
     * Returns one single-bit mask for the cursor-local bit index.
     */
    [[nodiscard]] std::uint32_t CursorBitMask(const BitCursor32& cursor) noexcept
    {
      return 1u << cursor.bit;
    }

    /**
     * Address: 0x00443830 (FUN_00443830)
     *
     * What it does:
     * Sets or clears one bit through a precomputed `(word,bit)` cursor.
     */
    void SetCursorBit(BitCursor32& cursor, const bool enabled) noexcept
    {
      const std::uint32_t bitMask = CursorBitMask(cursor);
      if (enabled) {
        *cursor.word |= bitMask;
      } else {
        *cursor.word &= ~bitMask;
      }
    }

    /**
     * Address: 0x00443860 (FUN_00443860)
     *
     * What it does:
     * Returns whether one bit is set through a precomputed `(word,bit)` cursor.
     */
    [[nodiscard]] bool TestCursorBit(const BitCursor32& cursor) noexcept
    {
      return ((*cursor.word) & CursorBitMask(cursor)) != 0u;
    }

    /**
     * Address: 0x00443950 (FUN_00443950)
     *
     * What it does:
     * Initializes one word-window triad (`begin/end/capacity`) for `wordCount` dwords.
     */
    [[nodiscard]] bool InitializeWordWindow(
      std::uint32_t*& words,
      std::uint32_t*& wordsEnd,
      std::uint32_t*& wordsCapacityEnd,
      const std::uint32_t wordCount
    )
    {
      words = nullptr;
      wordsEnd = nullptr;
      wordsCapacityEnd = nullptr;

      if (wordCount == 0u) {
        return false;
      }

      if (wordCount > 0x3FFFFFFFu) {
        throw std::length_error("SBitStorage32 word count exceeds legacy limit");
      }

      auto* const allocated = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * wordCount));
      words = allocated;
      wordsEnd = allocated;
      wordsCapacityEnd = allocated + wordCount;
      return true;
    }
  } // namespace

  /**
    * Alias of FUN_00440030 (non-canonical helper lane).
   *
   * What it does:
   * Releases word storage and clears all metadata lanes.
   */
  void SBitStorage32::Reset()
  {
    if (mWords != nullptr) {
      ::operator delete(mWords);
    }

    ResetStoragePreserveBase(*this);
    mReservedWordBase = 0;
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
      if (mWords == nullptr) {
        (void)InitializeWordWindow(mWords, mWordsEnd, mWordsCapacityEnd, requiredWordCount);
      } else {
        auto* const words = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * requiredWordCount));
        ::operator delete(mWords);
        mWords = words;
        mWordsCapacityEnd = words + requiredWordCount;
      }
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

    const BitCursor32 cursor = MakeCursorAtBitOffset(*this, bitIndex);
    return TestCursorBit(cursor);
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

    BitCursor32 cursor = MakeCursorAtBitOffset(*this, bitIndex);
    SetCursorBit(cursor, enabled);
  }
} // namespace moho
