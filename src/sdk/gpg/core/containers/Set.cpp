#include "Set.h"

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"

namespace
{
  using SetWordStorage = gpg::core::FastVectorN<std::uint32_t, 2>;
  using SetWordVector = gpg::core::FastVector<std::uint32_t>;

  static_assert(sizeof(SetWordStorage) == 0x18, "Set word-storage lane must match fastvector_n<uint32_t,2> ABI");
  static_assert(offsetof(moho::Set, items_begin) == 0x08, "Set::items_begin offset must be 0x08");
  static_assert(offsetof(moho::Set, owner_or_pad) == 0x1C, "Set::owner_or_pad offset must be 0x1C");
}

namespace moho
{
  /**
   * Address: 0x00401080 (FUN_00401080)
   *
   * What it does:
   * Initializes Set to the inline two-word fastvector window used by legacy
   * small-buffer storage paths.
   */
  Set::Set()
  {
    baseWordIndex = 0;

    auto* const inlineWords = &sso_word;
    items_begin = inlineWords;
    items_end = inlineWords;
    items_capacity_end = inlineWords + 2;
    alloc_or_cookie = inlineWords;
  }

  /**
   * Address: 0x00401E10 (FUN_00401E10, legacy Set copy-ctor lane)
   *
   * What it does:
   * Copies absolute base-word index and clones the packed word vector payload.
   */
  Set::Set(const Set& other)
  {
    baseWordIndex = other.baseWordIndex;

    // Binary lane does not write +0x04 for this copy-ctor path.
    // Keep meta untouched to preserve the original initialization behavior.

    auto& dstWords = *reinterpret_cast<SetWordStorage*>(&items_begin);
    const auto& srcWords = *reinterpret_cast<const SetWordStorage*>(&other.items_begin);
    gpg::core::legacy::RebindInlineAndCopy(
      dstWords,
      static_cast<const SetWordVector&>(srcWords)
    );
  }
} // namespace moho
