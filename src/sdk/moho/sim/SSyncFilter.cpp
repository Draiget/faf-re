#include "SSyncFilter.h"

#include <cstddef>

namespace
{
  bool AreMaskVectorsEqual(const gpg::core::FastVector<uint32_t>& lhs, const gpg::core::FastVector<uint32_t>& rhs)
  {
    if (lhs.Size() != rhs.Size()) {
      return false;
    }

    for (std::size_t i = 0; i < lhs.Size(); ++i) {
      if (lhs[i] != rhs[i]) {
        return false;
      }
    }

    return true;
  }
} // namespace

/**
  * Alias of FUN_00401C50 (non-canonical helper lane).
 *
 * What it does:
 * Compares the binary-significant mask payload (`rawWord` + full vector data).
 */
bool moho::SSyncFilterMaskBlock::Equals(const SSyncFilterMaskBlock& lhs, const SSyncFilterMaskBlock& rhs)
{
  return lhs.rawWord == rhs.rawWord && AreMaskVectorsEqual(lhs.masks, rhs.masks);
}

/**
 * Address: 0x004028E0 (FUN_004028E0 helper usage in FUN_0073DD10)
 *
 * What it does:
 * Copies the binary-significant mask payload (`rawWord` + vector data).
 */
void moho::SSyncFilterMaskBlock::CopyFrom(const SSyncFilterMaskBlock& source)
{
  rawWord = source.rawWord;
  masks.ResetFrom(source.masks);
}

/**
 * Address: 0x0073B980 (FUN_0073B980)
 * Mangled: ??1struct_SimDriverSubObj1@@QAE@@Z
 *
 * What it does:
 * Releases heap-backed lanes for both mask vectors and restores their inline
 * storage metadata before `geoCams` is destructed by member teardown order.
 */
moho::SSyncFilter::~SSyncFilter()
{
  maskB.masks.ResetStorageToInline();
  maskA.masks.ResetStorageToInline();
}

/**
 * Address: 0x0073DD10 (FUN_0073DD10)
 *
 * What it does:
 * Copies the binary-significant sync-filter payload:
 * focus army, geom-camera vector, both mask blocks, and option flag.
 */
void moho::SSyncFilter::CopyFrom(const SSyncFilter& source)
{
  focusArmy = source.focusArmy;
  geoCams = source.geoCams;
  maskA.CopyFrom(source.maskA);
  optionFlag = source.optionFlag;
  maskB.CopyFrom(source.maskB);
}
