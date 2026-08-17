#include "SSyncFilter.h"

#include <cstddef>

void moho::CopySyncFilterMaskPayload(SSyncFilterMaskBlock& target, const SSyncFilterMaskBlock& source)
{
  target.mFirstWordIndex = source.mFirstWordIndex;
  target.mWords.ResetFrom(source.mWords);
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
  maskB.mWords.ResetStorageToInline();
  maskA.mWords.ResetStorageToInline();
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
  CopySyncFilterMaskPayload(maskA, source.maskA);
  optionFlag = source.optionFlag;
  CopySyncFilterMaskPayload(maskB, source.maskB);
}
