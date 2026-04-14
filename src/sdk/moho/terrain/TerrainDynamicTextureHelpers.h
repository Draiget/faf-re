#pragma once

#include "boost/shared_ptr.h"

namespace moho
{
  class CD3DDynamicTextureSheet;

  /**
   * Address: 0x00807740 (FUN_00807740, sub_807740)
   *
   * What it does:
   * Creates one 128x1 dynamic texture sheet (`format = 18`), writes a
   * cubic-blend lookup table into 128 RGBA texels, unlocks the sheet, and
   * returns retained ownership.
   */
  boost::shared_ptr<CD3DDynamicTextureSheet> CreateTerrainCubicBlendLookupTexture();

  /**
   * Address: 0x00803720 (FUN_00803720, func_NewDynamicTextureSheet)
   *
   * What it does:
   * Creates one 128x1 dynamic texture sheet (`format = 18`) through the
   * non-tracked resource lane, writes the cubic-blend lookup table into 128
   * RGBA texels, unlocks the sheet, and returns retained ownership.
   */
  boost::shared_ptr<CD3DDynamicTextureSheet> CreateTerrainCubicBlendLookupTextureTransient();
} // namespace moho
