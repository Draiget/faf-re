#include "moho/resource/CAniResourceSkel.h"

namespace moho
{
  gpg::RType* CAniResourceSkel::sType = nullptr;

  /**
   * Address: 0x00538500 (FUN_00538500, Moho::CAniResourceSkel::dtr thunk/body)
   */
  CAniResourceSkel::~CAniResourceSkel()
  {
    mName.tidy(true, 0u);
  }
} // namespace moho
