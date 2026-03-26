#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "moho/animation/CAniDefaultSkel.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CAniResourceSkel : public CAniDefaultSkel
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00538500 (FUN_00538500, Moho::CAniResourceSkel::dtr thunk/body)
     * Slot: 0
     */
    ~CAniResourceSkel() override;

  public:
    msvc8::string mName; // +0x2C
  };

  static_assert(offsetof(CAniResourceSkel, mName) == 0x2C, "CAniResourceSkel::mName offset must be 0x2C");
  static_assert(sizeof(CAniResourceSkel) == 0x48, "CAniResourceSkel size must be 0x48");
} // namespace moho
