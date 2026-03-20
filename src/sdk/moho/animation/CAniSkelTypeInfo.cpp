#include "CAniSkelTypeInfo.h"

#include "moho/animation/CAniSkel.h"

namespace moho
{
  /**
   * Address: 0x00549FF0 (FUN_00549FF0, scalar deleting destructor thunk)
   */
  CAniSkelTypeInfo::~CAniSkelTypeInfo() = default;

  /**
   * Address: 0x00549FE0 (FUN_00549FE0)
   */
  const char* CAniSkelTypeInfo::GetName() const
  {
    return "CAniSkel";
  }

  /**
   * Address: 0x00549FC0 (FUN_00549FC0)
   *
   * What it does:
   * Initializes reflection metadata for `CAniSkel` (`sizeof = 0x2C`).
   */
  void CAniSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniSkel);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
