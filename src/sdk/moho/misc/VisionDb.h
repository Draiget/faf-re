#pragma once

#include "moho/vision/VisionDB.h"

namespace moho
{
  /**
   * Compatibility alias. This header used to carry a second, generated
   * skeleton of the same 0x24-byte binary object that `moho::VisionDB`
   * (moho/vision/VisionDB.h) models properly. Keeping both meant
   * `CWldSession::mVisionDb` was declared with the skeleton, whose trivial
   * constructor never ran `VisionDB::Pool::Pool` (0x0081ACA0) and so never
   * allocated the pool's self-linked list sentinels - every consumer that
   * reinterpreted the member as a real `VisionDB` then found a null
   * `mEntriesHead`. The recovered definition is the single owner now.
   */
  using VisionDb = VisionDB;
} // namespace moho
