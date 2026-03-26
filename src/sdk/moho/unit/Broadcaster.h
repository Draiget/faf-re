#pragma once

#include <cstddef>

#include "moho/containers/TDatList.h"

namespace moho
{
  class Broadcaster : public TDatList<Broadcaster, void> {};

  static_assert(offsetof(Broadcaster, mPrev) == 0x00, "Broadcaster::mPrev offset must be 0x00");
  static_assert(offsetof(Broadcaster, mNext) == 0x04, "Broadcaster::mNext offset must be 0x04");
  static_assert(sizeof(Broadcaster) == 0x08, "Broadcaster size must be 0x08");
} // namespace moho
