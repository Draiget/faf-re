#pragma once

#include <cstddef>

#include "moho/containers/TDatList.h"

namespace moho
{
  /**
   * Compatibility alias for legacy callsites that still include this header.
   *
   * Canonical intrusive node implementation lives in `TDatListItem`.
   */
  using SIntrusiveListNode = TDatListItem<void, void>;

  static_assert(sizeof(SIntrusiveListNode) == 0x08, "SIntrusiveListNode size must be 0x08");
  static_assert(offsetof(SIntrusiveListNode, mPrev) == 0x00, "SIntrusiveListNode::mPrev offset must be 0x00");
  static_assert(offsetof(SIntrusiveListNode, mNext) == 0x04, "SIntrusiveListNode::mNext offset must be 0x04");
} // namespace moho
