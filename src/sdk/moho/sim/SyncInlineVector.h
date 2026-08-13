#pragma once

#include <cstdint>

#include "gpg/core/containers/FastVector.h"

namespace moho
{
  /**
   * One small-buffer scratch run carried by `SSyncData::mInlineScratchVectors`
   * (+0x294) and copied wholesale onto `CWldSession::mSyncInlineVectors`
   * (+0x490) by `CWldSession::DoBeat`.
   *
   * Layout evidence: the sync-packet teardown lane walks the run with a 32-byte
   * stride and releases each element with `operator delete[]` once its data
   * pointer has moved off the inline block (SimDriver.cpp), and `DoBeat`'s
   * vector assignment at 0x00895214 divides the byte span by 32 (`sar ecx, 5`).
   * That is exactly `gpg::core::FastVectorN`'s `{first, last, end, inlineFirst}` head
   * plus a 16-byte inline block, and the array-delete says the element type is
   * trivially destructible.
   */
  using SyncInlineVector = gpg::core::FastVectorN<std::int32_t, 4>;

  static_assert(sizeof(SyncInlineVector) == 0x20, "SyncInlineVector size must be 0x20");
} // namespace moho
