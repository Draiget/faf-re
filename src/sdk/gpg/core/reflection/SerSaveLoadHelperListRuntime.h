#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  /**
   * Runtime view of the leading intrusive-list lanes in one
   * `SerSaveLoadHelper<T>` instance.
   *
   * Binary layout:
   * - +0x00: vtable pointer
   * - +0x04: `gpg::SerHelperBase::mNext`
   * - +0x08: `gpg::SerHelperBase::mPrev`
   */
  struct SerSaveLoadHelperListRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
  };

  static_assert(
    offsetof(SerSaveLoadHelperListRuntime, mNext) == 0x04,
    "SerSaveLoadHelperListRuntime::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperListRuntime, mPrev) == 0x08,
    "SerSaveLoadHelperListRuntime::mPrev offset must be 0x08"
  );
  static_assert(
    sizeof(SerSaveLoadHelperListRuntime) == 0x0C,
    "SerSaveLoadHelperListRuntime size must be 0x0C"
  );

  /**
   * Unlinks one serializer helper node from its intrusive list and rewires it
   * to a self-linked singleton lane.
   */
  [[nodiscard]] inline gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(
    gpg::SerSaveLoadHelperListRuntime& helper
  ) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      helper.mNext->mPrev = helper.mPrev;
      helper.mPrev->mNext = helper.mNext;
    }

    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }
} // namespace gpg
