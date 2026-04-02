#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/containers/TDatList.h"
#include "moho/resource/RResId.h"

namespace moho
{
  using PrefetchListLink = TDatListItem<void, void>;

  static_assert(sizeof(PrefetchListLink) == 0x08, "PrefetchListLink size must be 0x08");

  struct PrefetchRequestRuntime
  {
    RResId mResourceId;                 // +0x00
    gpg::RType* mResourceType;          // +0x1C
    std::uint8_t mIsLoading;            // +0x20
    std::uint8_t mLoadWakePending;      // +0x21
    std::uint8_t mPad22[2];             // +0x22
    boost::SharedCountPair mResolved;   // +0x24
    std::uint8_t mHadLoadFailure;       // +0x2C
    std::uint8_t mPad2D[3];             // +0x2D
    boost::SharedCountPair mPrefetch;   // +0x30
    PrefetchListLink mWaiterListHead;   // +0x38
  };

  static_assert(offsetof(PrefetchRequestRuntime, mResourceId) == 0x00, "PrefetchRequestRuntime::mResourceId offset must be 0x00");
  static_assert(offsetof(PrefetchRequestRuntime, mResourceType) == 0x1C, "PrefetchRequestRuntime::mResourceType offset must be 0x1C");
  static_assert(offsetof(PrefetchRequestRuntime, mIsLoading) == 0x20, "PrefetchRequestRuntime::mIsLoading offset must be 0x20");
  static_assert(offsetof(PrefetchRequestRuntime, mLoadWakePending) == 0x21, "PrefetchRequestRuntime::mLoadWakePending offset must be 0x21");
  static_assert(offsetof(PrefetchRequestRuntime, mResolved) == 0x24, "PrefetchRequestRuntime::mResolved offset must be 0x24");
  static_assert(offsetof(PrefetchRequestRuntime, mHadLoadFailure) == 0x2C, "PrefetchRequestRuntime::mHadLoadFailure offset must be 0x2C");
  static_assert(offsetof(PrefetchRequestRuntime, mPrefetch) == 0x30, "PrefetchRequestRuntime::mPrefetch offset must be 0x30");
  static_assert(offsetof(PrefetchRequestRuntime, mWaiterListHead) == 0x38, "PrefetchRequestRuntime::mWaiterListHead offset must be 0x38");
  static_assert(sizeof(PrefetchRequestRuntime) == 0x40, "PrefetchRequestRuntime size must be 0x40");
} // namespace moho
