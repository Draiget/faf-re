#pragma once
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/containers/BVIntSet.h"

namespace moho
{
  struct SimSubRes3
  {
    // Copied by 0x00403CB0 into SimSubRes2 history ring.
    int32_t mValue; // +0x00
    int32_t mReserved04;
    gpg::core::FastVectorN<int32_t, 2> mValues; // +0x08
  };
  static_assert(sizeof(SimSubRes3) == 0x20, "SimSubRes3 size must be 0x20");

  struct SimSubRes2
  {
    SimSubRes3 mData[100]; // +0x0000..+0x0C7F
    int32_t mStart;        // +0x0C80
    int32_t mEnd;          // +0x0C84
  };
  static_assert(sizeof(SimSubRes2) == 0xC88, "SimSubRes2 size must be 0xC88");

  class IdPool
  {
  public:
    // 0x00684480 uses this as sequential low-id allocator in the `(*v3)++` branch.
    int32_t mNextLowId; // +0x00
    int32_t mReserved04;
    BVIntSet mReleasedLows; // +0x08
    SimSubRes2 mSubRes2;    // +0x28
  };
  static_assert(sizeof(IdPool) == 0xCB0, "IdPool size must be 0xCB0");
} // namespace moho
