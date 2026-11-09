// Engine addition (dedicated-server plan WPR.21): the Wild Magic 3.8 library
// definitions the engine references, now that the compiled Wm3Foundation
// library is no longer linked (Wm3Vector3.cpp, Wm3Math.cpp, Wm3System.cpp;
// Geometric Tools, Inc., Wild Magic 3 license, version 1.0c). The queries the
// engine calls are in Wm3Queries.cpp; everything else in Wild Magic it uses is
// header code.

#include <cfloat>
#include <cstddef>
#include <cstring>

#include "Wm3Math.h"
#include "Wm3System.h"
#include "Wm3Vector3.h"

namespace Wm3
{
  template <>
  const Vector3<float> Vector3<float>::ZERO(0.0f, 0.0f, 0.0f);

  template <>
  const float Math<float>::ZERO_TOLERANCE = 1e-06f;
  template <>
  const float Math<float>::MAX_REAL = FLT_MAX;

  // The library's portable body, which behaves as its MSVC 8 `memcpy_s` call
  // does for every valid copy.
  void* System::Memcpy(void* const dst, const std::size_t dstSize, const void* const src, const std::size_t srcSize)
  {
    if (dst == nullptr || dstSize == 0 || src == nullptr || srcSize == 0) {
      return nullptr;
    }
    if (srcSize > dstSize) {
      return nullptr;
    }
    std::memcpy(dst, src, srcSize);
    return dst;
  }
} // namespace Wm3
