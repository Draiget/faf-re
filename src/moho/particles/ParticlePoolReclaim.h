#pragma once

#include <cstddef>

namespace moho::detail
{
  // Engine addition: an exhausted bucket can reclaim wholly expired work from
  // buckets this pass has not visited yet. Never revisit the rendered prefix.
  template<std::size_t BufferCapacity, typename Iterator, typename Prune>
  bool ReclaimRemainingBucketsUnderPressure(
    Iterator current,
    const Iterator end,
    const std::size_t availableBuffers,
    const std::size_t pending,
    const bool filterWater,
    const bool renderAboveSurface,
    const float waterSurface,
    const float frameValue,
    const Prune& prune
  )
  {
    static_assert(BufferCapacity > 0U);
    const std::size_t needed = pending / BufferCapacity + (pending % BufferCapacity != 0U);
    if (needed <= availableBuffers) {
      return false;
    }
    for (; current != end; ++current) {
      const auto& [key, bucket] = *current;
      if (filterWater) {
        if (renderAboveSurface) {
          if (!(key.sortScalar >= waterSurface)) {
            continue;
          }
        } else if (key.sortScalar > waterSurface) {
          break;
        }
      }
      if (bucket != nullptr) {
        prune(*bucket, frameValue);
      }
    }
    return true;
  }
} // namespace moho::detail
