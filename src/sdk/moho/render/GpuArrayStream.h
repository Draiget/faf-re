#pragma once

// Engine addition, not in the shipped binary.
//
// A GPU structured buffer that mirrors one CPU array between frames. Each
// `Update` compares the new contents with what the buffer already holds, in
// fixed blocks, and uploads only the blocks that changed (adjacent ones as one
// range), so data that is mostly the same from frame to frame - icon records
// of idle units, vision circles - costs a compare instead of a transfer.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class GpuBuffer;
} // namespace gpg::gal

namespace moho
{
  class GpuArrayStream
  {
  public:
    /** `stride`: bytes per element; `blockBytes`: the compare/upload granularity. */
    GpuArrayStream(const char* name, std::uint32_t stride, std::uint32_t blockBytes = 4096U) noexcept;

    /**
     * Makes the GPU copy hold the `count` elements at `data`. Returns the buffer,
     * or null when the device cannot create one.
     */
    gpg::gal::GpuBuffer* Update(const void* data, std::size_t count);

    /** Forgets the GPU copy (a new device). */
    void Reset() noexcept;

    [[nodiscard]] gpg::gal::GpuBuffer* Buffer() const noexcept { return mBuffer.get(); }

  private:
    const char* mName;
    std::uint32_t mStride;
    std::uint32_t mBlockBytes;
    boost::shared_ptr<gpg::gal::GpuBuffer> mBuffer;
    std::vector<std::uint8_t> mUploaded; // what mBuffer holds
  };
} // namespace moho
