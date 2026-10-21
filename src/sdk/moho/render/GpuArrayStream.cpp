// Engine addition, not in the shipped binary (see GpuArrayStream.h).

#include "GpuArrayStream.h"

#include <algorithm>
#include <cstring>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"

namespace moho
{
  GpuArrayStream::GpuArrayStream(const char* const name, const std::uint32_t stride, const std::uint32_t blockBytes) noexcept
    : mName(name)
    , mStride(stride)
    , mBlockBytes(std::max(stride, blockBytes - (blockBytes % stride)))
  {}

  void GpuArrayStream::Reset() noexcept
  {
    mBuffer.reset();
    mUploaded.clear();
  }

  gpg::gal::GpuBuffer* GpuArrayStream::Update(const void* const data, const std::size_t count)
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return nullptr;
    }
    if (mBuffer == nullptr || mBuffer->Desc().capacity < count) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = mName;
      desc.stride = mStride;
      desc.capacity = static_cast<std::uint32_t>(std::max<std::size_t>(4096U, count + count / 2U));
      mBuffer = device->CreateGpuBuffer(desc);
      mUploaded.clear();
      if (mBuffer == nullptr) {
        return nullptr;
      }
    }

    const auto* const bytes = static_cast<const std::uint8_t*>(data);
    const std::size_t total = count * mStride;
    const std::size_t known = std::min(mUploaded.size(), total);
    std::size_t rangeStart = 0U;
    bool inRange = false;
    const auto flush = [&](const std::size_t end) {
      if (inRange) {
        device->UpdateGpuBuffer(
          *mBuffer, static_cast<std::uint32_t>(rangeStart / mStride), static_cast<std::uint32_t>((end - rangeStart) / mStride),
          bytes + rangeStart
        );
        inRange = false;
      }
    };
    for (std::size_t block = 0U; block < total; block += mBlockBytes) {
      const std::size_t end = std::min(block + mBlockBytes, total);
      const bool changed = end > known || std::memcmp(bytes + block, mUploaded.data() + block, end - block) != 0;
      if (changed && !inRange) {
        rangeStart = block;
        inRange = true;
      } else if (!changed) {
        flush(block);
      }
    }
    flush(total);
    mUploaded.assign(bytes, bytes + total);
    return mBuffer.get();
  }
} // namespace moho
