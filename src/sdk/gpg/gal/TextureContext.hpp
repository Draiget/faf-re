#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
  /**
   * VFTABLE: 0x00D42190
   * COL:     0x00E50428
   */
  class TextureContext
  {
  public:
    /**
     * Address: 0x008E7C80 (FUN_008E7C80)
     *
     * What it does:
     * Initializes texture-context metadata and string/control lanes to zero.
     */
    TextureContext();

    /**
     * Address: 0x00903B60 (FUN_00903B60)
     *
     * What it does:
     * Copies texture-context payload fields and shared-count ownership lanes.
     */
    void AssignFrom(const TextureContext& other);

    /**
     * Address: 0x008E7CC0 (FUN_008E7CC0, __imp_??1TextureContext@gal@gpg@@UAE@XZ)
     * Address: 0x008E7AE0 (FUN_008E7AE0, scalar deleting destructor thunk)
     *
     * What it does:
     * Releases texture payload shared-count ownership and tears down object state.
     */
    virtual ~TextureContext();

  public:
    void SetDataBuffer(const gpg::MemBuffer<const char>& data)
    {
      auto& sharedData = *reinterpret_cast<boost::shared_ptr<const char>*>(&dataArray_);
      sharedData = data.mData;
      dataBegin_ = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(data.mBegin));
      dataEnd_ = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(data.mEnd));
    }

    void ClearDataBuffer()
    {
      auto& sharedData = *reinterpret_cast<boost::shared_ptr<const char>*>(&dataArray_);
      sharedData.reset();
      dataBegin_ = 0;
      dataEnd_ = 0;
    }

    [[nodiscard]] std::size_t DataSizeBytes() const
    {
      if (dataEnd_ < dataBegin_) {
        return 0;
      }
      return static_cast<std::size_t>(dataEnd_ - dataBegin_);
    }

    std::uint32_t source_ = 0;                            // +0x04
    msvc8::string location_{};                            // +0x08
    void* dataArray_ = nullptr;                           // +0x24
    boost::detail::sp_counted_base* dataCount_ = nullptr; // +0x28
    std::uint32_t dataBegin_ = 0;                         // +0x2C
    std::uint32_t dataEnd_ = 0;                           // +0x30
    std::uint32_t type_ = 0;                              // +0x34
    std::uint32_t usage_ = 0;                             // +0x38
    std::uint32_t format_ = 0;                            // +0x3C
    std::uint32_t mipmapLevels_ = 0;                      // +0x40
    std::uint32_t reserved0x44_ = 0;                      // +0x44
    std::uint32_t width_ = 0;                             // +0x48
    std::uint32_t height_ = 0;                            // +0x4C
    std::uint32_t reserved0x50_ = 0;                      // +0x50
  };

  static_assert(offsetof(TextureContext, source_) == 0x04, "TextureContext::source_ offset must be 0x04");
  static_assert(offsetof(TextureContext, location_) == 0x08, "TextureContext::location_ offset must be 0x08");
  static_assert(offsetof(TextureContext, dataArray_) == 0x24, "TextureContext::dataArray_ offset must be 0x24");
  static_assert(offsetof(TextureContext, dataCount_) == 0x28, "TextureContext::dataCount_ offset must be 0x28");
  static_assert(offsetof(TextureContext, type_) == 0x34, "TextureContext::type_ offset must be 0x34");
  static_assert(offsetof(TextureContext, mipmapLevels_) == 0x40, "TextureContext::mipmapLevels_ offset must be 0x40");
  static_assert(offsetof(TextureContext, width_) == 0x48, "TextureContext::width_ offset must be 0x48");
  static_assert(offsetof(TextureContext, height_) == 0x4C, "TextureContext::height_ offset must be 0x4C");
  static_assert(sizeof(TextureContext) == 0x54, "TextureContext size must be 0x54");
} // namespace gpg::gal
