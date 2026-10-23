#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
  /**
   * FAF addition: the gal texture format of four 32-bit floats per texel
   * (`D3DFMT_A32B32G32R32F`, which the D3D9 backend's format table pairs with
   * 18). The skinning palette texture uses it.
   */
  inline constexpr std::uint32_t kTextureFormatFloat4 = 18u;

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
     * Address: 0x008E7A40 (FUN_008E7A40, gpg::gal::TextureContext::Copy)
     *
     * What it does:
     * Copy-constructs one texture-context payload, cloning the location string
     * lane and incrementing shared-data ownership.
     */
    TextureContext(const TextureContext& other);

    /**
     * Address: 0x008E7D60 (FUN_008E7D60, ??0TextureContext@gal@gpg@@QAE@PBDIHH@Z)
     *
     * What it does:
     * Initializes archive-backed texture source metadata from one location
     * string plus explicit format and dimensions.
     */
    TextureContext(const char* location, std::uint32_t format, std::uint32_t width, std::uint32_t height);

    /**
     * Address: 0x008E7DF0 (FUN_008E7DF0)
     *
     * What it does:
     * Initializes archive-backed texture source metadata from one location
     * string, one retained shared data buffer view, and explicit format/dimensions.
     */
    TextureContext(
      const char* location,
      const gpg::MemBuffer<const char>& data,
      std::uint32_t format,
      std::uint32_t width,
      std::uint32_t height
    );

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
    void SetDataBuffer(const gpg::MemBuffer<const char>& data);
    void ClearDataBuffer() noexcept;
    [[nodiscard]] std::size_t DataSizeBytes() const noexcept;

    std::uint32_t source_ = 0;                            // +0x04
    msvc8::string location_{};                            // +0x08
    gpg::MemBuffer<const char> dataBuffer_{};             // +0x24, shared owner and native pointer bounds
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
  static_assert(offsetof(TextureContext, dataBuffer_) == 0x24, "TextureContext::dataBuffer_ offset must be 0x24");
  static_assert(sizeof(gpg::MemBuffer<const char>) == 0x10, "TextureContext data buffer size must be 0x10");
  static_assert(offsetof(TextureContext, type_) == 0x34, "TextureContext::type_ offset must be 0x34");
  static_assert(offsetof(TextureContext, mipmapLevels_) == 0x40, "TextureContext::mipmapLevels_ offset must be 0x40");
  static_assert(offsetof(TextureContext, width_) == 0x48, "TextureContext::width_ offset must be 0x48");
  static_assert(offsetof(TextureContext, height_) == 0x4C, "TextureContext::height_ offset must be 0x4C");
  static_assert(sizeof(TextureContext) == 0x54, "TextureContext size must be 0x54");
} // namespace gpg::gal
