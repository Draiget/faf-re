#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"

namespace moho
{
  class ID3DTextureSheet;
  struct MwsfdPlaybackStateSubobj;

  class CMovie
  {
  public:
    using TextureSheetHandle = boost::SharedPtrRaw<ID3DTextureSheet>;

    /**
     * Address: 0x00874530 (FUN_00874530, Moho::CMovie::Dispose)
     *
     * What it does:
     * Tears down one active Sofdec playback handle, clears the movie texture
     * sheet shared-owner lane, and marks playback inactive.
     */
    void Dispose();

    /**
     * Address: 0x00874750 (FUN_00874750, Moho::CMovie::Func10)
     *
     * What it does:
     * Copies the movie texture shared-handle `(px,pi)` pair into caller output
     * storage and retains one shared owner reference.
     */
    TextureSheetHandle* GetTextureSheetHandle(TextureSheetHandle* outHandle);

    /**
     * Address: 0x00874780 (FUN_00874780, Moho::CMovie::GetWidth)
     *
     * What it does:
     * Returns the decoded movie frame width.
     */
    [[nodiscard]] std::int32_t GetWidth() const;

    /**
     * Address: 0x00874790 (FUN_00874790, Moho::CMovie::GetHeight)
     *
     * What it does:
     * Returns the decoded movie frame height.
     */
    [[nodiscard]] std::int32_t GetHeight() const;

  public:
    void* mPrimaryVtable = nullptr;      // +0x00
    void* mListenerVtable = nullptr;     // +0x04
    void* mListenerPrev = nullptr;       // +0x08
    void* mListenerNext = nullptr;       // +0x0C
    std::uint8_t mPlaybackEnabled = 0;   // +0x10
    std::uint8_t mReserved11_13[0x3]{};  // +0x11
    TextureSheetHandle mTextureSheet{};  // +0x14
    std::uint8_t mReserved1C_33[0x18]{}; // +0x1C
    std::int32_t mWidth = 0;             // +0x34
    std::int32_t mHeight = 0;            // +0x38
    std::uint8_t mReserved3C_7F[0x44]{}; // +0x3C
    MwsfdPlaybackStateSubobj* mPly = nullptr; // +0x80
  };

  static_assert(offsetof(CMovie, mTextureSheet) == 0x14, "CMovie::mTextureSheet offset must be 0x14");
  static_assert(offsetof(CMovie, mWidth) == 0x34, "CMovie::mWidth offset must be 0x34");
  static_assert(offsetof(CMovie, mHeight) == 0x38, "CMovie::mHeight offset must be 0x38");
  static_assert(offsetof(CMovie, mPly) == 0x80, "CMovie::mPly offset must be 0x80");
} // namespace moho
