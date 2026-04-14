#include "moho/movie/CMovie.h"
#include "moho/audio/SofdecRuntime.h"

namespace moho
{
  /**
   * Address: 0x00874530 (FUN_00874530, Moho::CMovie::Dispose)
   *
   * What it does:
   * Tears down one active Sofdec playback handle, clears the movie texture
   * sheet shared-owner lane, and marks playback inactive.
   */
  void CMovie::Dispose()
  {
    if (mPly != nullptr) {
      ::mwPlyDestroy(mPly);
    }

    mPly = nullptr;
    mTextureSheet.px = nullptr;
    mTextureSheet.release();
    mPlaybackEnabled = 0;
  }

  /**
   * Address: 0x00874750 (FUN_00874750, Moho::CMovie::Func10)
   *
   * What it does:
   * Copies the movie texture shared-handle pair into caller output storage and
   * increments the shared owner refcount.
   */
  CMovie::TextureSheetHandle* CMovie::GetTextureSheetHandle(TextureSheetHandle* const outHandle)
  {
    (void)boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(outHandle),
      reinterpret_cast<const boost::SharedCountPair*>(&mTextureSheet)
    );
    return outHandle;
  }

  /**
   * Address: 0x00874780 (FUN_00874780, Moho::CMovie::GetWidth)
   *
   * What it does:
   * Returns one cached movie frame width lane.
   */
  std::int32_t CMovie::GetWidth() const
  {
    return mWidth;
  }

  /**
   * Address: 0x00874790 (FUN_00874790, Moho::CMovie::GetHeight)
   *
   * What it does:
   * Returns one cached movie frame height lane.
   */
  std::int32_t CMovie::GetHeight() const
  {
    return mHeight;
  }
} // namespace moho
