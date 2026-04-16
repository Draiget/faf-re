#include "moho/movie/CMovie.h"

#include <cstring>
#include <new>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/audio/SofdecRuntime.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/DeviceExitListener.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

/**
 * Address: 0x00ACB220 (FUN_00ACB220, _mwPlyPause)
 *
 * What it does:
 * Sets one playback handle pause state (`0` play, `1` pause) and returns the
 * runtime status lane.
 */
std::int32_t mwPlyPause(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t paused);

/**
 * Address: 0x00ACAE40 (FUN_00ACAE40, _mwPlyIsPause)
 *
 * What it does:
 * Returns non-zero when playback is currently paused.
 */
std::int32_t mwPlyIsPause(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC9710 (FUN_00AC9710, _mwPlyGetSubtitle)
 *
 * What it does:
 * Writes subtitle text for the current frame into caller buffer and returns
 * non-zero when subtitle output was produced.
 */
std::int32_t mwPlyGetSubtitle(
  moho::MwsfdPlaybackStateSubobj* ply,
  char* subtitleBuffer,
  std::int32_t subtitleBufferBytes,
  std::int32_t* subtitleStats
);

/**
 * Address: 0x00B06E60 (FUN_00B06E60, _ADXM_WaitVsync)
 *
 * What it does:
 * Blocks until the next Sofdec playback vsync boundary. Declared `extern "C"`
 * to match the C-linkage stub provided in cri/sofdec/SofdecExternalStubs.cpp;
 * without this, the C++ mangling would not resolve at link time.
 */
extern "C" std::int32_t ADXM_WaitVsync();

/**
 * Address: 0x00ACC6E0 (FUN_00ACC6E0, _mwPlyFxCnvFrmARGB8888)
 *
 * What it does:
 * Converts one decoded MWSFD frame descriptor into ARGB8888 pixels in the
 * caller-provided output buffer.
 */
void mwPlyFxCnvFrmARGB8888(
  moho::MwsfdPlaybackStateSubobj* ply,
  const moho::MwsfdFrameInfo* frameInfo,
  void* outputBits
);

namespace moho
{
  extern bool debug_movie;
  extern int snd_index;

  namespace
  {
    constexpr std::int32_t kSofdecInterlacedCompoMode = 33;

    struct MoviePlaybackInfoDebugView
    {
      std::int32_t mReserved00 = 0; // +0x00
      std::int32_t skipDec = 0;     // +0x04
      std::int32_t skipDisp = 0;    // +0x08
      std::int32_t mReserved0C = 0; // +0x0C
      std::int32_t noSupply = 0;    // +0x10
    };

    static_assert(sizeof(MoviePlaybackInfoDebugView) == 0x14, "MoviePlaybackInfoDebugView size must be 0x14");
  }

  /**
   * Address: 0x00873C40 (FUN_00873C40)
   *
   * What it does:
   * Destroys one previous Sofdec playback handle when present and stores the
   * replacement handle into the same slot.
   */
  [[maybe_unused]] void ReplaceSofdecPlaybackHandle(
    MwsfdPlaybackStateSubobj* const replacement,
    MwsfdPlaybackStateSubobj** const slot
  )
  {
    if (slot == nullptr) {
      return;
    }

    if (*slot != nullptr) {
      ::mwPlyDestroy(*slot);
    }
    *slot = replacement;
  }

  /**
   * Address: 0x00873C60 (FUN_00873C60)
   *
   * What it does:
   * Destroys one Sofdec playback handle when present and clears the slot.
   */
  [[maybe_unused]] void DestroySofdecPlaybackHandleAndClearSlot(
    MwsfdPlaybackStateSubobj** const slot
  )
  {
    if (slot == nullptr) {
      return;
    }

    if (*slot != nullptr) {
      ::mwPlyDestroy(*slot);
    }
    *slot = nullptr;
  }

  /**
   * Address: 0x00873BE0 (FUN_00873BE0, ??0IMovie@Moho@@QAE@XZ)
   * Address: 0x00874980 (FUN_00874980, IMovie ctor lane)
   *
   * What it does:
   * Initializes one movie-playback base interface object.
   */
  IMovie::IMovie() = default;

  /**
   * Address: 0x00873CA0 (FUN_00873CA0, Moho::CMovie::CMovie)
   *
   * What it does:
   * Initializes movie state and links this object into the D3D device-event
   * listener ring when a device is already active.
   */
  CMovie::CMovie()
  {
    mDeviceListener.mLink.ListResetLinks();

    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      auto* const deviceListenerHead = reinterpret_cast<TDatListItem<CMovie, void>*>(
        reinterpret_cast<std::uint8_t*>(device) + 0x04
      );
      mDeviceListener.mLink.ListLinkBefore(deviceListenerHead);
    }
  }

  /**
   * Address: 0x00874CD0 (FUN_00874CD0, ??2CMovie@Moho@@QAE@@Z)
   *
   * What it does:
   * Allocates one `CMovie`, constructs it with constructor-failure cleanup,
   * writes the result into caller output storage, and returns that storage.
   */
  CMovie** CMovie::AllocateAndConstruct(CMovie** const outMovie)
  {
    CMovie* allocatedStorage = static_cast<CMovie*>(::operator new(sizeof(CMovie), std::nothrow));
    CMovie* constructedMovie = nullptr;
    if (allocatedStorage != nullptr) {
      try {
        constructedMovie = ::new (allocatedStorage) CMovie();
      } catch (...) {
        ::operator delete(allocatedStorage);
        throw;
      }
    }

    *outMovie = constructedMovie;
    return outMovie;
  }

  /**
   * Address: 0x00873F10 (FUN_00873F10, Moho::CMovie::CreateTexture)
   *
   * What it does:
   * Creates one dynamic texture sheet for movie playback and validates that a
   * backing texture handle exists.
   */
  bool CMovie::CreateTexture()
  {
    ID3DDeviceResources::DynamicTextureSheetHandle dynamicSheet{};
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    (void)resources->CreateDynamicTextureSheet2(dynamicSheet, mWidth, mHeight, 2);

    const boost::shared_ptr<ID3DTextureSheet> textureSheet =
      boost::static_pointer_cast<ID3DTextureSheet>(dynamicSheet);
    mTextureSheet.assign_retain(boost::SharedPtrRawFromSharedBorrow(textureSheet));

    bool textureReady = false;
    if (mTextureSheet.px != nullptr) {
      ID3DTextureSheet::TextureHandle textureHandle{};
      (void)mTextureSheet.px->GetTexture(textureHandle);
      textureReady = (textureHandle.get() != nullptr);
    }

    if (textureReady) {
      return true;
    }

    Dispose();
    return false;
  }

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
   * Address: 0x00874590 (FUN_00874590, Moho::CMovie::PlayMovie)
   *
   * What it does:
   * Logs one movie-start debug line and unpauses playback for active handles.
   */
  bool CMovie::PlayMovie()
  {
    gpg::Debugf("Playing movie %s: %i", mMovieName.c_str(), snd_index);
    if (mPly == nullptr) {
      return false;
    }
    return (::mwPlyPause(mPly, 0) != 0);
  }

  /**
   * Address: 0x008745D0 (FUN_008745D0, Moho::CMovie::Stop)
   *
   * What it does:
   * Pauses one active Sofdec playback handle.
   */
  bool CMovie::Stop()
  {
    if (mPly == nullptr) {
      return false;
    }
    return (::mwPlyPause(mPly, 1) != 0);
  }

  /**
   * Address: 0x008745F0 (FUN_008745F0)
   *
   * What it does:
   * Restarts playback from the retained movie-name lane and unpauses output.
   */
  void CMovie::StartMoviePlaybackFromName()
  {
    if (mPly == nullptr) {
      return;
    }

    ::mwPlyStartFname(mPly, mMovieName.c_str());
    (void)::mwPlyPause(mPly, 0);
  }

  /**
   * Address: 0x00874660 (FUN_00874660)
   *
   * What it does:
   * Runs one per-frame movie playback tick, including frame upload and
   * subtitle refresh lanes.
   */
  void CMovie::UpdatePlaybackFrame()
  {
    if ((mPly == nullptr) || (::mwPlyIsPause(mPly) != 0) || (mFrameAdvanceBlocked != 0)) {
      return;
    }

    (void)::ADXM_WaitVsync();
    UploadCurrentFrameToTexture();

    std::int32_t subtitleStats[5]{};
    const std::int32_t subtitleBufferBytes = static_cast<std::int32_t>(mSubtitleBuffer.mEnd - mSubtitleBuffer.mBegin);
    char* const subtitleBuffer = mSubtitleBuffer.GetPtr(0, 0);
    if (::mwPlyGetSubtitle(mPly, subtitleBuffer, subtitleBufferBytes, subtitleStats) != 0) {
      mSubtitleText = mSubtitleBuffer.GetPtr(0, 0);
    } else {
      mSubtitleText.clear();
    }

    if (debug_movie) {
      MoviePlaybackInfoDebugView playbackInfo{};
      (void)::mwPlyGetPlyInf(mPly, reinterpret_cast<std::int32_t*>(&playbackInfo));
      gpg::Debugf(
        "skip_disp %i, no_supply %i, skip_dec %i",
        playbackInfo.skipDisp,
        playbackInfo.noSupply,
        playbackInfo.skipDec
      );
    }
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

  /**
   * Address: 0x008747A0 (FUN_008747A0)
   *
   * What it does:
   * Transfers one decoded Sofdec frame into the movie output texture and
   * releases the current frame slot.
   */
  void CMovie::UploadCurrentFrameToTexture()
  {
    MwsfdFrameInfo frameInfo{};
    ::mwPlyGetCurFrm(mPly, &frameInfo);
    if (frameInfo.bufferAddress == 0) {
      return;
    }

    ID3DTextureSheet* const textureSheet = mTextureSheet.px;
    std::uint32_t outputPitch = 0;
    void* outputBits = nullptr;
    if (textureSheet->Lock(&outputPitch, &outputBits)) {
      Wm3::Vector3f textureDimensions{};
      (void)textureSheet->GetDimensions(&textureDimensions);
      const std::int32_t textureHeight = static_cast<std::int32_t>(textureDimensions.y);
      const std::int32_t outputHeight = (::mwPlyFxGetCompoMode(mPly) == kSofdecInterlacedCompoMode)
        ? (textureHeight / 2)
        : textureHeight;

      ::mwPlyFxSetOutBufSize(mPly, static_cast<std::int32_t>(outputPitch), outputHeight);
      ::mwPlyFxCnvFrmARGB8888(mPly, &frameInfo, outputBits);
      (void)textureSheet->Unlock();
    }

    ::mwPlyRelCurFrm(mPly);
  }

  /**
   * Address: 0x00874890 (FUN_00874890)
   *
   * SD3DDeviceEvent const &
   *
   * What it does:
   * Handles one movie texture lifecycle event lane from the D3D listener path:
   * release-on-exit and rebuild-and-clear-on-init.
   */
  void CMovie::OnDeviceEvent(const SD3DDeviceEvent& event)
  {
    if (event.mEventType == 1u) {
      mTextureSheet.release();
      mFrameAdvanceBlocked = 1;
      return;
    }

    if (event.mEventType != 0u) {
      return;
    }

    mFrameAdvanceBlocked = 0;
    if (!CreateTexture() || mTextureSheet.px == nullptr) {
      return;
    }

    Wm3::Vector3f textureDimensions{};
    (void)mTextureSheet.px->GetDimensions(&textureDimensions);

    std::uint32_t rowPitchBytes = 0;
    void* rowBits = nullptr;
    if (!mTextureSheet.px->Lock(&rowPitchBytes, &rowBits)) {
      return;
    }

    std::int32_t remainingRows = static_cast<std::int32_t>(textureDimensions.y);
    auto* rowCursor = static_cast<std::uint8_t*>(rowBits);
    while (remainingRows != 0) {
      std::memset(rowCursor, 0, rowPitchBytes);
      rowCursor += rowPitchBytes;
      --remainingRows;
    }

    (void)mTextureSheet.px->Unlock();
  }
} // namespace moho
