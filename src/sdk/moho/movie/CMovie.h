#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class CMovie;
  class ID3DTextureSheet;
  struct MwsfdPlaybackStateSubobj;
  struct SD3DDeviceEvent;

  struct DeviceEventListenerLane
  {
    void* mVtable = nullptr;            // +0x00
    TDatListItem<CMovie, void> mLink{}; // +0x04
  };

  static_assert(sizeof(DeviceEventListenerLane) == 0x0C, "DeviceEventListenerLane size must be 0x0C");

  class IMovie
  {
  public:
    /**
     * Address: 0x00873BE0 (FUN_00873BE0, ??0IMovie@Moho@@QAE@XZ)
     * Address: 0x00874980 (FUN_00874980, IMovie ctor lane)
     *
     * What it does:
     * Initializes one movie-playback base interface object.
     */
    IMovie();

    virtual ~IMovie() = default;
  };

  static_assert(sizeof(IMovie) == 0x04, "IMovie size must be 0x04");

  class CMovie : public IMovie
  {
  public:
    using TextureSheetHandle = boost::SharedPtrRaw<ID3DTextureSheet>;

    /**
     * Address: 0x00873CA0 (FUN_00873CA0, Moho::CMovie::CMovie)
     *
     * What it does:
     * Initializes movie playback state and links into the D3D device listener
     * ring when a device is already available.
     */
    CMovie();

    /**
     * Address: 0x00874CD0 (FUN_00874CD0, ??2CMovie@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates storage for one `CMovie`, constructs it, and stores the
     * resulting pointer in caller-provided output storage.
     */
    static CMovie** AllocateAndConstruct(CMovie** outMovie);

    /**
     * Address: 0x00874530 (FUN_00874530, Moho::CMovie::Dispose)
     *
     * What it does:
     * Tears down one active Sofdec playback handle, clears the movie texture
     * sheet shared-owner lane, and marks playback inactive.
     */
    void Dispose();

    /**
     * Address: 0x00873F10 (FUN_00873F10, Moho::CMovie::CreateTexture)
     *
     * What it does:
     * Builds one dynamic movie texture sheet sized to `(mWidth,mHeight)` and
     * verifies that backing texture allocation succeeded.
     */
    bool CreateTexture();

    /**
     * Address: 0x00874590 (FUN_00874590, Moho::CMovie::PlayMovie)
     *
     * What it does:
     * Logs one movie-start debug line and unpauses playback when a Sofdec
     * handle is active.
     */
    bool PlayMovie();

    /**
     * Address: 0x008745D0 (FUN_008745D0, Moho::CMovie::Stop)
     *
     * What it does:
     * Pauses one active Sofdec playback handle.
     */
    bool Stop();

    /**
     * Address: 0x008745F0 (FUN_008745F0)
     *
     * What it does:
     * Starts playback for the retained movie-name lane and clears pause state.
     */
    void StartMoviePlaybackFromName();

    /**
     * Address: 0x00874660 (FUN_00874660)
     *
     * What it does:
     * Performs one per-frame playback tick: waits vsync, uploads the current
     * frame, refreshes subtitle text, and emits optional debug counters.
     */
    void UpdatePlaybackFrame();

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

    /**
     * Address: 0x008747A0 (FUN_008747A0)
     *
     * What it does:
     * Transfers the current decoded Sofdec frame into the movie texture-sheet
     * output buffer and releases the frame slot.
     */
    void UploadCurrentFrameToTexture();

    /**
     * Address: 0x00874890 (FUN_00874890)
     *
     * SD3DDeviceEvent const &
     *
     * What it does:
     * Handles D3D device-event lanes for movie playback texture ownership by
     * releasing texture state on exit and rebuilding/clearing texture content
     * on init.
     */
    void OnDeviceEvent(const SD3DDeviceEvent& event);

  public:
    DeviceEventListenerLane mDeviceListener{}; // +0x04
    std::uint8_t mPlaybackEnabled = 0;   // +0x10
    std::uint8_t mReserved11_13[0x3]{};  // +0x11
    TextureSheetHandle mTextureSheet{};  // +0x14
    gpg::MemBuffer<char> mSubtitleBuffer{}; // +0x1C
    std::uint8_t mReserved2C_33[0x08]{};    // +0x2C
    std::int32_t mWidth = 0;             // +0x34
    std::int32_t mHeight = 0;            // +0x38
    std::uint8_t mReserved3C_43[0x08]{}; // +0x3C
    msvc8::string mMovieName{};          // +0x44
    msvc8::string mSubtitleText{};       // +0x60
    std::uint8_t mFrameAdvanceBlocked = 0; // +0x7C
    std::uint8_t mReserved7D_7F[0x03]{}; // +0x7D
    MwsfdPlaybackStateSubobj* mPly = nullptr; // +0x80
  };

  static_assert(offsetof(CMovie, mDeviceListener) == 0x04, "CMovie::mDeviceListener offset must be 0x04");
  static_assert(offsetof(CMovie, mDeviceListener.mLink) == 0x08, "CMovie::mDeviceListener.mLink offset must be 0x08");
  static_assert(offsetof(CMovie, mTextureSheet) == 0x14, "CMovie::mTextureSheet offset must be 0x14");
  static_assert(offsetof(CMovie, mSubtitleBuffer) == 0x1C, "CMovie::mSubtitleBuffer offset must be 0x1C");
  static_assert(offsetof(CMovie, mWidth) == 0x34, "CMovie::mWidth offset must be 0x34");
  static_assert(offsetof(CMovie, mHeight) == 0x38, "CMovie::mHeight offset must be 0x38");
  static_assert(offsetof(CMovie, mMovieName) == 0x44, "CMovie::mMovieName offset must be 0x44");
  static_assert(offsetof(CMovie, mSubtitleText) == 0x60, "CMovie::mSubtitleText offset must be 0x60");
  static_assert(offsetof(CMovie, mFrameAdvanceBlocked) == 0x7C, "CMovie::mFrameAdvanceBlocked offset must be 0x7C");
  static_assert(offsetof(CMovie, mPly) == 0x80, "CMovie::mPly offset must be 0x80");
  static_assert(sizeof(CMovie) == 0x84, "CMovie size must be 0x84");
} // namespace moho
