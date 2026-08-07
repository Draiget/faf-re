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
     * Address: 0x00873D80 (FUN_00873D80, ??1CMovie@Moho@@QAE@@Z)
     * Mangled: ??1CMovie@Moho@@QAE@@Z
     *
     * What it does:
     * Unlinks this movie from the live D3D device-event listener ring, tears down
     * active Sofdec playback and the movie texture-sheet owner, releases the
     * subtitle/work buffers and name strings, then runs base listener/IMovie
     * teardown.
     */
    ~CMovie() override;

    /**
     * Address: 0x00874CD0 (FUN_00874CD0, ??2CMovie@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates storage for one `CMovie`, constructs it, and stores the
     * resulting pointer in caller-provided output storage.
     */
    static CMovie** AllocateAndConstruct(CMovie** outMovie);

    /**
     * Address: 0x00873F10 (FUN_00873F10, Moho::CMovie::CreateTexture)
     *
     * What it does:
     * Builds one dynamic movie texture sheet sized to `(mWidth,mHeight)` and
     * verifies that backing texture allocation succeeded.
     */
    bool CreateTexture();

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

    // ---------------------------------------------------------------------
    // Virtual playback interface - slots 1..14 of ??_7CMovie@Moho@@6B@
    // (0x00E494E4). The UI drives a movie only through these, so DECLARATION
    // ORDER HERE IS THE VTABLE LAYOUT and must not be rearranged: MSVC
    // assigns slots in declaration order, and CMauiMovie dispatches by slot.
    // Slot 0 is the destructor above. Verified against the vtable bytes in
    // bin/2025.7.1/ForgedAlliance.exe, and against two call sites that pin
    // absolute offsets: FUN_0079FCF0 reads [vptr+0x18] for IsLoaded (slot 6)
    // and FUN_0079FE50 reads [vptr+0x2C] for GetFrameCount (slot 11).
    // ---------------------------------------------------------------------

    /**
     * Address: 0x00874060 (FUN_00874060, Moho::CMovie::OpenMovie) - vtable slot 1
     *
     * IDA signature:
     * char __thiscall Moho::CMovie::OpenMovie(Moho::CMovie *this, const char *path);
     *
     * What it does:
     * Opens a Sofdec (.sfd) movie: resolves the path through the file wait-handle
     * set, reads and validates the SFD header, records frame count/rate, allocates
     * the Sofdec work buffer, creates the player, waits out the prepare status
     * loop, builds the movie texture, allocates the subtitle buffer, and uploads
     * the first frame. Returns true on success.
     */
    virtual bool OpenMovie(const char* path);

    /**
     * Address: 0x00874530 (FUN_00874530, Moho::CMovie::Dispose) - vtable slot 2
     *
     * What it does:
     * Tears down one active Sofdec playback handle, clears the movie texture
     * sheet shared-owner lane, and marks playback inactive.
     */
    virtual void Dispose();

    /**
     * Address: 0x00874590 (FUN_00874590, Moho::CMovie::PlayMovie) - vtable slot 3
     *
     * What it does:
     * Logs one movie-start debug line and unpauses playback when a Sofdec
     * handle is active.
     */
    virtual bool PlayMovie();

    /**
     * Address: 0x008745D0 (FUN_008745D0, Moho::CMovie::Stop) - vtable slot 4
     *
     * What it does:
     * Pauses one active Sofdec playback handle.
     */
    virtual bool Stop();

    /**
     * Address: 0x008745F0 (FUN_008745F0) - vtable slot 5
     *
     * What it does:
     * Starts playback for the retained movie-name lane and clears pause state.
     */
    virtual void StartMoviePlaybackFromName();

    /**
     * Address: 0x00874630 (FUN_00874630) - vtable slot 6
     *
     * IDA signature:
     * char __thiscall Moho::CMovie::Func4(_BYTE *this);
     *
     * What it does:
     * Reports whether a movie is loaded and playable, which is exactly the
     * playback-enabled lane `OpenMovie` sets once the player, texture and
     * subtitle buffer are all in place.
     */
    [[nodiscard]] virtual bool IsLoaded();

    /**
     * Address: 0x00874640 (FUN_00874640) - vtable slot 7
     *
     * IDA signature:
     * bool __thiscall Moho::CMovie::Func5(Moho::CMovie *this);
     *
     * What it does:
     * Reports whether the Sofdec player has reached playback-end status (3).
     */
    [[nodiscard]] virtual bool HasPlaybackFinished();

    /**
     * Address: 0x00874660 (FUN_00874660) - vtable slot 8
     *
     * What it does:
     * Performs one per-frame playback tick: waits vsync, uploads the current
     * frame, refreshes subtitle text, and emits optional debug counters.
     */
    virtual void UpdatePlaybackFrame();

    /**
     * Address: 0x00874780 (FUN_00874780, Moho::CMovie::GetWidth) - vtable slot 9
     *
     * What it does:
     * Returns the decoded movie frame width.
     */
    [[nodiscard]] virtual std::int32_t GetWidth() const;

    /**
     * Address: 0x00874790 (FUN_00874790, Moho::CMovie::GetHeight) - vtable slot 10
     *
     * What it does:
     * Returns the decoded movie frame height.
     */
    [[nodiscard]] virtual std::int32_t GetHeight() const;

    /**
     * Address: 0x00874870 (FUN_00874870) - vtable slot 11
     *
     * IDA signature:
     * int __thiscall Moho::CMovie::Func7(Moho::CMovie *this);
     *
     * What it does:
     * Returns the frame count read out of the SFD header.
     */
    [[nodiscard]] virtual std::int32_t GetFrameCount();

    /**
     * Address: 0x00874880 (FUN_00874880) - vtable slot 12
     *
     * IDA signature:
     * double __thiscall Moho::CMovie::Func8(Moho::CMovie *this);
     *
     * What it does:
     * Returns the frame rate read out of the SFD header. The decompiler shows
     * a double because the value comes back on the x87 stack; the field and
     * the load (`fld dword ptr [ecx+40h]`) are both single precision.
     */
    [[nodiscard]] virtual float GetFrameRate();

    /**
     * Address: 0x00874740 (FUN_00874740, Moho::CMovie::Func9) - vtable slot 13
     *
     * IDA signature:
     * char *__thiscall Moho::CMovie::Func9(Moho::CMovie *this);
     *
     * What it does:
     * Hands out the subtitle string lane itself, which `UpdatePlaybackFrame`
     * refreshes each tick. The caller does not own it.
     */
    [[nodiscard]] virtual const msvc8::string* GetSubtitleText();

    /**
     * Address: 0x00874750 (FUN_00874750, Moho::CMovie::Func10) - vtable slot 14
     *
     * What it does:
     * Copies the movie texture shared-handle `(px,pi)` pair into caller output
     * storage and retains one shared owner reference.
     *
     * The out parameter is a real `boost::shared_ptr`, not the raw pair the
     * member lane uses: the only caller, `CMauiMovie::DoRender`, hands the
     * result straight to `CD3DPrimBatcher::SetTexture(shared_ptr<...>)`, which
     * the binary calls at 0x00438870 by pushing the pair as two words.
     */
    virtual boost::shared_ptr<ID3DTextureSheet>* GetTextureSheetHandle(
      boost::shared_ptr<ID3DTextureSheet>* outHandle
    );

  public:
    DeviceEventListenerLane mDeviceListener{}; // +0x04
    std::uint8_t mPlaybackEnabled = 0;   // +0x10
    std::uint8_t mReserved11_13[0x3]{};  // +0x11
    TextureSheetHandle mTextureSheet{};  // +0x14
    gpg::MemBuffer<char> mSubtitleBuffer{}; // +0x1C
    boost::SharedPtrRaw<void> mWorkbuffer{}; // +0x2C (Sofdec work buffer shared owner)
    std::int32_t mWidth = 0;             // +0x34
    std::int32_t mHeight = 0;            // +0x38
    std::int32_t mFrameCount = 0;        // +0x3C
    float mFrameRate = 0.0f;             // +0x40
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
  static_assert(offsetof(CMovie, mWorkbuffer) == 0x2C, "CMovie::mWorkbuffer offset must be 0x2C");
  static_assert(offsetof(CMovie, mWidth) == 0x34, "CMovie::mWidth offset must be 0x34");
  static_assert(offsetof(CMovie, mHeight) == 0x38, "CMovie::mHeight offset must be 0x38");
  static_assert(offsetof(CMovie, mFrameCount) == 0x3C, "CMovie::mFrameCount offset must be 0x3C");
  static_assert(offsetof(CMovie, mFrameRate) == 0x40, "CMovie::mFrameRate offset must be 0x40");
  static_assert(offsetof(CMovie, mMovieName) == 0x44, "CMovie::mMovieName offset must be 0x44");
  static_assert(offsetof(CMovie, mSubtitleText) == 0x60, "CMovie::mSubtitleText offset must be 0x60");
  static_assert(offsetof(CMovie, mFrameAdvanceBlocked) == 0x7C, "CMovie::mFrameAdvanceBlocked offset must be 0x7C");
  static_assert(offsetof(CMovie, mPly) == 0x80, "CMovie::mPly offset must be 0x80");
  static_assert(sizeof(CMovie) == 0x84, "CMovie size must be 0x84");
} // namespace moho
