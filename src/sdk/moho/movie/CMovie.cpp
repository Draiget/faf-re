#include "moho/movie/CMovie.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
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
// extern "C" to match the definition's linkage, the same way mwPlyGetHdrInf
// below does. The Sofdec side declares this inside an extern "C" block, so it
// exports _mwPlyFxCnvFrmARGB8888; without this the call would ask for
// ?mwPlyFxCnvFrmARGB8888@@YAX... and go unresolved.
extern "C" void mwPlyFxCnvFrmARGB8888(
  moho::MwsfdPlaybackStateSubobj* ply,
  const moho::MwsfdFrameInfo* frameInfo,
  void* outputBits
);

/**
 * Address: 0x00AC8DF0 (FUN_00AC8DF0, _mwPlyGetHdrInf)
 *
 * What it does:
 * Parses one Sofdec .sfd header block into the caller header-info view.
 */
// extern "C" to match the definition's linkage. Without it this asks the
// linker for ?mwPlyGetHdrInf@@YAHPBDHPAX@Z while StartupHelpers.cpp exports
// the C name, so the call went unresolved and /FORCE bound it to the image
// base - a jump to address 0 the moment a movie is opened.
extern "C" std::int32_t mwPlyGetHdrInf(const char* buffer, std::int32_t size, void* outHeaderInfo);

// mwPlyCalcWorkCprmSfd / mwPlyCreateSofdec are declared with their real
// parameter type in moho/audio/SofdecRuntime.h. They used to be declared here
// taking `void*`, which gave them a different C++ mangling from the recovered
// definitions and left both unresolved.

/**
 * Address: 0x00AC9F60 (FUN_00AC9F60, _mwPlySetFrmSync)
 *
 * What it does:
 * Sets the frame-sync mode on one Sofdec playback handle.
 */
extern "C" void mwPlySetFrmSync(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t mode);

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

    // CRI Sofdec SDK external struct views (not engine objects). Field offsets
    // are taken from FUN_00874060.asm and mirror moho::SofdecHeaderInfoRuntimeView
    // in StartupHelpers.cpp, with the video width/height/composition lanes named.
    struct SofdecSfdHeaderInfo
    {
      std::int32_t headerValid = 0;        // +0x00
      std::int32_t streamType = 0;         // +0x04 (1 or 3 == valid SFD)
      std::int32_t videoWidth = 0;         // +0x08
      std::int32_t videoHeight = 0;        // +0x0C
      std::int32_t frameRateTimes1000 = 0; // +0x10
      std::int32_t frameCount = 0;         // +0x14
      std::int32_t compositionMode = 0;    // +0x18
      std::uint8_t reserved1C[0x10]{};     // +0x1C
    };

    static_assert(sizeof(SofdecSfdHeaderInfo) == 0x2C, "SofdecSfdHeaderInfo size must be 0x2C");

    // _mwsfcre_MallocTab create-params; the binary memsets 0x30 bytes then fills.
    // The create-parameter layout is shared with the recovered mwsfcre create
    // path, so it lives in moho/audio/SofdecRuntime.h rather than being
    // duplicated here.
    using SofdecCreateParams = ::moho::MwsfcreCreateParams;

    constexpr std::int32_t kSofdecStatFailed = 4;
    constexpr std::int32_t kSofdecStatPreparing = 1;
    /** Sofdec player has run the movie to its end; the UI polls for this. */
    constexpr std::int32_t kSofdecStatPlayEnd = 3;
    constexpr std::int32_t kMovieMaxBitsPerSecond = 6000000;
    constexpr std::int32_t kSofdecHeaderProbeBytes = 5000;
  }

  /**
   * Address: 0x00873C40 (FUN_00873C40)
   *
   * What it does:
   * Destroys one previous Sofdec playback handle when present and stores the
   * replacement handle into the same slot.
   */
  void ReplaceSofdecPlaybackHandle(
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
    mListenerLink.ListResetLinks();

    // The device's listener ring is its own Broadcaster base, which is the
    // +0x04 the binary indexes. Reaching it as a base rather than by offset
    // arithmetic is the same address and keeps the types honest.
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(device));
    }
  }

  /**
   * Address: 0x00873D80 (FUN_00873D80, ??1CMovie@Moho@@QAE@@Z)
   * Mangled: ??1CMovie@Moho@@QAE@@Z
   *
   * IDA signature:
   * Moho::TDatListItem_Listener *__stdcall Moho::CMovie::~CMovie(Moho::CMovie *this);
   *
   * What it does:
   * Unlinks this movie from the active D3D device-event listener ring, tears
   * down live playback and owned buffers/strings, then runs base listener and
   * IMovie subobject teardown.
   */
  CMovie::~CMovie()
  {
    // [0x00873DB1-0x00873DD5] While a device is active, unlink this listener
    // from the live device-event ring. The redundant D3D_GetDevice() call
    // mirrors the binary (its result is unused; intrusive unlink is
    // self-contained and does not need the ring head).
    if (D3D_GetDevice() != nullptr) {
      (void)D3D_GetDevice();
      mListenerLink.ListUnlink();
    }

    // [0x00873DDA] Tear down active Sofdec playback + texture-sheet owner lane.
    Dispose();

    // [0x00873DDF-0x00873DF4] Destroy any remaining Sofdec playback handle.
    if (mPly != nullptr) {
      ::mwPlyDestroy(mPly);
    }
    mPly = nullptr;

    // Member subobject teardown, in binary (reverse-declaration) order:
    // [0x00873DFA] free subtitle-text heap buffer (base +0x60).
    mSubtitleText.tidy(true, 0U);
    // [0x00873E1A] free movie-name heap buffer (base +0x44).
    mMovieName.tidy(true, 0U);
    // [0x00873E3A] release Sofdec work-buffer shared owner (+0x2C).
    mWorkbuffer.release();
    // [0x00873E70] release subtitle mem-buffer shared owner (+0x1C).
    mSubtitleBuffer.Reset();
    // [0x00873EA6] release movie texture-sheet shared owner (+0x14). Already
    // null after Dispose(), so this matches the skipped binary block.
    mTextureSheet.release();

    // [0x00873EDF-0x00873EF9] ~Listener<SD3DDeviceEvent const&> base subobject:
    // unlink this listener node from its ring (no-op when the conditional
    // unlink above already ran; the real unlink when no device was present).
    // This must happen before the base subobject goes away: a node left in the
    // device ring outlives the movie and the next device event dispatches
    // through freed memory.
    mListenerLink.ListUnlink();
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
   * Address: 0x00874060 (FUN_00874060, Moho::CMovie::OpenMovie)
   *
   * What it does:
   * Resolves and opens a Sofdec .sfd movie: reads a 5000-byte header, parses and
   * validates the SFD header, records frame count/rate, allocates the Sofdec work
   * buffer, creates the player, waits out the prepare status loop, builds the
   * movie texture, allocates the subtitle buffer, and uploads the first frame.
   */
  bool CMovie::OpenMovie(const char* const path)
  {
    gpg::Debugf("OpenMovie %s: %i", path, snd_index);
    if (path == nullptr || *path == '\0') {
      return false;
    }

    // Resolve the movie path through the process file wait-handle set.
    FWaitHandleSet* const waitSet = FILE_GetWaitHandleSet();
    msvc8::string resolvedPath{};
    waitSet->mHandle->FindFile(&resolvedPath, path, nullptr);
    if (resolvedPath.empty()) {
      gpg::Warnf("Movie \"%s\" doesn't exist.", path);
      return false;
    }

    mMovieName = resolvedPath;

    // Open the resolved file and read up to the 5000-byte Sofdec header. The
    // stream is closed as soon as the header is parsed (before the create work).
    msvc8::auto_ptr<gpg::Stream> movieStream = DISK_OpenFileRead(mMovieName.c_str());
    gpg::Stream* const stream = movieStream.get();

    char headerBuffer[5004] = {};
    const std::size_t buffered = static_cast<std::size_t>(stream->mReadEnd - stream->mReadHead);
    if (buffered < static_cast<std::size_t>(kSofdecHeaderProbeBytes)) {
      (void)stream->VirtRead(headerBuffer, static_cast<std::size_t>(kSofdecHeaderProbeBytes));
    } else {
      std::memcpy(headerBuffer, stream->mReadHead, static_cast<std::size_t>(kSofdecHeaderProbeBytes));
      stream->mReadHead += kSofdecHeaderProbeBytes;
    }

    SofdecSfdHeaderInfo header{};
    std::memset(&header, 0, sizeof(header));
    (void)::mwPlyGetHdrInf(headerBuffer, kSofdecHeaderProbeBytes, &header);

    if ((header.streamType != 3 && header.streamType != 1) || header.headerValid == 0) {
      gpg::Warnf("%s is not a valid SFD file.", path);
      Dispose();
      return false;
    }
    movieStream.reset(nullptr);

    mFrameRate = static_cast<float>(header.frameRateTimes1000) * 0.001f;
    mFrameCount = header.frameCount;

    SofdecCreateParams createParams{};
    std::memset(&createParams, 0, sizeof(createParams));
    createParams.ftype = header.streamType;
    createParams.bufferFormat = header.compositionMode;
    createParams.maxBitsPerSecond = kMovieMaxBitsPerSecond;
    createParams.maxWidth = header.videoWidth;
    createParams.maxHeight = header.videoHeight;
    createParams.framePoolWork = 2;
    createParams.maxStreams = 1;
    createParams.outerFramePoolNum = 0;

    const std::int32_t workSize = ::mwPlyCalcWorkCprmSfd(&createParams);
    createParams.workSize = workSize;
    if (workSize <= 0) {
      gpg::Warnf("Failed to get a valid worksize for %s", path);
      return false;
    }

    void* const workBuffer = std::malloc(static_cast<std::size_t>(workSize));
    mWorkbuffer = boost::SharedPtrRaw<void>::with_deleter(workBuffer, &std::free);
    createParams.work = mWorkbuffer.px;
    if (mWorkbuffer.px == nullptr) {
      gpg::Warnf("Failed to get a valid workbuffer for %s", path);
      return false;
    }
    std::memset(mWorkbuffer.px, 0, static_cast<std::size_t>(createParams.workSize));

    // Create the Sofdec player, destroying any prior handle first.
    MwsfdPlaybackStateSubobj* const created = ::mwPlyCreateSofdec(&createParams);
    ReplaceSofdecPlaybackHandle(created, &mPly);
    if (created == nullptr || ::mwPlyGetStat(created) == kSofdecStatFailed) {
      gpg::Warnf("mwPlyCreateSofdec failed for movie %s", path);
      Dispose();
      return false;
    }

    ::mwPlySetFrmSync(mPly, 0);
    (void)::mwPlyPause(mPly, 1);

    ::mwPlyStartFname(mPly, mMovieName.c_str());
    if (::mwPlyGetStat(mPly) == kSofdecStatFailed) {
      gpg::Warnf("initial mwPlyGetStat failed for movie %s", path);
      Dispose();
      return false;
    }

    // Cache decoded dimensions (height halved for interlaced composition mode).
    mWidth = createParams.maxWidth;
    mHeight = (::mwPlyFxGetCompoMode(mPly) == kSofdecInterlacedCompoMode)
      ? (createParams.maxHeight / 2)
      : createParams.maxHeight;

    if (!CreateTexture()) {
      gpg::Warnf("CreateTexture failed for movie %s", path);
      Dispose();
      return false;
    }

    // Prepare loop: pump vsync/exec until the player leaves the preparing state.
    gpg::Debugf("Preparing movie %s: %i", path, snd_index);
    std::int32_t stat = ::mwPlyGetStat(mPly);
    if (stat == kSofdecStatFailed) {
      gpg::Warnf("mwPlyGetStat failed for movie %s", path);
      Dispose();
      return false;
    }
    while (stat == kSofdecStatPreparing) {
      (void)::ADXM_WaitVsync();
      (void)::ADXM_ExecMain();
      gpg::Debugf("Preparing movie %s: %i", path, snd_index);
      stat = ::mwPlyGetStat(mPly);
      if (stat == kSofdecStatFailed) {
        gpg::Warnf("mwPlyGetStat failed for movie %s", path);
        Dispose();
        return false;
      }
    }

    mSubtitleBuffer = gpg::AllocMemBuffer(256);
    UploadCurrentFrameToTexture();
    mPlaybackEnabled = 1;
    return true;
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
  boost::shared_ptr<ID3DTextureSheet>* CMovie::GetTextureSheetHandle(
    boost::shared_ptr<ID3DTextureSheet>* const outHandle
  )
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
   * Address: 0x00874630 (FUN_00874630) - vtable slot 6
   *
   * IDA signature:
   * char __thiscall Moho::CMovie::Func4(_BYTE *this);
   *
   * What it does:
   * Reports whether a movie is loaded and playable. That is exactly the
   * playback-enabled lane, which OpenMovie raises only once the player, the
   * texture sheet and the subtitle buffer are all in place.
   */
  bool CMovie::IsLoaded()
  {
    return mPlaybackEnabled != 0;
  }

  /**
   * Address: 0x00874640 (FUN_00874640) - vtable slot 7
   *
   * IDA signature:
   * bool __thiscall Moho::CMovie::Func5(Moho::CMovie *this);
   *
   * What it does:
   * Reports whether the Sofdec player has reached playback-end status.
   */
  bool CMovie::HasPlaybackFinished()
  {
    return ::mwPlyGetStat(mPly) == kSofdecStatPlayEnd;
  }

  /**
   * Address: 0x00874870 (FUN_00874870) - vtable slot 11
   *
   * IDA signature:
   * int __thiscall Moho::CMovie::Func7(Moho::CMovie *this);
   *
   * What it does:
   * Returns the frame count read out of the SFD header.
   */
  std::int32_t CMovie::GetFrameCount()
  {
    return mFrameCount;
  }

  /**
   * Address: 0x00874880 (FUN_00874880) - vtable slot 12
   *
   * IDA signature:
   * double __thiscall Moho::CMovie::Func8(Moho::CMovie *this);
   *
   * What it does:
   * Returns the frame rate read out of the SFD header. The decompiler reports
   * a double only because the value comes back on the x87 stack; the load is
   * `fld dword ptr [ecx+40h]`, so both field and result are single precision.
   */
  float CMovie::GetFrameRate()
  {
    return mFrameRate;
  }

  /**
   * Address: 0x00874740 (FUN_00874740, Moho::CMovie::Func9) - vtable slot 13
   *
   * IDA signature:
   * char *__thiscall Moho::CMovie::Func9(Moho::CMovie *this);
   *
   * What it does:
   * Hands out the subtitle string lane itself - `lea eax, [ecx+60h]`, not a
   * copy - which UpdatePlaybackFrame refreshes on every tick.
   */
  const msvc8::string* CMovie::GetSubtitleText()
  {
    return &mSubtitleText;
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
  void CMovie::OnEvent(const SD3DDeviceEvent& event)
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
