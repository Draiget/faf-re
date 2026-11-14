#include "moho/audio/AudioEngine.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <windows.h>
#include <mmreg.h>
#include <mmsystem.h>
#include <dsound.h>
#include "gpg/core/utils/SharedPtrUtils.h"
#if !FAFRE_PLATFORM_WINDOWS
// The Linux client's XACT and X3DAudio: FAudio (issue #258).
#include <F3DAudio.h>
#include "platform/posix/XactOverFact.h"
#endif

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "moho/audio/XAudioError.h"
#include "moho/audio/XactClock.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/camera/VTransform.h"

/**
 * Address: 0x00BC67C0 (FUN_00BC67C0, dynamic initializer for `sSoundConfiguration`)
 * Address: 0x00BF0DB0 (FUN_00BF0DB0, dynamic atexit destructor for `sSoundConfiguration`)
 * Address: 0x004DC230 (FUN_004DC230, boost::scoped_ptr<SoundConfiguration>::swap, emitted for its reset)
 */
std::unique_ptr<moho::SoundConfiguration> moho::sSoundConfiguration;

namespace
{
  // Engine addition (dedicated-server plan WPL.4): sSoundEnabled (CSimSoundManager.h), the
  // test Sim::Sim made on sSoundConfiguration before it creates its sound manager.
  bool IsSoundEnabled()
  {
    const moho::SoundConfiguration* const soundConfiguration = moho::sSoundConfiguration.get();
    return soundConfiguration != nullptr && !soundConfiguration->mEngines.empty() && soundConfiguration->mNoSound == 0;
  }

  [[maybe_unused]] const bool gSoundEnabledSet = (moho::sSoundEnabled = &IsSoundEnabled, true);
} // namespace

namespace
{
  /**
   * Engine addition (issue #316): X3DAudio is loaded at run time instead of being imported from
   * X3DAudio1_7.dll, which only the DirectX End-User Runtime of June 2010 installs. Windows 10's
   * xaudio2_9.dll exports the same two functions with the same structures (X3DAUDIO_HANDLE_BYTESIZE 20,
   * pack 1, __cdecl; its X3DAudioInitialize returns an HRESULT the engine never read). X3DAudio1_7.dll
   * stays the fallback for Windows before 10. Both come from System32 only. Without either, 3D audio
   * fails to initialize and the game runs without sound, as for any other sound start-up error.
   */
  struct X3DAudioFunctions
  {
    void(__cdecl* mInitialize)(std::uint32_t speakerChannelMask, float speedOfSound, void* instance) = nullptr;
    void(__cdecl* mCalculate)(
      const void* instance,
      const moho::Audio3DListener* listener,
      const moho::Audio3DEmitter* emitter,
      std::uint32_t flags,
      moho::Audio3DDspSettings* dspSettings
    ) = nullptr;
  };

  const X3DAudioFunctions& X3DAudio()
  {
#if !FAFRE_PLATFORM_WINDOWS
    // The Linux client (issue #258): FAudio's F3DAudio, built in, with X3DAudio's structures.
    static const X3DAudioFunctions functions = [] {
      X3DAudioFunctions linked;
      linked.mInitialize = reinterpret_cast<decltype(linked.mInitialize)>(&F3DAudioInitialize);
      linked.mCalculate = reinterpret_cast<decltype(linked.mCalculate)>(&F3DAudioCalculate);
      return linked;
    }();
    return functions;
#else
    static const X3DAudioFunctions functions = [] {
      for (const wchar_t* const library : {L"xaudio2_9.dll", L"X3DAudio1_7.dll"}) {
        const HMODULE module = ::LoadLibraryExW(library, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == nullptr) {
          continue;
        }
        X3DAudioFunctions loaded;
        loaded.mInitialize =
          reinterpret_cast<decltype(loaded.mInitialize)>(::GetProcAddress(module, "X3DAudioInitialize"));
        loaded.mCalculate =
          reinterpret_cast<decltype(loaded.mCalculate)>(::GetProcAddress(module, "X3DAudioCalculate"));
        if (loaded.mInitialize != nullptr && loaded.mCalculate != nullptr) {
          gpg::Logf("SND: 3D audio from %ls", library);
          return loaded;
        }
        ::FreeLibrary(module);
      }
      gpg::Warnf("SND: neither xaudio2_9.dll nor X3DAudio1_7.dll provides X3DAudio");
      return X3DAudioFunctions{};
    }();
    return functions;
#endif
  }
} // namespace

namespace moho
{
  const char* func_SoundErrorCodeToMsg(int errorCode);
}

namespace
{
  // XACTENGINE_E_INSTANCELIMITFAILTOPLAY: the cue's or its category's instance limit refused the play.
  constexpr int kXactErrInstanceLimitFailToPlay = static_cast<int>(0x8AC70008u);
  constexpr int kHresultPointer = static_cast<int>(0x80004003u);
  constexpr int kHresultFail = static_cast<int>(0x80004005u);
  constexpr std::uint32_t kX3dCalculateFlags = 0x61u;
  constexpr std::uint16_t kInvalidCategoryId = 0xFFFFu;
  constexpr std::uint16_t kInvalidVariableId = 0xFFFFu;
  constexpr float kDefaultCategoryVolume = 1.0f;
  constexpr const char* kGlobalCategoryName = "Global";

  struct AudioDistanceCurvePoint
  {
    float mDistance;
    float mDspSetting;
  };

  struct AudioDistanceCurve
  {
    const AudioDistanceCurvePoint* mPoints;
    std::uint32_t mPointCount;
  };

  constexpr std::array<AudioDistanceCurvePoint, 2> kDefaultDistanceCurvePoints = {
    AudioDistanceCurvePoint{0.0f, 1.0f},
    AudioDistanceCurvePoint{1.0f, 1.0f},
  };

  constexpr AudioDistanceCurve kDefaultDistanceCurve = {kDefaultDistanceCurvePoints.data(), 2u};

  constexpr std::array<float, 2> kDefaultAzimuths2 = {4.71238899f, 1.57079637f};
  constexpr std::array<float, 3> kDefaultAzimuths3 = {4.71238899f, 1.57079637f, 6.28318548f};
  constexpr std::array<float, 4> kDefaultAzimuths4 = {5.49778748f, 0.785398185f, 3.92699075f, 2.3561945f};
  constexpr std::array<float, 5> kDefaultAzimuths5 = {5.49778748f, 0.785398185f, 6.28318548f, 3.92699075f, 2.3561945f};
  constexpr std::array<float, 6> kDefaultAzimuths6 = {
    5.49778748f,
    0.785398185f,
    0.0f,
    6.28318548f,
    3.92699075f,
    2.3561945f,
  };
  constexpr std::array<float, 8> kDefaultAzimuths8 = {
    5.49778748f,
    0.785398185f,
    0.0f,
    6.28318548f,
    3.92699075f,
    2.3561945f,
    4.71238899f,
    1.57079637f,
  };

  struct AudioSoundBankLoader
  {
    gpg::MemBuffer<char> mBuffer;   // +0x00
    moho::IXACTSoundBank* mBank;    // +0x10
    fa::string mName;               // +0x14
    moho::AudioEngineImpl* mEngine; // +0x30

    /**
     * Address: 0x004DA8E0 (FUN_004DA8E0, struct_SoundLoader::Load)
     *
     * gpg::StrArg
     *
     * What it does:
     * Resolves one sound-bank path, reads the bank bytes, creates an XACT
     * sound bank, and stores the base filename for diagnostics.
     */
    bool Load(gpg::StrArg soundBankPath);
  };
  static_assert(offsetof(AudioSoundBankLoader, mBuffer) == 0x00, "AudioSoundBankLoader::mBuffer offset must be 0x00");
  static_assert(offsetof(AudioSoundBankLoader, mBank) == 0x10, "AudioSoundBankLoader::mBank offset must be 0x10");
  static_assert(offsetof(AudioSoundBankLoader, mName) == 0x14, "AudioSoundBankLoader::mName offset must be 0x14");
  static_assert(offsetof(AudioSoundBankLoader, mEngine) == 0x30, "AudioSoundBankLoader::mEngine offset must be 0x30");
  static_assert(sizeof(AudioSoundBankLoader) == 0x34, "AudioSoundBankLoader size must be 0x34");

  class AudioStreamingWaveBankLoader;
  class AudioInMemoryWaveBankLoader;

  class AudioWaveBankLoaderBase
  {
  public:
    explicit AudioWaveBankLoaderBase(
      moho::AudioEngineImpl* const engine
    )
      : mWaveBank(nullptr)
      , mName()
      , mEngine(engine)
    {}

    virtual ~AudioWaveBankLoaderBase() = default;

    [[nodiscard]] virtual bool Load(gpg::StrArg waveBankPath) = 0;

    moho::IXACTWaveBank* mWaveBank; // +0x04
    fa::string mName;               // +0x08
    moho::AudioEngineImpl* mEngine; // +0x24
  };

  // The class carries a vtable, so its own fields start at +0x04. Asserting
  // on it directly says that; the parallel struct this replaces carried a
  // stand-in vtable lane and asserted only that the copy matched itself,
  // which is how it kept an invented `mReserved08` at +0x08 and pushed every
  // field after it four bytes late. The binary has no such lane:
  // `RWaveBankResInMemory::Load` reads the engine at `[edi+0x24]` (0x004DAC5A)
  // and the mapped buffer at `[edi+0x28]` (0x004DABEF), and
  // `RWaveBankResStreaming::LoadBank` reads the same engine lane at
  // `[esi+0x24]` (0x004DAE96) - which is where a 0x1C-byte `fa::string`
  // starting at +0x08 ends.
  static_assert(
    offsetof(AudioWaveBankLoaderBase, mWaveBank) == 0x04,
    "AudioWaveBankLoaderBase::mWaveBank offset must be 0x04"
  );
  static_assert(offsetof(AudioWaveBankLoaderBase, mName) == 0x08, "AudioWaveBankLoaderBase::mName offset must be 0x08");
  static_assert(
    offsetof(AudioWaveBankLoaderBase, mEngine) == 0x24,
    "AudioWaveBankLoaderBase::mEngine offset must be 0x24"
  );
  static_assert(sizeof(AudioWaveBankLoaderBase) == 0x28, "AudioWaveBankLoaderBase size must be 0x28");

  class AudioStreamingWaveBankLoader final : public AudioWaveBankLoaderBase
  {
  public:
    explicit AudioStreamingWaveBankLoader(
      moho::AudioEngineImpl* const engine
    )
      : AudioWaveBankLoaderBase(engine)
      , mFileHandle(INVALID_HANDLE_VALUE)
    {}

    ~AudioStreamingWaveBankLoader() override;

    /**
     * Address: 0x004DADF0 (FUN_004DADF0, Moho::RWaveBankResStreaming::LoadBank)
     *
     * gpg::StrArg
     *
     * What it does:
     * Resolves one streaming wave-bank path, opens its backing file handle,
     * creates one XACT streaming wave-bank instance, stores base-name metadata,
     * and registers the per-wavebank notification lane.
     */
    [[nodiscard]] bool Load(gpg::StrArg waveBankPath) override;

    HANDLE mFileHandle; // +0x28
  };

  static_assert(
    offsetof(AudioStreamingWaveBankLoader, mFileHandle) == 0x28,
    "AudioStreamingWaveBankLoader::mFileHandle offset must be 0x28"
  );

  class AudioInMemoryWaveBankLoader final : public AudioWaveBankLoaderBase
  {
  public:
    explicit AudioInMemoryWaveBankLoader(
      moho::AudioEngineImpl* const engine
    )
      : AudioWaveBankLoaderBase(engine)
      , mMappedBuffer()
    {}

    ~AudioInMemoryWaveBankLoader() override;

    /**
     * Address: 0x004DAB70 (FUN_004DAB70, Moho::RWaveBankResInMemory::Load)
     *
     * gpg::StrArg
     *
     * What it does:
     * Memory-maps one wave-bank file into the resource-owned buffer, creates
     * one in-memory XACT wave-bank lane, and stores the base filename.
     */
    [[nodiscard]] bool Load(gpg::StrArg waveBankPath) override;

    gpg::MemBuffer<const char> mMappedBuffer; // +0x28
  };

  static_assert(
    offsetof(AudioInMemoryWaveBankLoader, mMappedBuffer) == 0x28,
    "AudioInMemoryWaveBankLoader::mMappedBuffer offset must be 0x28"
  );

  using AudioStreamingWaveBankCreateParams = XACT_STREAMING_PARAMETERS;
  static_assert(
    offsetof(AudioStreamingWaveBankCreateParams, packetSize) == sizeof(HANDLE) + 8,
    "XACT streaming packet size offset mismatch"
  );
  static_assert(
    sizeof(AudioStreamingWaveBankCreateParams) == (sizeof(void*) == 4 ? 0x10 : 0x18),
    "XACT streaming parameter size mismatch"
  );

  [[nodiscard]] bool IsCategoryArgValid(
    const gpg::StrArg category
  )
  {
    return category != nullptr && *category != '\0';
  }

  /**
   * Address: 0x004DB7E0 (FUN_004DB7E0)
   *
   * What it does:
   * Finds one category-volume slot by category id or inserts a defaulted slot
   * (`1.0f`) and returns its volume lane.
   *
   * Own `lower_bound`-style descent (tracking the best `>=` candidate, the
   * same shape `fa::map<K,T>::operator[]` uses elsewhere in this file's
   * sibling instantiations) followed by a hinted insert against that
   * descent's own result when the exact key is absent -- register-traced
   * against the real `.asm` field for field: matches `fa::map<
   * std::uint16_t, float>::insert(const_iterator, const value_type&)`
   * (`insert_hint` in `RbTree.h`, cited there as `FUN_004DC080` for this
   * instantiation), including the leftmost/rightmost/predecessor-successor
   * branch structure this function's own inline descent result feeds in as
   * the hint. Two real callers, both members of this class: `AudioEngine::
   * SetVolume` (`FUN_004D9DB0`) and `AudioEngine::GetVolume` (`FUN_004D9E50`)
   * -- `GetVolume` is not a pure read in the real binary: it calls this same
   * find-or-insert helper and silently persists a defaulted `1.0f` entry the
   * first time a category is ever queried, exactly like `SetVolume` does
   * just before overwriting it with the caller's actual value.
   *
   * Previously modelled as `FindOrInsertCategoryVolumeNode`, a hand-rolled,
   * hand-walked BST insert reached through a duplicate `AudioCategoryVolumeNode`/
   * `AudioMapStorage` struct pair (deleted by this migration) that built and
   * linked new nodes directly with **no rotation/recolor step at all** -- the
   * same missing-rebalance shape independently diagnosed on
   * `AudioMap1CategoryNode` before its own fix
   * (`.memory/project_audiomap1_missing_rebalance_bug.md`). That function's
   * own address citation (0x004DC080) was itself wrong: register-tracing the
   * real `.asm` at that address shows the genuine VC8 hinted-insert
   * dispatcher (`insert_hint`), which -- through `insert_at`/`insert_unique`
   * -- DOES fully rebalance on every insert. The real bug was that the
   * previously-recovered source never reached any of those real functions at
   * all (its own descent didn't even take a hint parameter), not that the
   * real binary skips rebalancing on this instantiation.
   */
  [[nodiscard]] float* FindOrInsertCategoryVolume(
    fa::map<std::uint16_t, float>& map,
    const std::uint16_t category
  )
  {
    auto it = map.lower_bound(category);
    if (it != map.end() && it->first == category) {
      return &it->second;
    }

    it = map.insert(it, {category, kDefaultCategoryVolume});
    return &it->second;
  }

  [[nodiscard]] AudioSoundBankLoader* FindBankLoader(
    moho::AudioEngineImpl* impl,
    const std::uint16_t bankId
  )
  {
    if (impl == nullptr || impl->mBanks.empty()) {
      return nullptr;
    }

    const std::size_t bankCount = impl->mBanks.size();
    if (static_cast<std::size_t>(bankId) >= bankCount) {
      return nullptr;
    }

    return static_cast<AudioSoundBankLoader*>(impl->mBanks.begin()[bankId]);
  }

  [[nodiscard]] std::uint32_t ResolveDstChannelCount(
    const moho::SoundConfiguration* configuration
  )
  {
    if (configuration == nullptr) {
      return 2;
    }

    switch (configuration->mSpeakerConfiguration) {
    case 0x3F:
      return 6;
    case 0x0B:
      return 3;
    case 0xFF:
      return 7;
    case 0x03:
    case 0x33:
    case 0x107:
      return 2;
    default:
      gpg::Warnf("Invalid speaker configuration supplied: %i", configuration->mSpeakerConfiguration);
      return 2;
    }
  }

  /**
   * Address: 0x004DA8E0 (FUN_004DA8E0, struct_SoundLoader::Load)
   *
   * gpg::StrArg
   *
   * What it does:
   * Resolves one sound-bank path, reads the bank bytes, creates an XACT
   * sound bank, and stores the base filename for diagnostics.
   */
  bool AudioSoundBankLoader::Load(
    const gpg::StrArg soundBankPath
  )
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    fa::string mountedPath{};
    const fa::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, soundBankPath, nullptr);

    mBuffer = moho::DISK_ReadFile(resolvedPath->c_str());
    if (mBuffer.mBegin == nullptr) {
      gpg::Warnf("Error loading soundbank '%s'", soundBankPath);
      return false;
    }

    const int createResult = mEngine->mInstance->CreateSoundBank(
      mBuffer.mBegin, static_cast<std::int32_t>(mBuffer.mEnd - mBuffer.mBegin), 0u, 0u, &mBank
    );
    if (createResult < 0) {
      gpg::Warnf("Error loading soundbank '%s': %s", soundBankPath, moho::func_SoundErrorCodeToMsg(createResult));
      return false;
    }

    mName = moho::FILE_Base(soundBankPath, true);
    gpg::Debugf("SND: Loaded SoundBank '%s'", mName.c_str());
    return true;
  }

  // Retail's streaming wave-bank open flags: FILE_FLAG_OVERLAPPED |
  // FILE_FLAG_NO_BUFFERING (0x004DAE53: push 60000000h).
  constexpr DWORD kStreamingWaveBankOpenFlags = FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING;
  static_assert(kStreamingWaveBankOpenFlags == 0x60000000u, "streaming wave-bank open flags must match retail");

  /**
   * Not in the binary.
   *
   * What it does:
   * Returns the flags to open one streaming wave bank with: retail's
   * `kStreamingWaveBankOpenFlags`, or `FILE_FLAG_OVERLAPPED` alone when the
   * bank's wave alignment is not a multiple of the logical sector size of the
   * drive it is on.
   *
   * An unbuffered read must start on a logical sector, and XACT starts each
   * wave's reads at that wave's own offset in the bank. The shipped banks are
   * built with 2048-byte alignment (the bank-data field at +0x50), so on a
   * drive with 4096-byte logical sectors every wave that does not happen to
   * land on 4096 fails: `Play` reports "XACT: Invalid arg", and the failed cue
   * later crashes the engine's teardown inside `IXACTWaveBank::Destroy`
   * (a read of freed memory under 0x004DB004). Through the file cache the
   * same reads work at any offset. XACT's own reads are a multiple of 4096
   * already (`packetSize` 0x12 x 2048 bytes), so a bank rebuilt with
   * 4096-byte alignment keeps retail's unbuffered path.
   *
   * Any failure while checking leaves retail's flags, so the result can only
   * differ from retail on a drive and bank that retail cannot stream.
   */
  [[nodiscard]] DWORD ResolveStreamingWaveBankOpenFlags(
    const char* const resolvedPath,
    const gpg::StrArg waveBankPath
  )
  {
    const HANDLE file = ::CreateFileA(
      resolvedPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
      return kStreamingWaveBankOpenFlags;
    }

    DWORD openFlags = kStreamingWaveBankOpenFlags;
    FILE_STORAGE_INFO storageInfo{};
    std::array<std::uint32_t, 4> headerWords{}; // 'WBND', version, header version, bank-data offset
    std::uint32_t alignment = 0u;
    DWORD bytesRead = 0u;
    LARGE_INTEGER alignmentOffset{};

    if (
      ::GetFileInformationByHandleEx(file, FileStorageInfo, &storageInfo, sizeof(storageInfo)) &&
      storageInfo.LogicalBytesPerSector != 0u &&
      ::ReadFile(file, headerWords.data(), sizeof(headerWords), &bytesRead, nullptr) &&
      bytesRead == sizeof(headerWords) && headerWords[0] == 0x444E4257u
    ) {
      alignmentOffset.QuadPart = static_cast<LONGLONG>(headerWords[3]) + 0x50;
      if (
        ::SetFilePointerEx(file, alignmentOffset, nullptr, FILE_BEGIN) &&
        ::ReadFile(file, &alignment, sizeof(alignment), &bytesRead, nullptr) && bytesRead == sizeof(alignment) &&
        alignment % storageInfo.LogicalBytesPerSector != 0u
      ) {
        openFlags = FILE_FLAG_OVERLAPPED;
        gpg::Logf(
          "SND: WaveBank '%s' is aligned to %u bytes and its drive reads %u-byte sectors; streaming it through the "
          "file cache",
          waveBankPath,
          alignment,
          static_cast<unsigned>(storageInfo.LogicalBytesPerSector)
        );
      }
    }

    (void)::CloseHandle(file);
    return openFlags;
  }

  /**
   * Address: 0x004DADF0 (FUN_004DADF0, Moho::RWaveBankResStreaming::LoadBank)
   *
   * gpg::StrArg
   *
   * What it does:
   * Resolves one streaming wave-bank path, opens its backing file handle,
   * creates one XACT streaming wave-bank instance, stores base-name metadata,
   * and registers one wave-bank notification payload.
   *
   * Differs from retail: the open flags come from
   * `ResolveStreamingWaveBankOpenFlags`, which drops FILE_FLAG_NO_BUFFERING for
   * a bank its drive cannot read unbuffered.
   */
  bool AudioStreamingWaveBankLoader::Load(
    const gpg::StrArg waveBankPath
  )
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (
      waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || mEngine == nullptr ||
      mEngine->mInstance == nullptr
    ) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    fa::string mountedPath{};
    const fa::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);
    mFileHandle = ::CreateFileA(
      resolvedPath->c_str(),
      GENERIC_READ,
      FILE_SHARE_READ,
      nullptr,
      OPEN_EXISTING,
      ResolveStreamingWaveBankOpenFlags(resolvedPath->c_str(), waveBankPath),
      nullptr
    );
    if (mFileHandle == INVALID_HANDLE_VALUE) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    AudioStreamingWaveBankCreateParams createParams{};
    createParams.file = mFileHandle;
    createParams.offset = 0u;
    createParams.flags = 0u;
    createParams.packetSize = 0x12u;

    const int createResult = mEngine->mInstance->CreateStreamingWaveBank(&createParams, &mWaveBank);
    if (createResult < 0) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    mName = moho::FILE_Base(waveBankPath, true);

    moho::AudioNotificationDesc notification{};
    notification.type = XACTNOTIFICATIONTYPE_WAVEBANKPREPARED;
    // The notification holds an opaque XACT interface identity. It never calls
    // through the SDK's XACT 3 vtable on this recovered XACT 2 instance.
    notification.pWaveBank = reinterpret_cast<IXACT3WaveBank*>(mWaveBank);
    const int registerResult = mEngine->mInstance->RegisterNotification(&notification);
    if (registerResult < 0) {
      gpg::Warnf("SND: Error registering notification.\n%s", moho::func_SoundErrorCodeToMsg(registerResult));
    }

    gpg::Debugf("SND: Loaded WaveBank '%s' at %p", mName.c_str(), static_cast<void*>(mWaveBank));
    return true;
  }

  /**
   * Address: 0x004DAB70 (FUN_004DAB70, Moho::RWaveBankResInMemory::Load)
   *
   * gpg::StrArg
   *
   * What it does:
   * Memory-maps one non-streaming wave-bank file, creates one in-memory XACT
   * wave-bank lane from the mapped bytes, and stores the base filename.
   */
  bool AudioInMemoryWaveBankLoader::Load(
    const gpg::StrArg waveBankPath
  )
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (
      waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || mEngine == nullptr ||
      mEngine->mInstance == nullptr
    ) {
      return false;
    }

    fa::string mountedPath{};
    const fa::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);
    mMappedBuffer = moho::DISK_MemoryMapFile(resolvedPath->c_str());
    if (mMappedBuffer.mBegin == nullptr) {
      return false;
    }

    const int createResult = mEngine->mInstance->CreateInMemoryWaveBank(
      mMappedBuffer.mBegin, static_cast<std::int32_t>(mMappedBuffer.mEnd - mMappedBuffer.mBegin), 0u, 0u, &mWaveBank
    );
    if (createResult < 0) {
      gpg::Warnf("Error loading WaveBank '%s': %s", waveBankPath, moho::func_SoundErrorCodeToMsg(createResult));
      return false;
    }

    mName = moho::FILE_Base(waveBankPath, true);
    gpg::Debugf("SND: Loaded WaveBank '%s' at %p", mName.c_str(), static_cast<void*>(mWaveBank));
    return true;
  }

  /**
   * Address: 0x004D8660 (FUN_004D8660, IsStreamingWaveBank)
   *
   * What it does:
   * Opens one resolved wave-bank file, reads the header and metadata lanes,
   * and returns whether the metadata streaming bit (`bit0`) is set.
   */
  [[nodiscard]] bool IsStreamingWaveBank(
    const gpg::StrArg waveBankPath
  )
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || waveBankPath == nullptr) {
      return false;
    }

    fa::string mountedPath{};
    const fa::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);

    fa::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileRead(resolvedPath->c_str());
    gpg::Stream* const stream = openedStream.get();
    if (stream == nullptr) {
      return false;
    }

    gpg::BinaryReader reader(stream);

    std::array<std::uint32_t, 13> waveBankHeaderWords{};
    reader.ReadExactArray(waveBankHeaderWords.data(), waveBankHeaderWords.size());

    const std::uint32_t metadataOffset = waveBankHeaderWords[3];
    (void)stream->VirtSeek(
      gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, static_cast<std::int64_t>(metadataOffset)
    );

    std::array<std::uint8_t, 0x60> metadata{};
    reader.ReadExactArray(metadata.data(), metadata.size());
    return (metadata[0] & 0x01u) != 0u;
  }

  /**
   * Address: 0x004DB1D0 (FUN_004DB1D0)
   *
   * What it does:
   * Appends one shared engine reference into the global sound-configuration
   * engine vector, growing storage and retaining shared ownership as needed.
   */
  void RegisterEngineRef(
    moho::SoundConfiguration& configuration,
    const std::shared_ptr<moho::AudioEngine>& engineRef
  )
  {
    if (engineRef.get() == nullptr) {
      return;
    }
    configuration.mEngines.push_back(engineRef);
  }

  /**
   * Address: 0x004DB090 (FUN_004DB090)
   *
   * What it does:
   * Stores one replacement `AudioEngineImpl*` lane and destroys the previously
   * installed implementation object when present.
   */
  void ReplaceAudioEngineImplPointer(
    moho::AudioEngineImpl*& destination,
    moho::AudioEngineImpl* const replacement
  )
  {
    moho::AudioEngineImpl* const previous = destination;
    destination = replacement;
    if (previous == nullptr) {
      return;
    }

    previous->~AudioEngineImpl();
    operator delete(previous);
  }

  /**
   * Address: 0x004DB900 (FUN_004DB900)
   *
   * What it does:
   * Returns the process-global sound-configuration singleton lane.
   */
  [[nodiscard]] moho::SoundConfiguration* GetSoundConfigurationSingletonA() noexcept
  {
    return moho::sSoundConfiguration.get();
  }

  /**
   * Address: 0x004DB910 (FUN_004DB910)
   *
   * What it does:
   * Returns the process-global sound-configuration singleton lane.
   */
  [[nodiscard]] moho::SoundConfiguration* GetSoundConfigurationSingletonB() noexcept
  {
    return moho::sSoundConfiguration.get();
  }

  /**
   * Address: 0x004DA890 (FUN_004DA890)
   *
   * What it does:
   * Applies one mute/unmute transition for the `"Global"` category on one
   * active engine implementation and stores/restores the cached global volume.
   */
  void ApplyGlobalMuteToEngine(
    moho::AudioEngineImpl& impl,
    const bool doMute
  )
  {
    if (impl.mInstance == nullptr || impl.mEngine == nullptr) {
      return;
    }

    const float volume = doMute ? (impl.mGlobalCategoryVolume = impl.mEngine->GetVolume(kGlobalCategoryName), 0.0f)
                                : impl.mGlobalCategoryVolume;
    impl.mEngine->SetVolume(kGlobalCategoryName, volume);
  }

  /**
   * Address: 0x004DAAC0 (FUN_004DAAC0)
   *
   * What it does:
   * Tears down one `AudioSoundBankLoader` payload in place: destroys the
   * active XACT sound-bank lane, resets the filename string to empty SSO
   * state, and releases the shared mem-buffer control lane.
   */
  void DestroyAudioSoundBankLoaderNoDelete(
    AudioSoundBankLoader* const loader
  ) noexcept
  {
    if (loader == nullptr) {
      return;
    }

    if (loader->mBank != nullptr) {
      loader->mBank->Destroy();
    }

    if (loader->mName.myRes >= 0x10u) {
      operator delete(loader->mName.bx.ptr);
    }
    loader->mName.myRes = 15u;
    loader->mName.mySize = 0u;
    loader->mName.bx.buf[0] = '\0';

    loader->mBuffer.mData.reset();
  }

  /**
   * Address: 0x004DAD40 (FUN_004DAD40)
   *
   * What it does:
   * Destroys one in-memory-wavebank payload in place: releases the active
   * wave-bank runtime handle, clears the mapped-file shared buffer lanes, and
   * resets the stored bank-name string to empty SSO state.
   */
  void DestroyInMemoryWaveBankResourceNoDelete(
    AudioInMemoryWaveBankLoader* const inMemoryResource
  ) noexcept
  {
    if (inMemoryResource == nullptr) {
      return;
    }

    if (inMemoryResource->mWaveBank != nullptr) {
      inMemoryResource->mWaveBank->Destroy();
      inMemoryResource->mWaveBank = nullptr;
    }

    inMemoryResource->mMappedBuffer.Reset();
    inMemoryResource->mName.tidy(true, 0u);
  }

  /**
   * Address: 0x004DAFD0 (FUN_004DAFD0)
   *
   * What it does:
   * Destroys one streaming-wavebank payload in place: releases the active
   * wave-bank runtime handle, closes the Win32 file handle when valid, and
   * resets the stored bank-name string to empty SSO state.
   */
  void DestroyStreamingWaveBankResourceNoDelete(
    AudioStreamingWaveBankLoader* const streamingResource
  ) noexcept
  {
    if (streamingResource == nullptr) {
      return;
    }

    if (streamingResource->mWaveBank != nullptr) {
      streamingResource->mWaveBank->Destroy();
      streamingResource->mWaveBank = nullptr;
    }
    if (streamingResource->mFileHandle != INVALID_HANDLE_VALUE) {
      (void)::CloseHandle(streamingResource->mFileHandle);
      streamingResource->mFileHandle = INVALID_HANDLE_VALUE;
    }

    streamingResource->mName.tidy(true, 0u);
  }

  AudioInMemoryWaveBankLoader::~AudioInMemoryWaveBankLoader()
  {
    DestroyInMemoryWaveBankResourceNoDelete(this);
  }

  AudioStreamingWaveBankLoader::~AudioStreamingWaveBankLoader()
  {
    DestroyStreamingWaveBankResourceNoDelete(this);
  }

  /**
   * Address: 0x004DDED0 (FUN_004DDED0)
   *
   * What it does:
   * Destroys one contiguous range of audio sound-bank loader pointers.
   */
  void DeleteSoundBankLoaders(
    void** const first,
    void** const last
  ) noexcept
  {
    if (first == nullptr || last == nullptr) {
      return;
    }

    for (void** cursor = first; cursor != last; ++cursor) {
      auto* const loader = static_cast<AudioSoundBankLoader*>(*cursor);
      if (loader == nullptr) {
        continue;
      }

      DestroyAudioSoundBankLoaderNoDelete(loader);
      operator delete(loader);
      *cursor = nullptr;
    }
  }

  /**
   * Address: 0x004DDF10 (FUN_004DDF10)
   *
   * What it does:
   * Deletes every wave-bank loader in a range. `mHandles` only ever receives
   * `AudioWaveBankLoaderBase*` -- 0x004DA2xx pushes an
   * `AudioStreamingWaveBankLoader` or an `AudioInMemoryWaveBankLoader` -- and
   * that base declares `virtual ~AudioWaveBankLoaderBase()`, so a plain
   * `delete` is exactly what produces the loop body:
   *
   *   0x004DDF20: mov ecx, [esi]      ; the element
   *   0x004DDF22: test ecx, ecx / je  ; delete's own null test
   *   0x004DDF26: mov eax, [ecx]      ; vptr
   *   0x004DDF28: mov edx, [eax]      ; slot 0, MSVC's ??_G deleting dtor
   *   0x004DDF2A: push 1 / call edx
   *
   * This was hand-written as `reinterpret_cast<DeletingDtorFn>(vtable[0])`,
   * which is the vtable magic the reconstruction contract forbids, and it
   * carried two things the binary does not do: a `vtable[0] == nullptr` guard,
   * and a `*cursor = nullptr` writeback. There is no `mov [esi], 0` anywhere
   * in the body -- the caller clears the vector on the next line.
   */
  void DeleteWaveBankLoaders(
    void** const first,
    void** const last
  ) noexcept
  {
    if (first == nullptr || last == nullptr) {
      return;
    }

    for (void** cursor = first; cursor != last; ++cursor) {
      delete static_cast<AudioWaveBankLoaderBase*>(*cursor);
    }
  }

  [[nodiscard]] Wm3::Vec3f NormalizeOrDefault(
    Wm3::Vec3f value,
    const Wm3::Vec3f& fallback
  )
  {
    if (Wm3::Vec3f::LengthSq(value) <= 1.0e-8f) {
      return fallback;
    }

    Wm3::Vec3f::Normalize(&value);
    return value;
  }

  [[nodiscard]] Wm3::Quatf QuaternionFromBasis(
    const Wm3::Vec3f& right,
    const Wm3::Vec3f& up,
    const Wm3::Vec3f& forward
  )
  {
    const float m00 = right.x;
    const float m01 = up.x;
    const float m02 = forward.x;
    const float m10 = right.y;
    const float m11 = up.y;
    const float m12 = forward.y;
    const float m20 = right.z;
    const float m21 = up.z;
    const float m22 = forward.z;
    const float trace = m00 + m11 + m22;

    Wm3::Quatf out{};
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      out.w = 0.25f * s;
      out.x = (m21 - m12) / s;
      out.y = (m02 - m20) / s;
      out.z = (m10 - m01) / s;
    } else if (m00 > m11 && m00 > m22) {
      const float s = std::sqrt(1.0f + m00 - m11 - m22) * 2.0f;
      out.w = (m21 - m12) / s;
      out.x = 0.25f * s;
      out.y = (m01 + m10) / s;
      out.z = (m02 + m20) / s;
    } else if (m11 > m22) {
      const float s = std::sqrt(1.0f + m11 - m00 - m22) * 2.0f;
      out.w = (m02 - m20) / s;
      out.x = (m01 + m10) / s;
      out.y = 0.25f * s;
      out.z = (m12 + m21) / s;
    } else {
      const float s = std::sqrt(1.0f + m22 - m00 - m11) * 2.0f;
      out.w = (m10 - m01) / s;
      out.x = (m02 + m20) / s;
      out.y = (m12 + m21) / s;
      out.z = 0.25f * s;
    }

    out.Normalize();
    return out;
  }

  [[nodiscard]] Wm3::Quatf BuildListenerOrientation(
    const moho::Audio3DListener& listener
  )
  {
    Wm3::Vec3f forward{listener.mOrientFront.x, listener.mOrientFront.y, listener.mOrientFront.z};
    Wm3::Vec3f top{listener.mOrientTop.x, listener.mOrientTop.y, listener.mOrientTop.z};

    forward = NormalizeOrDefault(forward, Wm3::Vec3f{0.0f, 0.0f, 1.0f});

    // Binary SetListenerTransform stores the second axis in inverted world-up space.
    Wm3::Vec3f up{-top.x, -top.y, -top.z};
    up = NormalizeOrDefault(up, Wm3::Vec3f{0.0f, 1.0f, 0.0f});

    Wm3::Vec3f right = Wm3::Vec3f::Cross(up, forward);
    right = NormalizeOrDefault(right, Wm3::Vec3f{1.0f, 0.0f, 0.0f});
    up = Wm3::Vec3f::Cross(forward, right);
    up = NormalizeOrDefault(up, Wm3::Vec3f{0.0f, 1.0f, 0.0f});

    return QuaternionFromBasis(right, up, forward);
  }

  /**
   * Address: 0x004D82A0 (FUN_004D82A0, func_ApplySettingsToCue)
   *
   * What it does:
   * Applies one X3DAudio matrix and per-cue runtime variables (`Distance`,
   * `DopplerPitchScalar`, `OrientationAngle`) to the target cue.
   */
  int ApplySettingsToCue(
    const moho::Audio3DDspSettings* settings,
    moho::IXACTCue* cue
  )
  {
    if (settings == nullptr || cue == nullptr) {
      return static_cast<int>(0x80004003u);
    }

    int result =
      cue->SetMatrixCoefficients(settings->mSrcChannelCount, settings->mDstChannelCount, settings->mMatrixCoefficients);
    if (result < 0) {
      return result;
    }

    const std::uint16_t distanceVariable = cue->GetVariableIndex("Distance");
    result = cue->SetVariable(distanceVariable, settings->mEmitterToListenerDistance);
    if (result < 0) {
      return result;
    }

    const std::uint16_t dopplerVariable = cue->GetVariableIndex("DopplerPitchScalar");
    result = cue->SetVariable(dopplerVariable, settings->mDopplerFactor);
    if (result < 0) {
      return result;
    }

    const std::uint16_t orientationVariable = cue->GetVariableIndex("OrientationAngle");
    return cue->SetVariable(orientationVariable, settings->mEmitterToListenerAngle * 57.295776f);
  }
} // namespace

namespace moho
{
  namespace
  {
#if FAFRE_PLATFORM_WINDOWS
    // XACT's COM class and interface ids, for CoCreateInstance; the Linux client has FAudio (#258).
    const IID kXactAuditionComInterfaceClsid =
      {0xcedde475u, 0x50b5u, 0x47efu, {0x91u, 0xa7u, 0x3bu, 0x49u, 0xa0u, 0xe8u, 0xe5u, 0x88u}};
    const IID kXactDebugComInterfaceClsid =
      {0x3cbb606bu, 0x06f1u, 0x473eu, {0x9du, 0xd5u, 0x0eu, 0x4au, 0x3bu, 0x47u, 0x14u, 0x13u}};
    const IID kXactComInterfaceClsid =
      {0x343e68e6u, 0x8f82u, 0x4a8du, {0xa2u, 0xdau, 0x6eu, 0x9au, 0x94u, 0x4bu, 0x37u, 0x8cu}};
    const IID kXactComInterfaceRiid =
      {0x893ff2e4u, 0x8d03u, 0x4d5fu, {0xb0u, 0xaau, 0x36u, 0x3au, 0x9cu, 0xbbu, 0xf4u, 0x37u}};
#endif
  } // namespace

  /**
   * Address: 0x004D8090 (FUN_004D8090, func_CreateXACTinstance)
   *
   * What it does:
   * Chooses XACT engine CLSID from debug/audition mode + optional
   * `HKLM\\Software\\Microsoft\\XACT\\DebugEngine`, creates the COM instance,
   * and retries with retail CLSID when debug creation fails.
   *
   * FAF addition: `outEngineClass` receives the class that was created (null
   * on the Linux client), for `SND_InstallXactClock`.
   */
  int func_CreateXACTinstance(
    const std::uint32_t mode,
    void** const outEngine,
    const GUID** const outEngineClass
  )
  {
    *outEngineClass = nullptr;
#if !FAFRE_PLATFORM_WINDOWS
    // The Linux client (issue #258): XACT on FAudio's FACT; it has no debug or audition engine.
    (void)mode;
    return platform::posix::CreateXactEngineOverFact(outEngine);
#else
    std::uint32_t debug = (mode >> 1u) & 1u;
    const std::uint32_t audition = mode & 1u;
    const std::uint32_t auditionMode = audition;

    DWORD type = REG_DWORD;
    DWORD cbData = sizeof(DWORD);
    DWORD data = 0u;

    const IID* selectedClsid = nullptr;
    if (debug != 0u) {
      selectedClsid = (audition != 0u) ? &kXactAuditionComInterfaceClsid : &kXactDebugComInterfaceClsid;
    } else if (audition != 0u) {
      selectedClsid = &kXactAuditionComInterfaceClsid;
    } else {
      HKEY openedKey = nullptr;
      if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\XACT", 0u, 0x20019u, &openedKey) != ERROR_SUCCESS) {
        selectedClsid = &kXactComInterfaceClsid;
      } else {
        if (
          RegQueryValueExW(openedKey, L"DebugEngine", nullptr, &type, reinterpret_cast<LPBYTE>(&data), &cbData) ==
          ERROR_SUCCESS
        ) {
          debug = (data != 0u) ? 1u : 0u;
        }
        RegCloseKey(openedKey);
        selectedClsid = (debug != 0u) ? &kXactDebugComInterfaceClsid : &kXactComInterfaceClsid;
      }
    }

    int result = CoCreateInstance(*selectedClsid, nullptr, CLSCTX_INPROC_SERVER, kXactComInterfaceRiid, outEngine);
    if (result < 0 && debug != 0u && auditionMode == 0u) {
      selectedClsid = &kXactComInterfaceClsid;
      result = CoCreateInstance(*selectedClsid, nullptr, CLSCTX_INPROC_SERVER, kXactComInterfaceRiid, outEngine);
    }
    *outEngineClass = selectedClsid;
    return result;
#endif
  }

  void func_RetreiveXACTCOMInterface(AudioEngineImpl* impl);
  void func_LoadSoundPath(AudioEngineImpl* impl, gpg::StrArg voicePath);
  fa::string SND_GetVariableName(int variableId);

  /**
   * Address: 0x004D8A50 (FUN_004D8A50, func_SoundErrorCodeToMsg)
   *
   * What it does:
   * Maps common HRESULT/XACT failure codes to stable diagnostic text.
   */
  const char* func_SoundErrorCodeToMsg(int errorCode);

  /// What `IXACTEngine::GetFinalMixFormat` writes is a `WAVEFORMATEXTENSIBLE`,
  /// and `<mmreg.h>` is already included above, so this is the platform's own
  /// struct rather than a local restatement of it.
  ///
  /// The binary reserves exactly its 0x28 bytes: `func_AudioInitialize`
  /// subtracts 0x2C, puts the buffer at `ebp-0x28` and reads the speaker mask
  /// from `ebp-0x14`. IDA splits that into `char v7[20]` plus a separate
  /// `SpeakerChannelMask` local, but both name one buffer -- which is how the
  /// hand-written stand-in that used to sit here came to be 0x18 bytes, one
  /// `Samples` union and one `SubFormat` GUID short. XACT wrote the trailing
  /// GUID sixteen bytes past the end of the stack object, and `/RTC` stopped
  /// startup on "Run-Time Check Failure #2 - Stack around the variable
  /// 'finalMixFormat' was corrupted". The asserts below are kept because that
  /// is the failure they catch.
  static_assert(
    offsetof(WAVEFORMATEXTENSIBLE, dwChannelMask) == 0x14,
    "WAVEFORMATEXTENSIBLE::dwChannelMask offset must be 0x14"
  );
  static_assert(
    offsetof(WAVEFORMATEXTENSIBLE, SubFormat) == 0x18,
    "WAVEFORMATEXTENSIBLE::SubFormat offset must be 0x18"
  );
  static_assert(sizeof(WAVEFORMATEXTENSIBLE) == 0x28, "WAVEFORMATEXTENSIBLE size must be 0x28");

  /**
   * Address: 0x004D8170 (FUN_004D8170, func_AudioInitialize)
   *
   * What it does:
   * Reads XACT global `SpeedOfSound`, fetches final mix speaker-channel mask,
   * and initializes the 3D-audio handle with those two lanes.
   */
  int func_AudioInitialize(
    IXACTEngine* const engine,
    void* const audioHandle
  )
  {
    if (engine == nullptr) {
      return kHresultPointer;
    }

    const std::uint16_t speedOfSoundVariable = engine->GetGlobalVariableIndex("SpeedOfSound");
    float speedOfSound = 0.0f;
    int result = engine->GetGlobalVariable(speedOfSoundVariable, &speedOfSound);
    if (result < 0) {
      return result;
    }

    WAVEFORMATEXTENSIBLE finalMixFormat{};
    result = engine->GetFinalMixFormat(&finalMixFormat);
    if (result < 0) {
      return result;
    }

    if (X3DAudio().mInitialize == nullptr) {
      return kHresultFail;
    }
    X3DAudio().mInitialize(finalMixFormat.dwChannelMask, speedOfSound, audioHandle);
    return result;
  }

  /**
   * Address: 0x004D81E0 (FUN_004D81E0, func_X3DAudioCalculate)
   *
   * What it does:
   * Applies default channel azimuth/curve lanes for multi-channel emitters
   * and forwards one 3D-audio solve call into `X3DAudioCalculate`.
   */
  int func_X3DAudioCalculate(
    Audio3DEmitter* emitter,
    const Audio3DListener* listener,
    Audio3DDspSettings* settings,
    const void* audioHandle
  );

  /**
   * Address: 0x004D8970 (FUN_004D8970, func_RetreiveXACTCOMInterface)
   *
   * What it does:
   * Chooses XACT creation mode from `/xactdebug` + audition settings, creates
   * the engine COM instance, and throws `XAudioError` on failure.
   */
  void func_RetreiveXACTCOMInterface(
    AudioEngineImpl* const impl
  )
  {
    if (impl == nullptr) {
      return;
    }

    std::uint32_t mode = 0u;
    if (CFG_GetArgOption("/xactdebug", 0, nullptr)) {
      mode = 2u;
    } else if (sSoundConfiguration && sSoundConfiguration->mAudition != 0u) {
      mode = 1u;
    }

    const GUID* engineClass = nullptr;
    const int errorCode = func_CreateXACTinstance(mode, reinterpret_cast<void**>(&impl->mInstance), &engineClass);
    if (errorCode < 0) {
      const char* const errorMessage = func_SoundErrorCodeToMsg(errorCode);
      const fa::string fullMessage = gpg::STR_Printf(
        "SND: Error retrieving XACT COM interface. %s", errorMessage ? errorMessage : "Unknown XACT Error"
      );
      throw XAudioError(fullMessage.c_str());
    }

    // FAF addition, not in the shipped binary: XACT 2.9 stops working after
    // 24.86 days of Windows uptime; give it a clock that starts with the game.
    if (impl->mInstance != nullptr) {
      SND_InstallXactClock(engineClass);
    }
  }

  bool snd_ReadAhead = true;
  TConVar<bool> gTConVar_snd_ReadAhead(
    "snd_ReadAhead",
    "Loading sound banks reads the start of each file with several threads first (1, the default), or leaves every "
    "read to the loader, one file at a time (0). Same bytes. /nosndreadahead turns it off at startup.",
    &snd_ReadAhead
  );

  /**
   * Engine addition (`snd_ReadAhead`): reads the start of each bank file under one voice path with
   * several threads, so the loader finds them in the system's file cache. The first read of a small
   * file that isn't in memory takes about 12 ms alone and under 2 ms with 8 threads. Only file reads
   * run on the threads: no audio call, and no mounted file system lookup.
   */
  void ReadSoundBanksAhead(
    CVirtualFileSystem& fileSystem,
    const gpg::StrArg voicePath
  )
  {
    static const bool startupOff = CFG_GetArgOption("/nosndreadahead", 0u, nullptr);
    if (!snd_ReadAhead || startupOff) {
      return;
    }

    std::vector<std::string> diskPaths{};
    for (const char* const pattern : {"*.xwb", "*.xsb"}) {
      fa::vector<fa::string> mountedPaths{};
      fileSystem.EnumerateFiles(voicePath, pattern, false, &mountedPaths);
      for (const fa::string& mountedPath : mountedPaths) {
        fa::string resolved{};
        if (const fa::string* const found = fileSystem.FindFile(&resolved, mountedPath.c_str(), nullptr)) {
          diskPaths.emplace_back(found->c_str());
        }
      }
    }

    std::atomic<std::size_t> nextPath{0u};
    const auto readFiles = [&diskPaths, &nextPath] {
      std::vector<char> buffer(64u * 1024u);
      for (std::size_t index = nextPath++; index < diskPaths.size(); index = nextPath++) {
        const HANDLE file = ::CreateFileA(
          diskPaths[index].c_str(),
          GENERIC_READ,
          FILE_SHARE_READ,
          nullptr,
          OPEN_EXISTING,
          FILE_FLAG_SEQUENTIAL_SCAN,
          nullptr
        );
        if (file != INVALID_HANDLE_VALUE) {
          DWORD bytesRead = 0u;
          (void)::ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
          ::CloseHandle(file);
        }
      }
    };

    std::vector<std::thread> readers{};
    if (diskPaths.size() > 1u) {
      try {
        for (int reader = 0; reader < 7; ++reader) {
          readers.emplace_back(readFiles);
        }
      } catch (const std::system_error&) {
        // Fewer readers is only slower: this thread reads what is left.
      }
    }
    readFiles();
    for (std::thread& reader : readers) {
      reader.join();
    }
  }

  /**
   * Address: 0x004DA500 (FUN_004DA500, func_LoadSoundPath)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Enumerates wave-bank (`*.xwb`) and sound-bank (`*.xsb`) files under one
   * voice-path lane, constructs the corresponding loader objects, loads each
   * bank, and appends successful resources into `mHandles`/`mBanks`.
   */
  void func_LoadSoundPath(
    AudioEngineImpl* const impl,
    const gpg::StrArg voicePath
  )
  {
    if (impl == nullptr || voicePath == nullptr) {
      return;
    }

    FWaitHandleSet* waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return;
    }

    ReadSoundBanksAhead(*waitHandleSet->mHandle, voicePath);

    fa::vector<fa::string> waveBankPaths{};
    waitHandleSet->mHandle->EnumerateFiles(voicePath, "*.xwb", false, &waveBankPaths);

    for (const fa::string& waveBankPath : waveBankPaths) {
      const bool streamingWaveBank = IsStreamingWaveBank(waveBankPath.c_str());
      gpg::Logf("IsStreamingWaveBank(\"%s\") => %s", waveBankPath.c_str(), streamingWaveBank ? "true" : "false");

      AudioWaveBankLoaderBase* waveBankLoader = nullptr;
      if (streamingWaveBank) {
        waveBankLoader = new (std::nothrow) AudioStreamingWaveBankLoader(impl);
      } else {
        waveBankLoader = new (std::nothrow) AudioInMemoryWaveBankLoader(impl);
      }

      if (waveBankLoader != nullptr && waveBankLoader->Load(waveBankPath.c_str())) {
        impl->mHandles.push_back(waveBankLoader);
        waveBankLoader = nullptr;
      }

      delete waveBankLoader;
    }

    waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return;
    }

    fa::vector<fa::string> soundBankPaths{};
    waitHandleSet->mHandle->EnumerateFiles(voicePath, "*.xsb", false, &soundBankPaths);

    for (const fa::string& soundBankPath : soundBankPaths) {
      auto* soundBankLoader = new (std::nothrow) AudioSoundBankLoader{};
      if (soundBankLoader != nullptr) {
        soundBankLoader->mEngine = impl;
      }

      if (soundBankLoader != nullptr && soundBankLoader->Load(soundBankPath.c_str())) {
        impl->mBanks.push_back(soundBankLoader);
        soundBankLoader = nullptr;
      }

      if (soundBankLoader != nullptr) {
        DestroyAudioSoundBankLoaderNoDelete(soundBankLoader);
        operator delete(soundBankLoader);
      }
    }
  }

  /**
   * Address: 0x004D8A50 (FUN_004D8A50, func_SoundErrorCodeToMsg)
   *
   * What it does:
   * Translates XACT/HRESULT error codes into user-facing warning strings.
   */
  const char* func_SoundErrorCodeToMsg(
    const int errorCode
  )
  {
    const std::uint32_t code = static_cast<std::uint32_t>(errorCode);
    switch (code) {
    case 0x8007000Eu:
      return "Out of memory";
    case 0x80004001u:
      return "Not implemented";
    case 0x80004005u:
      return "Unknown error";
    case 0x80070057u:
      return "Invalid arg";

    case 0x8AC70001u:
      return "The engine is already initialized";
    case 0x8AC70002u:
      return "The engine has not been initialized";
    case 0x8AC70003u:
      return "The engine has expired (demo or pre-release version)";
    case 0x8AC70004u:
      return "No notification callback";
    case 0x8AC70005u:
      return "Notification already registered";
    case 0x8AC70006u:
      return "Invalid usage";
    case 0x8AC70007u:
      return "Invalid data";
    case 0x8AC70008u:
      return "Fail to play due to instance limit";
    case 0x8AC70009u:
      return "Global Settings not loaded";
    case 0x8AC7000Au:
      return "Invalid variable index";
    case 0x8AC7000Bu:
      return "Invalid category";
    case 0x8AC7000Cu:
      return "Invalid cue index";
    case 0x8AC7000Du:
      return "Invalid wave index";
    case 0x8AC7000Eu:
      return "Invalid track index";
    case 0x8AC7000Fu:
      return "Invalid sound offset or index";
    case 0x8AC70010u:
      return "Error reading a file";
    case 0x8AC70011u:
      return "Unknown event type";
    case 0x8AC70012u:
      return "Invalid call of method of function from callback";
    case 0x8AC70013u:
      return "No wavebank exists for desired operation";
    case 0x8AC70014u:
      return "Unable to select a variation";
    case 0x8AC70015u:
      return "There can be only one audition engine";
    case 0x8AC70016u:
      return "The wavebank is not prepared";
    case 0x8AC70017u:
      return "No audio device found on.";
    case 0x8AC70018u:
      return "Invalid entry count for channel maps";

    case 0x8AC70101u:
      return "Error writing a file during auditioning";
    case 0x8AC70102u:
      return "Missing a soundbank";
    case 0x8AC70103u:
      return "Missing an RPC curve";
    case 0x8AC70104u:
      return "Missing data for an audition command";
    case 0x8AC70105u:
      return "Unknown command";
    case 0x8AC70106u:
      return "Missing a DSP parameter";

    default:
      return "Unknown XACT Error";
    }
  }

  /**
   * Address: 0x004D81E0 (FUN_004D81E0, func_X3DAudioCalculate)
   *
   * What it does:
   * Validates listener/emitter/settings pointers, injects default azimuth
   * layouts for common channel counts when missing, applies default flat
   * distance curves, and dispatches one `X3DAudioCalculate` solve.
   */
  int func_X3DAudioCalculate(
    Audio3DEmitter* const emitter,
    const Audio3DListener* const listener,
    Audio3DDspSettings* const settings,
    const void* const audioHandle
  )
  {
    if (listener == nullptr || emitter == nullptr || settings == nullptr) {
      return kHresultPointer;
    }

    if (emitter->mChannelCount > 1u && emitter->mChannelAzimuths == nullptr) {
      emitter->mChannelRadius = 1.0f;
      switch (emitter->mChannelCount) {
      case 2u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths2.data());
        break;
      case 3u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths3.data());
        break;
      case 4u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths4.data());
        break;
      case 5u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths5.data());
        break;
      case 6u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths6.data());
        break;
      case 8u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths8.data());
        break;
      default:
        return kHresultFail;
      }
    }

    if (emitter->mVolumeCurve == nullptr) {
      emitter->mVolumeCurve = const_cast<AudioDistanceCurve*>(&kDefaultDistanceCurve);
    }
    if (emitter->mLfeCurve == nullptr) {
      emitter->mLfeCurve = const_cast<AudioDistanceCurve*>(&kDefaultDistanceCurve);
    }

    if (X3DAudio().mCalculate == nullptr) {
      return kHresultFail;
    }
    X3DAudio().mCalculate(audioHandle, listener, emitter, kX3dCalculateFlags, settings);
    return 0;
  }

  namespace
  {
    void RegisterNotificationOrWarn(
      AudioEngineImpl* const impl,
      const std::uint8_t notificationType
    )
    {
      if (impl == nullptr || impl->mInstance == nullptr) {
        return;
      }

      AudioNotificationDesc notification{};
      notification.type = notificationType;
      notification.flags = 1u;

      const int result = impl->mInstance->RegisterNotification(&notification);
      if (result < 0) {
        gpg::Warnf("SND: Error registering notification.\n%s", func_SoundErrorCodeToMsg(result));
      }
    }
  } // namespace

  /**
   * Address: 0x004D84D0 (FUN_004D84D0, func_SoundConfigInit)
   *
   * IDA signature:
   * struct_SoundConfig *__usercall func_SoundConfigInit@<eax>(struct_SoundConfig *this@<esi>);
   *
   * What it does:
   * Default-initializes a freshly allocated `SoundConfiguration`:
   * default-constructs the embedded `gpg::time::Timer`, zeros the
   * engine-pointer vector lanes, zeros the global settings memory
   * buffer lanes, primes the speaker-configuration field to `3`, and
   * clears every remaining flag, runtime-module pointer, and reserved
   * trailing dword. The binary returns `this`; the C++ ctor returns
   * implicitly.
   */
  SoundConfiguration::SoundConfiguration() noexcept
    : mTime{}
    , mEngines{}
    , mGlobalSettingsBuffer{}
    , mNoSound(0u)
    , mReserved29{}
    , mSpeakerConfiguration(3u)
    , mAudioModule(nullptr)
    , mRuntimeParams{}
    , mAudition(0u)
    , mReserved59{}
  {}

  /**
   * Address: 0x004D9250 (FUN_004D9250, ??1struct_SoundConfig@@QAE@@Z)
   * Mangled: ??1struct_SoundConfig@@QAE@@Z
   *
   * What it does:
   * Clears all active `AudioEngineImpl` lanes, unloads optional audio runtime
   * module state, and releases retained shared engine references.
   */
  SoundConfiguration::~SoundConfiguration()
  {
    for (const std::shared_ptr<AudioEngine>& entry : mEngines) {
      AudioEngine* const engine = entry.get();
      if (engine == nullptr) {
        continue;
      }

      AudioEngineImpl* const impl = engine->mImpl;
      engine->mImpl = nullptr;
      if (impl != nullptr) {
        impl->~AudioEngineImpl();
        operator delete(impl);
      }
    }

    if (mAudioModule != nullptr) {
      (void)::FreeLibrary(static_cast<HMODULE>(mAudioModule));
      mAudioModule = nullptr;
    }

    // The engine references are released, and the storage freed, by `mEngines`' own destructor.
  }

  std::uint32_t SoundConfiguration::EngineCount() const
  {
    return static_cast<std::uint32_t>(mEngines.size());
  }

  AudioEngineImpl* SoundConfiguration::EngineImplAt(
    const std::uint32_t index
  ) const
  {
    const std::uint32_t engineCount = EngineCount();
    if (index >= engineCount) {
      return nullptr;
    }

    AudioEngine* const engine = mEngines[index].get();
    if (engine == nullptr) {
      return nullptr;
    }

    return engine->mImpl;
  }

  /**
   * Address: 0x004D8810 (FUN_004D8810, func_HandleSoundEvent)
   *
   * What it does:
   * Handles XACT notification event payloads and emits diagnostics for
   * variable-value changes, GUI connect/disconnect signals, and wavebank
   * streaming state changes.
   */
  void __stdcall func_HandleSoundEvent(
    const AudioNotification* const eventDataBytes
  )
  {
    if (eventDataBytes == nullptr) {
      return;
    }

    const auto& eventData = *eventDataBytes;
    switch (eventData.type) {
    case 0x08:
      gpg::Logf("SND: Local var changed %i = %f", eventData.variable.variableIndex, eventData.variable.variableValue);
      break;

    case 0x09: {
      const fa::string variableName = SND_GetVariableName(static_cast<int>(eventData.variable.variableIndex));
      gpg::Logf("SND: Global var changed [%s] = %f", variableName.c_str(), eventData.variable.variableValue);
      break;
    }

    case 0x0A:
      gpg::Logf("SND: Gui Connected");
      break;

    case 0x0B:
      gpg::Logf("SND: Gui Disconnected");
      break;

    case 0x11:
      gpg::Debugf("Wavebank prepared: %p", static_cast<void*>(eventData.waveBank.pWaveBank));
      break;

    case 0x12:
      gpg::Logf("Error streaming from wavebank %p, invalid content", static_cast<void*>(eventData.waveBank.pWaveBank));
      break;

    default:
      break;
    }
  }

  /**
   * Address: 0x004D8C00 (FUN_004D8C00, func_InitSound)
   *
   * IDA signature:
   * void callcnv_33 func_InitSound();
   *
   * What it does:
   * Allocates and initializes a fresh `SoundConfiguration` slot,
   * replaces any existing global, parses the `/audition` and
   * `/nosound` CLI flags. When sound is enabled it also primes the
   * lookahead time to 250ms, wires the XACT notification handler,
   * loads the global settings buffer from `/sounds/SupCom.xgs` via
   * the file wait handle set + VFS, exposes the loaded buffer's
   * range through `mGlobalSettingsStart`/`mGlobalSettingsLength`,
   * then queries DirectSound for the current speaker channel mode
   * and stores it in `mSpeakerConfiguration`.
   */
  void func_InitSound()
  {
    sSoundConfiguration.reset(new SoundConfiguration());

    sSoundConfiguration->mAudition =
      static_cast<std::uint8_t>(moho::CFG_GetArgOption("/audition", 0u, nullptr) ? 1u : 0u);
    sSoundConfiguration->mNoSound =
      static_cast<std::uint8_t>(moho::CFG_GetArgOption("/nosound", 0u, nullptr) ? 1u : 0u);

    if (sSoundConfiguration->mNoSound == 0u) {
      sSoundConfiguration->mRuntimeParams.lookAheadTime = 250u;
      sSoundConfiguration->mRuntimeParams.fnNotificationCallback = &moho::func_HandleSoundEvent;
      sSoundConfiguration->mRuntimeParams.globalSettingsFlags = 0u;

      moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
      fa::string mountedPath{};
      const fa::string* const resolvedPath =
        waitHandleSet->mHandle->FindFile(&mountedPath, "/sounds/SupCom.xgs", nullptr);

      gpg::MemBuffer<char> loadedBuffer = moho::DISK_ReadFile(resolvedPath->c_str());
      sSoundConfiguration->mGlobalSettingsBuffer = loadedBuffer;

      if (sSoundConfiguration->mGlobalSettingsBuffer.mBegin != nullptr) {
        sSoundConfiguration->mRuntimeParams.globalSettingsBufferSize = static_cast<std::uint32_t>(
          sSoundConfiguration->mGlobalSettingsBuffer.mEnd - sSoundConfiguration->mGlobalSettingsBuffer.mBegin
        );
        sSoundConfiguration->mRuntimeParams.pGlobalSettingsBuffer = sSoundConfiguration->mGlobalSettingsBuffer.mBegin;
      }
    }

#if !FAFRE_PLATFORM_WINDOWS
    // The Linux client (issue #258) has no DirectSound to ask: stereo, the default the Windows
    // code falls back to as well. The cues' matrices follow FAudio's final mix format.
    sSoundConfiguration->mSpeakerConfiguration = 3u;
#else
    LPDIRECTSOUND directSound = nullptr;
    if (::DirectSoundCreate(nullptr, &directSound, nullptr) >= 0) {
      DWORD speakerConfig = 0;
      directSound->GetSpeakerConfig(&speakerConfig);
      switch (static_cast<std::uint8_t>(speakerConfig)) {
      case 0u:
      case 1u:
      case 2u:
      case 3u:
      case 4u:
      case 5u:
      case 7u:
        sSoundConfiguration->mSpeakerConfiguration = 3u;
        break;
      case 6u:
        sSoundConfiguration->mSpeakerConfiguration = 63u;
        break;
      default:
        gpg::Warnf(
          "Unknown DirectSound speaker configuration %i. Defaulting to Stereo.",
          static_cast<unsigned>(static_cast<std::uint8_t>(speakerConfig))
        );
        sSoundConfiguration->mSpeakerConfiguration = 3u;
        break;
      }
      directSound->Release();
    } else {
      gpg::Warnf("Failed to create DirectSound.");
    }
#endif
  }

  /**
   * Address: 0x004D8EE0 (FUN_004D8EE0, ?SND_Shutdown@Moho@@YAXXZ)
   *
   * What it does:
   * Clears and destroys the process-global sound configuration singleton.
   */
  void SND_Shutdown()
  {
    sSoundConfiguration.reset();
  }

  /**
   * Address: 0x004D8F40 (FUN_004D8F40, ?SND_Frame@Moho@@YAXXZ)
   *
   * What it does:
   * Advances XACT engine work queues for each configured audio engine and
   * resets the global sound-configuration frame timer.
   */
  void SND_Frame()
  {
    SoundConfiguration* configuration = GetSoundConfigurationSingletonB();
    if (configuration == nullptr) {
      return;
    }

    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      if (
        AudioEngineImpl* const impl = configuration->EngineImplAt(index); impl != nullptr && impl->mInstance != nullptr
      ) {
        impl->mInstance->DoWork();
        configuration = GetSoundConfigurationSingletonB();
      }
    }

    configuration->mTime.Reset();
  }

  /**
   * Address: 0x004D8F90 (FUN_004D8F90)
   *
   * What it does:
   * Issues one additional SND frame pass when `snd_ExtraDoWorkCalls` is
   * enabled and the sound frame timer exceeded 100ms.
   */
  void SND_FrameExtraDoWorkTick()
  {
    SoundConfiguration* const configuration = GetSoundConfigurationSingletonA();
    if (configuration == nullptr) {
      return;
    }

    if (moho::snd_ExtraDoWorkCalls && configuration->mTime.ElapsedMilliseconds() > 100.0f) {
      SND_Frame();
    }
  }

  /**
   * Address: 0x004D8FC0 (FUN_004D8FC0, ?SND_Mute@Moho@@YAX_N@Z)
   *
   * What it does:
   * Stores/restores per-engine "Global" category volume while applying
   * process-wide mute transitions.
   */
  void SND_Mute(
    const bool doMute
  )
  {
    SND_MuteFor(kSndMuteMinimized, doMute);
  }

  namespace
  {
    std::uint32_t sMuteReasons = 0;
    std::uint32_t sMuteTransitions = 0;
  } // namespace

  std::uint32_t SND_MuteReasons()
  {
    return sMuteReasons;
  }

  std::uint32_t SND_MuteTransitions()
  {
    return sMuteTransitions;
  }

  void SND_MuteFor(
    const std::uint32_t reason,
    const bool on
  )
  {
    // The binary's SND_Mute body, run only when the muted state changes: with two reasons (minimized, the editor's
    // unfocused window), muting twice would save the first mute's zero as the volume to give back.
    const bool wasMuted = sMuteReasons != 0;
    sMuteReasons = on ? (sMuteReasons | reason) : (sMuteReasons & ~reason);
    const bool doMute = sMuteReasons != 0;
    if (doMute == wasMuted) {
      return;
    }
    ++sMuteTransitions;
    SoundConfiguration* configuration = GetSoundConfigurationSingletonB();
    if (configuration == nullptr) {
      return;
    }

    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      AudioEngineImpl* const impl = configuration->EngineImplAt(index);
      if (impl == nullptr || impl->mInstance == nullptr) {
        continue;
      }

      ApplyGlobalMuteToEngine(*impl, doMute);
      configuration = GetSoundConfigurationSingletonB();
    }
  }

  /**
   * Address: 0x004D9040 (FUN_004D9040, ?SND_GetGlobalVarIndex@Moho@@...)
   *
   * gpg::StrArg variableName, std::uint16_t* outVarIndex
   *
   * What it does:
   * Resolves one global XACT variable index from the active primary engine.
   */
  bool SND_GetGlobalVarIndex(
    const gpg::StrArg variableName,
    std::uint16_t* const outVarIndex
  )
  {
    if (outVarIndex == nullptr) {
      return false;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration == nullptr || configuration->mEngines.empty() || configuration->mNoSound != 0u) {
      return false;
    }

    AudioEngine* const engine = configuration->mEngines[0].get();
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return false;
    }

    const std::uint16_t variableId = engine->mImpl->mInstance->GetGlobalVariableIndex(variableName);
    *outVarIndex = variableId;
    return variableId != kInvalidVariableId;
  }

  /**
   * Address: 0x004D9090 (FUN_004D9090, ?SND_GetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex
   *
   * What it does:
   * Reads one global XACT variable value from the active primary engine.
   */
  float SND_GetGlobalFloat(
    const std::uint16_t varIndex
  )
  {
    const SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration == nullptr || configuration->mEngines.empty() || configuration->mNoSound != 0u) {
      return gpg::NaN;
    }

    AudioEngine* const engine = configuration->mEngines[0].get();
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return gpg::NaN;
    }

    float value = gpg::NaN;
    if (engine->mImpl->mInstance->GetGlobalVariable(varIndex, &value) < 0) {
      return gpg::NaN;
    }
    return value;
  }

  /**
   * Address: 0x004D90E0 (FUN_004D90E0, ?SND_SetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex, float value
   *
   * What it does:
   * Writes one global XACT variable value on the active primary engine.
   */
  void SND_SetGlobalFloat(
    const std::uint16_t varIndex,
    const float value
  )
  {
    const SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration == nullptr || configuration->mEngines.empty() || configuration->mNoSound != 0u) {
      return;
    }

    AudioEngine* const engine = configuration->mEngines[0].get();
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return;
    }

    if (engine->mImpl->mInstance->SetGlobalVariable(varIndex, value) < 0) {
      gpg::Warnf("SND: Error setting global variable [index:%i]", varIndex);
    }
  }

  /**
   * Address: 0x004D9140 (FUN_004D9140, ?SND_FindEngine@Moho@@...)
   *
   * gpg::StrArg
   *
   * What it does:
   * Finds one loaded `AudioEngine` that owns a bank matching the supplied
   * bank name.
   */
  std::shared_ptr<AudioEngine> SND_FindEngine(
    const gpg::StrArg bankName
  )
  {
    SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration == nullptr || bankName == nullptr || configuration->mEngines.empty()) {
      return {};
    }

    const std::size_t engineCount = configuration->mEngines.size();
    for (std::size_t engineIndex = 0; engineIndex < engineCount; ++engineIndex) {
      const std::shared_ptr<AudioEngine>& engineRef = configuration->mEngines[engineIndex];
      AudioEngine* const engine = engineRef.get();
      if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mBanks.empty()) {
        continue;
      }

      const std::size_t bankCount = engine->mImpl->mBanks.size();
      for (std::size_t bankIndex = 0; bankIndex < bankCount; ++bankIndex) {
        auto* const loader = static_cast<AudioSoundBankLoader*>(engine->mImpl->mBanks.begin()[bankIndex]);
        if (loader == nullptr || ::_stricmp(bankName, loader->mName.c_str()) != 0) {
          continue;
        }
        return engineRef;
      }
    }

    return {};
  }

  /**
   * Address: 0x004D9410 (FUN_004D9410, ??0AudioEngine@Moho@@AAE@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Allocates and binds `AudioEngineImpl`, initializes XACT + 3D audio lanes,
   * loads voice/sound path data, and applies startup listener/category state.
   */
  AudioEngine::AudioEngine(
    const gpg::StrArg voicePath
  )
    : mImpl(nullptr)
  {
    SoundConfiguration* const configuration = sSoundConfiguration.get();
    ReplaceAudioEngineImplPointer(mImpl, new AudioEngineImpl(this, configuration));

    if (configuration == nullptr || configuration->mNoSound != 0u || mImpl == nullptr) {
      return;
    }

    func_RetreiveXACTCOMInterface(mImpl);
    if (mImpl->mInstance == nullptr) {
      return;
    }

    gpg::MD5Context md5Context{};
    md5Context.Reset();
    md5Context.Update(
      configuration->mRuntimeParams.pGlobalSettingsBuffer, configuration->mRuntimeParams.globalSettingsBufferSize
    );
    const fa::string globalSettingsDigest = md5Context.Digest().ToString();
    gpg::Logf("MD5 of global settings: %s", globalSettingsDigest.c_str());

    // FUN_004D9410 passes SoundConfiguration +0x34, the embedded XACT 2.5
    // parameter object. Typed callback fields grow and align natively on x64.
    const int initializeResult = mImpl->mInstance->Initialize(&configuration->mRuntimeParams);
    if (initializeResult < 0) {
      // The HRESULT too (engine addition): "Unknown XACT Error" alone doesn't say which.
      gpg::Warnf(
        "SND: Error initializing audio engine.\n%s (0x%08X)",
        func_SoundErrorCodeToMsg(initializeResult),
        static_cast<unsigned>(initializeResult)
      );
      configuration->mNoSound = 1u;
      return;
    }

    const int audio3dResult = func_AudioInitialize(mImpl->mInstance, mImpl->mAudioHandle);
    if (audio3dResult < 0) {
      gpg::Warnf("SND: Error initializing 3D audio.\n%s", func_SoundErrorCodeToMsg(audio3dResult));
      configuration->mNoSound = 1u;
      return;
    }

    // Deliberate change from retail: retail sized mSettings (mDelayTimes and
    // mMatrixCoefficients) in AudioEngineImpl using ResolveDstChannelCount from
    // DirectSound's speaker setting (which on modern Windows reports 9/8 for
    // 5.1/7.1 Surround and defaults to stereo, 2 floats). X3DAudio is initialized
    // from XACT's real output channel mask (GetFinalMixFormat). If the output has
    // 5.1/7.1 channels (6 or 8 floats), X3DAudioCalculate writes past the 2-float
    // buffer into adjacent heap memory (corrupting AudioEngine instances), and
    // SetMatrixCoefficients fails with "XACT3DApply failed: Invalid arg".
    // Size mSettings from the real output channel count from GetFinalMixFormat.
    WAVEFORMATEXTENSIBLE finalMixFormat{};
    if (mImpl->mInstance->GetFinalMixFormat(&finalMixFormat) >= 0) {
      const std::uint32_t realDstChannels = finalMixFormat.Format.nChannels;
      if (realDstChannels != 0u && realDstChannels != mImpl->mSettings.mDstChannelCount) {
        delete[] mImpl->mSettings.mDelayTimes;
        delete[] mImpl->mSettings.mMatrixCoefficients;
        mImpl->mSettings.mDstChannelCount = realDstChannels;
        mImpl->mSettings.mDelayTimes = new float[realDstChannels]();
        mImpl->mSettings.mMatrixCoefficients = new float[realDstChannels * mImpl->mSettings.mSrcChannelCount]();
      }
    }

    RegisterNotificationOrWarn(mImpl, 10u);
    RegisterNotificationOrWarn(mImpl, 11u);
    RegisterNotificationOrWarn(mImpl, 17u);
    RegisterNotificationOrWarn(mImpl, 18u);

    gpg::Logf("MEM: %i bytes SND", 0);
    func_LoadSoundPath(mImpl, voicePath);

    if (CFG_GetArgOption("/nomusic", 0, nullptr)) {
      SetVolume("Music", 0.0f);
    }

    VTransform listenerTransform{};
    listenerTransform.pos_.x = 0.0f;
    listenerTransform.pos_.y = 0.0f;
    listenerTransform.pos_.z = 0.0f;
    SetListenerTransform(listenerTransform);
  }

  /**
   * Address: 0x004D9340 (FUN_004D9340,
   * ?Create@AudioEngine@Moho@@SA?AV?$shared_ptr@VAudioEngine@Moho@@@boost@@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Ensures global audio configuration exists, creates one `AudioEngine`
   * object through the recovered constructor lane, and registers it into the
   * process-global engine lane used by `SND_Frame`/`SND_Mute`.
   */
  std::shared_ptr<AudioEngine> AudioEngine::Create(
    const gpg::StrArg voicePath
  )
  {
    // The binary opens with `if (!sSoundConfiguration) func_InitSound();`, and
    // func_InitSound is the only thing that builds a *usable* configuration: it
    // parses /audition and /nosound, primes the 250 ms look-ahead, installs
    // func_HandleSoundEvent as the XACT notification handler, loads
    // /sounds/SupCom.xgs into the global settings buffer and probes the
    // DirectSound speaker mode.
    //
    // This used to call a local EnsureSoundConfigurationForCreate() helper that
    // allocated a bare SoundConfiguration with mNoSound = 1 and
    // mHandleSoundEvent = nullptr, so the engine came up permanently muted with
    // no notification sink - zero "Wavebank prepared" lines, against 270 from
    // the shipped binary on the same startup.
    if (!sSoundConfiguration) {
      func_InitSound();
    }

    AudioEngine* const createdEngine = new AudioEngine(voicePath);

    // Address: 0x004DE750 (FUN_004DE750 -- this shared_ptr's `sp_counted_impl_p<AudioEngine>::dispose`: deletes the
    // engine, whose destructor deletes its `AudioEngineImpl`; formerly `DestroyAudioEngineImplOwnedByCountedBlock`
    // over a hand-made control-block layout in this file.)
    std::shared_ptr<AudioEngine> result(createdEngine);
    if (sSoundConfiguration && createdEngine != nullptr) {
      RegisterEngineRef(*sSoundConfiguration, result);
    }

    return result;
  }

  /**
   * Address: 0x004D93F0 (FUN_004D93F0)
   *
   * What it does:
   * Detaches and destroys the current implementation object.
   */
  void AudioEngine::Shutdown()
  {
    AudioEngineImpl* const impl = mImpl;
    mImpl = nullptr;
    if (impl == nullptr) {
      return;
    }

    impl->~AudioEngineImpl();
    operator delete(impl);
  }

  /**
   * Address: 0x004D9760 (FUN_004D9760)
   *
   * What it does:
   * Releases the active implementation object when present.
   */
  AudioEngine::~AudioEngine()
  {
    if (mImpl == nullptr) {
      return;
    }

    mImpl->~AudioEngineImpl();
    operator delete(mImpl);
  }

  /**
   * Address: 0x004D9780 (FUN_004D9780)
   *
   * What it does:
   * Reconstructs the listener transform from stored 3D listener axes.
   */
  VTransform AudioEngine::GetListenerTransform()
  {
    VTransform out{};
    if (mImpl == nullptr) {
      return out;
    }

    out.pos_.x = mImpl->mListener.mPosition.x;
    out.pos_.y = mImpl->mListener.mPosition.y;
    out.pos_.z = mImpl->mListener.mPosition.z;
    out.orient_ = BuildListenerOrientation(mImpl->mListener);
    return out;
  }

  /**
   * Address: 0x004D9FF0 (FUN_004D9FF0)
   *
   * Moho::AudioEngine*, Moho::SoundConfiguration*
   *
   * What it does:
   * Initializes map/vector sentinels, 3D emitter/listener state, and DSP buffers.
   */
  AudioEngineImpl::AudioEngineImpl(
    AudioEngine* const engine,
    SoundConfiguration* const configuration
  )
    : mConfigs(configuration)
    , mEngine(engine)
    , mBanks{}
    , mHandles{}
    , mPausedCategoryNames{}
    , mInstance(nullptr)
    , mListener{}
    , mCategoryVolumes{}
    , mGlobalCategoryVolume(0.0f)
    , mSettings{}
    , mEmitter{}
    , mAudioHandle{}
  {

    // mPausedCategoryNames (fa::set<fa::string>) and mCategoryVolumes
    // (fa::map<std::uint16_t, float>) both construct themselves via their
    // own member initializers above -- see RbTree.h's `rb_tree()` ctor
    // citations for both instantiations.
    mGlobalCategoryVolume = 0.0f;

    std::memset(&mSettings, 0, sizeof(mSettings));
    mSettings.mSrcChannelCount = 1u;
    mSettings.mDstChannelCount = ResolveDstChannelCount(configuration);
    mSettings.mDelayTimes = new float[mSettings.mDstChannelCount];
    mSettings.mMatrixCoefficients = new float[mSettings.mDstChannelCount * mSettings.mSrcChannelCount];

    std::memset(&mEmitter, 0, sizeof(mEmitter));
    mEmitter.mChannelCount = 1u;
    mEmitter.mCone = nullptr;
    mEmitter.mPosition.x = 0.0f;
    mEmitter.mPosition.y = 0.0f;
    mEmitter.mPosition.z = 0.0f;
    mEmitter.mVelocity.x = 0.0f;
    mEmitter.mVelocity.y = 0.0f;
    mEmitter.mVelocity.z = 0.0f;
    mEmitter.mCurveDistanceScaler = 1.0f;
    mEmitter.mOrientFront.z = 1.0f;
    mEmitter.mOrientTop.y = 1.0f;

    std::memset(&mListener, 0, sizeof(mListener));
    std::memset(mAudioHandle, 0, sizeof(mAudioHandle));
  }

  /**
   * Address: 0x004DA2A0 (FUN_004DA2A0)
   *
   * What it does:
   * Releases banks/maps/3D buffers and the active XACT engine instance.
   */
  AudioEngineImpl::~AudioEngineImpl()
  {
    // The banks and wave banks go first, while `mInstance` is still alive:
    // every loader's dtor calls `Destroy()` on an `IXACTSoundBank` /
    // `IXACTWaveBank` that the engine instance owns, so shutting the engine
    // down ahead of them leaves those dtors dispatching through freed vtables.
    // 0x004DA2CB-0x004DA35D clears mBanks (+0x08) and then mHandles (+0x18) --
    // both through the destroy-range helper, then an `erase(begin(), end())`
    // that only walks the end iterator back -- and reaches the engine
    // teardown at 0x004DA360 with both already empty.
    DeleteSoundBankLoaders(mBanks.begin(), mBanks.end());
    mBanks.clear();

    DeleteWaveBankLoaders(mHandles.begin(), mHandles.end());
    mHandles.clear();

    if (mInstance != nullptr) {
      mInstance->ShutDown();
      mInstance->Release();
      mInstance = nullptr;
    }

    delete[] mSettings.mDelayTimes;
    mSettings.mDelayTimes = nullptr;
    delete[] mSettings.mMatrixCoefficients;
    mSettings.mMatrixCoefficients = nullptr;

    // The storage behind mBanks/mHandles is released by their own implicit
    // member destructors, which is where 0x004DA475 and 0x004DA4CC free it --
    // by then both ranges are empty, so those emissions only free the buffer.
    //
    // mCategoryVolumes (fa::map<std::uint16_t, float>) and
    // mPausedCategoryNames (fa::set<fa::string>) both tear themselves
    // down via their own implicit member destructors, which run AFTER this
    // point in reverse declaration order: mCategoryVolumes (declared later in
    // AudioEngineImpl) destructs before mPausedCategoryNames (declared
    // earlier). This matches the real binary's own call order at 0x004DA2A0,
    // which tears down mMap2 (FUN_004DA250) before mMap1 (FUN_004DBD30) --
    // reproduced here for free purely from declaration order, with no
    // hand-written call needed for either tree. See RbTree.h's `~rb_tree()`
    // citations for both instantiations.
  }

  /**
   * Address: 0x004D9B30 (FUN_004D9B30)
   *
   * std::uint16_t bankId, IXACTCue**, AudioEngine*, std::uint16_t cueId, std::int32_t preloadOnly
   *
   * What it does:
   * Dispatches cue playback through the current engine/bank selection.
   */
  int AudioEngine::Play(
    const std::uint16_t bankId,
    IXACTCue** const outCue,
    AudioEngine* const engine,
    const std::uint16_t cueId,
    const std::int32_t preloadOnly
  )
  {
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return 1;
    }

    AudioSoundBankLoader* const loader = FindBankLoader(engine->mImpl, bankId);
    if (loader == nullptr || loader->mBank == nullptr) {
      if (outCue != nullptr) {
        *outCue = nullptr;
      }
      return static_cast<int>(0x80004003u);
    }

    const int result =
      preloadOnly != 0 ? loader->mBank->Prepare(cueId, 0u, 0u, outCue) : loader->mBank->Play(cueId, 0u, 0u, outCue);
    if (result >= 0) {
      return result;
    }

    // Every failure clears the cue, a play the instance limit refused too; only that one isn't
    // logged (0x004D9B77: `mov [edi], 0`, then 0x004D9B81: `cmp esi, 0x8ac70008` / `je` past the
    // warning).
    if (outCue != nullptr) {
      *outCue = nullptr;
    }
    if (result == kXactErrInstanceLimitFailToPlay) {
      return result;
    }

    gpg::Warnf(
      "SND: Error playing cue %i on bank %i [%s]\nXACT: %s",
      cueId,
      bankId,
      loader->mName.c_str(),
      func_SoundErrorCodeToMsg(result)
    );
    return result;
  }

  /**
   * Address: 0x004D9BD0 (FUN_004D9BD0)
   *
   * gpg::StrArg bankName, std::uint16_t* outBankId
   *
   * What it does:
   * Finds one loaded sound-bank index by case-insensitive bank name.
   */
  bool AudioEngine::GetBankIndex(
    const gpg::StrArg bankName,
    std::uint16_t* const outBankId
  )
  {
    if (bankName == nullptr || outBankId == nullptr || mImpl == nullptr || mImpl->mBanks.empty()) {
      return false;
    }

    const std::size_t bankCount = mImpl->mBanks.size();
    for (std::size_t bankIndex = 0; bankIndex < bankCount; ++bankIndex) {
      auto* const loader = static_cast<AudioSoundBankLoader*>(mImpl->mBanks.begin()[bankIndex]);
      if (loader == nullptr || ::_stricmp(loader->mName.c_str(), bankName) != 0) {
        continue;
      }

      *outBankId = static_cast<std::uint16_t>(bankIndex);
      return true;
    }

    return false;
  }

  /**
   * Address: 0x004D9C40 (FUN_004D9C40)
   *
   * gpg::StrArg cueName, std::uint16_t bankId, std::uint16_t* outCueId
   *
   * What it does:
   * Resolves one cue index from one loaded sound bank.
   */
  bool AudioEngine::GetCueIndex(
    const gpg::StrArg cueName,
    const std::uint16_t bankId,
    std::uint16_t* const outCueId
  )
  {
    if (cueName == nullptr || outCueId == nullptr || mImpl == nullptr || mImpl->mBanks.empty()) {
      return false;
    }

    const std::size_t bankCount = mImpl->mBanks.size();
    if (static_cast<std::size_t>(bankId) >= bankCount) {
      return false;
    }

    auto* const loader = static_cast<AudioSoundBankLoader*>(mImpl->mBanks.begin()[bankId]);
    if (loader == nullptr || loader->mBank == nullptr) {
      return false;
    }

    const std::uint16_t cueId = loader->mBank->GetCueIndex(cueName);
    *outCueId = cueId;
    return cueId != 0xFFFFu;
  }

  /**
   * Address: 0x004D9C90 (FUN_004D9C90, ?SetPaused@AudioEngine@Moho@@QAEXVStrArg@gpg@@_N@Z)
   *
   * gpg::StrArg category, bool paused
   *
   * What it does:
   * Pauses or unpauses one named sound category and updates the paused
   * category tracking map on success.
   */
  void AudioEngine::SetPaused(
    const gpg::StrArg category,
    const bool paused
  )
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Warnf("SND: SetPaused - Invalid Category [%s]", category);
      return;
    }

    const int result = mImpl->mInstance->Pause(categoryId, paused ? 1 : 0);
    if (result < 0) {
      gpg::Warnf("SND: Error pausing category %s\n%s", category, func_SoundErrorCodeToMsg(result));
      return;
    }

    if (paused) {
      mImpl->mPausedCategoryNames.insert(category);
    } else {
      mImpl->mPausedCategoryNames.erase(category);
    }
  }

  /**
   * Address: 0x004D9F50 (FUN_004D9F50, ?StopAllSounds@AudioEngine@Moho@@QAEXVStrArg@gpg@@@Z)
   *
   * gpg::StrArg category
   *
   * What it does:
   * Stops all playing cues in one resolved XACT category.
   */
  void AudioEngine::StopAllSounds(
    const gpg::StrArg category
  )
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Warnf("SND: StopAllSounds - Invalid Category [%s]", category);
      return;
    }

    mImpl->mInstance->Stop(categoryId, 0);
  }

  /**
   * Address: 0x004D9DB0 (FUN_004D9DB0)
   *
   * gpg::StrArg, float
   *
   * What it does:
   * Sets volume scalar for the named sound category.
   */
  void AudioEngine::SetVolume(
    const gpg::StrArg category,
    const float value
  )
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Debugf("SND: SetVolume - InvalidCategory [%s]", category);
      return;
    }

    const int result = mImpl->mInstance->SetVolume(categoryId, value);
    if (result < 0) {
      gpg::Warnf("SND: Error setting volume for category %s\n%s", category, func_SoundErrorCodeToMsg(result));
    }

    *FindOrInsertCategoryVolume(mImpl->mCategoryVolumes, categoryId) = value;
  }

  /**
   * Address: 0x004D9E50 (FUN_004D9E50)
   *
   * gpg::StrArg
   *
   * What it does:
   * Returns effective volume scalar for a category. Not a pure read: the real
   * binary calls the same find-or-insert helper `SetVolume` uses, so querying
   * a category for the first time persists a defaulted `1.0f` entry into the
   * category-volume map even though nothing was ever explicitly set.
   */
  float AudioEngine::GetVolume(
    const gpg::StrArg category
  )
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return kDefaultCategoryVolume;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Debugf("SND: GetVolume - Invalid Category [%s]", category);
      return kDefaultCategoryVolume;
    }

    return *FindOrInsertCategoryVolume(mImpl->mCategoryVolumes, categoryId);
  }

  /**
   * Address: 0x004D9890 (FUN_004D9890)
   *
   * Moho::VTransform const&
   *
   * What it does:
   * Updates listener transform for 3D cue calculations.
   */
  void AudioEngine::SetListenerTransform(
    const VTransform& transform
  )
  {
    if (mImpl == nullptr) {
      return;
    }

    mImpl->mListener.mPosition.x = transform.pos_.x;
    mImpl->mListener.mPosition.y = transform.pos_.y - 4.0f;
    mImpl->mListener.mPosition.z = transform.pos_.z;

    const float x = transform.orient_.x;
    const float y = transform.orient_.y;
    const float z = transform.orient_.z;
    const float w = transform.orient_.w;

    // Listener basis, scalar-first. Front is column 2 of the rotation matrix
    // (the local Z axis) and top is column 1 (the local Y axis); the previous
    // spelling had every lane rotated one place and gave `mOrientTop.y` a
    // `w*w` diagonal term the binary never computes.
    mImpl->mListener.mOrientFront.x = ((x * z) + (w * y)) * 2.0f;
    mImpl->mListener.mOrientFront.y = ((y * z) - (w * x)) * 2.0f;
    mImpl->mListener.mOrientFront.z = 1.0f - (((x * x) + (y * y)) * 2.0f);

    mImpl->mListener.mOrientTop.x = ((x * y) - (w * z)) * 2.0f;
    mImpl->mListener.mOrientTop.y = 1.0f - (((x * x) + (z * z)) * 2.0f);
    mImpl->mListener.mOrientTop.z = ((y * z) + (w * x)) * 2.0f;
  }

  /**
   * Address: 0x004D9A60 (FUN_004D9A60)
   * Address: 0x0128E866 (FUN_0128E866, patch_AudioEngine_Calculate3D)
   *
   * Wm3::Vector3<float> const *, AudioEngine *, IXACTCue *
   *
   * IDA signature:
   * void callcnv_E3 Moho::AudioEngine::Calculate3D(
   *   Wm3::Vector3f *a1@<eax>, Moho::AudioEngine *a2@<ecx>, struct IXACTCue *a3
   * );
   *
   * What it does:
   * Applies 3D listener/emitter transform to an active cue. A failed apply is
   * warned about once per process (FAF hot-patch, see the body).
   */
  void AudioEngine::Calculate3D(
    const Wm3::Vec3f* const worldPos,
    AudioEngine* const engine,
    IXACTCue* const cue
  )
  {
    AudioEngineImpl* const impl = engine->mImpl;
    if (impl->mInstance == nullptr) {
      return;
    }

    std::memset(&impl->mEmitter, 0, sizeof(impl->mEmitter));
    impl->mEmitter.mChannelCount = 1;
    impl->mEmitter.mCone = nullptr;
    impl->mEmitter.mPosition.x = worldPos->x;
    impl->mEmitter.mPosition.y = worldPos->y;
    impl->mEmitter.mPosition.z = worldPos->z;
    impl->mEmitter.mVelocity.x = 0.0f;
    impl->mEmitter.mVelocity.y = 0.0f;
    impl->mEmitter.mVelocity.z = 0.0f;
    impl->mEmitter.mCurveDistanceScaler = 1.0f;
    impl->mEmitter.mOrientFront.z = 1.0f;
    impl->mEmitter.mOrientTop.y = 1.0f;

    const int calculateResult = func_X3DAudioCalculate(
      &impl->mEmitter, &impl->mListener, &impl->mSettings, static_cast<const void*>(impl->mAudioHandle)
    );
    if (calculateResult < 0) {
      gpg::Warnf("SND: XACT3DCalculate failed.\n%s", func_SoundErrorCodeToMsg(calculateResult));
      return;
    }

    const int applyResult = ApplySettingsToCue(&impl->mSettings, cue);
    if (applyResult < 0) {
      // FAF hot-patch (FA-Binary-Patches xact_3dapply.cpp / section/xact_3d_fix.cpp):
      // 0x004D9A60 jumps to a copy of this body at 0x01291B52 in which this warning
      // is guarded by a process-wide byte (0x01292A60, tested at 0x01291C0D and
      // cleared at 0x01291C24 after the first log), so it is logged once per
      // process. The error-text lookup (0x004D8A50) still runs before the test.
      // The XACT3DCalculate warning above keeps logging every time.
      static bool sApplyFailureLogged = false;
      const char* const errorText = func_SoundErrorCodeToMsg(applyResult);
      if (!sApplyFailureLogged) {
        gpg::Warnf("SND: XACT3DApply failed.\n%s", errorText);
        sApplyFailureLogged = true;
      }
    }
  }

  /**
   * Address: 0x004D9FA0 (FUN_004D9FA0, ?IsStopped@AudioEngine@Moho@@QAE_NPAUIXACTCue@@@Z)
   *
   * IXACTCue* cue
   *
   * What it does:
   * Queries one cue state through `IXACTCue::GetState` and returns true when
   * the state equals `0x20` (stopped).
   */
  bool AudioEngine::IsStopped(
    IXACTCue* const cue
  ) const
  {
    // The original push ecx reserves this output local; it is not a
    // pointer-valued cue state. Successful GetState calls overwrite it.
    int cueState = 0;
    if (mImpl->mInstance == nullptr || cue == nullptr) {
      return false;
    }

    const bool queryFailed = cue->GetState(&cueState) < 0;
    if (queryFailed) {
      const char* const errorText = func_SoundErrorCodeToMsg(static_cast<int>(queryFailed));
      gpg::Warnf("SND: %s", errorText);
    }

    return cueState == 0x20;
  }
} // namespace moho
