#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/time/Timer.h"
#include "wm3/Vector3.h"

namespace moho
{
  class AudioEngine;
  class VTransform;
  class IXACTCue;
  class IXACTWaveBank;
  struct AudioEngineImpl;

  class IXACTSoundBank
  {
  public:
    /**
     * VTable slot 0 (+0x00).
     */
    virtual std::uint16_t __stdcall GetCueIndex(const char* cueName) = 0;

    virtual std::int32_t __stdcall Reserved04() = 0; // +0x04
    virtual std::int32_t __stdcall Reserved08() = 0; // +0x08

    /**
     * VTable slot 3 (+0x0C).
     */
    virtual std::int32_t __stdcall
    Prepare(std::uint16_t cueIndex, std::uint32_t flags, std::uint32_t timeOffset, IXACTCue** outCue) = 0;

    /**
     * VTable slot 4 (+0x10).
     */
    virtual std::int32_t __stdcall
    Play(std::uint16_t cueIndex, std::uint32_t flags, std::uint32_t timeOffset, IXACTCue** outCue) = 0;
  };

  class IXACTCue
  {
  public:
    /**
     * VTable slot 0 (+0x00).
     */
    virtual std::int32_t __stdcall Play() = 0;

    /**
     * VTable slot 1 (+0x04).
     */
    virtual void __stdcall Stop(std::int32_t stopFlags) = 0;

    /**
     * VTable slot 2 (+0x08).
     */
    virtual std::int32_t __stdcall GetState(std::int32_t* outState) = 0;

    /**
     * VTable slot 3 (+0x0C).
     */
    virtual std::int32_t __stdcall Destroy() = 0;

    virtual void __stdcall Reserved10() = 0; // +0x10
    virtual void __stdcall Reserved14() = 0; // +0x14
    virtual void __stdcall Reserved18() = 0; // +0x18
    virtual void __stdcall Reserved1C() = 0; // +0x1C

    /**
     * VTable slot 8 (+0x20).
     */
    virtual std::int32_t __stdcall SetMatrixCoefficients(
      std::uint32_t srcChannelCount, std::uint32_t dstChannelCount, const float* matrixCoefficients
    ) = 0;

    /**
     * VTable slot 9 (+0x24).
     */
    virtual std::uint16_t __stdcall GetVariableIndex(const char* variableName) = 0;

    /**
     * VTable slot 10 (+0x28).
     */
    virtual std::int32_t __stdcall SetVariable(std::uint16_t variableIndex, float value) = 0;
  };

  class IXACTEngine
  {
  public:
    /**
     * Slot map recovered from AudioEngine ctor/dtor, bank loaders, and
     * CUserSoundManager callsites.
     */
    virtual std::int32_t __stdcall QueryInterface(const void* riid, void** outObject) = 0; // +0x00
    virtual std::uint32_t __stdcall AddRef() = 0;                                          // +0x04
    virtual std::uint32_t __stdcall Release() = 0;                                         // +0x08
    virtual std::int32_t __stdcall GetRendererCount(std::uint16_t* outRendererCount) = 0;  // +0x0C
    virtual std::int32_t __stdcall
    GetRendererDetails(std::uint16_t rendererIndex, void* outRendererDetails) = 0;       // +0x10
    virtual std::int32_t __stdcall GetFinalMixFormat(void* outWaveFormatExtensible) = 0; // +0x14
    virtual std::int32_t __stdcall Initialize(const void* runtimeParams) = 0;            // +0x18
    virtual void __stdcall ShutDown() = 0;                                               // +0x1C
    virtual std::int32_t __stdcall DoWork() = 0;                                         // +0x20
    virtual std::int32_t __stdcall CreateSoundBank(
      const void* data,
      std::int32_t sizeBytes,
      std::uint32_t flags,
      std::uint32_t allocAttributes,
      IXACTSoundBank** outSoundBank
    ) = 0; // +0x24
    virtual std::int32_t __stdcall CreateInMemoryWaveBank(
      const void* data,
      std::int32_t sizeBytes,
      std::uint32_t flags,
      std::uint32_t allocAttributes,
      IXACTWaveBank** outWaveBank
    ) = 0; // +0x28
    virtual std::int32_t __stdcall CreateStreamingWaveBank(
      const void* streamingParams,
      IXACTWaveBank** outWaveBank
    ) = 0; // +0x2C
    virtual std::int32_t __stdcall PrepareWave(
      std::uint32_t flags,
      const char* wavePath,
      std::uint16_t streamingPacketSize,
      std::uint32_t alignment,
      std::uint32_t playOffset,
      std::uint8_t loopCount,
      void** outWave
    ) = 0; // +0x30
    virtual std::int32_t __stdcall PrepareInMemoryWave(
      std::uint32_t flags,
      const void* waveBankEntry,
      std::uint32_t* seekTable,
      std::uint8_t* waveData,
      std::uint32_t playOffset,
      std::uint8_t loopCount,
      void** outWave
    ) = 0; // +0x34
    virtual std::int32_t __stdcall PrepareStreamingWave(
      std::uint32_t flags,
      const void* waveBankEntry,
      const void* streamingParams,
      std::uint32_t alignment,
      std::uint32_t* seekTable,
      std::uint32_t playOffset,
      std::uint8_t loopCount,
      void** outWave
    ) = 0;                                                                                   // +0x38
    virtual std::int32_t __stdcall RegisterNotification(const void* notificationDesc) = 0;   // +0x3C
    virtual std::int32_t __stdcall UnRegisterNotification(const void* notificationDesc) = 0; // +0x40

    /**
     * VTable slot 17 (+0x44).
     */
    virtual std::uint16_t __stdcall GetCategory(const char* categoryName) = 0;

    /**
     * VTable slot 18 (+0x48).
     */
    virtual void __stdcall Stop(std::uint16_t category, std::int32_t flags) = 0;

    /**
     * VTable slot 19 (+0x4C).
     */
    virtual std::int32_t __stdcall SetVolume(std::uint16_t category, float volume) = 0;

    virtual std::int32_t __stdcall Pause(std::uint16_t category, std::int32_t pause) = 0; // +0x50
    virtual std::uint16_t __stdcall GetGlobalVariableIndex(const char* variableName) = 0; // +0x54

    /**
     * VTable slot 22 (+0x58).
     */
    virtual std::int32_t __stdcall SetGlobalVariable(std::uint16_t variableIndex, float value) = 0;

    virtual std::int32_t __stdcall GetGlobalVariable(std::uint16_t variableIndex, float* outValue) = 0; // +0x5C
  };

  struct AudioPointerVectorStorage
  {
    void* mAllocatorCookie; // +0x00
    void** mStart;          // +0x04
    void** mFinish;         // +0x08
    void** mEnd;            // +0x0C
  };

  struct AudioMapStorage
  {
    void* mAllocatorCookie; // +0x00
    void* mHead;            // +0x04
    std::uint32_t mSize;    // +0x08
  };

  struct Audio3DVector
  {
    float x; // +0x00
    float y; // +0x04
    float z; // +0x08
  };

  struct Audio3DListener
  {
    Audio3DVector mOrientFront; // +0x00
    Audio3DVector mOrientTop;   // +0x0C
    Audio3DVector mPosition;    // +0x18
    Audio3DVector mVelocity;    // +0x24
    void* mCone;                // +0x30
  };

  struct Audio3DDspSettings
  {
    float* mMatrixCoefficients;       // +0x00
    float* mDelayTimes;               // +0x04
    std::uint32_t mSrcChannelCount;   // +0x08
    std::uint32_t mDstChannelCount;   // +0x0C
    float mLpfDirectCoefficient;      // +0x10
    float mLpfReverbCoefficient;      // +0x14
    float mReverbLevel;               // +0x18
    float mDopplerFactor;             // +0x1C
    float mEmitterToListenerAngle;    // +0x20
    float mEmitterToListenerDistance; // +0x24
    float mEmitterVelocityComponent;  // +0x28
    float mListenerVelocityComponent; // +0x2C
  };

  struct Audio3DEmitter
  {
    void* mCone;                 // +0x00
    Audio3DVector mOrientFront;  // +0x04
    Audio3DVector mOrientTop;    // +0x10
    Audio3DVector mPosition;     // +0x1C
    Audio3DVector mVelocity;     // +0x28
    float mInnerRadius;          // +0x34
    float mInnerRadiusAngle;     // +0x38
    std::uint32_t mChannelCount; // +0x3C
    float mChannelRadius;        // +0x40
    float* mChannelAzimuths;     // +0x44
    void* mVolumeCurve;          // +0x48
    void* mLfeCurve;             // +0x4C
    void* mLpfDirectCurve;       // +0x50
    void* mLpfReverbCurve;       // +0x54
    void* mReverbCurve;          // +0x58
    float mCurveDistanceScaler;  // +0x5C
    float mDopplerScaler;        // +0x60
  };

  struct AudioEngineRef
  {
    AudioEngine* mEngine; // +0x00
    void* mControl;       // +0x04 (`boost::detail::sp_counted_base*`)
  };

  struct AudioEngineRefVector
  {
    void* mAllocatorCookie;   // +0x00
    AudioEngineRef* mStart;   // +0x04
    AudioEngineRef* mFinish;  // +0x08
    AudioEngineRef* mCapacity; // +0x0C
  };

  struct SoundConfiguration
  {
    gpg::time::Timer mTime;            // +0x00
    AudioEngineRefVector mEngines;     // +0x08
    gpg::MemBuffer<char> mGlobalSettingsBuffer; // +0x18
    std::uint8_t mNoSound;             // +0x28
    std::uint8_t mReserved29[0x03];    // +0x29
    std::uint32_t mSpeakerConfiguration; // +0x2C
    void* mAudioRuntimeModule;         // +0x30 (`HMODULE`)
    std::uint32_t mLookAheadTimeMs;    // +0x34
    const void* mGlobalSettingsStart;  // +0x38
    std::uint32_t mGlobalSettingsLength; // +0x3C
    std::uint32_t mRuntimeFlags;       // +0x40
    std::uint8_t mReserved44[0x0C];    // +0x44
    std::uint32_t (__cdecl* mHandleSoundEvent)(int*); // +0x50
    std::uint8_t mReserved54[0x04];    // +0x54
    std::uint8_t mAudition;            // +0x58
    std::uint8_t mReserved59[0x07];    // +0x59

    /**
     * Address: 0x004D9250 (FUN_004D9250, ??1struct_SoundConfig@@QAE@@Z)
     * Mangled: ??1struct_SoundConfig@@QAE@@Z
     *
     * What it does:
     * Tears down engine implementation lanes, unloads optional runtime module,
     * and releases shared engine ownership slots.
     */
    ~SoundConfiguration();

    [[nodiscard]] std::uint32_t EngineCount() const;
    [[nodiscard]] AudioEngineImpl* EngineImplAt(std::uint32_t index) const;
  };

  struct AudioEngineImpl
  {
    /**
     * Address: 0x004D9FF0 (FUN_004D9FF0)
     *
     * Moho::AudioEngine*, Moho::SoundConfiguration*
     *
     * What it does:
     * Initializes map/vector sentinels, 3D emitter/listener state, and DSP buffers.
     */
    AudioEngineImpl(AudioEngine* engine, SoundConfiguration* configuration);

    /**
     * Address: 0x004DA2A0 (FUN_004DA2A0)
     *
     * What it does:
     * Releases banks/maps/3D buffers and the active XACT engine instance.
     */
    ~AudioEngineImpl();

    SoundConfiguration* mConfigs;       // +0x00
    AudioEngine* mEngine;               // +0x04
    AudioPointerVectorStorage mBanks;   // +0x08
    AudioPointerVectorStorage mHandles; // +0x18
    AudioMapStorage mMap1;              // +0x28
    IXACTEngine* mInstance;             // +0x34
    Audio3DListener mListener;          // +0x38
    AudioMapStorage mMap2;              // +0x6C
    float mGlobalCategoryVolume;        // +0x78
    Audio3DDspSettings mSettings;       // +0x7C
    Audio3DEmitter mEmitter;            // +0xAC
    std::uint8_t mAudioHandle[0x14];    // +0x110
  };

  static_assert(sizeof(IXACTCue) == sizeof(void*), "IXACTCue interface size must be pointer-sized");
  static_assert(sizeof(IXACTSoundBank) == sizeof(void*), "IXACTSoundBank interface size must be pointer-sized");
  static_assert(sizeof(IXACTEngine) == sizeof(void*), "IXACTEngine interface size must be pointer-sized");
  static_assert(sizeof(AudioPointerVectorStorage) == 0x10, "AudioPointerVectorStorage size must be 0x10");
  static_assert(sizeof(AudioMapStorage) == 0x0C, "AudioMapStorage size must be 0x0C");
  static_assert(sizeof(Audio3DVector) == 0x0C, "Audio3DVector size must be 0x0C");
  static_assert(sizeof(Audio3DListener) == 0x34, "Audio3DListener size must be 0x34");
  static_assert(sizeof(Audio3DDspSettings) == 0x30, "Audio3DDspSettings size must be 0x30");
  static_assert(sizeof(Audio3DEmitter) == 0x64, "Audio3DEmitter size must be 0x64");
  static_assert(sizeof(AudioEngineRef) == 0x08, "AudioEngineRef size must be 0x08");
  static_assert(sizeof(AudioEngineRefVector) == 0x10, "AudioEngineRefVector size must be 0x10");
  static_assert(offsetof(SoundConfiguration, mTime) == 0x00, "SoundConfiguration::mTime offset must be 0x00");
  static_assert(offsetof(SoundConfiguration, mEngines) == 0x08, "SoundConfiguration::mEngines offset must be 0x08");
  static_assert(
    offsetof(SoundConfiguration, mGlobalSettingsBuffer) == 0x18,
    "SoundConfiguration::mGlobalSettingsBuffer offset must be 0x18"
  );
  static_assert(offsetof(SoundConfiguration, mNoSound) == 0x28, "SoundConfiguration::mNoSound offset must be 0x28");
  static_assert(
    offsetof(SoundConfiguration, mSpeakerConfiguration) == 0x2C,
    "SoundConfiguration::mSpeakerConfiguration offset must be 0x2C"
  );
  static_assert(
    offsetof(SoundConfiguration, mAudioRuntimeModule) == 0x30,
    "SoundConfiguration::mAudioRuntimeModule offset must be 0x30"
  );
  static_assert(
    offsetof(SoundConfiguration, mLookAheadTimeMs) == 0x34,
    "SoundConfiguration::mLookAheadTimeMs offset must be 0x34"
  );
  static_assert(
    offsetof(SoundConfiguration, mGlobalSettingsStart) == 0x38,
    "SoundConfiguration::mGlobalSettingsStart offset must be 0x38"
  );
  static_assert(
    offsetof(SoundConfiguration, mGlobalSettingsLength) == 0x3C,
    "SoundConfiguration::mGlobalSettingsLength offset must be 0x3C"
  );
  static_assert(
    offsetof(SoundConfiguration, mHandleSoundEvent) == 0x50,
    "SoundConfiguration::mHandleSoundEvent offset must be 0x50"
  );
  static_assert(offsetof(SoundConfiguration, mAudition) == 0x58, "SoundConfiguration::mAudition offset must be 0x58");
  static_assert(sizeof(SoundConfiguration) == 0x60, "SoundConfiguration size must be 0x60");
  static_assert(offsetof(AudioEngineImpl, mBanks) == 0x08, "AudioEngineImpl::mBanks offset must be 0x08");
  static_assert(offsetof(AudioEngineImpl, mInstance) == 0x34, "AudioEngineImpl::mInstance offset must be 0x34");
  static_assert(offsetof(AudioEngineImpl, mListener) == 0x38, "AudioEngineImpl::mListener offset must be 0x38");
  static_assert(offsetof(AudioEngineImpl, mMap2) == 0x6C, "AudioEngineImpl::mMap2 offset must be 0x6C");
  static_assert(
    offsetof(AudioEngineImpl, mGlobalCategoryVolume) == 0x78,
    "AudioEngineImpl::mGlobalCategoryVolume offset must be 0x78"
  );
  static_assert(offsetof(AudioEngineImpl, mSettings) == 0x7C, "AudioEngineImpl::mSettings offset must be 0x7C");
  static_assert(offsetof(AudioEngineImpl, mEmitter) == 0xAC, "AudioEngineImpl::mEmitter offset must be 0xAC");
  static_assert(offsetof(AudioEngineImpl, mAudioHandle) == 0x110, "AudioEngineImpl::mAudioHandle offset must be 0x110");
  static_assert(sizeof(AudioEngineImpl) == 0x124, "AudioEngineImpl size must be 0x124");

  /**
   * Recovered AudioEngine ABI surface used by CUserSoundManager and sound-bank paths.
   */
  class AudioEngine
  {
  public:
    AudioEngineImpl* mImpl; // +0x00

    /**
     * Address: 0x004D9410 (FUN_004D9410, ??0AudioEngine@Moho@@AAE@VStrArg@gpg@@@Z)
     *
     * gpg::StrArg voicePath
     *
     * What it does:
     * Allocates/binds `AudioEngineImpl`, initializes XACT runtime state, loads
     * sound banks from the supplied voice path, and applies startup listener /
     * category settings.
     */
    explicit AudioEngine(gpg::StrArg voicePath);

    /**
     * Address: 0x004D9340 (FUN_004D9340, ?Create@AudioEngine@Moho@@SA?AV?$shared_ptr@VAudioEngine@Moho@@@boost@@VStrArg@gpg@@@Z)
     *
     * gpg::StrArg voicePath
     *
     * What it does:
     * Ensures global sound-configuration ownership is available, creates an
     * `AudioEngine` instance, and registers it into the global engine lane.
     */
    [[nodiscard]] static boost::shared_ptr<AudioEngine> Create(gpg::StrArg voicePath);

    /**
     * Address: 0x004D9760 (FUN_004D9760)
     *
     * What it does:
     * Releases the active implementation object when present.
     */
    ~AudioEngine();

    /**
     * Address: 0x004D93F0 (FUN_004D93F0)
     *
     * What it does:
     * Detaches and destroys the current implementation object.
     */
    void Shutdown();

    /**
     * Address: 0x004D9B30 (FUN_004D9B30)
     *
     * std::uint16_t bankId, IXACTCue**, AudioEngine*, std::uint16_t cueId, std::int32_t preloadOnly
     *
     * What it does:
     * Dispatches cue playback through the current engine/bank selection.
     */
    static int
    Play(std::uint16_t bankId, IXACTCue** outCue, AudioEngine* engine, std::uint16_t cueId, std::int32_t preloadOnly);

    /**
     * Address: 0x004D9BD0 (FUN_004D9BD0)
     *
     * gpg::StrArg bankName, std::uint16_t* outBankId
     *
     * What it does:
     * Finds one loaded sound-bank index by case-insensitive bank name.
     */
    bool GetBankIndex(gpg::StrArg bankName, std::uint16_t* outBankId);

    /**
     * Address: 0x004D9C40 (FUN_004D9C40)
     *
     * gpg::StrArg cueName, std::uint16_t bankId, std::uint16_t* outCueId
     *
     * What it does:
     * Resolves one cue index from one loaded sound bank.
     */
    bool GetCueIndex(gpg::StrArg cueName, std::uint16_t bankId, std::uint16_t* outCueId);

    /**
     * Address: 0x004D9C90 (FUN_004D9C90, ?SetPaused@AudioEngine@Moho@@QAEXVStrArg@gpg@@_N@Z)
     *
     * gpg::StrArg category, bool paused
     *
     * What it does:
     * Pauses or unpauses one named sound category and updates the paused
     * category tracking map on success.
     */
    void SetPaused(gpg::StrArg category, bool paused);

    /**
     * Address: 0x004D9DB0 (FUN_004D9DB0)
     *
     * gpg::StrArg, float
     *
     * What it does:
     * Sets volume scalar for the named sound category.
     */
    void SetVolume(gpg::StrArg category, float value);

    /**
     * Address: 0x004D9E50 (FUN_004D9E50)
     *
     * gpg::StrArg
     *
     * What it does:
     * Returns effective volume scalar for a category.
     */
    float GetVolume(gpg::StrArg category);

    /**
     * Address: 0x004D9890 (FUN_004D9890)
     *
     * Moho::VTransform const&
     *
     * What it does:
     * Updates listener transform for 3D cue calculations.
     */
    void SetListenerTransform(const VTransform& transform);

    /**
     * Address: 0x004D9780 (FUN_004D9780)
     *
     * What it does:
     * Reconstructs the listener transform from stored 3D listener axes.
     */
    [[nodiscard]] VTransform GetListenerTransform();

    /**
     * Address: 0x004D9A60 (FUN_004D9A60)
     * Address: 0x0128E866 (FUN_0128E866, patch_AudioEngine_Calculate3D)
     *
     * Wm3::Vector3<float> const *, AudioEngine *, IXACTCue *
     *
     * What it does:
     * Applies 3D listener/emitter transform to an active cue.
     */
    static void Calculate3D(const Wm3::Vec3f* worldPos, AudioEngine* engine, IXACTCue* cue);
  };

  extern SoundConfiguration* sSoundConfiguration;

  /**
   * Address: 0x004D9140 (FUN_004D9140, ?SND_FindEngine@Moho@@...)
   *
   * gpg::StrArg
   *
   * What it does:
   * Finds one loaded `AudioEngine` that owns a bank matching the supplied
   * bank name.
   */
  boost::shared_ptr<AudioEngine> SND_FindEngine(gpg::StrArg bankName);

  /**
   * Address: 0x004D9040 (FUN_004D9040, ?SND_GetGlobalVarIndex@Moho@@...)
   *
   * gpg::StrArg variableName, std::uint16_t* outVarIndex
   *
   * What it does:
   * Resolves one global XACT variable index from the active primary engine.
   */
  bool SND_GetGlobalVarIndex(gpg::StrArg variableName, std::uint16_t* outVarIndex);

  /**
   * Address: 0x004D9090 (FUN_004D9090, ?SND_GetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex
   *
   * What it does:
   * Reads one global XACT variable value from the active primary engine.
   */
  float SND_GetGlobalFloat(std::uint16_t varIndex);

  /**
   * Address: 0x004D90E0 (FUN_004D90E0, ?SND_SetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex, float value
   *
   * What it does:
   * Writes one global XACT variable value on the active primary engine.
   */
  void SND_SetGlobalFloat(std::uint16_t varIndex, float value);

  /**
   * Address: 0x004E0150 (FUN_004E0150, ?SND_GetVariableName@Moho@@...)
   *
   * int variableId
   *
   * What it does:
   * Returns the registered name for one global sound variable id.
   */
  msvc8::string SND_GetVariableName(int variableId);

  /**
   * Address: 0x004D8810 (FUN_004D8810, func_HandleSoundEvent)
   *
   * What it does:
   * Handles XACT notification events and emits diagnostic logs for variable
   * changes, GUI connection state, and wavebank preparation failures.
   */
  void __stdcall func_HandleSoundEvent(const std::uint8_t* eventData);

  /**
   * Address: 0x004D8EE0 (FUN_004D8EE0, ?SND_Shutdown@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys the process-global sound configuration singleton and clears the
   * global pointer.
   */
  void SND_Shutdown();

  /**
   * Address: 0x004D8F10 (FUN_004D8F10, ?SND_Enabled@Moho@@YA_NXZ)
   *
   * What it does:
   * Returns true when sound configuration has at least one loaded engine and
   * no global no-sound override is active.
   */
  bool SND_Enabled();

  /**
   * Address: 0x004D8F40 (FUN_004D8F40, ?SND_Frame@Moho@@YAXXZ)
   *
   * What it does:
   * Advances XACT engine work queues for each configured audio engine and
   * resets the global sound-configuration frame timer.
   */
  void SND_Frame();

  /**
   * Address: 0x004D8FC0 (FUN_004D8FC0, ?SND_Mute@Moho@@YAX_N@Z)
   *
   * What it does:
   * Stores/restores per-engine "Global" category volume while applying
   * process-wide mute transitions.
   */
  void SND_Mute(bool doMute);

  static_assert(sizeof(AudioEngine) == sizeof(void*), "AudioEngine size must be pointer-sized");
} // namespace moho
