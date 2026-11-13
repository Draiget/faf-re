// Engine addition (issue #258): the XACT engine the Linux client's audio code talks to
// (moho::IXACTEngine, IXACTSoundBank, IXACTCue, IXACTWaveBank in moho/audio/AudioEngine.h), on
// FAudio's FACT, which reimplements XACT call for call (Wine's XACT engines are built the same
// way).
//
// Four things differ from passing calls straight through:
//  - XACT hands the engine its own interface pointers, in notifications too. Each FACT object the
//    engine sees is wrapped once, and notifications get the wrappers in place of FACT's objects
//    (and descriptors the engine registers get FACT's objects back).
//  - The engine opens streaming wave banks itself and passes a Win32 file handle, which on Linux
//    is the POSIX <Windows.h>'s. FACT reads through file callbacks; these read that handle at the
//    requested offset with SetFilePointerEx and ReadFile, one read at a time.
//  - The renderer ID is a wchar_t string, 32-bit on Linux; FACT wants UTF-16.
//  - A sound bank play its instance limit refuses fails and hands back no cue, as XACT's does;
//    FACT reports success with a stopped cue. And a stopped cue reports stopped alone, where
//    FACT can leave its prepared bit set too.

#include "platform/posix/XactOverFact.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <FACT.h>

#include <Windows.h>

#include "moho/audio/AudioEngine.h"

namespace
{
  constexpr std::int32_t kNotImplemented = static_cast<std::int32_t>(0x80004001u);  // E_NOTIMPL
  constexpr std::int32_t kNoInterface = static_cast<std::int32_t>(0x80004002u);     // E_NOINTERFACE
  constexpr std::int32_t kInvalidArgument = static_cast<std::int32_t>(0x80070057u); // E_INVALIDARG
  constexpr std::int32_t kInstanceLimitFailToPlay =
    static_cast<std::int32_t>(FACTENGINE_E_INSTANCELIMITFAILTOPLAY); // XACTENGINE_E_INSTANCELIMITFAILTOPLAY

  class CueOverFact;
  class SoundBankOverFact;
  class WaveBankOverFact;

  // FACT object -> its wrapper, for notifications. FACT calls the notification callback from its
  // own threads too, so the maps are locked.
  struct Wrappers
  {
    std::mutex mutex;
    std::unordered_map<FACTCue*, CueOverFact*> cues;
    std::unordered_map<FACTSoundBank*, SoundBankOverFact*> soundBanks;
    std::unordered_map<FACTWaveBank*, WaveBankOverFact*> waveBanks;
  };

  Wrappers& AllWrappers()
  {
    static Wrappers wrappers;
    return wrappers;
  }

  template <typename Map, typename Key>
  typename Map::mapped_type Find(
    Map& map,
    Key* const key
  )
  {
    if (key == nullptr) {
      return nullptr;
    }
    const std::lock_guard<std::mutex> lock(AllWrappers().mutex);
    const auto found = map.find(key);
    return found != map.end() ? found->second : nullptr;
  }

  template <typename Map, typename Key, typename Value>
  void Remember(
    Map& map,
    Key* const key,
    Value* const value
  )
  {
    const std::lock_guard<std::mutex> lock(AllWrappers().mutex);
    map[key] = value;
  }

  template <typename Map, typename Key>
  void Forget(
    Map& map,
    Key* const key
  )
  {
    const std::lock_guard<std::mutex> lock(AllWrappers().mutex);
    map.erase(key);
  }

  // --- Cues ------------------------------------------------------------------------------------

  class CueOverFact final : public moho::IXACTCue
  {
  public:
    explicit CueOverFact(
      FACTCue* const cue
    )
      : mCue(cue)
    {
      Remember(AllWrappers().cues, mCue, this);
    }

    std::int32_t __stdcall Play() override
    {
      return static_cast<std::int32_t>(FACTCue_Play(mCue));
    }

    void __stdcall Stop(
      const std::int32_t stopFlags
    ) override
    {
      (void)FACTCue_Stop(mCue, static_cast<std::uint32_t>(stopFlags));
    }

    // A stopped cue reports XACT_CUESTATE_STOPPED alone. FACT keeps FACT_STATE_PREPARED set on a
    // cue it stops before it played (a play the instance limit refused, a Stop on a preloaded cue),
    // and the engine reaps cues that compare equal to stopped (0x20): CUserSoundManager's pending
    // destroys and entity loops. Stopped is final, so nothing else of the state matters then.
    std::int32_t __stdcall GetState(
      std::int32_t* const outState
    ) override
    {
      std::uint32_t state = 0;
      const std::uint32_t result = FACTCue_GetState(mCue, &state);
      if ((state & FACT_STATE_STOPPED) != 0u) {
        state = FACT_STATE_STOPPED;
      }
      if (outState != nullptr) {
        *outState = static_cast<std::int32_t>(state);
      }
      return static_cast<std::int32_t>(result);
    }

    std::int32_t __stdcall Destroy() override
    {
      // FACT may report the destruction from inside the call; the wrapper stays findable until then.
      const std::uint32_t result = FACTCue_Destroy(mCue);
      Forget(AllWrappers().cues, mCue);
      delete this;
      return static_cast<std::int32_t>(result);
    }

    void __stdcall Reserved10() override {}
    void __stdcall Reserved14() override {}
    void __stdcall Reserved18() override {}
    void __stdcall Reserved1C() override {}

    std::int32_t __stdcall SetMatrixCoefficients(
      const std::uint32_t srcChannelCount,
      const std::uint32_t dstChannelCount,
      const float* const matrixCoefficients
    ) override
    {
      return static_cast<std::int32_t>(
        FACTCue_SetMatrixCoefficients(mCue, srcChannelCount, dstChannelCount, const_cast<float*>(matrixCoefficients))
      );
    }

    std::uint16_t __stdcall GetVariableIndex(
      const char* const variableName
    ) override
    {
      return FACTCue_GetVariableIndex(mCue, variableName);
    }

    std::int32_t __stdcall SetVariable(
      const std::uint16_t variableIndex,
      const float value
    ) override
    {
      return static_cast<std::int32_t>(FACTCue_SetVariable(mCue, variableIndex, value));
    }

    FACTCue* const mCue;
  };

  // A play that went through clears FACT's prepared state; one refused by an instance limit is
  // stopped while still prepared (FACTCue_Play returns before clearing it). A cue that played and
  // already ended is stopped without it, so it doesn't count as refused.
  bool WasRefused(
    FACTCue* const cue
  )
  {
    std::uint32_t state = 0;
    if (FACTCue_GetState(cue, &state) != 0u) {
      return false;
    }
    return (state & FACT_STATE_STOPPED) != 0u && (state & FACT_STATE_PREPARED) != 0u;
  }

  // A cue the engine asked for gets a wrapper; a fire-and-forget play (no out pointer) doesn't.
  std::int32_t WrapCue(
    const std::uint32_t result,
    FACTCue* const cue,
    moho::IXACTCue** const outCue
  )
  {
    if (outCue != nullptr) {
      *outCue = (result == 0u && cue != nullptr) ? new CueOverFact(cue) : nullptr;
    }
    return static_cast<std::int32_t>(result);
  }

  // --- Banks -----------------------------------------------------------------------------------

  class SoundBankOverFact final : public moho::IXACTSoundBank
  {
  public:
    explicit SoundBankOverFact(
      FACTSoundBank* const bank
    )
      : mBank(bank)
    {
      Remember(AllWrappers().soundBanks, mBank, this);
    }

    std::uint16_t __stdcall GetCueIndex(
      const char* const cueName
    ) override
    {
      return FACTSoundBank_GetCueIndex(mBank, cueName);
    }

    std::int32_t __stdcall Reserved04() override
    {
      return kNotImplemented;
    }
    std::int32_t __stdcall Reserved08() override
    {
      return kNotImplemented;
    }

    std::int32_t __stdcall Prepare(
      const std::uint16_t cueIndex,
      const std::uint32_t flags,
      const std::uint32_t timeOffset,
      moho::IXACTCue** const outCue
    ) override
    {
      FACTCue* cue = nullptr;
      const std::uint32_t result =
        FACTSoundBank_Prepare(mBank, cueIndex, flags, static_cast<std::int32_t>(timeOffset), &cue);
      return WrapCue(result, cue, outCue);
    }

    // XACT fails a play its instance limit refuses (XACTENGINE_E_INSTANCELIMITFAILTOPLAY) and hands
    // back no cue; the engine counts on that (AudioEngine::Play, 0x004D9B30, and the one-shot
    // requests, which keep every cue they get until it reports stopped). FACTSoundBank_Play returns
    // success either way, with the refused cue left prepared and stopped, a state XACT never reports.
    // Such a cue is destroyed here and the play fails, as on XACT. A play without an out pointer
    // stays FACT's to clean up: FACT destroys its own stopped cues.
    std::int32_t __stdcall Play(
      const std::uint16_t cueIndex,
      const std::uint32_t flags,
      const std::uint32_t timeOffset,
      moho::IXACTCue** const outCue
    ) override
    {
      FACTCue* cue = nullptr;
      const std::uint32_t result = FACTSoundBank_Play(
        mBank, cueIndex, flags, static_cast<std::int32_t>(timeOffset), outCue != nullptr ? &cue : nullptr
      );
      if (result == 0u && cue != nullptr && WasRefused(cue)) {
        (void)FACTCue_Destroy(cue);
        *outCue = nullptr;
        return kInstanceLimitFailToPlay;
      }
      return WrapCue(result, cue, outCue);
    }

    std::int32_t __stdcall Reserved14() override
    {
      return kNotImplemented;
    }

    void __stdcall Destroy() override
    {
      (void)FACTSoundBank_Destroy(mBank);
      Forget(AllWrappers().soundBanks, mBank);
      delete this;
    }

    FACTSoundBank* const mBank;
  };

  class WaveBankOverFact final : public moho::IXACTWaveBank
  {
  public:
    explicit WaveBankOverFact(
      FACTWaveBank* const bank
    )
      : mBank(bank)
    {
      Remember(AllWrappers().waveBanks, mBank, this);
    }

    void __stdcall Destroy() override
    {
      (void)FACTWaveBank_Destroy(mBank);
      Forget(AllWrappers().waveBanks, mBank);
      delete this;
    }

    FACTWaveBank* const mBank;
  };

  // --- Notifications ---------------------------------------------------------------------------

  // The engine's callback. XACT has one engine per process here, as on Windows.
  std::atomic<XACT_NOTIFICATION_CALLBACK> gEngineCallback{nullptr};

  template <typename Wrapper, typename Fact>
  Fact* AsFact(
    Wrapper* const wrapper
  )
  {
    return reinterpret_cast<Fact*>(wrapper);
  }

  void NotifyEngine(
    const FACTNotification* const notification
  )
  {
    const XACT_NOTIFICATION_CALLBACK callback = gEngineCallback.load();
    if (callback == nullptr || notification == nullptr) {
      return;
    }
    // The engine reads XACT's interface pointers out of a notification: the wrappers, here.
    FACTNotification copy = *notification;
    Wrappers& wrappers = AllWrappers();
    const auto cue = [&](FACTCue* const value) {
      return AsFact<CueOverFact, FACTCue>(Find(wrappers.cues, value));
    };
    const auto soundBank = [&](FACTSoundBank* const value) {
      return AsFact<SoundBankOverFact, FACTSoundBank>(Find(wrappers.soundBanks, value));
    };
    const auto waveBank = [&](FACTWaveBank* const value) {
      return AsFact<WaveBankOverFact, FACTWaveBank>(Find(wrappers.waveBanks, value));
    };
    switch (copy.type) {
    case FACTNOTIFICATIONTYPE_CUEPREPARED:
    case FACTNOTIFICATIONTYPE_CUEPLAY:
    case FACTNOTIFICATIONTYPE_CUESTOP:
    case FACTNOTIFICATIONTYPE_CUEDESTROYED:
      copy.cue.pSoundBank = soundBank(notification->cue.pSoundBank);
      copy.cue.pCue = cue(notification->cue.pCue);
      break;
    case FACTNOTIFICATIONTYPE_MARKER:
      copy.marker.pSoundBank = soundBank(notification->marker.pSoundBank);
      copy.marker.pCue = cue(notification->marker.pCue);
      break;
    case FACTNOTIFICATIONTYPE_SOUNDBANKDESTROYED:
      copy.soundBank.pSoundBank = soundBank(notification->soundBank.pSoundBank);
      break;
    case FACTNOTIFICATIONTYPE_WAVEBANKDESTROYED:
    case FACTNOTIFICATIONTYPE_WAVEBANKPREPARED:
    case FACTNOTIFICATIONTYPE_WAVEBANKSTREAMING_INVALIDCONTENT:
      copy.waveBank.pWaveBank = waveBank(notification->waveBank.pWaveBank);
      break;
    case FACTNOTIFICATIONTYPE_LOCALVARIABLECHANGED:
      copy.variable.pSoundBank = soundBank(notification->variable.pSoundBank);
      copy.variable.pCue = cue(notification->variable.pCue);
      break;
    case FACTNOTIFICATIONTYPE_WAVEPREPARED:
    case FACTNOTIFICATIONTYPE_WAVEPLAY:
    case FACTNOTIFICATIONTYPE_WAVESTOP:
    case FACTNOTIFICATIONTYPE_WAVELOOPED:
    case FACTNOTIFICATIONTYPE_WAVEDESTROYED:
      copy.wave.pWaveBank = waveBank(notification->wave.pWaveBank);
      copy.wave.pSoundBank = soundBank(notification->wave.pSoundBank);
      copy.wave.pCue = cue(notification->wave.pCue);
      break;
    default:
      break;
    }
    callback(&copy);
  }

  // A descriptor the engine registers names wrappers; FACT wants its own objects.
  FACTNotificationDescription ToFact(
    const moho::AudioNotificationDesc& description
  )
  {
    FACTNotificationDescription fact = description;
    fact.pSoundBank =
      description.pSoundBank != nullptr ? reinterpret_cast<SoundBankOverFact*>(description.pSoundBank)->mBank : nullptr;
    fact.pWaveBank =
      description.pWaveBank != nullptr ? reinterpret_cast<WaveBankOverFact*>(description.pWaveBank)->mBank : nullptr;
    fact.pCue = description.pCue != nullptr ? reinterpret_cast<CueOverFact*>(description.pCue)->mCue : nullptr;
    return fact;
  }

  // --- Streaming reads -------------------------------------------------------------------------

  std::mutex gFileMutex;

  std::int32_t FACTCALL ReadFileAt(
    void* const file,
    void* const buffer,
    const std::uint32_t bytesToRead,
    std::uint32_t* const bytesRead,
    FACTOverlapped* const overlapped
  )
  {
    const std::lock_guard<std::mutex> lock(gFileMutex);
    LARGE_INTEGER at{};
    if (overlapped != nullptr) {
      at.QuadPart =
        static_cast<std::int64_t>(overlapped->Offset) | (static_cast<std::int64_t>(overlapped->OffsetHigh) << 32);
    }
    DWORD got = 0;
    const bool ok =
      ::SetFilePointerEx(file, at, nullptr, FILE_BEGIN) && ::ReadFile(file, buffer, bytesToRead, &got, nullptr);
    if (overlapped != nullptr) {
      overlapped->Internal = nullptr;
      overlapped->InternalHigh = reinterpret_cast<void*>(static_cast<std::uintptr_t>(got));
    }
    if (bytesRead != nullptr) {
      *bytesRead = got;
    }
    return ok ? 1 : 0;
  }

  // Every read above has finished when it returns.
  std::int32_t FACTCALL ReadResult(
    void* const file,
    FACTOverlapped* const overlapped,
    std::uint32_t* const bytesTransferred,
    const std::int32_t wait
  )
  {
    (void)file;
    (void)wait;
    if (bytesTransferred != nullptr) {
      *bytesTransferred = overlapped != nullptr
        ? static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(overlapped->InternalHigh))
        : 0u;
    }
    return 1;
  }

  // --- The engine ------------------------------------------------------------------------------

  class EngineOverFact final : public moho::IXACTEngine
  {
  public:
    explicit EngineOverFact(
      FACTAudioEngine* const engine
    )
      : mEngine(engine)
    {}

    std::int32_t __stdcall QueryInterface(
      const void* const riid,
      void** const outObject
    ) override
    {
      (void)riid;
      if (outObject != nullptr) {
        *outObject = nullptr;
      }
      return kNoInterface;
    }

    std::uint32_t __stdcall AddRef() override
    {
      return ++mReferences;
    }

    std::uint32_t __stdcall Release() override
    {
      const std::uint32_t left = --mReferences;
      if (left == 0u) {
        (void)FACTAudioEngine_Release(mEngine);
        gEngineCallback.store(nullptr);
        delete this;
      }
      return left;
    }

    std::int32_t __stdcall GetRendererCount(
      std::uint16_t* const outRendererCount
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_GetRendererCount(mEngine, outRendererCount));
    }

    // XACT_RENDERER_DETAILS and FACTRendererDetails are the same: two UTF-16 strings and a BOOL.
    std::int32_t __stdcall GetRendererDetails(
      const std::uint16_t rendererIndex,
      void* const outRendererDetails
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_GetRendererDetails(
        mEngine, rendererIndex, static_cast<FACTRendererDetails*>(outRendererDetails)
      ));
    }

    std::int32_t __stdcall GetFinalMixFormat(
      void* const outWaveFormatExtensible
    ) override
    {
      return static_cast<std::int32_t>(
        FACTAudioEngine_GetFinalMixFormat(mEngine, static_cast<FAudioWaveFormatExtensible*>(outWaveFormatExtensible))
      );
    }

    std::int32_t __stdcall Initialize(
      const moho::AudioRuntimeParams* const params
    ) override
    {
      if (params == nullptr) {
        return kInvalidArgument;
      }
      XACT_RUNTIME_PARAMETERS fact{};
      fact.lookAheadTime = params->lookAheadTime;
      fact.pGlobalSettingsBuffer = params->pGlobalSettingsBuffer;
      fact.globalSettingsBufferSize = params->globalSettingsBufferSize;
      fact.globalSettingsFlags = params->globalSettingsFlags;
      fact.globalSettingsAllocAttributes = params->globalSettingsAllocAttributes;
      // The engine's file handles are the POSIX <Windows.h>'s (see the file comment).
      fact.fileIOCallbacks.readFileCallback = &ReadFileAt;
      fact.fileIOCallbacks.getOverlappedResultCallback = &ReadResult;
      gEngineCallback.store(params->fnNotificationCallback);
      fact.fnNotificationCallback = params->fnNotificationCallback != nullptr ? &NotifyEngine : nullptr;
      if (params->pRendererID != nullptr) {
        mRendererId.clear();
        for (const wchar_t* at = params->pRendererID; *at != L'\0'; ++at) {
          mRendererId.push_back(static_cast<std::int16_t>(*at)); // device IDs are ASCII
        }
        mRendererId.push_back(0);
        fact.pRendererID = mRendererId.data();
      }
      return static_cast<std::int32_t>(FACTAudioEngine_Initialize(mEngine, &fact));
    }

    void __stdcall ShutDown() override
    {
      (void)FACTAudioEngine_ShutDown(mEngine);
    }

    std::int32_t __stdcall DoWork() override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_DoWork(mEngine));
    }

    std::int32_t __stdcall CreateSoundBank(
      const void* const data,
      const std::int32_t sizeBytes,
      const std::uint32_t flags,
      const std::uint32_t allocAttributes,
      moho::IXACTSoundBank** const outSoundBank
    ) override
    {
      FACTSoundBank* bank = nullptr;
      const std::uint32_t result = FACTAudioEngine_CreateSoundBank(
        mEngine, data, static_cast<std::uint32_t>(sizeBytes), flags, allocAttributes, &bank
      );
      if (outSoundBank != nullptr) {
        *outSoundBank = (result == 0u && bank != nullptr) ? new SoundBankOverFact(bank) : nullptr;
      }
      return static_cast<std::int32_t>(result);
    }

    std::int32_t __stdcall CreateInMemoryWaveBank(
      const void* const data,
      const std::int32_t sizeBytes,
      const std::uint32_t flags,
      const std::uint32_t allocAttributes,
      moho::IXACTWaveBank** const outWaveBank
    ) override
    {
      FACTWaveBank* bank = nullptr;
      const std::uint32_t result = FACTAudioEngine_CreateInMemoryWaveBank(
        mEngine, data, static_cast<std::uint32_t>(sizeBytes), flags, allocAttributes, &bank
      );
      if (outWaveBank != nullptr) {
        *outWaveBank = (result == 0u && bank != nullptr) ? new WaveBankOverFact(bank) : nullptr;
      }
      return static_cast<std::int32_t>(result);
    }

    // The engine's parameters are XACT_STREAMING_PARAMETERS, FACT's own structure.
    std::int32_t __stdcall CreateStreamingWaveBank(
      const void* const streamingParams,
      moho::IXACTWaveBank** const outWaveBank
    ) override
    {
      FACTWaveBank* bank = nullptr;
      const std::uint32_t result = FACTAudioEngine_CreateStreamingWaveBank(
        mEngine, static_cast<const FACTStreamingParameters*>(streamingParams), &bank
      );
      if (outWaveBank != nullptr) {
        *outWaveBank = (result == 0u && bank != nullptr) ? new WaveBankOverFact(bank) : nullptr;
      }
      return static_cast<std::int32_t>(result);
    }

    // The engine plays waves only through cues.
    std::int32_t __stdcall PrepareWave(
      std::uint32_t,
      const char*,
      std::uint16_t,
      std::uint32_t,
      std::uint32_t,
      std::uint8_t,
      void**
    ) override
    {
      return kNotImplemented;
    }
    std::int32_t __stdcall PrepareInMemoryWave(
      std::uint32_t,
      const void*,
      std::uint32_t*,
      std::uint8_t*,
      std::uint32_t,
      std::uint8_t,
      void**
    ) override
    {
      return kNotImplemented;
    }
    std::int32_t __stdcall PrepareStreamingWave(
      std::uint32_t,
      const void*,
      const void*,
      std::uint32_t,
      std::uint32_t*,
      std::uint32_t,
      std::uint8_t,
      void**
    ) override
    {
      return kNotImplemented;
    }

    std::int32_t __stdcall RegisterNotification(
      const moho::AudioNotificationDesc* const description
    ) override
    {
      if (description == nullptr) {
        return kInvalidArgument;
      }
      const FACTNotificationDescription fact = ToFact(*description);
      return static_cast<std::int32_t>(FACTAudioEngine_RegisterNotification(mEngine, &fact));
    }

    std::int32_t __stdcall UnRegisterNotification(
      const moho::AudioNotificationDesc* const description
    ) override
    {
      if (description == nullptr) {
        return kInvalidArgument;
      }
      const FACTNotificationDescription fact = ToFact(*description);
      return static_cast<std::int32_t>(FACTAudioEngine_UnRegisterNotification(mEngine, &fact));
    }

    std::uint16_t __stdcall GetCategory(
      const char* const categoryName
    ) override
    {
      return FACTAudioEngine_GetCategory(mEngine, categoryName);
    }

    void __stdcall Stop(
      const std::uint16_t category,
      const std::int32_t flags
    ) override
    {
      (void)FACTAudioEngine_Stop(mEngine, category, static_cast<std::uint32_t>(flags));
    }

    std::int32_t __stdcall SetVolume(
      const std::uint16_t category,
      const float volume
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_SetVolume(mEngine, category, volume));
    }

    std::int32_t __stdcall Pause(
      const std::uint16_t category,
      const std::int32_t pause
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_Pause(mEngine, category, pause));
    }

    std::uint16_t __stdcall GetGlobalVariableIndex(
      const char* const variableName
    ) override
    {
      return FACTAudioEngine_GetGlobalVariableIndex(mEngine, variableName);
    }

    std::int32_t __stdcall SetGlobalVariable(
      const std::uint16_t variableIndex,
      const float value
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_SetGlobalVariable(mEngine, variableIndex, value));
    }

    std::int32_t __stdcall GetGlobalVariable(
      const std::uint16_t variableIndex,
      float* const outValue
    ) override
    {
      return static_cast<std::int32_t>(FACTAudioEngine_GetGlobalVariable(mEngine, variableIndex, outValue));
    }

  private:
    FACTAudioEngine* const mEngine;
    std::atomic<std::uint32_t> mReferences{1u};
    std::vector<std::int16_t> mRendererId;
  };
} // namespace

int platform::posix::CreateXactEngineOverFact(
  void** const outEngine
)
{
  if (outEngine == nullptr) {
    return kInvalidArgument;
  }
  *outEngine = nullptr;
  FACTAudioEngine* engine = nullptr;
  const std::uint32_t result = FACTCreateEngine(0u, &engine);
  if (result != 0u || engine == nullptr) {
    return static_cast<int>(result != 0u ? result : 0x80004005u); // E_FAIL
  }
  *outEngine = static_cast<moho::IXACTEngine*>(new EngineOverFact(engine));
  return 0;
}
