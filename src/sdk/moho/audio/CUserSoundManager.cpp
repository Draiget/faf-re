#include "moho/audio/CUserSoundManager.h"

#include <Windows.h>

#include <cmath>
#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/UserArmy.h"

namespace moho
{
  extern bool snd_SpewSound;
  extern bool snd_CheckDistance;
  extern bool snd_CheckLOS;
  extern int snd_index;

  float SND_GetGlobalFloat(std::uint16_t varIndex);
  void SND_SetGlobalFloat(std::uint16_t varIndex, float value);
  void SND_DestroyEntityLoop(SoundHandleRecord* record);
  const char* func_SoundErrorCodeToMsg(int errorCode);
} // namespace moho

namespace
{
  using LoopNode = moho::TDatListItem<moho::HSound, void>;
  using LoopList = moho::TDatList<moho::HSound, void>;
  using ListenerArmyHook = moho::ListenerArmyHook;

  constexpr int kXactErrCuePreparedOnly = static_cast<int>(0x8AC70008u);
  constexpr int kCueStatePlaying = 16;
  constexpr int kCueStateStopped = 32;
  constexpr float kHalfPi = 1.5707964f;
  constexpr float kRadToDeg = 57.29578f;
  constexpr moho::ELayer kLayerSeabed = static_cast<moho::ELayer>(2);
  constexpr moho::ELayer kLayerSub = static_cast<moho::ELayer>(4);
  constexpr const char* kWorldCameraName = "WorldCamera";
  constexpr const char* kAngleVariableName = "Angle";

  moho::CUserSoundManager* gUserSoundManager = nullptr;
  moho::StatItem* gEngineStatSoundLimitedLoop = nullptr;
  moho::StatItem* gEngineStatSoundStartEntityLoop = nullptr;
  moho::StatItem* gEngineStatSoundStopEntityLoop = nullptr;
  moho::StatItem* gEngineStatSoundPendingDestroy = nullptr;

  moho::HSound* LoopOwnerFromNode(LoopNode* node)
  {
    return LoopList::owner_from_member_node<moho::HSound, &moho::HSound::mSimLoopLink>(node);
  }

  bool IsSndVarReady(const moho::CSndVar& value)
  {
    if (value.mResolved != 0u) {
      return value.mState != 0xFFFFu;
    }
    return value.DoResolve();
  }

  bool ParamsHasResolvedEngine(const moho::CSndParams& params)
  {
    boost::shared_ptr<moho::AudioEngine> resolvedEngine;
    return params.GetEngine(&resolvedEngine)->get() != nullptr;
  }

  void StopAndDestroyCue(moho::IXACTCue* cue)
  {
    cue->Stop(1);
    cue->Destroy();
  }

  void WarnCuePlayFailure(
    const int xactResult, const std::uint16_t cueId, const std::uint16_t bankId, const msvc8::string& bankName
  )
  {
    if (xactResult >= 0 || xactResult == kXactErrCuePreparedOnly) {
      return;
    }

    const char* const xactMessage = moho::func_SoundErrorCodeToMsg(xactResult);
    gpg::Warnf("SND: Error playing cue %i on bank %i [%s]\nXACT: %s", cueId, bankId, bankName.c_str(), xactMessage);
  }

  void UnlinkArmyHook(ListenerArmyHook& hook)
  {
    if (hook.mOwnerAnchor == nullptr) {
      hook.mNext = nullptr;
      return;
    }

    auto** link = reinterpret_cast<ListenerArmyHook**>(hook.mOwnerAnchor);
    ListenerArmyHook* node = *link;
    while (node != &hook) {
      link =
        reinterpret_cast<ListenerArmyHook**>(reinterpret_cast<std::uint8_t*>(node) + offsetof(ListenerArmyHook, mNext));
      node = *link;
    }

    *link = hook.mNext;
    hook.mNext = nullptr;
  }

  void RelinkArmyHook(ListenerArmyHook& hook, moho::UserArmy* army)
  {
    auto* const newOwnerAnchor = army == nullptr
      ? nullptr
      : reinterpret_cast<std::uintptr_t*>(
          reinterpret_cast<std::uintptr_t>(army) + offsetof(moho::UserArmy, mVariableDataWord_01E0)
        );

    if (hook.mOwnerAnchor == newOwnerAnchor) {
      return;
    }

    UnlinkArmyHook(hook);
    hook.mOwnerAnchor = newOwnerAnchor;

    if (newOwnerAnchor != nullptr) {
      auto** const head = reinterpret_cast<ListenerArmyHook**>(newOwnerAnchor);
      hook.mNext = *head;
      *head = &hook;
    }
  }

  void EnsureSoundCounterStat(moho::StatItem*& slot, const char* const statPath)
  {
    if (slot != nullptr) {
      return;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (engineStats == nullptr) {
      return;
    }

    slot = engineStats->GetIntItem(statPath);
    if (slot != nullptr) {
      (void)slot->Release(0);
    }
  }

  void StoreSoundCounter(moho::StatItem* const slot, const std::int32_t value)
  {
    if (slot == nullptr) {
      return;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&slot->mPrimaryValueBits);
    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, static_cast<long>(value), observed) != observed);
  }

  [[nodiscard]] float ComputePitchRadians(const Wm3::Vec3f& value)
  {
    const float horizontal = std::sqrt((value.x * value.x) + (value.y * value.y));
    return std::atan2(value.z, horizontal);
  }

  [[nodiscard]] float ComputeCueAngleDegrees(const Wm3::Vec3f& worldPos, const Wm3::Vec3f& listenerPos)
  {
    const Wm3::Vec3f delta{
      worldPos.x - listenerPos.x,
      worldPos.y - listenerPos.y,
      worldPos.z - listenerPos.z,
    };
    return (kHalfPi - ComputePitchRadians(delta)) * kRadToDeg;
  }

  [[nodiscard]] int DrainFinishedPendingCues(
    msvc8::set<moho::IXACTCue*>& pendingCues, moho::AudioEngine* const voiceEngine
  )
  {
    const bool canQueryCueState =
      voiceEngine != nullptr && voiceEngine->mImpl != nullptr && voiceEngine->mImpl->mInstance != nullptr;

    int pendingCount = 0;
    for (auto cueIt = pendingCues.begin(); cueIt != pendingCues.end();) {
      moho::IXACTCue* const cue = *cueIt;
      if (!canQueryCueState || cue == nullptr) {
        ++pendingCount;
        ++cueIt;
        continue;
      }

      std::int32_t cueState = 0;
      const int stateResult = cue->GetState(&cueState);
      if (stateResult < 0) {
        gpg::Warnf("SND: %s", moho::func_SoundErrorCodeToMsg(stateResult));
      }

      if (cueState == kCueStateStopped) {
        cue->Destroy();
        cueIt = pendingCues.erase(cueIt);
        continue;
      }

      ++pendingCount;
      ++cueIt;
    }

    return pendingCount;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008AA800 (FUN_008AA800, ??0CUserSoundManager@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes user-audio runtime containers, cue vars, and the primary
   * voice engine.
   */
  CUserSoundManager::CUserSoundManager()
    : mReserved04(0u)
    , mRecentOneShotKeys()
    , mLoopHandleIdPool()
    , mReserved13C(0u)
    , mSoundHandles()
    , mPendingDestroyCues()
    , mListenerArmyHook{nullptr, nullptr}
    , mActiveLoops()
    , mAmbientEngine()
    , mTutorialEngine()
    , mVoiceEngine(AudioEngine::Create("/sounds"))
    , mCameraDistanceVar("CameraDistance")
    , mZoomPercentVar("ZoomPercent")
    , mCurrentCameraDistanceMetric(0.0f)
    , mWorldSoundsEnabled(1u)
    , mReserved29C9{0u, 0u, 0u}
    , mLanguageTag()
    , mDuckLengthVar("DuckLength")
    , mDuckVar("Duck")
    , mDuckMode(0)
    , mDuckElapsedSeconds(0.0f)
    , mActiveDuckingSounds(0)
    , mReserved2A34(0u)
  {
    mLoopHandleIdPool.mNextId = 0u;
    mSoundHandles.Resize(0x100u, SoundHandleRecord{});
    snd_SpewSound = CFG_GetArgOption("/spewsound", 0, nullptr);
  }

  /**
   * Address: 0x008AAA10 (FUN_008AAA10, ??1CUserSoundManager@Moho@@QAE@XZ)
   *
   * What it does:
   * Detaches intrusive list/hook links before member-owned container teardown.
   */
  CUserSoundManager::~CUserSoundManager()
  {
    mActiveLoops.mPrev->mNext = mActiveLoops.mNext;
    mActiveLoops.mNext->mPrev = mActiveLoops.mPrev;
    mActiveLoops.ListResetLinks();
    UnlinkArmyHook(mListenerArmyHook);
  }

  /**
   * Address: 0x008AB220 (FUN_008AB220, ?USER_GetSound@Moho@@YAPAVIUserSoundManager@1@XZ)
   *
   * What it does:
   * Returns the process-global user sound manager and lazily creates it.
   */
  IUserSoundManager* USER_GetSound()
  {
    if (gUserSoundManager == nullptr) {
      CUserSoundManager* const created = new CUserSoundManager();
      if (created != gUserSoundManager) {
        CUserSoundManager* const previous = gUserSoundManager;
        if (previous != nullptr) {
          previous->~CUserSoundManager();
          operator delete(previous);
        }
      }
      gUserSoundManager = created;
    }

    return gUserSoundManager;
  }

  /**
   * Address: 0x008AC0B0 (FUN_008AC0B0)
   *
   * gpg::fastvector<Moho::SAudioRequest> const&
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::UpdateSoundRequests(Moho::CUserSoundManager *this,
   * gpg::fastvector_SAudioRequest const *requests);
   *
   * What it does:
   * Consumes audio requests, updates camera-linked global sound vars, plays
   * one-shot/loop cues, and schedules transient cues for deferred destroy.
   */
  void CUserSoundManager::UpdateSoundRequests(const gpg::fastvector<SAudioRequest>& requests)
  {
    EnsureSoundCounterStat(gEngineStatSoundLimitedLoop, "Sound_LimitedLoop");
    EnsureSoundCounterStat(gEngineStatSoundStartEntityLoop, "Sound_StartEntityLoop");
    EnsureSoundCounterStat(gEngineStatSoundStopEntityLoop, "Sound_StopEntityLoop");
    StoreSoundCounter(gEngineStatSoundLimitedLoop, 0);
    StoreSoundCounter(gEngineStatSoundStartEntityLoop, 0);
    StoreSoundCounter(gEngineStatSoundStopEntityLoop, 0);

    if (mWorldSoundsEnabled == 0u) {
      return;
    }

    mRecentOneShotKeys.Clear();

    if (RCamManager* const camManager = CAM_GetManager(); camManager != nullptr) {
      if (CameraImpl* const camera = camManager->GetCamera(kWorldCameraName); camera != nullptr) {
        if (IsSndVarReady(mCameraDistanceVar)) {
          const float lodMetric = camera->LODMetric(camera->CameraGetOffset());
          if (lodMetric != mCurrentCameraDistanceMetric) {
            mCurrentCameraDistanceMetric = lodMetric;
            SND_SetGlobalFloat(mCameraDistanceVar.mState, lodMetric);
          }
        }

        if (IsSndVarReady(mZoomPercentVar)) {
          const float maxZoom = camera->GetMaxZoom();
          if (maxZoom > 0.0f) {
            const float zoomPercent = (camera->CameraGetTargetZoom() / maxZoom) * 100.0f;
            SND_SetGlobalFloat(mZoomPercentVar.mState, zoomPercent);
          }
        }
      }
    }

    AudioEngine* const voiceEngine = mVoiceEngine.get();
    const std::size_t requestCount = requests.Size();
    for (std::size_t requestIndex = 0; requestIndex < requestCount; ++requestIndex) {
      const SAudioRequest& request = requests.start_[requestIndex];

      switch (request.requestType) {
      case EAudioRequestType::StartLoop: {
        HSound* const sound = request.sound;
        CSndParams* params = request.params;
        if (params == nullptr && sound != nullptr) {
          params = static_cast<CSndParams*>(sound->mLoopOwnerContext);
        }

        if (sound == nullptr || params == nullptr || voiceEngine == nullptr) {
          break;
        }
        if (!ParamsHasResolvedEngine(*params)) {
          break;
        }

        IXACTCue* cue = nullptr;
        if (AudioEngine::Play(params->mBankId, &cue, voiceEngine, params->mCueId, 0) >= 0 && cue != nullptr) {
          sound->mLoopCue = cue;
          AudioEngine::Calculate3D(&request.position, voiceEngine, cue);
        }
        break;
      }

      case EAudioRequestType::StopLoop: {
        HSound* const sound = request.sound;
        IXACTCue* const cue = sound != nullptr ? sound->mLoopCue : nullptr;
        if (cue == nullptr) {
          gpg::Warnf("SND: No cue for stop loop request.");
          break;
        }

        cue->Stop(0);
        mPendingDestroyCues.insert(cue);
        break;
      }

      case EAudioRequestType::EntitySound: {
        const CSndParams* const params = request.params;
        if (params == nullptr || voiceEngine == nullptr) {
          break;
        }
        if (!ParamsHasResolvedEngine(*params)) {
          break;
        }
        if (FilterSound(params, request.layer, &request.position) != EFilterType::Pass) {
          break;
        }

        const std::uint32_t cueKey =
          static_cast<std::uint32_t>(params->mCueId) | (static_cast<std::uint32_t>(params->mBankId) << 16u);

        bool seenCueKey = false;
        const std::size_t recentKeyCount = mRecentOneShotKeys.Size();
        for (std::size_t keyIndex = 0; keyIndex < recentKeyCount; ++keyIndex) {
          if (mRecentOneShotKeys.start_[keyIndex] == cueKey) {
            seenCueKey = true;
            break;
          }
        }
        if (seenCueKey) {
          break;
        }

        mRecentOneShotKeys.PushBack(cueKey);

        if (snd_SpewSound) {
          gpg::Debugf("SND: 1shot   [Cue: %s] [Bank: %s] %i", params->mCue.c_str(), params->mBank.c_str(), snd_index);
        }

        IXACTCue* cue = nullptr;
        if (AudioEngine::Play(params->mBankId, &cue, voiceEngine, params->mCueId, 0) < 0 || cue == nullptr) {
          break;
        }

        mPendingDestroyCues.insert(cue);
        AudioEngine::Calculate3D(&request.position, voiceEngine, cue);

        const std::uint16_t angleVariable = cue->GetVariableIndex(kAngleVariableName);
        if (angleVariable != 0xFFFFu) {
          const VTransform listenerTransform = voiceEngine->GetListenerTransform();
          const float angleDegrees = ComputeCueAngleDegrees(request.position, listenerTransform.pos_);
          cue->SetVariable(angleVariable, angleDegrees);
        }
        break;
      }

      default:
        break;
      }
    }
  }

  /**
   * Address: 0x008AB770 (FUN_008AB770)
   *
   * float simDeltaSeconds, float frameSeconds
   *
   * IDA signature:
   * int __thiscall Moho::CUserSoundManager::Frame(Moho::CUserSoundManager *this, float a2, float a3);
   *
   * What it does:
   * Updates listener transform and active loop handles, runs duck interpolation,
   * and destroys transient cues that reached stopped state.
   */
  void CUserSoundManager::Frame(const float simDeltaSeconds, const float frameSeconds)
  {
    if (RCamManager* const camManager = CAM_GetManager(); camManager != nullptr) {
      if (CameraImpl* const camera = camManager->GetCamera(kWorldCameraName); camera != nullptr) {
        VTransform listenerTransform = camera->CameraGetView().tranform;
        const float targetZoom = camera->CameraGetTargetZoom();
        const Wm3::Vec3f& cameraOffset = camera->CameraGetOffset();
        listenerTransform.pos_.x = cameraOffset.x;
        listenerTransform.pos_.y = cameraOffset.y + targetZoom;
        listenerTransform.pos_.z = cameraOffset.z;
        SetListenerTransform(listenerTransform);
      }
    }

    if (mDuckMode != 0) {
      UpdateDuck(frameSeconds);
    }

    (void)simDeltaSeconds; // Used by unresolved entity-loop helper lane (0x008AA4E0).

    const AudioEngine* const voiceEngine = mVoiceEngine.get();
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      if (record.mLoopIndex == -1) {
        continue;
      }

      if (voiceEngine == nullptr || voiceEngine->mImpl == nullptr || voiceEngine->mImpl->mInstance == nullptr) {
        continue;
      }
      if (record.mCue == nullptr) {
        continue;
      }

      std::int32_t cueState = 0;
      const int firstStateResult = record.mCue->GetState(&cueState);
      if (firstStateResult < 0) {
        gpg::Warnf("SND: %s", func_SoundErrorCodeToMsg(firstStateResult));
      }

      if (cueState == kCueStateStopped) {
        SND_DestroyEntityLoop(&record);
        continue;
      }

      cueState = 0;
      record.mCue->GetState(&cueState);
      if (cueState == kCueStatePlaying) {
        record.mPlayingSeconds += frameSeconds;
      }
    }

    const int pendingDestroyCount = DrainFinishedPendingCues(mPendingDestroyCues, mVoiceEngine.get());
    EnsureSoundCounterStat(gEngineStatSoundPendingDestroy, "Sound_PendingDestroy");
    StoreSoundCounter(gEngineStatSoundPendingDestroy, pendingDestroyCount);
  }

  /**
   * Address: 0x008AAC50 (FUN_008AAC50)
   *
   * msvc8::string const&, msvc8::string const&
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::Play(Moho::CUserSoundManager *this, msvc8::string const& bankName,
   * msvc8::string const& cueName);
   *
   * What it does:
   * Builds transient cue params from bank+cue names and plays a one-shot on
   * the voice engine.
   */
  void CUserSoundManager::Play(const msvc8::string& bankName, const msvc8::string& cueName)
  {
    CSndParams params(mVoiceEngine, bankName, cueName, nullptr, nullptr);
    if (!ParamsHasResolvedEngine(params)) {
      return;
    }

    if (snd_SpewSound) {
      gpg::Debugf("SND: Play    [Cue: %s] [Bank: %s] %i", params.mCue.c_str(), params.mBank.c_str(), snd_index);
    }

    const int xactResult = AudioEngine::Play(params.mBankId, nullptr, mVoiceEngine.get(), params.mCueId, 0);
    WarnCuePlayFailure(xactResult, params.mCueId, params.mBankId, params.mBank);
  }

  /**
   * Address: 0x008AAE00 (FUN_008AAE00)
   *
   * Moho::CSndParams const&
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::Play2D(Moho::CUserSoundManager *this, Moho::CSndParams const& params);
   *
   * What it does:
   * Plays a one-shot from resolved cue parameters.
   */
  void CUserSoundManager::Play2D(const CSndParams& params)
  {
    if (!ParamsHasResolvedEngine(params)) {
      return;
    }

    if (snd_SpewSound) {
      gpg::Debugf("SND: Play2D  [Cue: %s] [Bank: %s] %i", params.mCue.c_str(), params.mBank.c_str(), snd_index);
    }

    const int xactResult = AudioEngine::Play(params.mBankId, nullptr, mVoiceEngine.get(), params.mCueId, 0);
    WarnCuePlayFailure(xactResult, params.mCueId, params.mBankId, params.mBank);
  }

  /**
   * Address: 0x008AAF30 (FUN_008AAF30)
   *
   * Moho::UserArmy*
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::SetListenerArmy(Moho::CUserSoundManager *this, Moho::UserArmy *army);
   *
   * What it does:
   * Rebinds listener-army intrusive hook to the new army visibility anchor.
   */
  void CUserSoundManager::SetListenerArmy(UserArmy* listenerArmy)
  {
    RelinkArmyHook(mListenerArmyHook, listenerArmy);
  }

  /**
   * Address: 0x008AAF20 (FUN_008AAF20)
   *
   * Moho::VTransform const&
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::SetListenerTransform(Moho::CUserSoundManager *this, Moho::VTransform
   * const& transform);
   *
   * What it does:
   * Forwards listener transform to the primary voice engine.
   */
  void CUserSoundManager::SetListenerTransform(const VTransform& transform)
  {
    if (AudioEngine* const voiceEngine = mVoiceEngine.get(); voiceEngine != nullptr) {
      voiceEngine->SetListenerTransform(transform);
    }
  }

  /**
   * Address: 0x008AB4C0 (FUN_008AB4C0)
   *
   * IDA signature:
   * char __thiscall Moho::CUserSoundManager::StopAllSounds(Moho::CUserSoundManager *this);
   *
   * What it does:
   * Destroys active entity loops, drains transient loop handles, and stops the
   * global category on the active voice engine.
   */
  void CUserSoundManager::StopAllSounds()
  {
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      if (record.mLoopIndex != -1) {
        SND_DestroyEntityLoop(&record);
      }
    }

    auto* const sentinel = reinterpret_cast<LoopNode*>(&mActiveLoops);
    while (mActiveLoops.mNext != sentinel) {
      HSound* const sound = LoopOwnerFromNode(mActiveLoops.mNext);
      if (sound->mLoopCue != nullptr) {
        StopAndDestroyCue(sound->mLoopCue);
        sound->mLoopCue = nullptr;

        if (sound->mAffectsDucking != 0u && mActiveDuckingSounds > 0) {
          --mActiveDuckingSounds;
          if (mActiveDuckingSounds == 0 && IsSndVarReady(mDuckLengthVar)) {
            mDuckElapsedSeconds = 0.0f;
            mDuckMode = 2;
          }
        }
      }

      sound->Destroy(1u);
    }

    if (AudioEngine* const engine = mVoiceEngine.get(); engine != nullptr && engine->mImpl != nullptr) {
      if (IXACTEngine* const xactEngine = engine->mImpl->mInstance; xactEngine != nullptr) {
        const std::uint16_t categoryId = xactEngine->GetCategory("Global");
        if (categoryId == 0xFFFFu) {
          gpg::Warnf("SND: StopAllSounds - Invalid Category [%s]", "Global");
        } else {
          xactEngine->Stop(categoryId, 0);
        }
      }
    }

    mActiveDuckingSounds = 0;
    mDuckMode = 0;

    if (IsSndVarReady(mDuckVar)) {
      SND_SetGlobalFloat(mDuckVar.mState, 0.0f);
    }
  }

  /**
   * Address: 0x008AAF60 (FUN_008AAF60)
   *
   * gpg::StrArg, float
   *
   * IDA signature:
   * void __thiscall Moho::CUserSoundManager::SetVolume(Moho::CUserSoundManager *this, gpg::StrArg category, float
   * value);
   *
   * What it does:
   * Clears ducking state, resets "Duck" global variable, then pushes category
   * volume to active engines.
   */
  void CUserSoundManager::SetVolume(const gpg::StrArg category, const float value)
  {
    mActiveDuckingSounds = 0;
    mDuckMode = 0;

    if (IsSndVarReady(mDuckVar)) {
      SND_SetGlobalFloat(mDuckVar.mState, 0.0f);
    }

    if (AudioEngine* const voiceEngine = mVoiceEngine.get(); voiceEngine != nullptr) {
      voiceEngine->SetVolume(category, value);
    }

    if (AudioEngine* const tutorialEngine = mTutorialEngine.get(); tutorialEngine != nullptr) {
      tutorialEngine->SetVolume(category, value);
    }
    if (AudioEngine* const ambientEngine = mAmbientEngine.get(); ambientEngine != nullptr) {
      ambientEngine->SetVolume(category, value);
    }
  }

  /**
   * Address: 0x008AB000 (FUN_008AB000)
   *
   * gpg::StrArg
   *
   * IDA signature:
   * double __thiscall Moho::CUserSoundManager::GetVolume(Moho::CUserSoundManager *this, gpg::StrArg category);
   *
   * What it does:
   * Returns category volume from the primary voice engine.
   */
  float CUserSoundManager::GetVolume(const gpg::StrArg category)
  {
    if (AudioEngine* const voiceEngine = mVoiceEngine.get(); voiceEngine != nullptr) {
      return voiceEngine->GetVolume(category);
    }

    return 1.0f;
  }

  /**
   * Address: 0x008AB670 (FUN_008AB670)
   *
   * float deltaSeconds
   *
   * IDA signature:
   * unsigned __int8 __userpurge Moho::CUserSoundManager::UpdateDuck@<al>(Moho::CUserSoundManager *this@<edi>, float
   * deltaSeconds);
   *
   * What it does:
   * Integrates ducking progress and writes the resulting duck scalar.
   */
  void CUserSoundManager::UpdateDuck(const float deltaSeconds)
  {
    if (!IsSndVarReady(mDuckVar)) {
      return;
    }
    if (!IsSndVarReady(mDuckLengthVar)) {
      return;
    }

    const float duckLengthSeconds = SND_GetGlobalFloat(mDuckLengthVar.mState);
    float nextElapsed = mDuckElapsedSeconds + deltaSeconds;
    if (duckLengthSeconds <= nextElapsed) {
      nextElapsed = duckLengthSeconds;
    }
    mDuckElapsedSeconds = nextElapsed;

    const float normalized = nextElapsed / duckLengthSeconds;
    float duckValue = normalized;
    if (mDuckMode == 2) {
      duckValue = 1.0f - normalized;
    }

    if (snd_SpewSound) {
      gpg::Debugf("duck time %f", duckValue);
    }

    SND_SetGlobalFloat(mDuckVar.mState, duckValue);
    if (mDuckElapsedSeconds == duckLengthSeconds) {
      mDuckMode = 0;
    }
  }

  /**
   * Address: 0x008ABBA0 (FUN_008ABBA0)
   *
   * Moho::CSndParams const*, Moho::ELayer, Wm3::Vector3<float> const*
   *
   * IDA signature:
   * Moho::CUserSoundManager::EFilterType __userpurge Moho::CUserSoundManager::FilterSound@<eax>(Moho::CSndParams
   * *params@<eax>, Moho::CUserSoundManager *this@<edx>, Moho::ELayer layer@<ecx>, Wm3::Vector3f *worldPos);
   *
   * What it does:
   * Applies distance and LOS filtering for candidate sounds.
   */
  CUserSoundManager::EFilterType CUserSoundManager::FilterSound(
    const CSndParams* const params, const ELayer layer, const Wm3::Vec3f* const worldPos
  ) const
  {
    if (params == nullptr) {
      return EFilterType::MissingParams;
    }

    if (snd_CheckDistance && params->mLodCutoff != nullptr) {
      const float lodCutoff = SND_GetGlobalFloat(params->mLodCutoff->mState);
      if (lodCutoff > -1.0f && mCurrentCameraDistanceMetric > lodCutoff) {
        return EFilterType::DistanceCulled;
      }
    }

    if (!snd_CheckLOS) {
      return EFilterType::Pass;
    }

    UserArmy::EReconGridMask reconMask = UserArmy::EReconGridMask::Explored;
    if (layer == kLayerSeabed || layer == kLayerSub) {
      reconMask = UserArmy::EReconGridMask::Fog;
    }

    UserArmy* listenerArmy = nullptr;
    if (mListenerArmyHook.mOwnerAnchor != nullptr) {
      listenerArmy = reinterpret_cast<UserArmy*>(
        reinterpret_cast<std::uintptr_t>(mListenerArmyHook.mOwnerAnchor) - offsetof(UserArmy, mVariableDataWord_01E0)
      );
    }

    if (listenerArmy == nullptr) {
      return EFilterType::Pass;
    }
    if (listenerArmy->CanSeePoint(*worldPos, reconMask)) {
      return EFilterType::Pass;
    }

    return EFilterType::LosCulled;
  }
} // namespace moho
