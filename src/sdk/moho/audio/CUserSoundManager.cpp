#include "moho/audio/CUserSoundManager.h"

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"
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
  constexpr moho::ELayer kLayerSeabed = static_cast<moho::ELayer>(2);
  constexpr moho::ELayer kLayerSub = static_cast<moho::ELayer>(4);

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
} // namespace

namespace moho
{
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
    mVoiceEngine.get()->SetListenerTransform(transform);
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

    mVoiceEngine.get()->SetVolume(category, value);

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
    return mVoiceEngine.get()->GetVolume(category);
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
