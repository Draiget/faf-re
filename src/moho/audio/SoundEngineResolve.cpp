// Engine addition (dedicated-server plan WPL.4, WPR.11): resolving sound parameters and
// variables against the client's audio engines (banks, cues, global variables) and a
// sound handle's loop-cue state, moved unchanged out of CSndParams.cpp, CSndVar.cpp and
// HSound.cpp: only the client's sound manager plays sounds. The simulation keeps the
// parameters, variables and handles themselves.
#include "moho/audio/CSndParams.h"
#include "moho/audio/CSndVar.h"
#include "moho/audio/HSound.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/AudioEngine.h"

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  constexpr std::uint32_t kResolvePolicyMissingBank = 4u;
  constexpr std::uint32_t kResolvePolicyMissingCue = 3u;
  constexpr std::uint32_t kResolvePolicyMissingEngine = 2u;
  constexpr std::uint32_t kResolvePolicyResolved = 1u;
  constexpr std::uint32_t kResolvePolicyUnresolved = 0u;
  constexpr const char* kSndParamsSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\SndParams.cpp";
  constexpr int kSndParamsUnreachableLine = 387;
  /**
   * Address: 0x004E14C0 (FUN_004E14C0)
   *
   * What it does:
   * Promotes one weak `AudioEngine` handle to a shared handle when the engine
   * is still alive.
   */
  [[nodiscard]] boost::shared_ptr<moho::AudioEngine>
  LockWeakAudioEngine(const boost::weak_ptr<moho::AudioEngine>& weakEngine)
  {
    return weakEngine.lock();
  }
} // namespace


namespace moho
{
  /**
   * Address: 0x004E0820 (FUN_004E0820)
   *
   * What it does:
   * Returns a resolved engine handle according to cached resolve state and
   * current sound-configuration availability.
   */
  boost::shared_ptr<AudioEngine>* CSndParams::GetEngine(boost::shared_ptr<AudioEngine>* const outEngine) const
  {
    if (outEngine == nullptr) {
      return outEngine;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mFinish == nullptr || configuration->mEngines.mStart == configuration->mEngines.mFinish ||
        configuration->mNoSound != 0u) {
      *outEngine = {};
      return outEngine;
    }

    boost::shared_ptr<AudioEngine> resolvedEngine = LockWeakAudioEngine(mEngine);
    switch (mResolvePolicy) {
    case kResolvePolicyUnresolved:
      *outEngine = DoResolve();
      break;

    case kResolvePolicyResolved:
      if (resolvedEngine.get() != nullptr) {
        *outEngine = resolvedEngine;
      } else {
        *outEngine = DoResolve();
      }
      break;

    case kResolvePolicyMissingEngine:
      *outEngine = {};
      break;

    case kResolvePolicyMissingCue:
    case kResolvePolicyMissingBank:
      if (resolvedEngine.get() != nullptr) {
        *outEngine = {};
      } else {
        *outEngine = DoResolve();
      }
      break;

    default:
      gpg::HandleAssertFailure("Reached the supposably unreachable.", kSndParamsUnreachableLine, kSndParamsSourcePath);
      *outEngine = {};
      break;
    }

    return outEngine;
  }

  /**
   * Address: 0x004E0930 (FUN_004E0930)
   * Mangled: ?DoResolve@CSndParams@Moho@@ABE?AV?$shared_ptr@VAudioEngine@Moho@@@boost@@XZ
   *
   * What it does:
   * Resolves one engine/bank/cue tuple and caches ids/resolve policy for
   * subsequent cue playback requests.
   */
  boost::shared_ptr<AudioEngine> CSndParams::DoResolve() const
  {
    boost::shared_ptr<AudioEngine> resolvedEngine = LockWeakAudioEngine(mEngine);
    if (resolvedEngine.get() == nullptr) {
      resolvedEngine = SND_FindEngine(mBank.c_str());
      mEngine = resolvedEngine;


      if (resolvedEngine.get() == nullptr) {
        gpg::Warnf("Error resolving bank '%s' to audio engine", mBank.c_str());
        mResolvePolicy = kResolvePolicyMissingEngine;
        return {};
      }
    }

    if (!resolvedEngine->GetBankIndex(mBank.c_str(), &mBankId)) {
      gpg::Warnf("Error resolving bank '%s'", mBank.c_str());
      mResolvePolicy = kResolvePolicyMissingBank;
      return {};
    }

    if (!resolvedEngine->GetCueIndex(mCue.c_str(), mBankId, &mCueId)) {
      gpg::Warnf("Error resolving cue '%s' in bank '%s'", mCue.c_str(), mBank.c_str());
      mResolvePolicy = kResolvePolicyMissingCue;
      return {};
    }

    if (mLodCutoff != nullptr && mLodCutoff->mResolved == 0u) {
      (void)mLodCutoff->DoResolve();
    }

    if (mRpcLoopVariable != nullptr && mRpcLoopVariable->mResolved == 0u) {
      (void)mRpcLoopVariable->DoResolve();
    }

    mResolvePolicy = kResolvePolicyResolved;
    return resolvedEngine;
  }

} // namespace moho

namespace moho
{
  /**
   * Address: 0x004E0390 (FUN_004E0390)
   *
   * What it does:
   * Resolves one global XACT variable index by name and caches the result.
   */
  bool CSndVar::DoResolve() const
  {
    mResolved = 1u;
    if (SND_GetGlobalVarIndex(mName.c_str(), &mState)) {
      return true;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration.get();
    if (configuration != nullptr && configuration->mEngines.mStart != nullptr &&
        configuration->mEngines.mStart != configuration->mEngines.mFinish && configuration->mNoSound == 0u) {
      gpg::Warnf("SND: Couldn't find variable %s", mName.c_str());
    }

    return false;
  }

} // namespace moho

namespace moho
{
  /**
   * Address: 0x004E1260 (FUN_004E1260, sub_4E1260)
   *
   * What it does:
   * Resolves loop-engine state and signals completion when the cue has stopped
   * or no longer has a valid engine/cue context.
   */
  bool HSound::UpdateLoopCompletionState()
  {
    if (mTriggered) {
      return false;
    }

    bool shouldSignal = true;
    if (mLoopCue != nullptr && mLoopOwnerContext != nullptr) {
      boost::shared_ptr<AudioEngine> engine{};
      mLoopOwnerContext->GetEngine(&engine);
      if (engine.get() != nullptr) {
        shouldSignal = engine->IsStopped(mLoopCue);
      }
    }

    if (!shouldSignal) {
      return false;
    }

    EventSetSignaled(true);
    return true;
  }

} // namespace moho
