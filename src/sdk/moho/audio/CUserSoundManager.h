#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/CSndVar.h"
#include "moho/audio/HSound.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/TDatList.h"
#include "wm3/Vector3.h"

namespace moho
{
  class AudioEngine;
  class UserArmy;
  class VTransform;
  class IXACTCue;

  struct SoundHandleIdPool
  {
    BVIntSet mFreeIds;     // +0x00
    std::uint32_t mNextId; // +0x20
  };

  struct SoundHandleRecord
  {
    std::uint32_t mHandleId = 0;         // +0x00
    std::uint32_t mFlags = 0;            // +0x04
    IXACTCue* mCue = nullptr;            // +0x08
    CSndParams* mParams = nullptr;       // +0x0C
    void* mEntityLoopState = nullptr;    // +0x10
    std::int32_t mLoopIndex = -1;        // +0x14 (-1 when inactive)
    void* mEntitySetRoot = nullptr;      // +0x18
    void* mEntitySetSentinel = nullptr;  // +0x1C
    std::uint32_t mRpcVariableValue = 0; // +0x20
    float mPlayingSeconds = 0.0f;        // +0x24
  };

  struct ListenerArmyHook
  {
    std::uintptr_t* mOwnerAnchor; // +0x00 (points to UserArmy + 0x1E0 slot)
    ListenerArmyHook* mNext;      // +0x04
  };

  static_assert(sizeof(SoundHandleIdPool) == 0x24, "SoundHandleIdPool size must be 0x24");
  static_assert(offsetof(SoundHandleIdPool, mFreeIds) == 0x00, "SoundHandleIdPool::mFreeIds offset must be 0x00");
  static_assert(offsetof(SoundHandleIdPool, mNextId) == 0x20, "SoundHandleIdPool::mNextId offset must be 0x20");

  static_assert(sizeof(SoundHandleRecord) == 0x28, "SoundHandleRecord size must be 0x28");
  static_assert(offsetof(SoundHandleRecord, mCue) == 0x08, "SoundHandleRecord::mCue offset must be 0x08");
  static_assert(offsetof(SoundHandleRecord, mParams) == 0x0C, "SoundHandleRecord::mParams offset must be 0x0C");
  static_assert(offsetof(SoundHandleRecord, mLoopIndex) == 0x14, "SoundHandleRecord::mLoopIndex offset must be 0x14");
  static_assert(
    offsetof(SoundHandleRecord, mPlayingSeconds) == 0x24, "SoundHandleRecord::mPlayingSeconds offset must be 0x24"
  );

  static_assert(sizeof(ListenerArmyHook) == 0x08, "ListenerArmyHook size must be 0x08");
  static_assert(sizeof(msvc8::set<IXACTCue*>) == 0x0C, "msvc8::set<IXACTCue*> size must be 0x0C");

  /**
   * VFTABLE: 0x00E4C444
   * COL:     0x00E9DB28
   */
  class CUserSoundManager final : public IUserSoundManager
  {
  public:
    enum class EFilterType : std::int32_t
    {
      Pass = 0,
      MissingParams = 1,
      DistanceCulled = 2,
      LosCulled = 3,
    };

    /**
     * Address: 0x008AA800 (FUN_008AA800, ??0CUserSoundManager@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes default sound-handle pools, per-category vars, and primary
     * voice-engine ownership for user audio playback.
     */
    CUserSoundManager();

    /**
     * Address: 0x008AAA10 (FUN_008AAA10, ??1CUserSoundManager@Moho@@QAE@XZ)
     *
     * What it does:
     * Unhooks intrusive listener/list entries and releases owned user-audio
     * resources.
     */
    ~CUserSoundManager();

    /**
     * Address: 0x008AC0B0 (FUN_008AC0B0)
     * Slot: 0
     *
     * gpg::fastvector<Moho::SAudioRequest> const&
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::UpdateSoundRequests(Moho::CUserSoundManager *this,
     * gpg::fastvector_SAudioRequest const *requests);
     *
     * What it does:
     * Consumes sim-produced audio requests and starts/stops one-shot and loop
     * cues after camera/visibility filtering.
     */
    void UpdateSoundRequests(const gpg::fastvector<SAudioRequest>& requests) override;

    /**
     * Address: 0x008AB770 (FUN_008AB770)
     * Slot: 1
     *
     * float simDeltaSeconds, float frameSeconds
     *
     * IDA signature:
     * int __thiscall Moho::CUserSoundManager::Frame(Moho::CUserSoundManager *this, float a2, float a3);
     *
     * What it does:
     * Updates listener transform and active handles, runs ducking updates, and
     * destroys finished cues.
     */
    void Frame(float simDeltaSeconds, float frameSeconds) override;

    /**
     * Address: 0x008AAF30 (FUN_008AAF30)
     * Slot: 2
     *
     * Moho::UserArmy*
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::SetListenerArmy(Moho::CUserSoundManager *this, Moho::UserArmy *army);
     *
     * What it does:
     * Rebinds the listener-army hook used for LOS audio filtering.
     */
    void SetListenerArmy(UserArmy* listenerArmy) override;

    /**
     * Address: 0x008AAC50 (FUN_008AAC50)
     * Slot: 3
     *
     * msvc8::string const&, msvc8::string const&
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::Play(Moho::CUserSoundManager *this, msvc8::string const& bankName,
     * msvc8::string const& cueName);
     *
     * What it does:
     * Resolves/plays a one-shot cue by bank+cue string names.
     */
    void Play(const msvc8::string& bankName, const msvc8::string& cueName) override;

    /**
     * Address: 0x008AAE00 (FUN_008AAE00)
     * Slot: 4
     *
     * Moho::CSndParams const&
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::Play2D(Moho::CUserSoundManager *this, Moho::CSndParams const& params);
     *
     * What it does:
     * Plays a 2D cue from a pre-resolved parameter block.
     */
    void Play2D(const CSndParams& params) override;

    /**
     * Address: 0x008AAF20 (FUN_008AAF20)
     * Slot: 5
     *
     * Moho::VTransform const&
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::SetListenerTransform(Moho::CUserSoundManager *this, Moho::VTransform
     * const& transform);
     *
     * What it does:
     * Writes listener transform into the active voice audio engine.
     */
    void SetListenerTransform(const VTransform& transform) override;

    /**
     * Address: 0x008AB4C0 (FUN_008AB4C0)
     * Slot: 6
     *
     * IDA signature:
     * char __thiscall Moho::CUserSoundManager::StopAllSounds(Moho::CUserSoundManager *this);
     *
     * What it does:
     * Stops all active cues/loops and resets ducking state.
     */
    void StopAllSounds() override;

    /**
     * Address: 0x008AAF60 (FUN_008AAF60)
     * Slot: 7
     *
     * gpg::StrArg, float
     *
     * IDA signature:
     * void __thiscall Moho::CUserSoundManager::SetVolume(Moho::CUserSoundManager *this, gpg::StrArg category, float
     * value);
     *
     * What it does:
     * Applies category volume to active audio engines and clears ducking.
     */
    void SetVolume(gpg::StrArg category, float value) override;

    /**
     * Address: 0x008AB000 (FUN_008AB000)
     * Slot: 8
     *
     * gpg::StrArg
     *
     * IDA signature:
     * double __thiscall Moho::CUserSoundManager::GetVolume(Moho::CUserSoundManager *this, gpg::StrArg category);
     *
     * What it does:
     * Reads category volume from the active voice audio engine.
     */
    float GetVolume(gpg::StrArg category) override;

  private:
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
     * Advances current duck interpolation and writes "Duck" global variable.
     */
    void UpdateDuck(float deltaSeconds);

    /**
     * Address: 0x008ABBA0 (FUN_008ABBA0)
     *
     * Moho::CSndParams const*, Moho::ELayer, Wm3::Vec3f const*
     *
     * IDA signature:
     * Moho::CUserSoundManager::EFilterType __userpurge Moho::CUserSoundManager::FilterSound@<eax>(Moho::CSndParams
     * *params@<eax>, Moho::CUserSoundManager *this@<edx>, Moho::ELayer layer@<ecx>, Wm3::Vector3f *worldPos);
     *
     * What it does:
     * Returns pass/cull reason based on distance and LOS checks.
     */
    EFilterType FilterSound(const CSndParams* params, ELayer layer, const Wm3::Vec3f* worldPos) const;

  public:
    std::uint32_t mReserved04;                               // +0x04
    gpg::fastvector_n<std::uint32_t, 64> mRecentOneShotKeys; // +0x08
    SoundHandleIdPool mLoopHandleIdPool;                     // +0x118
    std::uint32_t mReserved13C;                              // +0x13C
    gpg::fastvector_n<SoundHandleRecord, 256> mSoundHandles; // +0x140

    msvc8::set<IXACTCue*> mPendingDestroyCues; // +0x2950
    ListenerArmyHook mListenerArmyHook;        // +0x295C
    TDatList<HSound, void> mActiveLoops;       // +0x2964

    boost::shared_ptr<AudioEngine> mAmbientEngine;  // +0x296C
    boost::shared_ptr<AudioEngine> mTutorialEngine; // +0x2974
    boost::shared_ptr<AudioEngine> mVoiceEngine;    // +0x297C

    CSndVar mCameraDistanceVar;         // +0x2984
    CSndVar mZoomPercentVar;            // +0x29A4
    float mCurrentCameraDistanceMetric; // +0x29C4
    std::uint8_t mWorldSoundsEnabled;   // +0x29C8
    std::uint8_t mReserved29C9[0x03];   // +0x29C9
    msvc8::string mLanguageTag;         // +0x29CC

    CSndVar mDuckLengthVar;            // +0x29E8
    CSndVar mDuckVar;                  // +0x2A08
    std::int32_t mDuckMode;            // +0x2A28
    float mDuckElapsedSeconds;         // +0x2A2C
    std::int32_t mActiveDuckingSounds; // +0x2A30
    std::uint32_t mReserved2A34;       // +0x2A34
  };

  static_assert(
    offsetof(CUserSoundManager, mRecentOneShotKeys) == 0x08, "CUserSoundManager::mRecentOneShotKeys offset must be 0x08"
  );
  static_assert(
    offsetof(CUserSoundManager, mLoopHandleIdPool) == 0x118, "CUserSoundManager::mLoopHandleIdPool offset must be 0x118"
  );
  static_assert(
    offsetof(CUserSoundManager, mSoundHandles) == 0x140, "CUserSoundManager::mSoundHandles offset must be 0x140"
  );
  static_assert(
    offsetof(CUserSoundManager, mPendingDestroyCues) == 0x2950,
    "CUserSoundManager::mPendingDestroyCues offset must be 0x2950"
  );
  static_assert(
    offsetof(CUserSoundManager, mListenerArmyHook) == 0x295C,
    "CUserSoundManager::mListenerArmyHook offset must be 0x295C"
  );
  static_assert(
    offsetof(CUserSoundManager, mActiveLoops) == 0x2964, "CUserSoundManager::mActiveLoops offset must be 0x2964"
  );
  static_assert(
    offsetof(CUserSoundManager, mVoiceEngine) == 0x297C, "CUserSoundManager::mVoiceEngine offset must be 0x297C"
  );
  static_assert(
    offsetof(CUserSoundManager, mCameraDistanceVar) == 0x2984,
    "CUserSoundManager::mCameraDistanceVar offset must be 0x2984"
  );
  static_assert(
    offsetof(CUserSoundManager, mZoomPercentVar) == 0x29A4, "CUserSoundManager::mZoomPercentVar offset must be 0x29A4"
  );
  static_assert(
    offsetof(CUserSoundManager, mCurrentCameraDistanceMetric) == 0x29C4,
    "CUserSoundManager::mCurrentCameraDistanceMetric offset must be 0x29C4"
  );
  static_assert(
    offsetof(CUserSoundManager, mLanguageTag) == 0x29CC, "CUserSoundManager::mLanguageTag offset must be 0x29CC"
  );
  static_assert(
    offsetof(CUserSoundManager, mDuckLengthVar) == 0x29E8, "CUserSoundManager::mDuckLengthVar offset must be 0x29E8"
  );
  static_assert(offsetof(CUserSoundManager, mDuckVar) == 0x2A08, "CUserSoundManager::mDuckVar offset must be 0x2A08");
  static_assert(offsetof(CUserSoundManager, mDuckMode) == 0x2A28, "CUserSoundManager::mDuckMode offset must be 0x2A28");
  static_assert(
    offsetof(CUserSoundManager, mDuckElapsedSeconds) == 0x2A2C,
    "CUserSoundManager::mDuckElapsedSeconds offset must be 0x2A2C"
  );
  static_assert(
    offsetof(CUserSoundManager, mActiveDuckingSounds) == 0x2A30,
    "CUserSoundManager::mActiveDuckingSounds offset must be 0x2A30"
  );
  static_assert(sizeof(CUserSoundManager) == 0x2A38, "CUserSoundManager size must be 0x2A38");
  static_assert(std::is_polymorphic<CUserSoundManager>::value, "CUserSoundManager must remain polymorphic");
} // namespace moho
