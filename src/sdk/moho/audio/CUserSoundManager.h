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

struct lua_State;

namespace moho
{
  class AudioEngine;
  class CScrLuaInitForm;
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
    HSndEntityLoop* mOwnerHandle = nullptr;         // +0x00 (shared-ambient owner lane)
    SoundHandleRecord* mOwnerNextInChain = nullptr; // +0x04
    IXACTCue* mCue = nullptr;                       // +0x08
    CSndParams* mParams = nullptr;                  // +0x0C
    std::uint16_t mAngleVariableIndex = 0xFFFFu;    // +0x10 (0xFFFF => no angle variable)
    std::uint16_t mReserved12 = 0u;                 // +0x12
    std::int32_t mLoopIndex = -1;                   // +0x14 (-1 when inactive)
    void* mTrackedEntitySetProxy = nullptr;         // +0x18
    void* mTrackedEntitySetHead = nullptr;          // +0x1C
    std::uint32_t mTrackedEntityCount = 0u;         // +0x20
    float mPlayingSeconds = 0.0f;                   // +0x24
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
  static_assert(
    offsetof(SoundHandleRecord, mOwnerHandle) == 0x00, "SoundHandleRecord::mOwnerHandle offset must be 0x00"
  );
  static_assert(
    offsetof(SoundHandleRecord, mOwnerNextInChain) == 0x04,
    "SoundHandleRecord::mOwnerNextInChain offset must be 0x04"
  );
  static_assert(offsetof(SoundHandleRecord, mCue) == 0x08, "SoundHandleRecord::mCue offset must be 0x08");
  static_assert(offsetof(SoundHandleRecord, mParams) == 0x0C, "SoundHandleRecord::mParams offset must be 0x0C");
  static_assert(
    offsetof(SoundHandleRecord, mAngleVariableIndex) == 0x10,
    "SoundHandleRecord::mAngleVariableIndex offset must be 0x10"
  );
  static_assert(offsetof(SoundHandleRecord, mLoopIndex) == 0x14, "SoundHandleRecord::mLoopIndex offset must be 0x14");
  static_assert(
    offsetof(SoundHandleRecord, mTrackedEntitySetProxy) == 0x18,
    "SoundHandleRecord::mTrackedEntitySetProxy offset must be 0x18"
  );
  static_assert(
    offsetof(SoundHandleRecord, mTrackedEntitySetHead) == 0x1C,
    "SoundHandleRecord::mTrackedEntitySetHead offset must be 0x1C"
  );
  static_assert(
    offsetof(SoundHandleRecord, mTrackedEntityCount) == 0x20,
    "SoundHandleRecord::mTrackedEntityCount offset must be 0x20"
  );
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

    /**
     * Address: 0x008AAF50 (FUN_008AAF50)
     *
     * bool enabled
     *
     * What it does:
     * Toggles world-sound request processing for this user sound manager.
     */
    void EnableWorldSounds(bool enabled);

    /**
     * Address: 0x008AB020 (FUN_008AB020)
     *
     * What it does:
     * Increments active ducking sound count and starts duck fade-in when this
     * is the first active duck request.
     */
    void PushDuck();

    /**
     * Address: 0x008AB070 (FUN_008AB070)
     *
     * bool immediate
     *
     * What it does:
     * Decrements or clears active ducking sound count and starts/forces duck
     * fade-out depending on stop mode.
     */
    void PopDuck(bool immediate);

    /**
     * Address: 0x008AB2B0 (FUN_008AB2B0)
     *
     * Moho::AudioEngine*, Moho::CSndParams*, bool preloadOnly
     *
     * What it does:
     * Plays one script-triggered cue, wraps it in `HSound`, and links it to
     * the active loop list when cue creation succeeds.
     */
    [[nodiscard]] HSound* ScriptPlaySound(AudioEngine* engine, CSndParams* params, bool preloadOnly);

    /**
     * Address: 0x008AB450 (FUN_008AB450)
     *
     * Moho::HSound*, bool immediate
     *
     * What it does:
     * Stops one script-created cue (immediate or deferred) and destroys the
     * `HSound` handle when no deferred cue remains active.
     */
    void ScriptStopSound(HSound* sound, bool immediate);

    /**
     * Address: 0x008ACBD0 (FUN_008ACBD0, Moho::CUserSoundManager::DumpActiveLoops)
     *
     * What it does:
     * Dumps one line per sound-handle slot, including active
     * `bank.cue` and optional stopping-seconds suffix.
     */
    void DumpActiveLoops();

  private:
    /**
     * Address: 0x008ABE90 (FUN_008ABE90)
     *
     * std::int32_t const&, Moho::HSndEntityLoop*
     *
     * What it does:
     * Starts one entity-loop cue instance, binds a sound-handle slot, and
     * seeds initial spatialization from the tracked entity.
     */
    void StartEntityLoop(const std::int32_t& entityId, HSndEntityLoop* loopHandle);

    /**
     * Address: 0x008ABCD0 (FUN_008ABCD0)
     *
     * std::int32_t const&, Moho::HSndEntityLoop*
     *
     * What it does:
     * Starts/reuses one RPC entity-loop cue and publishes active tracked-entity
     * count into the RPC loop global variable lane.
     */
    void StartRPCEntityLoop(const std::int32_t& entityId, HSndEntityLoop* loopHandle);

    /**
     * Address: 0x008ABC60 (FUN_008ABC60)
     *
     * Moho::SoundHandleRecord*
     *
     * What it does:
     * Publishes `(tracked_count - 1)` to the record RPC loop variable and
     * stops the cue when this call removes the last tracked entity.
     */
    [[nodiscard]] bool StopRPCEntityLoop(SoundHandleRecord* record);

    /**
     * Address: 0x008ABCB0 (FUN_008ABCB0)
     *
     * Moho::SoundHandleRecord*, bool destroy
     *
     * What it does:
     * Routes one entity-loop stop request to either stop-only or
     * stop-and-destroy behavior.
     */
    void StopEntityLoop(SoundHandleRecord* record, bool destroy);

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

  /**
   * Address: 0x008AD100 (FUN_008AD100, cfunc_PlaySound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlaySoundL`.
   */
  int cfunc_PlaySound(lua_State* luaContext);

  /**
   * Address: 0x008AD120 (FUN_008AD120, func_PlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlaySound`.
   */
  CScrLuaInitForm* func_PlaySound_LuaFuncDef();

  /**
   * Address: 0x008AD180 (FUN_008AD180, cfunc_PlaySoundL)
   *
   * What it does:
   * Resolves one `CSndParams` Lua object, plays one voice-engine cue, and
   * returns an `HSound` Lua object or nil.
   */
  int cfunc_PlaySoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD280 (FUN_008AD280, cfunc_SoundIsPrepared)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_SoundIsPreparedL`.
   */
  int cfunc_SoundIsPrepared(lua_State* luaContext);

  /**
   * Address: 0x008AD2A0 (FUN_008AD2A0, func_SoundIsPrepared_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SoundIsPrepared`.
   */
  CScrLuaInitForm* func_SoundIsPrepared_LuaFuncDef();

  /**
   * Address: 0x008AD300 (FUN_008AD300, cfunc_SoundIsPreparedL)
   *
   * What it does:
   * Returns whether an optional script `HSound` handle still has an active cue
   * state (`true` for nil/missing handles).
   */
  int cfunc_SoundIsPreparedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD400 (FUN_008AD400, cfunc_StartSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_StartSoundL`.
   */
  int cfunc_StartSound(lua_State* luaContext);

  /**
   * Address: 0x008AD420 (FUN_008AD420, func_StartSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StartSound`.
   */
  CScrLuaInitForm* func_StartSound_LuaFuncDef();

  /**
   * Address: 0x008AD480 (FUN_008AD480, cfunc_StartSoundL)
   *
   * What it does:
   * Resolves optional script `HSound` handle and triggers cue playback when a
   * loop cue instance exists.
   */
  int cfunc_StartSoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD6D0 (FUN_008AD6D0, Moho::Con_DumpActiveLoops)
   *
   * What it does:
   * Runs one console helper that dumps currently active loop handles.
   */
  void Con_DumpActiveLoops();

  /**
   * Address: 0x008AD6F0 (FUN_008AD6F0, cfunc_SetVolume)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_SetVolumeL`.
   */
  int cfunc_SetVolume(lua_State* luaContext);

  /**
   * Address: 0x008AD710 (FUN_008AD710, func_SetVolume_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetVolume`.
   */
  CScrLuaInitForm* func_SetVolume_LuaFuncDef();

  /**
   * Address: 0x008AD770 (FUN_008AD770, cfunc_SetVolumeL)
   *
   * What it does:
   * Parses `(category, volume)` and applies category volume on user audio
   * manager.
   */
  int cfunc_SetVolumeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD850 (FUN_008AD850, cfunc_GetVolume)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_GetVolumeL`.
   */
  int cfunc_GetVolume(lua_State* luaContext);

  /**
   * Address: 0x008AD870 (FUN_008AD870, func_GetVolume_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetVolume`.
   */
  CScrLuaInitForm* func_GetVolume_LuaFuncDef();

  /**
   * Address: 0x008AD8D0 (FUN_008AD8D0, cfunc_GetVolumeL)
   *
   * What it does:
   * Parses one category string, queries user audio manager volume, and pushes
   * one Lua number result.
   */
  int cfunc_GetVolumeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD550 (FUN_008AD550, cfunc_StopSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_StopSoundL`.
   */
  int cfunc_StopSound(lua_State* luaContext);

  /**
   * Address: 0x008AD570 (FUN_008AD570, func_StopSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StopSound`.
   */
  CScrLuaInitForm* func_StopSound_LuaFuncDef();

  /**
   * Address: 0x008AD5D0 (FUN_008AD5D0, cfunc_StopSoundL)
   *
   * What it does:
   * Resolves optional script `HSound` handle and stops one cue immediately or
   * deferred based on the second Lua argument.
   */
  int cfunc_StopSoundL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008AD970 (FUN_008AD970, cfunc_StopAllSounds)
   *
   * What it does:
   * Validates no-arg Lua call and stops all currently active user sounds.
   */
  int cfunc_StopAllSounds(lua_State* luaContext);

  /**
   * Address: 0x008AD9C0 (FUN_008AD9C0, func_StopAllSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StopAllSounds`.
   */
  CScrLuaInitForm* func_StopAllSounds_LuaFuncDef();

  /**
   * Address: 0x008ADA50 (FUN_008ADA50, cfunc_DisableWorldSounds)
   *
   * What it does:
   * Validates no-arg Lua call and disables world-sound playback requests.
   */
  int cfunc_DisableWorldSounds(lua_State* luaContext);

  /**
   * Address: 0x008ADAA0 (FUN_008ADAA0, func_DisableWorldSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DisableWorldSounds`.
   */
  CScrLuaInitForm* func_DisableWorldSounds_LuaFuncDef();

  /**
   * Address: 0x008ADB30 (FUN_008ADB30, cfunc_EnableWorldSounds)
   *
   * What it does:
   * Validates no-arg Lua call and enables world-sound playback requests.
   */
  int cfunc_EnableWorldSounds(lua_State* luaContext);

  /**
   * Address: 0x008ADB80 (FUN_008ADB80, func_EnableWorldSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EnableWorldSounds`.
   */
  CScrLuaInitForm* func_EnableWorldSounds_LuaFuncDef();

  /**
   * Address: 0x008ADC10 (FUN_008ADC10, cfunc_PlayTutorialVO)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlayTutorialVOL`.
   */
  int cfunc_PlayTutorialVO(lua_State* luaContext);

  /**
   * Address: 0x008ADC30 (FUN_008ADC30, func_PlayTutorialVO_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlayTutorialVO`.
   */
  CScrLuaInitForm* func_PlayTutorialVO_LuaFuncDef();

  /**
   * Address: 0x008ADC90 (FUN_008ADC90, cfunc_PlayTutorialVOL)
   *
   * What it does:
   * Plays one tutorial VO cue, returning an `HSound` Lua object or nil.
   */
  int cfunc_PlayTutorialVOL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008ADD80 (FUN_008ADD80, cfunc_PlayVoice)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlayVoiceL`.
   */
  int cfunc_PlayVoice(lua_State* luaContext);

  /**
   * Address: 0x008ADDA0 (FUN_008ADDA0, func_PlayVoice_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlayVoice`.
   */
  CScrLuaInitForm* func_PlayVoice_LuaFuncDef();

  /**
   * Address: 0x008ADE00 (FUN_008ADE00, cfunc_PlayVoiceL)
   *
   * What it does:
   * Plays one voice cue, optionally flags ducking behavior, and returns an
   * `HSound` Lua object or nil.
   */
  int cfunc_PlayVoiceL(LuaPlus::LuaState* state);
} // namespace moho
