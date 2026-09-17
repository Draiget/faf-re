#include "moho/audio/CUserSoundManager.h"

#include <Windows.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <cstdio>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/audio/AudioEngine.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"
#include "moho/entity/UserEntity.h"

namespace moho
{
  extern bool snd_SpewSound;
  extern bool snd_CheckDistance;
  extern bool snd_CheckLOS;
  extern int snd_index;

  float SND_GetGlobalFloat(std::uint16_t varIndex);
  void SND_SetGlobalFloat(std::uint16_t varIndex, float value);
  void SND_StopEntityLoop(SoundHandleRecord* record);
  void SND_DestroyEntityLoop(SoundHandleRecord* record);
  const char* func_SoundErrorCodeToMsg(int errorCode);

  // TEMPORARY PROBE [SNDDIAG] (do not commit) -- defined in CSndParams.cpp,
  // which owns the registry of every live descriptor. Declared here rather than
  // in the header because the probes come back out again. It has to sit at
  // `moho` scope, not in the anonymous namespace below, or it would name a
  // distinct internal-linkage symbol that nothing ever defines.
  bool SndDiagIsRegisteredParams(const void* candidate);
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

  // 0x008AC9EC `comiss xmm0, ds:dword_E4F8E4`; the constant reads 43 48 00 00 in
  // the shipped image. Above this listener metric no entity loop is started.
  constexpr float kEntityLoopListenerCutoff = 200.0f;
  constexpr const char* kAngleVariableName = "Angle";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kPlaySoundHelpText = "handle = PlaySound(sndParams,prepareOnly)";
  constexpr const char* kPauseSoundHelpText = "PauseSound(categoryString,bPause)";
  constexpr const char* kPauseVoiceHelpText = "PauseVoice(categoryString,bPause)";
  constexpr const char* kSoundIsPreparedHelpText = "bool = SoundIsPrepared(handle)";
  constexpr const char* kStartSoundHelpText = "StartSound(handle)";
  constexpr const char* kSetVolumeHelpText = "SetVolume(category, volume)";
  constexpr const char* kGetVolumeHelpText = "float GetVolume(category)";
  constexpr const char* kStopSoundHelpText = "StopSound(handle,[immediate=false])";
  constexpr const char* kStopAllSoundsHelpText = "StopAllSounds";
  constexpr const char* kDisableWorldSoundsHelpText = "DisableWorldSounds";
  constexpr const char* kEnableWorldSoundsHelpText = "EnableWorldSounds";
  constexpr const char* kPlayTutorialVOHelpText = "PlayTutorialVO(params)";
  constexpr const char* kPlayVoiceHelpText = "PlayVoice(params,duck)";
  constexpr const char* kCueStateQueryFailedWarning = "SND: IXACTCUE::GetState failed.";
  constexpr std::int32_t kCueStateStoppedBit = 0x02;

  moho::CUserSoundManager* gUserSoundManager = nullptr;
  moho::StatItem* gEngineStatSoundLimitedLoop = nullptr;
  moho::StatItem* gEngineStatSoundStartEntityLoop = nullptr;
  moho::StatItem* gEngineStatSoundStopEntityLoop = nullptr;
  moho::StatItem* gEngineStatSoundActiveEntityLoops = nullptr;
  moho::StatItem* gEngineStatSoundPendingDestroy = nullptr;

  /**
   * Address: 0x008AA210 (FUN_008AA210)
   *
   * What it does:
   * Returns one resolved sound-variable state lane.
   */
  [[nodiscard]] std::uint16_t ReadSndVarState(const moho::CSndVar& value) noexcept
  {
    return value.mState;
  }

  /**
   * Address: 0x008AA220 (FUN_008AA220)
   *
   * What it does:
   * Returns one resolved bank id from a sound-parameter descriptor.
   */
  [[nodiscard]] std::uint16_t ReadSndParamsBankId(const moho::CSndParams& params) noexcept
  {
    return params.mBankId;
  }

  /**
   * Address: 0x008AA230 (FUN_008AA230)
   *
   * What it does:
   * Returns one resolved cue id from a sound-parameter descriptor.
   */
  [[nodiscard]] std::uint16_t ReadSndParamsCueId(const moho::CSndParams& params) noexcept
  {
    return params.mCueId;
  }

  /**
   * Address: 0x008AA260 (FUN_008AA260)
   *
   * What it does:
   * Returns one script-loop owner context pointer from a script sound handle.
   */
  [[nodiscard]] moho::CSndParams* ReadSoundLoopOwnerContext(moho::HSound& sound) noexcept
  {
    return sound.mLoopOwnerContext;
  }

  /**
   * Address: 0x008AA270 (FUN_008AA270)
   *
   * What it does:
   * Writes one loop-cue pointer into a script sound handle and returns the
   * same handle.
   */
  [[nodiscard]] moho::HSound* WriteSoundLoopCue(moho::HSound* const sound, moho::IXACTCue* const cue) noexcept
  {
    sound->mLoopCue = cue;
    return sound;
  }

  /**
   * Address: 0x008AA280 (FUN_008AA280)
   *
   * What it does:
   * Returns one loop-cue pointer from a script sound handle.
   */
  [[nodiscard]] moho::IXACTCue* ReadSoundLoopCue(moho::HSound& sound) noexcept
  {
    return sound.mLoopCue;
  }

  /**
   * Address: 0x008AA2A0 (FUN_008AA2A0)
   *
   * What it does:
   * Returns one ducking-flag byte from a script sound handle.
   */
  [[nodiscard]] std::uint8_t ReadSoundAffectsDuckingFlag(const moho::HSound& sound) noexcept
  {
    return sound.mAffectsDucking;
  }

  /**
   * Address: 0x008AA300 (FUN_008AA300)
   *
   * What it does:
   * Returns one RPC-loop variable pointer from a sound-parameter descriptor.
   */
  [[nodiscard]] moho::CSndVar* ReadSndParamsRpcLoopVariable(moho::CSndParams& params) noexcept
  {
    return params.mRpcLoopVariable;
  }

  /**
   * Address: 0x008AB1F0 (FUN_008AB1F0)
   *
   * What it does:
   * Packs one `(bankId, cueId)` pair into a 32-bit lookup key.
   */
  [[nodiscard]] std::uint32_t PackSndBankCueKey(const std::uint16_t bankId, const std::uint16_t cueId) noexcept
  {
    return static_cast<std::uint32_t>(cueId) | (static_cast<std::uint32_t>(bankId) << 16u);
  }

  /**
   * Address: 0x008AB440 (FUN_008AB440)
   *
   * What it does:
   * Destroys one loop cue attached to a script sound handle when present and
   * returns that cue pointer.
   */
  [[nodiscard]] moho::IXACTCue* DestroySoundLoopCueIfPresent(moho::HSound& sound)
  {
    moho::IXACTCue* const cue = ReadSoundLoopCue(sound);
    if (cue != nullptr) {
      cue->Destroy();
    }
    return cue;
  }

  /**
   * Address: 0x008AE440 (FUN_008AE440)
   *
   * What it does:
   * Clears the process-global user-sound-manager singleton storage and
   * returns the address of that singleton slot.
   */
  [[maybe_unused]] [[nodiscard]] moho::CUserSoundManager** ResetUserSoundManagerSingletonStorageLane() noexcept
  {
    gUserSoundManager = nullptr;
    return &gUserSoundManager;
  }

  /**
   * Address: 0x008AB400 (FUN_008AB400, IXACTCUE::GetState)
   *
   * What it does:
   * Queries the loop cue state for one script sound handle and returns true
   * when cue state does not carry the stopped bit; null cues are treated as
   * prepared.
   */
  [[nodiscard]] bool SoundHandleCueIsPrepared(moho::HSound* const sound)
  {
    std::int32_t cueState = 0;
    moho::IXACTCue* const cue = (sound != nullptr) ? ReadSoundLoopCue(*sound) : nullptr;
    if (cue == nullptr) {
      return true;
    }

    if (cue->GetState(&cueState) >= 0) {
      return (cueState & kCueStateStoppedBit) == 0;
    }

    gpg::Warnf(kCueStateQueryFailedWarning);
    return false;
  }

  void EnsureSoundCounterStat(moho::StatItem*& slot, const char* statPath);

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return set;
    }

    return moho::SCR_FindLuaInitFormSet("User");
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }



  // The record's three tracked-entity lanes *are* the set object; keep the
  // aliasing view pinned to them so a layout change fails loudly here.




  struct SelfLinkedDwordNode12
  {
    SelfLinkedDwordNode12* mNext; // +0x00
    SelfLinkedDwordNode12* mPrev; // +0x04
    std::uint32_t mLane08;        // +0x08
  };
  static_assert(sizeof(SelfLinkedDwordNode12) == 0x0C, "SelfLinkedDwordNode12 size must be 0x0C");

  /**
   * Address: 0x008AF3A0 (FUN_008AF3A0, sub_8AF3A0)
   *
   * What it does:
   * Allocates one 12-byte intrusive-list sentinel lane and self-links the
   * first two pointer lanes.
   */
  [[maybe_unused]] [[nodiscard]] SelfLinkedDwordNode12* CreateSelfLinkedDwordNode12()
  {
    auto* const node = static_cast<SelfLinkedDwordNode12*>(::operator new(sizeof(SelfLinkedDwordNode12)));
    if (node != nullptr) {
      node->mNext = node;
      node->mPrev = node;
    }
    return node;
  }

  [[nodiscard]] moho::SoundHandleRecord*& OwnerLoopHeadRef(moho::HSndEntityLoop& ownerHandle) noexcept
  {
    return *reinterpret_cast<moho::SoundHandleRecord**>(&ownerHandle.mListLinkHead);
  }

  void UnlinkRecordFromOwnerChain(moho::SoundHandleRecord* const record)
  {
    if (record == nullptr || record->mOwnerHandle == nullptr) {
      if (record != nullptr) {
        record->mOwnerNextInChain = nullptr;
      }
      return;
    }

    moho::HSndEntityLoop& ownerHandle = *record->mOwnerHandle;
    moho::SoundHandleRecord** ownerSlot = &OwnerLoopHeadRef(ownerHandle);
    while (*ownerSlot != record) {
      if (*ownerSlot == nullptr) {
        break;
      }
      ownerSlot = &(*ownerSlot)->mOwnerNextInChain;
    }
    if (*ownerSlot == record) {
      *ownerSlot = record->mOwnerNextInChain;
    }
    record->mOwnerHandle = nullptr;
    record->mOwnerNextInChain = nullptr;
  }

  struct UserSessionEntityMapNodeView
  {
    UserSessionEntityMapNodeView* left;   // +0x00
    UserSessionEntityMapNodeView* parent; // +0x04
    UserSessionEntityMapNodeView* right;  // +0x08
    std::int32_t key;                     // +0x0C
    moho::UserEntity* value;              // +0x10
    std::uint8_t color;                   // +0x14
    std::uint8_t isNil;                   // +0x15
    std::uint8_t pad_16_17[0x02];
  };
  static_assert(
    offsetof(UserSessionEntityMapNodeView, key) == 0x0C, "UserSessionEntityMapNodeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(UserSessionEntityMapNodeView, value) == 0x10,
    "UserSessionEntityMapNodeView::value offset must be 0x10"
  );
  static_assert(
    offsetof(UserSessionEntityMapNodeView, isNil) == 0x15,
    "UserSessionEntityMapNodeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(UserSessionEntityMapNodeView) == 0x18, "UserSessionEntityMapNodeView size must be 0x18");

  struct UserSessionEntityMapView
  {
    void* allocatorProxy;                // +0x00
    UserSessionEntityMapNodeView* head;  // +0x04
    std::uint32_t size;                  // +0x08
  };
  static_assert(
    offsetof(UserSessionEntityMapView, head) == 0x04, "UserSessionEntityMapView::head offset must be 0x04"
  );
  static_assert(
    offsetof(UserSessionEntityMapView, size) == 0x08, "UserSessionEntityMapView::size offset must be 0x08"
  );
  static_assert(sizeof(UserSessionEntityMapView) == 0x0C, "UserSessionEntityMapView size must be 0x0C");
  static_assert(offsetof(moho::CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");

  /**
   * Address: 0x008AA340 (FUN_008AA340)
   *
   * What it does:
   * Initializes one loop-handle record and creates an empty tracked-entity
   * set sentinel for that slot.
   */
  void InitializeSoundHandleRecordRuntime(moho::SoundHandleRecord* const record)
  {
    if (record == nullptr) {
      return;
    }

    record->mOwnerHandle = nullptr;
    record->mOwnerNextInChain = nullptr;
    record->mCue = nullptr;
    record->mParams = nullptr;
    record->mAngleVariableIndex = 0xFFFFu;
    record->mReserved12 = 0u;
    record->mLoopIndex = -1;

    // The record lives in raw pooled storage, so its set is constructed here
    // rather than by a member initialiser -- the shipped body buys the header
    // sentinel at exactly this point.
    new (&record->mTrackedEntities) moho::TrackedEntitySet();

    record->mPlayingSeconds = 0.0f;
  }

  /**
   * Address: 0x008AE5D0 (FUN_008AE5D0)
   *
   * What it does:
   * Inserts one entity id into a loop-handle tracked-entity tree and returns
   * whether this was a new key.
   */


  /**
   * Address: 0x008AA3B0 (FUN_008AA3B0)
   *
   * What it does:
   * Binds cue/owner lanes for one active sound-handle slot, inserts the
   * tracked entity id into that slot tree, and increments active-loop stats.
   */
  void BindSoundHandleRecordRuntime(
    moho::SoundHandleRecord* const record,
    moho::IXACTCue* const cue,
    const std::int32_t loopIndex,
    moho::HSndEntityLoop* const ownerHandle,
    const std::int32_t entityId
  )
  {
    if (record == nullptr) {
      return;
    }

    record->mLoopIndex = loopIndex;
    (void)record->mTrackedEntities.insert(entityId);
    record->mCue = cue;
    record->mAngleVariableIndex = cue != nullptr ? cue->GetVariableIndex(kAngleVariableName) : 0xFFFFu;

    if (record->mOwnerHandle != ownerHandle) {
      UnlinkRecordFromOwnerChain(record);
      record->mOwnerHandle = ownerHandle;
      if (ownerHandle != nullptr) {
        moho::SoundHandleRecord*& ownerHead = OwnerLoopHeadRef(*ownerHandle);
        record->mOwnerNextInChain = ownerHead;
        ownerHead = record;
      } else {
        record->mOwnerNextInChain = nullptr;
      }
    }

    if (ownerHandle != nullptr) {
      record->mParams = ownerHandle->mParams;
      ownerHandle->mLoopIndex = loopIndex;
    } else {
      record->mParams = nullptr;
    }

    EnsureSoundCounterStat(gEngineStatSoundActiveEntityLoops, "Sound_ActiveEntityLoops");
    if (gEngineStatSoundActiveEntityLoops != nullptr) {
      (void)::InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&gEngineStatSoundActiveEntityLoops->mPrimaryValueBits),
        1L
      );
    }
  }

  /**
   * Address: 0x008AECF0 (FUN_008AECF0, per-element SoundHandleRecord
   * copy-with-splice from the mSoundHandles growth path)
   *
   * What it does:
   * The binary spliced each copied record into its owner's chain head
   * inline while deep-copying SoundHandleRecord during storage growth
   * (called from FUN_008AEA40 / EnsureSoundHandleStorage). This helper
   * reproduces the same final chain state in one aggregate pass after
   * Resize(): clear every owner's chain head, then re-thread every
   * record whose mOwnerHandle is non-null onto that head.
   */
  void RebuildSoundHandleOwnerChains(moho::CUserSoundManager* const manager)
  {
    if (manager == nullptr) {
      return;
    }

    const std::size_t handleCount = manager->mSoundHandles.Size();

    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      moho::SoundHandleRecord& record = manager->mSoundHandles.start_[handleIndex];
      if (record.mOwnerHandle != nullptr) {
        OwnerLoopHeadRef(*record.mOwnerHandle) = nullptr;
      }
    }

    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      moho::SoundHandleRecord& record = manager->mSoundHandles.start_[handleIndex];
      record.mOwnerNextInChain = nullptr;
      if (record.mOwnerHandle != nullptr) {
        moho::SoundHandleRecord*& ownerHead = OwnerLoopHeadRef(*record.mOwnerHandle);
        record.mOwnerNextInChain = ownerHead;
        ownerHead = &record;
      }
    }
  }

  // Forward declaration: `RefreshTrackedEntitySetAfterRelocation` is defined
  // further below (next to `ReleaseSoundHandleRecordRuntime`, its sibling
  // tree-lifecycle helper), but `EnsureSoundHandleStorage` calls it inside
  // its grow-relocation loop, so the compiler needs to see the declaration
  // first. Both live in the same anonymous namespace.
  void RefreshTrackedEntitySetAfterRelocation(moho::SoundHandleRecord* record);

  /**
   * Address: 0x008AEA40 (FUN_008AEA40)
   *
   * What it does:
   * Ensures sound-handle storage has at least `requiredCount` slots, creating
   * new runtime-initialized records and rebuilding owner chains after moves.
   *
   * The real function is shaped like `gpg::fastvector_n<SoundHandleRecord,
   * 256>::resize(requiredCount, prototype)` inlined into its one call site
   * (grow-if-needed via `FUN_008AF760`, then construct every newly appended
   * slot) -- see the Address: 0x008AF760 citation on
   * `gpg::core::FastVectorN<T,N>::GrowInsert` (FastVector.h) for the grow
   * lane this delegates to via `.Resize()`. When that grow lane actually
   * reallocates, every pre-existing record needs
   * `RefreshTrackedEntitySetAfterRelocation` (below) to match the binary's
   * FUN_008AB160/FUN_008AEE40 per-relocated-record tree release-and-refresh;
   * when growth stays within existing capacity (the common case), the binary
   * never touches those records' trees at all, so the loop below is
   * skipped entirely.
   */
  void EnsureSoundHandleStorage(moho::CUserSoundManager* const manager, const std::uint32_t requiredCount)
  {
    if (manager == nullptr) {
      return;
    }

    const std::uint32_t currentCount = static_cast<std::uint32_t>(manager->mSoundHandles.Size());
    if (requiredCount <= currentCount) {
      return;
    }

    const bool willReallocate = requiredCount > static_cast<std::uint32_t>(manager->mSoundHandles.Capacity());

    manager->mSoundHandles.Resize(requiredCount, moho::SoundHandleRecord{});

    if (willReallocate) {
      for (std::uint32_t index = 0; index < currentCount; ++index) {
        RefreshTrackedEntitySetAfterRelocation(&manager->mSoundHandles.start_[index]);
      }
    }

    for (std::uint32_t index = currentCount; index < requiredCount; ++index) {
      InitializeSoundHandleRecordRuntime(&manager->mSoundHandles.start_[index]);
    }
    RebuildSoundHandleOwnerChains(manager);
  }

  /**
   * Address: 0x008AA7C0 (FUN_008AA7C0)
   *
   * What it does:
   * Returns one reusable loop-handle id from the free-id bitset, or allocates
   * the next monotonic id when the free-id set is empty.
   */
  [[nodiscard]] std::uint32_t AcquireSoundHandleIndex(moho::SoundHandleIdPool* const idPool)
  {
    if (idPool == nullptr) {
      return 0u;
    }

    if (idPool->mFreeIds.Count() == 0u) {
      const std::uint32_t next = idPool->mNextId;
      idPool->mNextId = next + 1u;
      return next;
    }

    const std::uint32_t next = idPool->mFreeIds.GetNext(0xFFFFFFFFu);
    (void)idPool->mFreeIds.Remove(next);
    return next;
  }

  // Forward declaration: `ReleaseSoundHandleRecordRuntime` is defined just
  // below `ClearSoundHandleVector` for source ordering / readability, but
  // `ClearSoundHandleVector` calls it inside its loop, so the compiler needs
  // to see the declaration first. Both functions live in the same anonymous
  // namespace and call no external code.
  void ReleaseSoundHandleRecordRuntime(moho::SoundHandleRecord* record);

  /**
   * Address: 0x008AF710 (FUN_008AF710)
   *
   * What it does:
   * Destroys every live `SoundHandleRecord` in one
   * `gpg::fastvector_n<SoundHandleRecord, 256>` storage lane via
   * `ReleaseSoundHandleRecordRuntime` (0x008AB160) and then returns the
   * vector to its inline-buffer state: when the current `begin` does not
   * match the inline-buffer anchor the heap storage is released via
   * `operator delete[]` and `begin/end/capacity` rebind back to the
   * inline buffer; when it already points at the inline buffer only the
   * `end` lane is clamped to `begin`. Binary stride between records is
   * `sizeof(SoundHandleRecord)=0x28`.
   */
  void ClearSoundHandleVector(gpg::fastvector_n<moho::SoundHandleRecord, 256>& soundHandles) noexcept
  {
    const std::size_t liveCount = soundHandles.Size();
    for (std::size_t recordIndex = 0u; recordIndex < liveCount; ++recordIndex) {
      ReleaseSoundHandleRecordRuntime(&soundHandles.start_[recordIndex]);
    }
    soundHandles.ResetStorageToInline();
  }

  /**
   * Address: 0x008AB160 (FUN_008AB160)
   *
   * What it does:
   * Releases one loop-handle record runtime tree storage and unlinks the
   * record from its owner-chain slot.
   */
  void ReleaseSoundHandleRecordRuntime(moho::SoundHandleRecord* const record)
  {
    if (record == nullptr) {
      return;
    }

    record->mTrackedEntities.~set();

    UnlinkRecordFromOwnerChain(record);
  }

  /**
   * Address: 0x008AB160 (FUN_008AB160, the per-relocated-record release call
   * `FUN_008AF760` makes on each pre-existing record immediately after
   * copying it into freshly grown `mSoundHandles` storage -- see the
   * Address: 0x008AF760 citation on `gpg::core::FastVectorN<T,N>::GrowInsert`,
   * FastVector.h)
   * Address: 0x008AEE40 (FUN_008AEE40, reached through FUN_008AECF0's
   * per-element copy for that same relocated record -- installs a fresh
   * empty sentinel rather than carrying the old copy's tree forward; same
   * self-referencing sentinel shape `InitializeSoundHandleRecordRuntime`
   * already builds for brand-new slots)
   *
   * What it does:
   * `GrowInsert`'s plain field copy leaves a relocated record's
   * `mTrackedEntitySetHead` pointing at the SAME tree its old-storage origin
   * owned (the pointer value is copied verbatim, not the tree). The binary
   * does not carry that tree forward across a relocation: it frees the
   * (now-shared) tree exactly once and gives the relocated copy a brand-new
   * empty one. This reproduces that combined effect for one already-relocated
   * record. Deliberately narrower than `ReleaseSoundHandleRecordRuntime` --
   * it must NOT touch `mOwnerHandle`/`mOwnerNextInChain`, which the plain
   * field copy already carried over correctly and which
   * `RebuildSoundHandleOwnerChains` re-threads right after.
   *
   * Known gap: FUN_008AEE40's real body also ends with an unconditional call
   * to `FUN_008AF580`, whose own two register-passed arguments are never
   * loaded by FUN_008AEE40 immediately before that call (they are apparently
   * already live from earlier context), so its effect could not be pinned
   * down with confidence from this call site alone and is not reproduced
   * here. It runs after every field this helper cares about is already
   * correct, so it is not required for the fresh-sentinel/owner-chain
   * behavior this helper restores; it is left as a documented gap rather than
   * a guessed citation.
   */
  void RefreshTrackedEntitySetAfterRelocation(moho::SoundHandleRecord* const record)
  {
    if (record == nullptr) {
      return;
    }

    record->mTrackedEntities.~set();
    new (&record->mTrackedEntities) moho::TrackedEntitySet();
  }

  moho::HSound* LoopOwnerFromNode(LoopNode* node)
  {
    return LoopList::owner_from_member_node<moho::HSound, &moho::HSound::mSimLoopLink>(node);
  }

  bool IsSndVarReady(const moho::CSndVar& value)
  {
    if (value.mResolved != 0u) {
      return ReadSndVarState(value) != 0xFFFFu;
    }
    return value.DoResolve();
  }

  // TEMPORARY PROBE [SNDDIAG] (do not commit) -- reports which memory region a
  // pointer lands in, without dereferencing it. `MEM_COMMIT` means the bytes
  // are really there (so a bad value was written into them); anything else
  // means the memory was handed back, which is a lifetime defect instead.
  const char* SndDiagRegionState(const void* const address)
  {
    if (address == nullptr) {
      return "null";
    }

    MEMORY_BASIC_INFORMATION region{};
    if (::VirtualQuery(address, &region, sizeof(region)) != sizeof(region)) {
      return "unqueryable";
    }
    switch (region.State) {
      case MEM_COMMIT:
        return (region.Protect == 0u || (region.Protect & PAGE_NOACCESS) != 0u) ? "commit-noaccess" : "commit";
      case MEM_RESERVE:
        return "reserve";
      case MEM_FREE:
        return "free";
      default:
        return "unknown";
    }
  }

  // TEMPORARY PROBE [SNDDIAG] (do not commit) -- decides WHICH defect we are
  // looking at, before the read that faults.
  //
  // The crash presents two ways: the assert "Reached the supposably
  // unreachable" (SndParams.cpp:387 -- `mResolvePolicy` at params+0x40 outside
  // the 0..4 the switch at 0x004E0892 covers), and an access violation inside
  // `weak_ptr<AudioEngine>::lock()` reading the control block stored at
  // params+0x4C. From the call stack those are one bug, but they have three
  // possible causes and each wants a completely different search:
  //
  //   reg=0                   the pointer is not a live descriptor at all, so
  //                           the defect is upstream of the audio code: either
  //                           a dangling `UserEntity` decoded out of the camera
  //                           frustum lane, or a garbage
  //                           `HSndEntityLoop::mParams`.
  //   reg=1 pi!=commit        the descriptor is real, but the AudioEngine
  //                           control block has been returned to the OS. The
  //                           weak count was therefore never held -- i.e. a
  //                           `weak_ptr` got byte-copied somewhere instead of
  //                           copy-constructed.
  //   reg=1 pi==commit        the descriptor is real and its control block is
  //                           still mapped, so the bytes at +0x40/+0x4C were
  //                           overwritten in place: a stray write.
  //
  // The verdict is delivered through `HandleAssertFailure` rather than
  // `gpg::Warnf` for a practical reason: the engine's assert dialog shows only
  // the last 100 log lines, and the navigation/steering/motion probes emit
  // several hundred lines per second, so a warning logged here is guaranteed to
  // have scrolled away before anyone can read it. Putting the verdict in the
  // dialog headline is the one channel that cannot be lost.
  //
  // Returns true when the descriptor is safe to dereference.
  bool SndDiagParamsLooksLive(
    const char* const arm, const moho::UserEntity* const entity, const moho::CSndParams* const params
  )
  {
    if (params == nullptr) {
      return false;
    }

    const char* const paramsRegion = SndDiagRegionState(params);
    const bool registered = moho::SndDiagIsRegisteredParams(params);
    if (!registered || std::strcmp(paramsRegion, "commit") != 0) {
      char verdict[512] = {};
      std::snprintf(
        verdict,
        sizeof(verdict),
        "[SNDDIAG] WILD PARAMS POINTER arm=%s entity=%p entityRegion=%.16s params=%p paramsRegion=%.16s "
        "registered=%d -- the descriptor was never a live CSndParams, so the defect is upstream: the entity "
        "or its HSndEntityLoop is dangling.",
        arm,
        static_cast<const void*>(entity),
        SndDiagRegionState(entity),
        static_cast<const void*>(params),
        paramsRegion,
        registered ? 1 : 0
      );
      gpg::HandleAssertFailure(verdict, __LINE__, __FILE__);
      return false;
    }

    // Raw {px_, pi_} of the weak_ptr at +0x48. boost::weak_ptr does not expose
    // pi_, and the whole question is whether it is a real control block, so
    // read the lane rather than trusting the type.
    std::uint32_t engineLane[2] = {0u, 0u};
    std::memcpy(engineLane, &params->mEngine, sizeof(engineLane));

    const std::uint32_t policy = params->mResolvePolicy;
    const std::uint32_t control = engineLane[1];
    const char* const controlRegion = SndDiagRegionState(reinterpret_cast<const void*>(control));
    const bool controlUsable = control == 0u || std::strcmp(controlRegion, "commit") == 0;
    if (policy <= 4u && controlUsable) {
      return true;
    }

    char verdict[512] = {};
    std::snprintf(
      verdict,
      sizeof(verdict),
      "[SNDDIAG] %s arm=%s entity=%p entityId=%d params=%p bank=%u cue=%u policy=%u px=%08X pi=%08X "
      "piRegion=%.16s -- descriptor is registered and mapped, so %s",
      controlUsable ? "TAIL OVERWRITTEN" : "ENGINE CONTROL BLOCK FREED",
      arm,
      static_cast<const void*>(entity),
      entity != nullptr ? static_cast<int>(entity->mParams.mEntityId) : -1,
      static_cast<const void*>(params),
      static_cast<unsigned>(params->mBankId),
      static_cast<unsigned>(params->mCueId),
      policy,
      engineLane[0],
      control,
      controlRegion,
      controlUsable ? "a stray write hit params+0x40/+0x4C in place."
                    : "the AudioEngine control block was released while this weak_ptr still referenced it."
    );
    gpg::HandleAssertFailure(verdict, __LINE__, __FILE__);
    return false;
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

  /**
   * Address: 0x008AEC20 (FUN_008AEC20, sub_8AEC20)
   *
   * What it does:
   * Rebinds one listener-army intrusive hook to a new owner anchor and keeps
   * the single-linked owner chain consistent across unlink/relink transitions.
   */
  void RelinkArmyHook(ListenerArmyHook& hook, moho::UserArmy* army)
  {
    auto* const newOwnerAnchor = army == nullptr
      ? nullptr
      : reinterpret_cast<std::uintptr_t*>(
          reinterpret_cast<std::uintptr_t>(army) + offsetof(moho::UserArmy, mWeakRefs)
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

  [[nodiscard]] const UserSessionEntityMapView&
  GetUserSessionEntityMapView(const moho::CWldSession* const session) noexcept
  {
    return *reinterpret_cast<const UserSessionEntityMapView*>(
      reinterpret_cast<const std::uint8_t*>(session) + offsetof(moho::CWldSession, mUnknownOwner44)
    );
  }

  [[nodiscard]] const UserSessionEntityMapNodeView*
  FindUserSessionEntityNode(const UserSessionEntityMapView& map, const std::int32_t entityId) noexcept
  {
    const UserSessionEntityMapNodeView* const head = map.head;
    if (head == nullptr) {
      return nullptr;
    }

    const UserSessionEntityMapNodeView* result = head;
    const UserSessionEntityMapNodeView* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      if (node->key >= entityId) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    if (result == head || entityId < result->key) {
      return head;
    }
    return result;
  }

  [[nodiscard]] moho::UserEntity*
  FindUserSessionEntityById(moho::CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    const UserSessionEntityMapView& entityMap = GetUserSessionEntityMapView(session);
    const UserSessionEntityMapNodeView* const node = FindUserSessionEntityNode(entityMap, entityId);
    if (node == nullptr || node == entityMap.head) {
      return nullptr;
    }
    return node->value;
  }

  /**
   * Address: 0x008AA4E0 (FUN_008AA4E0)
   *
   * What it does:
   * Resolves one representative entity from the loop's tracked-entity set,
   * updates cue 3D emitter placement from interpolated entity transform, and
   * writes optional angle variable when configured.
   */
  void UpdateEntityLoopSpatialization(
    moho::SoundHandleRecord* const record, moho::AudioEngine* const engine, const float interpolationAlpha
  )
  {
    if (record == nullptr || engine == nullptr || record->mTrackedEntities.empty()) {
      return;
    }

    // The first tracked entity spatialises the whole loop.
    const std::int32_t entityId = *record->mTrackedEntities.begin();

    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    moho::UserEntity* const entity = FindUserSessionEntityById(session, entityId);
    if (entity == nullptr) {
      return;
    }

    (void)entity->GetInterpolatedTransform(0.0f);
    const moho::VTransform transform = entity->GetInterpolatedTransform(interpolationAlpha);
    const Wm3::Vec3f emitterPosition{transform.pos_.x, transform.pos_.y, transform.pos_.z};
    moho::AudioEngine::Calculate3D(&emitterPosition, engine, record->mCue);

    if (record->mAngleVariableIndex == 0xFFFFu || record->mCue == nullptr) {
      return;
    }

    const moho::VTransform listenerTransform = engine->GetListenerTransform();
    const float angleDegrees = ComputeCueAngleDegrees(emitterPosition, listenerTransform.pos_);
    (void)record->mCue->SetVariable(record->mAngleVariableIndex, angleDegrees);
  }

  /**
   * Layout of the 12-byte intrusive tree-node the original MSVC8-era
   * `msvc8::set<IXACTCue*>` allocates for each insertion. Only the three
   * leading link pointers are observable in the binary's initialization
   * routine (`FUN_008AF8D0`); the comparison key is stored through the
   * `leftOrValue` lane because the set is used as a FIFO destroy queue and
   * the base allocator emits exactly three-pointer writes per node.
   */
  struct PendingDestroyCueNodeLinks
  {
    void* leftOrValue; // +0x00
    void* parent;      // +0x04
    void* right;       // +0x08
  };
  static_assert(sizeof(PendingDestroyCueNodeLinks) == 0xC, "PendingDestroyCueNodeLinks size must be 0x0C");

  /**
   * Address: 0x008AF8D0 (FUN_008AF8D0)
   *
   * IDA signature:
   * int *__stdcall sub_8AF8D0(int a1, int a2, int *a3);
   *
   * What it does:
   * Writes the three leading link pointers into an already-allocated
   * 12-byte pending-destroy cue tree-node: `{leftOrValue=a1, parent=a2,
   * right=*a3}`. The three branchless null-pointer guards the decompiler
   * synthesises (checking `result`, `result+4`, `result+8` separately
   * against the `-4`/`-8` aliases of nullptr) collapse to a single
   * non-null check here, because the binary's allocator
   * (`FUN_008AFE10`, `operator new(12)`) either returns a valid 12-byte
   * block or throws `std::bad_alloc`, so `result`, `result+4`, and
   * `result+8` can never be the `-4`/`-8` sentinel values. The node is
   * later threaded into the pending-destroy set by the caller's insertion
   * path (see `Moho::CUserSoundManager::UpdateSoundRequests`).
   */
  PendingDestroyCueNodeLinks* StorePendingDestroyCueNodeLinks(
    PendingDestroyCueNodeLinks* const node,
    void* const leftOrValue,
    void* const parent,
    void* const right
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    node->leftOrValue = leftOrValue;
    node->parent = parent;
    node->right = right;
    return node;
  }

  /**
   * Inserts one cue pointer into the pending-destroy set using the same
   * node-layout contract the release binary records via
   * `StorePendingDestroyCueNodeLinks`. The msvc8::set rewrite owns the
   * allocation; we bind the initialized node-links layout alongside it so
   * the insertion retains an explicit invocation of the recovered helper
   * name rather than dropping it through opaque STL internals.
   */
  void EnqueuePendingDestroyCue(
    msvc8::set<moho::IXACTCue*>& pendingCues, moho::IXACTCue* const cue
  )
  {
    // Build the node-link triplet FUN_008AF8D0 would have written: the
    // left/parent lanes both reference the cue key (the set keys by the
    // pointer value itself), and the `right` lane starts empty just like
    // the binary stages before `msvc8::set::insert` links the node.
    PendingDestroyCueNodeLinks stagedLinks{};
    (void)StorePendingDestroyCueNodeLinks(&stagedLinks, cue, cue, nullptr);

    pendingCues.insert(cue);
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
   * Address: 0x008AA7A0 (FUN_008AA7A0)
   *
   * What it does:
   * Initializes the free-id bitset runtime lanes and resets next-id to zero.
   */
  SoundHandleIdPool::SoundHandleIdPool()
    : mFreeIds()
    , mNextId(0u)
  {
  }

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
    mSoundHandles.Resize(0x100u, SoundHandleRecord{});
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      InitializeSoundHandleRecordRuntime(&mSoundHandles.start_[handleIndex]);
    }
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
    mActiveLoops.ListUnlink();
    UnlinkArmyHook(mListenerArmyHook);

    mPendingDestroyCues.clear();
    ClearSoundHandleVector(mSoundHandles);
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
   * Address: 0x008AE460 (FUN_008AE460, user-sound singleton getter lane)
   *
   * What it does:
   * Returns the process-global user-sound-manager singleton pointer without
   * creating a replacement instance.
   */
  [[maybe_unused]] [[nodiscard]] CUserSoundManager* USER_GetSoundManagerSingletonRaw() noexcept
  {
    return gUserSoundManager;
  }

  /**
   * Address: 0x008AE470 (FUN_008AE470, user-sound singleton getter lane)
   *
   * What it does:
   * Alias entry that returns the same process-global user-sound-manager
   * singleton pointer.
   */
  [[maybe_unused]] [[nodiscard]] CUserSoundManager* USER_GetSoundManagerSingletonRawAliasA() noexcept
  {
    return USER_GetSoundManagerSingletonRaw();
  }

  /**
   * Address: 0x008AED80 (FUN_008AED80, user-sound singleton getter lane)
   *
   * What it does:
   * Alias entry that returns the same process-global user-sound-manager
   * singleton pointer.
   */
  [[maybe_unused]] [[nodiscard]] CUserSoundManager* USER_GetSoundManagerSingletonRawAliasB() noexcept
  {
    return USER_GetSoundManagerSingletonRaw();
  }

  /**
   * Address: 0x008AA470 (FUN_008AA470, Moho::SND_StopEntityLoop)
   *
   * What it does:
   * Stops one active entity-loop cue when it is not currently in the playing
   * state, with optional debug spew.
   */
  void SND_StopEntityLoop(SoundHandleRecord* const record)
  {
    if (record == nullptr || record->mCue == nullptr) {
      return;
    }

    std::int32_t cueState = 0;
    record->mCue->GetState(&cueState);
    if (cueState == kCueStatePlaying) {
      return;
    }

    if (snd_SpewSound) {
      gpg::Debugf("SND: StopEntityLoop[Cue: %s] [Bank: %s]", record->mParams->mCue.c_str(), record->mParams->mBank.c_str());
    }

    record->mCue->Stop(0);
  }

  /**
   * Address: 0x008AA650 (FUN_008AA650, Moho::SND_DestroyEntityLoop)
   *
   * What it does:
   * Destroys one entity-loop cue handle, unlinks owner-chain state, returns
   * loop index to free-id pool, clears per-record entity-set tree lanes, and
   * decrements `Sound_ActiveEntityLoops` stat.
   */
  void SND_DestroyEntityLoop(SoundHandleRecord* const record)
  {
    if (record == nullptr) {
      return;
    }

    if (snd_SpewSound && record->mParams != nullptr) {
      gpg::Debugf(
        "SND: DestroyEntityLoop    [Cue: %s] [Bank: %s] %i",
        record->mParams->mCue.c_str(),
        record->mParams->mBank.c_str(),
        snd_index
      );
    }

    if (record->mCue != nullptr) {
      (void)record->mCue->Destroy();
      record->mCue = nullptr;
    }

    if (record->mOwnerHandle != nullptr) {
      record->mOwnerHandle->mLoopIndex = -1;
      UnlinkRecordFromOwnerChain(record);
    }

    if (gUserSoundManager != nullptr && record->mLoopIndex >= 0) {
      (void)gUserSoundManager->mLoopHandleIdPool.mFreeIds.Add(static_cast<std::uint32_t>(record->mLoopIndex));
    }
    record->mLoopIndex = -1;
    record->mParams = nullptr;

    record->mTrackedEntities.clear();

    record->mAngleVariableIndex = 0xFFFFu;
    record->mReserved12 = 0u;
    record->mPlayingSeconds = 0.0f;

    if (gEngineStatSoundActiveEntityLoops == nullptr) {
      EngineStats* const engineStats = GetEngineStats();
      if (engineStats != nullptr) {
        gEngineStatSoundActiveEntityLoops = engineStats->GetIntItem("Sound_ActiveEntityLoops");
        if (gEngineStatSoundActiveEntityLoops != nullptr) {
          (void)gEngineStatSoundActiveEntityLoops->Release(0);
        }
      }
    }

    if (gEngineStatSoundActiveEntityLoops != nullptr) {
      (void)::InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&gEngineStatSoundActiveEntityLoops->mPrimaryValueBits),
        -1L
      );
    }
  }

  /**
   * Address: 0x008AA600 (FUN_008AA600)
   *
   * What it does:
   * Destroys one entity-loop record when its cue is in stopped state, or
   * updates per-record playing-seconds when the cue remains in playing state.
   */
  [[maybe_unused]] int UpdateEntityLoopPlayingSecondsOrDestroy(
    SoundHandleRecord* const record,
    AudioEngine* const voiceEngine,
    const float frameSeconds
  )
  {
    if (record == nullptr || voiceEngine == nullptr || record->mCue == nullptr) {
      return 0;
    }

    if (voiceEngine->IsStopped(record->mCue)) {
      SND_DestroyEntityLoop(record);
      return 0;
    }

    std::int32_t cueState = 0;
    const int getStateResult = record->mCue->GetState(&cueState);
    if (cueState == kCueStatePlaying) {
      record->mPlayingSeconds += frameSeconds;
    }

    return getStateResult;
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
   * Then re-filters every live entity loop: RPC loops drop individual tracked
   * entities through `EraseEntityLoopTreeNode` (and release the whole set once
   * the last one goes), ambient loops stop or destroy outright.
   */
  // TEMPORARY PROBE [SNDDIAG] (do not commit) -- defined in CSndParams.cpp,
  // which owns the registry of every live descriptor. Declared here rather
  // than in the header because the probes come back out again.
  void SndDiagScanParamsRegistry();

  void CUserSoundManager::UpdateSoundRequests(const gpg::fastvector<SAudioRequest>& requests)
  {
    // TEMPORARY PROBE [SNDDIAG] (do not commit) -- sweep every live descriptor
    // once a beat so a corrupted one is reported on the beat it goes bad,
    // rather than later when whichever entity happens to own it enters the
    // sound frustum.
    SndDiagScanParamsRegistry();

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

    // The binary keeps this camera live in a frame slot from here to the tail of
    // the function (0x008AC1F8 stores it, 0x008AC9D4 reads it back), because the
    // loop-start pass at the bottom needs it too.
    CameraImpl* worldCamera = nullptr;
    if (RCamManager* const camManager = CAM_GetManager(); camManager != nullptr) {
      worldCamera = camManager->GetCamera(kWorldCameraName);
      if (CameraImpl* const camera = worldCamera; camera != nullptr) {
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
          params = ReadSoundLoopOwnerContext(*sound);
        }

        if (sound == nullptr || params == nullptr || voiceEngine == nullptr) {
          break;
        }
        if (!ParamsHasResolvedEngine(*params)) {
          break;
        }

        IXACTCue* cue = nullptr;
        if (
          AudioEngine::Play(ReadSndParamsBankId(*params), &cue, voiceEngine, ReadSndParamsCueId(*params), 0) >= 0
          && cue != nullptr
        ) {
          (void)WriteSoundLoopCue(sound, cue);
          AudioEngine::Calculate3D(&request.position, voiceEngine, cue);
        }
        break;
      }

      case EAudioRequestType::StopLoop: {
        HSound* const sound = request.sound;
        IXACTCue* const cue = sound != nullptr ? ReadSoundLoopCue(*sound) : nullptr;
        if (cue == nullptr) {
          gpg::Warnf("SND: No cue for stop loop request.");
          break;
        }

        cue->Stop(0);
        EnqueuePendingDestroyCue(mPendingDestroyCues, cue);
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

        const std::uint32_t cueKey = PackSndBankCueKey(ReadSndParamsBankId(*params), ReadSndParamsCueId(*params));

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
        if (
          AudioEngine::Play(ReadSndParamsBankId(*params), &cue, voiceEngine, ReadSndParamsCueId(*params), 0) < 0
          || cue == nullptr
        ) {
          break;
        }

        EnqueuePendingDestroyCue(mPendingDestroyCues, cue);
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

    // Second pass over the live handle table (0x008AC670..0x008AC9CE): every
    // entity loop re-filters the entities it is tracking and drops the ones the
    // sound filter no longer accepts.
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      if (record.mLoopIndex == -1) {
        continue;
      }

      moho::TrackedEntitySet& trackedSet = record.mTrackedEntities;
      const CSndVar* const rpcLoopVariable = ReadSndParamsRpcLoopVariable(*record.mParams);

      if (rpcLoopVariable == nullptr || rpcLoopVariable->mState == 0xFFFFu) {
        // Ambient (non-RPC) loop at 0x008AC8C1: the first tracked entity alone
        // decides whether the whole loop keeps playing.
        UserEntity* const entity =
          FindUserSessionEntityById(WLD_GetActiveSession(), *trackedSet.begin());
        const CSndParams* const ambientParams = entity != nullptr ? entity->mAmbientLoop.mParams : nullptr;

        EFilterType filterResult = EFilterType::Pass;
        if (ambientParams != nullptr && record.mParams == ambientParams) {
          filterResult = FilterSound(
            record.mParams,
            static_cast<ELayer>(entity->mVariableData.mLayerMask),
            &entity->mVariableData.mCurTransform.pos_
          );
          if (filterResult == EFilterType::Pass) {
            continue;
          }
        }

        EnsureSoundCounterStat(gEngineStatSoundStopEntityLoop, "Sound_StopEntityLoop");
        if (gEngineStatSoundStopEntityLoop != nullptr) {
          (void)::InterlockedExchangeAdd(
            reinterpret_cast<volatile long*>(&gEngineStatSoundStopEntityLoop->mPrimaryValueBits),
            1L
          );
        }

        if (filterResult == EFilterType::DistanceCulled) {
          SND_DestroyEntityLoop(&record);
        } else {
          SND_StopEntityLoop(&record);
        }
        continue;
      }

      // RPC loop at 0x008AC6D4: each tracked entity is filtered on its own and
      // culled from the set individually.
      for (auto node = trackedSet.begin(); node != trackedSet.end();) {
        UserEntity* const entity = FindUserSessionEntityById(WLD_GetActiveSession(), *node);
        const HSndEntityLoop* const entityLoop = entity != nullptr ? entity->mRumbleLoopHandle : nullptr;

        const bool keepEntity =
          entityLoop != nullptr
          && record.mParams == entityLoop->mParams
          && FilterSound(
               record.mParams,
               static_cast<ELayer>(entity->mVariableData.mLayerMask),
               &entity->mVariableData.mCurTransform.pos_
             ) == EFilterType::Pass;

        if (keepEntity) {
          ++node;
          continue;
        }

        if (entity != nullptr) {
          entity->mHasInitialUpdate = 0u;
        }

        if (StopRPCEntityLoop(&record)) {
          // That was the final tracked entity: the cue is stopped and the whole
          // tracked-entity set is released in one shot (0x008AC882).
          trackedSet.clear();
          break;
        }

        node = trackedSet.erase(node);
      }
    }

    // Third pass (0x008AC9D4..0x008ACBBF): start the loops that are not playing
    // yet. Nothing else in the engine starts an entity's ambient or rumble loop,
    // so without this pass `StartEntityLoop` / `StartRPCEntityLoop` are never
    // reached and no unit is ever audible.
    //
    // The candidate set is whatever the world camera currently has in frustum
    // (`CacheCameraFrustumUnits` refreshes it a few times a second), walked as
    // weak references so an entity destroyed since the last refresh drops out on
    // its own -- the binary's `mov esi,[ecx]; sub esi,8` is
    // `WeakPtr<UserEntity>::DecodeOwnerObject`, null slot and sentinel included.
    if (worldCamera == nullptr) {
      return;
    }
    if (mCurrentCameraDistanceMetric > kEntityLoopListenerCutoff) {
      return;
    }

    const CameraFrustumUserEntityList& audibleEntities = worldCamera->GetAllSoundEntitiesInFrustum();
    for (const CameraUserEntityWeakRef* ref = audibleEntities.mStart; ref != audibleEntities.mFinish; ++ref) {
      UserEntity* const entity = WeakPtr<UserEntity>::DecodeOwnerObject(ref->mOwnerLinkSlot);
      if (entity == nullptr) {
        continue;
      }

      const auto layer = static_cast<ELayer>(entity->mVariableData.mLayerMask);
      const Wm3::Vector3f& position = entity->mVariableData.mCurTransform.pos_;

      // Ambient loop: the entity's own inline HSndEntityLoop, started once and
      // then held down by its mLoopIndex leaving -1 (0x008ACA2F..0x008ACAE4).
      CSndParams* const ambientParams = entity->mAmbientLoop.mParams;
      if (ambientParams != nullptr && SndDiagParamsLooksLive("ambient", entity, ambientParams)
          && ParamsHasResolvedEngine(*ambientParams)
          && entity->mAmbientLoop.mLoopIndex == -1) {
        if (FilterSound(ambientParams, layer, &position) == EFilterType::Pass) {
          const std::int32_t entityId = static_cast<std::int32_t>(entity->mParams.mEntityId);
          StartEntityLoop(entityId, &entity->mAmbientLoop);
        }
      }

      // Rumble loop: a shared handle, so the "already started for this entity"
      // latch lives on the entity instead (+0x144), set right after the start
      // call at 0x008ACBA6 and cleared by the cull pass above.
      HSndEntityLoop* const rumbleLoop = entity->mRumbleLoopHandle;
      CSndParams* const rumbleParams = rumbleLoop != nullptr ? rumbleLoop->mParams : nullptr;
      if (rumbleParams != nullptr && SndDiagParamsLooksLive("rumble", entity, rumbleParams)
          && ParamsHasResolvedEngine(*rumbleParams)
          && entity->mHasInitialUpdate == 0u) {
        if (FilterSound(rumbleParams, layer, &position) == EFilterType::Pass) {
          const std::int32_t entityId = static_cast<std::int32_t>(entity->mParams.mEntityId);
          StartRPCEntityLoop(entityId, rumbleLoop);
          entity->mHasInitialUpdate = 1u;
        }
      }
    }
  }

  /**
   * Address: 0x008ABC60 (FUN_008ABC60, Moho::CUserSoundManager::StopRPCEntityLoop)
   *
   * What it does:
   * Writes `(tracked_count - 1)` into the record RPC loop global variable and
   * stops the cue when this call removes the final tracked entity.
   */
  bool CUserSoundManager::StopRPCEntityLoop(SoundHandleRecord* const record)
  {
    const float trackedCountMinusOne = static_cast<float>(static_cast<std::int32_t>(record->mTrackedEntities.size()) - 1);
    SND_SetGlobalFloat(ReadSndParamsRpcLoopVariable(*record->mParams)->mState, trackedCountMinusOne);
    if (record->mTrackedEntities.size() != 1u) {
      return false;
    }

    SND_StopEntityLoop(record);
    return true;
  }

  /**
   * Address: 0x008ABCB0 (FUN_008ABCB0, Moho::CUserSoundManager::StopEntityLoop)
   *
   * What it does:
   * Routes one entity-loop stop request to destroy-or-stop behavior.
   */
  void CUserSoundManager::StopEntityLoop(SoundHandleRecord* const record, const bool destroy)
  {
    if (destroy) {
      SND_DestroyEntityLoop(record);
      return;
    }

    SND_StopEntityLoop(record);
  }

  /**
   * Address: 0x008ABE90 (FUN_008ABE90)
   *
   * What it does:
   * Starts one entity-loop cue, allocates/binds one sound-handle record, and
   * seeds initial 3D placement from the referenced entity.
   */
  void CUserSoundManager::StartEntityLoop(const std::int32_t& entityId, HSndEntityLoop* const loopHandle)
  {
    if (loopHandle == nullptr || loopHandle->mParams == nullptr) {
      return;
    }

    CSndParams* const params = loopHandle->mParams;
    AudioEngine* const voiceEngine = mVoiceEngine.get();
    if (voiceEngine == nullptr) {
      return;
    }

    IXACTCue* cue = nullptr;
    if (AudioEngine::Play(ReadSndParamsBankId(*params), &cue, voiceEngine, ReadSndParamsCueId(*params), 0) < 0) {
      EnsureSoundCounterStat(gEngineStatSoundLimitedLoop, "Sound_LimitedLoop");
      if (gEngineStatSoundLimitedLoop != nullptr) {
        (void)::InterlockedExchangeAdd(
          reinterpret_cast<volatile long*>(&gEngineStatSoundLimitedLoop->mPrimaryValueBits),
          1L
        );
      }
      return;
    }

    EnsureSoundCounterStat(gEngineStatSoundStartEntityLoop, "Sound_StartEntityLoop");
    if (gEngineStatSoundStartEntityLoop != nullptr) {
      (void)::InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&gEngineStatSoundStartEntityLoop->mPrimaryValueBits),
        1L
      );
    }

    if (snd_SpewSound) {
      gpg::Debugf("SND: Loop    [Cue: %s] [Bank: %s]", params->mCue.c_str(), params->mBank.c_str());
    }

    std::uint32_t handleIndex = AcquireSoundHandleIndex(&mLoopHandleIdPool);
    if (handleIndex >= mSoundHandles.Size()) {
      gpg::Warnf("SND: Handles exceeded MAX_SOUND_HANDLES [%i/%i]", handleIndex, 256);
      std::uint32_t expandedCount = static_cast<std::uint32_t>(mSoundHandles.Size()) + 128u;
      if (expandedCount <= handleIndex) {
        expandedCount = handleIndex + 1u;
      }
      EnsureSoundHandleStorage(this, expandedCount);
    }

    SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
    BindSoundHandleRecordRuntime(&record, cue, static_cast<std::int32_t>(handleIndex), loopHandle, entityId);
    UpdateEntityLoopSpatialization(&record, voiceEngine, 0.0f);
  }

  /**
   * Address: 0x008ABCD0 (FUN_008ABCD0)
   *
   * What it does:
   * Starts/reuses one RPC loop cue and writes tracked-entity count to the
   * RPC loop variable lane.
   */
  void CUserSoundManager::StartRPCEntityLoop(const std::int32_t& entityId, HSndEntityLoop* const loopHandle)
  {
    if (
      loopHandle == nullptr
      || loopHandle->mParams == nullptr
      || ReadSndParamsRpcLoopVariable(*loopHandle->mParams) == nullptr
    ) {
      return;
    }

    CSndParams* const params = loopHandle->mParams;
    const std::uint16_t rpcLoopVariable = ReadSndParamsRpcLoopVariable(*params)->mState;

    if (loopHandle->mLoopIndex == -1) {
      IXACTCue* cue = nullptr;
      AudioEngine* const voiceEngine = mVoiceEngine.get();
      if (
        voiceEngine == nullptr
        || AudioEngine::Play(ReadSndParamsBankId(*params), &cue, voiceEngine, ReadSndParamsCueId(*params), 0) < 0
      ) {
        return;
      }

      if (snd_SpewSound) {
        gpg::Debugf("SND: LoopRPC [Cue: %s] [Bank: %s]", params->mCue.c_str(), params->mBank.c_str());
      }

      std::uint32_t handleIndex = AcquireSoundHandleIndex(&mLoopHandleIdPool);
      if (handleIndex >= mSoundHandles.Size()) {
        gpg::Warnf("SND: Handles exceeded MAX_SOUND_HANDLES [%i/%i]", handleIndex, 256);
        std::uint32_t expandedCount = static_cast<std::uint32_t>(mSoundHandles.Size()) + 128u;
        if (expandedCount <= handleIndex) {
          expandedCount = handleIndex + 1u;
        }
        EnsureSoundHandleStorage(this, expandedCount);
      }

      SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      BindSoundHandleRecordRuntime(&record, cue, static_cast<std::int32_t>(handleIndex), loopHandle, entityId);
      SND_SetGlobalFloat(rpcLoopVariable, static_cast<float>(record.mTrackedEntities.size()));
      return;
    }

    if (loopHandle->mLoopIndex < 0 || static_cast<std::size_t>(loopHandle->mLoopIndex) >= mSoundHandles.Size()) {
      return;
    }

    SoundHandleRecord& record = mSoundHandles.start_[loopHandle->mLoopIndex];
    (void)record.mTrackedEntities.insert(entityId);
    SND_SetGlobalFloat(rpcLoopVariable, static_cast<float>(record.mTrackedEntities.size()));
  }

  /**
   * Address: 0x008ACBD0 (FUN_008ACBD0, Moho::CUserSoundManager::DumpActiveLoops)
   *
   * What it does:
   * Dumps one line per sound-handle slot, including active `bank.cue` label
   * and optional stopping-seconds suffix.
   */
  void CUserSoundManager::DumpActiveLoops()
  {
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      const SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      if (record.mLoopIndex == -1) {
        gpg::Logf("%4i: <empty>", static_cast<int>(handleIndex));
        continue;
      }

      const msvc8::string baseLine = gpg::STR_Printf(
        "%4i: %s.%s",
        static_cast<int>(handleIndex),
        record.mParams->mBank.c_str(),
        record.mParams->mCue.c_str()
      );

      if (record.mPlayingSeconds > 0.0f) {
        const msvc8::string stoppingLine = gpg::STR_Printf("%s (stopping %2.2f)", baseLine.c_str(), record.mPlayingSeconds);
        gpg::Logf(stoppingLine.c_str());
        continue;
      }

      gpg::Logf(baseLine.c_str());
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

    const AudioEngine* const voiceEngine = mVoiceEngine.get();
    const std::size_t handleCount = mSoundHandles.Size();
    for (std::size_t handleIndex = 0; handleIndex < handleCount; ++handleIndex) {
      SoundHandleRecord& record = mSoundHandles.start_[handleIndex];
      if (record.mLoopIndex == -1) {
        continue;
      }

      const CSndVar* const rpcLoopVariable = record.mParams != nullptr ? ReadSndParamsRpcLoopVariable(*record.mParams)
                                                                       : nullptr;
      if (rpcLoopVariable == nullptr || rpcLoopVariable->mState == 0xFFFFu) {
        UpdateEntityLoopSpatialization(&record, mVoiceEngine.get(), simDeltaSeconds);
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

      (void)UpdateEntityLoopPlayingSecondsOrDestroy(&record, mVoiceEngine.get(), frameSeconds);
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
    CSndParams params(bankName, cueName, nullptr, nullptr, mVoiceEngine);
    if (!ParamsHasResolvedEngine(params)) {
      return;
    }

    if (snd_SpewSound) {
      gpg::Debugf("SND: Play    [Cue: %s] [Bank: %s] %i", params.mCue.c_str(), params.mBank.c_str(), snd_index);
    }

    const std::uint16_t bankId = ReadSndParamsBankId(params);
    const std::uint16_t cueId = ReadSndParamsCueId(params);
    const int xactResult = AudioEngine::Play(bankId, nullptr, mVoiceEngine.get(), cueId, 0);
    WarnCuePlayFailure(xactResult, cueId, bankId, params.mBank);
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

    const std::uint16_t bankId = ReadSndParamsBankId(params);
    const std::uint16_t cueId = ReadSndParamsCueId(params);
    const int xactResult = AudioEngine::Play(bankId, nullptr, mVoiceEngine.get(), cueId, 0);
    WarnCuePlayFailure(xactResult, cueId, bankId, params.mBank);
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
   * Address: 0x008AAF50 (FUN_008AAF50, Moho::CUserSoundManager::EnableWorldSounds)
   *
   * What it does:
   * Writes world-sound enable lane used by `UpdateSoundRequests`.
   */
  void CUserSoundManager::EnableWorldSounds(const bool enabled)
  {
    mWorldSoundsEnabled = enabled ? 1u : 0u;
  }

  /**
   * Address: 0x008AB020 (FUN_008AB020, Moho::CUserSoundManager::PushDuck)
   *
   * What it does:
   * Adds one active ducking request and starts duck fade-in when transitioning
   * from zero active duckers.
   */
  void CUserSoundManager::PushDuck()
  {
    if (mActiveDuckingSounds == 0 && IsSndVarReady(mDuckLengthVar)) {
      ++mActiveDuckingSounds;
      mDuckElapsedSeconds = 0.0f;
      mDuckMode = 1;
      return;
    }

    ++mActiveDuckingSounds;
  }

  /**
   * Address: 0x008AB070 (FUN_008AB070, Moho::CUserSoundManager::PopDuck)
   *
   * What it does:
   * Removes one active ducking request (or all requests for immediate mode),
   * and transitions duck mode/values to stop ducking.
   */
  void CUserSoundManager::PopDuck(const bool immediate)
  {
    if (immediate) {
      mActiveDuckingSounds = 0;
      mDuckMode = 0;
      if (IsSndVarReady(mDuckVar)) {
        SND_SetGlobalFloat(mDuckVar.mState, 0.0f);
      }
      return;
    }

    if (mActiveDuckingSounds == 0) {
      return;
    }

    --mActiveDuckingSounds;
    if (mActiveDuckingSounds != 0) {
      return;
    }

    if (IsSndVarReady(mDuckLengthVar)) {
      mDuckElapsedSeconds = 0.0f;
      mDuckMode = 2;
    }
  }

  /**
   * Address: 0x008AB2B0 (FUN_008AB2B0, Moho::CUserSoundManager::ScriptPlaySound)
   *
   * What it does:
   * Plays one script-triggered cue and wraps it into one intrusive `HSound`
   * node owned by `mActiveLoops`.
   */
  HSound* CUserSoundManager::ScriptPlaySound(AudioEngine* const engine, CSndParams* const params, const bool preloadOnly)
  {
    if (params == nullptr || !ParamsHasResolvedEngine(*params)) {
      return nullptr;
    }

    IXACTCue* cue = nullptr;
    if (snd_SpewSound) {
      gpg::Debugf("SND: Play2D  [Cue: %s] [Bank: %s] %i", params->mCue.c_str(), params->mBank.c_str(), snd_index);
    }

    if (
      AudioEngine::Play(ReadSndParamsBankId(*params), &cue, engine, ReadSndParamsCueId(*params), preloadOnly ? 1 : 0)
        < 0
      || cue == nullptr
    ) {
      return nullptr;
    }

    HSound* const sound = new HSound(params);
    sound->mSimLoopLink.ListLinkBefore(reinterpret_cast<LoopNode*>(&mActiveLoops));
    (void)WriteSoundLoopCue(sound, cue);
    return sound;
  }

  /**
   * Address: 0x008AB450 (FUN_008AB450, Moho::CUserSoundManager::ScriptStopSound)
   *
   * What it does:
   * Stops one script-driven cue and destroys the sound handle immediately when
   * no deferred stop path remains.
   */
  void CUserSoundManager::ScriptStopSound(HSound* const sound, const bool immediate)
  {
    if (sound == nullptr) {
      return;
    }

    IXACTCue* const cue = ReadSoundLoopCue(*sound);
    if (cue != nullptr) {
      if (!immediate) {
        cue->Stop(0);
        return;
      }

      cue->Stop(1);
      (void)DestroySoundLoopCueIfPresent(*sound);
      const bool hadDuck = ReadSoundAffectsDuckingFlag(*sound) != 0u;
      (void)WriteSoundLoopCue(sound, nullptr);
      if (hadDuck) {
        PopDuck(false);
      }
    }

    (void)sound->Destroy(1u);
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
      if (ReadSoundLoopCue(*sound) != nullptr) {
        StopAndDestroyCue(ReadSoundLoopCue(*sound));
        (void)WriteSoundLoopCue(sound, nullptr);

        if (ReadSoundAffectsDuckingFlag(*sound) != 0u && mActiveDuckingSounds > 0) {
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
        reinterpret_cast<std::uintptr_t>(mListenerArmyHook.mOwnerAnchor) - offsetof(UserArmy, mWeakRefs)
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

  /**
   * Address: 0x008AD100 (FUN_008AD100, cfunc_PlaySound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlaySoundL`.
   */
  int cfunc_PlaySound(lua_State* const luaContext)
  {
    return cfunc_PlaySoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD120 (FUN_008AD120, func_PlaySound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlaySound`.
   */
  CScrLuaInitForm* func_PlaySound_LuaFuncDef()
  {
    static CScrLuaBinder binder(UserLuaInitSet(), "PlaySound", &cfunc_PlaySound, nullptr, "<global>", kPlaySoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x008AD180 (FUN_008AD180, cfunc_PlaySoundL)
   *
   * What it does:
   * Resolves one `CSndParams` Lua object, plays one voice-engine cue, and
   * returns an `HSound` Lua object or nil.
   */
  int cfunc_PlaySoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kPlaySoundHelpText, 1, 2, argumentCount);
    }

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 1));
    CSndParams* const params = *func_GetCObj_CSndParams(paramsObject);
    CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());

    bool preloadOnly = false;
    if (lua_gettop(rawState) >= 2) {
      preloadOnly = LuaPlus::LuaStackObject(state, 2).GetBoolean();
    }

    HSound* const sound = userSound->ScriptPlaySound(userSound->mVoiceEngine.get(), params, preloadOnly);
    if (sound != nullptr) {
      func_CreateLuaHSoundObject(state, sound);
      sound->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }

    return 1;
  }

  /**
   * Address: 0x008ACDA0 (FUN_008ACDA0, cfunc_PauseSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PauseSoundL`.
   */
  int cfunc_PauseSound(lua_State* const luaContext)
  {
    return cfunc_PauseSoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008ACDC0 (FUN_008ACDC0, func_PauseSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PauseSound(category, bPause)`.
   */
  CScrLuaInitForm* func_PauseSound_LuaFuncDef()
  {
    static CScrLuaBinder binder(UserLuaInitSet(), "PauseSound", &cfunc_PauseSound, nullptr, "<global>", kPauseSoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x008ACE20 (FUN_008ACE20, cfunc_PauseSoundL)
   *
   * What it does:
   * Resolves `(categoryString, bPause)` from Lua and forwards the pause
   * request to the user sound manager's voice-engine instance when
   * present. The FA binder names this entry point `PauseSound` but
   * actually routes through `mVoiceEngine`, not the tutorial engine.
   */
  int cfunc_PauseSoundL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPauseSoundHelpText, 2, argumentCount);
    }

    LuaPlus::LuaStackObject categoryArg(state, 1);
    const char* const categoryPtr = lua_tostring(rawState, 1);
    if (!categoryPtr) {
      LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
    }
    const msvc8::string category(categoryPtr);

    LuaPlus::LuaStackObject pausedArg(state, 2);
    const bool paused = LuaPlus::LuaStackObject::GetBoolean(&pausedArg);

    auto* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
    if (userSound != nullptr) {
      if (AudioEngine* const voiceEngine = userSound->mVoiceEngine.get(); voiceEngine != nullptr) {
        voiceEngine->SetPaused(gpg::StrArg{category.c_str()}, paused);
      }
    }

    return 0;
  }

  /**
   * Address: 0x008ACF50 (FUN_008ACF50, cfunc_PauseVoice)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PauseVoiceL`.
   */
  int cfunc_PauseVoice(lua_State* const luaContext)
  {
    return cfunc_PauseVoiceL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008ACF70 (FUN_008ACF70, func_PauseVoice_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PauseVoice(category, bPause)`.
   */
  CScrLuaInitForm* func_PauseVoice_LuaFuncDef()
  {
    static CScrLuaBinder binder(UserLuaInitSet(), "PauseVoice", &cfunc_PauseVoice, nullptr, "<global>", kPauseVoiceHelpText);
    return &binder;
  }

  /**
   * Address: 0x008ACFD0 (FUN_008ACFD0, cfunc_PauseVoiceL)
   *
   * What it does:
   * Resolves `(categoryString, bPause)` from Lua and forwards the pause
   * request to the user sound manager's tutorial-engine instance when
   * present. The FA binder names this entry point `PauseVoice` but
   * routes through `mTutorialEngine`.
   */
  int cfunc_PauseVoiceL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPauseVoiceHelpText, 2, argumentCount);
    }

    LuaPlus::LuaStackObject categoryArg(state, 1);
    const char* const categoryPtr = lua_tostring(rawState, 1);
    if (!categoryPtr) {
      LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
    }
    const msvc8::string category(categoryPtr);

    LuaPlus::LuaStackObject pausedArg(state, 2);
    const bool paused = LuaPlus::LuaStackObject::GetBoolean(&pausedArg);

    auto* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
    if (userSound != nullptr) {
      if (AudioEngine* const tutorialEngine = userSound->mTutorialEngine.get(); tutorialEngine != nullptr) {
        tutorialEngine->SetPaused(gpg::StrArg{category.c_str()}, paused);
      }
    }

    return 0;
  }

  /**
   * Address: 0x008AD280 (FUN_008AD280, cfunc_SoundIsPrepared)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_SoundIsPreparedL`.
   */
  int cfunc_SoundIsPrepared(lua_State* const luaContext)
  {
    return cfunc_SoundIsPreparedL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD2A0 (FUN_008AD2A0, func_SoundIsPrepared_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SoundIsPrepared`.
   */
  CScrLuaInitForm* func_SoundIsPrepared_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "SoundIsPrepared",
      &cfunc_SoundIsPrepared,
      nullptr,
      "<global>",
      kSoundIsPreparedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008AD300 (FUN_008AD300, cfunc_SoundIsPreparedL)
   *
   * What it does:
   * Returns whether an optional script `HSound` handle still has an active cue
   * state (`true` for nil/missing handles).
   */
  int cfunc_SoundIsPreparedL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSoundIsPreparedHelpText, 1, argumentCount);
    }

    bool isPrepared = true;
    if (lua_type(rawState, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject soundObject(LuaPlus::LuaStackObject(state, 1));
      if (HSound* const sound = SCR_FromLua_HSoundOpt(soundObject, state); sound != nullptr) {
        (void)USER_GetSound();
        isPrepared = SoundHandleCueIsPrepared(sound);
      }
    }

    lua_pushboolean(rawState, isPrepared ? 1 : 0);
    (void)lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x008AD400 (FUN_008AD400, cfunc_StartSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_StartSoundL`.
   */
  int cfunc_StartSound(lua_State* const luaContext)
  {
    return cfunc_StartSoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD420 (FUN_008AD420, func_StartSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StartSound`.
   */
  CScrLuaInitForm* func_StartSound_LuaFuncDef()
  {
    static CScrLuaBinder binder(UserLuaInitSet(), "StartSound", &cfunc_StartSound, nullptr, "<global>", kStartSoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x008AD480 (FUN_008AD480, cfunc_StartSoundL)
   *
   * What it does:
   * Resolves optional script `HSound` handle and triggers cue playback when a
   * loop cue instance exists.
   */
  int cfunc_StartSoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kStartSoundHelpText, 1, argumentCount);
    }

    if (lua_type(rawState, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject soundObject(LuaPlus::LuaStackObject(state, 1));
      if (HSound* const sound = SCR_FromLua_HSoundOpt(soundObject, state); sound != nullptr) {
        (void)USER_GetSound();
        if (ReadSoundLoopCue(*sound) != nullptr) {
          ReadSoundLoopCue(*sound)->Play();
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x008AD6D0 (FUN_008AD6D0, Moho::Con_DumpActiveLoops)
   *
   * What it does:
   * Runs one console helper that dumps active loop handles from the current
   * user sound manager when available.
   */
  void Con_DumpActiveLoops()
  {
    if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
      userSound->DumpActiveLoops();
    }
  }

  /**
   * Address: 0x008AD6F0 (FUN_008AD6F0, cfunc_SetVolume)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_SetVolumeL`.
   */
  int cfunc_SetVolume(lua_State* const luaContext)
  {
    return cfunc_SetVolumeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD710 (FUN_008AD710, func_SetVolume_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetVolume`.
   */
  CScrLuaInitForm* func_SetVolume_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(UserLuaInitSet(), "SetVolume", &cfunc_SetVolume, nullptr, "<global>", kSetVolumeHelpText);
    return &binder;
  }

  /**
   * Address: 0x008AD770 (FUN_008AD770, cfunc_SetVolumeL)
   *
   * What it does:
   * Parses `(category, volume)` and applies category volume on user audio
   * manager.
   */
  int cfunc_SetVolumeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetVolumeHelpText, 2, argumentCount);
    }

    CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
    if (userSound != nullptr) {
      LuaPlus::LuaStackObject volumeArg(state, 2);
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&volumeArg, "number");
      }
      const float volume = static_cast<float>(lua_tonumber(rawState, 2));

      LuaPlus::LuaStackObject categoryArg(state, 1);
      const char* const category = lua_tostring(rawState, 1);
      if (category == nullptr) {
        LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
      }

      userSound->SetVolume(category, volume);
    }

    return 0;
  }

  /**
   * Address: 0x008AD850 (FUN_008AD850, cfunc_GetVolume)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_GetVolumeL`.
   */
  int cfunc_GetVolume(lua_State* const luaContext)
  {
    return cfunc_GetVolumeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD870 (FUN_008AD870, func_GetVolume_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetVolume`.
   */
  CScrLuaInitForm* func_GetVolume_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(UserLuaInitSet(), "GetVolume", &cfunc_GetVolume, nullptr, "<global>", kGetVolumeHelpText);
    return &binder;
  }

  /**
   * Address: 0x008AD8D0 (FUN_008AD8D0, cfunc_GetVolumeL)
   *
   * What it does:
   * Parses one category string, queries user audio manager volume, and pushes
   * one Lua number result.
   */
  int cfunc_GetVolumeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetVolumeHelpText, 1, argumentCount);
    }

    CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
    if (userSound != nullptr) {
      LuaPlus::LuaStackObject categoryArg(state, 1);
      const char* const category = lua_tostring(rawState, 1);
      if (category == nullptr) {
        LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
      }

      lua_pushnumber(rawState, userSound->GetVolume(category));
      (void)lua_gettop(rawState);
    }

    return 1;
  }

  /**
   * Address: 0x008AD550 (FUN_008AD550, cfunc_StopSound)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_StopSoundL`.
   */
  int cfunc_StopSound(lua_State* const luaContext)
  {
    return cfunc_StopSoundL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008AD570 (FUN_008AD570, func_StopSound_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StopSound`.
   */
  CScrLuaInitForm* func_StopSound_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(UserLuaInitSet(), "StopSound", &cfunc_StopSound, nullptr, "<global>", kStopSoundHelpText);
    return &binder;
  }

  /**
   * Address: 0x008AD5D0 (FUN_008AD5D0, cfunc_StopSoundL)
   *
   * What it does:
   * Resolves optional script `HSound` handle and stops one cue immediately or
   * deferred based on the second Lua argument.
   */
  int cfunc_StopSoundL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kStopSoundHelpText, 1, 2, argumentCount);
    }

    if (lua_type(rawState, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject soundObject(LuaPlus::LuaStackObject(state, 1));
      HSound* const sound = SCR_FromLua_HSoundOpt(soundObject, state);
      if (sound != nullptr) {
        bool immediate = false;
        if (lua_gettop(rawState) > 1) {
          immediate = LuaPlus::LuaStackObject(state, 2).GetBoolean();
        }

        if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
          userSound->ScriptStopSound(sound, immediate);
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x008AD970 (FUN_008AD970, cfunc_StopAllSounds)
   *
   * What it does:
   * Validates no-arg Lua call and stops all currently active user sounds.
   */
  int cfunc_StopAllSounds(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kStopAllSoundsHelpText, 0, argumentCount);
    }

    if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
      userSound->StopAllSounds();
    }

    return 0;
  }

  /**
   * Address: 0x008AD9C0 (FUN_008AD9C0, func_StopAllSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `StopAllSounds`.
   */
  CScrLuaInitForm* func_StopAllSounds_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(UserLuaInitSet(), "StopAllSounds", &cfunc_StopAllSounds, nullptr, "<global>", kStopAllSoundsHelpText);
    return &binder;
  }

  /**
   * Address: 0x008ADA50 (FUN_008ADA50, cfunc_DisableWorldSounds)
   *
   * What it does:
   * Validates no-arg Lua call and disables world-sound playback requests.
   */
  int cfunc_DisableWorldSounds(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDisableWorldSoundsHelpText, 0, argumentCount);
    }

    if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
      userSound->EnableWorldSounds(false);
    }

    return 0;
  }

  /**
   * Address: 0x008ADAA0 (FUN_008ADAA0, func_DisableWorldSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DisableWorldSounds`.
   */
  CScrLuaInitForm* func_DisableWorldSounds_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "DisableWorldSounds",
      &cfunc_DisableWorldSounds,
      nullptr,
      "<global>",
      kDisableWorldSoundsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008ADB30 (FUN_008ADB30, cfunc_EnableWorldSounds)
   *
   * What it does:
   * Validates no-arg Lua call and enables world-sound playback requests.
   */
  int cfunc_EnableWorldSounds(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEnableWorldSoundsHelpText, 0, argumentCount);
    }

    if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
      userSound->EnableWorldSounds(true);
    }

    return 0;
  }

  /**
   * Address: 0x008ADB80 (FUN_008ADB80, func_EnableWorldSounds_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EnableWorldSounds`.
   */
  CScrLuaInitForm* func_EnableWorldSounds_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "EnableWorldSounds",
      &cfunc_EnableWorldSounds,
      nullptr,
      "<global>",
      kEnableWorldSoundsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008ADC10 (FUN_008ADC10, cfunc_PlayTutorialVO)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlayTutorialVOL`.
   */
  int cfunc_PlayTutorialVO(lua_State* const luaContext)
  {
    return cfunc_PlayTutorialVOL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008ADC30 (FUN_008ADC30, func_PlayTutorialVO_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlayTutorialVO`.
   */
  CScrLuaInitForm* func_PlayTutorialVO_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      UserLuaInitSet(),
      "PlayTutorialVO",
      &cfunc_PlayTutorialVO,
      nullptr,
      "<global>",
      kPlayTutorialVOHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008ADC90 (FUN_008ADC90, cfunc_PlayTutorialVOL)
   *
   * What it does:
   * Plays one tutorial VO cue, returning an `HSound` Lua object or nil.
   */
  int cfunc_PlayTutorialVOL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPlayTutorialVOHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 1));
    CSndParams* const params = *func_GetCObj_CSndParams(paramsObject);

    bool preloadOnly = false;
    if (lua_gettop(rawState) >= 2) {
      preloadOnly = LuaPlus::LuaStackObject(state, 2).GetBoolean();
    }

    HSound* sound = nullptr;
    if (CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound()); userSound != nullptr) {
      sound = userSound->ScriptPlaySound(userSound->mAmbientEngine.get(), params, preloadOnly);
    }

    if (sound != nullptr) {
      func_CreateLuaHSoundObject(state, sound);
      sound->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }

    return 1;
  }

  /**
   * Address: 0x008ADD80 (FUN_008ADD80, cfunc_PlayVoice)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_PlayVoiceL`.
   */
  int cfunc_PlayVoice(lua_State* const luaContext)
  {
    return cfunc_PlayVoiceL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008ADDA0 (FUN_008ADDA0, func_PlayVoice_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `PlayVoice`.
   */
  CScrLuaInitForm* func_PlayVoice_LuaFuncDef()
  {
    static CScrLuaBinder
      binder(UserLuaInitSet(), "PlayVoice", &cfunc_PlayVoice, nullptr, "<global>", kPlayVoiceHelpText);
    return &binder;
  }

  /**
   * Address: 0x008ADE00 (FUN_008ADE00, cfunc_PlayVoiceL)
   *
   * What it does:
   * Plays one voice cue, optionally flags ducking behavior, and returns an
   * `HSound` Lua object or nil.
   */
  int cfunc_PlayVoiceL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kPlayVoiceHelpText, 1, 3, argumentCount);
    }

    const LuaPlus::LuaObject paramsObject(LuaPlus::LuaStackObject(state, 1));
    CSndParams* const params = *func_GetCObj_CSndParams(paramsObject);

    bool duck = false;
    if (lua_gettop(rawState) >= 2) {
      duck = LuaPlus::LuaStackObject(state, 2).GetBoolean();
    }

    bool preloadOnly = false;
    if (lua_gettop(rawState) >= 3) {
      preloadOnly = LuaPlus::LuaStackObject(state, 3).GetBoolean();
    }

    HSound* sound = nullptr;
    CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
    if (userSound != nullptr) {
      sound = userSound->ScriptPlaySound(userSound->mTutorialEngine.get(), params, preloadOnly);
    }

    if (sound != nullptr) {
      if (duck && userSound != nullptr) {
        userSound->PushDuck();
        sound->mAffectsDucking = 1u;
      }

      func_CreateLuaHSoundObject(state, sound);
      sound->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }

    return 1;
  }
} // namespace moho

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct CUserSoundManagerLuaFuncDefBootstrap
  {
    CUserSoundManagerLuaFuncDefBootstrap()
    {
      (void)::moho::func_PlaySound_LuaFuncDef();
      (void)::moho::func_PauseSound_LuaFuncDef();
      (void)::moho::func_PauseVoice_LuaFuncDef();
      (void)::moho::func_SoundIsPrepared_LuaFuncDef();
      (void)::moho::func_StartSound_LuaFuncDef();
      (void)::moho::func_SetVolume_LuaFuncDef();
      (void)::moho::func_GetVolume_LuaFuncDef();
      (void)::moho::func_StopSound_LuaFuncDef();
      (void)::moho::func_StopAllSounds_LuaFuncDef();
      (void)::moho::func_DisableWorldSounds_LuaFuncDef();
      (void)::moho::func_EnableWorldSounds_LuaFuncDef();
      (void)::moho::func_PlayTutorialVO_LuaFuncDef();
      (void)::moho::func_PlayVoice_LuaFuncDef();
    }
  };

  const CUserSoundManagerLuaFuncDefBootstrap gCUserSoundManagerLuaFuncDefBootstrap{};
} // namespace
