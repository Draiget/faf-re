#include "SimDriver.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <exception>
#include <new>

#include "boost/function.hpp"
#include <boost/ptr_container/exception.hpp>
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/app/WxAppRuntime.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/TimeBar.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/render/CDecalTypes.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/unit/core/Unit.h"
#include "Sim.h"

using namespace moho;

namespace
{
  bool gSimInterlocked = false;
  ISTIDriver* gActiveSimDriver = nullptr;
  StatItem* gEngineStatSimSync = nullptr;

  template <class T>
  struct LegacyVectorSlot
  {
    std::uint32_t mProxyLane; // +0x00
    T* mFirst;               // +0x04
    T* mLast;                // +0x08
    T* mEnd;                 // +0x0C
  };
  static_assert(sizeof(LegacyVectorSlot<std::byte>) == 0x10, "LegacyVectorSlot size must be 0x10");
  static_assert(offsetof(LegacyVectorSlot<std::byte>, mFirst) == 0x04, "LegacyVectorSlot::mFirst offset must be 0x04");
  static_assert(offsetof(LegacyVectorSlot<std::byte>, mLast) == 0x08, "LegacyVectorSlot::mLast offset must be 0x08");
  static_assert(offsetof(LegacyVectorSlot<std::byte>, mEnd) == 0x0C, "LegacyVectorSlot::mEnd offset must be 0x0C");

  struct SyncAudioRequestQueueRuntimeView
  {
    SAudioRequest* mFirst;       // +0x00
    SAudioRequest* mLast;        // +0x04
    SAudioRequest* mEnd;         // +0x08
    SAudioRequest* mInlineFirst; // +0x0C
    alignas(SAudioRequest) std::byte mInlineStorage[sizeof(SAudioRequest) * 8u]; // +0x10

    [[nodiscard]] SAudioRequest* InlineStorageBegin() noexcept
    {
      return reinterpret_cast<SAudioRequest*>(mInlineStorage);
    }

    [[nodiscard]] SAudioRequest* InlineStorageEnd() noexcept
    {
      return reinterpret_cast<SAudioRequest*>(mInlineStorage + sizeof(mInlineStorage));
    }

    void InitializeInlineStorage() noexcept
    {
      mFirst = InlineStorageBegin();
      mLast = InlineStorageBegin();
      mEnd = InlineStorageEnd();
      mInlineFirst = InlineStorageBegin();
      *reinterpret_cast<SAudioRequest**>(mInlineStorage) = InlineStorageEnd();
    }

    void ReleaseHeapAndResetInline() noexcept
    {
      if (mFirst != mInlineFirst) {
        ::operator delete[](mFirst);
        mFirst = mInlineFirst;
        mEnd = *reinterpret_cast<SAudioRequest**>(mInlineFirst);
      }
      mLast = mFirst;
    }
  };
  static_assert(sizeof(SyncAudioRequestQueueRuntimeView) == 0xF0, "SyncAudioRequestQueueRuntimeView size must be 0xF0");
  static_assert(
    offsetof(SyncAudioRequestQueueRuntimeView, mInlineStorage) == 0x10,
    "SyncAudioRequestQueueRuntimeView::mInlineStorage offset must be 0x10"
  );

  struct SyncInlineVectorRuntimeView
  {
    void* mFirst;       // +0x00
    void* mLast;        // +0x04
    void* mEnd;         // +0x08
    void* mInlineFirst; // +0x0C
    std::byte mInlineStorage[0x10]; // +0x10

    void ReleaseHeapAndResetInline() noexcept
    {
      if (mFirst != mInlineFirst) {
        ::operator delete[](mFirst);
        mFirst = mInlineFirst;
        mEnd = *reinterpret_cast<void**>(mInlineFirst);
      }
      mLast = mFirst;
    }
  };
  static_assert(sizeof(SyncInlineVectorRuntimeView) == 0x20, "SyncInlineVectorRuntimeView size must be 0x20");
  static_assert(
    offsetof(SyncInlineVectorRuntimeView, mInlineStorage) == 0x10,
    "SyncInlineVectorRuntimeView::mInlineStorage offset must be 0x10"
  );

  struct SyncPoseUpdateRuntimeView
  {
    std::uint32_t mKindOrEntity;    // +0x00
    boost::shared_ptr<void> mPose;  // +0x04
  };
  static_assert(sizeof(SyncPoseUpdateRuntimeView) == 0x0C, "SyncPoseUpdateRuntimeView size must be 0x0C");
  static_assert(offsetof(SyncPoseUpdateRuntimeView, mPose) == 0x04, "SyncPoseUpdateRuntimeView::mPose offset must be 0x04");

  /**
   * Address: 0x0088E9F0 (FUN_0088E9F0)
   *
   * What it does:
   * Swaps the process-global active sim-driver singleton lane with the value
   * stored at `inOutDriver`.
   */
  [[maybe_unused]] CSimDriver** SwapActiveSimDriverStorageLane(CSimDriver** const inOutDriver) noexcept
  {
    CSimDriver* const previous = static_cast<CSimDriver*>(gActiveSimDriver);
    if (inOutDriver != nullptr) {
      gActiveSimDriver = static_cast<ISTIDriver*>(*inOutDriver);
      *inOutDriver = previous;
    }
    return inOutDriver;
  }

  struct LegacyGeomCameraVectorSlot
  {
    std::uint32_t mProxyLane; // +0x00
    GeomCamera3* mFirst; // +0x04
    GeomCamera3* mLast; // +0x08
    GeomCamera3* mEnd; // +0x0C
  };
  static_assert(sizeof(LegacyGeomCameraVectorSlot) == 0x10, "LegacyGeomCameraVectorSlot size must be 0x10");
  static_assert(offsetof(LegacyGeomCameraVectorSlot, mFirst) == 0x04, "LegacyGeomCameraVectorSlot::mFirst offset must be 0x04");
  static_assert(offsetof(LegacyGeomCameraVectorSlot, mLast) == 0x08, "LegacyGeomCameraVectorSlot::mLast offset must be 0x08");
  static_assert(offsetof(LegacyGeomCameraVectorSlot, mEnd) == 0x0C, "LegacyGeomCameraVectorSlot::mEnd offset must be 0x0C");

  struct LegacyStringVectorSlot
  {
    std::uint32_t mProxyLane; // +0x00
    msvc8::string* mFirst; // +0x04
    msvc8::string* mLast; // +0x08
    msvc8::string* mEnd; // +0x0C
  };
  static_assert(sizeof(LegacyStringVectorSlot) == 0x10, "LegacyStringVectorSlot size must be 0x10");
  static_assert(offsetof(LegacyStringVectorSlot, mFirst) == 0x04, "LegacyStringVectorSlot::mFirst offset must be 0x04");
  static_assert(offsetof(LegacyStringVectorSlot, mLast) == 0x08, "LegacyStringVectorSlot::mLast offset must be 0x08");
  static_assert(offsetof(LegacyStringVectorSlot, mEnd) == 0x0C, "LegacyStringVectorSlot::mEnd offset must be 0x0C");

  struct LegacySyncEntityVariableEntry
  {
    EntId mEntityId;                          // +0x00
    std::uint32_t mReserved04;                // +0x04
    SSTIEntityVariableData mVariableData;     // +0x08
  };
  static_assert(sizeof(LegacySyncEntityVariableEntry) == 0xD8, "LegacySyncEntityVariableEntry size must be 0xD8");
  static_assert(
    offsetof(LegacySyncEntityVariableEntry, mVariableData) == 0x08,
    "LegacySyncEntityVariableEntry::mVariableData offset must be 0x08"
  );

  struct LegacySyncEntityVariableVectorSlot
  {
    std::uint32_t mProxyLane;                     // +0x00
    LegacySyncEntityVariableEntry* mFirst;        // +0x04
    LegacySyncEntityVariableEntry* mLast;         // +0x08
    LegacySyncEntityVariableEntry* mEnd;          // +0x0C
  };
  static_assert(
    sizeof(LegacySyncEntityVariableVectorSlot) == 0x10,
    "LegacySyncEntityVariableVectorSlot size must be 0x10"
  );
  static_assert(
    offsetof(LegacySyncEntityVariableVectorSlot, mFirst) == 0x04,
    "LegacySyncEntityVariableVectorSlot::mFirst offset must be 0x04"
  );
  static_assert(
    offsetof(LegacySyncEntityVariableVectorSlot, mLast) == 0x08,
    "LegacySyncEntityVariableVectorSlot::mLast offset must be 0x08"
  );
  static_assert(
    offsetof(LegacySyncEntityVariableVectorSlot, mEnd) == 0x0C,
    "LegacySyncEntityVariableVectorSlot::mEnd offset must be 0x0C"
  );

  struct LegacySyncUnitVariableEntry
  {
    EntId mEntityId;                         // +0x000
    std::uint32_t mReserved04;               // +0x004
    SSTIUnitVariableData mVariableData;      // +0x008
    std::uint8_t mReservedTail[0x08]{};      // +0x230
  };
  static_assert(sizeof(LegacySyncUnitVariableEntry) == 0x238, "LegacySyncUnitVariableEntry size must be 0x238");
  static_assert(
    offsetof(LegacySyncUnitVariableEntry, mVariableData) == 0x08,
    "LegacySyncUnitVariableEntry::mVariableData offset must be 0x08"
  );

  struct SSyncDataTeardownRuntimeView
  {
    std::int32_t mCurBeat;                                                   // +0x000
    std::uint8_t mPad0004_0010[0x0C];                                        // +0x004
    gpg::Stream* mStream;                                                    // +0x010
    std::uint8_t mPad0014_0018[0x04];                                        // +0x014
    SyncAudioRequestQueueRuntimeView mAudioRequests;                         // +0x018
    LegacyVectorSlot<SSTIArmyConstantData> mNewGrids;                        // +0x108
    LegacyVectorSlot<SSTIArmyVariableData> mArmyUpdates;                     // +0x118
    LegacyVectorSlot<std::byte> mNewEntities;                                // +0x128
    LegacyVectorSlot<SCreateUnitParams> mNewUnits;                           // +0x138
    LegacyVectorSlot<LegacySyncEntityVariableEntry> mEntityUpdates;           // +0x148
    LegacyVectorSlot<LegacySyncUnitVariableEntry> mUnitUpdates;               // +0x158
    LegacyVectorSlot<EntId> mDeleteIds;                                      // +0x168
    LegacyVectorSlot<EntId> mEraseIds;                                       // +0x178
    LegacyVectorSlot<SSTICommandConstantData> mNewCommands;                  // +0x188
    LegacyVectorSlot<SSyncPublishedCommandPacket> mCommandUpdates;            // +0x198
    LegacyVectorSlot<CmdId> mPendingCommandEventRemovals;                    // +0x1A8
    LegacyVectorSlot<CmdId> mPendingReleasedCommandIds;                      // +0x1B8
    boost::shared_ptr<void> mParticleBuffer;                                 // +0x1C8
    LegacyVectorSlot<SDecalInfo> mAddDecals;                                 // +0x1D0
    LegacyVectorSlot<std::byte> mRemoveDecals;                               // +0x1E0
    LegacyVectorSlot<std::byte> mCamShakeParams;                             // +0x1F0
    LegacyVectorSlot<std::byte> mFollowCameras;                              // +0x200
    LegacyVectorSlot<std::byte> mAuxiliaryVector17;                          // +0x210
    LegacyVectorSlot<SyncPoseUpdateRuntimeView> mPoseUpdates;                // +0x220
    LegacyVectorSlot<std::byte> mPlayableRectUpdates;                        // +0x230
    LegacyVectorSlot<std::byte> mDesyncs;                                    // +0x240
    std::int32_t mPausedBy;                                                   // +0x250
    msvc8::string mSubmitArmyStats;                                          // +0x254
    bool mGameOver;                                                          // +0x270
    std::uint8_t mPad0271_0274[0x03];                                        // +0x271
    boost::shared_ptr<void> mTerrainUpdate;                                  // +0x274
    boost::shared_ptr<void> mSimResources;                                   // +0x27C
    LegacyVectorSlot<msvc8::string> mPrintField;                             // +0x284
    LegacyVectorSlot<SyncInlineVectorRuntimeView> mInlineScratchVectors;      // +0x294
    boost::shared_ptr<void> mTickDebugCanvas;                                // +0x2A4
    boost::shared_ptr<void> mBeatDebugCanvas;                                // +0x2AC
    std::uint8_t mPad02B4_02B8[0x04];                                        // +0x2B4
  };
  static_assert(sizeof(SSyncDataTeardownRuntimeView) == 0x2B8, "SSyncDataTeardownRuntimeView size must be 0x2B8");
  static_assert(offsetof(SSyncDataTeardownRuntimeView, mStream) == 0x10, "SSyncData::mStream offset must be 0x10");
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mAudioRequests) == 0x18,
    "SSyncData::mAudioRequests offset must be 0x18"
  );
  static_assert(offsetof(SSyncDataTeardownRuntimeView, mNewGrids) == 0x108, "SSyncData::mNewGrids offset must be 0x108");
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mNewUnits) == 0x138,
    "SSyncData::mNewUnits offset must be 0x138"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mEntityUpdates) == 0x148,
    "SSyncData::mEntityUpdates offset must be 0x148"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mUnitUpdates) == 0x158,
    "SSyncData::mUnitUpdates offset must be 0x158"
  );
  // The teardown view mirrors the promoted `SSyncData::mDeleteIds` (+0x168) and
  // `SSyncData::mEraseIds` (+0x178) members; `LegacyVectorSlot<EntId>` shares the
  // 0x10-byte {proxy,first,last,end} layout of `msvc8::vector<EntId>`, so the two
  // structs describe one owning layout for these lanes.
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mDeleteIds) == 0x168,
    "SSyncData::mDeleteIds offset must be 0x168"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mEraseIds) == 0x178,
    "SSyncData::mEraseIds offset must be 0x178"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mNewCommands) == 0x188,
    "SSyncData::mNewCommands offset must be 0x188"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mCommandUpdates) == 0x198,
    "SSyncData::mCommandUpdates offset must be 0x198"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mSubmitArmyStats) == 0x254,
    "SSyncData::mSubmitArmyStats offset must be 0x254"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mGameOver) == 0x270,
    "SSyncData::mGameOver offset must be 0x270"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mPrintField) == 0x284,
    "SSyncData::mPrintField offset must be 0x284"
  );
  static_assert(
    offsetof(SSyncDataTeardownRuntimeView, mBeatDebugCanvas) == 0x2AC,
    "SSyncData::mBeatDebugCanvas offset must be 0x2AC"
  );

  struct LegacyArmyConstantDataVectorSlot
  {
    std::uint32_t mProxyLane;        // +0x00
    SSTIArmyConstantData* mFirst;    // +0x04
    SSTIArmyConstantData* mLast;     // +0x08
    SSTIArmyConstantData* mEnd;      // +0x0C
  };
  static_assert(sizeof(LegacyArmyConstantDataVectorSlot) == 0x10, "LegacyArmyConstantDataVectorSlot size must be 0x10");
  static_assert(
    offsetof(LegacyArmyConstantDataVectorSlot, mFirst) == 0x04,
    "LegacyArmyConstantDataVectorSlot::mFirst offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyArmyConstantDataVectorSlot, mLast) == 0x08,
    "LegacyArmyConstantDataVectorSlot::mLast offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyArmyConstantDataVectorSlot, mEnd) == 0x0C,
    "LegacyArmyConstantDataVectorSlot::mEnd offset must be 0x0C"
  );

  struct LegacyArmyVariableDataVectorSlot
  {
    std::uint32_t mProxyLane;        // +0x00
    SSTIArmyVariableData* mFirst;    // +0x04
    SSTIArmyVariableData* mLast;     // +0x08
    SSTIArmyVariableData* mEnd;      // +0x0C
  };
  static_assert(sizeof(LegacyArmyVariableDataVectorSlot) == 0x10, "LegacyArmyVariableDataVectorSlot size must be 0x10");
  static_assert(
    offsetof(LegacyArmyVariableDataVectorSlot, mFirst) == 0x04,
    "LegacyArmyVariableDataVectorSlot::mFirst offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyArmyVariableDataVectorSlot, mLast) == 0x08,
    "LegacyArmyVariableDataVectorSlot::mLast offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyArmyVariableDataVectorSlot, mEnd) == 0x0C,
    "LegacyArmyVariableDataVectorSlot::mEnd offset must be 0x0C"
  );

  template <class T>
  void ResetLegacyVectorSlot(LegacyVectorSlot<T>& slot) noexcept
  {
    slot.mFirst = nullptr;
    slot.mLast = nullptr;
    slot.mEnd = nullptr;
  }

  template <class T>
  void ReleaseLegacyVectorStorage(LegacyVectorSlot<T>& slot) noexcept
  {
    if (slot.mFirst != nullptr) {
      ::operator delete(static_cast<void*>(slot.mFirst));
    }
    ResetLegacyVectorSlot(slot);
  }

  template <class T, class TDestroyElement>
  void DestroyLegacyVectorElementsAndRelease(LegacyVectorSlot<T>& slot, TDestroyElement destroyElement)
  {
    if (slot.mFirst != nullptr) {
      for (T* cursor = slot.mFirst; cursor != slot.mLast; ++cursor) {
        destroyElement(*cursor);
      }
      ::operator delete(static_cast<void*>(slot.mFirst));
    }
    ResetLegacyVectorSlot(slot);
  }

  template <class T>
  void DestroyLegacyVectorElementsAndRelease(LegacyVectorSlot<T>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](T& element) { element.~T(); });
  }

  void DestroyLegacyCommandConstantRange(LegacyVectorSlot<SSTICommandConstantData>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](SSTICommandConstantData& command) {
      command.unk2.tidy(true, 0u);
    });
  }

  void DestroyLegacyStringVectorSlot(LegacyVectorSlot<msvc8::string>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](msvc8::string& value) {
      value.tidy(true, 0u);
    });
  }

  void DestroyLegacySyncEntityVariableVector(LegacyVectorSlot<LegacySyncEntityVariableEntry>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](LegacySyncEntityVariableEntry& entry) {
      entry.mVariableData.~SSTIEntityVariableData();
    });
  }

  void DestroyLegacySyncUnitVariableVector(LegacyVectorSlot<LegacySyncUnitVariableEntry>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](LegacySyncUnitVariableEntry& entry) {
      entry.mVariableData.~SSTIUnitVariableData();
    });
  }

  void DestroyLegacyPoseUpdateVector(LegacyVectorSlot<SyncPoseUpdateRuntimeView>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](SyncPoseUpdateRuntimeView& update) {
      update.mPose.reset();
    });
  }

  void DestroyLegacyInlineScratchVectorRange(LegacyVectorSlot<SyncInlineVectorRuntimeView>& slot)
  {
    DestroyLegacyVectorElementsAndRelease(slot, [](SyncInlineVectorRuntimeView& scratch) {
      scratch.ReleaseHeapAndResetInline();
    });
  }

  /**
   * Address: 0x00740C00 (FUN_00740C00, ??1fastvector_struct_SSTIEntitytVariableData@gpg@@QAE@@Z)
   *
   * What it does:
   * Destroys one legacy vector lane of `(EntId, SSTIEntityVariableData)` pairs,
   * releases element storage, and clears range pointers.
   */
  [[maybe_unused]] void DestroyLegacySyncEntityVariableVectorSlot(
    LegacySyncEntityVariableVectorSlot* const slot
  )
  {
    if (slot == nullptr) {
      return;
    }

    LegacySyncEntityVariableEntry* cursor = slot->mFirst;
    if (cursor != nullptr) {
      while (cursor != slot->mLast) {
        cursor->mVariableData.~SSTIEntityVariableData();
        ++cursor;
      }
      ::operator delete(slot->mFirst);
    }

    slot->mFirst = nullptr;
    slot->mLast = nullptr;
    slot->mEnd = nullptr;
  }

  /**
   * Address: 0x00742090 (FUN_00742090, sub_742090)
   *
   * What it does:
   * Destroys one half-open range of `SDecalInfo` payloads by resetting the
   * type-string lane and tearing down both texture-name strings per element.
   */
  [[maybe_unused]] void DestroyLegacyDecalInfoRangeForSyncPayload(
    SDecalInfo* begin,
    SDecalInfo* const end
  )
  {
    while (begin != end) {
      if (begin->mType.myRes >= 0x10u) {
        ::operator delete(begin->mType.bx.ptr);
      }
      begin->mType.myRes = 15u;
      begin->mType.mySize = 0u;
      begin->mType.bx.buf[0] = '\0';

      begin->mTexName1.tidy(true, 0u);
      begin->mTexName2.tidy(true, 0u);
      ++begin;
    }
  }

  /**
   * Address: 0x0074E720 (FUN_0074E720, sub_74E720)
   *
   * What it does:
   * Compacts one `SSTIArmyConstantData` vector lane by assignment-copying the
   * half-open source tail `[sourceBegin, slot->mLast)` into `destinationBegin`,
   * destroys now-dead trailing elements, updates `mLast`, and returns
   * `destinationBegin` via the output pointer.
   */
  [[maybe_unused]] SSTIArmyConstantData** CompactLegacyArmyConstantDataVectorTail(
    LegacyArmyConstantDataVectorSlot* const slot,
    SSTIArmyConstantData** const outResult,
    SSTIArmyConstantData* const destinationBegin,
    SSTIArmyConstantData* const sourceBegin
  )
  {
    SSTIArmyConstantData* destinationResult = destinationBegin;
    if (destinationBegin != sourceBegin) {
      SSTIArmyConstantData* writeCursor = destinationBegin;
      for (SSTIArmyConstantData* sourceCursor = sourceBegin; sourceCursor != slot->mLast; ++sourceCursor, ++writeCursor) {
        *writeCursor = *sourceCursor;
      }

      for (SSTIArmyConstantData* destroyCursor = writeCursor; destroyCursor != slot->mLast; ++destroyCursor) {
        destroyCursor->~SSTIArmyConstantData();
      }

      slot->mLast = writeCursor;
    }

    *outResult = destinationResult;
    return outResult;
  }

  /**
   * Address: 0x0074EAB0 (FUN_0074EAB0, sub_74EAB0)
   *
   * What it does:
   * Compacts one `SSTIArmyVariableData` vector lane by assignment-copying the
   * half-open source tail `[sourceBegin, slot->mLast)` into `destinationBegin`,
   * destroys now-dead trailing elements, updates `mLast`, and returns
   * `destinationBegin` via the output pointer.
   */
  [[maybe_unused]] SSTIArmyVariableData** CompactLegacyArmyVariableDataVectorTail(
    LegacyArmyVariableDataVectorSlot* const slot,
    SSTIArmyVariableData** const outResult,
    SSTIArmyVariableData* const destinationBegin,
    SSTIArmyVariableData* const sourceBegin
  )
  {
    SSTIArmyVariableData* destinationResult = destinationBegin;
    if (destinationBegin != sourceBegin) {
      SSTIArmyVariableData* writeCursor = destinationBegin;
      for (SSTIArmyVariableData* sourceCursor = sourceBegin; sourceCursor != slot->mLast; ++sourceCursor, ++writeCursor) {
        *writeCursor = *sourceCursor;
      }

      for (SSTIArmyVariableData* destroyCursor = writeCursor; destroyCursor != slot->mLast; ++destroyCursor) {
        destroyCursor->~SSTIArmyVariableData();
      }

      slot->mLast = writeCursor;
    }

    *outResult = destinationResult;
    return outResult;
  }

  void DestroyLegacyStringPayloadRange(msvc8::string* begin, msvc8::string* end)
  {
    while (begin != end) {
      begin->tidy(true, 0u);
      ++begin;
    }
  }

  /**
   * Address: 0x00740700 (FUN_00740700, sub_740700)
   *
   * What it does:
   * Destroys one legacy `GeomCamera3` vector lane and releases its backing
   * heap storage, preserving the leading proxy lane.
   */
  [[maybe_unused]] void DestroyLegacyGeomCameraVectorSlot(LegacyGeomCameraVectorSlot* const slot)
  {
    if (slot == nullptr) {
      return;
    }

    GeomCamera3* cursor = slot->mFirst;
    if (cursor != nullptr) {
      while (cursor != slot->mLast) {
        cursor->~GeomCamera3();
        ++cursor;
      }
      ::operator delete(slot->mFirst);
    }

    slot->mFirst = nullptr;
    slot->mLast = nullptr;
    slot->mEnd = nullptr;
  }

  /**
   * Address: 0x0073F620 (FUN_0073F620)
   *
   * What it does:
   * Tail-forwards one legacy `GeomCamera3` vector teardown thunk lane into the
   * canonical slot destroy helper.
   */
  [[maybe_unused]] void DestroyLegacyGeomCameraVectorSlotThunk(
    LegacyGeomCameraVectorSlot* const slot
  )
  {
    DestroyLegacyGeomCameraVectorSlot(slot);
  }

  /**
   * Address: 0x00741F70 (FUN_00741F70, sub_741F70)
   *
   * What it does:
   * Destroys each legacy string-vector lane in `[begin,end)`, releases each
   * lane's element storage, and clears the three range pointers.
   */
  [[maybe_unused]] void DestroyLegacyStringVectorRange(
    LegacyStringVectorSlot* begin,
    LegacyStringVectorSlot* const end
  )
  {
    while (begin != end) {
      if (begin->mFirst != nullptr) {
        DestroyLegacyStringPayloadRange(begin->mFirst, begin->mLast);
        ::operator delete(begin->mFirst);
      }

      begin->mFirst = nullptr;
      begin->mLast = nullptr;
      begin->mEnd = nullptr;
      ++begin;
    }
  }

  boost::mutex& DriverMutexRef(SDriverMutex& lockCell)
  {
    if (lockCell.lock == nullptr) {
      lockCell.lock = new boost::mutex();
    }
    return *lockCell.lock;
  }

  bool AreGeomCameraVectorsEqual(const msvc8::vector<GeomCamera3>& lhs, const msvc8::vector<GeomCamera3>& rhs)
  {
    if (lhs.size() != rhs.size()) {
      return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i) {
      if (std::memcmp(&lhs[i], &rhs[i], sizeof(GeomCamera3)) != 0) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0055AE10 (FUN_0055AE10)
   * Maps the floating sim-rate estimate to the integer value consumed by CClientManagerImpl::SetSimRate.
   */
  int QuantizeSimRateSample(const float sample)
  {
    if (!std::isfinite(sample)) {
      return 0;
    }

    return static_cast<int>(std::lround(sample));
  }

  void AddElapsedMicrosecondsToStat(StatItem* const statItem, const std::int64_t elapsedMicroseconds)
  {
    if (statItem == nullptr) {
      return;
    }

    (void)::InterlockedExchangeAdd(
      reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits),
      static_cast<long>(elapsedMicroseconds)
    );
  }

  bool IsZeroDigest(const gpg::MD5Digest& digest)
  {
    return digest.vals[0] == 0 && digest.vals[1] == 0 && digest.vals[2] == 0 && digest.vals[3] == 0;
  }

  [[nodiscard]] boost::function<void()> BuildCallLaterCallback(
    void (*fn)(CSimDriver*),
    CSimDriver* driver
  );

  /**
   * Address: 0x00741810 (FUN_00741810, func_call_later)
   *
   * What it does:
   * Builds one deferred driver callback object and seeds it by forwarding to
   * `BuildCallLaterCallback`.
   */
  [[nodiscard]] boost::function<void()> BuildDeferredDriverCallback(
    void (*fn)(CSimDriver*),
    CSimDriver* const driver
  )
  {
    boost::function<void()> callback{};
    callback = BuildCallLaterCallback(fn, driver);
    return callback;
  }

  /**
   * Address: 0x00741D70 (FUN_00741D70, func_call_later_0)
   *
   * What it does:
   * Builds one deferred callback lane that will invoke `fn(driver)` when the
   * created `boost::thread` runs.
   */
  [[nodiscard]] boost::function<void()> BuildCallLaterCallback(
    void (*fn)(CSimDriver*),
    CSimDriver* const driver
  )
  {
    if (fn == nullptr || driver == nullptr) {
      return {};
    }

    return [fn, driver]() { fn(driver); };
  }
} // namespace

/**
 * Address: 0x00748370 (FUN_00748370, ??0SSyncData@Moho@@QAE@@Z)
 *
 * What it does:
 * Builds an empty sync publication packet. The recovered `SSyncData` runtime
 * view keeps unknown retail lanes in typed padding blocks while preserving the
 * same constructor-side zero-init behavior for the modeled fields.
 */
SSyncData::SSyncData()
  : mCurBeat(0)
  , pad_0004_0138{}
  , mNewUnits()
  , pad_0144_0148{}
  , mEntityUpdates()
  , pad_0154_0158{}
  , mUnitUpdates()
  , pad_0164_0168{}
  , mDeleteIds()
  , mEraseIds()
  , mPublishedCommandDescriptors()
  , mPublishedCommandPackets()
  , mPendingCommandEventRemovals()
  , mPendingReleasedCommandIds()
  , pad_01C8_0250{}
  , mPausedBy(-1)
  , mSubmitArmyStats()
  , mGameOver(false)
  , pad_0271_02B8{}
{
  auto& runtimeView = reinterpret_cast<SSyncDataTeardownRuntimeView&>(*this);
  runtimeView.mAudioRequests.InitializeInlineStorage();
}

/**
 * Address: 0x0073FC70 (FUN_0073FC70, ??1SSyncData@Moho@@QAE@XZ)
 *
 * IDA signature:
 * void __stdcall Moho::SSyncData::~SSyncData(Moho::SSyncData *a1);
 *
 * What it does:
 * Tears down the sync publication packet in reverse field order, releasing
 * hidden publication vectors, shared debug/resource handles, the inline audio
 * request queue, and the owned stream pointer.
 */
SSyncData::~SSyncData()
{
  auto& runtimeView = reinterpret_cast<SSyncDataTeardownRuntimeView&>(*this);

  runtimeView.mBeatDebugCanvas.reset();
  runtimeView.mTickDebugCanvas.reset();
  DestroyLegacyInlineScratchVectorRange(runtimeView.mInlineScratchVectors);
  DestroyLegacyStringVectorSlot(runtimeView.mPrintField);
  runtimeView.mSimResources.reset();
  runtimeView.mTerrainUpdate.reset();

  runtimeView.mSubmitArmyStats.tidy(true, 0u);
  ReleaseLegacyVectorStorage(runtimeView.mDesyncs);
  ReleaseLegacyVectorStorage(runtimeView.mPlayableRectUpdates);
  DestroyLegacyPoseUpdateVector(runtimeView.mPoseUpdates);
  ReleaseLegacyVectorStorage(runtimeView.mAuxiliaryVector17);
  ReleaseLegacyVectorStorage(runtimeView.mFollowCameras);
  ReleaseLegacyVectorStorage(runtimeView.mCamShakeParams);
  ReleaseLegacyVectorStorage(runtimeView.mRemoveDecals);
  if (runtimeView.mAddDecals.mFirst != nullptr) {
    DestroyLegacyDecalInfoRangeForSyncPayload(runtimeView.mAddDecals.mFirst, runtimeView.mAddDecals.mLast);
    ::operator delete(static_cast<void*>(runtimeView.mAddDecals.mFirst));
  }
  ResetLegacyVectorSlot(runtimeView.mAddDecals);
  runtimeView.mParticleBuffer.reset();

  ReleaseLegacyVectorStorage(runtimeView.mPendingReleasedCommandIds);
  ReleaseLegacyVectorStorage(runtimeView.mPendingCommandEventRemovals);
  DestroyLegacyVectorElementsAndRelease(runtimeView.mCommandUpdates);
  DestroyLegacyCommandConstantRange(runtimeView.mNewCommands);
  ReleaseLegacyVectorStorage(runtimeView.mEraseIds);
  ReleaseLegacyVectorStorage(runtimeView.mDeleteIds);
  DestroyLegacySyncUnitVariableVector(runtimeView.mUnitUpdates);
  DestroyLegacySyncEntityVariableVector(runtimeView.mEntityUpdates);
  DestroyLegacyVectorElementsAndRelease(runtimeView.mNewUnits);
  ReleaseLegacyVectorStorage(runtimeView.mNewEntities);
  DestroyLegacyVectorElementsAndRelease(runtimeView.mArmyUpdates);
  DestroyLegacyVectorElementsAndRelease(runtimeView.mNewGrids);

  runtimeView.mAudioRequests.ReleaseHeapAndResetInline();
  delete runtimeView.mStream;
  runtimeView.mStream = nullptr;
}

void SSyncData::QueuePendingCommandEventRemoval(const CmdId commandId)
{
  mPendingCommandEventRemovals.push_back(commandId);
}

/**
 * Address: 0x005C38E0 (FUN_005C38E0)
 *
 * What it does:
 * Appends one unit-create sync packet to `syncData->mNewUnits` and returns
 * the inserted element pointer.
 */
SCreateUnitParams* moho::QueueCreateUnitParams(SSyncData* const syncData, const SCreateUnitParams& params)
{
  if (!syncData) {
    return nullptr;
  }

  syncData->mNewUnits.push_back(params);
  if (syncData->mNewUnits.empty()) {
    return nullptr;
  }

  return &syncData->mNewUnits.back();
}

/**
 * Address: 0x0067A290 tail (inlined push lane of Moho::Entity::SyncInterface)
 *
 * What it does:
 * Appends one default `SEntityVariableUpdateEntry` to `syncData->mEntityUpdates`
 * (header word 0xF0000000 + default-constructed `SSTIEntityVariableData`), then
 * writes the entity id and assignment-copies the supplied variable payload into
 * the stored record. Returns the inserted element pointer. This matches the
 * binary's push-default (0x0067A384) then write-id + `operator=`
 * (0x0067A3B3..0x0067A3B5) sequence.
 */
SEntityVariableUpdateEntry* moho::QueueEntityVariableUpdate(
  SSyncData* const syncData,
  const EntId entityId,
  const SSTIEntityVariableData& variableData)
{
  if (!syncData) {
    return nullptr;
  }

  SEntityVariableUpdateEntry defaultEntry{};
  defaultEntry.mEntityId = ToRaw(EEntityIdSentinel::Invalid);
  syncData->mEntityUpdates.push_back(defaultEntry);
  if (syncData->mEntityUpdates.empty()) {
    return nullptr;
  }

  SEntityVariableUpdateEntry& stored = syncData->mEntityUpdates.back();
  stored.mEntityId = entityId;
  stored.mVariableData = variableData;
  return &stored;
}

namespace moho
{
  /**
   * One replicated unit-variable update record queued onto
   * `SSyncData::mUnitUpdates` by the `Unit` / `ReconBlip` overrides of
   * `SyncInterface`.
   *
   * Layout evidence (FUN_006AC3A0 / FUN_005BEFB0):
   * - `sub edi, 238h` / `sub esi, 238h` anchor the record stride at 0x238; the
   *   back element is `mUnitUpdates._Mylast - 142` (142 * 4 == 0x238).
   * - `mov [edi], eax` (eax = `Entity::id_`) stores the entity id at record +0x00.
   * - `lea edx, [edi+8]` hands `SSTIUnitVariableData::Assign` the payload lane at
   *   record +0x08 (a 4-byte header word precedes it).
   * - `mov dword ptr [edi+230h], 1Ch` (Unit) / `mov [esi+230h], edx`
   *   (ReconBlip, from `SPerArmyReconInfo::mReconFlags`) writes the trailing
   *   recon-flag word at record +0x230.
   * The 0x08 offset and 0x238 total both hold because `SSTIUnitVariableData` is
   * 0x228 bytes (0x08 header + 0x228 payload = 0x230, then the recon-flag word +
   * a 4-byte tail = 0x238).
   *
   * This mirrors the `.cpp`-anonymous `LegacySyncUnitVariableEntry` used by the
   * `SSyncData` teardown lane; it is the public, named-field owner of that layout
   * (the trailing word is `mReconFlags`, not opaque tail bytes).
   */
  struct SUnitVariableUpdateEntry
  {
    EntId mEntityId = 0;                    // +0x000
    std::uint32_t mReserved04 = 0;          // +0x004
    SSTIUnitVariableData mVariableData{};   // +0x008
    std::int32_t mReconFlags = 0;           // +0x230
    std::uint32_t mReserved234 = 0;         // +0x234
  };
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SUnitVariableUpdateEntry, mVariableData) == 0x08,
    "SUnitVariableUpdateEntry::mVariableData offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SUnitVariableUpdateEntry, mReconFlags) == 0x230,
    "SUnitVariableUpdateEntry::mReconFlags offset must be 0x230"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(SUnitVariableUpdateEntry) == 0x238, "SUnitVariableUpdateEntry size must be 0x238"
  );
} // namespace moho

/**
 * Address: 0x005C39A0 (FUN_005C39A0) + the inlined id/`Assign` tail of the
 *          SyncInterface overrides (FUN_006AC3A0 / FUN_005BEFB0).
 *
 * What it does:
 * Appends one default `SUnitVariableUpdateEntry` to `syncData->mUnitUpdates`
 * (header word 0xF0000000 in `mEntityId` + default-constructed
 * `SSTIUnitVariableData`), then writes the entity id and assignment-copies the
 * supplied variable payload into the stored record, returning the inserted
 * element pointer. Matches the binary's push-default (`sub_5C39A0` with the
 * 0xF0000000 header) then write-id (`mov [edi], eax`) + `SSTIUnitVariableData::Assign`
 * (`lea edx, [edi+8]`) sequence.
 */
moho::SUnitVariableUpdateEntry* moho::QueueUnitVariableUpdate(
  SSyncData* const syncData,
  const EntId entityId,
  const SSTIUnitVariableData& variableData)
{
  if (!syncData) {
    return nullptr;
  }

  SUnitVariableUpdateEntry defaultEntry{};
  defaultEntry.mEntityId = ToRaw(EEntityIdSentinel::Invalid);
  syncData->mUnitUpdates.push_back(defaultEntry);
  if (syncData->mUnitUpdates.empty()) {
    return nullptr;
  }

  SUnitVariableUpdateEntry& stored = syncData->mUnitUpdates.back();
  stored.mEntityId = entityId;
  stored.mVariableData = variableData;
  return &stored;
}

void moho::SetUnitUpdateReconFlags(SUnitVariableUpdateEntry* const entry, const std::int32_t reconFlags) noexcept
{
  if (entry != nullptr) {
    entry->mReconFlags = reconFlags;
  }
}

namespace
{
  /**
   * Replicates the binary's per-slot shared-pointer swap used by
   * `ReconBlip::SyncInterface`: writes the new pointee first, then, when the
   * control block changes, add_ref_copy()s the new block and weak_release()s the
   * old one before storing it. Mirrors the `lock xadd [pi+4], 1` /
   * `sp_counted_base::weak_release` sequence at 0x005BF0A4.. and 0x005BF186..
   * operating on a raw `{px, pi}` pair.
   */
  void SwapSharedPointerSlotWithReconRefcount(
    boost::SharedPtrRaw<void>& slot,
    void* const newPx,
    boost::detail::sp_counted_base* const newPi) noexcept
  {
    slot.px = newPx;
    if (newPi == slot.pi) {
      return;
    }
    if (newPi != nullptr) {
      newPi->add_ref_copy();
    }
    if (slot.pi != nullptr) {
      slot.pi->weak_release();
    }
    slot.pi = newPi;
  }
} // namespace

void moho::PatchUnitUpdateReconPose(
  SUnitVariableUpdateEntry* const entry,
  void* const priorPosePx,
  boost::detail::sp_counted_base* const priorPosePi,
  void* const posePx,
  boost::detail::sp_counted_base* const posePi,
  const bool applyStunTicks,
  const std::int32_t stunTicks) noexcept
{
  if (entry == nullptr) {
    return;
  }

  // The binary writes the current-pose slot (varData +0x8C / entry +0x94) before
  // the prior-pose slot (varData +0x84 / entry +0x8C); preserve that order.
  auto& sharedPose = reinterpret_cast<boost::SharedPtrRaw<void>&>(entry->mVariableData.mSharedPose);
  SwapSharedPointerSlotWithReconRefcount(sharedPose, posePx, posePi);

  auto& priorSharedPose = reinterpret_cast<boost::SharedPtrRaw<void>&>(entry->mVariableData.mPriorSharedPose);
  SwapSharedPointerSlotWithReconRefcount(priorSharedPose, priorPosePx, priorPosePi);

  if (applyStunTicks) {
    entry->mVariableData.mStunTicks = stunTicks;
  }
}

void moho::PatchEntityUpdateReconMesh(
  SSyncData* const syncData,
  const RMeshBlueprint* const meshBlueprint,
  void* const scmResourcePx,
  boost::detail::sp_counted_base* const scmResourcePi,
  const float health,
  const float maxHealth,
  const float fractionComplete,
  const std::uint8_t isDead) noexcept
{
  if (syncData == nullptr || syncData->mEntityUpdates.empty()) {
    return;
  }

  SSTIEntityVariableData& mDat = syncData->mEntityUpdates.back().mVariableData;
  mDat.mMeshBlueprint = meshBlueprint;

  auto& scmResource = reinterpret_cast<boost::SharedPtrRaw<void>&>(mDat.mScmResource);
  SwapSharedPointerSlotWithReconRefcount(scmResource, scmResourcePx, scmResourcePi);

  mDat.mHealth = health;
  mDat.mMaxHealth = maxHealth;
  mDat.mFractionComplete = fractionComplete;
  mDat.mIsDead = isDead;
}

/**
 * Address: 0x0073B940 (FUN_0073B940, ??1SSyncDataQueue@Moho@@QAE@XZ)
 *
 * IDA signature:
 * void __stdcall sub_73B940(int a1);
 *
 * What it does:
 * Drains every live sync-data payload currently in the ring-buffer range
 * `[head, head + size)` via `DrainLiveRingBufferRange`, then releases the
 * backing map allocation and resets bookkeeping lanes via
 * `ReleaseOwnedSlotsAndReset`. Wrapped by an SEH frame so a throw from
 * any payload destructor still unwinds cleanly to the two-phase teardown
 * exit lane shared with `CSimDriver::~CSimDriver`.
 */
SSyncDataQueue::~SSyncDataQueue()
{
  DrainLiveRingBufferRange();
  ReleaseOwnedSlotsAndReset();
}

/**
 * Address: 0x007407F0 (FUN_007407F0, SSyncDataQueue drain-live helper)
 *
 * IDA signature:
 * int __usercall sub_7407F0@<eax>(int a1@<eax>);
 *
 * What it does:
 * Dispatches the inclusive destroy-range helper `sub_741980(this, head,
 * this, head + size)` that walks every live ring-buffer slot in
 * `[head, head + size)`, destroys the pointed-to `SSyncData` payload, and
 * clears the slot. Called as the first phase of both the destructor and
 * the ctor SEH unwind path via FUN_0073B940.
 */
void SSyncDataQueue::DrainLiveRingBufferRange() noexcept
{
  if (map == nullptr || size == 0u || mapSize == 0u) {
    return;
  }

  const std::uint32_t liveCount = size;
  const std::uint32_t startSlot = head;
  for (std::uint32_t index = 0u; index < liveCount; ++index) {
    const std::uint32_t slot = (startSlot + index) % mapSize;
    SSyncData* const payload = map[slot];
    if (payload != nullptr) {
      delete payload;
      map[slot] = nullptr;
    }
  }
}

bool SSyncDataQueue::Empty() const
{
  return size == 0;
}

void SSyncDataQueue::PushBack(SSyncData* data)
{
  if (!data) {
    return;
  }

  if (size >= mapSize) {
    const uint32_t newCap = (mapSize == 0) ? 8u : mapSize * 2u;
    auto** newMap = static_cast<SSyncData**>(::operator new(static_cast<std::size_t>(newCap) * sizeof(SSyncData*)));
    for (uint32_t i = 0; i < newCap; ++i) {
      newMap[i] = nullptr;
    }

    for (uint32_t i = 0; i < size; ++i) {
      newMap[i] = map[(head + i) % mapSize];
    }

    ::operator delete(static_cast<void*>(map));
    map = newMap;
    mapSize = newCap;
    head = 0;
  }

  map[(head + size) % mapSize] = data;
  ++size;
}

SSyncData* SSyncDataQueue::PopFront()
{
  if (size == 0 || !map) {
    return nullptr;
  }

  SSyncData* out = map[head];
  map[head] = nullptr;
  head = (head + 1u) % mapSize;
  --size;

  if (size == 0) {
    head = 0;
  }

  return out;
}

/**
 * Address: 0x007411A0 (FUN_007411A0)
 *
 * What it does:
 * Drains queue-size bookkeeping, destroys every non-null queue slot payload in
 * the backing map, releases map storage, and resets queue ownership lanes.
 */
void SSyncDataQueue::ReleaseOwnedSlotsAndReset()
{
  while (size != 0u) {
    const uint32_t nextSize = size - 1u;
    size = nextSize;
    if (nextSize == 0u) {
      head = 0u;
    }
  }

  if (map != nullptr) {
    for (uint32_t slot = mapSize; slot != 0u; --slot) {
      SSyncData* const queuedPayload = map[slot - 1u];
      if (queuedPayload != nullptr) {
        delete queuedPayload;
      }
    }

    ::operator delete(static_cast<void*>(map));
  }

  map = nullptr;
  mapSize = 0u;
}

void SSyncDataQueue::ClearAndDelete()
{
  while (!Empty()) {
    delete PopFront();
  }
}

/**
 * Address: 0x0073F9C0 (FUN_0073F9C0,
 *                      boost::ptr_sequence_adapter_deque_SSyncData::pop_front)
 *
 * What it does:
 * Per-T named free helper that captures the engine-instantiated MSVC8 body of
 * `boost::ptr_sequence_adapter< std::deque<SSyncData*> >::pop_front`. The
 * binary's `mSyncdat` lane is a `boost::ptr_sequence_adapter` over a deque of
 * sync-data pointers; the recovered side models the same 0x14-byte layout as
 * `SSyncDataQueue` (`_Myproxy` / `_Map` / `_Mapsize` / `_Myoff` / `_Mysize`
 * mapped to `reserved` / `map` / `mapSize` / `head` / `size`).
 *
 * Binary semantics, preserved 1:1:
 *   1. If the underlying deque is empty, construct and throw
 *      `boost::bad_ptr_container_operation("'pop_front()' on empty container")`.
 *      The `.rdata` literal at 0x00E33430 matches this exact message and the
 *      vtable at 0x00E068F0 (`??_7bad_ptr_container_operation@boost@@6B@`)
 *      is patched onto the on-stack `std::exception` shell before the throw.
 *   2. Otherwise read the front pointer, advance the front-offset, decrement
 *      the size, and return the popped pointer. Ownership transfers to the
 *      caller (the binary does not delete; `GetSyncData` either keeps the
 *      pointer or runs the auto_type destructor when an exception escapes).
 *
 * Callers invoke this helper by explicit name from
 * `Moho::CSimDriver::GetSyncData` (FUN_0073C520), preserving the MSVC8
 * out-of-line symbol shape for the ptr_sequence_adapter emission.
 */
SSyncData* moho::PopFrontSSyncDataPtrDeque(SSyncDataQueue& queue)
{
  if (queue.size == 0u) {
    throw boost::bad_ptr_container_operation("'pop_front()' on empty container");
  }

  return queue.PopFront();
}

/**
 * Address: 0x0073B570 (FUN_0073B570)
 * Mangled: ??0CSimDriver@Moho@@QAE@@Z
 *
 * What it does:
 * Initializes driver state, events, marshaller, and the create-sim bootstrap thread.
 */
CSimDriver::CSimDriver(
  msvc8::auto_ptr<gpg::Stream> stream,
  msvc8::auto_ptr<CClientManagerImpl> clientManager,
  const boost::shared_ptr<LaunchInfoBase>& launchInfo,
  const uint32_t commandSourceId
)
  : mSim(nullptr)
  , mClientManager(clientManager.release())
  , mStream(stream.release())
  , mLaunchInfo(launchInfo)
  , mCommandSourceId(commandSourceId)
  , mLastDequeuedBeat(-1)
  , mDispatchBeat(1)
  , mCommandCookie(1)
  , mMarshaller(nullptr)
  , mDecoder(nullptr)
  , mSimThread(nullptr)
  , mOutstandingRequests(1)
  , mConnectionEvent(nullptr)
  , mLastSyncCycleTime(0)
  , mStopSimThread(false)
  , mFirstCommandCycleTime(0)
  , mSimBusy(false)
  , mCreateSimThread(nullptr)
  , mStopCreateSimThread(false)
  , mState(EDriverState::Startup)
  , mSyncDataQueue{}
  , mSyncDataAvailableEvent(nullptr)
  , mInterlockedMode(gSimInterlocked)
  , mInterlockRefCount(0)
  , mPendingSyncFilter{}
  , mActiveSyncFilter{}
  , mSaveGameRequest(nullptr)
  , mWantsToSave(false)
  , mSaveRequestUsesSuggestedName(false)
  , mPendingSaveName{}
  , mSimSpeedSamples{}
  , mCurrentSimRate(10)
{
  mLock.lock = new boost::mutex();

  mPendingSyncFilter.focusArmy = static_cast<int32_t>(commandSourceId);
  mActiveSyncFilter.focusArmy = static_cast<int32_t>(commandSourceId);

  mConnectionEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  mSyncDataAvailableEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  mClientManager->SelectEvent(mConnectionEvent);

  mMarshaller = new CMarshaller(mClientManager);
  mMarshaller->SetCommandSource(commandSourceId);

  // 0x0073D260 creates the simulation bootstrap thread. The full function
  // still depends on additional lifted classes; for now we preserve state flow.
  const auto createSimBootstrapProc = [](CSimDriver* const driver) {
    boost::mutex::scoped_lock lock(DriverMutexRef(driver->mLock));
    if (driver->mStopCreateSimThread) {
      driver->mState = EDriverState::Stopped;
      driver->mStateChanged.notify_all();
      return;
    }

    driver->mState = EDriverState::Ready;
    driver->mStateChanged.notify_all();
  };
  mCreateSimThread = new boost::thread(BuildDeferredDriverCallback(createSimBootstrapProc, this));
}

/**
 * Address: 0x0073BA50 (FUN_0073BA50)
 * Mangled: ??1CSimDriver@Moho@@QAE@@Z
 * Slot: 0 (ISTIDriver override)
 *
 * What it does:
 * Performs full shutdown and releases owned driver resources.
 */
CSimDriver::~CSimDriver()
{
  if (gActiveSimDriver == this) {
    gActiveSimDriver = nullptr;
  }

  ShutDown();
  delete mLock.lock;
  mLock.lock = nullptr;

  if (mConnectionEvent) {
    CloseHandle(mConnectionEvent);
    mConnectionEvent = nullptr;
  }

  if (mSyncDataAvailableEvent) {
    CloseHandle(mSyncDataAvailableEvent);
    mSyncDataAvailableEvent = nullptr;
  }

  mSyncDataQueue.ClearAndDelete();

  if (mDecoder) {
    mDecoder->~CDecoder();
    ::operator delete(static_cast<void*>(mDecoder));
    mDecoder = nullptr;
  }

  delete mMarshaller;
  mMarshaller = nullptr;

  delete mStream;
  mStream = nullptr;

  delete mClientManager;
  mClientManager = nullptr;

  delete mSim;
  mSim = nullptr;
}

/**
 * Address: 0x0073B910 (FUN_0073B910, Moho::CSimDriver::dtr)
 *
 * What it does:
 * Runs destructor logic and conditionally frees object storage.
 */
CSimDriver* CSimDriver::DestroyWithDeleteFlag(const std::uint8_t deleteFlag)
{
  this->~CSimDriver();
  if ((deleteFlag & 0x1u) != 0u) {
    ::operator delete(static_cast<void*>(this));
  }
  return this;
}

void CSimDriver::JoinAndDeleteThread(boost::thread*& thread)
{
  if (!thread) {
    return;
  }

  try {
    thread->join();
  } catch (...) {
    // Boost 1.34 does not expose joinable(); preserve best-effort shutdown.
  }

  delete thread;
  thread = nullptr;
}

// Shared tail extracted from SetArmyIndex/DisconnectClients/command wrappers.
// First transition to "active" stamps the cycle timer and signals mConnectionEvent.
void CSimDriver::MarkFirstConnectionActivityLocked()
{
  if (mFirstCommandCycleTime != 0) {
    return;
  }

  mFirstCommandCycleTime = mTimer.ElapsedCycles();
  if (mConnectionEvent) {
    SetEvent(mConnectionEvent);
  }
}

/**
 * Address: 0x0073DD70 (FUN_0073DD70), plus exception branch at 0x0073DDF9..0x0073DE2B
 *
 * What it does:
 * Unlocks the driver mutex, serializes Sim state into the request archive,
 * records success/failure completion payload, then relocks and signals waiters.
 */
void CSimDriver::PreparePendingSaveRequestLocked(boost::mutex::scoped_lock& lock)
{
  if (!mSaveGameRequest) {
    return;
  }

  lock.unlock();
  try {
    gpg::WriteArchive* const archive = mSaveGameRequest->GetArchive();
    mSim->SaveState(archive);
    mPendingSaveName.clear();
    mSaveRequestUsesSuggestedName = true;
  } catch (const std::exception& ex) {
    mPendingSaveName = ex.what();
    mSaveRequestUsesSuggestedName = false;
  } catch (...) {
    mPendingSaveName.clear();
    mSaveRequestUsesSuggestedName = false;
  }
  lock.lock();

  mWantsToSave = true;
  if (--mOutstandingRequests == 0) {
    mLastSyncCycleTime = mTimer.ElapsedCycles();
  }
  if (mConnectionEvent) {
    SetEvent(mConnectionEvent);
  }
}

// Source-only adapter: binary wrappers write mCommandCookie to caller-provided out pointers.
void CSimDriver::ForwardCommandResultLocked()
{
  // The original methods return mCommandCookie via an out pointer.
  // The reconstructed ISTIDriver interface models those methods as void.
}

/**
 * Address: 0x0073DAD0 (FUN_0073DAD0)
 *
 * What it does:
 * Unlocks the driver mutex, runs one `Sim::Sync` publish pass, relocks,
 * verifies historical checksums when available, and enqueues the sync packet.
 */
void CSimDriver::FinalizeSyncDispatchLocked(boost::mutex::scoped_lock& lock)
{
  mActiveSyncFilter.CopyFrom(mPendingSyncFilter);

  lock.unlock();

  CTimeBarSection timebar("Sim - Sync");
  if (gEngineStatSimSync == nullptr) {
    gEngineStatSimSync = GetEngineStats()->GetItem3("Sim_Sync");
    if (gEngineStatSimSync != nullptr) {
      (void)gEngineStatSimSync->Release(1);
    }
  }

  gpg::time::Timer syncTimer;
  SSyncData* syncData = nullptr;
  mSim->Sync(mActiveSyncFilter, syncData);

  AddElapsedMicrosecondsToStat(
    gEngineStatSimSync,
    static_cast<std::int64_t>(gpg::time::CyclesToMicroseconds(syncTimer.ElapsedCycles()))
  );

  lock.lock();

  const int32_t currentBeat = static_cast<int32_t>(mSim->mCurBeat);
  const int32_t syncBeat = syncData->mCurBeat;
  const int32_t oldestRetainedBeat = currentBeat - 128;
  if (syncBeat >= oldestRetainedBeat && syncBeat < currentBeat) {
    const gpg::MD5Digest& expectedDigest = mSim->mSimHashes[syncBeat & 0x7F];
    if (!IsZeroDigest(expectedDigest)) {
      mMarshaller->VerifyChecksum(expectedDigest, syncBeat);
    }
  }

  const bool hasBlockingSyncState = syncData->mPausedBy != -1 || syncData->mGameOver;
  if (mSimBusy != hasBlockingSyncState) {
    mSimBusy = hasBlockingSyncState;
    if (!hasBlockingSyncState) {
      mLastSyncCycleTime = mTimer.ElapsedCycles();
    }
    SetEvent(mConnectionEvent);
  }

  mSyncDataQueue.PushBack(syncData);

  if (mSyncDataAvailableEvent) {
    SetEvent(mSyncDataAvailableEvent);
  }
}

/**
 * Address: 0x0073D8C0 (FUN_0073D8C0, thunk to FUN_0128FAC0)
 *
 * What it does:
 * Runs one dispatch beat, then executes sync publication and sim-rate sampling.
 */
void CSimDriver::ExecuteDispatchStepLocked(boost::mutex::scoped_lock& lock)
{
  const int32_t beatToDispatch = mDispatchBeat;
  ++mDispatchBeat;

  gpg::time::Timer dispatchTimer;

  lock.unlock();
  mClientManager->UpdateStates(beatToDispatch);
  lock.lock();

  FinalizeSyncDispatchLocked(lock);

  if (mSimBusy) {
    return;
  }

  const float dispatchDurationMs = static_cast<float>(dispatchTimer.ElapsedMilliseconds());
  mSimSpeedSamples.Append(dispatchDurationMs);

  const float medianDispatchMs = mSimSpeedSamples.Median();
  if (!(medianDispatchMs > 0.0f)) {
    return;
  }

  const float simRateEstimate = (1000.0f / medianDispatchMs) * 0.1f;
  const int updatedSimRate = QuantizeSimRateSample(simRateEstimate);
  if (updatedSimRate != mCurrentSimRate) {
    mCurrentSimRate = updatedSimRate;
    mClientManager->SetSimRate(updatedSimRate);
  }
}

/**
 * Address: 0x0073B190 (FUN_0073B190), ISTIDriver slot 3
 * Returns the associated client manager instance.
 */
CClientManagerImpl* CSimDriver::GetClientManager()
{
  return mClientManager;
}

/**
 * Address: 0x0073B1A0 (FUN_0073B1A0), ISTIDriver slot 10
 * Returns the manual-reset event used for sync-data availability.
 */
HANDLE CSimDriver::GetSyncDataAvailableEvent()
{
  return mSyncDataAvailableEvent;
}

/**
 * Address: 0x0073B1B0 (FUN_0073B1B0), ISTIDriver slot 12
 * Updates the pending sync-filter focus army and marks first connection activity when it changes.
 */
void CSimDriver::SetArmyIndex(const int armyIndex)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  if (mPendingSyncFilter.focusArmy == armyIndex) {
    return;
  }

  mPendingSyncFilter.focusArmy = armyIndex;
  MarkFirstConnectionActivityLocked();
}

void CSimDriver::SetPendingFocusArmyRaw(const std::int32_t focusArmy) noexcept
{
  mPendingSyncFilter.focusArmy = focusArmy;
}

/**
 * Address: 0x0073B240 (FUN_0073B240), ISTIDriver slot 16
 * Updates the pending sync-filter option flag.
 */
void CSimDriver::SetSyncFilterOptionFlag(const bool value)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mPendingSyncFilter.optionFlag = value;
}

/**
 * Address: 0x0073B270 (FUN_0073B270), ISTIDriver slot 13
 * Replaces pending sync-filter cameras only when content differs.
 */
void CSimDriver::SetGeomCams(const msvc8::vector<GeomCamera3>& geoCams)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  if (!AreGeomCameraVectorsEqual(mPendingSyncFilter.geoCams, geoCams)) {
    mPendingSyncFilter.geoCams = geoCams;
  }
}

/**
 * Address: 0x0073B3F0 (FUN_0073B3F0), ISTIDriver slot 14
 * Retail build executes compare-only logic for mask block A; no state mutation occurs.
 * Verified in raw bytes: 0x0073B43D = EB 3C (unconditional jump over copy block).
 */
void CSimDriver::SetSyncFilterMaskA(const SSyncFilterMaskBlock& block)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  (void)SSyncFilterMaskBlock::Equals(mPendingSyncFilter.maskA, block);
}

/**
 * Address: 0x0073B4B0 (FUN_0073B4B0), ISTIDriver slot 15
 * Replaces pending sync-filter mask block B when the incoming block differs.
 */
void CSimDriver::SetSyncFilterMaskB(const SSyncFilterMaskBlock& block)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  if (SSyncFilterMaskBlock::Equals(mPendingSyncFilter.maskB, block)) {
    return;
  }

  mPendingSyncFilter.maskB.CopyFrom(block);
}

/**
 * Address: 0x0073BBF0 (FUN_0073BBF0), ISTIDriver slot 1
 * Disconnects all clients and marks first connection activity.
 */
void CSimDriver::DisconnectClients()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mClientManager->Disconnect();
  MarkFirstConnectionActivityLocked();
}

/**
 * Address: 0x0073BC80 (FUN_0073BC80), ISTIDriver slot 2
 * Stops worker threads, shuts down the sim, and releases the live sim object.
 */
void CSimDriver::ShutDown()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));

  if (mSimThread) {
    mStopSimThread = true;
    if (mConnectionEvent) {
      SetEvent(mConnectionEvent);
    }

    lock.unlock();
    JoinAndDeleteThread(mSimThread);
    lock.lock();
  }

  if (mCreateSimThread) {
    mStopCreateSimThread = true;
    mStateChanged.notify_all();

    while (mState != EDriverState::Stopped && mState != EDriverState::Failed) {
      lock.unlock();
      PerformNextEvent();
      lock.lock();
    }

    lock.unlock();
    JoinAndDeleteThread(mCreateSimThread);
    lock.lock();
  }

  if (mSim) {
    // The original shutdown path calls Sim::Shutdown() and then performs one
    // final sync transfer before deleting the object.
    mSim->Shutdown();
    delete mSim;
    mSim = nullptr;
  }
}

/**
 * Address: 0x0073BDE0 (FUN_0073BDE0), ISTIDriver slot 4
 * Intentional no-op extension slot (nullsub in retail binary).
 */
void CSimDriver::NoOp() {}

/**
 * Address: 0x0073C250 (FUN_0073C250), ISTIDriver slot 5
 * Handles save requests and interlocked-mode dispatch transitions.
 */
void CSimDriver::Dispatch()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));

  if (mWantsToSave) {
    CSaveGameRequestImpl* request = mSaveGameRequest;
    SSaveGameDispatchData data{};
    data.useSuggestedName = mSaveRequestUsesSuggestedName;
    data.saveName = mPendingSaveName;

    mSaveGameRequest = nullptr;
    mWantsToSave = false;

    lock.unlock();
    request->Save(data);
    lock.lock();
  }

  const bool desiredInterlocked = gSimInterlocked || (mInterlockRefCount > 0);
  if (mInterlockedMode != desiredInterlocked) {
    mInterlockedMode = desiredInterlocked;
    mStateChanged.notify_all();
  }

  if (!mInterlockedMode) {
    return;
  }

  while (mInterlockedMode) {
    if (!mSyncDataQueue.Empty()) {
      break;
    }

    if (mSaveGameRequest && !mWantsToSave && (mState == EDriverState::Dispatching || mState == EDriverState::Ready)) {
      PreparePendingSaveRequestLocked(lock);
      continue;
    }

    if (mState != EDriverState::Dispatching) {
      break;
    }

    ExecuteDispatchStepLocked(lock);
    mState = EDriverState::Ready;
    mStateChanged.notify_all();
  }
}

/**
 * Address: 0x0073C410 (FUN_0073C410), ISTIDriver slot 6
 * Increments the outstanding request counter.
 */
void CSimDriver::IncrementOutstandingRequests()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  ++mOutstandingRequests;
}

/**
 * Address: 0x0073C440 (FUN_0073C440), ISTIDriver slot 7
 * Decrements outstanding requests; timestamps when the counter reaches zero and signals the connection event.
 */
void CSimDriver::DecrementOutstandingRequestsAndSignal()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  if (--mOutstandingRequests == 0) {
    mLastSyncCycleTime = mTimer.ElapsedCycles();
  }
  if (mConnectionEvent) {
    SetEvent(mConnectionEvent);
  }
}

/**
 * Address: 0x0073C4F0 (FUN_0073C4F0), ISTIDriver slot 8
 * Returns true when the sync-data queue is non-empty.
 */
bool CSimDriver::HasSyncData()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  return !mSyncDataQueue.Empty();
}

/**
 * Address: 0x0073C520 (FUN_0073C520), ISTIDriver slot 9
 * Waits for, pops, and returns the next sync packet.
 */
void CSimDriver::GetSyncData(SSyncData*& outSyncData)
{
  outSyncData = nullptr;

  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  while (mSyncDataQueue.Empty()) {
    lock.unlock();
    PerformNextEvent();
    lock.lock();
  }

  // Invoke the engine-instantiated `boost::ptr_sequence_adapter pop_front`
  // body by its named per-T helper so the MSVC8 out-of-line symbol shape
  // (FUN_0073F9C0) is preserved at the source-level callsite.
  outSyncData = PopFrontSSyncDataPtrDeque(mSyncDataQueue);
  if (outSyncData) {
    mLastDequeuedBeat = outSyncData->mCurBeat;
  }

  mLastSyncCycleTime = mTimer.ElapsedCycles();
  if (mConnectionEvent) {
    SetEvent(mConnectionEvent);
  }

  if (mSyncDataQueue.Empty() && mSyncDataAvailableEvent) {
    ResetEvent(mSyncDataAvailableEvent);
  }
}

/**
 * Address: 0x0073C630 (FUN_0073C630), ISTIDriver slot 11
 * Returns the driver sim-speed metric (retail implementation returns 0.0).
 */
double CSimDriver::GetSimSpeed()
{
  return 0.0;
}

/**
 * Address: 0x0073C640 (FUN_0073C640, sub_73C640)
 *
 * What it does:
 * Stamps `mLastSyncCycleTime`, signals the connection event, and writes the
 * current command-cookie lane to one output pointer.
 */
std::int32_t* CSimDriver::SignalConnectionAndWriteCommandCookie(std::int32_t* const outCommandCookie)
{
  mLastSyncCycleTime = mTimer.ElapsedCycles();
  if (mConnectionEvent != nullptr) {
    SetEvent(mConnectionEvent);
  }

  if (outCommandCookie != nullptr) {
    *outCommandCookie = mCommandCookie;
  }

  return outCommandCookie;
}

/**
 * Address: 0x0073DE90 (FUN_0073DE90)
 *
 * What it does:
 * Stores one driver-state lane and notifies all waiters on `mStateChanged`.
 */
void CSimDriver::SetStateAndNotify(const EDriverState state)
{
  mState = state;
  mStateChanged.notify_all();
}

/**
 * Address: 0x0073C4C0 (FUN_0073C4C0)
 *
 * What it does:
 * Queries the client-manager available beat lane and promotes
 * `mState` to `Dispatching` when the available beat has reached
 * `mDispatchBeat`.
 */
void CSimDriver::PromoteToDispatchingWhenBeatAvailable(const int beatQuerySeed)
{
  int availableBeat = beatQuerySeed;
  mClientManager->GetAvailableBeat(availableBeat);
  if (availableBeat >= mDispatchBeat) {
    SetStateAndNotify(EDriverState::Dispatching);
  }
}

/**
 * Address: 0x0073C660 (FUN_0073C660), ISTIDriver slot 17
 * Marshals CMDST_RequestPause and reports command-cookie result.
 */
void CSimDriver::RequestPause(std::int32_t* const outCommandCookie)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->RequestPause();
  MarkFirstConnectionActivityLocked();
  if (outCommandCookie != nullptr) {
    *outCommandCookie = mCommandCookie;
  }
}

/**
 * Address: 0x0073C700 (FUN_0073C700), ISTIDriver slot 18
 * Marshals CMDST_Resume and reports command-cookie result.
 */
void CSimDriver::Resume(std::int32_t* const outCommandCookie)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->Resume();
  MarkFirstConnectionActivityLocked();
  if (outCommandCookie != nullptr) {
    *outCommandCookie = mCommandCookie;
  }
}

/**
 * Address: 0x0073C7A0 (FUN_0073C7A0), ISTIDriver slot 19
 * Marshals CMDST_SingleStep and reports command-cookie result.
 */
void CSimDriver::SingleStep()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->SingleStep();
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073C840 (FUN_0073C840), ISTIDriver slot 20
 * Marshals CMDST_CreateUnit and reports command-cookie result.
 */
void CSimDriver::CreateUnit(const uint32_t armyIndex, const RResId& id, const SCoordsVec2& pos, const float heading)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->CreateUnit(armyIndex, id, pos, heading);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073C8F0 (FUN_0073C8F0), ISTIDriver slot 21
 * Marshals CMDST_CreateProp and reports command-cookie result.
 */
void CSimDriver::CreateProp(const char* id, const Wm3::Vec3f& loc)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->CreateProp(id, loc);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073C990 (FUN_0073C990), ISTIDriver slot 22
 * Marshals CMDST_DestroyEntity and reports command-cookie result.
 */
void CSimDriver::DestroyEntity(const EntId entityId)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->DestroyEntity(entityId);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CA30 (FUN_0073CA30), ISTIDriver slot 23
 * Marshals CMDST_WarpEntity and reports command-cookie result.
 */
void CSimDriver::WarpEntity(const EntId entityId, const VTransform& transform)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->WarpEntity(entityId, transform);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CAD0 (FUN_0073CAD0), ISTIDriver slot 24
 * Marshals CMDST_ProcessInfoPair and reports command-cookie result.
 */
void CSimDriver::ProcessInfoPair(void* id, const char* key, const char* val)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->ProcessInfoPair(id, key, val);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CB70 (FUN_0073CB70), ISTIDriver slot 25
 * Marshals CMDST_IssueCommand and reports command-cookie result.
 */
void CSimDriver::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, const bool clear
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->IssueCommand(entities, data, clear);
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CC10 (FUN_0073CC10), ISTIDriver slot 26
 * Marshals CMDST_IssueFactoryCommand and reports command-cookie result.
 */
void CSimDriver::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, const bool clear
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->IssueFactoryCommand(entities, data, clear);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CCB0 (FUN_0073CCB0), ISTIDriver slot 27
 * Marshals CMDST_IncreaseCommandCount and reports command-cookie result.
 */
void CSimDriver::IncreaseCommandCount(const CmdId id, const int count)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->IncreaseCommandCount(id, count);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CD50 (FUN_0073CD50), ISTIDriver slot 28
 * Marshals CMDST_DecreaseCommandCount and returns the resulting command cookie
 * (the binary writes `mCommandCookie` into a caller-provided out pointer).
 */
CmdId CSimDriver::DecreaseCommandCount(const CmdId id, const int count)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->DecreaseCommandCount(id, count);
  MarkFirstConnectionActivityLocked();
  return mCommandCookie;
}

/**
 * Address: 0x0073CDF0 (FUN_0073CDF0), ISTIDriver slot 29
 * Marshals CMDST_SetCommandTarget and reports command-cookie result.
 */
void CSimDriver::SetCommandTarget(const CmdId id, const SSTITarget& target)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->SetCommandTarget(id, target);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CE90 (FUN_0073CE90), ISTIDriver slot 30
 * Marshals CMDST_SetCommandType and reports command-cookie result.
 */
void CSimDriver::SetCommandType(const CmdId id, const EUnitCommandType type)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->SetCommandType(id, type);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CF30 (FUN_0073CF30), ISTIDriver slot 31
 * Marshals CMDST_SetCommandCells and reports command-cookie result.
 */
void CSimDriver::SetCommandCells(
  const CmdId id, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& target
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->SetCommandCells(id, cells, target);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CFD0 (FUN_0073CFD0), ISTIDriver slot 32
 * Marshals CMDST_RemoveCommandFromQueue and reports command-cookie result.
 */
void CSimDriver::RemoveCommandFromUnitQueue(const CmdId id, const EntId unitId)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->RemoveCommandFromUnitQueue(id, unitId);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073D070 (FUN_0073D070), ISTIDriver slot 33
 * Marshals CMDST_ExecuteLuaInSim and reports command-cookie result.
 */
void CSimDriver::ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->ExecuteLuaInSim(lua, args);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073D110 (FUN_0073D110), ISTIDriver slot 34
 * Marshals CMDST_LuaSimCallback and reports command-cookie result.
 */
void CSimDriver::LuaSimCallback(
  const char* fnName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->LuaSimCallback(fnName, args, entities);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073D1B0 (FUN_0073D1B0), ISTIDriver slot 35
 * Marshals CMDST_DebugCommand and reports command-cookie result.
 */
void CSimDriver::ExecuteDebugCommand(
  const char* command,
  const Wm3::Vector3<float>& worldPos,
  const uint32_t focusArmy,
  const BVSet<EntId, EntIdUniverse>& entities
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->ExecuteDebugCommand(command, worldPos, focusArmy, entities);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073DEA0 (FUN_0073DEA0), ISTIDriver slot 36
 * Enters interlocked mode and pumps events until main-thread waiting state clears.
 */
Sim* CSimDriver::ProcessEvents()
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  ++mInterlockRefCount;
  mInterlockedMode = true;

  while (mState == EDriverState::WaitingForMainThread) {
    lock.unlock();
    PerformNextEvent();
    lock.lock();
  }

  return mSim;
}

/**
 * Address: 0x0073DF50 (FUN_0073DF50), ISTIDriver slot 37
 * Decrements the interlock reference counter.
 */
void CSimDriver::ReleaseInterlockRef()
{
  --mInterlockRefCount;
}

/**
 * Address: 0x0073DF60 (FUN_0073DF60), ISTIDriver slot 38
 * Queues a save-game request and wakes dispatch waiters.
 */
void CSimDriver::RequestSaveGame(CSaveGameRequestImpl* request)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mSaveGameRequest = request;
  mStateChanged.notify_all();
  ++mOutstandingRequests;
}

/**
 * Address: 0x0073DFE0 (FUN_0073DFE0), ISTIDriver slot 39
 * Builds and draws the network diagnostics overlay (current lift keeps synchronization semantics only).
 */
void CSimDriver::DrawNetworkStats(
  CD3DPrimBatcher* batcher, const float anchorX, const float anchorY, const float scaleX, const float scaleY
)
{
  (void)batcher;
  (void)anchorX;
  (void)anchorY;
  (void)scaleX;
  (void)scaleY;

  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  // 0x0073DFE0 builds a multi-column network table and renders it with
  // D3D font batching ("Courier New", columns ping/maxsp/data/behind/avail).
  // Full lifting is blocked until CD3DPrimBatcher/CD3DFont surfaces are
  // reconstructed in src/sdk.
}

/**
 * Address: 0x0073F430 (FUN_0073F430)
 * Performs one client-manager beat, pumps wx pending/idle events, then sleeps alertably.
 */
DWORD CSimDriver::PerformNextEvent()
{
  {
    boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
    mClientManager->DoBeat();
  }

  bool keepIdle = true;
  for (;;) {
    if (moho::WxAppRuntime::Pending()) {
      moho::WxAppRuntime::Dispatch();
      keepIdle = true;
      continue;
    }

    if (!keepIdle) {
      break;
    }

    keepIdle = moho::WxAppRuntime::ProcessIdle();
  }

  return SleepEx(100, TRUE);
}

/**
 * Address: 0x0073F4E0 (FUN_0073F4E0)
 * Mangled:
 * ?SIM_CreateDriver@Moho@@YAPAVISTIDriver@1@V?$auto_ptr@VIClientManager@Moho@@@std@@V?$auto_ptr@VStream@gpg@@@4@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@I@Z
 *
 * What it does:
 * Factory that transfers stream/client ownership into a new CSimDriver instance.
 */
ISTIDriver* moho::SIM_CreateDriver(
  CClientManagerImpl* clientManager,
  gpg::Stream* stream,
  const boost::shared_ptr<LaunchInfoBase>& launchInfo,
  const uint32_t commandSourceId
)
{
  msvc8::auto_ptr<CClientManagerImpl> clientOwner(clientManager);
  msvc8::auto_ptr<gpg::Stream> streamOwner(stream);
  CSimDriver* const created = new CSimDriver(streamOwner, clientOwner, launchInfo, commandSourceId);
  gActiveSimDriver = created;
  return created;
}

/**
 * Address context: process-global `sSimDriver` ownership lane used by world/app frame code.
 */
ISTIDriver* moho::SIM_GetActiveDriver()
{
  return gActiveSimDriver;
}

/**
 * Address: 0x0088E8D0 (FUN_0088E8D0, sim-driver singleton getter lane)
 *
 * What it does:
 * Returns the process-global concrete `CSimDriver` singleton pointer without
 * changing ownership.
 */
namespace
{
  [[maybe_unused]] [[nodiscard]] moho::CSimDriver* SIM_GetActiveDriverRaw() noexcept
  {
    return static_cast<moho::CSimDriver*>(gActiveSimDriver);
  }

  /**
   * Address: 0x0088E8E0 (FUN_0088E8E0, sim-driver singleton getter lane)
   *
   * What it does:
   * Alias entry that returns the same process-global concrete `CSimDriver`
   * singleton pointer.
   */
  [[maybe_unused]] [[nodiscard]] moho::CSimDriver* SIM_GetActiveDriverRawAlias() noexcept
  {
    return SIM_GetActiveDriverRaw();
  }
}

ISTIDriver* moho::SIM_DetachActiveDriver()
{
  ISTIDriver* const detached = gActiveSimDriver;
  gActiveSimDriver = nullptr;
  return detached;
}
