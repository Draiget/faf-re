#include "SimDriver.h"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <vector>

#include "boost/function.hpp"
#include <boost/ptr_container/exception.hpp>
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/app/WxAppRuntime.h"
#include "moho/net/CClientBase.h"
#include "moho/net/IClient.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
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

  // Issue-thread pacing, from CSimDriver::ThreadRun (0x0073BDF0).
  constexpr unsigned int kCurrentThreadId = 0xFFFFFFFFu;
  constexpr std::uint32_t kIssueThreadTimeBarColor = 0xFF00FF00u;
  constexpr int kIssueThreadIdleWaitMs = 1000;
  constexpr std::uint32_t kMaxQueuedSyncPacketsBeforeStalling = 10u;
  constexpr int kMaxBeatsAheadOfExecuted = 98;
  constexpr int kMaxCatchUpBeats = 99;
  constexpr float kBlockedIssueGraceMs = 250.0f;

  // Sim bootstrap, from CSimDriver::ThreadCreateSim (0x0073D260).
  constexpr std::uint32_t kSimThreadTimeBarColor = 0xFFFF0000u;
  constexpr unsigned int kSimCommandMessageUpperBound = 0x32u;

  /**
   * Address: 0x0073D260 (FUN_0073D260, opening block)
   *
   * What it does:
   * Confines the sim thread to a single NUMA node when `/NUMA` is on, so its
   * working set stays on one memory controller. Only meaningful on the
   * platforms that report node topology - Windows Server 2003, XP SP2 and
   * later - which is what the version gate below checks. `/NUMAbad` picks the
   * complement of the node instead, which the original used to measure what
   * the pinning was worth.
   */
  void PinThisThreadToOneNumaNodeIfRequested()
  {
    if (!moho::CFG_GetArgOption("/NUMA", 0, nullptr)) {
      return;
    }

    OSVERSIONINFOW versionInfo{};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    if (!GetVersionExW(&versionInfo) || versionInfo.dwPlatformId != VER_PLATFORM_WIN32_NT) {
      return;
    }
    if (versionInfo.dwMajorVersion < 5) {
      return;
    }
    if (versionInfo.dwMajorVersion == 5 && versionInfo.dwMinorVersion == 0) {
      return;
    }
    if (versionInfo.dwMajorVersion == 5 && versionInfo.dwMinorVersion == 1) {
      // XP needs Service Pack 2 or later for the NUMA queries.
      const wchar_t* const servicePack = std::wcsstr(versionInfo.szCSDVersion, L"Service Pack ");
      if (servicePack == nullptr || servicePack[13] < L'2') {
        return;
      }
    }

    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &processAffinity, &systemAffinity)) {
      return;
    }

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    // Walk processors until one reports a node whose mask overlaps the first
    // core this process is allowed to use; that node is the one to sit on.
    ULONGLONG nodeMask = 0;
    bool foundNode = false;
    for (UCHAR processor = 0; processor < systemInfo.dwNumberOfProcessors && !foundNode; ++processor) {
      UCHAR node = 0;
      if (!GetNumaProcessorNode(processor, &node) || node == 0xFF) {
        continue;
      }
      if (!GetNumaNodeProcessorMask(node, &nodeMask)) {
        continue;
      }

      nodeMask &= static_cast<ULONGLONG>(processAffinity);

      int firstAllowed = 0;
      while (firstAllowed < 32 && ((static_cast<DWORD_PTR>(1) << firstAllowed) & processAffinity) == 0) {
        ++firstAllowed;
      }
      if (firstAllowed < 32 && (nodeMask & (1ull << firstAllowed)) != 0) {
        foundNode = true;
      } else {
        nodeMask = 0;
      }
    }

    ULONGLONG chosenMask = nodeMask;
    if (moho::CFG_GetArgOption("/NUMAbad", 0, nullptr)) {
      chosenMask = ~nodeMask & static_cast<ULONGLONG>(processAffinity);
    }

    // Pin to the second core of that node when it has one, which keeps the sim
    // off whichever core the main thread already owns.
    int seen = 0;
    for (int processor = 0; processor < 32; ++processor) {
      if ((chosenMask & (1ull << processor)) == 0) {
        continue;
      }
      if (seen == 1) {
        (void)SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << processor);
        return;
      }
      ++seen;
    }
  }
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

  /**
   * Address: 0x0073AEF0 (FUN_0073AEF0, sub_73AEF0)
   *
   * IDA signature:
   * BOOL __fastcall sub_73AEF0(float* lhs, float* rhs);
   *
   * What it does:
   * Compares two 4x4 matrices element by element. Float `==`, not a bit
   * compare: -0.0f and +0.0f count as equal, and a NaN anywhere makes the
   * matrices unequal even against itself.
   */
  [[nodiscard]] bool AreGalMatricesEqual(const gpg::gal::Matrix& lhs, const gpg::gal::Matrix& rhs) noexcept
  {
    for (int row = 0; row < 4; ++row) {
      for (int column = 0; column < 4; ++column) {
        if (lhs.r[row][column] != rhs.r[row][column]) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Compares the camera lanes that `CSimDriver::SetGeomCams` (0x0073B270)
   * actually tests: transform orientation and position, then the projection and
   * view matrices. It deliberately ignores `viewProjection`, the three inverse
   * matrices, the solids and `lodScale` - those are derived or unused by the
   * sync filter, and the binary does not look at them.
   *
   * Previously a `memcmp` over all 0x2C8 bytes, which differed twice over: it
   * compared fields the binary ignores, and compared bit patterns rather than
   * float values, inverting the NaN case.
   */
  bool AreGeomCameraVectorsEqual(const msvc8::vector<GeomCamera3>& lhs, const msvc8::vector<GeomCamera3>& rhs)
  {
    if (lhs.size() != rhs.size()) {
      return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i) {
      const GeomCamera3& a = lhs[i];
      const GeomCamera3& b = rhs[i];

      if (!(a.tranform.orient_ == b.tranform.orient_) || !(a.tranform.pos_ == b.tranform.pos_)) {
        return false;
      }
      if (!AreGalMatricesEqual(a.projection, b.projection) || !AreGalMatricesEqual(a.view, b.view)) {
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
  , mFocusArmy(-1)
  , mCurTick(0)
  , mAdvanced(false)
  , mStream(nullptr)
  , mNewGrids()
  , mArmyUpdates()
  , mNewEntities()
  , mNewUnits()
  , mEntityUpdates()
  , mUnitUpdates()
  , mDeleteIds()
  , mEraseIds()
  , mPublishedCommandDescriptors()
  , mPublishedCommandPackets()
  , mPendingCommandEventRemovals()
  , mPendingReleasedCommandIds()
  , mParticleBuffer()
  , mAddDecals()
  , mRemoveDecals()
  , mCamShakeParams()
  , mFollowCameras()
  , mAuxiliaryVector17()
  , mPoseUpdates()
  , mPlayableRectUpdates()
  , mDesyncs()
  , mPausedBy(-1)
  , mSubmitArmyStats()
  , mGameOver(false)
  , mFogOfWar(false)
  , mTerrainUpdate()
  , mSimResources()
  , mPrintField()
  , mInlineScratchVectors()
  , mTickDebugCanvas()
  , mBeatDebugCanvas()
{
  // Every owning lane above is a real member with a real constructor now, so
  // the teardown view no longer aliases uninitialised storage. Only the inline
  // audio-request queue still needs its hand-built storage seeded.
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
 * Address: 0x0067A290 (FUN_0067A290) tail (inlined push lane of Moho::Entity::SyncInterface)
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

/**
 * Address: 0x0073F940 (FUN_0073F940) - guard half only
 *
 * What it does:
 * Appends one sync-data payload. `CSimDriver::Sync` reaches this at
 * 0x0073DAD0's tail, immediately before it signals the availability event.
 *
 * DIVERGES from the binary on the null case. 0x0073F940 throws
 * `boost::bad_pointer` carrying "Null pointer in 'push_back()'" - it is the
 * guard boost's ptr_vector puts in front of the real insert at 0x007408F0.
 * This returns quietly instead, so a null payload is dropped and the waiter is
 * still woken with nothing queued.
 *
 * Not fixed here because `boost::bad_pointer` is only forward-declared in
 * `gpg/core/utils/BoostWrappers.h`. Its helpers are recovered
 * (`ConstructBadPointerFromCopy` 0x0049C140, `DestructBadPointer` 0x004913B0,
 * `GetBadPtrContainerMessage`), but the class itself has no definition to
 * throw. Define it there first, then make this throw.
 *
 * Note also that this queue is a hand-rolled ring buffer while the binary uses
 * a boost ptr_vector - the two are not the same container, so do not annotate
 * the insert half of this body with 0x007408F0.
 */
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
  , mNextIssueBeat(1)
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

  const auto createSimBootstrapProc = [](CSimDriver* const driver) { driver->ThreadCreateSim(); };
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

// Source-only adapter: binary wrappers write mNextIssueBeat to caller-provided out pointers.
void CSimDriver::ForwardCommandResultLocked()
{
  // The original methods return mNextIssueBeat via an out pointer.
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
  (void)mPendingSyncFilter.maskA.Equals(&block);
}

/**
 * Address: 0x0073B4B0 (FUN_0073B4B0), ISTIDriver slot 15
 * Replaces pending sync-filter mask block B when the incoming block differs.
 */
void CSimDriver::SetSyncFilterMaskB(const SSyncFilterMaskBlock& block)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  if (mPendingSyncFilter.maskB.Equals(&block)) {
    return;
  }

  CopySyncFilterMaskPayload(mPendingSyncFilter.maskB, block);
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
 * Address: 0x0073D260 (FUN_0073D260, Moho::CSimDrive::ThreadCreateSim)
 *
 * What it does:
 * Body of the bootstrap thread the constructor starts. Builds the simulation
 * from the launch info, hands the command stream to a fresh decoder and
 * registers it with the client manager, starts the issue thread, publishes an
 * opening sync, and then runs the driver's dispatch loop until shutdown. If
 * the simulation cannot be built it parks the driver in Stopped so callers
 * waiting on the state give up instead of hanging.
 *
 * The whole loop lives on this thread in the binary; `Dispatch` (slot 5) only
 * duplicates it for interlocked mode, where the caller drives beats itself.
 */
void CSimDriver::ThreadCreateSim()
{
  PinThisThreadToOneNumaNodeIfRequested();

  // The sim runs at reduced x87 precision so its arithmetic is bit-identical
  // on every machine in the game.
  (void)::_controlfp(_PC_24, _MCW_PC);
  gpg::SetThreadName(kCurrentThreadId, "Sim");
  TIME_SetTimeBarColor(kSimThreadTimeBarColor);

  {
    Sim* const previousSim = mSim;
    mSim = Sim_Create_exxt(boost::SharedPtrRawFromSharedBorrow(mLaunchInfo));
    if (previousSim != nullptr && previousSim != mSim) {
      delete previousSim;
    }
  }

  // The launch info was only needed to build the sim; the sim owns whatever it
  // kept from it.
  mLaunchInfo = boost::shared_ptr<LaunchInfoBase>{};

  if (mSim == nullptr) {
    boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
    SetStateAndNotify(EDriverState::Failed);
    return;
  }

  // The decoder takes the command stream and replays it into the sim.
  {
    msvc8::auto_ptr<gpg::Stream> commandStream(mStream);
    mStream = nullptr;

    CDecoder* const previousDecoder = mDecoder;
    mDecoder = new CDecoder(commandStream, mSim, mSim->mRules, mSim->mLuaState);
    delete previousDecoder;
  }
  mClientManager->PushReceiver(0u, kSimCommandMessageUpperBound, mDecoder);

  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));

  mSimThread = new boost::thread(
    BuildDeferredDriverCallback([](CSimDriver* const driver) { driver->ThreadRun(); }, this)
  );

  // The opening sync: the frame machine waits on it before it will leave
  // Initialize.
  FinalizeSyncDispatchLocked(lock);
  SetStateAndNotify(EDriverState::Ready);

  while (!mStopCreateSimThread) {
    if (mInterlockedMode) {
      // Interlocked mode drives beats from Dispatch() on the caller's thread.
      mStateChanged.wait(lock);
      continue;
    }

    if (mSaveGameRequest != nullptr && !mWantsToSave
        && (mState == EDriverState::Dispatching || mState == EDriverState::Ready)) {
      PreparePendingSaveRequestLocked(lock);
      continue;
    }

    if (mState != EDriverState::Dispatching) {
      mStateChanged.wait(lock);
      continue;
    }

    SetStateAndNotify(EDriverState::WaitingForMainThread);
    ExecuteDispatchStepLocked(lock);
    SetStateAndNotify(EDriverState::Ready);

    if (mState == EDriverState::Ready) {
      PromoteToDispatchingWhenBeatAvailable(0);
    }
  }

  SetStateAndNotify(EDriverState::Stopped);
}

/**
 * Address: 0x0073BDF0 (FUN_0073BDF0, Moho::CSimDriver::ThreadRun)
 *
 * What it does:
 * The "Issue" thread. Each pass beats the client manager, decides the last
 * beat it may issue, hands the marshaller the difference, promotes the driver
 * to Dispatching once the clients have supplied a beat, then sleeps on the
 * connection event until the next beat is due.
 *
 * Two pacing regimes, exactly as the binary splits them: while the sim is
 * blocked (`mSimBusy`) the thread follows what the other clients have already
 * partially queued, capped 98 beats ahead of the last executed one, and falls
 * back to a 250ms grace window measured from the first command it saw. Running
 * normally it paces off the negotiated sim rate, running `net_Lag`
 * milliseconds ahead of where the executed beat says it should be, and when it
 * has fallen behind it catches up by whole beats rather than waiting.
 */
void CSimDriver::ThreadRun()
{
  gpg::SetThreadName(kCurrentThreadId, "Issue");
  (void)SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
  TIME_SetTimeBarColor(kIssueThreadTimeBarColor);

  CTimeBarSection runningSection("IssueThread -- running");
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));

  if (sim_IssueThreadDebugLevel >= 1) {
    gpg::Debugf("ISSUE: thread running.");
  }

  while (!mStopSimThread) {
    mClientManager->DoBeat();

    int waitMilliseconds = kIssueThreadIdleWaitMs;
    const std::int64_t now = mTimer.ElapsedCycles();

    // Nothing is issued until the sim has published at least one sync, every
    // outstanding request has been answered, and the sync queue has room.
    if (mLastSyncCycleTime != 0 && mOutstandingRequests == 0
        && mSyncDataQueue.size < kMaxQueuedSyncPacketsBeforeStalling) {
      int lastBeatToIssue = mNextIssueBeat - 1;
      const int beatCeiling = mLastDequeuedBeat + kMaxBeatsAheadOfExecuted;

      if (mSimBusy) {
        int partiallyQueuedBeat = 0;
        mClientManager->GetPartiallyQueuedBeat(partiallyQueuedBeat);

        if (partiallyQueuedBeat < mNextIssueBeat) {
          // Nobody has queued the beat we are about to issue. Hold it back for
          // the grace window, then issue anyway so a quiet client cannot stall
          // everyone else indefinitely.
          if (mFirstCommandCycleTime != 0 && mNextIssueBeat <= beatCeiling) {
            const std::int64_t deadline =
              mFirstCommandCycleTime + gpg::time::MillisecondsToCycles(kBlockedIssueGraceMs);
            if (deadline >= now) {
              waitMilliseconds = static_cast<int>(gpg::time::CyclesToMilliseconds(deadline - now));
            } else {
              lastBeatToIssue = mNextIssueBeat;
            }
          }
        } else {
          lastBeatToIssue = std::min(partiallyQueuedBeat, beatCeiling);
        }
      } else {
        const float simRateScale = std::pow(10.0f, static_cast<float>(mClientManager->GetSimRate()) * 0.1f);
        const float millisecondsPerBeat = (0.1f / simRateScale) * 1000.0f;
        const float leadMilliseconds =
          static_cast<float>(mNextIssueBeat - mLastDequeuedBeat) * millisecondsPerBeat - net_Lag;
        const std::int64_t dueAt = mLastSyncCycleTime + gpg::time::MillisecondsToCycles(leadMilliseconds);

        if (dueAt >= now) {
          const float remaining = gpg::time::CyclesToMilliseconds(dueAt - now);
          waitMilliseconds = static_cast<int>(std::ceil(remaining));
        } else {
          // Behind schedule: issue however many whole beats have come due, but
          // never further ahead of the executed beat than two seconds' worth.
          const float lateMilliseconds = gpg::time::CyclesToMilliseconds(now - dueAt);
          const float lateBeats = (1.0f / millisecondsPerBeat) * lateMilliseconds;
          lastBeatToIssue = static_cast<int>(std::floor(lateBeats)) + mNextIssueBeat;

          int catchUpCeiling = static_cast<int>((1.0f / millisecondsPerBeat) * 2000.0f);
          if (catchUpCeiling > kMaxCatchUpBeats) {
            catchUpCeiling = kMaxCatchUpBeats;
          }
          if (lastBeatToIssue <= mLastDequeuedBeat + catchUpCeiling) {
            waitMilliseconds = 0;
          } else {
            lastBeatToIssue = mLastDequeuedBeat + catchUpCeiling;
          }
        }
      }

      if (lastBeatToIssue >= mNextIssueBeat) {
        mMarshaller->AdvanceBeat(lastBeatToIssue - mNextIssueBeat + 1);
        mNextIssueBeat = lastBeatToIssue + 1;
        mFirstCommandCycleTime = 0;
      }
    }

    if (mState == EDriverState::Ready) {
      PromoteToDispatchingWhenBeatAvailable(0);
    }

    if (waitMilliseconds != 0) {
      lock.unlock();
      if (sim_IssueThreadDebugLevel >= 2) {
        gpg::Debugf("ISSUE: thread waiting, timeout=%d.", waitMilliseconds);
      }
      {
        CTimeBarSection waitingSection("IssueThread -- waiting");
        (void)WaitForSingleObject(mConnectionEvent, static_cast<DWORD>(waitMilliseconds));
      }
      if (sim_IssueThreadDebugLevel >= 2) {
        const std::int64_t elapsedMicroseconds =
          gpg::time::CyclesToMicroseconds(mTimer.ElapsedCycles() - now);
        gpg::Debugf(
          "ISSUE: thread awaking, elapsed=%d.%03dms.",
          static_cast<int>(elapsedMicroseconds / 1000),
          static_cast<int>(elapsedMicroseconds % 1000)
        );
      }
      lock.lock();
    }
  }

  if (sim_IssueThreadDebugLevel >= 1) {
    gpg::Debugf("ISSUE: thread exiting.");
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
    *outCommandCookie = mNextIssueBeat;
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
    *outCommandCookie = mNextIssueBeat;
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
    *outCommandCookie = mNextIssueBeat;
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
 * (the binary writes `mNextIssueBeat` into a caller-provided out pointer).
 */
CmdId CSimDriver::DecreaseCommandCount(const CmdId id, const int count)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock));
  mMarshaller->DecreaseCommandCount(id, count);
  MarkFirstConnectionActivityLocked();
  return mNextIssueBeat;
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
 *
 * IDA signature:
 * void __thiscall Moho::CSimDriver::DrawNetworkStats(
 *     CSimDriver *this, CD3DPrimBatcher *batcher, float anchorX, float anchorY,
 *     float scaleX, float scaleY);
 *
 * What it does:
 * Builds the network-diagnostics HUD: an 8-column per-client table (index,
 * nickname, ping, maxsp, data, behind, avail, acks) plus a 4-line summary
 * block, measures per-column widths with a 10pt "Courier New" font, draws a
 * translucent backdrop quad, renders every cell right-justified, and strokes a
 * white 4-line border rectangle. Runs entirely under the driver lock.
 *
 * Note:
 * Several per-cell numeric columns reproduce genuine 2007 debug-HUD arithmetic
 * bugs 1:1 (documented inline). These are preserved deliberately.
 */
void CSimDriver::DrawNetworkStats(
  CD3DPrimBatcher* batcher, const float anchorX, const float anchorY, const float scaleX, const float scaleY
)
{
  boost::mutex::scoped_lock lock(DriverMutexRef(mLock)); // 0x0073E014 do_lock / 0x0073F40D unlock

  // 10pt Courier New font handle (0x0073E042). Held as a raw retained handle;
  // released explicitly at function exit (0x0073F3D3 releases the CountedPtr).
  boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(10, "Courier New");
  CD3DFont* const font = rawFont.px;

  const std::size_t numClients = mClientManager->NumberOfClients(); // 0x0073E057 (mgr slot 6)

  // ---- Table columns: 8 inner string vectors. 0x0073E052..0x0073E681.
  constexpr int kNumColumns = 8;
  std::vector<std::vector<msvc8::string>> columns(kNumColumns);

  // Header row (0x0073E098..0x0073E28F).
  columns[0].push_back(msvc8::string(""));        // 0x0073E098 index header (empty)
  columns[1].push_back(msvc8::string(""));        // 0x0073E0FA nickname header (empty)
  columns[2].push_back(msvc8::string(" ping"));   // 0x0073E14B
  columns[3].push_back(msvc8::string(" maxsp"));  // 0x0073E19C
  columns[4].push_back(msvc8::string(" data"));   // 0x0073E1ED
  columns[5].push_back(msvc8::string(" behind")); // 0x0073E23E
  columns[6].push_back(msvc8::string(" avail"));  // 0x0073E28F

  // Index column body: one " %3d" per client (0x0073E2F0..0x0073E357).
  for (std::size_t i = 0; i < numClients; ++i) {
    columns[0].push_back(gpg::STR_Printf(" %3d", static_cast<int>(i))); // 0x0073E310
  }

  // Per-client body rows (0x0073E367..0x0073E681).
  for (std::size_t i = 0; i < numClients; ++i) {
    IClient* const client = mClientManager->GetClient(static_cast<int>(i)); // 0x0073E374 (mgr slot 7)

    columns[7].push_back(gpg::STR_Printf("%d: ", static_cast<int>(i))); // 0x0073E38B (acks column label)
    columns[1].push_back(client->GetNickname());                        // 0x0073E3D0 (nickname)

    if (client->NoEjectionPending()) { // 0x0073E3DE (client slot 1)
      // Retail captures the latest-dispatched-remote beat here but never uses it.
      std::uint32_t latestBeatDispatchedRemote = 0;
      client->GetLatestBeatDispatchedRemote(latestBeatDispatchedRemote); // 0x0073E3F2 (client slot 5)
      (void)latestBeatDispatchedRemote; // value intentionally unused (matches retail)

      const float ping = client->GetStatusMetricA();          // 0x0073E3FB (client slot 2)
      columns[2].push_back(gpg::STR_Printf(" %7.3fms", ping)); // 0x0073E40D

      columns[3].push_back(gpg::STR_Printf(" %+3d", client->GetSimRate())); // 0x0073E455 (client slot 12)

      // "data" column (0x0073E489..0x0073E4BC).
      std::uint32_t queuedBeat = 0;
      client->GetQueuedBeat(queuedBeat); // 0x0073E495 (client slot 9)
      // Latent 2007 debug-HUD bug preserved 1:1 (see 0x0073E499): subtracts the
      // CSimDriver 'this' pointer from a beat counter.
      const int dataCell =
        static_cast<int>(queuedBeat - static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(this)));
      columns[4].push_back(gpg::STR_Printf(" %3d", dataCell)); // 0x0073E4A8

      // "behind" column (0x0073E4DC..0x0073E502).
      // Latent 2007 debug-HUD bug preserved 1:1 (see 0x0073E4E0): subtracts the
      // client count from the 'this' pointer.
      const int behindCell = static_cast<int>(
        static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(this)) - static_cast<std::uint32_t>(numClients));
      columns[5].push_back(gpg::STR_Printf(" %3d", behindCell)); // 0x0073E4EF

      // "avail" column (0x0073E522..0x0073E558).
      std::uint32_t availableBeatRemote = 0;
      client->GetAvailableBeatRemote(availableBeatRemote); // 0x0073E531 (client slot 6)
      // Latent 2007 debug-HUD bug preserved 1:1 (see 0x0073E535): the subtrahend
      // is an uninitialized stack dword in retail; reproduced here as 0.
      const std::uint32_t kUninitializedAvailSubtrahend = 0;
      const int availCell = static_cast<int>(availableBeatRemote - kUninitializedAvailSubtrahend);
      columns[6].push_back(gpg::STR_Printf(" %3d", availCell)); // 0x0073E544

      // "acks" column body (0x0073E578..0x0073E665).
      const msvc8::vector<int32_t>* const acks = client->GetLatestAcksVector(); // 0x0073E57F (client slot 4)
      if (!acks->empty()) {
        for (std::size_t j = 0; j < acks->size(); ++j) {
          // Latent 2007 debug-HUD bug preserved 1:1 (see 0x0073E5C0): subtracts the
          // address of the driver mutex cell from each ack value.
          const int ackCell = static_cast<int>(
            static_cast<std::uint32_t>((*acks)[j])
            - static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&mLock)));
          columns[7].push_back(gpg::STR_Printf(" %3d", ackCell)); // 0x0073E5D3
        }
      } else {
        columns[7].push_back(msvc8::string("")); // 0x0073E620 (empty ack cell)
      }
    } else {
      // Ejection pending: pad columns 2..6 with empty cells so row counts stay
      // aligned (0x0073E929..0x0073E9AB).
      for (int c = 2; c <= 6; ++c) {
        columns[c].push_back(msvc8::string("")); // 0x0073E96D
      }
    }
  }

  // ---- Summary block: 4 lines (0x0073E687..0x0073E876).
  std::vector<msvc8::string> summary;

  {
    int availableBeat = 0;
    mClientManager->GetAvailableBeat(availableBeat); // 0x0073E6BA (mgr slot 21)

    const int inflight = (mNextIssueBeat - 1) - availableBeat;   // 0x0073E6D1..0x0073E6D8
    const int available = availableBeat - (mDispatchBeat - 1);   // 0x0073E6BC..0x0073E6CF
    const int queued = static_cast<int>(mSyncDataQueue.size);    // 0x0073E6C6 (mSyncDataQueue.size @ CSimDriver+0xA0)
    summary.push_back(
      gpg::STR_Printf("inflight: %d, available: %d, queued: %d", inflight, available, queued)); // 0x0073E6EB
  }

  {
    const float medianDispatchMs = mSimSpeedSamples.Median(); // 0x0073E731 (NetSpeeds::Median, no args)
    summary.push_back(gpg::STR_Printf(
      "sim time: %.3f, max speed=%+d", static_cast<double>(medianDispatchMs), mCurrentSimRate)); // 0x0073E74E
  }

  {
    const int desiredSpeed = mClientManager->GetSimRateRequested(); // 0x0073E79E (mgr slot 15)
    const int actualSpeed = mClientManager->GetSimRate();           // 0x0073E792 (mgr slot 14)
    summary.push_back(
      gpg::STR_Printf("desired speed: %+d, actual speed: %+d", desiredSpeed, actualSpeed)); // 0x0073E7AB
  }

  {
    const SClientBottleneckInfo bottleneck = mClientManager->GetBottleneckInfo(); // 0x0073E7EB (mgr slot 24)
    msvc8::string bottleneckLabel;
    FormatBottleneckLabel(bottleneck, bottleneckLabel);                 // 0x0073E80F (FUN_0053B6B0)
    summary.push_back(msvc8::string("bottleneck: ") + bottleneckLabel); // 0x0073E859 operator+
  }

  // ---- Per-column max-advance measurement (0x0073E9BC..0x0073EB2F).
  // colWidths[c] = max advance across every cell in column c. GetAdvance's flags
  // argument is -1 (canonical "whole string" form; matches sibling HUDs).
  std::vector<float> colWidths(static_cast<std::size_t>(kNumColumns), 0.0f); // 0x0073E9CD

  // Running total table width, seeded with 6.0 (flt_E4F71C @0x0073E90E).
  float totalWidth = 6.0f;
  for (int c = 0; c < kNumColumns; ++c) {
    for (const msvc8::string& cell : columns[c]) {
      const float advance = font->GetAdvance(cell.c_str(), -1); // 0x0073EA68
      colWidths[static_cast<std::size_t>(c)] =
        std::max(colWidths[static_cast<std::size_t>(c)], advance); // 0x0073EA75..0x0073EA7F
    }
    totalWidth += colWidths[static_cast<std::size_t>(c)]; // 0x0073EA9B
  }

  // Summary lines are measured (advance + 3.0) into a running max, but the retail
  // frame overwrites that stack slot with the panel-bottom coordinate before it is
  // ever consumed -- so the result is dead. Preserved 1:1 (0x0073EAB6..0x0073EB2F,
  // slot reused at 0x0073EC10). Latent 2007 debug-HUD quirk.
  float summaryMax = 0.0f;
  for (const msvc8::string& line : summary) {
    const float advance = font->GetAdvance(line.c_str(), -1) + 3.0f; // 0x0073EB06/0x0073EB0B (flt_E4F718 == 3.0)
    summaryMax = std::max(summaryMax, advance);                      // 0x0073EB13..0x0073EB1A
  }
  (void)summaryMax; // dead in retail (overwritten by rectBottom before use)

  // ---- Backdrop rectangle geometry (0x0073EB2F..0x0073EC10).
  const int rowCount = static_cast<int>(columns[0].size());       // 0x0073EB2F..0x0073EB57
  const int summaryLineCount = static_cast<int>(summary.size());  // 0x0073EB59..0x0073EB80
  const int totalTextRows = rowCount + summaryLineCount;          // 0x0073EB82

  // Panel pixel height = mHeight*rows + mExternalLeading*(rows-1) + 6.0
  // (0x0073EB84..0x0073EBC4; the unsigned->float fixups are ordinary casts).
  const float tableHeight = font->mHeight * static_cast<float>(totalTextRows)
                            + font->mExternalLeading * static_cast<float>(totalTextRows - 1) + 6.0f;

  // Panel corners (floor() on the scaled extents). 0x0073EBC8..0x0073EC10.
  const float rectLeft = anchorX - std::floor(totalWidth * scaleX);  // 0x0073EBCC..0x0073EBD7
  const float rectRight = rectLeft + totalWidth;                     // 0x0073EBDE..0x0073EBE2
  const float rectTop = anchorY - std::floor(tableHeight * scaleY);  // 0x0073EBED..0x0073EBF8
  const float rectBottom = rectTop + tableHeight;                    // 0x0073EC0C..0x0073EC10

  // ---- Backdrop quad (semi-transparent black over a white texture). 0x0073EC14..0x0073ED81.
  {
    const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu); // 0x0073EC14
    batcher->SetTexture(whiteTex);                                                                       // 0x0073EC29

    constexpr std::uint32_t kBackdropColor = 0x80000000u; // 0x0073EC85
    const CD3DPrimBatcher::Vertex topLeft{rectLeft, rectTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex topRight{rectRight, rectTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomRight{rectRight, rectBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomLeft{rectLeft, rectBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
    batcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft); // 0x0073ED81
  }

  // ---- Text rendering (0x0073EDAD..0x0073F0B2).
  // Glyph pen advances along +X; the row axis advances down-screen. The retail
  // frame threads these vectors and the glyph-scale scalar through registers in a
  // way that could not be pinned to specific lanes from the disassembly.
  const Vector3f xAxis{1.0f, 0.0f, 0.0f}; // ds:a7 == 1.0 (glyph advance basis)
  // UNRESOLVED: yAxis lane values not provable from the register-threaded Render
  // frame (asm 0x0073EE0E..0x0073EE77 / 0x0073EFCB..0x0073F047). Using the
  // canonical down-screen row axis from sibling HUD Render call sites.
  const Vector3f yAxis{0.0f, 1.0f, 0.0f};
  constexpr std::uint32_t kTextColor = 0xFFFFFFFFu; // 0x0073EE04 (a5 == 0xFFFFFFFF)
  // UNRESOLVED: glyph-scale scalar. Retail loads flt_E4F6E8 (-1.0) and a7 (1.0)
  // into adjacent scalar/vector lanes (asm 0x0073EDF2 / 0x0073EE17); the exact
  // scalar passed to Render's glyphScale param is not provable from this frame.
  // Using 0.0f ("natural glyph size") to match sibling debug-HUD Render sites.
  constexpr float kGlyphScale = /* UNRESOLVED: Render glyphScale, asm 0x0073EE1F */ 0.0f;
  // Render's maxAdvance sentinel is the "NaN_206" global (asm 0x0073EDEC /
  // 0x0073EF9F) -- a quiet NaN meaning "no advance limit", matching sibling
  // debug-HUD Render call sites.
  const float kNoMaxAdvance = std::numeric_limits<float>::quiet_NaN();

  // Shared pen Y: the summary block renders first (top), then the per-client
  // table continues BELOW it from the same running Y (retail preserves the pen
  // Y across both loops; 0x0073EED0 clears only the row/column counters).
  const float rowStep = font->mExternalLeading + font->mHeight; // 0x0073EEAC / 0x0073F088
  float penY = rectTop + font->mAscent + 3.0f; // 0x0073ED86..0x0073EDB6 (mAscent @ CD3DFont+0x14)

  // Summary lines, left-anchored at rectLeft+3 (loop over var_DC). 0x0073EDAD..0x0073EED0.
  for (const msvc8::string& line : summary) {
    const Vector3f origin{rectLeft + 3.0f, penY, 0.0f}; // 0x0073EE28..0x0073EE6E
    (void)font->Render(
      line.c_str(), batcher, origin, xAxis, yAxis, kTextColor, kGlyphScale, kNoMaxAdvance); // 0x0073EEA7
    penY += rowStep; // 0x0073EEAC..0x0073EEC5
  }

  // Per-client table, drawn row-major (outer = rows bounded by the index column,
  // inner = the 8 columns). Loop over var_C0. 0x0073EEE0..0x0073F0B2.
  //   - X starts at rectLeft+3 each row and accumulates each column's measured
  //     width; columns 0..1 are left-anchored, columns >=2 right-justified.
  //   - Y advances by one row height per outer iteration.
  const std::size_t tableRowCount = columns[0].size(); // outer trip = len(columns[0]) (0x0073EEF2..0x0073EF08)
  for (std::size_t row = 0; row < tableRowCount; ++row) {
    float cellX = rectLeft + 3.0f; // running X base, reset per row (0x0073EF22..0x0073EF44)
    for (int c = 0; c < kNumColumns; ++c) {
      const std::vector<msvc8::string>& column = columns[static_cast<std::size_t>(c)];
      // The retail grid is rectangular (all data columns carry one row per
      // client); shorter columns simply contribute an empty cell for the tail
      // rows rather than reading past their storage.
      const msvc8::string cell = (row < column.size()) ? column[row] : msvc8::string();

      float originX;
      if (c < 2) {
        // Index/nickname columns are left-anchored (0x0073EF53 jb).
        originX = cellX;
      } else {
        // Numeric columns are right-justified within their slot (0x0073EF81..0x0073EF94).
        const float advance = font->GetAdvance(cell.c_str(), -1); // 0x0073EF7C
        originX = cellX + colWidths[static_cast<std::size_t>(c)] - advance;
      }

      const Vector3f origin{originX, penY, 0.0f}; // 0x0073F009..0x0073F01B
      (void)font->Render(
        cell.c_str(), batcher, origin, xAxis, yAxis, kTextColor, kGlyphScale, kNoMaxAdvance); // 0x0073F056

      cellX += colWidths[static_cast<std::size_t>(c)]; // running X += column width (0x0073F05F..0x0073F064)
    }
    penY += rowStep; // per-row Y advance (0x0073F088..0x0073F0A7)
  }

  // ---- Border rectangle: 4 white edges over a white texture. 0x0073F0B2..0x0073F365.
  {
    const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu); // 0x0073F0BE
    batcher->SetTexture(whiteTex);                                                                       // 0x0073F0D3

    constexpr std::uint32_t kBorderColor = 0xFFFFFFFFu; // esi == 0xFFFFFFFF (0x0073F0B2)
    const CD3DPrimBatcher::Vertex tl{rectLeft, rectTop, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex tr{rectRight, rectTop, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex br{rectRight, rectBottom, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bl{rectLeft, rectBottom, 0.0f, kBorderColor, 0.0f, 0.0f};

    batcher->DrawLine(tl, tr); // 0x0073F1A6 (top edge)
    batcher->DrawLine(tr, br); // 0x0073F23C (right edge)
    batcher->DrawLine(br, bl); // 0x0073F2D2 (bottom edge)
    batcher->DrawLine(bl, tl); // 0x0073F365 (left edge)
  }

  // Release the retained font handle (0x0073F3D3..0x0073F3F9).
  rawFont.release();
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
