#include "SimDriver.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <exception>
#include <new>

#include "moho/app/WxAppRuntime.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CClientManagerImpl.h"
#include "Sim.h"

using namespace moho;

namespace
{
  bool gSimInterlocked = false;
  ISTIDriver* gActiveSimDriver = nullptr;

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
} // namespace

void SSyncData::QueuePendingCommandEventRemoval(const CmdId commandId)
{
  mPendingCommandEventRemovals.push_back(commandId);
}

SSyncDataQueue::~SSyncDataQueue()
{
  ClearAndDelete();
  delete[] map;
  map = nullptr;
  mapSize = 0;
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
    auto** newMap = new SSyncData*[newCap];
    for (uint32_t i = 0; i < newCap; ++i) {
      newMap[i] = nullptr;
    }

    for (uint32_t i = 0; i < size; ++i) {
      newMap[i] = map[(head + i) % mapSize];
    }

    delete[] map;
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

void SSyncDataQueue::ClearAndDelete()
{
  while (!Empty()) {
    delete PopFront();
  }
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
  mPendingSyncFilter.focusArmy = static_cast<int32_t>(commandSourceId);
  mActiveSyncFilter.focusArmy = static_cast<int32_t>(commandSourceId);

  mConnectionEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  mSyncDataAvailableEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  mClientManager->SelectEvent(mConnectionEvent);

  mMarshaller = new CMarshaller(mClientManager);
  mMarshaller->SetCommandSource(commandSourceId);

  // 0x0073D260 creates the simulation bootstrap thread. The full function
  // still depends on additional lifted classes; for now we preserve state flow.
  mCreateSimThread = new boost::thread([this]() {
    boost::mutex::scoped_lock lock(mLock.lock);
    if (mStopCreateSimThread) {
      mState = EDriverState::Stopped;
      mStateChanged.notify_all();
      return;
    }

    mState = EDriverState::Ready;
    mStateChanged.notify_all();
  });
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
 * Copies pending filter state into active state and queues one sync packet.
 */
void CSimDriver::FinalizeSyncDispatchLocked(const int32_t beatToDispatch)
{
  mActiveSyncFilter.CopyFrom(mPendingSyncFilter);

  if (!mSim) {
    return;
  }

  // Sim::Sync (0x007474B0) is partially lifted; keep a defensive beat-only
  // fallback packet so queue/event flow remains stable during wider recovery.
  SSyncData* syncData = nullptr;
  mSim->Sync(mActiveSyncFilter, syncData);
  if (!syncData) {
    syncData = new SSyncData{};
    syncData->mCurBeat = beatToDispatch;
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

  FinalizeSyncDispatchLocked(beatToDispatch);

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
  boost::mutex::scoped_lock lock(mLock.lock);
  if (mPendingSyncFilter.focusArmy == armyIndex) {
    return;
  }

  mPendingSyncFilter.focusArmy = armyIndex;
  MarkFirstConnectionActivityLocked();
}

/**
 * Address: 0x0073B240 (FUN_0073B240), ISTIDriver slot 16
 * Updates the pending sync-filter option flag.
 */
void CSimDriver::SetSyncFilterOptionFlag(const bool value)
{
  boost::mutex::scoped_lock lock(mLock.lock);
  mPendingSyncFilter.optionFlag = value;
}

/**
 * Address: 0x0073B270 (FUN_0073B270), ISTIDriver slot 13
 * Replaces pending sync-filter cameras only when content differs.
 */
void CSimDriver::SetGeomCams(const msvc8::vector<GeomCamera3>& geoCams)
{
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
  (void)SSyncFilterMaskBlock::Equals(mPendingSyncFilter.maskA, block);
}

/**
 * Address: 0x0073B4B0 (FUN_0073B4B0), ISTIDriver slot 15
 * Replaces pending sync-filter mask block B when the incoming block differs.
 */
void CSimDriver::SetSyncFilterMaskB(const SSyncFilterMaskBlock& block)
{
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
  mClientManager->Disconnect();
  MarkFirstConnectionActivityLocked();
}

/**
 * Address: 0x0073BC80 (FUN_0073BC80), ISTIDriver slot 2
 * Stops worker threads, shuts down the sim, and releases the live sim object.
 */
void CSimDriver::ShutDown()
{
  boost::mutex::scoped_lock lock(mLock.lock);

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
  boost::mutex::scoped_lock lock(mLock.lock);

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
  boost::mutex::scoped_lock lock(mLock.lock);
  ++mOutstandingRequests;
}

/**
 * Address: 0x0073C440 (FUN_0073C440), ISTIDriver slot 7
 * Decrements outstanding requests; timestamps when the counter reaches zero and signals the connection event.
 */
void CSimDriver::DecrementOutstandingRequestsAndSignal()
{
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
  return !mSyncDataQueue.Empty();
}

/**
 * Address: 0x0073C520 (FUN_0073C520), ISTIDriver slot 9
 * Waits for, pops, and returns the next sync packet.
 */
void CSimDriver::GetSyncData(SSyncData*& outSyncData)
{
  outSyncData = nullptr;

  boost::mutex::scoped_lock lock(mLock.lock);
  while (mSyncDataQueue.Empty()) {
    lock.unlock();
    PerformNextEvent();
    lock.lock();
  }

  outSyncData = mSyncDataQueue.PopFront();
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
 * Address: 0x0073C660 (FUN_0073C660), ISTIDriver slot 17
 * Marshals CMDST_RequestPause and reports command-cookie result.
 */
void CSimDriver::RequestPause()
{
  boost::mutex::scoped_lock lock(mLock.lock);
  mMarshaller->RequestPause();
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073C700 (FUN_0073C700), ISTIDriver slot 18
 * Marshals CMDST_Resume and reports command-cookie result.
 */
void CSimDriver::Resume()
{
  boost::mutex::scoped_lock lock(mLock.lock);
  mMarshaller->Resume();
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073C7A0 (FUN_0073C7A0), ISTIDriver slot 19
 * Marshals CMDST_SingleStep and reports command-cookie result.
 */
void CSimDriver::SingleStep()
{
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
  mMarshaller->IncreaseCommandCount(id, count);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CD50 (FUN_0073CD50), ISTIDriver slot 28
 * Marshals CMDST_DecreaseCommandCount and reports command-cookie result.
 */
void CSimDriver::DecreaseCommandCount(const CmdId id, const int count)
{
  boost::mutex::scoped_lock lock(mLock.lock);
  mMarshaller->DecreaseCommandCount(id, count);
  MarkFirstConnectionActivityLocked();
  ForwardCommandResultLocked();
}

/**
 * Address: 0x0073CDF0 (FUN_0073CDF0), ISTIDriver slot 29
 * Marshals CMDST_SetCommandTarget and reports command-cookie result.
 */
void CSimDriver::SetCommandTarget(const CmdId id, const SSTITarget& target)
{
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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
  boost::mutex::scoped_lock lock(mLock.lock);
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

  boost::mutex::scoped_lock lock(mLock.lock);
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
    boost::mutex::scoped_lock lock(mLock.lock);
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

ISTIDriver* moho::SIM_DetachActiveDriver()
{
  ISTIDriver* const detached = gActiveSimDriver;
  gActiveSimDriver = nullptr;
  return detached;
}
