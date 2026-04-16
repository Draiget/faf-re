#include "CClientManagerImpl.h"
#include "CLocalClient.h"
#include "CMessage.h"
#include "CMessageStream.h"
#include "CNetClient.h"
#include "CNullClient.h"
#include "CReplayClient.h"
#include "EClientMsg.h"
#include "ECmdStreamOp.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "INetConnector.h"
#include "moho/containers/BVIntSet.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SOCellPos.h"

using namespace moho;
namespace
{
  float GetBottleneckUiTimestampMs(const CClientManagerImpl& manager)
  {
    float out = 0.0f;
    std::memcpy(&out, &manager.mTimer2.mTime, sizeof(out));
    return out;
  }

  void SetBottleneckUiTimestampMs(CClientManagerImpl& manager, const float value)
  {
    std::memcpy(&manager.mTimer2.mTime, &value, sizeof(value));
  }

  /**
   * Address: 0x0053EE40 (FUN_0053EE40, func_ClientNeedsPartiallyQueuedBeatsUntil)
   *
   * What it does:
   * Returns whether at least one non-ejection-pending client is already
   * ejected/eject-pending or has queued through `beat`.
   */
  bool ClientNeedsPartiallyQueuedBeatsUntil(CClientManagerImpl& manager, const int beat)
  {
    const std::size_t count = manager.mClients.size();
    if (count == 0u) {
      return false;
    }

    for (std::size_t index = 0; index < count; ++index) {
      CClientBase* const client = manager.mClients[index];
      if (client->NoEjectionPending()) {
        if (client->mEjected || client->mEjectPending || ((beat - static_cast<int>(client->mQueuedBeat)) <= 0)) {
          return true;
        }
      }
    }

    return false;
  }
} // namespace

/**
 * Address: <synthetic host-build helper>
 */
CMarshaller::CMarshaller() = default;

/**
 * Address: 0x006E5A60 (FUN_006E5A60)
 *
 * What it does:
 * Initializes marshaller vtable and binds owner client-manager pointer.
 */
CMarshaller::CMarshaller(CClientManagerImpl* manager)
  : mClientManager(manager)
{}

/**
 * Address: 0x0053B680 (FUN_0053B680)
 *
 * What it does:
 * Runs interface-base teardown for `IClientManager`.
 */
IClientManager::~IClientManager() = default;

/**
 * Address: 0x0053DF20 (FUN_0053DF20)
 *
 * What it does:
 * Initializes client-manager runtime state, client vector storage, and
 * timing/connectivity lanes.
 */
CClientManagerImpl::CClientManagerImpl(
  const std::size_t clientCount,
  INetConnector* const connector,
  const int gameSpeed,
  const bool adjustableGameSpeed
)
  : mLock()
  , mInterface(nullptr)
  , mClients()
  , mConnector(connector)
  , mLocalClient(nullptr)
  , mWeAreReady(false)
  , mEveryoneIsReady(false)
  , mDispatchedBeat(0)
  , mAvailableBeat(0)
  , mFullyQueuedBeat(0)
  , mPartiallyQueuedBeat(0)
  , mGameSpeedClock(0)
  , mGameSpeedRequester(0)
  , mGameSpeed(gameSpeed)
  , mAdjustableGameSpeed(adjustableGameSpeed)
  , mCurrentEvent(nullptr)
  , gap(0)
  , mTimer3()
  , mStampBuffer()
  , mStream()
  , mMarshaller()
  , mDispatchedTimer()
  , mTimer2()
{
  ListResetLinks();
  std::memset(mReceivers, 0, sizeof(mReceivers));
  mClients.resize(clientCount, nullptr);
}

/**
 * Address: 0x0053FAF0 (FUN_0053FAF0)
 *
 * What it does:
 * Allocates and constructs one `CClientManagerImpl`.
 */
CClientManagerImpl* moho::CLIENT_CreateClientManager(
  const std::size_t clientCount,
  INetConnector* const connector,
  const int gameSpeed,
  const bool adjustableGameSpeed
)
{
  return new CClientManagerImpl(clientCount, connector, gameSpeed, adjustableGameSpeed);
}

/**
 * Address: 0x006E5A90 (FUN_006E5A90)
 * Address: 0x102C0F90
 */
void CMarshaller::SetCommandSource(const CommandSourceId sourceId)
{
  CMessage message{ECmdStreamOp::CMDST_SetCommandSource};
  CMessageStream stream{message};
  const auto sourceByte = static_cast<std::uint8_t>(sourceId);
  stream.Write(sourceByte);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E5B90 (FUN_006E5B90)
 * Address: 0x102C1090
 */
void CMarshaller::OnCommandSourceTerminated()
{
  CMessage message{ECmdStreamOp::CMDST_CommandSourceTerminated};
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E5C70 (FUN_006E5C70)
 * Address: 0x102C1170
 */
void CMarshaller::VerifyChecksum(const gpg::MD5Digest& digest, const CSeqNo seqNo)
{
  CMessage message{ECmdStreamOp::CMDST_VerifyChecksum};
  CMessageStream stream{message};
  stream.Write(reinterpret_cast<const char*>(&digest), sizeof(digest));
  stream.Write(seqNo);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E5DB0 (FUN_006E5DB0)
 * Address: 0x102C1270
 */
void CMarshaller::RequestPause()
{
  CMessage message{ECmdStreamOp::CMDST_RequestPause};
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E5E90 (FUN_006E5E90)
 * Address: 0x102C1350
 */
void CMarshaller::Resume()
{
  CMessage message{ECmdStreamOp::CMDST_Resume};
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E5F70 (FUN_006E5F70)
 * Address: 0x102C1430
 */
void CMarshaller::SingleStep()
{
  CMessage message{ECmdStreamOp::CMDST_SingleStep};
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6050 (FUN_006E6050)
 * Address: 0x102C1510
 */
void CMarshaller::CreateUnit(
  const std::uint32_t armyIndex, const RResId& blueprintId, const SCoordsVec2& pos, const float heading
)
{
  CMessage message{ECmdStreamOp::CMDST_CreateUnit};
  CMessageStream stream{message};
  const auto armyByte = static_cast<std::uint8_t>(armyIndex);
  stream.Write(armyByte);
  stream.Write(blueprintId.name);
  stream.Write(reinterpret_cast<const char*>(&pos), sizeof(pos));
  stream.Write(heading);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E61E0 (FUN_006E61E0)
 * Address: 0x102C1660
 */
void CMarshaller::CreateProp(const char* blueprintPath, const Wm3::Vec3f& pos)
{
  CMessage message{ECmdStreamOp::CMDST_CreateProp};
  CMessageStream stream{message};
  stream.Write(blueprintPath);
  stream.Write(reinterpret_cast<const char*>(&pos), sizeof(pos));
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6320 (FUN_006E6320)
 * Address: 0x102C1780
 */
void CMarshaller::DestroyEntity(const EntId entityId)
{
  CMessage message{ECmdStreamOp::CMDST_DestroyEntity};
  CMessageStream stream{message};
  stream.Write(entityId);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6420 (FUN_006E6420)
 * Address: 0x102C1880
 */
void CMarshaller::WarpEntity(const EntId entityId, const VTransform& transform)
{
  CMessage message{ECmdStreamOp::CMDST_WarpEntity};
  CMessageStream stream{message};
  stream.Write(entityId);
  stream.Write(reinterpret_cast<const char*>(&transform), sizeof(transform));
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6560 (FUN_006E6560)
 * Address: 0x102C1990
 */
void CMarshaller::ProcessInfoPair(void* id, const char* key, const char* val)
{
  CMessage message{ECmdStreamOp::CMDST_ProcessInfoPair};
  CMessageStream stream{message};
  const auto entityId = static_cast<EntId>(reinterpret_cast<std::uintptr_t>(id));
  stream.Write(entityId);
  stream.Write(key);
  stream.Write(val);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6690 (FUN_006E6690)
 * Address: 0x102C1AD0
 */
void CMarshaller::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandData, const bool clear
)
{
  CMessage message{ECmdStreamOp::CMDST_IssueCommand};
  CMessageStream stream{message};
  WriteEntIdSet(stream, entities);
  WriteCommandData(stream, commandData);
  const auto clearByte = static_cast<std::uint8_t>(clear);
  stream.Write(clearByte);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E67D0 (FUN_006E67D0)
 * Address: 0x102C1BF0
 */
void CMarshaller::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandData, const bool clear
)
{
  CMessage message{ECmdStreamOp::CMDST_IssueFactoryCommand};
  CMessageStream stream{message};
  WriteEntIdSet(stream, entities);
  WriteCommandData(stream, commandData);
  const auto clearByte = static_cast<std::uint8_t>(clear);
  stream.Write(clearByte);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6910 (FUN_006E6910)
 * Address: 0x102C1D10
 */
void CMarshaller::IncreaseCommandCount(const CmdId cmdId, const int count)
{
  CMessage message{ECmdStreamOp::CMDST_IncreaseCommandCount};
  CMessageStream stream{message};
  stream.Write(cmdId);
  stream.Write(count);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6A40 (FUN_006E6A40)
 * Address: 0x102C1E20
 */
void CMarshaller::DecreaseCommandCount(const CmdId cmdId, const int count)
{
  CMessage message{ECmdStreamOp::CMDST_DecreaseCommandCount};
  CMessageStream stream{message};
  stream.Write(cmdId);
  stream.Write(count);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6B70 (FUN_006E6B70)
 * Address: 0x102C1F30
 */
void CMarshaller::SetCommandTarget(const CmdId cmdId, const SSTITarget& target)
{
  CMessage message{ECmdStreamOp::CMDST_SetCommandTarget};
  CMessageStream stream{message};
  stream.Write(cmdId);
  WriteTarget(stream, target);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6C90 (FUN_006E6C90)
 * Address: 0x102C2040
 */
void CMarshaller::SetCommandType(const CmdId cmdId, const EUnitCommandType type)
{
  CMessage message{ECmdStreamOp::CMDST_SetCommandType};
  CMessageStream stream{message};
  stream.Write(cmdId);
  const auto typeWord = static_cast<std::int32_t>(type);
  stream.Write(typeWord);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6DD0 (FUN_006E6DD0)
 * Address: 0x102C2150
 */
void CMarshaller::SetCommandCells(
  const CmdId cmdId, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& pos
)
{
  CMessage message{ECmdStreamOp::CMDST_SetCommandCells};
  CMessageStream stream{message};
  stream.Write(cmdId);
  WriteCells(stream, cells);
  stream.Write(reinterpret_cast<const char*>(&pos), sizeof(pos));
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E6F30 (FUN_006E6F30)
 * Address: 0x102C22A0
 */
void CMarshaller::RemoveCommandFromUnitQueue(const CmdId cmdId, const EntId entityId)
{
  CMessage message{ECmdStreamOp::CMDST_RemoveCommandFromQueue};
  CMessageStream stream{message};
  stream.Write(cmdId);
  stream.Write(entityId);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E7070 (FUN_006E7070)
 * Address: 0x102C23B0
 */
void CMarshaller::ExecuteDebugCommand(
  const char* commandText,
  const Wm3::Vector3<float>& worldPos,
  const std::uint32_t armyIndex,
  const BVSet<EntId, EntIdUniverse>& entities
)
{
  CMessage message{ECmdStreamOp::CMDST_DebugCommand};
  CMessageStream stream{message};
  stream.Write(commandText);
  stream.Write(reinterpret_cast<const char*>(&worldPos), sizeof(worldPos));
  const auto armyByte = static_cast<std::uint8_t>(armyIndex);
  stream.Write(armyByte);
  WriteEntIdSet(stream, entities);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E71F0 (FUN_006E71F0)
 * Address: 0x102C24F0
 */
void CMarshaller::ExecuteLuaInSim(const char* functionName, const LuaPlus::LuaObject& args)
{
  CMessage message{ECmdStreamOp::CMDST_ExecuteLuaInSim};
  CMessageStream stream{message};
  stream.Write(functionName);
  if (!const_cast<LuaPlus::LuaObject&>(args).ToByteStream(stream)) {
    gpg::Die("Unable to marshal lua args");
  }
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E7300 (FUN_006E7300)
 * Address: 0x102C2620
 */
void CMarshaller::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  CMessage message{ECmdStreamOp::CMDST_LuaSimCallback};
  CMessageStream stream{message};
  stream.Write(callbackName);
  if (!const_cast<LuaPlus::LuaObject&>(args).ToByteStream(stream)) {
    gpg::Die("Unable to marshal lua function %s", callbackName);
  }
  WriteEntIdSet(stream, entities);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E7420 (FUN_006E7420)
 * Address: 0x102C2760
 */
void CMarshaller::AdvanceBeat(const int beatDelta)
{
  CMessage message{ECmdStreamOp::CMDST_Advance};
  CMessageStream stream{message};
  stream.Write(beatDelta);
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E7520 (FUN_006E7520)
 * Address: 0x102C2860
 */
void CMarshaller::EndGame()
{
  CMessage message{ECmdStreamOp::CMDST_EndGame};
  mClientManager->ProcessClients(message);
}

/**
 * Address: 0x006E7600 (FUN_006E7600)
 * Address: 0x102C2940
 */
void CMarshaller::WriteEntIdSet(CMessageStream& stream, const BVSet<EntId, EntIdUniverse>& entities)
{
  const BVIntSet& bits = entities.Bits();

  const auto count = static_cast<std::int32_t>(bits.Count());
  stream.Write(count);

  entities.ForEachValue([&stream](const unsigned int value) {
    const auto entityId = static_cast<EntId>(value);
    stream.Write(entityId);
  });
}

/**
 * Address: 0x006E76C0 (FUN_006E76C0)
 * Address: 0x102C29D0
 */
void CMarshaller::WriteCommandData(CMessageStream& stream, const SSTICommandIssueData& commandData)
{
  stream.Write(commandData.nextCommandId);
  stream.Write(commandData.unk04);

  const auto commandTypeByte = static_cast<std::uint8_t>(commandData.mCommandType);
  stream.Write(commandTypeByte);
  stream.Write(commandData.mIndex);

  WriteTarget(stream, commandData.mTarget);
  WriteTarget(stream, commandData.mTarget2);

  stream.Write(commandData.unk38);
  if (commandData.unk38 != -1) {
    stream.Write(reinterpret_cast<const char*>(&commandData.mOri), sizeof(commandData.mOri));
    stream.Write(commandData.unk4C);
  }

  if (commandData.mBlueprint != nullptr) {
    stream.Write(commandData.mBlueprint->mBlueprintId);
  } else {
    stream.Write("");
  }

  WriteCells(stream, commandData.mCells);
  stream.Write(commandData.unk70);
  stream.Write(commandData.unk74);
  (void)const_cast<LuaPlus::LuaObject&>(commandData.mObject).ToByteStream(stream);
}

/**
 * Address: 0x006E7890 (FUN_006E7890)
 * Address: 0x102C2B20
 */
void CMarshaller::WriteTarget(CMessageStream& stream, const SSTITarget& target)
{
  const auto targetTypeWord = static_cast<std::int32_t>(target.mType);
  const auto targetTypeByte = static_cast<std::uint8_t>(targetTypeWord);
  stream.Write(targetTypeByte);

  if (targetTypeWord == static_cast<std::int32_t>(EAiTargetType::AITARGET_Entity)) {
    stream.Write(target.mEntityId);
  } else if (targetTypeWord == static_cast<std::int32_t>(EAiTargetType::AITARGET_Ground)) {
    stream.Write(reinterpret_cast<const char*>(&target.mPos), sizeof(target.mPos));
  }
}

/**
 * Address: 0x006E7940 (FUN_006E7940)
 * Address: <inlined in MohoEngine WriteCommandData/SetCommandCells>
 */
void CMarshaller::WriteCells(CMessageStream& stream, const gpg::core::FastVector<SOCellPos>& cells)
{
  const auto count = static_cast<std::int32_t>(cells.Size());
  stream.Write(count);

  if (count > 0) {
    stream.Write(reinterpret_cast<const char*>(cells.start_), static_cast<std::size_t>(count) * sizeof(SOCellPos));
  }
}

/**
 * Address: 0x0053E050 (FUN_0053E050, scalar deleting dtor thunk)
 * Address: 0x0053E090 (FUN_0053E090, non-deleting destructor core)
 *
 * What it does:
 * Destroys owned clients, tears down connector ownership, and leaves
 * remaining member/base teardown to C++ destruction order.
 */
CClientManagerImpl::~CClientManagerImpl()
{
  mMarshaller.mClientManager = nullptr;

  for (CClientBase*& client : mClients) {
    delete client;
    client = nullptr;
  }
  mLocalClient = nullptr;

  if (mConnector != nullptr) {
    mConnector->Destroy();
    mConnector = nullptr;
  }

  mClients.clear();
}

/**
 * Address: 0x0053E180 (FUN_0053E180)
 */
IClient* CClientManagerImpl::CreateLocalClient(
  const char* name, const int32_t index, const int32_t ownerId, const uint32_t sourceId
)
{
  BVIntSet commandSources{};
  commandSources.Add(sourceId);

  const auto client = new CLocalClient(index, this, name, ownerId, commandSources, sourceId);
  mLocalClient = client;
  mClients[index] = client;
  return client;
}

/**
 * Address: 0x0053E260 (FUN_0053E260)
 */
IClient* CClientManagerImpl::CreateNetClient(
  const char* name,
  const int32_t index,
  const int32_t ownerId,
  const uint32_t sourceId,
  INetConnection* connection
)
{
  BVIntSet commandSources{};
  commandSources.Add(sourceId);

  const auto client = new CNetClient(index, this, name, ownerId, commandSources, sourceId, connection);
  mClients[index] = client;
  return client;
}

/**
 * Address: 0x0053E330 (FUN_0053E330)
 */
IClient* CClientManagerImpl::CreateNullClient(
  const char* name, const int32_t index, const int32_t ownerId, const uint32_t sourceId
)
{
  BVIntSet commandSources{};
  commandSources.Add(sourceId);

  const auto client = new CNullClient(index, this, name, ownerId, commandSources, sourceId);
  mClients[index] = client;
  return client;
}

/**
 * Address: 0x0053E400 (FUN_0053E400)
 */
IClient* CClientManagerImpl::CreateReplayClient(gpg::Stream** replayStreamStorage, BVIntSet* set)
{
  const auto client = new CReplayClient(this, *set, *replayStreamStorage);
  if (mClients.empty()) {
    mClients.resize(1, nullptr);
  }
  mClients[0] = client;
  return client;
}

/**
 * Address: 0x0053BCB0 (FUN_0053BCB0)
 */
INetConnector* CClientManagerImpl::GetConnector()
{
  std::scoped_lock lock(mLock);
  return mConnector;
}

/**
 * Address: 0x0053BCC0 (FUN_0053BCC0)
 */
size_t CClientManagerImpl::NumberOfClients()
{
  std::scoped_lock lock(mLock);
  return mClients.size();
}

/**
 * Address: 0x0053BCE0 (FUN_0053BCE0)
 */
IClient* CClientManagerImpl::GetClient(const int idx)
{
  std::scoped_lock lock(mLock);
  if (idx < 0 || static_cast<size_t>(idx) >= mClients.size()) {
    return nullptr;
  }
  return mClients[static_cast<size_t>(idx)];
}

/**
 * Address: 0x0053E470 (FUN_0053E470)
 */
IClient* CClientManagerImpl::GetClientWithData(const int32_t ownerId)
{
  std::scoped_lock lock(mLock);
  for (CClientBase* const client : mClients) {
    if (client != nullptr && client->GetOwnerId() == ownerId) {
      return client;
    }
  }
  return nullptr;
}

/**
 * Address: 0x0053BD10 (FUN_0053BD10)
 */
IClient* CClientManagerImpl::GetLocalClient()
{
  std::scoped_lock lock(mLock);
  return mLocalClient;
}

/**
 * Address: 0x0053BD20 (FUN_0053BD20)
 */
void CClientManagerImpl::SetUIInterface(IClientMgrUIInterface* clientMgrInterface)
{
  std::scoped_lock lock(mLock);
  mInterface = clientMgrInterface;
}

/**
 * Address: 0x0053BD30 (FUN_0053BD30)
 */
IClientMgrUIInterface* CClientManagerImpl::GetUIInterface() const
{
  return mInterface;
}

/**
 * Address: 0x0053E4B0 (FUN_0053E4B0)
 */
void CClientManagerImpl::Cleanup()
{
  {
    std::scoped_lock lock(mLock);
    mWeAreReady = true;
    mDispatchedTimer.Reset();
  }

  CMessage message{EClientMsg::CLIMSG_Ready};
  ProcessClients(message);
}

/**
 * Address: 0x0053E560 (FUN_0053E560)
 */
bool CClientManagerImpl::IsEveryoneReady()
{
  std::scoped_lock lock(mLock);
  return mEveryoneIsReady;
}

/**
 * Address: 0x0053E590 (FUN_0053E590)
 */
void CClientManagerImpl::SetSimRate(const int rate)
{
  if (!mAdjustableGameSpeed) {
    return;
  }

  std::scoped_lock lock(mLock);
  CMessage message{EClientMsg::CLIMSG_AdjustSimSpeed};
  CMessageStream stream{message};
  const int nextClock = mGameSpeedClock + 1;
  stream.Write(nextClock);
  stream.Write(rate);
  ProcessClients(message);
}

/**
 * Address: 0x0053E720 (FUN_0053E720)
 */
int CClientManagerImpl::GetSimRate()
{
  std::scoped_lock lock(mLock);
  int simRate = mGameSpeed;
  for (CClientBase* const client : mClients) {
    if (client == nullptr || !client->NoEjectionPending()) {
      continue;
    }

    const int clientRate = client->GetSimRate();
    if (clientRate < simRate) {
      simRate = clientRate;
    }
  }

  return simRate;
}

/**
 * Address: 0x0053E7E0 (FUN_0053E7E0)
 */
int CClientManagerImpl::GetSimRateRequested()
{
  std::scoped_lock lock(mLock);
  return mGameSpeed;
}

/**
 * Address: 0x0053E850 (FUN_0053E850)
 *
 * What it does:
 * Broadcasts `CLIMSG_IntParam` with a 32-bit payload to all managed clients.
 */
void CClientManagerImpl::BroadcastIntParam(const int value)
{
  std::scoped_lock lock(mLock);
  CMessage message{EClientMsg::CLIMSG_IntParam};
  CMessageStream stream{message};
  stream.Write(value);
  ProcessClients(message);
}

/**
 * Address: 0x0053E990 (FUN_0053E990)
 */
void CClientManagerImpl::ProcessClients(CMessage& msg)
{
  std::scoped_lock lock(mLock);
  for (CClientBase* const client : mClients) {
    if (client != nullptr) {
      client->Process(msg);
    }
  }
}

/**
 * Address: 0x0053EEC0 (FUN_0053EEC0)
 *
 * What it does:
 * Returns whether all non-ejected clients have queued data through `beat`.
 * Clients in eject-pending state are probed for oldest-eject bookkeeping but
 * do not block advancement.
 */
bool CClientManagerImpl::ClientNeedsFullyQueuedBeatsUntil(const int beat)
{
  const std::size_t count = mClients.size();
  if (count == 0u) {
    return true;
  }

  for (std::size_t index = 0; index < count; ++index) {
    CClientBase* const client = mClients[index];
    if (client->mEjected) {
      continue;
    }

    if (client->mEjectPending) {
      int ignoredMostExpiredBeat = beat;
      client->GetMostExpiredEjectRequest(ignoredMostExpiredBeat);
      continue;
    }

    if (beat > static_cast<int>(client->mQueuedBeat)) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x0053EF30 (FUN_0053EF30, Moho::CClientManagerImpl::EveryoneResponsiveSince)
 *
 * What it does:
 * Returns whether every managed client is responsive for the requested beat.
 */
bool CClientManagerImpl::EveryoneResponsiveSince(const int beat)
{
  const std::size_t count = mClients.size();
  if (count == 0u) {
    return true;
  }

  for (std::size_t index = 0; index < count; ++index) {
    if (!mClients[index]->IsReadyForBeat(beat)) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x0053EA30 (FUN_0053EA30)
 */
void CClientManagerImpl::DoBeat()
{
  std::scoped_lock lock(mLock);

  // Binary toggles this slot during DoBeat as a re-entrancy/event guard.
  mMarshaller.mClientManager = this;

  if (mConnector != nullptr) {
    mConnector->Pull();
  }

  if (mWeAreReady && !mEveryoneIsReady) {
    bool everyoneReady = true;
    for (const CClientBase* const client : mClients) {
      if (client != nullptr && !client->mReady) {
        everyoneReady = false;
        break;
      }
    }
    if (everyoneReady) {
      mEveryoneIsReady = true;
    }
  }

  if (ClientNeedsPartiallyQueuedBeatsUntil(*this, mPartiallyQueuedBeat + 1)) {
    if (mPartiallyQueuedBeat == mDispatchedBeat) {
      mDispatchedTimer.Reset();
    }
    do {
      ++mPartiallyQueuedBeat;
    } while (ClientNeedsPartiallyQueuedBeatsUntil(*this, mPartiallyQueuedBeat + 1));
  }

  if (ClientNeedsFullyQueuedBeatsUntil(mFullyQueuedBeat + 1)) {
    if (mFullyQueuedBeat == mDispatchedBeat) {
      mDispatchedTimer.Reset();
    }
    do {
      ++mFullyQueuedBeat;
    } while (ClientNeedsFullyQueuedBeatsUntil(mFullyQueuedBeat + 1));
  }

  if (EveryoneResponsiveSince(mAvailableBeat + 1)) {
    do {
      ++mAvailableBeat;
    } while (EveryoneResponsiveSince(mAvailableBeat + 1));

    CMessage message{EClientMsg::CLIMSG_Available};
    CMessageStream stream{message};
    stream.Write(mAvailableBeat);
    ProcessClients(message);
  }

  const SClientBottleneckInfo bottleneckInfo = GetBottleneckInfo();
  const float currentUiBottleneckTimeMs = GetBottleneckUiTimestampMs(*this);
  if (((bottleneckInfo.mType == SClientBottleneckInfo::Nothing) ||
       (currentUiBottleneckTimeMs > bottleneckInfo.mFloat)) &&
      currentUiBottleneckTimeMs != 0.0f) {
    if (mInterface != nullptr) {
      mInterface->ReportBottleneckCleared();
    }
    SetBottleneckUiTimestampMs(*this, 0.0f);
  }

  const float uiBottleneckTimeMs = GetBottleneckUiTimestampMs(*this);
  if ((bottleneckInfo.mType != SClientBottleneckInfo::Nothing) &&
      (bottleneckInfo.mFloat >= uiBottleneckTimeMs + 5000.0f)) {
    SetBottleneckUiTimestampMs(*this, bottleneckInfo.mFloat);
    if (mInterface != nullptr) {
      mInterface->ReportBottleneck();
    }
  }

  if (!mClients.empty()) {
    auto* const replayClient = dynamic_cast<CReplayClient*>(mClients[0]);
    if (replayClient != nullptr) {
      replayClient->Start();
    }
  }

  mMarshaller.mClientManager = nullptr;
}

/**
 * Address: 0x0053EDA0 (FUN_0053EDA0)
 */
void CClientManagerImpl::SelectEvent(HANDLE ev)
{
  std::scoped_lock lock(mLock);
  if (mConnector != nullptr) {
    mConnector->SelectEvent(ev);
  }
  mCurrentEvent = ev;
}

/**
 * Address: 0x0053EF90 (FUN_0053EF90)
 */
void CClientManagerImpl::GetPartiallyQueuedBeat(int& out)
{
  std::scoped_lock lock(mLock);
  out = mPartiallyQueuedBeat;
}

/**
 * Address: 0x0053EFD0 (FUN_0053EFD0)
 */
void CClientManagerImpl::GetAvailableBeat(int& out)
{
  std::scoped_lock lock(mLock);
  out = mAvailableBeat;
}

/**
 * Address: 0x0053F010 (FUN_0053F010)
 */
void CClientManagerImpl::UpdateStates(const int beat)
{
  {
    std::scoped_lock lock(mLock);

    for (CClientBase* const client : mClients) {
      if (client != nullptr) {
        client->UpdateState(beat, &mMarshaller, &mStream);
      }
    }

    CMessage dispatchedMessage{EClientMsg::CLIMSG_Dispatched};
    CMessageStream dispatchedStream{dispatchedMessage};
    dispatchedStream.Write(beat);
    ProcessClients(dispatchedMessage);
    ++mDispatchedBeat;

    if (mDispatchedBeat == mAvailableBeat) {
      mDispatchedTimer.Reset();
    }
  }

  mStream.VirtFlush();

  while (mStream.GetLength() != 0u) {
    CMessage nextMessage{};
    if (!nextMessage.ReadMessage(&mStream)) {
      break;
    }
    Dispatch(&nextMessage);
  }

  CMessage beatMessage{ECmdStreamOp::CMDST_Advance};
  CMessageStream beatStream{beatMessage};
  const int beatDelta = 1;
  beatStream.Write(beatDelta);
  Dispatch(&beatMessage);
}

/**
 * Address: 0x0053F4C0 (FUN_0053F4C0)
 */
SSendStampView CClientManagerImpl::GetBetween(const int since)
{
  std::scoped_lock lock(mLock);
  const auto nowUs = static_cast<uint64_t>(mTimer3.ElapsedMicroseconds());
  const auto sinceUs = since > 0 ? static_cast<uint64_t>(since) * 1000ULL : 0ULL;
  return mStampBuffer.GetBetween(nowUs, sinceUs);
}

/**
 * Address: 0x0053F5A0 (FUN_0053F5A0)
 */
SClientBottleneckInfo CClientManagerImpl::GetBottleneckInfo()
{
  std::scoped_lock lock(mLock);

  SClientBottleneckInfo out{};
  if (!mWeAreReady) {
    out.mType = SClientBottleneckInfo::Nothing;
    return out;
  }

  if (!mEveryoneIsReady) {
    out.mType = SClientBottleneckInfo::Readiness;
    for (size_t index = 0; index < mClients.size(); ++index) {
      const CClientBase* const client = mClients[index];
      if (client != nullptr && !client->mReady) {
        out.mSubobj.Add(static_cast<unsigned int>(index));
      }
    }
  } else if (mAvailableBeat > mDispatchedBeat || mPartiallyQueuedBeat == mDispatchedBeat) {
    out.mType = SClientBottleneckInfo::Nothing;
    return out;
  } else if (mFullyQueuedBeat <= mAvailableBeat) {
    out.mType = SClientBottleneckInfo::Data;
    const int targetBeat = mAvailableBeat + 1;
    for (size_t index = 0; index < mClients.size(); ++index) {
      const CClientBase* const client = mClients[index];
      if (client == nullptr || client->mEjected) {
        continue;
      }

      if (client->mEjectPending) {
        int expiredEjectBeat = 0;
        client->GetMostExpiredEjectRequest(expiredEjectBeat);
        if (targetBeat > expiredEjectBeat) {
          out.mSubobj.Add(static_cast<unsigned int>(index));
        }
        continue;
      }

      if (targetBeat > static_cast<int>(client->mQueuedBeat)) {
        out.mSubobj.Add(static_cast<unsigned int>(index));
      }
    }
  } else {
    out.mType = SClientBottleneckInfo::Ack;
    const int targetBeat = mAvailableBeat + 1;
    for (size_t index = 0; index < mClients.size(); ++index) {
      const CClientBase* const client = mClients[index];
      if (client != nullptr && !client->IsReadyForBeat(targetBeat)) {
        out.mSubobj.Add(static_cast<unsigned int>(index));
      }
    }
  }

  out.mVal = mAvailableBeat + 1;
  out.mFloat = static_cast<float>(mDispatchedTimer.ElapsedMilliseconds());
  return out;
}

/**
 * Address: 0x0053F920 (FUN_0053F920)
 */
void CClientManagerImpl::Debug()
{
  std::scoped_lock lock(mLock);

  gpg::Logf("CClientManagerImpl 0x%08x:", this);
  gpg::Logf("  mWeAreReady=%s", mWeAreReady ? "true" : "false");
  gpg::Logf("  mEveryoneIsReady=%s", mEveryoneIsReady ? "true" : "false");
  gpg::Logf("  mDispatchedBeat=%d", mDispatchedBeat);
  gpg::Logf("  mAvailableBeat=%d", mAvailableBeat);
  gpg::Logf("  mFullyQueuedBeat=%d", mFullyQueuedBeat);
  gpg::Logf("  mPartiallyQueuedBeat=%d", mPartiallyQueuedBeat);
  gpg::Logf("  mGameSpeedClock=%d", mGameSpeedClock);
  gpg::Logf("  mGameSpeedRequester=%d", mGameSpeedRequester);
  gpg::Logf("  mGameSpeed=%d", mGameSpeed);
  gpg::Logf("  mAdjustableGameSpeed=%s", mAdjustableGameSpeed ? "true" : "false");
  gpg::Logf("  mClients.size()=%d", static_cast<int>(mClients.size()));

  for (size_t index = 0; index < mClients.size(); ++index) {
    CClientBase* const client = mClients[index];
    if (client != nullptr) {
      gpg::Logf("  mClients[%d]=0x%08x", static_cast<int>(index), client);
      client->Debug();
    }
  }

  if (mConnector != nullptr) {
    mConnector->Debug();
  }
}

/**
 * Address: 0x0053F830 (FUN_0053F830)
 */
void CClientManagerImpl::Disconnect()
{
  std::scoped_lock lock(mLock);
  for (CClientBase* const client : mClients) {
    if (client != nullptr && client != mLocalClient) {
      client->Open();
    }
  }

  CMessage message{ECmdStreamOp::CMDST_EndGame};
  ProcessClients(message);
}
