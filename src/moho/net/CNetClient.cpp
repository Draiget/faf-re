#include "CNetClient.h"

#include <mutex>

#include "CClientManagerImpl.h"
#include "Common.h"
#include "ECmdStreamOp.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "moho/misc/DiagnosticBudget.h"
#include "NetConVars.h"

using namespace moho;

/**
 * Address: 0x0053BB60 (FUN_0053BB60)
 * Address: 0x10129420 (sub_10129420)
 */
CNetClient::CNetClient(
  const int32_t index,
  CClientManagerImpl* manager,
  const char* name,
  const int32_t ownerId,
  BVIntSet& commandSources,
  const uint32_t sourceId,
  INetConnection* connection
)
  : CClientBase(index, manager, name, ownerId, commandSources, sourceId)
  , IMessageReceiver()
  , mConnection(connection)
{
  auto* const dispatcher = static_cast<CMessageDispatcher*>(mConnection);
  dispatcher->PushReceiver(MSGTYPE_SimBase, MSGTYPE_SimEnd, this);
  dispatcher->PushReceiver(MSGTYPE_ClientBase, MSGTYPE_ClientEnd, this);
  dispatcher->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
}

/**
 * Address: 0x0053BC20 (FUN_0053BC20, scalar deleting destructor)
 * Address: 0x0053BC70 (FUN_0053BC70, the same base teardown without the delete)
 * Address: 0x101294E0 (sub_101294E0)
 *
 * What it does:
 * Nothing of its own: `~IMessageReceiver` on the +0xD8 base, then
 * `~CClientBase`.
 */
CNetClient::~CNetClient() = default;

/**
 * Address: 0x0053DC30 (FUN_0053DC30)
 * Address: 0x1012AFF0 (sub_1012AFF0)
 */
float CNetClient::GetStatusMetricA()
{
  std::scoped_lock lock(mManager->mLock);
  return mConnection ? mConnection->GetPing() : 0.0f;
}

/**
 * Address: 0x0053DCC0 (FUN_0053DCC0)
 * Address: 0x1012B080 (sub_1012B080)
 */
float CNetClient::GetStatusMetricB()
{
  std::scoped_lock lock(mManager->mLock);
  return mConnection ? mConnection->GetTime() : -1.0f;
}

/**
 * Address: 0x0053DD60 (FUN_0053DD60)
 * Address: 0x1012B120 (sub_1012B120)
 */
void CNetClient::Process(
  CMessage& msg
)
{
  std::scoped_lock lock(mManager->mLock);
  if (mConnection == nullptr) {
    return;
  }

  const auto bytes = static_cast<int>(msg.mBuff.Size());
  const auto elapsedUs = gpg::time::CyclesToMicroseconds(mManager->mTimer3.ElapsedCycles());
  mManager->mStampBuffer.Push(0, elapsedUs, bytes);

  // Engine addition, test only (net_DebugAlterOrdersTo, off by default): the
  // checksum reports this client sends to one player differ from the ones
  // everyone else gets, which is what a player sending different orders to
  // different players looks like to CommandStreamCheck.
  if (net_DebugAlterOrdersTo == mIndex && msg.GetType().raw() == static_cast<uint8_t>(ECmdStreamOp::CMDST_VerifyChecksum) &&
      msg.GetMessageSize() > 0) {
    CMessage altered = msg;
    altered.mBuff[3] = static_cast<char>(altered.mBuff[3] ^ 0x01); // first checksum byte
    NetDataSpan alteredSpan{
      reinterpret_cast<uint8_t*>(altered.mBuff.start_),
      reinterpret_cast<uint8_t*>(altered.mBuff.end_),
    };
    mConnection->Write(&alteredSpan);
    return;
  }

  NetDataSpan span{
    reinterpret_cast<uint8_t*>(msg.mBuff.start_),
    reinterpret_cast<uint8_t*>(msg.mBuff.end_),
  };
  mConnection->Write(&span);
}

/**
 * Address: 0x0053DE20 (FUN_0053DE20)
 * Address: 0x1012B1D0 (sub_1012B1D0)
 */
void CNetClient::Open()
{
  if (mConnection != nullptr) {
    mConnection->ScheduleDestroy();
    mConnection = nullptr;
  }
}

/**
 * Address: 0x0053DE50 (FUN_0053DE50)
 * Address: 0x1012B200 (sub_1012B200)
 */
void CNetClient::Debug()
{
  gpg::Logf("    CNetClient %p:", static_cast<const void*>(this));
  CClientBase::Debug();
}

/**
 * Address: 0x0053DE70 (FUN_0053DE70)
 * Address: 0x1012B220 (sub_1012B220)
 */
void CNetClient::ReceiveMessage(
  CMessage* message,
  CMessageDispatcher* dispatcher
)
{
  (void)dispatcher;

  std::scoped_lock lock(mManager->mLock);
  const auto bytes = static_cast<int>(message->mBuff.Size());
  const auto elapsedUs = gpg::time::CyclesToMicroseconds(mManager->mTimer3.ElapsedCycles());
  mManager->mStampBuffer.Push(1, elapsedUs, bytes);

  // Engine addition, not in the binary: `CMDST_EndGame` is never sent to a
  // peer -- `CClientManagerImpl::Disconnect` closes every remote connection
  // before it broadcasts it, so it only ever reaches the local stream. Taken
  // from the wire it went through `UpdateState` into every sim, where
  // `Sim::EndGame` froze the game for all players and `CDecoder` closed the
  // replay recording. It is dropped here, on every receiver alike.
  if (message->GetType().raw() == static_cast<uint8_t>(ECmdStreamOp::CMDST_EndGame)) {
    static DiagnosticBudget sEndGameWarnings;
    if (sEndGameWarnings.Take(20)) {
      gpg::Warnf("Ignoring end-game command from client %d:%s.", mIndex, mNickname.c_str());
    }
    return;
  }

  CClientBase::Process(*message);
}
