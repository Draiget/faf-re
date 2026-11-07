#include "remote/ServerClient.h"

#include <mutex>
#include <utility>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/EClientMsg.h"

namespace faf::remote
{
  namespace
  {
    // Each refused op is logged this many times per seat, as a player can send them at will.
    constexpr std::uint64_t kRefusalsLoggedPerOp = 3u;
  } // namespace

  bool SeatMaySend(const moho::ECmdStreamOp op) noexcept
  {
    switch (op) {
    case moho::ECmdStreamOp::CMDST_RequestPause:
    case moho::ECmdStreamOp::CMDST_Resume:
    case moho::ECmdStreamOp::CMDST_ProcessInfoPair:
    case moho::ECmdStreamOp::CMDST_IssueCommand:
    case moho::ECmdStreamOp::CMDST_IssueFactoryCommand:
    case moho::ECmdStreamOp::CMDST_IncreaseCommandCount:
    case moho::ECmdStreamOp::CMDST_DecreaseCommandCount:
    case moho::ECmdStreamOp::CMDST_SetCommandTarget:
    case moho::ECmdStreamOp::CMDST_SetCommandType:
    case moho::ECmdStreamOp::CMDST_SetCommandCells:
    case moho::ECmdStreamOp::CMDST_RemoveCommandFromQueue:
    case moho::ECmdStreamOp::CMDST_LuaSimCallback:
      return true;
    case moho::ECmdStreamOp::CMDST_Advance:
    case moho::ECmdStreamOp::CMDST_SetCommandSource:
    case moho::ECmdStreamOp::CMDST_CommandSourceTerminated:
    case moho::ECmdStreamOp::CMDST_VerifyChecksum:
    case moho::ECmdStreamOp::CMDST_SingleStep:
    case moho::ECmdStreamOp::CMDST_CreateUnit:
    case moho::ECmdStreamOp::CMDST_CreateProp:
    case moho::ECmdStreamOp::CMDST_DestroyEntity:
    case moho::ECmdStreamOp::CMDST_WarpEntity:
    case moho::ECmdStreamOp::CMDST_DebugCommand:
    case moho::ECmdStreamOp::CMDST_ExecuteLuaInSim:
    case moho::ECmdStreamOp::CMDST_EndGame:
      return false;
    }
    return false;
  }

  CServerClient::CServerClient(
    moho::CClientManagerImpl& manager, const char* const name, const std::int32_t index, const std::int32_t ownerId,
    moho::BVIntSet& sources, const std::uint32_t sourceId
  )
    : CClientBase(index, &manager, name, ownerId, sources, sourceId)
  {}

  CServerClient& CServerClient::Create(
    moho::CClientManagerImpl& manager, const char* const name, const std::int32_t index, const std::int32_t ownerId,
    const std::uint32_t sourceId
  )
  {
    moho::BVIntSet sources{};
    sources.Add(sourceId);
    auto* const seat = new CServerClient(manager, name, index, ownerId, sources, sourceId);
    manager.mClients[static_cast<std::size_t>(index)] = seat;
    return *seat;
  }

  void CServerClient::Process(moho::CMessage& message)
  {
    std::scoped_lock lock(mManager->mLock);

    const std::uint8_t type = message.GetType().raw();
    if (type == static_cast<std::uint8_t>(moho::EClientMsg::CLIMSG_Ack)) {
      CClientBase::Process(message);
      return;
    }
    if (type != static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_Advance) || mEjectPending) {
      return;
    }

    moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadOnly);
    gpg::BinaryReader reader(&stream);
    std::int32_t beats = 0;
    reader.ReadExact(beats);

    // One at a time: the hook puts each beat's commands ahead of that beat.
    for (std::int32_t beat = 0; beat < beats; ++beat) {
      if (mBeatHook) {
        mBeatHook(*this, static_cast<std::int32_t>(mQueuedBeat));
      }
      if (mEjectPending) {
        return;
      }
      moho::CMessage one(moho::ECmdStreamOp::CMDST_Advance);
      moho::CMessageStream oneStream(one);
      const std::int32_t delta = 1;
      oneStream.Write(delta);
      CClientBase::Process(one);
    }
  }

  void CServerClient::Debug()
  {
    gpg::Logf("    CServerClient %p:", static_cast<const void*>(this));
    CClientBase::Debug();
  }

  bool CServerClient::ReceiveCommand(moho::CMessage& message, std::int32_t* const beat)
  {
    std::scoped_lock lock(mManager->mLock);

    const std::uint8_t type = message.GetType().raw();
    const auto op = static_cast<moho::ECmdStreamOp>(type);
    if (type >= kOpCount || !SeatMaySend(op)) {
      const std::size_t slot = type < kOpCount ? type : 0u;
      if (++mRefused[slot] <= kRefusalsLoggedPerOp) {
        gpg::Logf("Seat %d:%s: refused message type %d from its player", mIndex, mNickname.c_str(), static_cast<int>(type));
      }
      return false;
    }
    if (mEjectPending || mEjected) {
      return false;
    }
    CClientBase::Process(message);
    if (beat != nullptr) {
      *beat = static_cast<std::int32_t>(mQueuedBeat);
    }
    return true;
  }

  void CServerClient::AppendFromServer(moho::CMessage& message)
  {
    std::scoped_lock lock(mManager->mLock);
    CClientBase::Process(message);
  }

  void CServerClient::MarkLoaded()
  {
    std::scoped_lock lock(mManager->mLock);
    moho::CMessage ready(moho::EClientMsg::CLIMSG_Ready);
    CClientBase::Process(ready);
  }

  void CServerClient::SetBeatHook(BeatHook hook)
  {
    std::scoped_lock lock(mManager->mLock);
    mBeatHook = std::move(hook);
  }
} // namespace faf::remote
