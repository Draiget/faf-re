#pragma once

#include "EClientMsg.h"
#include "ECmdStreamOp.h"
#include "ELobbyMsg.h"

namespace moho
{
  // Dispatcher ranges are half-open [lower, upper), per CMessageDispatcher::PushReceiver.
  //
  // Binary evidence for these exact bounds:
  // - FA 0x0053BB60 / Moho 0x10129420 (CNetClient ctor PushReceiver setup)
  //   - [0,50), [50,60), [200,210)
  // - FA 0x007C5CA0 (CLobby::ConnectionMade)
  //   - [100,120)

  // Sim command stream: 0..49
  constexpr unsigned MSGTYPE_SimBase = static_cast<unsigned>(ECmdStreamOp::CMDST_Advance);
  constexpr unsigned MSGTYPE_SimEnd = static_cast<unsigned>(EClientMsg::CLIMSG_Ack);

  // Client/replay control: 50..59
  constexpr unsigned MSGTYPE_ClientBase = static_cast<unsigned>(EClientMsg::CLIMSG_Ack);
  constexpr unsigned MSGTYPE_ClientEnd = 60u;

  // Lobby protocol/handshake: 100..119
  constexpr unsigned MSGTYPE_LobbyMsgStart = static_cast<unsigned>(ELobbyMsg::LOBMSG_Join);
  constexpr unsigned MSGTYPE_LobbyMsgEnd = static_cast<unsigned>(ELobbyMsg::LOBMSG_LobbyMsgEnd);

  // Connection lifecycle events: 200..209
  constexpr unsigned MSGTYPE_LobbyBase = static_cast<unsigned>(ELobbyMsg::LOBMSG_ConnFailed);
  constexpr unsigned MSGTYPE_LobbyEnd = static_cast<unsigned>(ELobbyMsg::LOBMSG_ConnMsgEnd);
} // namespace moho
