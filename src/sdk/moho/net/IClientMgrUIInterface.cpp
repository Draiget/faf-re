#include "moho/net/IClientMgrUIInterface.h"

#include "moho/net/CClientBase.h"

namespace moho
{
  /**
   * Address: 0x0088B6D0 (FUN_0088B6D0, Moho::IClientMgrUIInterface::NoteDisconnect)
   *
   * What it does:
   * Default UI callback lane for disconnect notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteDisconnect(const CClientBase* const client)
  {
    (void)client;
  }

  /**
   * Address: 0x0088B6E0 (FUN_0088B6E0, Moho::IClientMgrUIInterface::Func2)
   *
   * What it does:
   * Default UI callback lane for eject-request notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteEjectRequest(const CClientBase* const requester, const CClientBase* const target)
  {
    (void)requester;
    (void)target;
  }

  /**
   * Address: 0x0088B6F0 (FUN_0088B6F0, Moho::IClientMgrUIInterface::ReceiveChat)
   *
   * What it does:
   * Default UI callback lane for inbound chat payload notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReceiveChat(const CClientBase* const sender, const gpg::MemBuffer<const char> data)
  {
    (void)sender;
    (void)data;
  }

  /**
   * Address: 0x0088B700 (FUN_0088B700, Moho::IClientMgrUIInterface::NoteGameSpeedChange)
   *
   * What it does:
   * Default UI callback lane for game-speed updates (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteGameSpeedChanged()
  {}

  /**
   * Address: 0x0088B710 (FUN_0088B710, Moho::IClientMgrUIInterface::ReportBottleneck)
   *
   * What it does:
   * Default UI callback lane for bottleneck notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneck()
  {}

  /**
   * Address: 0x0088B720 (FUN_0088B720, Moho::IClientMgrUIInterface::ReportBottleneckCleared)
   *
   * What it does:
   * Default UI callback lane for bottleneck-clear notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneckCleared()
  {}
} // namespace moho
