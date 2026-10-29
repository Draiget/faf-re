#include "moho/net/IClientMgrUIInterface.h"

#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/net/CClientBase.h"

namespace moho
{

  /**
   * Address: 0x0088B6C0 (FUN_0088B6C0)
   * Address: 0x0088BB90 (FUN_0088BB90)
   *
   * What it does:
   * Restores the base vtable in `sCWldUiInterface`; the two emissions of this
   * destructor for that one object.
   */
  IClientMgrUIInterface::~IClientMgrUIInterface() = default;

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
  void IClientMgrUIInterface::NoteEjectRequest(const CClientBase* const target, const CClientBase* const requester)
  {
    (void)target;
    (void)requester;
  }

  /**
   * Address: 0x0088B6F0 (FUN_0088B6F0, Moho::IClientMgrUIInterface::ReceiveChat)
   *
   * What it does:
   * Default UI callback lane for inbound chat payload notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReceiveChat(const CClientBase* const sender, const gpg::MemBuffer<const char>& data)
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
  void IClientMgrUIInterface::NoteGameSpeedChanged(const CClientBase* const client, const std::int32_t gameSpeed)
  {
    (void)client;
    (void)gameSpeed;
  }

  /**
   * Address: 0x0088B710 (FUN_0088B710, Moho::IClientMgrUIInterface::ReportBottleneck)
   *
   * What it does:
   * Default UI callback lane for bottleneck notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneck(const SClientBottleneckInfo& info)
  {
    (void)info;
  }

  /**
   * Address: 0x0088B720 (FUN_0088B720, Moho::IClientMgrUIInterface::ReportBottleneckCleared)
   *
   * What it does:
   * Default UI callback lane for bottleneck-clear notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneckCleared()
  {}

  /**
   * Engine addition, not in the binary: no-op default (see the header).
   */
  void IClientMgrUIInterface::NoteOrdersDiffer(
    const msvc8::string& sender, const msvc8::string& reporter, const bool selfReport, const bool stopped
  )
  {
    (void)sender;
    (void)reporter;
    (void)selfReport;
    (void)stopped;
  }


} // namespace moho
