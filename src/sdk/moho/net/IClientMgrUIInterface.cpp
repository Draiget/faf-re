#include "moho/net/IClientMgrUIInterface.h"

#include "moho/net/CClientBase.h"

#include <cstddef>
#include <new>

namespace
{
  alignas(moho::IClientMgrUIInterface) std::byte gClientMgrUiInterfaceStorage[sizeof(moho::IClientMgrUIInterface)]{};

  [[nodiscard]] moho::IClientMgrUIInterface* ClientMgrUiInterfaceBootstrapObject() noexcept
  {
    return reinterpret_cast<moho::IClientMgrUIInterface*>(gClientMgrUiInterfaceStorage);
  }
}

namespace moho
{
  /**
   * Address: 0x0088B6C0 (FUN_0088B6C0)
   *
   * What it does:
   * Re-initializes the static client-manager UI interface bootstrap storage so
   * the base-interface vtable lane is restored.
   */
  [[maybe_unused]] void InitializeClientMgrUiInterfaceBootstrapLaneA()
  {
    ::new (ClientMgrUiInterfaceBootstrapObject()) IClientMgrUIInterface();
  }

  /**
   * Address: 0x0088BB90 (FUN_0088BB90)
   *
   * What it does:
   * Duplicate bootstrap lane that re-initializes the same static client-manager
   * UI interface storage.
   */
  [[maybe_unused]] void InitializeClientMgrUiInterfaceBootstrapLaneB()
  {
    ::new (ClientMgrUiInterfaceBootstrapObject()) IClientMgrUIInterface();
  }

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
