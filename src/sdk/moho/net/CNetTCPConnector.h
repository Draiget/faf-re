#pragma once

#include <cstdint>

#include "INetConnector.h"
#include "moho/containers/TDatList.h"
#include "platform/Platform.h"

namespace gpg
{
  class PipeStream;
}

namespace moho
{
  class CNetTCPConnection;
  struct STcpPartialConnection;

  struct STcpConnWorkList
  {
    STcpConnWorkList* next{nullptr};
  };
  static_assert(sizeof(STcpConnWorkList) == 0x4, "STcpConnWorkList size must be 0x4");

  /**
   * VFTABLE: 0x00E049C0
   * COL:     0x00E60BE8
   */
  class CNetTCPConnector : public INetConnector
  {
  public:
    /**
     * Address: 0x00484AE0 (FUN_00484AE0)
     * Address: 0x1007E6E0 (sub_1007E6E0)
     * Slot: 0
     *
     * What it does:
     * Deletes all TCP connections/partials and closes listening socket.
     */
    ~CNetTCPConnector() override;

    /**
     * Address: 0x00483600 (FUN_00483600)
     * Address: 0x1007D3F0 (sub_1007D3F0)
     * Slot: 1
     *
     * What it does:
     * Self-destruct helper (equivalent to deleting this connector).
     */
    void Destroy() override;

    /**
     * Address: 0x00483610 (FUN_00483610)
     * Address: 0x1007D400 (sub_1007D400)
     * Slot: 2
     *
     * What it does:
     * Returns TCP protocol tag.
     */
    ENetProtocolType GetProtocol() override;

    /**
     * Address: 0x00484C20 (FUN_00484C20)
     * Address: 0x1007E820 (sub_1007E820)
     * Slot: 3
     *
     * What it does:
     * Returns local listening port.
     */
    u_short GetLocalPort() override;

    /**
     * Address: 0x00484C50 (FUN_00484C50)
     * Address: 0x1007E850 (sub_1007E850)
     * Slot: 4
     *
     * What it does:
     * Creates an outbound non-blocking TCP connection object.
     */
    INetConnection* Connect(u_long address, u_short port) override;

    /**
     * Address: 0x00484EA0 (FUN_00484EA0)
     * Address: 0x1007EA80 (sub_1007EA80)
     * Slot: 5
     *
     * What it does:
     * Finds next pending remote endpoint awaiting accept.
     */
    bool FindNextAddress(u_long& outAddress, u_short& outPort) override;

    /**
     * Address: 0x00484F00 (FUN_00484F00)
     * Address: 0x1007EAE0 (sub_1007EAE0)
     * Slot: 6
     *
     * What it does:
     * Accepts endpoint into active connection list or creates placeholder.
     */
    INetConnection* Accept(u_long address, u_short port) override;

    /**
     * Address: 0x00485050 (FUN_00485050)
     * Address: 0x1007EC20 (sub_1007EC20)
     * Slot: 7
     *
     * What it does:
     * Rejects endpoint pending connection.
     */
    void Reject(u_long address, u_short port) override;

    /**
     * Address: 0x00485190 (FUN_00485190)
     * Address: 0x1007ED50 (sub_1007ED50)
     * Slot: 8
     *
     * What it does:
     * Polls listener/partials/connections and advances TCP handshake/data flow.
     */
    void Pull() override;

    /**
     * Address: 0x00485610 (FUN_00485610)
     * Address: 0x1007F140 (sub_1007F140)
     * Slot: 9
     *
     * What it does:
     * Flushes all TCP connection outbound queues.
     */
    void Push() override;

    /**
     * Address: 0x00485640 (FUN_00485640)
     * Address: 0x1007F170 (sub_1007F170)
     * Slot: 10
     *
     * What it does:
     * Redirects socket network events to supplied event handle.
     */
    void SelectEvent(HANDLE ev) override;

    /**
     * Address: 0x00483620 (FUN_00483620)
     * Address: 0x1007D410 (sub_1007D410)
     * Slot: 12
     *
     * What it does:
     * Returns empty stamp snapshot for legacy TCP path.
     */
    SSendStampView SnapshotSendStamps(int32_t since) override;

    /**
     * Address: 0x00484AB0 (FUN_00484AB0)
     *
     * What it does:
     * Initializes TCP connector around already-open listening socket.
     */
    explicit CNetTCPConnector(SOCKET socket) noexcept;

    /**
     * Address: 0x004853D0 (FUN_004853D0)
     *
     * What it does:
     * Binds accepted partial socket stream to a TCP connection.
     */
    void ReadFromStream(SOCKET socket, u_long address, u_short port, gpg::PipeStream& stream);

  private:
    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Releases live connection/partial lists and closes listener socket.
     */
    void CleanupConnectionsAndPartials();

  private:
    friend class CNetTCPConnection;
    friend struct STcpPartialConnection;

    STcpConnWorkList mWorkingList{};                 // +0x04
    SOCKET mSocket{INVALID_SOCKET};                  // +0x08
    TDatList<CNetTCPConnection, void> mConnections;  // +0x0C
    TDatList<STcpPartialConnection, void> mPartials; // +0x14
    HANDLE mHandle{nullptr};                         // +0x1C
  };
  static_assert(sizeof(CNetTCPConnector) == 0x20, "CNetTCPConnector size must be 0x20");
} // namespace moho
