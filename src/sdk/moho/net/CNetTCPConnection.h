#pragma once

#include <cstdint>

#include "CMessage.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/time/Timer.h"
#include "INetConnection.h"
#include "moho/containers/TDatList.h"
#include "NetConstants.h"
#include "NetTransportEnums.h"
#include "platform/Platform.h"

namespace moho
{
  class CNetTCPConnector;

  /**
   * VFTABLE: 0x00E049F8
   * COL:     0x00E60B20
   */
  class CNetTCPConnection : public INetConnection, public TDatListItem<CNetTCPConnection, void>
  {
  public:
    /**
     * Address: 0x004835B0 (FUN_004835B0)
     * Address: 0x1007D3A0 (sub_1007D3A0)
     * Slot: 0
     *
     * What it does:
     * Returns remote IPv4 address in host byte order.
     */
    u_long GetAddr() override;

    /**
     * Address: 0x004835C0 (FUN_004835C0)
     * Address: 0x1007D3B0 (sub_1007D3B0)
     * Slot: 1
     *
     * What it does:
     * Returns remote TCP port in host byte order.
     */
    u_short GetPort() override;

    /**
     * Address: 0x004835D0 (FUN_004835D0)
     * Address: 0x1007D3C0 (sub_1007D3C0)
     * Slot: 2
     *
     * What it does:
     * Returns fixed placeholder ping value used by legacy TCP path.
     */
    float GetPing() override;

    /**
     * Address: 0x00484520 (FUN_00484520)
     * Address: 0x1007E190 (sub_1007E190)
     * Slot: 3
     *
     * What it does:
     * Returns elapsed time in milliseconds since last timer reset.
     */
    float GetTime() override;

    /**
     * Address: 0x00484540 (FUN_00484540)
     * Address: 0x1007E1A0 (sub_1007E1A0)
     * Slot: 4
     *
     * What it does:
     * Queues span bytes into outbound pipe stream.
     */
    void Write(NetDataSpan* data) override;

    /**
     * Address: 0x00484590 (FUN_00484590)
     * Address: 0x1007E1C0 (sub_1007E1C0)
     * Slot: 5
     *
     * What it does:
     * Closes outbound direction for this connection.
     */
    void Close() override;

    /**
     * Address: 0x004845B0 (FUN_004845B0)
     * Address: 0x1007E1D0 (sub_1007E1D0)
     * Slot: 6
     *
     * What it does:
     * Returns "host:port" textual identity for logs/debug.
     */
    msvc8::string ToString() override;

    /**
     * Address: 0x004835E0 (FUN_004835E0)
     * Address: 0x1007D3D0 (sub_1007D3D0)
     * Slot: 7
     *
     * What it does:
     * Marks connection for deferred destroy.
     */
    void ScheduleDestroy() override;

    /**
     * Address: 0x00483650 (FUN_00483650)
     *
     * What it does:
     * Initializes TCP connection object and links it into connector list.
     */
    CNetTCPConnection(
      CNetTCPConnector* connector, SOCKET socket, u_long address, u_short port, ENetConnectionState state
    );

    /**
     * Address: 0x004837E0 (FUN_004837E0)
     *
     * What it does:
     * Closes socket/streams and unlinks from connector intrusive list.
     */
    ~CNetTCPConnection();

    /**
     * Address: 0x00483A60 (FUN_00483A60)
     *
     * What it does:
     * Polls socket input/connect state and dispatches buffered messages.
     */
    void Pull();

    /**
     * Address: 0x004838D0 (FUN_004838D0)
     *
     * What it does:
     * Flushes outbound stream bytes to socket and handles send-side shutdown.
     */
    void Push();

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Attaches accepted socket stream payload to this connection.
     */
    void AdoptIncomingStream(SOCKET socket, gpg::PipeStream& stream);

  public:
    CNetTCPConnector* mConnector{nullptr};        // +0x418
    SOCKET mSocket{INVALID_SOCKET};               // +0x41C
    u_long mAddr{0};                              // +0x420
    u_short mPort{0};                             // +0x424
    std::uint16_t mPad0x426{0};                   // +0x426
    ENetConnectionState mState{kNetStatePending}; // +0x428
    std::uint32_t mPad0x42C{0};                   // +0x42C
    gpg::time::Timer mTimer;                      // +0x430
    gpg::PipeStream mInputStream;                 // +0x438
    gpg::PipeStream mOutputStream;                // +0x480
    char mSendBuffer[kNetIoBufferSize]{};         // +0x4C8
    std::uint32_t mSendBufferSize{0};             // +0xCC8
    std::uint8_t mHasShutdownOutput{0};           // +0xCCC
    std::uint8_t mPad0xCCD[3]{};                  // +0xCCD
    CMessage mDatagram;                           // +0xCD0
    std::uint32_t mPad0xD24{0};                   // +0xD24
    std::uint8_t mPushFailed{0};                  // +0xD28
    std::uint8_t mPullFailed{0};                  // +0xD29
    std::uint8_t mScheduleDestroy{0};             // +0xD2A
    std::uint8_t mPad0xD2B[5]{};                  // +0xD2B
  };
  static_assert(sizeof(CNetTCPConnection) == 0xD30, "CNetTCPConnection size must be 0xD30");
} // namespace moho
