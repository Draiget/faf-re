#pragma once

#include <cstddef>
#include <cstdint>

#include "INetTCPSocket.h"
#include "NetConstants.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E04530
   * COL:     0x00E60A34
   *
   * Log/code strings:
   *  - CNetTCPBuf::Write(): send() failed: %s
   *  - CNetTCPBuf::Flush(): send() failed: %s
   *  - CNetTCPBuf::Read(): recv() failed: %s
   */
  class CNetTCPBuf : public INetTCPSocket
  {
  public:
    /**
     * Address: 0x004827C0 (FUN_004827C0)
     * Address: 0x1007C610 (sub_1007C610)
     * Slot: 0
     *
     * What it does:
     * Closes active stream directions and tears down the socket stream.
     */
    ~CNetTCPBuf() override;

    /**
     * Address: 0x00482880 (FUN_00482880)
     * Address: 0x1007C690 (sub_1007C690)
     * Slot: 10
     *
     * What it does:
     * Returns local socket port.
     */
    u_short GetPort() override;

    /**
     * Address: 0x00482930 (FUN_00482930)
     * Address: 0x1007C720 (sub_1007C720)
     * Slot: 11
     *
     * What it does:
     * Returns connected peer IPv4 address in host byte order.
     */
    u_long GetPeerAddr() override;

    /**
     * Address: 0x004829E0 (FUN_004829E0)
     * Address: 0x1007C7B0 (sub_1007C7B0)
     * Slot: 12
     *
     * What it does:
     * Returns connected peer port in host byte order.
     */
    u_short GetPeerPort() override;

    /**
     * Address: 0x00482A90 (FUN_00482A90)
     * Address: 0x1007C840 (sub_1007C840)
     * Slot: 3
     *
     * What it does:
     * Reads bytes using blocking socket behavior.
     */
    size_t VirtRead(char* buff, size_t len) override;

    /**
     * Address: 0x00482AB0 (FUN_00482AB0)
     * Address: 0x1007C860 (sub_1007C860)
     * Slot: 4
     *
     * What it does:
     * Reads bytes without blocking.
     */
    size_t VirtReadNonBlocking(char* buf, size_t len) override;

    /**
     * Address: 0x00482AD0 (FUN_00482AD0)
     * Address: 0x1007C880 (sub_1007C880)
     * Slot: 6
     *
     * What it does:
     * Reports read-end-of-stream/failure state.
     */
    bool VirtAtEnd() override;

    /**
     * Address: 0x00482B50 (FUN_00482B50)
     * Address: 0x1007C8F0 (sub_1007C8F0)
     * Slot: 7
     *
     * What it does:
     * Writes bytes into the pending send window or directly to socket.
     */
    void VirtWrite(const char* data, size_t size) override;

    /**
     * Address: 0x00482CE0 (FUN_00482CE0)
     * Address: 0x1007CA70 (sub_1007CA70)
     * Slot: 8
     *
     * What it does:
     * Flushes pending write-buffer bytes to socket.
     */
    void VirtFlush() override;

    /**
     * Address: 0x00482DA0 (FUN_00482DA0)
     * Address: 0x1007CB20 (sub_1007CB20)
     * Slot: 9
     *
     * What it does:
     * Shuts down selected socket directions and closes when both are off.
     */
    void VirtClose(Mode mode) override;

    /**
     * Address: 0x00482770 (FUN_00482770)
     * Address: 0x1007C5C0 (sub_1007C5C0)
     *
     * What it does:
     * Initializes stream pointers/mode around an already-connected socket.
     */
    explicit CNetTCPBuf(SOCKET socket) noexcept;

  private:
    /**
     * Address: 0x00482E20 (FUN_00482E20)
     * Address: 0x1007CBA0 (sub_1007CBA0)
     *
     * What it does:
     * Shared buffered read routine used by blocking/non-blocking variants.
     */
    size_t Read(char* buf, size_t len, bool isBlocking);

    /**
     * Address: 0x00483040 (FUN_00483040)
     * Address: 0x1007CDA0 (sub_1007CDA0)
     *
     * What it does:
     * Polls the socket with zero-timeout select for readability.
     */
    [[nodiscard]]
    bool Select() const;

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Throws `std::runtime_error("socket closed")`.
     */
    [[noreturn]]
    void ThrowSocketClosed() const;

  private:
    static constexpr size_t kChunkSize = kNetIoBufferSize;
    static constexpr size_t kBufferSize = 0x1000;

    SOCKET mSocket{INVALID_SOCKET}; // +0x1C
    std::uint32_t mMode{0};         // +0x20
    std::uint8_t mFailed{0};        // +0x24
    std::uint8_t mPad0x25{0};       // +0x25
    char mBuffer[kBufferSize]{};    // +0x26
  };
  static_assert(sizeof(CNetTCPBuf) == 0x1028, "CNetTCPBuf size must be 0x1028");
} // namespace moho
