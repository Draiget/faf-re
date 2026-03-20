#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Address bundle:
   * - 0x00483A60 (CNetTCPConnection::Pull recv scratch)
   * - 0x00484540/0x004838D0 related TCP stream staging paths
   * - 0x00484770 (STcpPartialConnection::Pull recv scratch)
   *
   * What it does:
   * Shared net I/O chunk size used by TCP recv/send staging loops.
   */
  inline constexpr std::size_t kNetIoBufferSize = 0x800;
  inline constexpr std::size_t kNetTcpIoChunkSize = kNetIoBufferSize;
} // namespace moho
