#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "gpg/core/streams/Stream.h"

namespace moho
{
  struct CMessage;

  /**
   * VFTABLE: 0x00E03BEC
   * COL:  0x00E606AC
   */
  class CMessageStream : public gpg::Stream
  {
  public:
    enum class Access : std::uint8_t
    {
      kReadOnly,
      kReadWrite
    };

    /**
     * Address: 0x0047C030 (FUN_0047C030)
     * Address: 0x10076630 (sub_10076630)
     *
     * Slot: 0
     *
     * What it does:
     * Destroys stream wrapper; does not own backing `CMessage`.
     */
    ~CMessageStream() override;

    /**
     * Address: 0x0047C0F0
     * Address: 0x100766F0 (sub_100766F0)
     *
     * Slot: 3
     *
     * What it does:
     * Copies up to `len` bytes from current read window and advances `mReadHead`.
     */
    size_t VirtRead(char* buff, size_t len) override;

    /**
     * Address: 0x0047C120
     * Address: 0x10076720 (sub_10076720)
     *
     * Slot: 6
     *
     * What it does:
     * Returns whether read head reached read end.
     */
    bool VirtAtEnd() override;

    /**
     * Address: 0x0047C130
     * Address: 0x10076730 (sub_10076730)
     *
     * Slot: 7
     *
     * What it does:
     * Writes into payload window and appends overflow bytes to backing `CMessage`.
     */
    void VirtWrite(const char* data, size_t size) override;

    /**
     * Address: 0x0047BFE0 (FUN_0047BFE0)
     * Address: 0x100765E0 (sub_100765E0)
     *
     * What it does:
     * Builds a read/write stream view over `msg` payload bytes.
     */
    explicit CMessageStream(CMessage& msg);

    /**
     * Address: 0x0047C060 (FUN_0047C060)
     * Address: 0x10076660 (sub_10076660)
     *
     * What it does:
     * Builds a read-only stream view over `msg` payload bytes.
     */
    explicit CMessageStream(CMessage* msg);

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Delegates to binary read/write ctor and optionally downgrades to read-only.
     */
    explicit CMessageStream(CMessage& msg, Access access);

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Delegates to binary read-only ctor and optionally enables write window.
     */
    explicit CMessageStream(CMessage* msg, Access access);

  private:
    CMessage* mMessage{nullptr}; // +0x1C

    /**
     * Compute payload window [start, end) from message buffer.
     */
    static std::pair<char*, char*> PayloadWindow(CMessage& m) noexcept;

    /**
     * Rebind to payload window preserving absolute offsets exactly as in binary code.
     * No defensive clamping is applied.
     */
    void RebindToPayloadUnchecked(std::ptrdiff_t readOff, std::ptrdiff_t writeOffPlus) noexcept;
  };

  static_assert(sizeof(CMessageStream) == 0x20, "CMessageStream size must be 0x20");
} // namespace moho
