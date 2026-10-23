#pragma once

#include <cstddef>
#include <cstdint>

#include "IMessageReceiver.h"
#include "legacy/containers/String.h"

namespace moho
{
  struct CMessage;

  struct NetDataSpan
  {
    uint8_t* start{nullptr};
    uint8_t* end{nullptr};

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Stores a caller-provided byte span [start, end).
     */
    NetDataSpan(uint8_t* begin, uint8_t* finish) noexcept;

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Creates a span over a message's whole wire buffer (header + payload).
     */
    explicit NetDataSpan(const CMessage& message) noexcept;

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Returns byte length of [start, end).
     */
    [[nodiscard]]
    size_t size() const noexcept;

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Returns span start pointer.
     */
    [[nodiscard]]
    uint8_t* data() const noexcept;
  };

  /**
   * VFTABLE: 0x00E0499C
   * COL:     0x00E60C88
   */
  class INetConnection : public CMessageDispatcher
  {
  public:
    /**
     * Address: 0x00A82547
     * Slot: 0
     */
    virtual u_long GetAddr() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 1
     */
    virtual u_short GetPort() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     */
    virtual float GetPing() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     */
    virtual float GetTime() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 4
     */
    virtual void Write(NetDataSpan* data) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 5
     */
    virtual void Close() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 6
     */
    virtual msvc8::string ToString() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     */
    virtual void ScheduleDestroy() = 0;

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Queues one whole message (3-byte header + payload) through Write(NetDataSpan*).
     */
    void Write(const CMessage& message);
  };
  // The vtable and `CMessageDispatcher` (+0x04, 0x408). A derived connection's
  // own `gpg::DListItem` then starts at +0x410, not +0x40C: its empty
  // `noncopyable` base may not share an address with the one inside
  // `CMessageDispatcher::mLinkages`.
  static_assert(sizeof(INetConnection) == 0x40C, "INetConnection size must be 0x40C");
} // namespace moho
