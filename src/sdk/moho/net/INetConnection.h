#pragma once

#include <cstddef>
#include <cstdint>

#include "IMessageReceiver.h"
#include "legacy/containers/String.h"

namespace moho
{
  class CMessageStream;

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
     * Creates a span over CMessageStream write window [mWriteStart, mWriteHead).
     */
    explicit NetDataSpan(const CMessageStream& stream) noexcept;

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
     * Forwards CMessageStream write window [mWriteStart, mWriteHead) to virtual Write(NetDataSpan*).
     */
    void Write(const CMessageStream& stream);

  private:
    // +0x40C, observed from derived-class field starts; semantic meaning not recovered yet.
    std::int32_t mReserved0x40C{0};
  };
  static_assert(sizeof(INetConnection) == 0x410, "INetConnection size must be 0x410");
} // namespace moho
