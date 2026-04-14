#pragma once

#include <cstddef>

#include "EnumByte.h"
#include "gpg/core/containers/FastVector.h"
#include "platform/Platform.h"

namespace gpg
{
  class Stream;
}

namespace moho
{
  /**
   * Message type byte wrapper.
   */
  struct MessageType : EnumByte
  {
    using EnumByte::EnumByte;
    MessageType() noexcept = default;
  };
  static_assert(sizeof(MessageType) == 0x1, "MessageType size must be 0x1");

  /**
   * Network message data-container.
   */
  struct CMessage
  {
    gpg::core::FastVectorN<char, 64> mBuff; // +0x00, full wire buffer (type + size + payload)
    int mPos{0};                            // +0x50, incremental read cursor used by Read()

    /**
     * Address: 0x00483510 (FUN_00483510)
     *
     * What it does:
     * Initializes inline message storage and resets incremental read cursor.
     */
    CMessage();

    /**
     * Address: 0x0047F000 (FUN_0047F000)
     *
     * What it does:
     * Releases heap-backed payload storage (if active) and rebinds vector lanes
     * to inline storage metadata.
     */
    ~CMessage();

    /**
     * Address: 0x00483490 (FUN_00483490)
     * Address: 0x10076360 (sub_10076360)
     * Address: 0x100763B0 (sub_100763B0)
     *
     * What it does:
     * Builds a message with a 3-byte header and pre-sized payload area.
     */
    CMessage(MessageType type, size_t size = 0);

    /**
     * Host-build helper (synthetic):
     * Allows direct enum usage (for example `ECmdStreamOp`) without explicit cast wrappers.
     */
    template <U8Enum E>
    explicit CMessage(E type, size_t size = 0)
      : CMessage(MessageType(type), size)
    {}

    /**
     * Host-build helper (synthetic):
     * Deep-copy message payload and read position.
     */
    CMessage(const CMessage& other);

    /**
     * Host-build helper (synthetic):
     * Deep-copy assignment for message payload and read position.
     */
    CMessage& operator=(const CMessage& other);

    /**
     * Host-build helper (synthetic):
     * Move-construct by payload transfer semantics (implemented as safe clone+reset).
     */
    CMessage(CMessage&& other);

    /**
     * Host-build helper (synthetic):
     * Move-assign by payload transfer semantics (implemented as safe clone+reset).
     */
    CMessage& operator=(CMessage&& other);

    /**
     * Address: <inlined helper>
     *
     * What it does:
     * Stores message wire-size (header + payload) into bytes 1..2.
     */
    void SetSize(const size_t size)
    {
      mBuff[1] = LOBYTE(size);
      mBuff[2] = HIBYTE(size);
    }

    /**
     * Address: <inlined helper>
     *
     * What it does:
     * Reads message wire-size (header + payload) from bytes 1..2.
     */
    unsigned short GetSize()
    {
      return MAKEWORD(mBuff[1], mBuff[2]);
    }

    /**
     * Address: <inlined helper>
     *
     * What it does:
     * Returns whether the 3-byte message header has been read.
     */
    [[nodiscard]]
    bool HasReadLength() const
    {
      return mPos >= 3;
    }

    /**
     * Address: 0x0047BC80 (FUN_0047BC80)
     *
     * What it does:
     * Returns message type stored in header byte 0.
     */
    MessageType GetType()
    {
      return MessageType(static_cast<std::uint8_t>(this->mBuff[0]));
    }

    /**
     * Address: 0x0047BD00 (FUN_0047BD00)
     *
     * What it does:
     * Writes message type to header byte 0.
     */
    void SetType(const MessageType type)
    {
      mBuff[0] = type.raw();
    }

    /**
     * Address: 0x0047BD10 (FUN_0047BD10)
     *
     * What it does:
     * Resizes wire storage to `payloadSize + 3` and writes the two-byte wire-size header.
     */
    void InitializeHeaderForPayloadSize(size_t payloadSize);

    /**
     * Address: 0x0047BCC0 (FUN_0047BCC0)
     *
     * What it does:
     * Rebuilds wire header for payload size and writes message type byte 0.
     */
    void InitializeHeaderForPayloadSizeAndType(size_t payloadSize, MessageType type);

    template <U8Enum E>
    void SetType(E e)
    {
      this->mBuff[0] = static_cast<std::uint8_t>(e);
    }

    /**
     * Address: 0x0047BE90 (FUN_0047BE90)
     * Address: 0x100764F0 (sub_100764F0)
     *
     * What it does:
     * Returns payload size, excluding the 3-byte header.
     */
    int GetMessageSize();

    /**
     * Address: 0x0047BD40 (FUN_0047BD40)
     * Address: 0x100763E0 (sub_100763E0)
     *
     * What it does:
     * Reads a full message from stream in one blocking call path.
     */
    bool ReadMessage(gpg::Stream* stream);

    /**
     * Address: 0x0047BEE0 (FUN_0047BEE0)
     * Address: 0x10076530 (sub_10076530)
     *
     * What it does:
     * Incrementally reads header and payload using non-blocking reads.
     */
    bool Read(gpg::Stream* stream);

    /**
     * Address: 0x0047BDE0 (FUN_0047BDE0)
     * Address: 0x10076460 (sub_10076460)
     *
     * What it does:
     * Appends payload bytes, updates header length, and returns high-byte of wire-size.
     */
    unsigned int Append(const char* ptr, size_t size);

    /**
     * Address: 0x0048BD30 (FUN_0048BD30, Moho::CMessage::AppendChar)
     *
     * What it does:
     * Appends one raw byte to payload storage, growing vector capacity when
     * the current end pointer is at capacity.
     */
    void AppendChar(const char* ptr);

    /**
     * Address: 0x00483530 (FUN_00483530)
     *
     * What it does:
     * Resets storage to inline buffer and clears read cursor.
     */
    void Clear() noexcept;
  };

  static_assert(sizeof(CMessage) == 0x54, "CMessage size must be 0x54");
} // namespace moho
