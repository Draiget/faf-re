#pragma once
#include <cstdint>
#include <stdexcept>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "moho/net/INetConnection.h"

namespace gpg
{
  // 0x00D49658
  class Stream
  {
  public:
    // 0x00D49684
    class UnsupportedOperation : public std::logic_error
    {
    public:
      /**
       * Address: 0x00956E40 (FUN_00956E40)
       *
       * What it does:
       * Constructs the standard "unsupported stream operation" logic_error payload.
       */
      UnsupportedOperation();
    };

    enum Mode
    {
      ModeNone = 0,
      ModeReceive = 1,
      ModeSend = 2,
      ModeBoth = 3,
    };

    enum SeekOrigin
    {
      OriginBegin = 0,
      OriginCurr = 1,
      OriginEnd = 2,
    };

  public:
    char* mReadStart;
    char* mReadHead;
    char* mReadEnd;
    char* mWriteStart;
    char* mWriteHead;
    char* mWriteEnd;

    /**
     * Address: 0x00956DD0 (FUN_00956DD0, non-deleting dtor lane)
     * Address: 0x00956E20 (FUN_00956E20)
     * Slot: 0
     *
     * What it does:
     * Resets Stream vftable in the base dtor lane and owns deleting-dtor
     * dispatch for the scalar-delete path.
     */
    virtual ~Stream();

    /**
     * Address: 0x00956DB0 (FUN_00956DB0)
     *
     * What it does:
     * Initializes stream read/write window pointers to null.
     */
    Stream();

    /**
     * Address: 0x00956F50 (FUN_00956F50)
     * Slot: 1
     *
     * What it does:
     * Default seek-position query lane throws UnsupportedOperation.
     */
    virtual std::uint64_t VirtTell(Mode mode);

    /**
     * Address: 0x00956F90 (FUN_00956F90)
     * Slot: 2
     *
     * What it does:
     * Default seek lane throws UnsupportedOperation.
     */
    virtual std::uint64_t VirtSeek(Mode mode, SeekOrigin orig, std::int64_t pos);

    /**
     * Address: 0x00956FB0 (FUN_00956FB0)
     * Slot: 3
     *
     * What it does:
     * Default read lane throws UnsupportedOperation.
     */
    virtual size_t VirtRead(char* buff, size_t len);

    /**
     * Address: 0x00956DE0 (FUN_00956DE0)
     * Slot: 4
     *
     * What it does:
     * Default non-blocking read forwards to VirtRead.
     */
    virtual size_t VirtReadNonBlocking(char* buf, size_t len);

    /**
     * Address: 0x00956FD0 (FUN_00956FD0)
     * Slot: 5
     *
     * What it does:
     * Default unget lane throws UnsupportedOperation.
     */
    virtual void VirtUnGetByte(int unknown);

    /**
     * Address: 0x00956DF0 (FUN_00956DF0)
     * Slot: 6
     *
     * What it does:
     * Default end-of-stream query returns false.
     */
    virtual bool VirtAtEnd();

    /**
     * Address: 0x00956FF0 (FUN_00956FF0)
     * Slot: 7
     *
     * What it does:
     * Default write lane throws UnsupportedOperation.
     */
    virtual void VirtWrite(const char* data, size_t size);

    /**
     * Address: 0x00956E00 (FUN_00956E00)
     * Slot: 8
     *
     * What it does:
     * Default flush lane is a no-op.
     */
    virtual void VirtFlush();

    /**
     * Address: 0x00956E10 (FUN_00956E10)
     * Slot: 9
     *
     * What it does:
     * Default close lane is a no-op.
     */
    virtual void VirtClose(Mode mode);

    /**
     * Address: 0x0046BED0 (FUN_0046BED0, __imp_?Seek@Stream@gpg@@QAE_KW4Mode@12@W4SeekOrigin@12@_J@Z)
     *
     * What it does:
     * Non-virtual receive-lane seek wrapper that forwards to `VirtSeek`
     * with `ModeReceive`.
     */
    std::uint64_t Seek(SeekOrigin origin, std::int64_t pos);

    /**
     * NOTE: Inlined
     * @return
     */
    [[nodiscard]]
    bool CanRead() const
    {
      return mReadEnd != mReadHead;
    }

    /**
     * NOTE: Inlined
     * Bytes pending in the small inline input buffer.
     */
    [[nodiscard]]
    size_t BytesRead() const
    {
      return mReadEnd - mReadHead;
    }

    /**
     * NOTE: Inlined
     * @return
     */
    [[nodiscard]]
    bool CanWrite() const
    {
      return this->mWriteEnd != this->mWriteHead;
    }

    /**
     * NOTE: Inlined
     * @return
     */
    [[nodiscard]]
    size_t LeftToWrite() const
    {
      return mWriteEnd - mWriteHead;
    }

    /**
     * NOTE: Inlined
     * @return
     */
    [[nodiscard]]
    size_t BytesWritten() const
    {
      return mWriteHead - mWriteStart;
    }

    /**
     * Address: 0x006E5A10 (FUN_006E5A10)
     *
     * What it does:
     * Writes string bytes including trailing NUL through inline-buffer fast path or virtual write fallback.
     */
    void Write(const msvc8::string& str);

    /**
     * Address: 0x0043D130 (FUN_0043D130)
     *
     * What it does:
     * Writes one byte span through inline-buffer fast path or virtual write fallback.
     */
    void Write(const char* buf, size_t size);

    /**
     * Address: 0x004CCD80 (FUN_004CCD80)
     *
     * What it does:
     * Writes one NUL-terminated C-string including terminator.
     */
    void Write(const char* buf);

    /**
     * Address: 0x004455B0 (FUN_004455B0)
     *
     * What it does:
     * Writes one 32-bit integer through inline-buffer fast path or virtual
     * write fallback.
     */
    void WriteInt32(std::int32_t value);

    /**
     * Note: Custom function.
     *
     * Write any trivially-copyable non-pointer, non-enum value as raw bytes.
     * Endianness: bytes are emitted as-is (little-endian on x86).
     */
    template <class T>
    std::enable_if_t<std::is_trivially_copyable_v<T> && !std::is_pointer_v<T> && !std::is_enum_v<T>, void>
    Write(const T& value)
    {
      Write(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    /**
     * Note: Custom function.
     *
     * Write enum by its underlying integral type.
     */
    template <class E>
    std::enable_if_t<std::is_enum_v<E>, void> Write(const E value)
    {
      using U = std::underlying_type_t<E>;
      U tmp = static_cast<U>(value);
      Write(reinterpret_cast<const char*>(&tmp), sizeof(U));
    }

    /**
     * Note: Custom function.
     *
     * Write fixed-size C array (e.g., byte blobs).
     */
    template <class T, std::size_t N>
    std::enable_if_t<std::is_trivially_copyable_v<T>, void> Write(const T (&arr)[N])
    {
      Write(reinterpret_cast<const char*>(arr), sizeof(arr));
    }

    /**
     * Address: 0x00955760 (FUN_00955760)
     *
     * What it does:
     * Calls `VirtClose(mode)` and returns `false` instead of throwing on any exception.
     */
    bool CloseNoThrow(Mode access);

    /**
     * NOTE: helper wrapper (no stable standalone symbol mapping).
     *
     * Calls `VirtClose(mode)` and returns true when no exception is thrown.
     */
    bool Close(Mode access);

    /**
     * Address: 0x0043D100 (FUN_0043D100)
     *
     * What it does:
     * Reads one byte span from inline read window or virtual read fallback.
     */
    size_t Read(char* buf, size_t size);

    /**
     * Address: 0x004CCC10 (FUN_004CCC10)
     *
     * What it does:
     * Rewinds one previously-read byte with validation, or delegates to virtual unget when at read window start.
     */
    void UnGetByte(int value);

    /**
     * NOTE: Inlined (e.g. - 0x0047BF13)
     *
     * @param buf
     * @param size
     * @return
     */
    size_t ReadNonBlocking(char* buf, size_t size);

    /**
     * NOTE: Inlined
     * @param vec
     */
    void Write(const core::FastVector<char>& vec)
    {
      Write(vec.start_, vec.Size());
    }

    /**
     * NOTE: helper method (no stable standalone symbol mapping yet).
     *
     * Returns one byte from read window or virtual read fallback; returns -1 on EOF.
     */
    int8_t GetByte();
  };
  static_assert(sizeof(Stream) == 0x1C, "gpg::Stream size must be 0x1C");

  /**
   * Note: helper wrapper (no stable standalone symbol mapping).
   *
   * Performs checked single-byte unget via `Stream::UnGetByte`.
   */
  void UnGetByteChecked(Stream& stream, int value);

  class TextWriter
  {
  public:
    /**
     * Address: 0x00957040 (FUN_00957040)
     *
     * What it does:
     * Initializes writer state around a target stream and line-ending mode.
     */
    TextWriter(Stream* stream, int mode);

    /**
     * Address: 0x00957060 (FUN_00957060)
     *
     * What it does:
     * Emits one logical newline according to configured line-ending mode.
     */
    void WriteNewline();

    /**
     * Address: 0x00957130 (FUN_00957130)
     *
     * What it does:
     * Writes one character with optional CR/LF normalization.
     */
    void WriteChar(char value);

    /**
     * Address: 0x009571B0 (FUN_009571B0)
     *
     * What it does:
     * Writes one NUL-terminated C-string through WriteChar normalization.
     */
    void WriteCString(const char* value);

    /**
     * Address: 0x00957210 (FUN_00957210)
     *
     * What it does:
     * Writes one msvc8::string payload through WriteChar normalization.
     */
    void WriteString(const msvc8::string& value);

    /**
     * Address: 0x00957250 (FUN_00957250)
     *
     * What it does:
     * Formats one vararg message with STR_Va and writes it through this TextWriter.
     */
    void Printf(const char* format, ...);

  private:
    void WriteByte(char value);

    Stream* mStream{};
    int mMode{};
    bool mSawCarriageReturn{};
  };
  static_assert(sizeof(TextWriter) == 0x0C, "gpg::TextWriter size must be 0x0C");
} // namespace gpg
