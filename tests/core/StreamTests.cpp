// gpg::Stream (the base and its inline read/write windows), MemBufferStream and its buffers, and the
// TextReader/TextWriter line codecs. Inputs are built here; expected bytes follow from what each function
// documents (Stream.h, MemBufferStream.h), not from earlier runs.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <gtest/gtest.h>

#include "CoreTestSupport.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/streams/Stream.h"

namespace
{
  using namespace std::string_view_literals;
  using faf_core_tests::PatternBytes;

  /** A stream with no overrides: every slot is the base's. */
  class BareStream final : public gpg::Stream
  {
  };

  /** A stream whose window the test sets, and whose virtual slots record what reached them. */
  class WindowStream final : public gpg::Stream
  {
  public:
    void SetReadWindow(char* const begin, const std::size_t size)
    {
      mReadStart = begin;
      mReadHead = begin;
      mReadEnd = begin + size;
    }

    void SetWriteWindow(char* const begin, const std::size_t size)
    {
      mWriteStart = begin;
      mWriteHead = begin;
      mWriteEnd = begin + size;
    }

    size_t VirtRead(char* const buf, const size_t len) override
    {
      ++mVirtReads;
      const std::size_t take = (std::min)(len, mSource.size() - mSourcePos);
      std::memcpy(buf, mSource.data() + mSourcePos, take);
      mSourcePos += take;
      return take;
    }

    void VirtWrite(const char* const data, const size_t size) override
    {
      ++mVirtWrites;
      mSink.append(data, size);
    }

    void VirtUnGetByte(const int value) override { mUngot = value; }

    void VirtClose(const Mode mode) override
    {
      mClosedMode = mode;
      if (mThrowOnClose) {
        throw std::runtime_error("close failed");
      }
    }

    std::string mSource;
    std::size_t mSourcePos = 0;
    std::string mSink;
    int mVirtReads = 0;
    int mVirtWrites = 0;
    int mUngot = -1000;
    Mode mClosedMode = ModeNone;
    bool mThrowOnClose = false;
  };

  enum class SmallEnum : std::uint16_t
  {
    Value = 0x1234,
  };

  /** Everything a MemBufferStream holds, from its own buffer: what a reader would get from offset 0. */
  std::string ContentOf(const gpg::MemBufferStream& stream)
  {
    const gpg::MemBuffer<const char> buffer = stream.GetConstBuffer();
    return std::string(buffer.begin(), stream.GetLength());
  }

  std::string ReadAll(gpg::Stream& stream, const std::size_t chunk = 7u)
  {
    std::string out;
    std::string piece(chunk, '\0');
    for (;;) {
      const std::size_t got = stream.Read(piece.data(), chunk);
      out.append(piece.data(), got);
      if (got < chunk) {
        return out;
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // gpg::Stream base
  // ---------------------------------------------------------------------------------------------

  TEST(GpgStream, BaseSlotsThrowUnsupportedOperation)
  {
    BareStream stream;
    char byte = 0;
    EXPECT_THROW((void)stream.VirtTell(gpg::Stream::ModeReceive), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW((void)stream.VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW((void)stream.VirtRead(&byte, 1u), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW((void)stream.VirtReadNonBlocking(&byte, 1u), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW(stream.VirtUnGetByte(0), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW(stream.VirtWrite(&byte, 1u), gpg::Stream::UnsupportedOperation);
    EXPECT_THROW((void)stream.Seek(gpg::Stream::OriginBegin, 0), gpg::Stream::UnsupportedOperation);
    EXPECT_FALSE(stream.VirtAtEnd());
    EXPECT_NO_THROW(stream.VirtFlush());
    EXPECT_TRUE(stream.Close(gpg::Stream::ModeBoth));
    EXPECT_TRUE(stream.CloseNoThrow(gpg::Stream::ModeBoth));
  }

  TEST(GpgStream, UnsupportedOperationCarriesItsMessage)
  {
    try {
      BareStream stream;
      (void)stream.VirtTell(gpg::Stream::ModeSend);
      FAIL() << "VirtTell did not throw";
    } catch (const std::logic_error& error) {
      EXPECT_STREQ(error.what(), "Unsupported stream operation.");
    }
  }

  TEST(GpgStream, CloseNoThrowTurnsAThrowIntoFalse)
  {
    WindowStream stream;
    stream.mThrowOnClose = true;
    EXPECT_FALSE(stream.CloseNoThrow(gpg::Stream::ModeSend));
    EXPECT_EQ(stream.mClosedMode, gpg::Stream::ModeSend);
    EXPECT_THROW((void)stream.Close(gpg::Stream::ModeReceive), std::runtime_error);
    EXPECT_EQ(stream.mClosedMode, gpg::Stream::ModeReceive);
  }

  TEST(GpgStream, ReadTakesTheWindowFirstAndFallsBackToVirtRead)
  {
    char window[] = {'a', 'b', 'c', 'd'};
    WindowStream stream;
    stream.SetReadWindow(window, sizeof(window));
    stream.mSource = "XYZ";

    char out[8] = {};
    EXPECT_EQ(stream.Read(out, 3u), 3u);
    EXPECT_EQ(std::string_view(out, 3u), "abc"sv);
    EXPECT_EQ(stream.mVirtReads, 0);
    EXPECT_EQ(stream.BytesRead(), 1u);
    EXPECT_TRUE(stream.CanRead());

    // More than the window holds goes to the virtual slot as a whole; the window is left as it was.
    EXPECT_EQ(stream.Read(out, 2u), 2u);
    EXPECT_EQ(std::string_view(out, 2u), "XY"sv);
    EXPECT_EQ(stream.mVirtReads, 1);
    EXPECT_EQ(stream.BytesRead(), 1u);

    EXPECT_EQ(stream.Read(out, 0u), 0u);
    EXPECT_EQ(stream.mVirtReads, 1);
  }

  TEST(GpgStream, GetByteCheckByteAndUnGetByte)
  {
    char window[] = {'\x01', '\xFE'};
    WindowStream stream;
    stream.SetReadWindow(window, sizeof(window));

    EXPECT_EQ(stream.CheckByte(), 0x01);
    EXPECT_EQ(stream.GetByte(), 0x01);
    EXPECT_EQ(stream.GetByte(), 0xFE); // bytes come back unsigned
    stream.UnGetByte(0xFE);
    EXPECT_EQ(stream.BytesRead(), 1u);
    EXPECT_THROW(stream.UnGetByte(0x02), std::invalid_argument); // not the byte that was read
    stream.UnGetByte(0x01);
    EXPECT_EQ(stream.BytesRead(), 2u);

    // At the window's start the unget goes to the virtual slot.
    stream.UnGetByte(0x55);
    EXPECT_EQ(stream.mUngot, 0x55);

    // Past the window and the source: GetByte gives -1 and CheckByte 255.
    stream.SetReadWindow(window, 0u);
    EXPECT_EQ(stream.GetByte(), -1);
    EXPECT_EQ(stream.CheckByte(), 255);
  }

  TEST(GpgStream, WriteFillsTheWindowAndSendsWhatDoesNotFitToVirtWrite)
  {
    char window[8] = {};
    WindowStream stream;
    stream.SetWriteWindow(window, sizeof(window));

    stream.Write("abc", 3u);
    EXPECT_EQ(stream.BytesWritten(), 3u);
    EXPECT_EQ(stream.LeftToWrite(), 5u);
    EXPECT_EQ(stream.mVirtWrites, 0);
    EXPECT_TRUE(stream.CanWrite());

    stream.Write("0123456789", 6u); // 6 > 5 left
    EXPECT_EQ(stream.mVirtWrites, 1);
    EXPECT_EQ(stream.mSink, "012345");
    EXPECT_EQ(stream.BytesWritten(), 3u);

    stream.Write("de", 2u);
    EXPECT_EQ(std::string_view(window, 5u), "abcde"sv);
  }

  TEST(GpgStream, StringFormsWriteTheirTerminator)
  {
    char window[32] = {};
    WindowStream stream;
    stream.SetWriteWindow(window, sizeof(window));

    stream.Write("hi");
    const fa::string text("yo");
    stream.Write(text);
    EXPECT_EQ(stream.BytesWritten(), 6u);
    EXPECT_EQ(std::string_view(window, 6u), std::string_view("hi\0yo\0", 6u));
  }

  TEST(GpgStream, ScalarWritesAreLittleEndianRawBytes)
  {
    char window[32] = {};
    WindowStream stream;
    stream.SetWriteWindow(window, sizeof(window));

    stream.WriteInt32(0x11223344);
    stream.Write(std::uint16_t{0xA1B2});
    stream.Write(SmallEnum::Value);
    const std::uint8_t blob[3] = {9, 8, 7};
    stream.Write(blob);
    stream.Write(1.0f);

    const unsigned char expected[] = {0x44, 0x33, 0x22, 0x11, 0xB2, 0xA1, 0x34, 0x12, 9, 8, 7, 0x00, 0x00, 0x80, 0x3F};
    ASSERT_EQ(stream.BytesWritten(), sizeof(expected));
    EXPECT_EQ(std::memcmp(window, expected, sizeof(expected)), 0);

    // With no room left, WriteInt32 goes through VirtWrite with the same four bytes.
    WindowStream full;
    full.WriteInt32(-2);
    EXPECT_EQ(full.mSink, std::string("\xFE\xFF\xFF\xFF", 4u));
  }

  TEST(GpgStream, ReadNonBlockingFallsBackToVirtReadNonBlocking)
  {
    WindowStream stream; // VirtReadNonBlocking is the base's, which forwards to VirtRead
    stream.mSource = "pq";
    char out[4] = {};
    EXPECT_EQ(stream.ReadNonBlocking(out, 4u), 2u);
    EXPECT_EQ(std::string_view(out, 2u), "pq"sv);
    EXPECT_EQ(stream.mVirtReads, 1);
  }

  // ---------------------------------------------------------------------------------------------
  // MemBuffer helpers
  // ---------------------------------------------------------------------------------------------

  TEST(GpgMemBuffer, AllocIsZeroFilledAndSized)
  {
    const gpg::MemBuffer<char> buffer = gpg::AllocMemBuffer(100u);
    ASSERT_NE(buffer.data(), nullptr);
    EXPECT_EQ(buffer.Size(), 100u);
    for (std::size_t index = 0; index < buffer.Size(); ++index) {
      ASSERT_EQ(buffer[index], '\0') << "at " << index;
    }
  }

  TEST(GpgMemBuffer, CopiesOwnTheirBytes)
  {
    std::string source = PatternBytes(33u);
    const gpg::MemBuffer<const char> copy = gpg::CopyMemBuffer(source.data(), source.size());
    source.assign(33u, 'x');
    ASSERT_EQ(copy.Size(), 33u);
    EXPECT_EQ(std::string(copy.begin(), copy.end()), PatternBytes(33u));

    const gpg::MemBuffer<char> again = gpg::CopyMemBuffer(copy);
    ASSERT_EQ(again.Size(), 33u);
    EXPECT_NE(static_cast<const void*>(again.data()), static_cast<const void*>(copy.data()));
    EXPECT_EQ(std::string(again.begin(), again.end()), PatternBytes(33u));

    EXPECT_EQ(gpg::CopyMemBuffer(nullptr, 4u).data(), nullptr);
  }

  TEST(GpgMemBuffer, SubBufferSharesStorageAndChecksBounds)
  {
    gpg::MemBuffer<char> buffer = gpg::AllocMemBuffer(16u);
    for (std::size_t index = 0; index < 16u; ++index) {
      buffer[index] = static_cast<char>('a' + index);
    }

    const gpg::MemBuffer<char> middle = buffer.SubBuffer(4u, 5u);
    EXPECT_EQ(middle.Size(), 5u);
    EXPECT_EQ(std::string(middle.begin(), middle.end()), "efghi");
    EXPECT_EQ(middle.data(), buffer.data() + 4);
    EXPECT_EQ(middle.mData.get(), buffer.mData.get());

    EXPECT_EQ(buffer.GetPtr(15u, 1u), buffer.data() + 15);
    EXPECT_THROW((void)buffer.GetPtr(15u, 2u), std::range_error);
    EXPECT_THROW((void)buffer.SubBuffer(10u, 7u), std::range_error);

    gpg::MemBuffer<char> reset = buffer;
    reset.Reset();
    EXPECT_EQ(reset.data(), nullptr);
    EXPECT_EQ(reset.Size(), 0u);
    EXPECT_EQ(buffer.Size(), 16u);
  }

  TEST(GpgMemBuffer, LoadFileToMemBufferReadsWhatWasWritten)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("blob.bin");
    const std::string bytes = PatternBytes(5000u, 7u);
    faf_core_tests::WriteWholeFile(path, bytes);

    const gpg::MemBuffer<const char> loaded = gpg::LoadFileToMemBuffer(path.c_str());
    ASSERT_EQ(loaded.Size(), bytes.size());
    EXPECT_EQ(std::string(loaded.begin(), loaded.end()), bytes);

    EXPECT_EQ(gpg::LoadFileToMemBuffer(folder.File("missing.bin").c_str()).data(), nullptr);
    EXPECT_EQ(gpg::LoadFileToMemBuffer("").data(), nullptr);
    EXPECT_EQ(gpg::LoadFileToMemBuffer(nullptr).data(), nullptr);
  }

  // ---------------------------------------------------------------------------------------------
  // MemBufferStream
  // ---------------------------------------------------------------------------------------------

  TEST(GpgMemBufferStream, WriteThenReadBack)
  {
    gpg::MemBufferStream stream(64u);
    EXPECT_EQ(stream.GetLength(), 0u);
    EXPECT_TRUE(stream.VirtAtEnd());

    stream.Write("hello ", 6u);
    stream.Write("world", 5u);
    EXPECT_EQ(stream.GetLength(), 11u);
    EXPECT_FALSE(stream.VirtAtEnd());
    EXPECT_EQ(ReadAll(stream), "hello world");
    EXPECT_TRUE(stream.VirtAtEnd());
  }

  TEST(GpgMemBufferStream, GrowsPastItsFirstCapacity)
  {
    gpg::MemBufferStream stream(4u);
    const std::string bytes = PatternBytes(10000u, 3u);
    for (std::size_t offset = 0; offset < bytes.size(); offset += 333u) {
      stream.Write(bytes.data() + offset, std::min<std::size_t>(333u, bytes.size() - offset));
    }
    EXPECT_EQ(stream.GetLength(), bytes.size());
    EXPECT_GE(stream.GetBuffer().Size(), bytes.size());
    EXPECT_EQ(ContentOf(stream), bytes);
    EXPECT_EQ(ReadAll(stream, 1000u), bytes);
  }

  TEST(GpgMemBufferStream, InterleavedReadsSeeLaterWrites)
  {
    gpg::MemBufferStream stream(8u);
    char out[16] = {};
    stream.Write("ab", 2u);
    EXPECT_EQ(stream.Read(out, 1u), 1u);
    EXPECT_EQ(out[0], 'a');
    stream.Write("cdefghijkl", 10u); // grows; the read cursor keeps its offset
    EXPECT_EQ(stream.Read(out, 16u), 11u);
    EXPECT_EQ(std::string_view(out, 11u), "bcdefghijkl"sv);
    EXPECT_EQ(stream.VirtTell(gpg::Stream::ModeReceive), 12u);
  }

  TEST(GpgMemBufferStream, TellReportsEachCursor)
  {
    gpg::MemBufferStream stream(32u);
    stream.Write("0123456789", 10u);
    char out[4] = {};
    (void)stream.Read(out, 4u);
    EXPECT_EQ(stream.VirtTell(gpg::Stream::ModeReceive), 4u);
    EXPECT_EQ(stream.VirtTell(gpg::Stream::ModeSend), 10u);
    EXPECT_THROW((void)stream.VirtTell(gpg::Stream::ModeBoth), std::invalid_argument);
    EXPECT_THROW((void)stream.VirtTell(gpg::Stream::ModeNone), std::invalid_argument);
  }

  TEST(GpgMemBufferStream, SeekReadCursorFromEachOrigin)
  {
    gpg::MemBufferStream stream(32u);
    stream.Write("0123456789", 10u);
    char out = 0;

    EXPECT_EQ(stream.Seek(gpg::Stream::OriginBegin, 3), 3u);
    (void)stream.Read(&out, 1u);
    EXPECT_EQ(out, '3');
    EXPECT_EQ(stream.Seek(gpg::Stream::OriginCurr, 2), 6u);
    (void)stream.Read(&out, 1u);
    EXPECT_EQ(out, '6');
    EXPECT_EQ(stream.Seek(gpg::Stream::OriginEnd, -1), 9u);
    (void)stream.Read(&out, 1u);
    EXPECT_EQ(out, '9');
    EXPECT_EQ(stream.Seek(gpg::Stream::OriginCurr, -10), 0u);

    EXPECT_THROW((void)stream.Seek(gpg::Stream::OriginBegin, -1), std::invalid_argument);
    EXPECT_THROW((void)stream.Seek(gpg::Stream::OriginCurr, -1), std::invalid_argument);
    EXPECT_THROW((void)stream.Seek(static_cast<gpg::Stream::SeekOrigin>(7), 0), std::invalid_argument);
  }

  TEST(GpgMemBufferStream, SeekingTheWriteCursorPastTheEndZeroFills)
  {
    gpg::MemBufferStream stream(4u);
    stream.Write("abc", 3u);
    EXPECT_EQ(stream.VirtSeek(gpg::Stream::ModeSend, gpg::Stream::OriginBegin, 6), 6u);
    stream.Write("z", 1u);
    EXPECT_EQ(stream.GetLength(), 7u);
    EXPECT_EQ(ContentOf(stream), std::string("abc\0\0\0z", 7u));

    // Back over written bytes: the write cursor overwrites, the length stays.
    EXPECT_EQ(stream.VirtSeek(gpg::Stream::ModeSend, gpg::Stream::OriginBegin, 1), 1u);
    stream.Write("B", 1u);
    EXPECT_EQ(ContentOf(stream), std::string("aBc\0\0\0z", 7u));
  }

  TEST(GpgMemBufferStream, SeekBothMovesBothCursors)
  {
    gpg::MemBufferStream stream(16u);
    stream.Write("abcdef", 6u);
    EXPECT_EQ(stream.VirtSeek(gpg::Stream::ModeBoth, gpg::Stream::OriginBegin, 2), 2u);
    EXPECT_EQ(stream.VirtTell(gpg::Stream::ModeReceive), 2u);
    EXPECT_EQ(stream.VirtTell(gpg::Stream::ModeSend), 2u);
  }

  TEST(GpgMemBufferStream, ReadOnlyStreamRefusesWrites)
  {
    const std::string bytes = "read only";
    const gpg::MemBuffer<const char> source = gpg::CopyMemBuffer(bytes.data(), bytes.size());
    gpg::MemBufferStream stream(source);
    EXPECT_EQ(stream.GetLength(), bytes.size());
    EXPECT_EQ(stream.LeftToWrite(), 0u);

    EXPECT_THROW(stream.Write("x", 1u), std::runtime_error);
    EXPECT_THROW((void)stream.VirtSeek(gpg::Stream::ModeSend, gpg::Stream::OriginBegin, 0), std::logic_error);
    EXPECT_THROW((void)stream.Seek(gpg::Stream::OriginBegin, 100), std::runtime_error);
    EXPECT_THROW((void)stream.GetBuffer(), std::runtime_error);
    EXPECT_EQ(stream.GetConstBuffer().data(), source.data());
    EXPECT_EQ(ReadAll(stream), bytes);
  }

  TEST(GpgMemBufferStream, ReadOnlyInitialLengthLimitsTheReadWindow)
  {
    const gpg::MemBuffer<const char> source = gpg::CopyMemBuffer("abcdefgh", 8u);
    gpg::MemBufferStream stream(source, 3u);
    EXPECT_EQ(stream.GetLength(), 3u);
    EXPECT_EQ(ReadAll(stream), "abc");
    EXPECT_THROW((void)gpg::MemBufferStream(source, 9u), std::invalid_argument);
  }

  TEST(GpgMemBufferStream, WritableFromCallerBuffer)
  {
    gpg::MemBuffer<char> storage = gpg::AllocMemBuffer(16u);
    std::memcpy(storage.data(), "0123456789", 10u);
    gpg::MemBufferStream stream(storage, 4u);

    // The first `initialLength` bytes are readable; writes start at offset 0 of the same storage.
    EXPECT_EQ(stream.GetLength(), 4u);
    EXPECT_EQ(stream.GetBuffer().data(), storage.data());
    stream.Write("ab", 2u);
    EXPECT_EQ(std::string_view(storage.data(), 4u), "ab23"sv);
    EXPECT_EQ(ReadAll(stream), "ab23");
    EXPECT_THROW((void)gpg::MemBufferStream(storage, 17u), std::invalid_argument);
  }

  TEST(GpgMemBufferStream, UnGetByteBeyondStartThrows)
  {
    gpg::MemBufferStream stream(8u);
    stream.Write("q", 1u);
    EXPECT_EQ(stream.GetByte(), 'q');
    stream.UnGetByte('q');
    EXPECT_EQ(stream.GetByte(), 'q');
    stream.UnGetByte('q');
    EXPECT_THROW(stream.UnGetByte('q'), std::runtime_error);
  }

  // ---------------------------------------------------------------------------------------------
  // TextWriter / TextReader
  // ---------------------------------------------------------------------------------------------

  std::string WriteText(const int mode, const std::string& text)
  {
    gpg::MemBufferStream stream(4u);
    gpg::TextWriter writer(&stream, mode);
    writer.WriteChars(text.data(), static_cast<int>(text.size()));
    return ContentOf(stream);
  }

  TEST(GpgTextIo, WriterLineEndingModes)
  {
    const std::string mixed = "a\r\nb\nc\rd";
    EXPECT_EQ(WriteText(0, mixed), mixed);         // raw
    EXPECT_EQ(WriteText(1, mixed), "a\nb\nc\nd");  // LF
    EXPECT_EQ(WriteText(2, mixed), "a\r\nb\r\nc\r\nd"); // CR LF
    EXPECT_EQ(WriteText(3, mixed), "a\rb\rc\rd");  // CR
    // A CR followed by a CR is two line ends.
    EXPECT_EQ(WriteText(1, "x\r\ry"), "x\n\ny");
  }

  TEST(GpgTextIo, WriterStringFormsAndPrintf)
  {
    gpg::MemBufferStream stream(4u);
    gpg::TextWriter writer(&stream, 2);
    writer.WriteCString("one\n");
    writer.WriteCString(nullptr);
    writer.WriteString(fa::string("two\n"));
    writer.Printf("%d-%s-%04x\n", 42, "three", 0xBEEF);
    writer.WriteNewline();
    EXPECT_EQ(ContentOf(stream), "one\r\ntwo\r\n42-three-beef\r\n\r\n");
  }

  TEST(GpgTextIo, ReaderKeepsTerminatorsAsWrittenWithoutNormalizing)
  {
    const std::string text = "l1\nl2\r\nl3\rl4";
    const gpg::MemBuffer<const char> source = gpg::CopyMemBuffer(text.data(), text.size());
    gpg::MemBufferStream stream(source);
    gpg::TextReader reader(&stream, false);
    EXPECT_EQ(reader.ReadLine().view(), "l1\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l2\r\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l3\r"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l4"sv); // end of input ends the line, nothing appended
    EXPECT_EQ(reader.ReadLine().view(), ""sv);
  }

  TEST(GpgTextIo, ReaderNormalizesCrAndCrLfToLf)
  {
    const std::string text = "l1\nl2\r\nl3\rl4\r";
    const gpg::MemBuffer<const char> source = gpg::CopyMemBuffer(text.data(), text.size());
    gpg::MemBufferStream stream(source);
    gpg::TextReader reader(&stream, true);
    EXPECT_EQ(reader.ReadLine().view(), "l1\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l2\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l3\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "l4\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), ""sv);
  }

  TEST(GpgTextIo, ReadByteNormalizes)
  {
    const std::string text = "a\r\nb\rc";
    const gpg::MemBuffer<const char> source = gpg::CopyMemBuffer(text.data(), text.size());
    gpg::MemBufferStream stream(source);
    gpg::TextReader reader(&stream, true);
    EXPECT_EQ(reader.ReadByte(), 'a');
    EXPECT_EQ(reader.ReadByte(), '\n');
    EXPECT_EQ(reader.ReadByte(), 'b');
    EXPECT_EQ(reader.ReadByte(), '\n');
    EXPECT_EQ(reader.ReadByte(), 'c'); // ungot after the bare CR
    EXPECT_EQ(reader.ReadByte(), -1);
  }

  TEST(GpgTextIo, WriterThenReaderRoundTrip)
  {
    gpg::MemBufferStream stream(4u);
    gpg::TextWriter writer(&stream, 2);
    writer.WriteCString("alpha\nbeta\ngamma\n");
    gpg::TextReader reader(&stream, true);
    EXPECT_EQ(reader.ReadLine().view(), "alpha\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "beta\n"sv);
    EXPECT_EQ(reader.ReadLine().view(), "gamma\n"sv);
  }
} // namespace
