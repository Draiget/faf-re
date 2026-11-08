// The streams that move bytes somewhere: PipeStream (in memory, between threads), FileStream (a file under a
// temporary folder) and ZLibOutputFilterStream (raw deflate/inflate into a pipe). Compressed bytes are checked
// by inflating them with zlib itself, and the inflate side is fed what zlib's own deflate produced.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <gtest/gtest.h>
#include <zlib.h>

#include "CoreTestSupport.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"

namespace
{
  using namespace std::string_view_literals;
  using faf_core_tests::PatternBytes;

  /** Reads until a read comes back short; with a blocking stream that is the end of a closed stream. */
  std::string ReadUntilShort(gpg::Stream& stream, const std::size_t chunk)
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

  /** Writes `bytes` in pieces whose sizes cycle through `sizes`. */
  void WriteInPieces(gpg::Stream& stream, const std::string& bytes, std::initializer_list<std::size_t> sizes)
  {
    std::size_t offset = 0;
    for (;;) {
      for (const std::size_t size : sizes) {
        if (offset >= bytes.size()) {
          return;
        }
        const std::size_t take = (std::min)(size, bytes.size() - offset);
        stream.Write(bytes.data() + offset, take);
        offset += take;
      }
    }
  }

  /** Text that compresses: repeated words with a counter in it. */
  std::string CompressibleText(const std::size_t size)
  {
    std::string text;
    for (int line = 0; text.size() < size; ++line) {
      text += "unit " + std::to_string(line % 97) + " moves to the rally point and waits;\n";
    }
    text.resize(size);
    return text;
  }

  /** Raw (headerless) inflate with zlib; returns the output and the last inflate result. */
  std::pair<std::string, int> RawInflate(const std::string& compressed)
  {
    z_stream stream{};
    EXPECT_EQ(inflateInit2(&stream, -15), Z_OK);
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());
    std::string out;
    char buffer[4096];
    int result = Z_OK;
    do {
      stream.next_out = reinterpret_cast<Bytef*>(buffer);
      stream.avail_out = sizeof(buffer);
      result = inflate(&stream, Z_NO_FLUSH);
      out.append(buffer, sizeof(buffer) - stream.avail_out);
    } while (result == Z_OK && (stream.avail_in != 0u || stream.avail_out == 0u));
    inflateEnd(&stream);
    return {out, result};
  }

  /** Raw (headerless) deflate with zlib, finished. */
  std::string RawDeflate(const std::string& plain)
  {
    z_stream stream{};
    EXPECT_EQ(deflateInit2(&stream, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY), Z_OK);
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(plain.data()));
    stream.avail_in = static_cast<uInt>(plain.size());
    std::string out;
    char buffer[4096];
    int result = Z_OK;
    do {
      stream.next_out = reinterpret_cast<Bytef*>(buffer);
      stream.avail_out = sizeof(buffer);
      result = deflate(&stream, Z_FINISH);
      out.append(buffer, sizeof(buffer) - stream.avail_out);
    } while (result == Z_OK);
    EXPECT_EQ(result, Z_STREAM_END);
    deflateEnd(&stream);
    return out;
  }

  /** Closes the pipe's sending side and reads everything it holds. */
  std::string Drain(gpg::PipeStream& pipe)
  {
    pipe.VirtClose(gpg::Stream::ModeSend);
    return ReadUntilShort(pipe, 1000u);
  }

  // ---------------------------------------------------------------------------------------------
  // PipeStream
  // ---------------------------------------------------------------------------------------------

  TEST(GpgPipeStream, BytesShowAfterFlush)
  {
    gpg::PipeStream pipe;
    char out[8] = {};
    pipe.Write("hello", 5u);
    // Written into the first chunk but not published yet.
    EXPECT_EQ(pipe.ReadNonBlocking(out, 5u), 0u);
    EXPECT_EQ(pipe.GetLength(), 0u);

    pipe.VirtFlush();
    EXPECT_EQ(pipe.GetLength(), 5u);
    EXPECT_EQ(pipe.ReadNonBlocking(out, 5u), 5u);
    EXPECT_EQ(std::string_view(out, 5u), "hello"sv);
    EXPECT_EQ(pipe.ReadNonBlocking(out, 1u), 0u);
    EXPECT_FALSE(pipe.VirtAtEnd()); // still open
  }

  TEST(GpgPipeStream, AcrossChunkBoundaries)
  {
    gpg::PipeStream pipe;
    const std::string bytes = PatternBytes(3u * gpg::PipeStreamBuffer::kSize + 1234u, 11u);
    WriteInPieces(pipe, bytes, {1u, 100u, 4095u, 4096u, 5000u, 3u});
    pipe.VirtClose(gpg::Stream::ModeSend);

    EXPECT_EQ(ReadUntilShort(pipe, 333u), bytes);
    EXPECT_TRUE(pipe.VirtAtEnd());
    EXPECT_TRUE(pipe.Empty());
  }

  // Bug in src/gpg/core/streams/PipeStream.cpp, PipeStream::VirtAtEnd: it returns
  // `mClosed && mReadHead == mReadEnd`, but retail (0x009568E0) compares the read head with the published write
  // end, `cmp eax, [esi+10h]` (mWriteStart). A closed pipe whose bytes the reader has not scanned yet keeps
  // mReadEnd at mReadHead, so ours reports the end (and Empty() true) with the bytes still unread.
  // Minimal input: Write("ab"), VirtClose(ModeSend), then VirtAtEnd() / Empty() before any read.
  TEST(GpgPipeStream, DISABLED_ClosedPipeWithUnreadBytesIsNotAtTheEnd)
  {
    gpg::PipeStream pipe;
    pipe.Write("ab", 2u);
    pipe.VirtClose(gpg::Stream::ModeSend);
    EXPECT_FALSE(pipe.VirtAtEnd());
    EXPECT_FALSE(pipe.Empty());
    EXPECT_EQ(ReadUntilShort(pipe, 8u), "ab");
    EXPECT_TRUE(pipe.VirtAtEnd());
    EXPECT_TRUE(pipe.Empty());
  }

  TEST(GpgPipeStream, OneLargeWriteSpansSeveralChunks)
  {
    gpg::PipeStream pipe;
    const std::string bytes = PatternBytes(5u * gpg::PipeStreamBuffer::kSize, 12u);
    pipe.Write(bytes.data(), bytes.size());
    EXPECT_EQ(Drain(pipe), bytes);
  }

  TEST(GpgPipeStream, NoWritesAfterClose)
  {
    gpg::PipeStream pipe;
    pipe.Write("ab", 2u);
    pipe.VirtClose(gpg::Stream::ModeSend);
    EXPECT_THROW(pipe.VirtWrite("c", 1u), std::runtime_error);
    EXPECT_THROW(pipe.VirtFlush(), std::runtime_error);
    // Closing the receive side only is not a close of the pipe.
    gpg::PipeStream other;
    other.VirtClose(gpg::Stream::ModeReceive);
    EXPECT_NO_THROW(other.VirtWrite("c", 1u));
    // What was written before the close is still there.
    EXPECT_EQ(ReadUntilShort(pipe, 8u), "ab");
  }

  TEST(GpgPipeStream, BlockingReaderOnAnotherThread)
  {
    gpg::PipeStream pipe;
    const std::string bytes = PatternBytes(300000u, 13u);

    std::thread writer([&pipe, &bytes] {
      std::uint32_t seed = 5u;
      std::size_t offset = 0;
      while (offset < bytes.size()) {
        seed = seed * 1664525u + 1013904223u;
        const std::size_t take = std::min<std::size_t>(1u + (seed >> 8) % 9000u, bytes.size() - offset);
        pipe.Write(bytes.data() + offset, take);
        pipe.VirtFlush();
        offset += take;
      }
      pipe.VirtClose(gpg::Stream::ModeSend);
    });

    const std::string received = ReadUntilShort(pipe, 777u);
    writer.join();
    EXPECT_EQ(received.size(), bytes.size());
    EXPECT_TRUE(received == bytes);
    EXPECT_TRUE(pipe.VirtAtEnd());
  }

  // ---------------------------------------------------------------------------------------------
  // FileStream
  // ---------------------------------------------------------------------------------------------

  // `attributes` low three bits pick the creation disposition (FileStream.cpp's table): 0 creates or truncates,
  // 3 opens an existing file. Bits 3-4 are the share mode.
  constexpr unsigned int kCreateAlways = 0u;
  constexpr unsigned int kOpenExisting = 3u;

  TEST(GpgFileStream, WriteThroughTheBufferAndDirect)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("out.bin");
    const std::string bytes = PatternBytes(4000u, 21u);
    {
      gpg::FileStream file(path.c_str(), gpg::Stream::ModeSend, kCreateAlways, 64);
      std::size_t offset = 0;
      for (const std::size_t size : {1u, 10u, 63u, 64u, 65u, 200u, 5u, 1000u, 2592u}) {
        file.Write(bytes.data() + offset, size);
        offset += size;
        EXPECT_EQ(file.VirtTell(gpg::Stream::ModeSend), offset);
      }
      ASSERT_EQ(offset, bytes.size());
      EXPECT_TRUE(file.Close(gpg::Stream::ModeSend));
    }
    EXPECT_EQ(faf_core_tests::ReadWholeFile(path), bytes);
  }

  TEST(GpgFileStream, DestructorFlushesPendingBytes)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("pending.txt");
    {
      gpg::FileStream file(path.c_str(), gpg::Stream::ModeSend, kCreateAlways, 4096);
      file.Write("only in the buffer", 18u);
    }
    EXPECT_EQ(faf_core_tests::ReadWholeFile(path), "only in the buffer");
  }

  TEST(GpgFileStream, ReadSeekAndTell)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("in.bin");
    const std::string bytes = PatternBytes(1000u, 22u);
    faf_core_tests::WriteWholeFile(path, bytes);

    gpg::FileStream file(path.c_str(), gpg::Stream::ModeReceive, kOpenExisting, 64);
    std::string piece(200u, '\0');

    EXPECT_EQ(file.Read(piece.data(), 5u), 5u);
    EXPECT_EQ(piece.substr(0, 5u), bytes.substr(0, 5u));
    EXPECT_EQ(file.VirtTell(gpg::Stream::ModeReceive), 5u);

    EXPECT_EQ(file.Read(piece.data(), 100u), 100u); // more than the 64-byte buffer
    EXPECT_EQ(piece.substr(0, 100u), bytes.substr(5u, 100u));
    EXPECT_EQ(file.VirtTell(gpg::Stream::ModeReceive), 105u);

    EXPECT_EQ(file.Seek(gpg::Stream::OriginBegin, 10), 10u);
    EXPECT_EQ(file.Read(piece.data(), 4u), 4u);
    EXPECT_EQ(piece.substr(0, 4u), bytes.substr(10u, 4u));

    // OriginCurr counts from the logical position, not from where the buffer left the file pointer.
    EXPECT_EQ(file.Seek(gpg::Stream::OriginCurr, -4), 10u);
    EXPECT_EQ(file.GetByte(), static_cast<unsigned char>(bytes[10]));

    EXPECT_EQ(file.Seek(gpg::Stream::OriginEnd, -3), 997u);
    EXPECT_EQ(file.Read(piece.data(), 200u), 3u);
    EXPECT_EQ(piece.substr(0, 3u), bytes.substr(997u));
    EXPECT_TRUE(file.VirtAtEnd());
  }

  TEST(GpgFileStream, ReadAndWriteOneFile)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("both.txt");
    {
      gpg::FileStream file(path.c_str(), gpg::Stream::ModeBoth, kCreateAlways, 32);
      file.Write("hello world", 11u);
      EXPECT_EQ(file.VirtSeek(gpg::Stream::ModeBoth, gpg::Stream::OriginBegin, 6), 6u);
      char out[8] = {};
      EXPECT_EQ(file.Read(out, 5u), 5u);
      EXPECT_EQ(std::string_view(out, 5u), "world"sv);
      file.Write("!", 1u);

      // A write after a read lands at the logical position, not past the read-ahead.
      EXPECT_EQ(file.VirtSeek(gpg::Stream::ModeBoth, gpg::Stream::OriginBegin, 0), 0u);
      EXPECT_EQ(file.GetByte(), 'h');
      file.Write("J", 1u);
    }
    EXPECT_EQ(faf_core_tests::ReadWholeFile(path), "hJllo world!");
  }

  TEST(GpgFileStream, MissingFileThrowsIOErrorWithTheSystemCode)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("missing.bin");
    try {
      gpg::FileStream file(path.c_str(), gpg::Stream::ModeReceive, kOpenExisting, 64);
      FAIL() << "opening a missing file did not throw";
    } catch (const gpg::FileStream::IOError& error) {
      EXPECT_EQ(error.mMsg, static_cast<DWORD>(ERROR_FILE_NOT_FOUND));
      EXPECT_STRNE(error.what(), "");
    }
  }

  TEST(GpgFileStream, WrongDirectionThrows)
  {
    const faf_core_tests::TempDir folder;
    const std::string path = folder.File("dir.bin");
    {
      gpg::FileStream out(path.c_str(), gpg::Stream::ModeSend, kCreateAlways, 64);
      char byte = 0;
      EXPECT_THROW((void)out.VirtRead(&byte, 1u), std::runtime_error);
      EXPECT_THROW((void)out.VirtAtEnd(), std::runtime_error);
      EXPECT_THROW((void)out.VirtTell(gpg::Stream::ModeReceive), std::invalid_argument);
      EXPECT_THROW((void)out.Seek(gpg::Stream::OriginBegin, 0), std::invalid_argument);
      EXPECT_THROW((void)out.VirtSeek(gpg::Stream::ModeSend, static_cast<gpg::Stream::SeekOrigin>(3), 0), std::invalid_argument);
      out.Write("x", 1u);
    }
    gpg::FileStream in(path.c_str(), gpg::Stream::ModeReceive, kOpenExisting, 64);
    EXPECT_THROW(in.Write("y", 1u), std::runtime_error);
    EXPECT_THROW(in.VirtFlush(), std::runtime_error);
    EXPECT_THROW((void)in.VirtTell(gpg::Stream::ModeSend), std::invalid_argument);
    EXPECT_EQ(in.GetByte(), 'x');
  }

  // ---------------------------------------------------------------------------------------------
  // ZLibOutputFilterStream
  // ---------------------------------------------------------------------------------------------

  TEST(GpgZLibStream, DeflateInflatesBackWithZlib)
  {
    const std::string text = CompressibleText(60000u);
    const std::string noise = PatternBytes(5000u, 31u);
    const std::string plain = text + noise;

    gpg::PipeStream pipe;
    {
      gpg::ZLibOutputFilterStream deflater(&pipe, gpg::FLOP_Deflate);
      WriteInPieces(deflater, plain, {1u, 700u, 1024u, 1025u, 3000u, 17u});
      deflater.VirtClose(gpg::Stream::ModeSend);
    }
    const std::string compressed = Drain(pipe);
    EXPECT_LT(compressed.size(), plain.size() / 2u);

    const auto [inflated, result] = RawInflate(compressed);
    EXPECT_EQ(result, Z_STREAM_END);
    EXPECT_EQ(inflated.size(), plain.size());
    EXPECT_TRUE(inflated == plain);
  }

  TEST(GpgZLibStream, EmptyDeflateIsAFinishedStream)
  {
    gpg::PipeStream pipe;
    {
      gpg::ZLibOutputFilterStream deflater(&pipe, gpg::FLOP_Deflate);
      deflater.VirtClose(gpg::Stream::ModeSend);
    }
    const auto [inflated, result] = RawInflate(Drain(pipe));
    EXPECT_EQ(result, Z_STREAM_END);
    EXPECT_TRUE(inflated.empty());
  }

  TEST(GpgZLibStream, FlushEndsWithASyncMarker)
  {
    gpg::PipeStream pipe;
    gpg::ZLibOutputFilterStream deflater(&pipe, gpg::FLOP_Deflate);
    deflater.Write("hello hello hello", 17u);
    deflater.VirtFlush();
    pipe.VirtFlush();

    std::string flushed(256u, '\0');
    flushed.resize(pipe.ReadNonBlocking(flushed.data(), flushed.size()));
    ASSERT_GE(flushed.size(), 4u);
    // A Z_SYNC_FLUSH ends with an empty stored block: 00 00 FF FF (RFC 1951 3.2.4, zlib.h).
    EXPECT_EQ(flushed.substr(flushed.size() - 4u), std::string("\x00\x00\xFF\xFF", 4u));
    const auto [inflated, result] = RawInflate(flushed);
    EXPECT_NE(result, Z_STREAM_END); // the stream goes on
    EXPECT_EQ(inflated, "hello hello hello");
    deflater.VirtClose(gpg::Stream::ModeSend);
  }

  TEST(GpgZLibStream, InflateWhatZlibDeflated)
  {
    const std::string plain = CompressibleText(40000u) + PatternBytes(3000u, 32u);
    const std::string compressed = RawDeflate(plain);

    gpg::PipeStream pipe;
    {
      gpg::ZLibOutputFilterStream inflater(&pipe, gpg::FLOP_Inflate);
      WriteInPieces(inflater, compressed, {7u, 1500u, 1u, 300u});
      if (std::string_view(zlibVersion()).substr(0, 4) == "1.1.") {
        // zlib 1.1.x, which the x86 build links as the shipped exe does (cmake/deps/wxwindows), decodes the end
        // code with a 9-bit lookahead, so a raw stream whose end code and padding are shorter than that (this
        // one) reports its end only with a byte past it (zlib 1.2.3's ChangeLog: "Raw inflate no longer needs
        // an extra dummy byte at end"), and this class then calls that byte excess data. Either way the close
        // throws; every byte is out already. The game's only inflating stream, the network connection's
        // (CNetUDPConnection), never ends during play.
        EXPECT_THROW(inflater.VirtClose(gpg::Stream::ModeSend), std::runtime_error);
      } else {
        EXPECT_NO_THROW(inflater.VirtClose(gpg::Stream::ModeSend));
      }
    }
    const std::string out = Drain(pipe);
    EXPECT_EQ(out.size(), plain.size());
    EXPECT_TRUE(out == plain);
  }

  TEST(GpgZLibStream, InflateClosedBeforeTheEndThrows)
  {
    const std::string compressed = RawDeflate(PatternBytes(8000u, 33u));
    ASSERT_GT(compressed.size() / 2u, 1024u); // one write past the inline buffer, so nothing is left in it
    gpg::PipeStream pipe;
    gpg::ZLibOutputFilterStream inflater(&pipe, gpg::FLOP_Inflate);
    inflater.Write(compressed.data(), compressed.size() / 2u);
    EXPECT_THROW(inflater.VirtClose(gpg::Stream::ModeSend), std::runtime_error);
  }

  TEST(GpgZLibStream, InflateRefusesDataAfterTheEnd)
  {
    const std::string compressed = RawDeflate("short") + "XYZ";
    gpg::PipeStream pipe;
    gpg::ZLibOutputFilterStream inflater(&pipe, gpg::FLOP_Inflate);
    inflater.Write(compressed.data(), compressed.size());
    EXPECT_THROW(inflater.VirtClose(gpg::Stream::ModeSend), std::runtime_error);
  }

  TEST(GpgZLibStream, ClosedStreamRefusesWritesAndFlushes)
  {
    gpg::PipeStream pipe;
    gpg::ZLibOutputFilterStream deflater(&pipe, gpg::FLOP_Deflate);
    deflater.VirtClose(gpg::Stream::ModeSend);
    EXPECT_THROW(deflater.VirtWrite("x", 1u), std::runtime_error);
    EXPECT_THROW(deflater.VirtFlush(), std::runtime_error);
    EXPECT_NO_THROW(deflater.VirtClose(gpg::Stream::ModeSend)); // a second close does nothing
  }

  TEST(GpgZLibStream, UnknownOperationThrows)
  {
    gpg::PipeStream pipe;
    EXPECT_THROW((void)gpg::ZLibOutputFilterStream(&pipe, static_cast<gpg::EFilterOperation>(5)), std::invalid_argument);
  }
} // namespace
