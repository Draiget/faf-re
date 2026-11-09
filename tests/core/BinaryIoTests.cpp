// gpg::BinaryWriter and gpg::BinaryReader over in-memory streams: every primitive and string form they offer,
// written and read back, with the bytes checked against the raw little-endian layout they document, and the
// short-read behaviour (PrematureEOF) of each read form.

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <gtest/gtest.h>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/streams/MemBufferStream.h"

namespace
{
  using namespace std::string_view_literals;

  struct Packed
  {
    std::int32_t a;
    std::uint16_t b;
    std::uint8_t c;
    std::uint8_t d;
  };
  static_assert(sizeof(Packed) == 8u);

  std::string ContentOf(const gpg::MemBufferStream& stream)
  {
    return std::string(stream.GetConstBuffer().begin(), stream.GetLength());
  }

  /** A read-only stream over `bytes`: every byte is in the read window, so reads take the inline path. */
  gpg::MemBufferStream WindowedReader(const std::string& bytes)
  {
    return gpg::MemBufferStream(gpg::CopyMemBuffer(bytes.data(), bytes.size()));
  }

  /** A writable stream holding `bytes`, whose read window starts empty: reads go through VirtRead. */
  void FillWritable(gpg::MemBufferStream& stream, const std::string& bytes)
  {
    stream.Write(bytes.data(), bytes.size());
  }

  void WriteEveryPrimitive(const gpg::BinaryWriter& writer)
  {
    writer.Write(std::int8_t{-2});
    writer.Write(std::uint8_t{0xFE});
    writer.Write(std::int16_t{-3});
    writer.Write(std::uint16_t{0xCAFE});
    writer.Write(std::int32_t{-4});
    writer.Write(std::uint32_t{0xDEADBEEFu});
    writer.Write(std::int64_t{-5});
    writer.Write(std::uint64_t{0x0102030405060708ULL});
    writer.Write(0.5f);
    writer.Write(-2.0);
    writer.Write(true);
    writer.Write(Packed{0x11223344, 0x5566, 0x77, 0x88});
    writer.Write(std::array<std::uint16_t, 3>{1u, 2u, 0xFFFFu});
  }

  const unsigned char kEveryPrimitive[] = {
    0xFE,                                           // int8 -2
    0xFE,                                           // uint8 0xFE
    0xFD, 0xFF,                                     // int16 -3
    0xFE, 0xCA,                                     // uint16 0xCAFE
    0xFC, 0xFF, 0xFF, 0xFF,                         // int32 -4
    0xEF, 0xBE, 0xAD, 0xDE,                         // uint32 0xDEADBEEF
    0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // int64 -5
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // uint64
    0x00, 0x00, 0x00, 0x3F,                         // float 0.5
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, // double -2.0
    0x01,                                           // bool
    0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x77, 0x88, // Packed
    0x01, 0x00, 0x02, 0x00, 0xFF, 0xFF,             // array<uint16_t, 3>
  };

  void ExpectEveryPrimitive(const gpg::BinaryReader& reader)
  {
    EXPECT_EQ(reader.ReadExact<std::int8_t>(), -2);
    EXPECT_EQ(reader.ReadChar(), 0xFEu);
    EXPECT_EQ(reader.ReadExact<std::int16_t>(), -3);
    EXPECT_EQ(reader.ReadExact<std::uint16_t>(), 0xCAFEu);
    EXPECT_EQ(reader.ReadInt32(), -4);
    int asInt = 0;
    EXPECT_EQ(reader.ReadInt(&asInt), &asInt);
    EXPECT_EQ(static_cast<std::uint32_t>(asInt), 0xDEADBEEFu);
    std::int64_t i64 = 0;
    reader.ReadExact(i64);
    EXPECT_EQ(i64, -5);
    EXPECT_EQ(reader.ReadExact<std::uint64_t>(), 0x0102030405060708ULL);
    EXPECT_EQ(reader.ReadExact<float>(), 0.5f);
    EXPECT_EQ(reader.ReadExact<double>(), -2.0);
    EXPECT_TRUE(reader.ReadExact<bool>());
    const Packed packed = reader.ReadExact<Packed>();
    EXPECT_EQ(packed.a, 0x11223344);
    EXPECT_EQ(packed.b, 0x5566u);
    EXPECT_EQ(packed.c, 0x77u);
    EXPECT_EQ(packed.d, 0x88u);
    std::array<std::uint16_t, 3> values{};
    reader.ReadExact(values);
    EXPECT_EQ(values, (std::array<std::uint16_t, 3>{1u, 2u, 0xFFFFu}));
  }

  TEST(GpgBinaryIo, WriterLaysOutEveryPrimitiveLittleEndian)
  {
    gpg::MemBufferStream stream(4u); // small, so most writes go through VirtWrite
    WriteEveryPrimitive(gpg::BinaryWriter(&stream));
    const std::string bytes = ContentOf(stream);
    ASSERT_EQ(bytes.size(), sizeof(kEveryPrimitive));
    EXPECT_EQ(std::memcmp(bytes.data(), kEveryPrimitive, sizeof(kEveryPrimitive)), 0);
  }

  TEST(GpgBinaryIo, ReaderReadsEveryPrimitiveFromTheWindow)
  {
    gpg::MemBufferStream stream = WindowedReader(std::string(reinterpret_cast<const char*>(kEveryPrimitive), sizeof(kEveryPrimitive)));
    const gpg::BinaryReader reader(&stream);
    ExpectEveryPrimitive(reader);
    EXPECT_THROW((void)reader.ReadChar(), gpg::BinaryReader::PrematureEOF);
  }

  TEST(GpgBinaryIo, ReaderReadsEveryPrimitiveFromAGrowingStream)
  {
    gpg::MemBufferStream stream(4u);
    WriteEveryPrimitive(gpg::BinaryWriter(&stream));
    const gpg::BinaryReader reader(&stream);
    ExpectEveryPrimitive(reader);
    EXPECT_THROW((void)reader.ReadInt32(), gpg::BinaryReader::PrematureEOF);
  }

  TEST(GpgBinaryIo, ArraysAndRawSpans)
  {
    gpg::MemBufferStream stream(64u);
    const gpg::BinaryWriter writer(&stream);
    const std::uint32_t words[4] = {1u, 2u, 3u, 0x80000000u};
    writer.Write(words);
    writer.Write("tail", 4u);
    writer.Write("", 0u);

    const gpg::BinaryReader reader(&stream);
    std::uint32_t back[4] = {};
    reader.ReadExactArray(back, 4u);
    EXPECT_EQ(std::memcmp(back, words, sizeof(words)), 0);
    char tail[4] = {};
    reader.Read(tail, sizeof(tail));
    EXPECT_EQ(std::string_view(tail, 4u), "tail"sv);
    reader.Read(tail, 0u); // a zero-length read at the end is not an EOF
  }

  TEST(GpgBinaryIo, TerminatedStringsRoundTrip)
  {
    gpg::MemBufferStream stream(8u);
    const gpg::BinaryWriter writer(&stream);
    writer.WriteString(fa::string("first"));
    writer.WriteString(fa::string());
    const fa::string pointed("pointed");
    writer.WriteString(&pointed);
    writer.WriteString(static_cast<const fa::string*>(nullptr)); // a null string is an empty one
    EXPECT_EQ(ContentOf(stream), std::string("first\0\0pointed\0\0", 16u));

    const gpg::BinaryReader reader(&stream);
    fa::string out("previous contents");
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), "first"sv);
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), ""sv);
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), "pointed"sv);
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), ""sv);
  }

  TEST(GpgBinaryIo, TerminatedStringEndsAtEndOfInputWithoutThrowing)
  {
    gpg::MemBufferStream stream = WindowedReader("no terminator");
    const gpg::BinaryReader reader(&stream);
    fa::string out;
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), "no terminator"sv);
    reader.ReadString(&out);
    EXPECT_EQ(out.view(), ""sv);
  }

  TEST(GpgBinaryIo, LengthPrefixedStrings)
  {
    const auto prefixed = [](const std::int32_t length, const std::string_view body) {
      std::string bytes(reinterpret_cast<const char*>(&length), 4u);
      bytes.append(body);
      return bytes;
    };

    {
      gpg::MemBufferStream stream = WindowedReader(prefixed(5, "hello") + prefixed(0, ""));
      const gpg::BinaryReader reader(&stream);
      fa::string out;
      reader.ReadLengthPrefixedString(&out);
      EXPECT_EQ(out.view(), "hello"sv);
      reader.ReadLengthPrefixedString(&out);
      EXPECT_EQ(out.view(), ""sv);
      reader.ReadLengthPrefixedString(nullptr); // nothing to read into: nothing is read
      EXPECT_TRUE(stream.VirtAtEnd());
    }
    {
      gpg::MemBufferStream stream = WindowedReader(prefixed(-1, "x"));
      fa::string out;
      EXPECT_THROW(gpg::BinaryReader(&stream).ReadLengthPrefixedString(&out), std::runtime_error);
    }
    {
      gpg::MemBufferStream stream = WindowedReader(prefixed(10, "abc"));
      fa::string out;
      EXPECT_THROW(gpg::BinaryReader(&stream).ReadLengthPrefixedString(&out), gpg::BinaryReader::PrematureEOF);
    }
  }

  TEST(GpgBinaryIo, ShortReadsThrowPrematureEOF)
  {
    for (std::size_t available = 0; available < 8u; ++available) {
      gpg::MemBufferStream windowed = WindowedReader(std::string(available, 'z'));
      EXPECT_THROW((void)gpg::BinaryReader(&windowed).ReadExact<std::uint64_t>(), gpg::BinaryReader::PrematureEOF)
        << available << " bytes";

      gpg::MemBufferStream written(16u);
      FillWritable(written, std::string(available, 'z'));
      EXPECT_THROW((void)gpg::BinaryReader(&written).ReadExact<std::uint64_t>(), gpg::BinaryReader::PrematureEOF)
        << available << " bytes";
    }

    gpg::MemBufferStream three = WindowedReader("abc");
    const gpg::BinaryReader reader(&three);
    EXPECT_THROW((void)reader.ReadInt32(), gpg::BinaryReader::PrematureEOF);
    EXPECT_THROW((void)reader.ReadInt(nullptr), gpg::BinaryReader::PrematureEOF);
  }

  TEST(GpgBinaryIo, PrematureEOFCarriesItsMessage)
  {
    const gpg::BinaryReader::PrematureEOF error;
    EXPECT_STREQ(error.what(), "Premature EOF");
    const std::runtime_error& base = error;
    EXPECT_STREQ(base.what(), "Premature EOF");
  }

  TEST(GpgBinaryIo, ReaderAndWriterKeepTheirStream)
  {
    gpg::MemBufferStream stream(4u);
    const gpg::BinaryWriter writer(&stream, 7u);
    gpg::BinaryReader reader(&stream);
    EXPECT_EQ(writer.stream(), &stream);
    EXPECT_EQ(reader.stream(), &stream);
    EXPECT_EQ(static_cast<const gpg::BinaryReader&>(reader).stream(), &stream);
  }
} // namespace
