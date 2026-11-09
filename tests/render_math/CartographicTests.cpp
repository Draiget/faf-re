// The map's cartographic decal batches (moho/render/Cartographic.h) read and written without a device: the
// stream format of CartographicDecalBatch::Read (0x007D5400) and Write (0x007D5650).

#include "moho/render/Cartographic.h"

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/streams/MemBufferStream.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace
{
  constexpr std::uint32_t kVersionWithTechnique = 0x3Cu; // Read takes the technique name from 0x3C on

  void AppendInt(std::string& bytes, const std::int32_t value)
  {
    bytes.append(reinterpret_cast<const char*>(&value), sizeof(value));
  }

  void AppendFloat(std::string& bytes, const float value)
  {
    bytes.append(reinterpret_cast<const char*>(&value), sizeof(value));
  }

  /** The payload after the technique name: texture path, count, nine floats per decal. */
  std::string Payload(const int decals)
  {
    std::string bytes = std::string("/textures/ui/cartographic.dds") + '\0';
    AppendInt(bytes, decals);
    for (int decal = 0; decal < decals; ++decal) {
      for (int lane = 0; lane < 9; ++lane) {
        AppendFloat(bytes, static_cast<float>(decal * 100 + lane) + 0.25f);
      }
    }
    return bytes;
  }

  std::string Written(moho::CartographicDecalBatch& batch)
  {
    gpg::MemBufferStream stream(16u);
    gpg::BinaryWriter writer(&stream);
    batch.Write(writer);
    return std::string(stream.GetConstBuffer().begin(), stream.GetLength());
  }

  gpg::MemBufferStream Reader(const std::string& bytes)
  {
    return gpg::MemBufferStream(gpg::CopyMemBuffer(bytes.data(), bytes.size()));
  }
} // namespace

// A batch read at the current version writes back the same bytes: technique and texture as NUL-terminated
// strings, the decal count, then each decal's nine floats in order.
TEST(RenderCartographic, BatchWritesBackWhatItRead)
{
  for (const int decals : {0, 1, 3}) {
    SCOPED_TRACE(testing::Message() << decals << " decals");
    const std::string input = std::string("CartographicDecal") + '\0' + Payload(decals);
    gpg::MemBufferStream stream = Reader(input);
    gpg::BinaryReader reader(&stream);
    moho::CartographicDecalBatch batch(kVersionWithTechnique, reader);

    EXPECT_STREQ(batch.mTechniqueName.c_str(), "CartographicDecal");
    EXPECT_STREQ(batch.mTexturePath.c_str(), "/textures/ui/cartographic.dds");
    EXPECT_EQ(batch.mDecals.mDecalCount, decals);
    EXPECT_TRUE(batch.mNeedsVertexUpload);
    EXPECT_EQ(Written(batch), input);
  }
}

// Before version 0x3C a batch has no technique name in the stream; it reads as "Decal" (0x007D5400), and writes
// it out, so a legacy batch saves in the current form.
TEST(RenderCartographic, LegacyBatchDefaultsToTheDecalTechnique)
{
  const std::string legacy = Payload(2);
  gpg::MemBufferStream stream = Reader(legacy);
  gpg::BinaryReader reader(&stream);
  moho::CartographicDecalBatch batch(kVersionWithTechnique - 1u, reader);
  EXPECT_STREQ(batch.mTechniqueName.c_str(), "Decal");
  EXPECT_EQ(batch.mDecals.mDecalCount, 2);
  EXPECT_EQ(Written(batch), std::string("Decal") + '\0' + legacy);
}

// Reading again replaces the batch (Read calls Shutdown first), and a copy keeps every decal.
TEST(RenderCartographic, ReadReplacesAndCopyKeepsTheDecals)
{
  const std::string first = std::string("A") + '\0' + Payload(3);
  const std::string second = std::string("B") + '\0' + Payload(1);
  gpg::MemBufferStream firstStream = Reader(first);
  gpg::BinaryReader firstReader(&firstStream);
  moho::CartographicDecalBatch batch(kVersionWithTechnique, firstReader);

  const moho::CartographicDecalBatch copy(batch);
  gpg::MemBufferStream secondStream = Reader(second);
  gpg::BinaryReader secondReader(&secondStream);
  batch.Read(kVersionWithTechnique, secondReader);

  EXPECT_EQ(batch.mDecals.mDecalCount, 1);
  EXPECT_EQ(Written(batch), second);
  moho::CartographicDecalBatch copyAgain(copy);
  EXPECT_EQ(copyAgain.mDecals.mDecalCount, 3);
  EXPECT_EQ(Written(copyAgain), first);
}
