// The map editor's kept images (src/editor/doc/EdImageChunks.cpp): the DDS images inside a `.scmap` found, and the
// original ones put back in place of the engine's re-encoded copies.

#include "editor/doc/EdImageChunks.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

namespace
{
  // A chunk: the length, "DDS ", the header size 124, then filler to `length`.
  std::string Chunk(const std::size_t length, const char fill)
  {
    std::string chunk(4 + length, fill);
    const std::int32_t size = static_cast<std::int32_t>(length);
    std::memcpy(chunk.data(), &size, 4);
    std::memcpy(chunk.data() + 4, "DDS ", 4);
    const std::uint32_t header = 124;
    std::memcpy(chunk.data() + 8, &header, 4);
    return chunk;
  }

  TEST(ImageChunks, FindsThemAndPutsTheOriginalsBack)
  {
    const std::string a = Chunk(200, 'a');
    // An image whose data happens to hold "DDS " is still one image.
    std::string b = Chunk(300, 'b');
    std::memcpy(b.data() + 150, "DDS ", 4);
    const std::string c = Chunk(128, 'c');
    const std::string bytes = "head" + a + "mid" + b + c + "tail";
    const std::vector<faf::editor::ImageChunk> chunks = faf::editor::FindImageChunks(bytes, 0);
    ASSERT_EQ(chunks.size(), 3u);
    EXPECT_EQ(chunks[0].at, 4u);
    EXPECT_EQ(chunks[0].size, a.size());
    EXPECT_EQ(chunks[1].size, b.size());
    // The first and last kept as the originals (of other sizes), the middle as written.
    const std::vector<std::string> originals = {Chunk(150, 'x'), Chunk(300, 'y'), Chunk(140, 'z')};
    const std::string patched = faf::editor::WithOriginalImages(bytes, chunks, originals, {true, false, true});
    EXPECT_EQ(patched, "head" + originals[0] + "mid" + b + originals[2] + "tail");
    // Counts that differ leave the bytes alone.
    EXPECT_EQ(faf::editor::WithOriginalImages(bytes, chunks, {originals[0]}, {true}), bytes);
    // Nothing before `from` is looked at.
    EXPECT_EQ(faf::editor::FindImageChunks(bytes, chunks[1].at).size(), 2u);
  }
} // namespace
