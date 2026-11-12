// The size of the DDS files a material bake writes (src/editor/graph/EdTextureBake.h DdsFileSize): the header and
// every mip level, as the Materials workspace's Stats say them.

#include "editor/graph/EdTextureBake.h"

#include <gtest/gtest.h>

using faf::editor::DdsFileSize;
using faf::editor::DdsKind;

namespace
{
  TEST(
    DdsSize,
    AsMeasured
  )
  {
    // The sizes measured on the files the bake wrote at 1024 px.
    EXPECT_EQ(DdsFileSize(1024, DdsKind::Bc3), 1398256u) << "albedo, DXT5";
    EXPECT_EQ(DdsFileSize(1024, DdsKind::Bc1), 699192u) << "normals, DXT1";
  }

  TEST(
    DdsSize,
    SmallLevelsTakeAWholeBlock
  )
  {
    // 4 x 4: one block; 2 x 2 and 1 x 1 still one block each.
    EXPECT_EQ(DdsFileSize(4, DdsKind::Bc1), 128u + 8u * 3u);
    EXPECT_EQ(DdsFileSize(4, DdsKind::Bc3), 128u + 16u * 3u);
    EXPECT_EQ(DdsFileSize(2, DdsKind::Bgra), 128u + 16u + 4u) << "BGRA: 4 bytes a pixel, 2 x 2 then 1 x 1";
    EXPECT_LT(DdsFileSize(512, DdsKind::Bc3), DdsFileSize(1024, DdsKind::Bc3));
  }
} // namespace
