// The terrain tesselator's vertex cache and collision quads (moho/render/tess/CTesselator.h), without a camera or
// a terrain resource: the parts that only read the heightfield.

#include "moho/render/tess/CTesselator.h"
#include "moho/sim/STIMap.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace
{
  using Rect16 = moho::ITesselator::Rect16;

  Rect16 RectAt(const std::uint16_t x, const std::uint16_t z, const std::uint16_t height = 0)
  {
    Rect16 rect{};
    rect.xPos = x;
    rect.xSize = height;
    rect.zPos = z;
    rect.zSize = 1u;
    return rect;
  }

  /**
   * A 64 x 64 map's heightfield, whose sample at (x, z) is 100 * x + z over its whole sample grid (Width() by
   * Height(), which may be one more than the map size), and a tesselator over it (1.3 MB, on the heap).
   */
  class TesselatorFixture : public testing::Test
  {
  protected:
    TesselatorFixture()
      : mField(64, 64)
    {
      mLastX = mField.Width() - 1;
      mLastZ = mField.Height() - 1;
      std::vector<std::uint16_t> heights(static_cast<std::size_t>(mField.Width() * mField.Height()));
      for (int z = 0; z <= mLastZ; ++z) {
        for (int x = 0; x <= mLastX; ++x) {
          heights[static_cast<std::size_t>(x + z * mField.Width())] = Sample(x, z);
        }
      }
      gpg::Rect2i all{}; // SetElevationRectRaw's rectangle is inclusive (0x00477F10 loops x <= x1, z <= z1)
      all.x0 = 0;
      all.z0 = 0;
      all.x1 = mLastX;
      all.z1 = mLastZ;
      mField.SetElevationRectRaw(all, heights.data(), mField.Width());
      mTesselator = std::make_unique<moho::CTesselator>(&mField);
    }

    static std::uint16_t Sample(const int x, const int z)
    {
      return static_cast<std::uint16_t>(100 * x + z);
    }

    int mLastX = 0;
    int mLastZ = 0;

    moho::CHeightField mField;
    std::unique_ptr<moho::CTesselator> mTesselator;
  };
} // namespace

// The terrain effect's HeightScale: heights are stored in 1/128 units (0x0080D2E0 loads 0.0078125).
TEST_F(TesselatorFixture, HeightScaleIsOneHundredTwentyEighth)
{
  EXPECT_EQ(mTesselator->GetHeightScale(), 0.0078125f);
}

// A rect added at (x, z) is found there through the 512 x 512 lookup ring; another rect landing in the same
// slot (coordinates equal modulo 512) takes the slot over, and the first no longer answers (0x0080BA30).
TEST_F(TesselatorFixture, LookupFindsTheLatestRectInEachSlot)
{
  EXPECT_EQ(mTesselator->AddRect(RectAt(10, 20)), 0u);
  EXPECT_EQ(mTesselator->AddRect(RectAt(11, 20)), 1u);
  EXPECT_EQ(mTesselator->GetData(20, 10), 0);
  EXPECT_EQ(mTesselator->GetData(20, 11), 1);

  EXPECT_EQ(mTesselator->AddRect(RectAt(10 + 512, 20 + 512)), 2u);
  EXPECT_EQ(mTesselator->GetData(20 + 512, 10 + 512), 2);
  EXPECT_EQ(mTesselator->GetData(20, 10), -1); // the slot now holds the other rect
  EXPECT_EQ(mTesselator->GetRectCacheCount(), 3);
}

// GetIndexAt samples the heightfield at the cell times 2^size, clamped to the field, stores the height in the
// rect's xSize (word * 1/128 * 128), and hands back the cached index on the next request (0x0080D230).
TEST_F(TesselatorFixture, IndexAtSamplesClampsAndCaches)
{
  const std::uint16_t first = mTesselator->GetIndexAt(1, 3, 5); // sample (6, 10)
  const Rect16 sampled = mTesselator->GetRectCacheData()[first];
  EXPECT_EQ(sampled.xPos, 6u);
  EXPECT_EQ(sampled.zPos, 10u);
  EXPECT_EQ(sampled.xSize, 610u);
  EXPECT_EQ(sampled.zSize, 1u);
  EXPECT_EQ(mTesselator->GetIndexAt(1, 3, 5), first);
  EXPECT_EQ(mTesselator->GetRectCacheCount(), 1);

  // Past the edge the sample clamps to the last column or row, but the rect keeps the asked-for position.
  const auto heightAt = [this](const int size, const int x, const int z) {
    return mTesselator->GetRectCacheData()[mTesselator->GetIndexAt(size, x, z)].xSize;
  };
  const std::uint16_t outside = mTesselator->GetIndexAt(2, 50, 60); // (200, 240)
  const Rect16 clamped = mTesselator->GetRectCacheData()[outside];
  EXPECT_EQ(clamped.xPos, 200u);
  EXPECT_EQ(clamped.zPos, 240u);
  EXPECT_EQ(clamped.xSize, Sample(mLastX, mLastZ));
  EXPECT_EQ(heightAt(0, 200, 40), Sample(mLastX, 40)) << "x past the edge";
  EXPECT_EQ(heightAt(0, 40, 200), Sample(40, mLastZ)) << "z past the edge";
  EXPECT_EQ(heightAt(0, mLastX, mLastZ), Sample(mLastX, mLastZ)) << "the last sample itself";
  EXPECT_EQ(heightAt(0, 30, 31), Sample(30, 31)) << "inside";
}

// A collision quad adds four rects (x, height * 128, z, 1) and the two triangles {2, 1, 0} and {1, 2, 3}
// (0x0080C120 through 0x0080D2F0), reporting where they start.
TEST_F(TesselatorFixture, CollisionQuadAddsFourRectsAndTwoTriangles)
{
  ASSERT_EQ(mTesselator->AddRect(RectAt(1, 1)), 0u); // something before, so the starts are not zero
  const Wm3::Vector3f corners[4] = {{10.0f, 1.5f, 20.0f}, {11.0f, 2.0f, 20.0f}, {10.0f, 2.5f, 21.0f}, {11.0f, 3.0f, 21.0f}};
  std::int32_t indexStart = -1;
  std::uint32_t indexCount = 0;
  std::int32_t rectStart = -1;
  std::uint32_t lastRect = 0;
  const std::uint16_t* const last = mTesselator->EmitCollisionQuad(corners, &indexStart, &indexCount, &rectStart, &lastRect);

  EXPECT_EQ(rectStart, 1);
  EXPECT_EQ(lastRect, 4u);
  EXPECT_EQ(indexStart, 0);
  EXPECT_EQ(indexCount, 6u);
  ASSERT_EQ(mTesselator->GetCollisionIndexCount(), 6);
  const std::uint16_t* const indices = mTesselator->GetCollisionIndexData();
  const std::uint16_t expected[6] = {3, 2, 1, 2, 3, 4};
  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(indices[i], expected[i]) << "index " << i;
  }
  EXPECT_EQ(last, indices + 5);

  const Rect16* const rects = mTesselator->GetRectCacheData();
  EXPECT_EQ(rects[1].xPos, 10u);
  EXPECT_EQ(rects[1].xSize, 192u); // 1.5 * 128
  EXPECT_EQ(rects[1].zPos, 20u);
  EXPECT_EQ(rects[4].xPos, 11u);
  EXPECT_EQ(rects[4].xSize, 384u); // 3.0 * 128
  EXPECT_EQ(rects[4].zPos, 21u);
}

// The cache holds at most 65000 rects; past that AddRect stores nothing and answers the last index (0x0080C850).
TEST_F(TesselatorFixture, CacheStopsAtSixtyFiveThousandRects)
{
  for (std::uint32_t i = 0; i < 65000u; ++i) {
    ASSERT_EQ(mTesselator->AddRect(RectAt(static_cast<std::uint16_t>(i % 256), static_cast<std::uint16_t>(i / 256))), i);
  }
  EXPECT_EQ(mTesselator->AddRect(RectAt(300, 300)), 64999u);
  EXPECT_EQ(mTesselator->GetRectCacheCount(), 65000);
}
