// Symmetry detection with markers and Make symmetric with options (src/editor/tools/EdSymmetryCheck.cpp,
// EdSymmetrize.cpp; FAF Studio's symmetry.lua and `symmetrize` op): images about any centre, start positions and
// resource markers that prove or rule out a mode, an axis a little off the middle, and the heights, masks and
// terrain types made symmetric from a chosen part, combined, cross-faded or about a moved centre.

#include "editor/tools/EdSymmetrize.h"
#include "editor/tools/EdSymmetryCheck.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <random>
#include <set>
#include <utility>
#include <vector>

namespace
{
  using faf::editor::DetectSymmetry;
  using faf::editor::Symmetry;
  using faf::editor::SymmetryCombine;
  using faf::editor::SymmetryMarker;
  using faf::editor::SymmetrizeOptions;

  constexpr int kSize = 65;
  using Kind = SymmetryMarker::Kind;

  std::vector<std::uint16_t> Random(
    const unsigned seed
  )
  {
    std::mt19937 random(seed);
    std::vector<std::uint16_t> words(kSize * kSize);
    for (std::uint16_t& w : words) {
      w = static_cast<std::uint16_t>(4000 + random() % 3000);
    }
    return words;
  }

  std::uint16_t At(
    const std::vector<std::uint16_t>& words,
    const int x,
    const int z
  )
  {
    return words[static_cast<std::size_t>(z) * kSize + static_cast<std::size_t>(x)];
  }

  constexpr Symmetry kExact[] = {
    Symmetry::LeftRight,
    Symmetry::TopBottom,
    Symmetry::DiagonalBack,
    Symmetry::DiagonalForward,
    Symmetry::HalfTurn,
    Symmetry::BothAxes,
    Symmetry::BothDiagonals,
    Symmetry::QuarterTurns,
  };

  TEST(
    Symmetrize,
    ImagesAboutTheMiddleAreTheBrushCopies
  )
  {
    for (const Symmetry symmetry : kExact) {
      for (const auto& [x, z] : std::vector<std::pair<float, float>>{{10.0f, 20.0f}, {3.0f, 50.0f}, {40.0f, 7.0f}}) {
        float bx[faf::editor::kMaxSymmetryCopies];
        float bz[faf::editor::kMaxSymmetryCopies];
        const int brush = faf::editor::HeightBrushCentres(kSize, kSize, x, z, symmetry, 3, bx, bz);
        float ix[faf::editor::kMaxSymmetryCopies];
        float iz[faf::editor::kMaxSymmetryCopies];
        const int images = faf::editor::SymmetryImages(symmetry, 3, 32.0f, 32.0f, x, z, ix, iz);
        std::set<std::pair<float, float>> a;
        std::set<std::pair<float, float>> b;
        for (int i = 0; i < brush; ++i) {
          a.insert({bx[i], bz[i]});
        }
        for (int i = 0; i < images; ++i) {
          b.insert({ix[i], iz[i]});
        }
        EXPECT_EQ(a, b) << "mode " << static_cast<int>(symmetry) << " at " << x << "," << z;
      }
    }
  }

  TEST(
    Symmetrize,
    MarkersShowTheSymmetryOfAFlatMap
  )
  {
    const std::vector<std::uint16_t> flat(kSize * kSize, 5000);
    // Starts and mass mirrored left / right only.
    std::vector<SymmetryMarker> markers = {
      {10.0f, 20.0f, Kind::Start},
      {54.0f, 20.0f, Kind::Start},
      {15.0f, 40.0f, Kind::Mass},
      {49.0f, 40.0f, Kind::Mass},
      {12.0f, 25.0f, Kind::Mass},
      {52.0f, 25.0f, Kind::Mass},
    };
    faf::editor::DetectedSymmetry found = DetectSymmetry(flat.data(), kSize, kSize, markers);
    EXPECT_EQ(found.symmetry, Symmetry::LeftRight);
    EXPECT_EQ(found.startsMatched, 2);
    EXPECT_EQ(found.resourcesMatched, 4);
    EXPECT_EQ(DetectSymmetry(flat.data(), kSize, kSize).symmetry, Symmetry::None) << "flat and no markers: nothing";

    // The same in all four corners: both axes (more partners than either mirror alone).
    markers = {
      {10.0f, 20.0f, Kind::Start},
      {54.0f, 20.0f, Kind::Start},
      {10.0f, 44.0f, Kind::Start},
      {54.0f, 44.0f, Kind::Start},
    };
    EXPECT_EQ(DetectSymmetry(flat.data(), kSize, kSize, markers).symmetry, Symmetry::BothAxes);
  }

  TEST(
    Symmetrize,
    MarkersRuleOutAModeTheHeightsFit
  )
  {
    // Heights mirrored left / right, but the starts are mirrored top / bottom: the heights alone would say left /
    // right.
    std::vector<std::uint16_t> heights = Random(3);
    std::string error;
    SymmetrizeOptions options;
    options.symmetry = Symmetry::LeftRight;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(heights.data(), kSize, kSize, options, error)) << error;
    EXPECT_EQ(DetectSymmetry(heights.data(), kSize, kSize).symmetry, Symmetry::LeftRight);
    const std::vector<SymmetryMarker> starts = {{10.0f, 12.0f, Kind::Start}, {10.0f, 52.0f, Kind::Start}};
    EXPECT_NE(DetectSymmetry(heights.data(), kSize, kSize, starts).symmetry, Symmetry::LeftRight);
  }

  TEST(
    Symmetrize,
    MatchingHeightsOutweighRoughlyPlacedResources
  )
  {
    // As on SCMP_009: a half turn in the heights and the starts, but a third of the resource markers without a partner.
    std::vector<std::uint16_t> heights = Random(5);
    SymmetrizeOptions options;
    options.symmetry = Symmetry::HalfTurn;
    std::string error;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(heights.data(), kSize, kSize, options, error)) << error;
    std::vector<SymmetryMarker> markers = {{10.0f, 12.0f, Kind::Start}, {54.0f, 52.0f, Kind::Start}};
    for (int i = 0; i < 6; ++i) {
      const float x = 8.0f + 6.0f * static_cast<float>(i);
      markers.push_back({x, 20.0f, Kind::Mass});
      if (i < 3) {
        markers.push_back({64.0f - x, 44.0f, Kind::Mass}); // the partner of the first three: 3 of 9 left alone
      }
    }
    const faf::editor::DetectedSymmetry found = DetectSymmetry(heights.data(), kSize, kSize, markers);
    EXPECT_EQ(found.symmetry, Symmetry::HalfTurn);
    EXPECT_EQ(found.startsMatched, 2);
  }

  TEST(
    Symmetrize,
    AnAxisOffTheMiddleIsFoundFromThePartners
  )
  {
    const std::vector<std::uint16_t> flat(kSize * kSize, 5000);
    // Mirrored about x = 33.5, not the middle (32): the partners lie 3 off their mirror images about the middle,
    // within the tolerance, and say where the axis is.
    const std::vector<SymmetryMarker> markers = {
      {10.0f, 20.0f, Kind::Start},
      {57.0f, 20.0f, Kind::Start},
      {20.0f, 40.0f, Kind::Mass},
      {47.0f, 40.0f, Kind::Mass},
    };
    const faf::editor::DetectedSymmetry found = DetectSymmetry(flat.data(), kSize, kSize, markers);
    EXPECT_EQ(found.symmetry, Symmetry::LeftRight);
    EXPECT_NEAR(found.centreX, 33.5f, 0.01f);
    EXPECT_NEAR(found.centreZ, 32.0f, 0.01f);
  }

  TEST(
    Symmetrize,
    EveryModeIsExactFromEveryPart
  )
  {
    for (const Symmetry symmetry : kExact) {
      const int parts = faf::editor::SymmetryParts(symmetry, 3);
      for (int part = 0; part < parts; ++part) {
        std::vector<std::uint16_t> heights = Random(11);
        SymmetrizeOptions options;
        options.symmetry = symmetry;
        options.part = part;
        std::string error;
        ASSERT_TRUE(faf::editor::SymmetrizeHeights(heights.data(), kSize, kSize, options, error)) << error;
        const faf::editor::SymmetryReport report =
          faf::editor::CheckSymmetry(heights.data(), kSize, kSize, symmetry, 3);
        EXPECT_EQ(report.differing, 0) << "mode " << static_cast<int>(symmetry) << " part " << part;
      }
    }
  }

  TEST(
    Symmetrize,
    PartsCombineAndSeamDoWhatTheySay
  )
  {
    const std::vector<std::uint16_t> start = Random(17);
    SymmetrizeOptions options;
    options.symmetry = Symmetry::LeftRight;
    std::string error;

    // Part 0 keeps the left half, part 1 the right.
    std::vector<std::uint16_t> left = start;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(left.data(), kSize, kSize, options, error)) << error;
    EXPECT_EQ(At(left, 5, 9), At(start, 5, 9));
    EXPECT_EQ(At(left, 59, 9), At(start, 5, 9));
    options.part = 1;
    std::vector<std::uint16_t> right = start;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(right.data(), kSize, kSize, options, error)) << error;
    EXPECT_EQ(At(right, 59, 9), At(start, 59, 9));
    EXPECT_EQ(At(right, 5, 9), At(start, 59, 9));

    // Max: every pair takes its higher.
    options.part = 0;
    options.combine = SymmetryCombine::Max;
    std::vector<std::uint16_t> highest = start;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(highest.data(), kSize, kSize, options, error)) << error;
    EXPECT_EQ(At(highest, 5, 9), std::max(At(start, 5, 9), At(start, 59, 9)));
    EXPECT_EQ(At(highest, 59, 9), At(highest, 5, 9));

    // A seam evens out the step across the mirror line that copying a rough part leaves.
    options.combine = SymmetryCombine::Copy;
    const auto stepAtLine = [&](const std::vector<std::uint16_t>& h) {
      double sum = 0.0;
      for (int z = 0; z < kSize; ++z) {
        sum += std::abs(static_cast<int>(At(h, 31, z)) - static_cast<int>(At(h, 30, z)));
      }
      return sum;
    };
    std::vector<std::uint16_t> seamed = start;
    options.seam = 8.0f;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(seamed.data(), kSize, kSize, options, error)) << error;
    EXPECT_LT(stepAtLine(seamed), stepAtLine(left));
    EXPECT_EQ(faf::editor::CheckSymmetry(seamed.data(), kSize, kSize, Symmetry::LeftRight, 3).differing, 0);
  }

  TEST(
    Symmetrize,
    MasksAndTerrainTypesFollow
  )
  {
    std::mt19937 random(23);
    // 32 x 32 mask texels over the 65 x 65 map: texel i mirrors texel 31 - i.
    std::vector<std::uint64_t> texels(32 * 32);
    for (std::uint64_t& t : texels) {
      t = (static_cast<std::uint64_t>(random()) << 32) | random();
    }
    SymmetrizeOptions options;
    options.symmetry = Symmetry::LeftRight;
    std::string error;
    ASSERT_TRUE(faf::editor::SymmetrizeMasks(texels.data(), 32, 32, kSize, kSize, options, error)) << error;
    for (int z = 0; z < 32; ++z) {
      for (int x = 0; x < 32; ++x) {
        ASSERT_EQ(texels[static_cast<std::size_t>(z) * 32 + x], texels[static_cast<std::size_t>(z) * 32 + (31 - x)])
          << x << "," << z;
      }
    }

    // Terrain types (64 x 64 cells): codes only, never a blend, and mirrored.
    std::vector<std::uint8_t> cells(64 * 64);
    const std::uint8_t codes[] = {3, 17, 40, 200};
    for (std::uint8_t& c : cells) {
      c = codes[random() % 4];
    }
    options.symmetry = Symmetry::HalfTurn;
    options.combine = SymmetryCombine::Average; // an average of codes: it copies instead
    ASSERT_TRUE(faf::editor::SymmetrizeCells(cells.data(), 64, 64, kSize, kSize, options, error)) << error;
    for (int z = 0; z < 64; ++z) {
      for (int x = 0; x < 64; ++x) {
        const std::uint8_t c = cells[static_cast<std::size_t>(z) * 64 + x];
        ASSERT_TRUE(c == 3 || c == 17 || c == 40 || c == 200) << "a blended code " << int(c);
        ASSERT_EQ(c, cells[static_cast<std::size_t>(63 - z) * 64 + (63 - x)]);
      }
    }
  }

  TEST(
    Symmetrize,
    AMovedCentreMirrorsAboutIt
  )
  {
    std::vector<std::uint16_t> heights = Random(29);
    SymmetrizeOptions options;
    options.symmetry = Symmetry::LeftRight;
    options.centreX = 28.0f;
    std::string error;
    ASSERT_TRUE(faf::editor::SymmetrizeHeights(heights.data(), kSize, kSize, options, error)) << error;
    for (int z = 0; z < kSize; ++z) {
      for (int x = 0; x <= 56; ++x) {
        ASSERT_EQ(At(heights, x, z), At(heights, 56 - x, z)) << x << "," << z;
      }
    }
  }
} // namespace
