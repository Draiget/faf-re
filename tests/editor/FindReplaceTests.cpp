// Find and replace objects (src/editor/tools/EdFindReplace.cpp): types counted, matches by scope, the symmetry's first
// part.

#include "editor/tools/EdFindReplace.h"

#include <gtest/gtest.h>

#include <vector>

namespace
{
  using faf::editor::CountFindTypes;
  using faf::editor::FindKind;
  using faf::editor::FindMatches;
  using faf::editor::FindObject;
  using faf::editor::FindScope;
  using faf::editor::FindTypeLabel;
  using faf::editor::HeightBrushCentres;
  using faf::editor::InFirstPart;
  using faf::editor::kMaxSymmetryCopies;
  using faf::editor::Symmetry;

  constexpr int kSide = 257;

  std::vector<FindObject> Objects()
  {
    return {
      {FindKind::Prop, "/env/pine06_prop.bp", 0, true, true},
      {FindKind::Prop, "/env/rock01_prop.bp", 1, false, true},
      {FindKind::Prop, "/env/pine06_prop.bp", 2, false, false},
      {FindKind::Marker, "Mass", 0, false, true},
      {FindKind::Prop, "/env/pine06_prop.bp", 3, true, false},
      {FindKind::Decal, "/env/decals/a.dds", 7, false, true},
    };
  }

  TEST(
    FindReplace,
    CountsEachKindsTypesMostFirst
  )
  {
    const auto types = CountFindTypes(Objects());
    ASSERT_EQ(types.size(), 4U);
    EXPECT_EQ(types[0].kind, FindKind::Marker) << "kinds in order: markers, units, props, decals";
    EXPECT_EQ(types[1].type, "/env/pine06_prop.bp");
    EXPECT_EQ(types[1].count, 3);
    EXPECT_EQ(types[2].type, "/env/rock01_prop.bp");
    EXPECT_EQ(types[3].kind, FindKind::Decal);
  }

  TEST(
    FindReplace,
    MatchesByScope
  )
  {
    const auto objects = Objects();
    EXPECT_EQ(FindMatches(objects, FindKind::Prop, "/env/pine06_prop.bp", FindScope::Map), (std::vector<int>{0, 2, 4}));
    EXPECT_EQ(
      FindMatches(objects, FindKind::Prop, "/env/pine06_prop.bp", FindScope::Selection), (std::vector<int>{0, 4})
    );
    EXPECT_EQ(FindMatches(objects, FindKind::Prop, "/env/pine06_prop.bp", FindScope::FirstPart), (std::vector<int>{0}));
    EXPECT_TRUE(FindMatches(objects, FindKind::Decal, "/env/pine06_prop.bp", FindScope::Map).empty())
      << "the type is matched within its kind";
  }

  TEST(
    FindReplace,
    FirstPartHoldsOneOfEachSetOfCopies
  )
  {
    for (const auto& [symmetry, turns] : std::vector<std::pair<Symmetry, int>>{
           {Symmetry::LeftRight, 2}, {Symmetry::HalfTurn, 2}, {Symmetry::QuarterTurns, 4}, {Symmetry::TopBottom, 2}
         }) {
      for (const auto& [x, z] :
           std::vector<std::pair<float, float>>{{40.0f, 60.0f}, {200.0f, 30.0f}, {90.0f, 230.0f}}) {
        float cx[kMaxSymmetryCopies];
        float cz[kMaxSymmetryCopies];
        const int copies = HeightBrushCentres(kSide, kSide, x, z, symmetry, turns, cx, cz);
        int inside = 0;
        for (int c = 0; c < copies; ++c) {
          inside += InFirstPart(kSide, kSide, symmetry, turns, cx[c], cz[c]) ? 1 : 0;
        }
        EXPECT_EQ(inside, 1) << "symmetry " << static_cast<int>(symmetry) << " at " << x << ", " << z;
      }
    }
    EXPECT_TRUE(InFirstPart(kSide, kSide, Symmetry::LeftRight, 2, 40.0f, 60.0f)) << "left-right: the left half";
    EXPECT_FALSE(InFirstPart(kSide, kSide, Symmetry::LeftRight, 2, 200.0f, 60.0f));
    EXPECT_TRUE(InFirstPart(kSide, kSide, Symmetry::LeftRight, 2, 128.0f, 60.0f)) << "on the mirror line";
    EXPECT_TRUE(InFirstPart(kSide, kSide, Symmetry::None, 1, 200.0f, 60.0f)) << "no symmetry: everything";
  }

  TEST(
    FindReplace,
    LabelsAreShortNames
  )
  {
    EXPECT_EQ(FindTypeLabel(FindKind::Prop, "/env/evergreen/props/trees/pine06_prop.bp"), "pine06");
    EXPECT_EQ(FindTypeLabel(FindKind::Decal, "/env/evergreen2/decals/eg_mudder03_albedo.dds"), "eg_mudder03_albedo");
    EXPECT_EQ(FindTypeLabel(FindKind::Marker, "Land Path Node"), "Land Path Node");
  }
} // namespace
