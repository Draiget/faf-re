// G and R in the view (src/editor/tools/EdModalTransform.cpp): moves with an axis lock and typed numbers, turns about
// the middle.

#include "editor/tools/EdModalTransform.h"

#include <gtest/gtest.h>

#include <cmath>

namespace
{
  using faf::editor::ApplyModalDelta;
  using faf::editor::ArrangePlaces;
  using faf::editor::ModalDelta;
  using faf::editor::ModalDeltaFor;
  using faf::editor::ModalHudText;
  using faf::editor::ModalInput;
  using faf::editor::TypeIntoNumber;

  constexpr float kPi = 3.14159265358979f;

  TEST(
    ModalTransform,
    MoveFollowsTheCursorOrOneAxis
  )
  {
    ModalInput input;
    input.cursorDX = 5.0f;
    input.cursorDZ = -3.0f;
    ModalDelta d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dx, 5.0f);
    EXPECT_FLOAT_EQ(d.dz, -3.0f);
    input.axis = 'X';
    d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dx, 5.0f);
    EXPECT_FLOAT_EQ(d.dz, 0.0f);
    input.axis = 'Z';
    d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dx, 0.0f);
    EXPECT_FLOAT_EQ(d.dz, -3.0f);
  }

  TEST(
    ModalTransform,
    TypedNumbersAreExact
  )
  {
    ModalInput input;
    input.cursorDX = 99.0f;
    for (const char key : std::string("12.5")) {
      ASSERT_TRUE(TypeIntoNumber(input.typed, key));
    }
    EXPECT_FALSE(TypeIntoNumber(input.typed, '.')) << "one point";
    EXPECT_FALSE(TypeIntoNumber(input.typed, 'Q'));
    ModalDelta d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dx, 12.5f) << "along X when no axis is locked";
    EXPECT_FLOAT_EQ(d.dz, 0.0f);
    input.axis = 'Z';
    ASSERT_TRUE(TypeIntoNumber(input.typed, '-'));
    EXPECT_EQ(input.typed, "-12.5");
    d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dz, -12.5f);
    ASSERT_TRUE(TypeIntoNumber(input.typed, 8));
    EXPECT_EQ(input.typed, "-12.");
    input.typed = "-";
    d = ModalDeltaFor(input);
    EXPECT_FLOAT_EQ(d.dx, 0.0f) << "a lone minus is no number yet: the cursor (locked to Z) moves it";
    EXPECT_FLOAT_EQ(d.dz, 0.0f);
    EXPECT_NE(ModalHudText(input, d).find("along Z"), std::string::npos);
  }

  TEST(
    ModalTransform,
    TurnsAboutTheMiddleWithTheHeadings
  )
  {
    const ArrangePlaces start{{10.0f, 30.0f}, {20.0f, 20.0f}, {0.0f, 0.5f}};
    ModalInput input;
    input.rotate = true;
    input.typed = "90";
    const ModalDelta d = ModalDeltaFor(input);
    EXPECT_NEAR(d.turn, kPi * 0.5f, 1e-5f);
    const ArrangePlaces out = ApplyModalDelta(start, 20.0f, 20.0f, d);
    // A quarter turn as a heading turns: facing +z (heading 0) becomes facing +x; the one at -x of the middle goes to
    // +z.
    EXPECT_NEAR(out.x[0], 20.0f, 1e-4f);
    EXPECT_NEAR(out.z[0], 30.0f, 1e-4f);
    EXPECT_NEAR(out.x[1], 20.0f, 1e-4f);
    EXPECT_NEAR(out.z[1], 10.0f, 1e-4f);
    EXPECT_NEAR(out.heading[0], kPi * 0.5f, 1e-5f);
    EXPECT_NEAR(out.heading[1], 0.5f + kPi * 0.5f, 1e-5f);
    // Check the sense: a point ahead of a heading-0 object (at +z) turned with it stays ahead of it.
    const ArrangePlaces ahead = ApplyModalDelta(ArrangePlaces{{0.0f}, {1.0f}, {0.0f}}, 0.0f, 0.0f, d);
    EXPECT_NEAR(ahead.x[0], std::sin(d.turn), 1e-5f);
    EXPECT_NEAR(ahead.z[0], std::cos(d.turn), 1e-5f);
  }

  TEST(
    ModalTransform,
    CursorTurnFollowsTheCursorRound
  )
  {
    // The cursor from +x of the middle (angle 0) to +z (angle pi/2): an object at +x goes to +z with it.
    ModalInput input;
    input.rotate = true;
    input.startAngle = 0.0f;
    input.nowAngle = kPi * 0.5f;
    const ModalDelta d = ModalDeltaFor(input);
    const ArrangePlaces out = ApplyModalDelta(ArrangePlaces{{1.0f}, {0.0f}, {0.0f}}, 0.0f, 0.0f, d);
    EXPECT_NEAR(out.x[0], 0.0f, 1e-5f);
    EXPECT_NEAR(out.z[0], 1.0f, 1e-5f);
    // Across the wrap (from just under pi to just over -pi) it is a small turn, not nearly a whole one.
    input.startAngle = kPi - 0.05f;
    input.nowAngle = -kPi + 0.05f;
    EXPECT_NEAR(std::fabs(ModalDeltaFor(input).turn), 0.1f, 1e-4f);
  }
} // namespace
