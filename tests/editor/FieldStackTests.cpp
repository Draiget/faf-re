// The Fields panel's model: ops stacked on the map's heights, Back, and the typed parameters.

#include "editor/tools/EdFieldStack.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  TEST(
    FieldStack,
    OpsStackAndBack
  )
  {
    FieldStack stack;
    EXPECT_FALSE(stack.Apply("invert", {}));
    field::Grid base(9, 9, 1.0f, 0.0f, 0.0f, 0.0f);
    base.At(4, 4) = 10.0f;
    stack.Start(base);
    const auto blurred = stack.Apply("blur", ParseOpParams("radius = 2"));
    ASSERT_TRUE(blurred) << blurred.error();
    ASSERT_NE(stack.Top(), nullptr);
    EXPECT_LT(stack.Top()->At(4, 4), 10.0f); // the peak spread out
    EXPECT_GT(stack.Top()->At(5, 4), 0.0f);
    EXPECT_EQ(stack.Steps().size(), 1U);
    EXPECT_EQ(stack.Steps()[0], "blur (radius=2)");
    EXPECT_FALSE(stack.Apply("no_such_op", {}));
    EXPECT_EQ(stack.Steps().size(), 1U);
    EXPECT_TRUE(stack.Back());
    EXPECT_FLOAT_EQ(stack.Top()->At(4, 4), 10.0f);
    EXPECT_FALSE(stack.Back()); // only the base left
  }

  TEST(
    FieldStack,
    ParametersByKind
  )
  {
    const field::Params p = ParseOpParams("radius = 4\n-- a comment\nmode = 'soft'\nlevels = 0, 0.5, 1\nname=x y\n\n");
    EXPECT_DOUBLE_EQ(p.N("radius", 0.0), 4.0);
    EXPECT_EQ(p.S("mode", ""), "soft");
    ASSERT_NE(p.A("levels"), nullptr);
    EXPECT_EQ(p.A("levels")->size(), 3U);
    EXPECT_EQ(p.S("name", ""), "x y");
    EXPECT_EQ(ParamsText(p), "radius=4 mode=soft name=x y levels=0,0.5,1");
  }
} // namespace faf::editor
