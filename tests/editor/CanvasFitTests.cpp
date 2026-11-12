// The node canvases' fit (src/editor/ui/EdCanvasFit.cpp): a graph fitted with a margin at the panels' scale, no
// larger than the cap, and when it would be too small to read, the readable floor centred on the selection.

#include "editor/ui/EdCanvasFit.h"

#include <gtest/gtest.h>

using faf::editor::FitCanvas;

namespace
{
  /** Where a graph point lands on the canvas for a place (screen = (graph + pan) * zoom * unit). */
  float ScreenX(
    const faf::editor::EdCanvasPlace& place,
    const float gx,
    const float unit
  )
  {
    return (gx + place.panX) * place.zoom * unit;
  }

  TEST(
    CanvasFit,
    FitsWithAMarginCentred
  )
  {
    // A graph 0..1000 wide, 0..500 high into 1200 x 800 pixels at unit 1, a tenth's margin: 960 x 640 usable.
    const auto place = FitCanvas(0.0f, 0.0f, 1000.0f, 500.0f, 1200.0f, 800.0f, 1.0f, 0.10f, 0.0f, 1.5f, 0.0f, 0.0f);
    EXPECT_FLOAT_EQ(place.zoom, 0.96f) << "width-bound";
    EXPECT_FLOAT_EQ(ScreenX(place, 500.0f, 1.0f), 600.0f) << "the graph's middle at the canvas's middle";
    EXPECT_NEAR(ScreenX(place, 0.0f, 1.0f), 120.0f, 0.01f) << "a tenth of the width left free";
  }

  TEST(
    CanvasFit,
    TheUnitIsThePanelsScale
  )
  {
    // At UI scale 2 (unit 2) the same graph fits at half the zoom: the same pixels on screen.
    const auto one = FitCanvas(0.0f, 0.0f, 1000.0f, 500.0f, 1200.0f, 800.0f, 1.0f, 0.10f, 0.0f, 1.5f, 0.0f, 0.0f);
    const auto two = FitCanvas(0.0f, 0.0f, 1000.0f, 500.0f, 1200.0f, 800.0f, 2.0f, 0.10f, 0.0f, 1.5f, 0.0f, 0.0f);
    EXPECT_FLOAT_EQ(two.zoom * 2.0f, one.zoom);
    EXPECT_NEAR(ScreenX(two, 0.0f, 2.0f), ScreenX(one, 0.0f, 1.0f), 0.01f);
  }

  TEST(
    CanvasFit,
    CappedAndFloored
  )
  {
    // A small graph doesn't blow up past the cap.
    EXPECT_FLOAT_EQ(FitCanvas(0, 0, 100, 50, 1200, 800, 1, 0.1f, 0.0f, 1.5f, 0, 0).zoom, 1.5f);
    // A huge graph: the floor, centred on the focus (the selection) instead of the graph's middle.
    const auto place = FitCanvas(0, 0, 20000, 8000, 1200, 800, 1, 0.1f, 0.6f, 1.5f, 3000.0f, 1000.0f);
    EXPECT_FLOAT_EQ(place.zoom, 0.6f);
    EXPECT_NEAR(ScreenX(place, 3000.0f, 1.0f), 600.0f, 0.01f) << "the selection at the middle";
    // No floor: everything, however small.
    EXPECT_LT(FitCanvas(0, 0, 20000, 8000, 1200, 800, 1, 0.1f, 0.0f, 1.5f, 0, 0).zoom, 0.06f);
    // Nothing to fit, or no canvas: zoom 1.
    EXPECT_FLOAT_EQ(FitCanvas(10, 10, 0, 0, 1200, 800, 1, 0.1f, 0.6f, 1.5f, 0, 0).zoom, 1.0f);
    EXPECT_FLOAT_EQ(FitCanvas(0, 0, 10, 10, 0, 0, 1, 0.1f, 0.6f, 1.5f, 0, 0).zoom, 1.0f);
  }
} // namespace
