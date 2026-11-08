// Checks the stable shadow box (`ren_ShadowStable`): it always covers the volume, its corner sits on
// the texel grid, and panning over uneven ground keeps the texel size.

#include "moho/render/ShadowStableFit.h"

#include <cmath>
#include <cstdio>
#include <random>

namespace
{
  int gFailures = 0;

  void Check(const bool condition, const char* const what)
  {
    if (!condition) {
      std::printf("FAILED: %s\n", what);
      ++gFailures;
    }
  }

  // The corner is a whole number of texels, within what a float can hold at this distance.
  [[nodiscard]] bool OnGrid(const float value, const float extent, const int size)
  {
    const double texel = static_cast<double>(extent) / (size - 2);
    const double nearest = std::round(static_cast<double>(value) / texel) * texel;
    const double ulp = std::fabs(static_cast<double>(std::nextafter(value, value + 1.0f)) - value);
    return std::fabs(nearest - value) <= ulp;
  }

  void TestCoversAndSnaps()
  {
    std::mt19937 rng(1234);
    std::uniform_real_distribution<float> position(-6000.0f, 6000.0f);
    std::uniform_real_distribution<float> length(20.0f, 3000.0f);
    const int sizes[] = {512, 1024, 1536, 2048, 4096};

    for (int i = 0; i < 200000; ++i) {
      const int size = sizes[i % 5];
      const float minX = position(rng);
      const float maxX = minX + length(rng);
      const float minY = position(rng);
      const float maxY = minY + length(rng);
      float heldWidth = 0.0f;
      float heldHeight = 0.0f;
      const moho::ShadowStableBox box =
        moho::FitShadowStableBox(minX, maxX, minY, maxY, size, heldWidth, heldHeight);

      Check(box.minX <= minX && box.maxX >= maxX, "box covers the volume on X");
      Check(box.minY <= minY && box.maxY >= maxY, "box covers the volume on Y");
      Check(OnGrid(box.minX, heldWidth, size), "X corner on the texel grid");
      Check(OnGrid(box.minY, heldHeight, size), "Y corner on the texel grid");
      Check(heldWidth <= (maxX - minX) * 1.08f, "width wastes at most one step");
      if (gFailures != 0) {
        std::printf("at i=%d size=%d minX=%f maxX=%f minY=%f maxY=%f\n", i, size, minX, maxX, minY, maxY);
        return;
      }
    }
  }

  void TestPanKeepsTexelSize()
  {
    // A pan where hills change the volume's length by up to 8%.
    std::mt19937 rng(99);
    std::uniform_real_distribution<float> hills(0.0f, 0.08f);
    float heldWidth = 0.0f;
    float heldHeight = 0.0f;
    float firstWidth = 0.0f;
    int changes = 0;
    float previous = 0.0f;
    for (int frame = 0; frame < 5000; ++frame) {
      const float pan = 0.37f * static_cast<float>(frame);
      const float length = 400.0f * (1.0f + hills(rng));
      const moho::ShadowStableBox box = moho::FitShadowStableBox(
        pan, pan + length, pan * 0.5f, pan * 0.5f + length, 1024, heldWidth, heldHeight
      );
      Check(box.maxX >= pan + length, "held box still covers the volume");
      if (frame == 0) {
        firstWidth = heldWidth;
      } else if (heldWidth != previous) {
        ++changes;
      }
      previous = heldWidth;
    }
    std::printf("pan: first width %.1f, final width %.1f, %d changes in 5000 frames\n", firstWidth, heldWidth, changes);
    Check(changes <= 2, "uneven ground changes the texel size at most twice");
  }

  void TestShrinksAfterZoomIn()
  {
    float held = 0.0f;
    (void)moho::FitShadowStableAxis(0.0f, 1000.0f, 1024, held);
    const float wide = held;
    (void)moho::FitShadowStableAxis(0.0f, 100.0f, 1024, held);
    Check(held < wide / 5.0f, "zooming in gives the resolution back");
  }
} // namespace

int main()
{
  TestCoversAndSnaps();
  TestPanKeepsTexelSize();
  TestShrinksAfterZoomIn();
  std::printf(gFailures == 0 ? "all shadow fit tests passed\n" : "%d shadow fit checks failed\n", gFailures);
  return gFailures == 0 ? 0 : 1;
}
