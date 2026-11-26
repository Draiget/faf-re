// StratumMaskExtent (src/moho/terrain/StratumMaskSize.h): the size of a stratum mask sheet from the size it was saved
// with, half the map and the map's size in cells. The same rules are static_asserts in the header; this runs them with
// the variables the game passes.

#include <gtest/gtest.h>

#include "moho/terrain/StratumMaskSize.h"

namespace
{
  using moho::kStratumMaskCeiling;
  using moho::StratumMaskExtent;

  // Map sizes in cells: 5, 10, 20, 40 and 81 km.
  constexpr int kCells[] = {256, 512, 1024, 2048, 4096};

  TEST(
    StratumMaskExtent,
    KeepsTheSavedSizeUpToTheMapCap
  )
  {
    for (const int cells : kCells) {
      const int half = cells / 2;
      const int cap = std::min(std::max(2048, 2 * cells), kStratumMaskCeiling);
      for (const int saved : {64, half, 1024, 2048, 4096, 8192}) {
        const int extent = StratumMaskExtent(saved, half, cells);
        EXPECT_GE(extent, half) << "saved " << saved << " cells " << cells;
        EXPECT_LE(extent, std::max(cap, half)) << "saved " << saved << " cells " << cells;
        if (saved >= half && saved <= cap) {
          EXPECT_EQ(extent, saved) << "cells " << cells;
        }
      }
    }
  }

  TEST(
    StratumMaskExtent,
    TheLargestMaskPerMapSize
  )
  {
    EXPECT_EQ(StratumMaskExtent(8192, 128, 256), 2048);   // 5 km
    EXPECT_EQ(StratumMaskExtent(8192, 256, 512), 2048);   // 10 km
    EXPECT_EQ(StratumMaskExtent(8192, 512, 1024), 2048);  // 20 km
    EXPECT_EQ(StratumMaskExtent(8192, 1024, 2048), 4096); // 40 km
    EXPECT_EQ(StratumMaskExtent(8192, 2048, 4096), 8192); // 81 km
  }

  TEST(
    StratumMaskExtent,
    TheConsoleVariableLowersOrSwitchesOff
  )
  {
    EXPECT_EQ(StratumMaskExtent(4096, 1024, 2048, 2048), 2048);
    EXPECT_EQ(StratumMaskExtent(4096, 1024, 2048, 0), 1024); // ren_StratumMaskMax 0: the shipped size
    EXPECT_EQ(StratumMaskExtent(512, 1024, 2048, 0), 1024);
  }
} // namespace
