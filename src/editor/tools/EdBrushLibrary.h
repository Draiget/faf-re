#pragma once

// The Terrain tool's brush library (FAF Studio's brushes.lua and stamp.lua): the procedural shapes rasterised on a
// grid, the greyscale images of the editor's brush folder (`%LOCALAPPDATA%\FAForever\Editor\brushes`), and where a
// stamp stroke puts its dabs. No engine types: tested on its own (tests/editor/BrushLibraryTests.cpp).

#include "editor/tools/EdHeightBrush.h"

#include <filesystem>
#include <string>
#include <vector>

namespace faf::editor
{
  /** The grid size shapes and images are read at: odd, so the middle of the brush (u = v = 0) is a grid sample. */
  inline constexpr int kShapeGridSize = 129;

  /** A procedural shape (not Round, not Image) on an n x n grid over its square. */
  [[nodiscard]] ShapeGrid RasterizeShape(BrushShape shape, int n = kShapeGridSize);

  /** An image of the brush folder. */
  struct BrushImage
  {
    std::string name; // the file name without its extension
    std::filesystem::path path;
  };

  /** The images in `folder` the height image reader takes (PNG, TIFF, BMP, R16, RAW), by name. */
  [[nodiscard]] std::vector<BrushImage> ListBrushImages(const std::filesystem::path& folder);

  /** An image read as grey (0..1) on an n x n grid; false with `error` when it can't be read. */
  bool LoadBrushImage(const std::filesystem::path& file, int n, ShapeGrid& out, std::string& error);

  /** Copies the images among `files` into `folder` (made when missing); the number copied, `error` for the others. */
  int ImportBrushImages(
    const std::vector<std::filesystem::path>& files,
    const std::filesystem::path& folder,
    std::string& error
  );

  /** A grid as a height stamp: white (1) is the full stamp height. */
  [[nodiscard]] HeightStamp StampFromGrid(const ShapeGrid& grid);

  /**
   * The dabs a stamp stroke puts down as the cursor moves from (x0, z0) to (x1, z1): one every `spacing` samples
   * along the way. `travelled` carries the distance since the last dab from one call to the next (start a stroke at
   * `spacing` so its first point is a dab). A spacing of 0 or less means one dab per click: none after the first.
   */
  struct StampDab
  {
    float x = 0.0f;
    float z = 0.0f;
  };
  [[nodiscard]] std::vector<StampDab>
  StampDabsAlong(float x0, float z0, float x1, float z1, float spacing, float& travelled);
} // namespace faf::editor
