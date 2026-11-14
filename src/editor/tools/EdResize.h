#pragma once

#include "editor/tools/EdHeightFile.h"

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Map › Resize (FAF Studio's resize.lua): the map made another size in a new folder (the engine's terrain can't
   * change size in place; the original folder stays as it was, the undo). Two ways:
   *  - Canvas: the terrain as it is, cut or padded around an anchor (a corner, an edge's middle or the centre);
   * everything moves by the offset, what falls outside is dropped; padding repeats the edge heights or sits at a level.
   *  - Scale: the whole map resampled to the new size; every position times the size ratio; nothing dropped.
   */
  enum class ResizeMode
  {
    Canvas,
    Scale,
  };

  struct ResizeOptions
  {
    int oldWidth = 512;
    int oldDepth = 512;
    int newWidth = 512;
    int newDepth = 512;
    ResizeMode mode = ResizeMode::Canvas;
    /** 0..8, row by row from the top left (4: the centre): where the old map sits in the new. */
    int anchor = 4;
    /** Canvas padding: the edge heights repeated (else the level below). */
    bool padEdge = true;
    float padLevel = 20.0f;
  };

  /** A position's mapping: x' = x * fx + ox, z' = z * fz + oz, inside [0, width] x [0, depth]. */
  struct ResizeGeometry
  {
    ResizeMode mode = ResizeMode::Canvas;
    float fx = 1.0f;
    float fz = 1.0f;
    float ox = 0.0f;
    float oz = 0.0f;
    float oldWidth = 512.0f;
    float oldDepth = 512.0f;
    float width = 512.0f;
    float depth = 512.0f;
  };
  [[nodiscard]] ResizeGeometry MakeResizeGeometry(const ResizeOptions& options);
  /** Where a point goes; false when it falls outside the new map (canvas). */
  bool ResizePoint(const ResizeGeometry& g, float x, float z, float& nx, float& nz);
  /**
   * An image over the whole map (heights, a mask) for the new map, `width` x `height` samples: each new sample the old
   * one under it (bilinear); outside the old map the nearest edge sample (`padEdge`) or `pad`.
   */
  [[nodiscard]] HeightImage ResizeImage(
    const HeightImage& image,
    const ResizeGeometry& g,
    int width,
    int height,
    bool padEdge,
    std::uint16_t pad
  );

  /** What a resize kept and dropped, for its report. */
  struct ResizeReport
  {
    int markersKept = 0;
    int markersDropped = 0;
    int areasKept = 0;
    int areasDropped = 0;
    int unitsKept = 0;
    int unitsDropped = 0;
    int chainsDropped = 0;
    int propsKept = 0;
    int propsDropped = 0;
    int decalsKept = 0;
    int decalsDropped = 0;
    [[nodiscard]] std::string Text() const;
  };
  /**
   * A `_save.lua`'s text for the new map: markers moved (dropped outside, and out of their chains; a chain left with
   * none goes), areas moved and clipped (one left with no size goes), every army's units moved (dropped outside).
   * Empty with `error` when the text can't be read.
   */
  [[nodiscard]] std::string
  ResizeSaveText(const std::string& saveText, const ResizeGeometry& g, ResizeReport& report, std::string& error);
  /** The scenario's `size = {w, d}` set. */
  [[nodiscard]] std::string WithScenarioSize(const std::string& scenario, int width, int depth);
} // namespace faf::editor
