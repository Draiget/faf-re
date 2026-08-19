#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Grid-walk line state shared by the occupancy grid, the terrain influence
   * map and the path navigator.
   *
   * Layout matches the binary's `struct_Line`: the walker keeps both endpoints
   * mirrored into a monotonically-increasing frame (`xMask` / `zMask` record
   * which axes were flipped, so a caller can map an edge back to real grid
   * coordinates) and steps whichever axis is currently behind.
   */
  struct GridTraversalLine
  {
    float x0;           // +0x00
    float z0;           // +0x04
    float x1;           // +0x08
    float z1;           // +0x0C
    float dx;           // +0x10
    float dz;           // +0x14
    std::int32_t step;  // +0x18
    std::int32_t xEdge; // +0x1C
    std::int32_t zEdge; // +0x20
    std::int32_t xMask; // +0x24
    std::int32_t zMask; // +0x28
  };

  static_assert(sizeof(GridTraversalLine) == 0x2C, "GridTraversalLine size must be 0x2C");

  /**
   * Address: 0x0040D860 (FUN_0040D860, ??0struct_Line@@QAE@@Z)
   *
   * IDA signature:
   * void __thiscall struct_Line::struct_Line(int step, struct_Line *line,
   *   float xEnd, float xStart, float zStart, float zEnd);
   *
   * What it does:
   * Initializes grid-walker line state from segment endpoints and step size.
   * Each axis whose end lies before its start is negated so the walk always
   * runs in the increasing direction, and the flip is recorded in that axis'
   * mask. The starting cell edges are the floors of the (possibly negated)
   * start coordinates, aligned down to the step grid.
   */
  void InitGridTraversalLine(
    GridTraversalLine& line,
    std::int32_t step,
    float xEnd,
    float xStart,
    float zStart,
    float zEnd
  ) noexcept;

  /**
   * Address: 0x00475FD0 (FUN_00475FD0, sub_475FD0)
   *
   * What it does:
   * Steps the walker one cell along whichever axis the segment crosses first,
   * by comparing the two cross-multiplied edge metrics.
   */
  void AdvanceGridTraversalEdge(GridTraversalLine& line) noexcept;

  /**
   * Address: 0x00476050 (FUN_00476050)
   *
   * What it does:
   * Decodes the current signed cell coordinates from the masked edge state,
   * undoing the per-axis negation `InitGridTraversalLine` recorded.
   */
  void GetGridTraversalCell(const GridTraversalLine& line, std::int32_t& outX, std::int32_t& outZ) noexcept;

  /**
   * Address: 0x00476070 (FUN_00476070)
   *
   * What it does:
   * True once the walk has stepped past the segment end on either axis.
   */
  [[nodiscard]] bool IsGridTraversalBeyondEnd(const GridTraversalLine& line) noexcept;
} // namespace moho
