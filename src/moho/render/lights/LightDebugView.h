#pragma once

namespace moho
{
  struct GeomCamera3;
  class CD3DPrimBatcher;
} // namespace moho

namespace moho::lights
{
  // Console variable ren_DynLightsView: 0 off (the default), 1 draws the light grid over the world (every cell that
  // lists a light, tinted from green with one light to red with the eight the cell can hold, on the ground), plus a
  // marker on each light.
  extern int ren_DynLightsView;

  // Draws the grid image of the last BeginFrame through the viewport's prim batcher. Debug only; a no-op when the
  // variable is 0.
  void DrawDebugView(GeomCamera3& camera, CD3DPrimBatcher* primBatcher);
} // namespace moho::lights
