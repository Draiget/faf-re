#pragma once

namespace moho
{
  class MeshRenderer;
}

// What the meshes of the frame do to the water simulation (docs/WATER_SIMULATION.md, "Sources"): the hulls under way
// leave wakes (WaterHull.h), every body with a volume pushes the water by it (HullDisplacement.h). Render only: nothing
// here reads or changes game state.
namespace moho::water
{
  // Once per frame, after the mesh batch has been built and right before StepWaterSimulation: walks the batched units
  // and buildings and hands the simulation their sources. The water of an instance is the level where it stands
  // (SimLevelAt): nothing is pushed ashore or over a dry polder.
  void FeedWaterFromMeshes(MeshRenderer& renderer);
} // namespace moho::water
