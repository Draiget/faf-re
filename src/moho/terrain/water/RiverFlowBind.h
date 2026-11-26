#pragma once

#include <memory>

namespace moho
{
  class CD3DDynamicTextureSheet;
  class IWldTerrainRes;
} // namespace moho

// Rivers, render side: the flow texture of a map's rivers and the variables of the patched water effect that carry it
// (the arithmetic and the source patch are RiverFlow.h's; docs/projects/RIVERS.md). Render only.
namespace moho::water
{
  /// 1 (the default): rivers flow (scrolled normals, white water) and the shader patch is made at the next map load.
  extern int ren_River;
  /// Whether the water effect should get the river patch.
  [[nodiscard]] bool RiverPatchWanted();

  /**
   * The flow of the rivers of `terrainRes`'s map: one A8R8G8B8 texel per 2 x 2 block (the layout of the water map),
   * see `PackRiverFlowTexel`. Rebuilt when the map's bodies change; null for a map without rivers.
   */
  [[nodiscard]] std::shared_ptr<CD3DDynamicTextureSheet> RiverFlowTexture(IWldTerrainRes* terrainRes);

  /// Once per frame before the water is drawn: binds the flow texture and the parameters of the patched effect
  /// (everything off when the map has no rivers, the cvar is 0, or the effect carries no patch).
  void BindRiverFlow(IWldTerrainRes* terrainRes);

  /// Around the draw of one water: `river` says that its mesh carries its own heights (a river's). Call
  /// `BindRiverMesh(false)` after the last water.
  void BindRiverMesh(bool river);

  /// Drops the flow texture, with the device.
  void ReleaseRiverFlow();
} // namespace moho::water
