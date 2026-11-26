#pragma once

#include <string>

#include "moho/render/lights/LightTexture.h"

// A census of what the light feeds saw (docs/DYNAMIC_LIGHTS.md, "Census"): every distinct glowing-or-not thing that
// reached a feed, how often, and whether it became a light or why it did not. Switched on by the console variable
// ren_DynLightsCensus N (dump the table every N rendered frames); off it costs one integer test per call. The point is
// to find what glows on screen but gets no light.
namespace moho::lights
{
  extern int ren_DynLightsCensus;

  inline bool CensusEnabled()
  {
    return ren_DynLightsCensus > 0;
  }

  // One sighting. `kind`: "particle", "trail", "beam", "mesh". `key` names the thing (texture paths, shader, blend
  // mode). `result` is "ok:<how>" when it became a light and "no:<why>" when it did not. `size` is the sprite size,
  // beam width or bounding radius; `colour` the texture summary when there is one.
  void
  CensusNote(const char* kind, const std::string& key, const char* result, float size, const TextureColour* colour);

  // Writes the table to the log (the busiest entries first) and the totals per kind and result.
  void CensusDump();

  // Called once per rendered frame; dumps every ren_DynLightsCensus frames.
  void CensusFrame();
} // namespace moho::lights
