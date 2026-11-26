#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

// The waterline outline of a hull, from the vertices of its mesh. Pure functions on plain numbers (no engine types), so
// that the headless lab can use them.
//
// The wake of a ship is drawn from the places where the hull meets the water: the bow splash hugs the front of the
// outline, the foam along the sides follows its sides, the wash behind the stern starts where the outline ends. An
// oriented box is not that: a round hull or a pointed bow does not fill its box, and foam placed on the box floats in
// open water.
namespace moho::water
{
  constexpr int kOutlineBins = 16;

  struct HullProfile
  {
    bool valid = false;
    int axis = 2;    // the model axis the hull is longest along: 0 = x, 2 = z
    float lo = 0.0f; // the extent along that axis (model units)
    float hi = 0.0f;
    float width[kOutlineBins]{}; // the half width across, per bin, from the low end of the axis to the high end
  };

  // `vertex(i, x, y, z)` fills the position of vertex i. The waterline slice is the lowest part of the mesh (the hull
  // below and around the water; the superstructure above it is narrower or is a turret that must not widen the
  // outline).
  template <class Vertex>
  HullProfile ComputeHullProfile(
    const std::size_t count,
    Vertex&& vertex
  )
  {
    HullProfile profile;
    if (count < 8U) {
      return profile;
    }
    float yMin = 1.0e30f;
    float yMax = -1.0e30f;
    for (std::size_t i = 0; i < count; ++i) {
      float x, y, z;
      vertex(i, x, y, z);
      if (!std::isfinite(y)) {
        return profile;
      }
      yMin = std::min(yMin, y);
      yMax = std::max(yMax, y);
    }
    const float band = yMin + 0.4f * (yMax - yMin);
    float xMin = 1.0e30f, xMax = -1.0e30f, zMin = 1.0e30f, zMax = -1.0e30f;
    std::size_t inBand = 0;
    for (std::size_t i = 0; i < count; ++i) {
      float x, y, z;
      vertex(i, x, y, z);
      if (y <= band && std::isfinite(x) && std::isfinite(z)) {
        xMin = std::min(xMin, x);
        xMax = std::max(xMax, x);
        zMin = std::min(zMin, z);
        zMax = std::max(zMax, z);
        ++inBand;
      }
    }
    if (inBand < 8U || !(xMax - xMin > 0.05f) || !(zMax - zMin > 0.05f)) {
      return profile;
    }
    profile.axis = (xMax - xMin) > (zMax - zMin) * 1.0001f ? 0 : 2;
    profile.lo = profile.axis == 0 ? xMin : zMin;
    profile.hi = profile.axis == 0 ? xMax : zMax;
    const float latMin = profile.axis == 0 ? zMin : xMin;
    const float latMax = profile.axis == 0 ? zMax : xMax;
    const float latCentre = 0.5f * (latMin + latMax);
    float width[kOutlineBins] = {};
    bool seen[kOutlineBins] = {};
    const float span = profile.hi - profile.lo;
    for (std::size_t i = 0; i < count; ++i) {
      float x, y, z;
      vertex(i, x, y, z);
      if (!(y <= band) || !std::isfinite(x) || !std::isfinite(z)) {
        continue;
      }
      const float along = profile.axis == 0 ? x : z;
      const float across = (profile.axis == 0 ? z : x) - latCentre;
      const int bin = std::min(
        std::max(static_cast<int>((along - profile.lo) / span * static_cast<float>(kOutlineBins)), 0), kOutlineBins - 1
      );
      width[bin] = std::max(width[bin], std::fabs(across));
      seen[bin] = true;
    }
    // bins without a vertex take the nearer neighbour that has one
    for (int pass = 0; pass < kOutlineBins; ++pass) {
      for (int b = 0; b < kOutlineBins; ++b) {
        if (!seen[b]) {
          if (b > 0 && seen[b - 1]) {
            width[b] = width[b - 1];
            seen[b] = true;
          } else if (b + 1 < kOutlineBins && seen[b + 1]) {
            width[b] = width[b + 1];
            seen[b] = true;
          }
        }
      }
    }
    for (int b = 0; b < kOutlineBins; ++b) {
      if (!seen[b]) {
        return profile;
      }
      profile.width[b] = width[b];
    }
    profile.valid = true;
    return profile;
  }
} // namespace moho::water
