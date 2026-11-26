#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <deque>

#include "HullOutline.h"

// What a hull under way does to the water: the sources of the wave simulation it is made of. Pure functions on plain
// numbers (no engine types), so that the headless lab (tools/watersimlab --wake) builds exactly what the game builds
// and measures the wake (docs/WATER_SIMULATION.md).
//
// Two things are kept apart, as on a real ship:
//  - the WAVES: the bow wave, the trough behind it and the two arms of the V (the Kelvin wake). They are heights; they
//  travel away from the track.
//  - the FOAM: a splash at the bow, a thin line along the sides of the hull and the turbulent wash behind the stern. It
//  sits ON the track, close to the
//    ship, and trails behind it; it does not follow the arms.
// Both are placed on the outline of the hull where it meets the water (HullState::outline), not on its bounding box.
namespace moho::water
{
  struct HullState
  {
    float x = 0.0f, z = 0.0f;   // the middle of the hull
    float hx = 1.0f, hz = 0.0f; // the heading (unit vector)
    float speed = 0.0f;         // world units a second
    float halfLength = 1.0f;    // half the extent along the heading
    float halfBeam = 1.0f;      // half the extent across it
    float radius = 1.0f;        // the bounding sphere
    float foamScale = 1.0f;     // the foam of every source of the hull is multiplied with it
    bool outlined = false;      // `outline` holds the half widths of the hull at the waterline, from the bow (0) to the
                                // stern (kOutlineBins - 1)
    float outline[kOutlineBins]{};
  };

  // The half width of the hull at t = 0 (the tip of the bow) .. 1 (the stern). Without an outline of the mesh: a
  // generic ship, a pointed bow that fills out over a third of the length and a blunt stern.
  inline float OutlineWidth(
    const HullState& hull,
    const float t
  )
  {
    const float c = std::min(std::max(t, 0.0f), 1.0f);
    if (hull.outlined) {
      const float f = c * static_cast<float>(kOutlineBins - 1);
      const int i = std::min(static_cast<int>(f), kOutlineBins - 2);
      const float a = f - static_cast<float>(i);
      return hull.outline[i] * (1.0f - a) + hull.outline[i + 1] * a;
    }
    const float shape = c < 0.35f ? std::pow(c / 0.35f, 0.65f) : 1.0f - 0.15f * ((c - 0.35f) / 0.65f);
    return hull.halfBeam * shape;
  }

  class HullWake
  {
  public:
    // One frame of a hull that is under way. `emit(x, z, radius, push, foam)` takes a source of the simulation.
    // `weight` is the game time of the frame in steps of the simulation (what a hull pushes per second must not depend
    // on the frame rate), `wakeScale` the user's factor.
    template <class Emit>
    void Move(
      const HullState& hull,
      const float time,
      const float weight,
      const float wakeScale,
      Emit&& emit
    )
    {
      const float foamScale = hull.foamScale;
      const float fast = 0.7f + 0.3f * std::min(hull.speed / 6.0f, 1.3f);
      const float height = std::min(std::max(2.4f * std::pow(hull.radius / 8.0f, 1.8f), 0.1f), 1.2f) * fast;
      const float body = std::min(hull.radius / 3.0f, 1.2f);
      const float cx = hull.x;
      const float cz = hull.z;
      const float hx = hull.hx;
      const float hz = hull.hz;
      const float px = -hz; // across the heading
      const float pz = hx;
      const float halfLength = hull.halfLength;
      // the widest the hull is, and where
      float widest = 0.0f;
      float widestAt = 0.4f;
      for (int i = 0; i < kOutlineBins; ++i) {
        const float t = static_cast<float>(i) / static_cast<float>(kOutlineBins - 1);
        const float w = OutlineWidth(hull, t);
        if (w > widest) {
          widest = w;
          widestAt = t;
        }
      }
      widest = std::max(widest, 0.3f);
      // a point on the outline: `side` -1 or 1, `offset` further out from the hull
      const auto onOutline = [&](const float t, const float side, const float offset, float& wx, float& wz) {
        const float along = halfLength * (1.0f - 2.0f * t);
        const float across = (OutlineWidth(hull, t) + offset) * side;
        wx = cx + hx * along + px * across;
        wz = cz + hz * along + pz * across;
      };

      // ---- the waves: the bow wave along the front of the outline, the trough behind, the arms of the V (Stamp) ----
      const int count = std::min(std::max(static_cast<int>(widest / 1.6f + 0.5f), 1), 5);
      const float spacing = count > 1 ? 1.6f * widest / static_cast<float>(count - 1) : 0.0f;
      const float lumpRadius = std::min(std::max(count > 1 ? 0.7f * spacing : 0.5f * widest, 0.8f), 3.0f);
      const float lumpCells = lumpRadius / 0.5f;
      const float unit = 2.5f * height /
        (2.5f + 0.8f * lumpCells); // (x 2.5: the waves of a ship were a few hundredths of a unit, too small to see)
      const float strength = unit * wakeScale * weight;
      for (int k = 0; k < count; ++k) {
        const float u = count > 1 ? static_cast<float>(k) / static_cast<float>(count - 1) : 0.3f;
        const float t = 0.03f + 0.30f * u;
        const float tStern = 0.78f + 0.1f * u;
        for (int side = -1; side <= 1; side += 2) {
          float wx, wz;
          onOutline(t, static_cast<float>(side), 0.35f * lumpRadius, wx, wz);
          emit(wx, wz, lumpRadius, strength, 0.0f);
          onOutline(tStern, static_cast<float>(side), -0.2f * lumpRadius, wx, wz);
          emit(wx, wz, lumpRadius, -strength * 0.5f, 0.0f);
        }
      }
      // The V of the bow wave: the two arms run back from the widest part of the hull at the Kelvin angle (19.5
      // degrees, tan 0.35) as waves only. The hull leaves a point of them every 1.6 units of its track (a slow hull
      // leaves short arms, a fast one long ones); the points live in the water and spread by themselves (Stamp). They
      // carry no foam: the foam of a ship is not on the arms.
      const float arm = std::min(std::max(hull.speed - 1.0f, 0.0f) / 3.0f, 1.0f);
      const float armLength =
        std::min(std::max(6.0f * halfLength, 10.0f), 30.0f) * (0.5f + 0.5f * std::min(hull.speed / 5.0f, 1.5f)) * arm;
      if (armLength > 3.0f) {
        const float originAlong = halfLength * (1.0f - 2.0f * widestAt);
        const float originX = cx + hx * originAlong;
        const float originZ = cz + hz * originAlong;
        const float moved = points_.empty() ? 1.0e9f : std::hypot(originX - lastX_, originZ - lastZ_);
        if (moved >= 1.6f) {
          seed_ = seed_ * 1664525u + 1013904223u;
          Point point{};
          point.x = originX;
          point.z = originZ;
          point.px = px;
          point.pz = pz;
          point.born = time;
          point.speed = hull.speed;
          point.lateral = widest * 0.95f;
          point.radius = std::min(std::max(0.2f * widest, 0.8f), 2.0f);
          point.unit = unit;
          point.life = std::min(std::max(armLength / std::max(hull.speed, 1.0f), 1.5f), 8.0f);
          point.variation = 0.65f + 0.35f * static_cast<float>((seed_ >> 8) & 0xFFFFu) / 65535.0f;
          points_.push_back(point);
          lastX_ = originX;
          lastZ_ = originZ;
        }
      }
      Stamp(time, weight, wakeScale, foamScale, emit);

      // ---- the foam: on the hull and on its track ----
      const float f0 = fast * weight * foamScale;
      // the splash at the bow: along the front of the outline, tight to the hull
      const float splashRadius = std::min(std::max(0.12f * widest, 0.5f), 1.2f);
      for (int a = 0; a < 4; ++a) {
        const float t = 0.02f + 0.07f * static_cast<float>(a);
        for (int side = -1; side <= 1; side += 2) {
          float wx, wz;
          onOutline(t, static_cast<float>(side), 0.25f * splashRadius, wx, wz);
          emit(wx, wz, splashRadius, 0.0f, 0.010f * f0 * fast);
        }
      }
      // a thin line along the sides of the hull
      const int along = std::min(std::max(static_cast<int>(halfLength * 2.0f / 3.0f + 0.5f), 3), 12);
      const float sideRadius = std::min(std::max(widest * 0.14f, 0.4f), 0.9f);
      for (int a = 0; a < along; ++a) {
        const float t = 0.28f + 0.66f * static_cast<float>(a) / static_cast<float>(along - 1);
        for (int side = -1; side <= 1; side += 2) {
          float wx, wz;
          onOutline(t, static_cast<float>(side), 0.15f * sideRadius, wx, wz);
          emit(wx, wz, sideRadius, 0.0f, 0.0035f * f0 / std::sqrt(static_cast<float>(along) * 0.5f));
        }
      }
      // the wash of the propellers: a band as wide as the stern, emitted from the stern; it stays where it is made, so
      // it is a trail behind the ship
      const float washWidth = std::min(std::max(OutlineWidth(hull, 0.9f), 0.35f * widest) * 0.9f, 9.0f);
      const int washCount = std::min(std::max(static_cast<int>(washWidth / 1.0f + 1.0f), 1), 8);
      const float washRadius = std::min(std::max(washWidth / static_cast<float>(washCount) * 1.0f, 0.6f), 1.1f);
      for (int k = 0; k < washCount; ++k) {
        const float across =
          washCount > 1 ? (static_cast<float>(k) / static_cast<float>(washCount - 1) * 2.0f - 1.0f) * washWidth : 0.0f;
        emit(
          cx - hx * halfLength * 1.05f + px * across,
          cz - hz * halfLength * 1.05f + pz * across,
          washRadius,
          0.0f,
          0.011f * f0 * body / std::sqrt(static_cast<float>(washCount))
        );
      }
    }

    // Puts the points of the arms into the water for this frame (the simulation takes sources per frame, so the points
    // are stamped every frame while they live). A hull that has stopped only does this: the arms it left go on
    // spreading and fading. They are waves: no foam.
    template <class Emit>
    void Stamp(
      const float time,
      const float weight,
      const float wakeScale,
      const float /*foamScale*/,
      Emit&& emit
    )
    {
      while (!points_.empty() && time - points_.front().born > points_.front().life) {
        points_.pop_front();
      }
      for (const Point& p : points_) {
        const float age = time - p.born;
        const float fade = 1.0f - age / p.life;
        const float ramp = std::min(age / 0.8f, 1.0f); // the arms start a little behind the bow, not on it
        const float strength = p.unit * wakeScale * weight * 0.5f * fade * ramp * p.variation;
        const float radius = std::min(std::max(p.radius + 0.04f * p.speed * age, 0.8f), 2.5f);
        const float lateral = p.lateral + 0.35f * p.speed * age; // tan 19.5 degrees, the Kelvin angle
        for (int side = -1; side <= 1; side += 2) {
          emit(
            p.x + p.px * lateral * static_cast<float>(side),
            p.z + p.pz * lateral * static_cast<float>(side),
            radius,
            strength,
            0.0f
          );
        }
      }
    }

    bool Empty() const
    {
      return points_.empty();
    }
    float NewestBorn() const
    {
      return points_.empty() ? -1.0e9f : points_.back().born;
    }

  private:
    struct Point
    {
      float x, z;      // the track point where the hull left it (water frame: it does not move with the ship)
      float px, pz;    // across the heading there
      float born;      // simulation time
      float speed;     // of the hull then: how fast the arm spreads
      float lateral;   // how far from the track it starts (the hull's widest half width)
      float radius;    // the size of its disc to begin with
      float unit;      // push per unit of wake scale
      float life;      // seconds until it is gone
      float variation; // 0.65 .. 1
    };
    std::deque<Point> points_; // oldest first
    float lastX_ = 0.0f;
    float lastZ_ = 0.0f;
    std::uint32_t seed_ = 2463534242u;
  };
} // namespace moho::water
