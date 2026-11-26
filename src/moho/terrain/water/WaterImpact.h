#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

// What a shell, a bomb or a sinking hull does to the water: the sources of the wave simulation it is made of. Pure
// functions on plain numbers (no engine types), so that the headless lab (tools/watersimlab) builds exactly what the
// game builds and measures it (docs/WATER_SIMULATION.md).
//
// Why not one lump (the first version): a lump that only pushes up has a volume, and the wave equation cannot carry a
// volume away (the part of the water that has no wavelength stays where it was): the middle of every splash held a
// mound that rang for seconds ("the surface jiggles"). A splash is a crater with a rim (no volume), a few smaller
// craters and mounds around it (the broken crown), and the column that falls back into the hole a moment later (a
// mound, with the volume of the crater), spread over a tenth of a second instead of one step, so that short, rough
// waves leave it.
namespace moho::water
{
  // One source of an impact, relative to the point of impact. `kind` 0 is a disc (the push falls with the square of 1 -
  // r^2 / R^2), 1 a crater with a rim (the same bell times (4 f - 3) with f = 1 - r^2 / R^2: the volume is zero; a
  // negative push digs, a positive one raises the middle and digs the rim). `delay` and `duration` are in seconds: the
  // push and the foam are handed to the simulation in parts, over `duration` after `delay`.
  struct ImpactPart
  {
    float dx = 0.0f, dz = 0.0f;
    float radius = 1.0f;
    float push = 0.0f;
    float foam = 0.0f; // the foam it throws over its whole duration (the simulation's foam units)
    float kind = 1.0f;
    float delay = 0.0f;
    float duration = 0.05f;
  };

  // The radius of the splash (world units) for a shell of this `size` (the cube root of the energy: a shell of 100
  // damage 4.6, a nuke 20).
  inline float ImpactRadius(
    const float size
  )
  {
    return std::min(std::max(0.7f * std::max(size, 0.5f), 0.8f), 18.0f);
  }

  // `random` returns a number in [0, 1). `scale` is 1 on the surface and less below it, `strength` the user's factor
  // (ren_WaterSimImpact).
  template <class Random>
  void BuildImpact(
    const float size,
    const float scale,
    const float strength,
    Random&& random,
    std::vector<ImpactPart>& out
  )
  {
    const float s = std::max(size, 0.5f);
    const float radius = ImpactRadius(s);
    // the same strength scale as before: a twentieth of the wanted height is pushed (docs/WATER_SIMULATION.md)
    const float hump = std::min(std::max(0.03f * s, 0.03f), 0.5f) * scale * strength;
    const float push = hump * 90.0f * 0.05f *
      2.0f; // (twice the first model: its lumps had volume and the waves they left were weaker than the mound)
    // the foam of the whole splash (the foam value of the cells it covers goes above 1 at the middle and the rim:
    // white, not a haze; the visible threshold of the water shader is about 0.6)
    const float foam = std::min(0.9f + 0.14f * s, 2.6f);
    const float spread =
      0.04f + 0.006f * std::min(s, 20.0f); // seconds the crater takes to open (bigger shells take longer)

    // the crater with its rim
    ImpactPart main;
    main.radius = radius;
    main.push = -push;
    main.foam = foam * 0.6f;
    main.duration = spread;
    out.push_back(main);

    // the crown: smaller craters and mounds of random sign around the rim, a little later
    const int crown = 3 + std::min(static_cast<int>(s / 3.0f), 4);
    float balance = 0.0f;
    for (int i = 0; i < crown; ++i) {
      ImpactPart p;
      const float angle = random() * 6.2831853f;
      const float distance = radius * (0.25f + 0.65f * random());
      p.dx = std::cos(angle) * distance;
      p.dz = std::sin(angle) * distance;
      p.radius = radius * (0.22f + 0.25f * random());
      // random signs that add up to about nothing
      const float sign = (balance > 0.0f) ? -1.0f : 1.0f;
      p.push = sign * push * (0.3f + 0.5f * random());
      balance += p.push;
      p.foam = foam * 0.4f / static_cast<float>(crown) * (0.5f + random());
      p.delay = 0.01f + 0.10f * random();
      p.duration = spread * (0.6f + 0.8f * random());
      out.push_back(p);
    }

    // the column that falls back into the hole: a mound in the middle
    ImpactPart column;
    column.radius = radius * 0.55f;
    column.push = push * 0.55f;
    column.foam = foam * 0.5f;
    column.delay = 0.10f + 0.012f * std::min(s, 20.0f);
    column.duration = spread * 1.4f;
    out.push_back(column);
  }

  // The parts of impacts that are still being handed over to the simulation: each frame the share of its duration that
  // passed is emitted.
  struct QueuedPart
  {
    float x = 0.0f, z = 0.0f, radius = 1.0f, push = 0.0f, foam = 0.0f, kind = 1.0f;
    float delay = 0.0f, remaining = 0.05f, duration = 0.05f;
    bool shown = false;
  };

  class ImpactQueue
  {
  public:
    void Add(
      const QueuedPart& part
    )
    {
      if (items_.size() < 256U) {
        items_.push_back(part);
      }
    }

    // `emit(x, z, radius, push, foam, kind, shown)`: called for every part that is under way, with its share of the
    // push and the foam for `dt` seconds of game time (the shares of a part add up to its whole push, whatever the
    // frame rate).
    template <class Emit>
    void Advance(
      const float dt,
      Emit&& emit
    )
    {
      if (!(dt > 0.0f)) {
        return;
      }
      for (QueuedPart& p : items_) {
        if (p.delay > 0.0f) {
          p.delay -= dt;
          continue;
        }
        const float slice = std::min(dt, p.remaining);
        const float share = slice / p.duration;
        emit(p.x, p.z, p.radius, p.push * share, p.foam * share, p.kind, p.shown);
        p.remaining -= slice;
      }
      items_.erase(
        std::remove_if(
          items_.begin(),
          items_.end(),
          [](const QueuedPart& p) {
        return p.remaining <= 0.0f;
      }
        ),
        items_.end()
      );
    }

    void Clear()
    {
      items_.clear();
    }
    std::size_t Size() const
    {
      return items_.size();
    }

  private:
    std::vector<QueuedPart> items_;
  };

  // Impacts that land on each other: the second shell of a salvo falls into the first one's waves and, added up, a
  // standing wave builds (what rang is what the first splash left). A new impact close to a recent one (in space and
  // time) is weaker and falls a little to the side.
  class ImpactGate
  {
  public:
    struct Result
    {
      float factor = 1.0f; // the push and the foam are multiplied with it
      float jitterX = 0.0f, jitterZ = 0.0f;
    };

    template <class Random>
    Result Admit(
      const float x,
      const float z,
      const float radius,
      const float time,
      Random&& random
    )
    {
      Result result;
      int overlaps = 0;
      for (const Recent& r : recent_) {
        const float age = time - r.time;
        if (age < 0.0f || age > kMemory) {
          continue;
        }
        const float dx = x - r.x;
        const float dz = z - r.z;
        const float reach = 1.5f * (radius + r.radius);
        if (dx * dx + dz * dz < reach * reach) {
          ++overlaps;
        }
      }
      if (overlaps > 0) {
        result.factor = 1.0f / (1.0f + 0.8f * static_cast<float>(overlaps));
        const float angle = random() * 6.2831853f;
        const float distance = radius * (0.3f + 0.5f * random());
        result.jitterX = std::cos(angle) * distance;
        result.jitterZ = std::sin(angle) * distance;
      }
      Recent now{x, z, radius, time};
      if (recent_.size() >= kCapacity) {
        recent_.erase(recent_.begin());
      }
      recent_.push_back(now);
      return result;
    }

    void Clear()
    {
      recent_.clear();
    }

  private:
    struct Recent
    {
      float x, z, radius, time;
    };
    static constexpr float kMemory = 0.8f; // seconds
    static constexpr std::size_t kCapacity = 24;
    std::vector<Recent> recent_;
  };
} // namespace moho::water
