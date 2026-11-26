#include "moho/render/lights/SimLights.h"

#include <cmath>
#include <map>
#include <memory>
#include <unordered_map>

#include "gpg/core/utils/Logging.h"
#include "legacy/math/X87Math.h"
#include "moho/entity/Entity.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/math/QuaternionMath.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/particles/SWorldLight.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/Sim.h"

namespace moho::lights
{
  namespace
  {
    constexpr float kMaxRadius = 5000.0f;
    constexpr float kMaxIntensity = 100.0f;
    constexpr float kPi = 3.14159265358979f;

    struct SimLight
    {
      std::uint32_t id = 0;
      bool hasEntity = false;
      SEntAttachInfo attach;               // the weak link to the entity; the bone is in mParentBoneIndex
      float world[3] = {0.0f, 0.0f, 0.0f}; // a light without an entity
      float offset[3] = {0.0f, 0.0f, 0.0f};
      float rgb[3] = {1.0f, 1.0f, 1.0f};
      float radius = 10.0f;
      float intensity = 1.0f;
      bool spot = false;
      float dir[3] = {0.0f, 0.0f, 1.0f};
      float cone = 0.0f; // cosine of the outer half angle
      int logged = 0;    // diagnostic lines written for this light
    };

    struct SimSet
    {
      std::uint32_t nextId = 1;
      std::map<std::uint32_t, std::unique_ptr<SimLight>> lights;
    };

    std::unordered_map<const Sim*, SimSet>& Sets()
    {
      static std::unordered_map<const Sim*, SimSet> sets;
      return sets;
    }

    SimLight* Find(
      Sim* sim,
      const std::uint32_t id
    )
    {
      const auto set = Sets().find(sim);
      if (set == Sets().end()) {
        return nullptr;
      }
      const auto it = set->second.lights.find(id);
      return it == set->second.lights.end() ? nullptr : it->second.get();
    }

    bool Finite(
      const float v
    )
    {
      return std::isfinite(v);
    }

    float Clamp01(
      const float v
    )
    {
      return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
    }

    void Normalise(
      float (&v)[3]
    )
    {
      const float len = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
      if (len > 1.0e-6f) {
        v[0] /= len;
        v[1] /= len;
        v[2] /= len;
      } else {
        v[0] = 0.0f;
        v[1] = 0.0f;
        v[2] = 1.0f;
      }
    }
  } // namespace

  std::uint32_t SimLightCreate(
    Sim* const sim,
    Entity* const entity,
    const int bone,
    const float (&world)[3]
  )
  {
    if (sim == nullptr) {
      return 0;
    }
    SimSet& set = Sets()[sim];
    auto light = std::make_unique<SimLight>();
    light->id = set.nextId++;
    if (set.nextId == 0) {
      set.nextId = 1;
    }
    if (entity != nullptr) {
      light->hasEntity = true;
      light->attach.mParentBoneIndex = bone;
      light->attach.mAttachTargetWeak.ResetFromObject(entity);
    } else {
      for (int i = 0; i < 3; ++i) {
        light->world[i] = Finite(world[i]) ? world[i] : 0.0f;
      }
    }
    const std::uint32_t id = light->id;
    set.lights[id] = std::move(light);
    return id;
  }

  bool SimLightSetColour(
    Sim* const sim,
    const std::uint32_t id,
    const float r,
    const float g,
    const float b,
    const float radius,
    const float intensity
  )
  {
    SimLight* const light = Find(sim, id);
    if (light == nullptr) {
      return false;
    }
    if (Finite(r) && Finite(g) && Finite(b)) {
      light->rgb[0] = Clamp01(r);
      light->rgb[1] = Clamp01(g);
      light->rgb[2] = Clamp01(b);
    }
    if (Finite(radius) && radius > 0.0f) {
      light->radius = radius > kMaxRadius ? kMaxRadius : radius;
    }
    if (Finite(intensity) && intensity >= 0.0f) {
      light->intensity = intensity > kMaxIntensity ? kMaxIntensity : intensity;
    }
    return true;
  }

  bool SimLightSetOffset(
    Sim* const sim,
    const std::uint32_t id,
    const float x,
    const float y,
    const float z
  )
  {
    SimLight* const light = Find(sim, id);
    if (light == nullptr) {
      return false;
    }
    if (Finite(x) && Finite(y) && Finite(z)) {
      light->offset[0] = x;
      light->offset[1] = y;
      light->offset[2] = z;
    }
    return true;
  }

  bool SimLightSetPosition(
    Sim* const sim,
    const std::uint32_t id,
    const float x,
    const float y,
    const float z
  )
  {
    SimLight* const light = Find(sim, id);
    if (light == nullptr) {
      return false;
    }
    if (Finite(x) && Finite(y) && Finite(z)) {
      light->world[0] = x;
      light->world[1] = y;
      light->world[2] = z;
    }
    return true;
  }

  bool SimLightSetSpot(
    Sim* const sim,
    const std::uint32_t id,
    const float dx,
    const float dy,
    const float dz,
    const float coneDegrees
  )
  {
    SimLight* const light = Find(sim, id);
    if (light == nullptr) {
      return false;
    }
    if (!Finite(dx) || !Finite(dy) || !Finite(dz) || !Finite(coneDegrees) || coneDegrees <= 0.0f) {
      light->spot = false;
      return true;
    }
    light->dir[0] = dx;
    light->dir[1] = dy;
    light->dir[2] = dz;
    Normalise(light->dir);
    const float half = (coneDegrees > 89.0f ? 89.0f : coneDegrees) * kPi / 180.0f;
    light->cone = fa::cos(half);
    light->spot = true;
    return true;
  }

  bool SimLightDestroy(
    Sim* const sim,
    const std::uint32_t id
  )
  {
    const auto set = Sets().find(sim);
    if (set == Sets().end()) {
      return false;
    }
    return set->second.lights.erase(id) != 0;
  }

  void SimLightsTick(
    Sim* const sim
  )
  {
    const auto set = Sets().find(sim);
    if (sim == nullptr || set == Sets().end() || set->second.lights.empty()) {
      return;
    }

    SParticleBuffer* buffer = nullptr; // allocated with the first record
    for (auto it = set->second.lights.begin(); it != set->second.lights.end();) {
      SimLight& l = *it->second;
      SWorldLight rec;
      rec.id = l.id;
      if (l.hasEntity) {
        Entity* const entity = l.attach.GetAttachTargetEntity();
        if (entity == nullptr || entity->DestroyQueuedFlag != 0u) {
          it = set->second.lights.erase(it); // the owner is gone: so is the light
          continue;
        }
        const VTransform t = entity->GetBoneWorldTransform(l.attach.mParentBoneIndex);
        if (l.logged < 3) {
          ++l.logged;
          gpg::Logf(
            "DynLights: Lua light %u on entity bone %d: bone transform pos=(%.2f %.2f %.2f) orient=(%.3f %.3f %.3f "
            "%.3f) offset=(%.2f %.2f %.2f) spot=%d",
            l.id,
            l.attach.mParentBoneIndex,
            t.pos_.x,
            t.pos_.y,
            t.pos_.z,
            t.orient_.w,
            t.orient_.x,
            t.orient_.y,
            t.orient_.z,
            l.offset[0],
            l.offset[1],
            l.offset[2],
            l.spot ? 1 : 0
          );
        }
        const Wm3::Vector3f off(l.offset[0], l.offset[1], l.offset[2]);
        Wm3::Vector3f rotated(0.0f, 0.0f, 0.0f);
        MultQuadVec(&rotated, &off, &t.orient_);
        rec.pos[0] = t.pos_.x + rotated.x;
        rec.pos[1] = t.pos_.y + rotated.y;
        rec.pos[2] = t.pos_.z + rotated.z;
        if (l.spot) {
          const Wm3::Vector3f d(l.dir[0], l.dir[1], l.dir[2]);
          Wm3::Vector3f world(0.0f, 0.0f, 1.0f);
          MultQuadVec(&world, &d, &t.orient_);
          rec.dir[0] = world.x;
          rec.dir[1] = world.y;
          rec.dir[2] = world.z;
        }
      } else {
        rec.pos[0] = l.world[0] + l.offset[0];
        rec.pos[1] = l.world[1] + l.offset[1];
        rec.pos[2] = l.world[2] + l.offset[2];
        rec.dir[0] = l.dir[0];
        rec.dir[1] = l.dir[1];
        rec.dir[2] = l.dir[2];
      }
      for (int i = 0; i < 3; ++i) {
        rec.rgb[i] = l.rgb[i];
      }
      rec.radius = l.radius;
      rec.intensity = l.intensity;
      rec.cone = l.cone;
      rec.spot = l.spot ? 1u : 0u;

      if (buffer == nullptr) {
        buffer = sim->GetParticleBuffer();
      }
      buffer->mLights.push_back(rec);
      ++it;
    }
  }

  void SimLightsOnSimDestroyed(
    Sim* const sim
  )
  {
    Sets().erase(sim);
  }

  std::uint32_t SimLightCount(
    Sim* const sim
  )
  {
    const auto set = Sets().find(sim);
    return set == Sets().end() ? 0u : static_cast<std::uint32_t>(set->second.lights.size());
  }
} // namespace moho::lights
