#include "moho/terrain/water/WaterMeshFeed.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/math/QuaternionMath.h"
#include "moho/mesh/Mesh.h"
#include "moho/mesh/MeshBatchKey.h"
#include "moho/mesh/MeshBatchLod.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "moho/terrain/water/HullDisplacement.h"
#include "moho/terrain/water/HullFoot.h"
#include "moho/terrain/water/HullOutline.h"
#include "moho/terrain/water/WaterHull.h"
#include "moho/terrain/water/WaterSimParams.h"
#include "moho/terrain/water/WaterSimulation.h"

// What the meshes of the frame do to the water (docs/WATER_SIMULATION.md, "Sources"): the hulls under way leave wakes,
// every body with a volume pushes the water by it. Render only: nothing here reads or changes game state.
namespace moho::water
{
  static int ren_WaterBodyHold = 1;

  static TConVar<int> gTConVar_ren_WaterBodyHold(
    "ren_WaterBodyHold",
    "Wave simulation, bodies in the water: 1 (the default) a body (a building, a tree, a wreck) that has not moved "
    "since the "
    "last frame is only kept, not worked out again (its columns, bins and their change are the same as last frame's, "
    "which is nothing); 0 works every body out every frame, as before. The simulation is the same either way. Render "
    "only.",
    &ren_WaterBodyHold
  );

  namespace
  {
    // Wreckage is a crowd of small low boxes after a fight: no body worth the room in the simulation's source list.
    bool IsWreckage(
      const MeshLOD& lod
    )
    {
      // Not every LOD the renderer batches has a blueprint behind it (the engine makes some itself, for shields and the
      // like): no blueprint, no name to read.
      const RMeshBlueprintLOD* const blueprintLod = lod.lodBlueprintCopy.get();
      if (blueprintLod == nullptr) {
        return false;
      }
      char shader[64] = {};
      std::strncpy(shader, blueprintLod->mShaderName.c_str(), sizeof(shader) - 1);
      for (char* c = shader; *c != 0; ++c) {
        *c = static_cast<char>(std::tolower(static_cast<unsigned char>(*c)));
      }
      return std::strstr(shader, "wreck") != nullptr;
    }

    // Units and buildings are what a body in the water is: the material of a bucket that draws into the sun shadow map
    // (the render stage has the depth bit and a depth technique is defined, the gate of MeshRenderer::RenderDepth).
    // Effects, shields and the like do not.
    bool IsSolidBody(
      const MeshLOD& lod
    )
    {
      const MeshMaterial& material = lod.mat;
      return material.mShaderIndex >= 0 && (material.mShaderIndex & 1) != 0 && material.mDepthTechniqueResolved &&
        material.mDepthTechnique.size() != 0;
    }

    // The wake of every hull under way (what it does to the water is the shared model of WaterHull.h; the arms of the V
    // are points it leaves in the water, so the state lives here, per mesh instance).
    std::unordered_map<const MeshInstance*, water::HullWake> gHulls;
    float gWakePurge = 0.0f;

    void PurgeHulls()
    {
      const float now = water::SimTime();
      if (gHulls.size() > 64 && now - gWakePurge > 5.0f) {
        gWakePurge = now;
        for (auto it = gHulls.begin(); it != gHulls.end();) {
          it = (it->second.Empty() || now - it->second.NewestBorn() > 12.0f) ? gHulls.erase(it) : std::next(it);
        }
      }
    }

    void FeedSource(
      const float x,
      const float z,
      const float radius,
      const float push,
      const float foam
    )
    {
      water::SimAddSource(x, z, radius, push, foam, true);
    }

    // The waterline outline of the hull of a mesh LOD (HullOutline.h), once per model file: the wake is drawn from
    // where the hull meets the water.
    const water::HullProfile& OutlineOf(
      const MeshLOD& lod
    )
    {
      struct Entry
      {
        std::uint32_t vertexCount = 0;
        water::HullProfile profile;
      };
      static std::unordered_map<const SScmFile*, Entry> sCache;
      static const water::HullProfile sNone;
      const SScmFile* const file = lod.res ? lod.res->mFile.get() : nullptr;
      if (file == nullptr || file->mVertexCount == 0U || file->mVertexCount > 400000U) {
        return sNone;
      }
      const auto found = sCache.find(file);
      if (found != sCache.end() && found->second.vertexCount == file->mVertexCount) {
        return found->second.profile;
      }
      const SScmVertex* const vertices = scm_file::GetVertices(*file);
      Entry entry;
      entry.vertexCount = file->mVertexCount;
      entry.profile =
        water::ComputeHullProfile(file->mVertexCount, [&](const std::size_t i, float& x, float& y, float& z) {
        x = vertices[i].mLocalPositionX;
        y = vertices[i].mLocalPositionY;
        z = vertices[i].mLocalPositionZ;
      });
      return (sCache[file] = entry).profile;
    }

    // The volume of the columns of a mesh LOD (HullFoot.h), once per model file.
    const water::HullFoot& FootOf(
      const MeshLOD& lod
    )
    {
      struct Entry
      {
        std::uint32_t vertexCount = 0;
        water::HullFoot foot;
      };
      static std::unordered_map<const SScmFile*, Entry> sCache;
      static const water::HullFoot sNone;
      const SScmFile* const file = lod.res ? lod.res->mFile.get() : nullptr;
      if (file == nullptr || file->mVertexCount < 4U || file->mVertexCount > 60000U || file->mIndexCount < 6U) {
        return sNone;
      }
      const auto found = sCache.find(file);
      if (found != sCache.end() && found->second.vertexCount == file->mVertexCount) {
        return found->second.foot;
      }
      const SScmVertex* const vertices = scm_file::GetVertices(*file);
      const std::uint16_t* const indices = scm_file::GetIndices(*file);
      Entry entry;
      entry.vertexCount = file->mVertexCount;
      entry.foot = water::ComputeHullFoot(file->mVertexCount, [&](const std::size_t i, float& x, float& y, float& z) {
        x = vertices[i].mLocalPositionX;
        y = vertices[i].mLocalPositionY;
        z = vertices[i].mLocalPositionZ;
      }, file->mIndexCount / 3U, [&](const std::size_t t, std::uint32_t& a, std::uint32_t& b, std::uint32_t& c) {
        a = indices[t * 3U];
        b = indices[t * 3U + 1U];
        c = indices[t * 3U + 2U];
      });
      if (water::SimDiagnostics()) {
        int cells = 0;
        float lo = 1.0e30f, hi = -1.0e30f;
        for (int j = 0; j < entry.foot.nz; ++j) {
          for (int i = 0; i < entry.foot.nx; ++i) {
            const int k = j * water::kFootMax + i;
            if (entry.foot.has[k]) {
              ++cells;
              lo = std::min(lo, entry.foot.bottom[k]);
              hi = std::max(hi, entry.foot.top[k]);
            }
          }
        }
        gpg::Logf(
          "WaterSim body foot: %d vertices, %u indices, grid %d x %d, %d cells, valid %d, model height %.2f .. %.2f, "
          "cell %.2f x %.2f",
          static_cast<int>(file->mVertexCount),
          file->mIndexCount,
          entry.foot.nx,
          entry.foot.nz,
          cells,
          entry.foot.valid ? 1 : 0,
          lo,
          hi,
          entry.foot.cellX,
          entry.foot.cellZ
        );
      }
      return (sCache[file] = entry).foot;
    }

    water::BodyTracker& Bodies()
    {
      static water::BodyTracker sBodies;
      return sBodies;
    }

    // Every body with a mesh pushes the water by its volume (HullFoot.h, WaterBody.h): the volume of its columns below
    // the surface is put into the bins of the world and what changed since the last frame goes to the simulation: a bow
    // raises the water, a stern leaves a gap and a wash, a body that falls into the sea makes a splash. Returns false
    // for a mesh that has no volume to speak of (the caller falls back on the hand-made wake).
    bool AddWaterBody(
      const MeshInstance& instance,
      const MeshLOD& lod,
      const float waterElevation
    )
    {
      if (water::SimBodyScale() <= 0.0f) {
        return false;
      }
      const water::HullFoot& foot = FootOf(lod);
      if (!foot.valid) {
        return false;
      }
      if (instance.isHidden != 0) {
        return true;
      }
      const float radius = instance.sphere.Radius;
      const float cy = instance.sphere.Center.y;
      if (!std::isfinite(radius) || !(radius > 0.4f) || radius > 80.0f || !std::isfinite(cy)) {
        return true;
      }
      if (!(cy - radius < waterElevation + 0.5f && cy + radius > waterElevation - 8.0f)) {
        return true; // nowhere near the surface: nothing to push
      }
      const Wm3::Vec3f position = instance.interpolatedPosition;
      Wm3::Quatf orientation = instance.curOrientation;
      const float norm = orientation.w * orientation.w + orientation.x * orientation.x + orientation.y * orientation.y +
        orientation.z * orientation.z;
      if (!std::isfinite(position.x + position.y + position.z) || !(norm > 0.5f) || !(norm < 1.5f)) {
        return true;
      }
      float sx = instance.scale.x;
      float sy = instance.scale.y;
      float sz = instance.scale.z;
      if (!(sx > 0.0f && sy > 0.0f && sz > 0.0f && std::isfinite(sx + sy + sz))) {
        sx = sy = sz = instance.uniformScale > 0.0f ? instance.uniformScale : 1.0f;
      }
      // A body that has not moved since the last frame has the bins it had (every delta would be zero): it is only
      // kept.
      water::BodyPose pose;
      pose.values[0] = position.x;
      pose.values[1] = position.y;
      pose.values[2] = position.z;
      pose.values[3] = orientation.w;
      pose.values[4] = orientation.x;
      pose.values[5] = orientation.y;
      pose.values[6] = orientation.z;
      pose.values[7] = sx;
      pose.values[8] = sy;
      pose.values[9] = sz;
      pose.values[10] = waterElevation;
      pose.shape = &foot;
      if (ren_WaterBodyHold != 0 && Bodies().Hold(&instance, pose)) {
        return true;
      }
      std::vector<water::BodyBin> bins;
      bins.reserve(static_cast<std::size_t>(foot.nx) * static_cast<std::size_t>(foot.nz) * 4U);
      water::BodyBins(
        foot,
        position.x,
        position.y,
        position.z,
        sx,
        sy,
        sz,
        waterElevation,
        [&](const float x, const float y, const float z, float& wx, float& wy, float& wz) {
        const Wm3::Vector3f model{x, y, z};
        Wm3::Vector3f world{};
        MultQuadVec(&world, &model, &orientation);
        wx = world.x;
        wy = world.y;
        wz = world.z;
      },
        bins
      );
      if (water::SimDiagnostics()) {
        static int sCounter = 0;
        if ((++sCounter % 40) == 0) {
          gpg::Logf(
            "WaterSim body: radius %.2f, scale %.2f %.2f %.2f, foot %d x %d, bins %d, centre height above the water "
            "%.2f",
            radius,
            sx,
            sy,
            sz,
            foot.nx,
            foot.nz,
            static_cast<int>(bins.size()),
            cy - waterElevation
          );
        }
      }
      const float push = water::kBodyPush * water::SimBodyScale();
      const float foamScale = water::SimBodyFoamScale();
      Bodies().Update(&instance, bins, [&](const float x, const float z, const float delta) {
        // (a bin of the world is a unit of ground: the volume that came or went is the height of the water it raises
        // there)
        const float foam = (delta > 0.0f ? water::kBodyBowFoam * delta : -water::kBodyWashFoam * delta) * foamScale;
        water::SimAddSource(x, z, water::kBodyRadius, push * delta, foam, true);
      });
      Bodies().Remember(&instance, pose);
      return true;
    }

    // Units standing in the water leave a wake: a disc at the unit that pushes the water in proportion to how fast it
    // moves (docs/LIGHTING_V2.md).
    void AddWaterSource(
      const MeshInstance& instance,
      const MeshLOD& lod,
      const float waterElevation
    )
    {
      if (instance.isHidden != 0) {
        return;
      }
      const float radius = instance.sphere.Radius;
      const float cy = instance.sphere.Center.y;
      const bool log = water::SimDiagnostics();
      // (the member called startTransform is the later one, the one called endTransform the earlier: measured with the
      // recorder, tools/waterrec.py headings, a hull sailing along +x had its heading from end minus start pointing to
      // -x, and the whole wake was mirrored)
      const float dx = instance.startTransform.pos_.x - instance.endTransform.pos_.x;
      const float dz = instance.startTransform.pos_.z - instance.endTransform.pos_.z;
      const float speed = std::sqrt(dx * dx + dz * dz) * 10.0f; // per tick, ten ticks a second
      const auto note = [&](const char* const verdict) {
        static int sBudget = 300;
        static std::unordered_set<int> sSeen;
        const int key = static_cast<int>(radius * 4.0f) * 4096 + static_cast<int>(std::min(speed, 60.0f) * 4.0f) * 4 +
          (verdict[0] == 's' ? 1 : 0);
        if (log && sBudget > 0 && std::isfinite(speed) && speed >= 0.4f && sSeen.insert(key).second) {
          --sBudget;
          gpg::Logf(
            "WaterSim wake mesh: radius %.2f, centre %.2f above the water, speed %.2f: %s",
            radius,
            cy - waterElevation,
            speed,
            verdict
          );
        }
      };
      if (
        !std::isfinite(radius) || !(radius > 0.4f) || radius > 40.0f || !std::isfinite(cy) ||
        !std::isfinite(instance.sphere.Center.x) || !std::isfinite(instance.sphere.Center.z)
      ) {
        note("rejected: radius or centre");
        return;
      }
      if (!(cy - radius * 0.6f < waterElevation + 0.4f && cy > waterElevation - 0.25f * radius - 0.3f)) {
        note(
          "rejected: not at the surface"
        ); // a body whose middle is under water (a submarine, an amphibious unit on the sea bed) moves no waves
        return;
      }
      const float weight = water::SimSourceWeight();
      if (!(weight > 0.0f)) {
        return; // the game is paused: a hull under way pushes nothing
      }
      if (!std::isfinite(speed) || speed < 0.4f) {
        PurgeHulls();
        const auto found = gHulls.find(&instance);
        if (found != gHulls.end()) {
          found->second.Stamp(
            water::SimTime(), weight, water::SimWakeScale(), water::kHullFoam * water::SimFoamScale(), FeedSource
          ); // a hull that has stopped: the arms it left go on spreading and fading
        }
        return;
      }
      note("source");
      // A hull pushes the water up at its bow and leaves a trough behind it: a pair of discs of opposite sign along the
      // heading (a single push piles a mound that follows the ship), and the wash of the propellers behind. The size
      // follows the hull: the height of the waves grows with its radius (0.45 units at a radius of 8: a battleship;
      // 0.13 at 2.6: a frigate; next to nothing for a hover tank) and with its speed, the discs widen with it. The push
      // for that height comes from the measured response of the simulation: a disc of R cells raises the water by about
      // (2.5 + 0.8 R) times its push (ships of radius 0.6, 2.6, 3.4 and 8 sailing the test bay; docs/LIGHTING_V2.md).
      const float length = std::sqrt(dx * dx + dz * dz);
      const float hx = dx / length;
      const float hz = dz / length;
      // The extents of the hull along and across its heading (the oriented box of the mesh): a round hull is as wide as
      // it is long, a destroyer is a fifth as wide. The bow wave is an arc of lumps across the beam (one for a slender
      // ship, up to five for a broad one), the trough and the wash behind it are as wide, and foam runs along the
      // sides.
      float halfLength = radius * 0.7f;
      float halfBeam = radius * 0.7f;
      {
        // (boundsValid is the stale flag of the swept box, not a flag that the oriented box is good: the box is rebuilt
        // with the interpolated stance)
        float along = 0.0f;
        float across = 0.0f;
        for (int axis = 0; axis < 3; ++axis) {
          const float extent = instance.box.Extent[axis];
          const float ax = instance.box.Axis[axis].x;
          const float az = instance.box.Axis[axis].z;
          along += extent * std::fabs(ax * hx + az * hz);
          across += extent * std::fabs(-ax * hz + az * hx);
        }
        if (std::isfinite(along) && std::isfinite(across) && along > 0.3f && across > 0.15f) {
          halfLength = along;
          halfBeam = across;
        }
      }
      water::SimRecordHull(
        instance.sphere.Center.x, instance.sphere.Center.z, hx, hz, speed, halfLength, halfBeam, radius
      );
      PurgeHulls();
      water::HullState state;
      // the hull as it meets the water, from the mesh: the model axis it is longest along, turned into the world and
      // the heading (a hull sails bow first)
      const water::HullProfile& profile = OutlineOf(lod);
      if (profile.valid) {
        const Wm3::Vector3f axisModel =
          profile.axis == 0 ? Wm3::Vector3f{1.0f, 0.0f, 0.0f} : Wm3::Vector3f{0.0f, 0.0f, 1.0f};
        Wm3::Vector3f axisWorld{};
        MultQuadVec(&axisWorld, &axisModel, &instance.startTransform.orient_);
        const float along = axisWorld.x * hx + axisWorld.z * hz;
        const float modelHalf = 0.5f * (profile.hi - profile.lo);
        if (std::fabs(along) > 0.6f && modelHalf > 0.05f) {
          float scale = instance.uniformScale > 0.0f ? instance.uniformScale : 1.0f;
          if (!(std::fabs(scale * modelHalf - halfLength) < 0.35f * halfLength)) {
            scale = halfLength /
              modelHalf; // the box and the mesh disagree on the scale: the box is what was measured in the world
          }
          state.halfLength = scale * modelHalf;
          float widest = 0.0f;
          for (int b = 0; b < water::kOutlineBins; ++b) {
            const int source = along > 0.0f
              ? water::kOutlineBins - 1 - b
              : b; // the bow is at the high end of the axis when the axis points the way the ship sails
            state.outline[b] = scale * profile.width[source];
            widest = std::max(widest, state.outline[b]);
          }
          state.outlined = true;
          halfBeam = std::max(widest, 0.15f);
          halfLength = state.halfLength;
        }
      }
      state.x = instance.sphere.Center.x;
      state.z = instance.sphere.Center.z;
      state.hx = hx;
      state.hz = hz;
      state.speed = speed;
      state.halfLength = halfLength;
      state.halfBeam = halfBeam;
      state.radius = radius;
      state.foamScale = water::kHullFoam * water::SimFoamScale();
      gHulls[&instance].Move(state, water::SimTime(), weight, water::SimWakeScale(), FeedSource);
    }
  } // namespace

  void FeedWaterFromMeshes(
    MeshRenderer& renderer
  )
  {
    float seaLevel = 0.0f;
    if (!SimWaterLevel(seaLevel)) {
      Bodies().Clear();
      return;
    }
    Bodies().BeginFrame();
    for (const MeshBatchBucket& bucket : renderer.meshes) {
      MeshLOD* const lod = bucket.first.mLod;
      // MeshRenderer::Batch stores Mesh::ComputeLOD's result in the key, and that is -1 (all bits set) for an instance
      // that is too far for every LOD: not a pointer, not drawn (the engine's own marker, not a bad pointer).
      if (
        lod == nullptr || lod == reinterpret_cast<MeshLOD*>(~static_cast<std::uintptr_t>(0)) || bucket.second.empty() ||
        !BatchLodIsLive(bucket.second.front(), lod) || !IsSolidBody(*lod) || IsWreckage(*lod)
      ) {
        continue; // units and buildings: what casts a shadow is a body in the water
      }
      for (const MeshInstance* const instance : bucket.second) {
        if (instance == nullptr) {
          continue;
        }
        // The water where the instance stands: the one level of a map without water bodies, a lake's, a polder's or the
        // sea's with them (a hull does not straddle two levels). A place with no water (ashore, a dry polder) moves
        // nothing.
        float level = 0.0f;
        if (
          !std::isfinite(instance->sphere.Center.x + instance->sphere.Center.z) ||
          !SimLevelAt(instance->sphere.Center.x, instance->sphere.Center.z, level)
        ) {
          continue;
        }
        if (!AddWaterBody(*instance, *lod, level)) {
          AddWaterSource(*instance, *lod, level);
        }
      }
    }
    Bodies().EndFrame();
  }
} // namespace moho::water
