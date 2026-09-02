#include "moho/render/ProjectileArcRenderer.h"

#include <cmath>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldSession.h"

namespace
{
  /**
   * The high nibble of a `SCreateEntityParams::mEntityId` carries the entity
   * kind; `1` is the one this pass draws. `SpatialDB_MeshInstance::Collect`
   * already narrows to projectiles, so this is the binary's own second check
   * (0x00860250) that the id really is one and not a recycled slot.
   */
  constexpr std::uint32_t kEntityIdKindMask = 0xF0000000u;
  constexpr std::uint32_t kEntityIdKindProjectile = 0x10000000u;

  /** Trail quads are unmodulated; the tint comes from the solid-colour texture. */
  constexpr std::uint32_t kTrailVertexColor = 0xFFFFFFFFu;

  /**
   * The arc table. Its head node is the global at 0x010C4318, so the map
   * object itself starts at 0x010C4314 (`{proxy, head, size}`).
   */
  [[nodiscard]] moho::ProjectileArcTable& ArcTable()
  {
    static moho::ProjectileArcTable table;
    return table;
  }
} // namespace

namespace moho
{
  /** Address: 0x010A645C (?UI_RenProjectileArcs@Moho@@3_NA) - tested by CRenderWorldView::Render. */
  bool UI_RenProjectileArcs = false;

  /** Address: 0x00F57B50 (?UI_RenProjectileArcsSampleInterval@Moho@@3HA). */
  std::int32_t UI_RenProjectileArcsSampleInterval = 0;

  /** Address: 0x00F57B48 (?UI_RenProjectileTrailColor@Moho@@3HA). */
  std::int32_t UI_RenProjectileTrailColor = 0;

  /** Address: 0x00F57B4C (?UI_RenProectileTrailWidth@Moho@@3MA) - the binary's own spelling. */
  float UI_RenProectileTrailWidth = 0.0f;

  /**
   * Address: 0x008600E0 (FUN_008600E0, Moho::CRenderWorldView::RenderProjectileArcs)
   *
   * What it does: see the header.
   */
  void RenderProjectileArcs(
    CWldSession* const session,
    GeomCamera3* const camera,
    CD3DPrimBatcher* const primBatcher,
    [[maybe_unused]] CWldMap* const map
  )
  {
    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(camera->viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(camera->viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(*camera));
    primBatcher->SetViewMatrix(VMatrix4::Identity()); // 0x00860204 (sIdentity)
    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");

    ProjectileArcTable& arcTable = ArcTable();

    // Pass one: refresh every live projectile's track.
    //
    // Heap-backed on purpose - `Collect` takes the vector by its
    // `gpg::fastvector<T>` base and that base's grow path frees `start_`
    // unconditionally. See the matching note on the ENTITYTYPE_Unit collect in
    // CWldSession.cpp.
    gpg::fastvector<UserEntity*> projectiles;
    auto* const spatialDb = static_cast<SpatialDB_MeshInstance*>(session->GetEntitySpatialDbStorage());
    (void)spatialDb->Collect(projectiles, ENTITYTYPE_Projectile);

    for (UserEntity* const entity : projectiles) {
      if ((entity->mParams.mEntityId & kEntityIdKindMask) != kEntityIdKindProjectile) {
        continue;
      }

      const REntityBlueprint* const blueprint = entity->mParams.mBlueprint;
      if (blueprint == nullptr || blueprint->mStrategicIconName.empty()) {
        continue;
      }

      // The icon is loaded but never bound: this is a residency check, and a
      // projectile whose icon will not load aborts the whole pass (0x0086035E).
      const boost::shared_ptr<CD3DBatchTexture> icon =
        CD3DBatchTexture::FromFile(blueprint->mStrategicIconName.c_str(), 0u);
      if (!icon) {
        break;
      }

      const RMeshBlueprint* const meshBlueprint = entity->mVariableData.mMeshBlueprint;
      if (meshBlueprint == nullptr) {
        continue;
      }

      // Interpolant 0: the arc pass samples projectiles at the start of the
      // tick. See the header for why the binary's `movss` off the fourth
      // argument amounts to the same thing.
      const VTransform transform = entity->GetInterpolatedTransform(0.0f);
      const bool visible =
        meshBlueprint->mIconFadeInZoom <= camera->viewport.ProjectViewportDepthRow1(transform.pos_);

      const auto key = static_cast<std::int32_t>(entity->mParams.mEntityId);
      const ProjectileArcTable::iterator existing = arcTable.find(key);
      if (existing == arcTable.end()) {
        // A brand-new track starts active and visible with no samples yet.
        ProjectileArcTrack& track = arcTable[key];
        track.mActive = true;
        track.mVisible = true;
        track.mTicksSinceSample = 0;
        continue;
      }

      ProjectileArcTrack& track = existing->second;
      track.mActive = true;
      track.mLatestPosition = transform.pos_;
      track.mVisible = visible;
      if (track.mTicksSinceSample >= UI_RenProjectileArcsSampleInterval) {
        track.mSamples.push_back(transform.pos_);
        track.mTicksSinceSample = 0;
      } else {
        ++track.mTicksSinceSample;
      }
    }

    // Pass two: draw each track as a screen-space ribbon, then drop the tracks
    // whose projectile is gone.
    primBatcher->Flush();
    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");

    const boost::shared_ptr<CD3DBatchTexture> trailTexture =
      CD3DBatchTexture::FromSolidColor(static_cast<std::uint32_t>(UI_RenProjectileTrailColor));
    primBatcher->SetTexture(trailTexture);

    const float halfWidth = UI_RenProectileTrailWidth;
    gpg::fastvector_n<std::int32_t, 16> expiredKeys{};

    for (ProjectileArcTable::iterator it = arcTable.begin(); it != arcTable.end(); ++it) {
      ProjectileArcTrack& track = it->second;
      if (!track.mActive) {
        expiredKeys.push_back(it->first);
        continue;
      }

      if (track.mVisible) {
        const auto sampleCount = static_cast<std::int32_t>(track.mSamples.size());
        // The binary guards on `!= 1`, so a track that has not sampled yet
        // still runs one iteration and draws a segment out of its untouched
        // inline storage (0x008607C6). Kept, including the do/while shape that
        // tests the bound only after the first segment.
        if (sampleCount != 1) {
          const Wm3::Vector3f* const samples = track.mSamples.begin();
          std::int32_t index = 0;
          do {
            const Wm3::Vector3f& from = samples[index];
            const Wm3::Vector3f& to =
              (index == sampleCount - 2) ? track.mLatestPosition : samples[index + 1];

            const Wm3::Vector2f fromScreen =
              camera->Project(from, 0.0f, viewportWidth, viewportHeight, 0.0f);
            const Wm3::Vector2f toScreen =
              camera->Project(to, 0.0f, viewportWidth, viewportHeight, 0.0f);

            const float x0 = std::floor(fromScreen.x);
            const float y0 = std::floor(fromScreen.y);
            const float x1 = std::floor(toScreen.x);
            const float y1 = std::floor(toScreen.y);

            const CD3DPrimBatcher::Vertex topLeft{x0 - halfWidth, y0, 0.0f, kTrailVertexColor, 0.0f, 0.0f};
            const CD3DPrimBatcher::Vertex topRight{x0 + halfWidth, y0, 0.0f, kTrailVertexColor, 1.0f, 0.0f};
            const CD3DPrimBatcher::Vertex bottomRight{x1 + halfWidth, y1, 0.0f, kTrailVertexColor, 1.0f, 1.0f};
            const CD3DPrimBatcher::Vertex bottomLeft{x1 - halfWidth, y1, 0.0f, kTrailVertexColor, 0.0f, 1.0f};
            primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);

            ++index;
          } while (index < sampleCount - 1);
        }
      }

      track.mActive = false;
    }

    for (const std::int32_t expiredKey : expiredKeys) {
      (void)arcTable.erase(expiredKey);
    }

    primBatcher->Flush();
  }
} // namespace moho
