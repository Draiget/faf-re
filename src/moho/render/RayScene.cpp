#include "moho/render/RayScene.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/effects/RayTracedShadows.h"
#include "moho/console/CConCommand.h"
#include "moho/mesh/Mesh.h"
#include "moho/mesh/MeshBatch.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/TerrainTessellation.h"

namespace moho
{
  // Engine addition (ren_RayTracedShadows): the biases and reach of the shadow rays (RayTracedShadows.h).
  float ren_RayShadowBias = 0.02f;
  float ren_RayShadowTerrainBias = 0.05f;
  float ren_RayShadowTerrainBiasFar = 0.02f;
  float ren_RayShadowReach = 1500.0f;
  int ren_RayShadowDebug = 0;
  int ren_RayShadowTerrainStep = 0;

  namespace
  {
    TConVar<float> gTConVar_ren_RayShadowBias(
      "ren_RayShadowBias",
      "Ray-traced shadows: how far past a unit's own surface a ray must go before something shades it, in world units.",
      &ren_RayShadowBias
    );
    TConVar<float> gTConVar_ren_RayShadowTerrainBias(
      "ren_RayShadowTerrainBias",
      "Ray-traced shadows: how far from the ground a ray must go before something shades the ground, in world units, near the camera.",
      &ren_RayShadowTerrainBias
    );
    TConVar<float> gTConVar_ren_RayShadowTerrainBiasFar(
      "ren_RayShadowTerrainBiasFar",
      "Ray-traced shadows: how far, per world unit from the camera, a ground point's ray must go before the traced "
      "ground counts (the drawn ground is coarser than the traced one far away; units and buildings keep the small "
      "biases).",
      &ren_RayShadowTerrainBiasFar
    );
    TConVar<int> gTConVar_ren_RayShadowDebug(
      "ren_RayShadowDebug",
      "Ray-traced shadows diagnostics: 1 or 2 stripes the shading every 20 world units across x or z from the point "
      "each lookup rebuilt; 3 shades points with ray geometry straight above them; 0 off.",
      &ren_RayShadowDebug
    );
    TConVar<float> gTConVar_ren_RayShadowReach(
      "ren_RayShadowReach", "Ray-traced shadows: the longest shadow ray, in world units.", &ren_RayShadowReach
    );
    TConVar<int> gTConVar_ren_RayShadowTerrainStep(
      "ren_RayShadowTerrainStep",
      "Ray-traced shadows: the traced ground takes one height sample every this many cells; 0 picks it from the map "
      "size (1 up to 1024 cells across, then ceil(cells / 1024)).",
      &ren_RayShadowTerrainStep
    );

    constexpr int kTerrainTileCells = 64;
    constexpr int kTerrainFullDetailCells = 1024;

    // Tiles rehashed per frame after the heights change: 64 covers a 10 km map's whole field in one frame
    // (65 x 65 samples a tile), and keeps an 81 km map's (257 x 257 a tile) to about 8 MB a frame.
    constexpr std::size_t kTerrainTilesPerFrame = 64U;

    /** Hash of `count` height samples, eight bytes at a time. */
    [[nodiscard]] std::uint64_t HashHeights(const std::uint16_t* const samples, const std::size_t count, std::uint64_t hash)
    {
      constexpr std::uint64_t kMultiplier = 0x9E3779B97F4A7C15ULL;
      std::size_t i = 0U;
      for (; i + 4U <= count; i += 4U) {
        std::uint64_t word = 0U;
        std::memcpy(&word, samples + i, sizeof(word));
        hash = (hash ^ word) * kMultiplier;
        hash ^= hash >> 29U;
      }
      for (; i < count; ++i) {
        hash = (hash ^ samples[i]) * kMultiplier;
      }
      return hash;
    }

    /** Inverse of a 4x4 row-major matrix (Gauss-Jordan in double); false when it is singular. */
    [[nodiscard]] bool Invert4x4(const float (&in)[4][4], float (&out)[4][4])
    {
      double a[4][8]{};
      for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
          a[r][c] = in[r][c];
        }
        a[r][4 + r] = 1.0;
      }
      for (int c = 0; c < 4; ++c) {
        int pivot = c;
        for (int r = c + 1; r < 4; ++r) {
          if (std::fabs(a[r][c]) > std::fabs(a[pivot][c])) {
            pivot = r;
          }
        }
        if (std::fabs(a[pivot][c]) < 1e-20) {
          return false;
        }
        if (pivot != c) {
          for (int k = 0; k < 8; ++k) {
            std::swap(a[c][k], a[pivot][k]);
          }
        }
        const double scale = 1.0 / a[c][c];
        for (int k = 0; k < 8; ++k) {
          a[c][k] *= scale;
        }
        for (int r = 0; r < 4; ++r) {
          if (r != c) {
            const double factor = a[r][c];
            for (int k = 0; k < 8; ++k) {
              a[r][k] -= factor * a[c][k];
            }
          }
        }
      }
      for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
          out[r][c] = static_cast<float>(a[r][4 + c]);
        }
      }
      return true;
    }

    void Publish(const float (&vectors)[gpg::gal::effects::kRayShadowVectors][4])
    {
      gpg::gal::effects::RayShadowConstants& constants = gpg::gal::effects::gRayShadows;
      if (std::memcmp(constants.vectors, vectors, sizeof(constants.vectors)) != 0) {
        std::memcpy(constants.vectors, vectors, sizeof(constants.vectors));
        ++constants.version;
      }
    }
  } // namespace

  RayScene& RayScene::Instance()
  {
    static RayScene scene;
    return scene;
  }

  bool RayScene::Active() const
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    return gpg::gal::effects::gRayTracedShadows > 0 && device != nullptr &&
      (device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureRayQuery) != 0U;
  }

  void RayScene::PublishOff()
  {
    const float off[gpg::gal::effects::kRayShadowVectors][4]{};
    Publish(off);
    gMeshDepthSkipsTraced = false;
  }

  void RayScene::SweepMeshes()
  {
    for (auto entry = mMeshes.begin(); entry != mMeshes.end();) {
      if (!entry->second.resource.expired()) {
        ++entry;
        continue;
      }
      for (const gpg::gal::RayGeometryId piece : entry->second.pieces) {
        mDevice->DestroyRayGeometry(piece);
      }
      entry = mMeshes.erase(entry);
    }
  }

  RayScene::MeshPieces* RayScene::PiecesFor(const boost::shared_ptr<RScmResource>& resource, const bool skinned)
  {
    if (!resource || !resource->mFile) {
      return nullptr;
    }
    const auto key = std::make_pair(static_cast<const RScmResource*>(resource.get()), skinned);
    auto found = mMeshes.find(key);
    if (found != mMeshes.end()) {
      if (!found->second.resource.expired()) {
        return &found->second;
      }
      // The address now belongs to another resource.
      for (const gpg::gal::RayGeometryId piece : found->second.pieces) {
        mDevice->DestroyRayGeometry(piece);
      }
      mMeshes.erase(found);
    }

    MeshPieces mesh;
    mesh.resource = resource;
    mesh.skinned = skinned;
    const SScmFile& file = *resource->mFile;
    const SScmVertex* const vertices = scm_file::GetVertices(file);
    const std::uint16_t* const indices = scm_file::GetIndices(file);
    const std::uint32_t vertexCount = file.mVertexCount;
    const std::uint32_t triangleCount = file.mIndexCount / 3U;
    const std::uint32_t boneCount = skinned ? std::max<std::uint32_t>(file.mSkinBoneCount, 1U) : 1U;
    mesh.pieces.assign(boneCount, 0U);

    std::vector<std::vector<std::uint32_t>> triangles(boneCount);
    for (std::uint32_t triangle = 0U; triangle < triangleCount; ++triangle) {
      const std::uint16_t* const corner = indices + (static_cast<std::size_t>(triangle) * 3U);
      if (corner[0] >= vertexCount || corner[1] >= vertexCount || corner[2] >= vertexCount) {
        continue;
      }
      const std::uint32_t bone = skinned ? vertices[corner[0]].mBoneIndex : 0U;
      if (bone < boneCount) {
        triangles[bone].push_back(triangle);
      }
    }

    std::vector<float> positions;
    std::vector<std::uint32_t> pieceIndices;
    std::vector<std::uint32_t> remap(vertexCount, ~0U);
    for (std::uint32_t bone = 0U; bone < boneCount; ++bone) {
      if (triangles[bone].empty()) {
        continue;
      }
      positions.clear();
      pieceIndices.clear();
      std::fill(remap.begin(), remap.end(), ~0U);
      for (const std::uint32_t triangle : triangles[bone]) {
        for (int k = 0; k < 3; ++k) {
          const std::uint16_t vertex = indices[(static_cast<std::size_t>(triangle) * 3U) + static_cast<std::size_t>(k)];
          if (remap[vertex] == ~0U) {
            remap[vertex] = static_cast<std::uint32_t>(positions.size() / 3U);
            positions.push_back(vertices[vertex].mLocalPositionX);
            positions.push_back(vertices[vertex].mLocalPositionY);
            positions.push_back(vertices[vertex].mLocalPositionZ);
          }
          pieceIndices.push_back(remap[vertex]);
        }
      }
      gpg::gal::RayGeometryDesc desc;
      desc.name = "mesh bone";
      desc.positions = positions.data();
      desc.positionStride = 12U;
      desc.vertexCount = static_cast<std::uint32_t>(positions.size() / 3U);
      desc.indices = pieceIndices.data();
      desc.indexCount = static_cast<std::uint32_t>(pieceIndices.size());
      mesh.pieces[bone] = mDevice->CreateRayGeometry(desc);
      mesh.incomplete = mesh.incomplete || mesh.pieces[bone] == 0U;
    }
    return &mMeshes.emplace(key, std::move(mesh)).first->second;
  }

  void RayScene::AddMeshes(MeshRenderer& meshRenderer, const MeshBatchBucketTree& meshes)
  {
    (void)meshRenderer;
    for (const MeshBatchBucket& bucket : meshes) {
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = bucket.first.mLod;
      if (lod == nullptr || !MeshMaterialTraced(lod->mat)) {
        continue;
      }
      boost::shared_ptr<MeshBatch> batch;
      if (bucket.first.mIsStaticPose != 0) {
        lod->GetSkinnedBatch(batch);
      } else {
        lod->GetStaticBatch(batch);
      }
      if (!batch) {
        continue;
      }
      MeshPieces* const pieces = PiecesFor(batch->mCurrentResource, batch->mUseBoneRemap != 0);
      if (pieces == nullptr || pieces->incomplete) {
        // RenderDepth would leave it out of the map too: let the map keep the traced materials this frame.
        mMeshesMissing = true;
      }
      if (pieces == nullptr) {
        continue;
      }
      for (MeshInstance* const instance : bucket.second) {
        if (instance == nullptr || !MeshInstanceRayTransforms(*batch, *instance, mTransforms)) {
          continue;
        }
        const std::size_t count = std::min(mTransforms.size(), pieces->pieces.size());
        for (std::size_t bone = 0U; bone < count; ++bone) {
          const gpg::gal::RayGeometryId piece = pieces->pieces[bone];
          const std::array<float, 12>& m = mTransforms[bone];
          // A hidden bone has scale 0 (FillInstanceBonePalettes), so its whole basis is zero; a turned bone's
          // diagonal can be zero, but a row of a rotation never is.
          if (piece == 0U || (m[0] == 0.0f && m[1] == 0.0f && m[2] == 0.0f)) {
            continue;
          }
          gpg::gal::RayInstance ray;
          std::memcpy(ray.transform, m.data(), sizeof(ray.transform));
          ray.geometry = piece;
          ray.mask = gpg::gal::kRayMaskMesh;
          mInstances.push_back(ray);
        }
      }
    }
  }

  void RayScene::AddTerrain(const CHeightField& field)
  {
    if (field.data == nullptr || field.width < 2 || field.height < 2) {
      return;
    }
    const int cellsX = field.width - 1;
    const int cellsZ = field.height - 1;
    const int step = (ren_RayShadowTerrainStep > 0)
      ? std::min(ren_RayShadowTerrainStep, 16)
      : std::max(1, (std::max(cellsX, cellsZ) + kTerrainFullDetailCells - 1) / kTerrainFullDetailCells);
    const int tileSpan = kTerrainTileCells * step;
    const int tilesX = (cellsX + tileSpan - 1) / tileSpan;
    const int tilesZ = (cellsZ + tileSpan - 1) / tileSpan;
    if (&field != mTerrainField || step != mTerrainStep || tilesX != mTerrainTilesX || tilesZ != mTerrainTilesZ) {
      for (const TerrainTile& tile : mTerrainTiles) {
        mDevice->DestroyRayGeometry(tile.geometry);
      }
      mTerrainTiles.assign(static_cast<std::size_t>(tilesX) * static_cast<std::size_t>(tilesZ), TerrainTile{});
      mTerrainField = &field;
      mTerrainStep = step;
      mTerrainTilesX = tilesX;
      mTerrainTilesZ = tilesZ;
      mTerrainRevision = ~0ULL;
    }
    const std::uint64_t revision = HeightFieldRevision();
    if (revision != mTerrainRevision) {
      // Rehash every tile, starting where the last pass stopped, a few a frame.
      mTerrainRevision = revision;
      mTerrainScanLeft = mTerrainTiles.size();
    }
    if (mTerrainScanLeft != 0U) {
      std::vector<float> positions;
      std::vector<std::uint32_t> indices;
      int rebuilt = 0;
      for (std::size_t scanned = 0U; scanned < kTerrainTilesPerFrame && mTerrainScanLeft != 0U; ++scanned) {
        --mTerrainScanLeft;
        const std::size_t index = mTerrainScan % mTerrainTiles.size();
        mTerrainScan = index + 1U;
        const int tx = static_cast<int>(index % static_cast<std::size_t>(tilesX));
        const int tz = static_cast<int>(index / static_cast<std::size_t>(tilesX));
        {
          const int x0 = tx * tileSpan;
          const int z0 = tz * tileSpan;
          const int x1 = std::min(x0 + tileSpan, cellsX);
          const int z1 = std::min(z0 + tileSpan, cellsZ);
          std::uint64_t hash = 1469598103934665603ULL;
          for (int z = z0; z <= z1; ++z) {
            hash = HashHeights(field.data + (static_cast<std::size_t>(z) * static_cast<std::size_t>(field.width)) + x0,
                               static_cast<std::size_t>(x1 - x0 + 1), hash);
          }
          TerrainTile& tile = mTerrainTiles[index];
          if (tile.geometry != 0U && tile.hash == hash) {
            continue;
          }
          // Samples every `step` cells, plus the tile's far edge so neighbouring tiles meet.
          std::vector<int> xs;
          std::vector<int> zs;
          for (int x = x0; x < x1; x += step) {
            xs.push_back(x);
          }
          xs.push_back(x1);
          for (int z = z0; z < z1; z += step) {
            zs.push_back(z);
          }
          zs.push_back(z1);
          positions.clear();
          indices.clear();
          for (const int z : zs) {
            for (const int x : xs) {
              const std::uint16_t raw = field.data[static_cast<std::size_t>(z) * static_cast<std::size_t>(field.width) + static_cast<std::size_t>(x)];
              positions.push_back(static_cast<float>(x));
              positions.push_back(static_cast<float>(raw) * (1.0f / 128.0f));
              positions.push_back(static_cast<float>(z));
            }
          }
          const auto columns = static_cast<std::uint32_t>(xs.size());
          for (std::uint32_t row = 0U; row + 1U < zs.size(); ++row) {
            for (std::uint32_t column = 0U; column + 1U < columns; ++column) {
              const std::uint32_t a = row * columns + column;
              const std::uint32_t b = a + 1U;
              const std::uint32_t c = a + columns;
              const std::uint32_t d = c + 1U;
              indices.insert(indices.end(), {a, c, b, b, c, d});
            }
          }
          if (tile.geometry != 0U) {
            mDevice->DestroyRayGeometry(tile.geometry);
          }
          gpg::gal::RayGeometryDesc desc;
          desc.name = "terrain tile";
          desc.positions = positions.data();
          desc.vertexCount = static_cast<std::uint32_t>(positions.size() / 3U);
          desc.indices = indices.data();
          desc.indexCount = static_cast<std::uint32_t>(indices.size());
          tile.geometry = mDevice->CreateRayGeometry(desc);
          tile.hash = hash;
          ++rebuilt;
        }
      }
      if (rebuilt != 0) {
        gpg::Logf("Ray-traced shadows: %d terrain tiles built (%dx%d heights, every %d)", rebuilt, field.width, field.height, step);
      }
    }
    for (const TerrainTile& tile : mTerrainTiles) {
      if (tile.geometry == 0U) {
        continue;
      }
      gpg::gal::RayInstance ray;
      ray.transform[0][0] = 1.0f;
      ray.transform[1][1] = 1.0f;
      ray.transform[2][2] = 1.0f;
      ray.geometry = tile.geometry;
      ray.mask = gpg::gal::kRayMaskTerrain;
      mInstances.push_back(ray);
    }
  }

  bool RayScene::Submit(
    MeshRenderer& meshRenderer, const MeshBatchBucketTree& meshes, const CHeightField* const heightField, const GeomCamera3& lightCamera,
    const GeomCamera3& viewCamera, const float (&sunDirection)[3]
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const std::uint64_t epoch = gpg::gal::gRaySceneEpoch.load();
    if (device != mDevice || epoch != mEpoch) {
      // A new device, or the device remade its ray objects: the old pieces went with them.
      mMeshes.clear();
      mTerrainTiles.clear();
      mTerrainField = nullptr;
      mTerrainRevision = ~0ULL;
      mTerrainScan = 0U;
      mTerrainScanLeft = 0U;
      mDevice = device;
      mEpoch = epoch;
    }
    if (++mSweepFrames >= 600U) {
      mSweepFrames = 0U;
      SweepMeshes();
    }
    mInstances.clear();
    mMeshesMissing = false;
    if (heightField != nullptr) {
      AddTerrain(*heightField);
    }
    AddMeshes(meshRenderer, meshes);
    if (!device->SetRayInstances(mInstances.data(), static_cast<std::uint32_t>(mInstances.size()))) {
      PublishOff();
      return false;
    }
    if (mLoggedFrames < 3U) {
      ++mLoggedFrames;
      gpg::Logf("Ray-traced shadows: %u instances (%zu meshes known)", static_cast<unsigned>(mInstances.size()), mMeshes.size());
    }

    float viewProjection[4][4]{};
    std::memcpy(viewProjection, &lightCamera.viewProjection, sizeof(viewProjection));
    float inverse[4][4]{};
    if (!Invert4x4(viewProjection, inverse)) {
      PublishOff();
      return false;
    }
    float vectors[gpg::gal::effects::kRayShadowVectors][4]{};
    std::memcpy(vectors, inverse, sizeof(inverse));
    vectors[4][0] = 1.0f;
    vectors[4][1] = ren_RayShadowBias;
    vectors[4][2] = ren_RayShadowTerrainBias;
    vectors[4][3] = ren_RayShadowTerrainBiasFar;
    const auto& eye = viewCamera.inverseView.r[3];
    vectors[5][0] = eye.x;
    vectors[5][1] = eye.y;
    vectors[5][2] = eye.z;
    vectors[5][3] = ren_RayShadowReach;
    const float sunLength = std::sqrt(sunDirection[0] * sunDirection[0] + sunDirection[1] * sunDirection[1] + sunDirection[2] * sunDirection[2]);
    if (sunLength < 1e-6f) {
      PublishOff();
      return false;
    }
    vectors[6][0] = sunDirection[0] / sunLength;
    vectors[6][1] = sunDirection[1] / sunLength;
    vectors[6][2] = sunDirection[2] / sunLength;
    vectors[6][3] = static_cast<float>(ren_RayShadowDebug);
    // How far under the traced ground a drawn ground point can lie: half a unit per skipped sample of the
    // traced field, and terrain tessellation's deepest sinking (terrain_tess.fx's TerrainTessDepthScale);
    // a ray towards the sun leaves that depth after it over the sun's height.
    const float under = 0.5f * static_cast<float>(std::max(mTerrainStep, 1) - 1) + (ren_TerrainTessellation ? 0.3f : 0.0f);
    vectors[7][0] = under / std::max(vectors[6][1], 0.2f);
    vectors[7][1] = under; // ren_RayAo's rays (AmbientOcclusionRenderer)
    Publish(vectors);
    gMeshDepthSkipsTraced = !mMeshesMissing;
    return true;
  }
} // namespace moho
