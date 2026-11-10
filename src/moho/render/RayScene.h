#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_RayTracedShadows`): what the renderer hands the device's ray-traced scene
// (gpg/gal/RayTracing.h) each frame, and the constants the shadow lookups trace with
// (gpg/gal/effects/RayTracedShadows.h).
//  - Meshes: the shadow pass's whole-view batch (every mesh the light reaches over the view), the
//    materials whose depth pass is plain "Depth". Alpha-tested ones (trees, "DepthClip") stay in the shadow
//    map. A skinned mesh is one piece per bone, placed by that bone's palette transform, which is exactly
//    how mesh.fx places it (one bone per vertex).
//  - Terrain: the height field in tiles of 64 x 64 cells, one sample every ceil(cells / 1024) cells (every
//    second on 20 km maps, every fourth on 81 km ones). After the heights change (flattening under buildings,
//    the editor's brushes) the tiles are rehashed, at most kTerrainTilesPerFrame a frame, and the changed ones
//    rebuilt.

#include <array>
#include <cstdint>
#include <map>
#include <vector>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/RayTracing.h"
#include "moho/mesh/MeshBatchKey.h"

namespace gpg::gal
{
  class Device;
}

namespace moho
{
  class CHeightField;
  class MeshRenderer;
  class RScmResource;
  struct GeomCamera3;

  class RayScene
  {
  public:
    static RayScene& Instance();

    /** The device traces rays and `ren_RayTracedShadows` is on. */
    [[nodiscard]] bool Active() const;

    /**
     * Builds this frame's scene from the shadow pass's whole-view mesh batch and the height field, hands it
     * to the device, and publishes the lookups' constants for `shadowViewProjection` (the whole-view light
     * camera) and `viewCamera`; `sunDirection` points towards the sun (the map's, any length). False when
     * the lookups won't trace this frame (the device couldn't build the scene): the shadow map must then hold
     * everything again.
     */
    [[nodiscard]] bool Submit(
      MeshRenderer& meshRenderer, const MeshBatchBucketTree& meshes, const CHeightField* heightField, const GeomCamera3& lightCamera,
      const GeomCamera3& viewCamera, const float (&sunDirection)[3]
    );

    /**
     * Every ground tile is in the scene. While one is missing (being built in the first frames, or its geometry
     * failed) the shadow map must draw the ground's depth again.
     */
    [[nodiscard]] bool TerrainTraced() const;

    /** Tells the lookups not to trace (rays off, or no light camera this frame). */
    static void PublishOff();

  private:
    struct MeshPieces
    {
      boost::weak_ptr<RScmResource> resource;
      std::vector<gpg::gal::RayGeometryId> pieces; // per skin bone, or one for an unskinned batch
      bool skinned = false;
      bool incomplete = false; // a piece with triangles got no geometry (out of memory)
    };
    struct TerrainTile
    {
      gpg::gal::RayGeometryId geometry = 0U;
      std::uint64_t hash = 0U;
    };

    void AddMeshes(MeshRenderer& meshRenderer, const MeshBatchBucketTree& meshes);
    /** Frees the pieces of meshes whose resource is gone. */
    void SweepMeshes();
    void AddTerrain(const CHeightField& field);
    /** `alpha`: the pieces carry texture coordinates (an alpha-tested material). */
    [[nodiscard]] MeshPieces* PiecesFor(const boost::shared_ptr<RScmResource>& resource, bool skinned, bool alpha);

    gpg::gal::Device* mDevice = nullptr;
    std::uint64_t mEpoch = ~0ULL; // gpg::gal::gRaySceneEpoch the pieces belong to
    std::uint32_t mSweepFrames = 0U;
    std::map<std::pair<const RScmResource*, int>, MeshPieces> mMeshes; // resource, 1 skinned | 2 alpha-tested
    std::vector<boost::shared_ptr<gpg::gal::Texture>> mAlphaTextures;   // this frame's, indexed by RayInstance::texture - 1
    bool mAlphaMissing = false; // this frame, an alpha-tested mesh isn't in the scene
    const CHeightField* mTerrainField = nullptr;
    std::uint64_t mTerrainRevision = ~0ULL;
    int mTerrainStep = 1;
    int mTerrainTilesX = 0;
    int mTerrainTilesZ = 0;
    std::vector<TerrainTile> mTerrainTiles;
    std::size_t mTerrainScan = 0U;     // the next tile to rehash
    std::size_t mTerrainScanLeft = 0U; // tiles still to rehash since the heights last changed
    bool mTerrainComplete = false;     // every tile has its geometry
    std::vector<gpg::gal::RayInstance> mInstances;
    std::vector<std::array<float, 12>> mTransforms;
    std::uint32_t mLoggedFrames = 0U;
    bool mMeshesMissing = false; // this frame, a traced material's mesh isn't in the scene
  };
} // namespace moho
