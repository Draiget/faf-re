#include "moho/terrain/splat/CWldSplat.h"

#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/STIMap.h"

namespace
{
  struct CWldTerrainResRuntimeView
  {
    void* mVftable;
    moho::STIMap* mMap;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");
  static_assert(
    offsetof(CWldTerrainResRuntimeView, mMap) == 0x04,
    "CWldTerrainResRuntimeView::mMap offset must be 0x04"
  );

  [[nodiscard]] const CWldTerrainResRuntimeView*
  AsCWldTerrainResRuntimeView(const moho::IWldTerrainRes* const terrainRes) noexcept
  {
    return reinterpret_cast<const CWldTerrainResRuntimeView*>(terrainRes);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0089DF70 (FUN_0089DF70, Moho::CWldSplat::CWldSplat)
   *
   * What it does:
   * Seeds the splat's base decal state and leaves the batch-texture lane
   * empty until a name is assigned.
   */
  CWldSplat::CWldSplat(SpatialDB_MeshInstance* const spatialDbOwner, IWldTerrainRes* const terrainRes)
    : CWldTerrainDecal(spatialDbOwner, terrainRes)
    , mTex()
  {}

  /**
   * Address: 0x0089DFE0 (FUN_0089DFE0, Moho::CWldSplat::dtr)
   * Address: 0x0089E010 (FUN_0089E010, Moho::CWldSplat::~CWldSplat)
   *
   * What it does:
   * Releases the retained batch texture and then tears down the terrain
   * decal base lanes.
   */
  CWldSplat::~CWldSplat() = default;

  /**
   * Address: 0x0089E2C0 (FUN_0089E2C0, Moho::CWldSplat::SetName)
   *
   * What it does:
   * Stores the splat name, resolves the texture from disk when non-empty,
   * and keeps the previous texture lane intact when the name is empty.
   */
  void CWldSplat::SetName(const msvc8::string& name, const int slot)
  {
    (void)slot;

    mNames[0] = name;
    if (mNames[0].empty()) {
      return;
    }

    mTex = CD3DBatchTexture::FromFile(mNames[0].c_str(), 0u);
  }

  /**
   * Address: 0x0089E090 (FUN_0089E090, Moho::CWldSplat::Update)
   *
   * What it does:
   * Advances the base decal state and refreshes the splat vertex positions.
   */
  void CWldSplat::Update()
  {
    CWldTerrainDecal::Update();
    UpdateVertices();
  }

  /**
   * Address: 0x0089E0B0 (FUN_0089E0B0, Moho::CWldSplat::UpdateVertices)
   *
   * What it does:
   * Projects the unit quad into world space and samples terrain elevation
   * for each corner.
   */
  void CWldSplat::UpdateVertices()
  {
    const auto* const terrainView = AsCWldTerrainResRuntimeView(mTerrainRes);
    const STIMap* const map = terrainView->mMap;
    const CHeightField* const heightField = map->mHeightField.get();

    const Wm3::Vec2f localCorners[4]{
      {0.0f, 0.0f},
      {1.0f, 0.0f},
      {1.0f, 1.0f},
      {0.0f, 1.0f},
    };

    for (std::size_t index = 0; index < 4; ++index) {
      const Wm3::Vec2f corner = ComputeCorner(localCorners[index]);
      SplatVertex& vertex = mSplatVertices[index];
      vertex.mPosition.x = corner.x;
      vertex.mPosition.z = corner.y;
      vertex.mPosition.y = heightField->GetElevation(vertex.mPosition.x, vertex.mPosition.z);
    }
  }

  /**
   * Address: 0x0089E1F0 (FUN_0089E1F0, Moho::CWldSplat::UpdateBatchTexture)
   *
   * What it does:
   * Adds the retained batch texture to the atlas and writes the returned UV
   * rectangle into the splat quad.
   */
  void CWldSplat::UpdateBatchTexture(CD3DTextureBatcher* const batcher)
  {
    if (mTex) {
      const gpg::Rect2f* const uvRect = batcher->AddTexture(mTex);
      if (uvRect != nullptr) {
        mSplatVertices[0].mTexCoord.x = uvRect->x0;
        mSplatVertices[0].mTexCoord.y = uvRect->z0;
        mSplatVertices[1].mTexCoord.x = uvRect->x1;
        mSplatVertices[1].mTexCoord.y = uvRect->z0;
        mSplatVertices[2].mTexCoord.x = uvRect->x1;
        mSplatVertices[2].mTexCoord.y = uvRect->z1;
        mSplatVertices[3].mTexCoord.x = uvRect->x0;
        mSplatVertices[3].mTexCoord.y = uvRect->z1;
      }
    }
  }

  /**
   * Address: 0x0089E2B0 (FUN_0089E2B0, Moho::CWldSplat::GetSplatVertices)
   *
   * What it does:
   * Returns the first vertex lane for the splat quad.
   */
  CWldSplat::SplatVertex* CWldSplat::GetSplatVertices() noexcept
  {
    return mSplatVertices;
  }
} // namespace moho
