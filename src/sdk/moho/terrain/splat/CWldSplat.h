#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/CWldTerrainDecal.h"

namespace moho
{
  class CD3DBatchTexture;
  class CD3DTextureBatcher;

  /**
   * CWldTerrainDecal specialization that owns one terrain-splat quad and one
   * retained batch-texture lane.
   */
  class CWldSplat : public CWldTerrainDecal
  {
  public:
    struct SplatVertex
    {
      Wm3::Vec3f mPosition;       // +0x00
      std::uint8_t mPad0C_0F[0x4];
      Wm3::Vec2f mTexCoord;       // +0x10
      std::uint8_t mPad18_1B[0x4];
    };

    /**
     * Address: 0x0089DF70 (FUN_0089DF70, Moho::CWldSplat::CWldSplat)
     *
     * What it does:
     * Seeds the splat's base decal state and leaves the batch-texture lane
     * empty until a name is assigned.
     */
    CWldSplat(SpatialDB_MeshInstance* spatialDbOwner, IWldTerrainRes* terrainRes);

    /**
     * Address: 0x0089DFE0 (FUN_0089DFE0, Moho::CWldSplat::dtr)
     * Address: 0x0089E010 (FUN_0089E010, Moho::CWldSplat::~CWldSplat)
     *
     * What it does:
     * Releases the retained batch texture and then tears down the terrain
     * decal base lanes.
     */
    ~CWldSplat() override;

    /**
     * Address: 0x0089E2C0 (FUN_0089E2C0, Moho::CWldSplat::SetName)
     *
     * What it does:
     * Stores the splat name, resolves the texture from disk when non-empty,
     * and keeps the previous texture lane intact when the name is empty.
     */
    void SetName(const msvc8::string& name, int slot) override;

    /**
     * Address: 0x0089E090 (FUN_0089E090, Moho::CWldSplat::Update)
     *
     * What it does:
     * Advances the base decal state and refreshes the splat vertex positions.
     */
    void Update() override;

    /**
     * Address: 0x0089E0B0 (FUN_0089E0B0, Moho::CWldSplat::UpdateVertices)
     *
     * What it does:
     * Projects the unit quad into world space and samples terrain elevation
     * for each corner.
     */
    void UpdateVertices();

    /**
     * Address: 0x0089E1F0 (FUN_0089E1F0, Moho::CWldSplat::UpdateBatchTexture)
     *
     * What it does:
     * Adds the retained batch texture to the atlas and writes the returned UV
     * rectangle into the splat quad.
     */
    void UpdateBatchTexture(CD3DTextureBatcher* batcher);

    /**
     * Address: 0x0089E2B0 (FUN_0089E2B0, Moho::CWldSplat::GetSplatVertices)
     *
     * What it does:
     * Returns the first vertex lane for the splat quad.
     */
    [[nodiscard]]
    SplatVertex* GetSplatVertices() noexcept;

  public:
    SplatVertex mSplatVertices[4];                  // +0x170
    boost::shared_ptr<CD3DBatchTexture> mTex;       // +0x1E0
  };

  static_assert(offsetof(CWldSplat::SplatVertex, mPosition) == 0x00, "CWldSplat::SplatVertex::mPosition offset must be 0x00");
  static_assert(offsetof(CWldSplat::SplatVertex, mTexCoord) == 0x10, "CWldSplat::SplatVertex::mTexCoord offset must be 0x10");
  static_assert(sizeof(CWldSplat::SplatVertex) == 0x1C, "CWldSplat::SplatVertex size must be 0x1C");
  static_assert(offsetof(CWldSplat, mSplatVertices) == 0x170, "CWldSplat::mSplatVertices offset must be 0x170");
  static_assert(offsetof(CWldSplat, mTex) == 0x1E0, "CWldSplat::mTex offset must be 0x1E0");
  static_assert(sizeof(CWldSplat) == 0x1E8, "CWldSplat size must be 0x1E8");
} // namespace moho
