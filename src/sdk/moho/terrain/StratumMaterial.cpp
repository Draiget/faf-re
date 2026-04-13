#include "moho/terrain/StratumMaterial.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/sim/STIMap.h"

namespace
{
  struct CWldTerrainResRuntimeView
  {
    void* vftable;
    moho::STIMap* mMap;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");
  static_assert(
    offsetof(CWldTerrainResRuntimeView, mMap) == 0x04, "CWldTerrainResRuntimeView::mMap offset must be 0x04"
  );

  [[nodiscard]] const CWldTerrainResRuntimeView* AsTerrainView(const moho::CWldTerrainRes* terrainRes) noexcept
  {
    return reinterpret_cast<const CWldTerrainResRuntimeView*>(terrainRes);
  }

  [[nodiscard]] moho::CStratumMaterial& AssignTextureDefaults(moho::CStratumMaterial& material) noexcept
  {
    material.mPath.clear();
    material.mScaleX = 1.0f;
    material.mScaleY = 1.0f;
    material.v3 = 0.0f;
    material.v4 = 1.0f;
    material.mTextureSheet = {};
    material.mSize = 1.0f;
    return material;
  }

  void SetTexturePathAndSize(moho::CStratumMaterial& material, const char* const path, const float size) noexcept
  {
    material.mPath.assign(path != nullptr ? path : "");
    material.mSize = size;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0089F0A0 (FUN_0089F0A0, Moho::CStratumMaterial::~CStratumMaterial)
   *
   * What it does:
   * Releases the retained texture-sheet control block and clears the path
   * string back to the short-string empty state.
   */
  CStratumMaterial::~CStratumMaterial()
  {
    mTextureSheet.release();
    mPath.tidy();
  }

  /**
   * Address: 0x008A7B30 (FUN_008A7B30, Moho::CStratumMaterial::CStratumMaterial)
   *
   * What it does:
   * Retains the source texture-sheet handle and deep-copies the layer path.
   */
  CStratumMaterial::CStratumMaterial(const CStratumMaterial& source)
    : mPath(source.mPath)
    , mScaleX(source.mScaleX)
    , mScaleY(source.mScaleY)
    , v3(source.v3)
    , v4(source.v4)
    , mTextureSheet{}
    , mSize(source.mSize)
  {
    mTextureSheet.assign_retain(source.mTextureSheet);
  }

  /**
   * Address: 0x0089F4E0 (FUN_0089F4E0, Moho::CStratumMaterial::SetSize)
   *
   * What it does:
   * Loads the backing terrain texture when needed and derives layer scale from
   * the provided map bounds.
   */
  void CStratumMaterial::SetSize(const Wm3::Vector2f& maxSize, CStratumMaterial& material)
  {
    if (material.mTextureSheet.px == nullptr && !material.mPath.empty()) {
      if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          boost::shared_ptr<RD3DTextureResource> textureResource{};
          resources->GetTexture(textureResource, material.mPath.c_str(), 0, true);
          material.mTextureSheet.assign_retain(boost::SharedPtrRawFromSharedBorrow(textureResource));
        }
      }
    }

    if (material.mTextureSheet.px != nullptr) {
      const float invSize = 1.0f / material.mSize;
      material.mScaleX = maxSize.x * invSize;
      material.mScaleY = maxSize.y * invSize;
      material.v3 = 0.0f;
      material.v4 = 1.0f;
    }
  }

  /**
   * Address: 0x0089E8B0 (FUN_0089E8B0, Moho::StratumMaterial::StratumMaterial)
   *
   * What it does:
   * Sets up the default terrain shader name, shared stratum masks, and all
   * twenty stratum layers with their initial paths and sizes.
   */
  StratumMaterial::StratumMaterial()
  {
    byte0 = 0;
    byte1 = 0;
    mShaderName.assign("TTerrain");
    v1 = 0;
    v2 = 0;
    mStratumMask0 = {};
    mStratumMask1 = {};

    AssignTextureDefaults(mLowerAlbedoTexture);
    AssignTextureDefaults(mStratum0AlbedoTexture);
    AssignTextureDefaults(mStratum1AlbedoTexture);
    AssignTextureDefaults(mStratum2AlbedoTexture);
    AssignTextureDefaults(mStratum3AlbedoTexture);
    AssignTextureDefaults(mStratum4AlbedoTexture);
    AssignTextureDefaults(mStratum5AlbedoTexture);
    AssignTextureDefaults(mStratum6AlbedoTexture);
    AssignTextureDefaults(mStratum7AlbedoTexture);
    AssignTextureDefaults(mUpperAlbedoTexture);
    AssignTextureDefaults(mLowerNormalTexture);
    AssignTextureDefaults(mStratum0NormalTexture);
    AssignTextureDefaults(mStratum1NormalTexture);
    AssignTextureDefaults(mStratum2NormalTexture);
    AssignTextureDefaults(mStratum3NormalTexture);
    AssignTextureDefaults(mStratum4NormalTexture);
    AssignTextureDefaults(mStratum5NormalTexture);
    AssignTextureDefaults(mStratum6NormalTexture);
    AssignTextureDefaults(mStratum7NormalTexture);
    AssignTextureDefaults(mUpperNormalTexture);

    SetTexturePathAndSize(mLowerAlbedoTexture, "/env/evergreen/layers/SandLight_albedo.dds", 4.0f);
    SetTexturePathAndSize(mLowerNormalTexture, "/env/evergreen/layers/SandLight_normals.dds", 4.0f);
    SetTexturePathAndSize(mStratum0AlbedoTexture, "/env/evergreen/layers/grass001_albedo.dds", 4.0f);
    SetTexturePathAndSize(mStratum0NormalTexture, "/env/evergreen/layers/grass001_normals.dds", 4.0f);
    SetTexturePathAndSize(mStratum1AlbedoTexture, "/env/evergreen/layers/Dirt001_albedo.dds", 4.0f);
    SetTexturePathAndSize(mStratum1NormalTexture, "/env/evergreen/layers/Dirt001_normals.dds", 4.0f);
    SetTexturePathAndSize(mStratum2AlbedoTexture, "/env/evergreen/layers/RockMed_albedo.dds", 4.0f);
    SetTexturePathAndSize(mStratum2NormalTexture, "/env/evergreen/layers/RockMed_normals.dds", 4.0f);
    SetTexturePathAndSize(mStratum3AlbedoTexture, "/env/evergreen/layers/snow001_albedo.dds", 4.0f);
    SetTexturePathAndSize(mStratum3NormalTexture, "/env/evergreen/layers/snow001_normals.dds", 4.0f);
    SetTexturePathAndSize(mStratum4AlbedoTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum4NormalTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum5AlbedoTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum5NormalTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum6AlbedoTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum6NormalTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum7AlbedoTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mStratum7NormalTexture, nullptr, 4.0f);
    SetTexturePathAndSize(mUpperAlbedoTexture, "/env/evergreen/layers/macrotexture000_albedo.dds", 128.0f);
  }

  /**
   * Address: 0x008A7890 (FUN_008A7890, Moho::StratumMaterial::StratumMaterial)
   *
   * What it does:
   * Copies the shader name, shared mask handles, and each layer descriptor
   * while retaining shared texture ownership.
   */
  StratumMaterial::StratumMaterial(const StratumMaterial& source)
    : byte0(source.byte0)
    , byte1(source.byte1)
    , pad02_03{0, 0}
    , mShaderName(source.mShaderName)
    , v1(source.v1)
    , v2(source.v2)
    , mStratumMask0{}
    , mStratumMask1{}
    , mLowerAlbedoTexture(source.mLowerAlbedoTexture)
    , mStratum0AlbedoTexture(source.mStratum0AlbedoTexture)
    , mStratum1AlbedoTexture(source.mStratum1AlbedoTexture)
    , mStratum2AlbedoTexture(source.mStratum2AlbedoTexture)
    , mStratum3AlbedoTexture(source.mStratum3AlbedoTexture)
    , mStratum4AlbedoTexture(source.mStratum4AlbedoTexture)
    , mStratum5AlbedoTexture(source.mStratum5AlbedoTexture)
    , mStratum6AlbedoTexture(source.mStratum6AlbedoTexture)
    , mStratum7AlbedoTexture(source.mStratum7AlbedoTexture)
    , mUpperAlbedoTexture(source.mUpperAlbedoTexture)
    , mLowerNormalTexture(source.mLowerNormalTexture)
    , mStratum0NormalTexture(source.mStratum0NormalTexture)
    , mStratum1NormalTexture(source.mStratum1NormalTexture)
    , mStratum2NormalTexture(source.mStratum2NormalTexture)
    , mStratum3NormalTexture(source.mStratum3NormalTexture)
    , mStratum4NormalTexture(source.mStratum4NormalTexture)
    , mStratum5NormalTexture(source.mStratum5NormalTexture)
    , mStratum6NormalTexture(source.mStratum6NormalTexture)
    , mStratum7NormalTexture(source.mStratum7NormalTexture)
    , mUpperNormalTexture(source.mUpperNormalTexture)
  {
    mStratumMask0.assign_retain(source.mStratumMask0);
    mStratumMask1.assign_retain(source.mStratumMask1);
  }

  /**
   * Address: 0x008A74F0 (FUN_008A74F0, Moho::StratumMaterial::~StratumMaterial)
   *
   * What it does:
   * Drops both shared mask handles and clears the shader name, while the
   * layer members unwind through their own destructors.
   */
  StratumMaterial::~StratumMaterial()
  {
    mStratumMask1.release();
    mStratumMask0.release();
    mShaderName.tidy();
  }

  /**
   * Address: 0x0089F130 (FUN_0089F130, Moho::StratumMaterial::SetSizeTo)
   *
   * What it does:
   * Applies world-map dimensions to every non-empty terrain layer.
   */
  void StratumMaterial::SetSizeTo(CWldTerrainRes* const terrainRes)
  {
    if (terrainRes == nullptr) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    if (device != nullptr) {
      (void)device->GetResources();
    }

    const CWldTerrainResRuntimeView* const view = AsTerrainView(terrainRes);
    if (view == nullptr || view->mMap == nullptr || view->mMap->mHeightField.get() == nullptr) {
      return;
    }

    const float maxX = static_cast<float>(view->mMap->mHeightField->width - 1);
    const float maxY = static_cast<float>(view->mMap->mHeightField->height - 1);
    const Wm3::Vector2f maxSize{maxX, maxY};

    auto applyIfConfigured = [&maxSize](CStratumMaterial& material) {
      if (!material.mPath.empty()) {
        CStratumMaterial::SetSize(maxSize, material);
      }
    };

    applyIfConfigured(mLowerAlbedoTexture);
    applyIfConfigured(mStratum0AlbedoTexture);
    applyIfConfigured(mStratum1AlbedoTexture);
    applyIfConfigured(mStratum2AlbedoTexture);
    applyIfConfigured(mStratum3AlbedoTexture);
    applyIfConfigured(mStratum4AlbedoTexture);
    applyIfConfigured(mStratum5AlbedoTexture);
    applyIfConfigured(mStratum6AlbedoTexture);
    applyIfConfigured(mStratum7AlbedoTexture);
    applyIfConfigured(mUpperAlbedoTexture);
    applyIfConfigured(mLowerNormalTexture);
    applyIfConfigured(mStratum0NormalTexture);
    applyIfConfigured(mStratum1NormalTexture);
    applyIfConfigured(mStratum2NormalTexture);
    applyIfConfigured(mStratum3NormalTexture);
    applyIfConfigured(mStratum4NormalTexture);
    applyIfConfigured(mStratum5NormalTexture);
    applyIfConfigured(mStratum6NormalTexture);
    applyIfConfigured(mStratum7NormalTexture);
    applyIfConfigured(mUpperNormalTexture);
  }
} // namespace moho
