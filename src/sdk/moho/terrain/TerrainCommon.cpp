#include "moho/terrain/TerrainCommon.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  /**
   * Address: 0x007FF840 (FUN_007FF840, ??0TerrainCommon@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes the vtable and loads the shared decal mask texture from the
   * active D3D device resource manager.
   */
  TerrainCommon::TerrainCommon()
  {
    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
    resources->GetTexture(mDecalMask, "/textures/engine/decalMask.dds", 0, true);
  }

  /**
   * Address: 0x007FF8D0 (FUN_007FF8D0, ??1IRenTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Releases the shared decal-mask texture handle and restores the terrain
   * base vtable lane during teardown.
   */
  TerrainCommon::~TerrainCommon()
  {
    mDecalMask.reset();
  }
} // namespace moho
