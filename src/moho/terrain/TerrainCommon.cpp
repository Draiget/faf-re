#include "moho/terrain/TerrainCommon.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  /**
   * Address: 0x007FF840 (FUN_007FF840, ??0TerrainCommon@Moho@@QAE@@Z)
   * Address: 0x007FF7C0 (FUN_007FF7C0, ??0IRenTerrain@Moho@@QAE@@Z)
   * Address: 0x007FF7D0 (FUN_007FF7D0, the same body with `this` in eax)
   *
   * What it does:
   * Loads the shared decal mask texture from the active D3D device resource
   * manager. The vtable install is compiler-emitted, not a source statement.
   *
   * The two base-ctor addresses are MSVC's emission of `IRenTerrain::
   * IRenTerrain()`, which is nothing but `mov [this], offset
   * ??_7IRenTerrain@Moho@@6B@ (0x00E41994); ret` -- 0x007FF7C0 takes `this` in
   * ecx and 0x007FF7D0 in eax, so they are register-allocation twins of one
   * body. `TerrainCommon.h` models the pure interface and `TerrainCommon` as a
   * single class (all 15 IRenTerrain slots are `_purecall`), so neither has a
   * source-level home here -- and neither needs one: this constructor never
   * calls them in the binary either. At 0x007FF865 it stores its own vftable
   * 0x00E419D4 straight into `[esi]`, because MSVC elides a base constructor
   * whose only effect is a vtable the derived constructor overwrites on the
   * next instruction.
   *
   * Previously the body opened with `ResetIRenTerrainBaseVtable(this)`, an
   * empty file-static standing in for that elided glue -- a call the binary
   * does not make, to a function that did nothing.
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
