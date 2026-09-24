#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"

namespace gpg::gal
{
  class Texture;
}

namespace moho
{
  class ID3DRenderTarget;
  class CWaterShaderProperties;
  struct GeomCamera3;
  class IWldTerrainRes;

  /**
   * Common water-render interface used by terrain fidelity factory lanes.
   */
  class WaterSurface
  {
  public:
    /**
     * Address: 0x0080F920 (FUN_0080F920, ??0WaterSurface@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one water-surface base interface object.
     */
    WaterSurface();

    /**
     * Address: 0x0080F930 (FUN_0080F930)
     *
     * Vtable slot 0. Defined in WaterFactory.cpp alongside the constructor.
     */
    virtual ~WaterSurface();

    /**
     * Rebuilds render sheets from the current terrain map dimensions.
     */
    virtual bool InitVerts(IWldTerrainRes* terrainResource) = 0;

    /**
     * Address family:
     * - 0x00810540 (FUN_00810540, Moho::HighFidelityWater::Func1)
     * - 0x0080FC40 (FUN_0080FC40, Moho::LowFidelityWater::Func1)
     *
     * Vtable slot 2 of ??_7WaterSurface@Moho@@6B@ (0x00E41F74), which has five
     * pure slots; this one was missing here, so the two draw lanes below sat in
     * slots 2 and 3 where the binary keeps them in 3 and 4. It pairs with
     * InitVerts exactly as TerrainCommon pairs Init (slot 3) with Destroy
     * (slot 4).
     *
     * Both bodies return nothing: each ends in a bare `ret` with `eax` left
     * holding whatever the last handle release put there, so the `int` the
     * low-fidelity override used to return was never a value the engine
     * produced.
     *
     * What it does:
     * Releases every render resource the surface owns and unbinds the terrain
     * resource, leaving the object reusable by a later InitVerts.
     */
    virtual void Destroy() = 0;

    /**
     * Address family:
     * - 0x008105E0 (FUN_008105E0, Moho::HighFidelityWater::Func2)
     * - 0x0080FC70 (FUN_0080FC70, Moho::LowFidelityWater reserved lane)
     *
     * Vtable slot 3.
     *
     * What it does:
     * Executes one water-layer alpha-mask draw lane for the current camera.
     */
    virtual bool RenderWaterLayerAlphaMask(const GeomCamera3* camera) = 0;

    /**
     * Address family:
     * - 0x008106D0 (FUN_008106D0, Moho::HighFidelityWater::Func3)
     * - 0x0080FC80 (FUN_0080FC80, Moho::LowFidelityWater::Func3)
     *
     * Vtable slot 4.
     *
     * What it does:
     * Executes one full water-surface draw pass using the active camera,
     * runtime water shader properties, and reflection/refraction inputs.
     */
    virtual bool RenderWaterSurface(
      std::int32_t tick,
      float tickLerp,
      const GeomCamera3* camera,
      const CWaterShaderProperties* shaderProperties,
      const boost::shared_ptr<ID3DRenderTarget>& refractionTexture,
      const boost::shared_ptr<ID3DRenderTarget>& reflectionTexture
    ) = 0;
  };
} // namespace moho
