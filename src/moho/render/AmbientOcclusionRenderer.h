#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  struct GeomCamera3;
  class Shadow;

  extern int ren_Ao;

  /**
   * Engine addition (`ren_Ao`): ambient occlusion, the darkening in creases, under units and where
   * terrain meets them, from the depth of terrain and the opaque meshes. Direct3D 12 and Vulkan only:
   * it reads the bound depth target (`GpuBindings::readBoundDepth`). Direct3D 9 and 11 keep the
   * original look.
   */
  class AmbientOcclusionRenderer
  {
  public:
    [[nodiscard]] static AmbientOcclusionRenderer& Get();

    /** `ren_Ao` is on, the renderer is Direct3D 12 or Vulkan with compute, and the programs built. */
    [[nodiscard]] bool IsActive();

    /**
     * Darkens the bound colour target over the view at (`x`, `y`), `width` by `height` pixels, by the
     * occlusion the bound depth shows. Call it with the world view's viewport set, after the opaque
     * meshes and before effects and water. `shadowReach` is how far the shadow map reaches this frame:
     * terrain shadows from the heightfield take over beyond it; 0 when the map is off past
     * ren_ShadowLOD, and negative when the player has shadows off, which keeps them off too.
     * `shadow`, when it drew this frame's sun shadow, keeps contact shadows to the points it lights:
     * it already shades the rest, and a second darkening turned the ground under trees near-black.
     */
    void Render(const GeomCamera3& camera, int x, int y, int width, int height, float shadowReach, const Shadow* shadow);

  private:
    /** Re-bakes terrain shadows when the map's heightfield or the sun changed; false when there are none. */
    [[nodiscard]] bool PrepareTerrainShadows(const float sun[3]);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompute;
    boost::shared_ptr<gpg::gal::GpuProgram> mBake;
    boost::shared_ptr<gpg::gal::GpuBuffer> mHeights;
    boost::shared_ptr<gpg::gal::GpuBuffer> mTerrainShadow;
    const void* mBakedField = nullptr;
    float mBakedSun[3]{};
    std::int32_t mFieldWidth = 0;
    std::int32_t mFieldHeight = 0;
    std::uint32_t mShadowCellSize = 1U;
    std::uint32_t mShadowAcross = 0U;
    std::uint32_t mShadowDown = 0U;
    boost::shared_ptr<gpg::gal::GpuProgram> mComposite;
    boost::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;
  };
} // namespace moho
