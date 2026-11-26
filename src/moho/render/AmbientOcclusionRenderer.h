#pragma once

#include <cstdint>
#include <string>

#include <memory>

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
   * Engine addition (`ren_AmbientOcclusion`, `ren_Ao`): ambient occlusion, the darkening in creases, under units and
   * where terrain meets them, from the depth of terrain and the opaque meshes, in one frame slot (after the opaque
   * meshes, before effects and water). At most one occlusion kernel runs at a time:
   *  - Standard: this renderer's compute kernel, with contact shadows and terrain shadows (Direct3D 12 and Vulkan; it
   * reads the bound depth target, `GpuBindings::readBoundDepth`);
   *  - Low, Medium, High: GTAO (AmbientOcclusion.h, gpg::gal::AmbientOcclusionPass; Direct3D 11 too), after which the
   * compute pass only adds the contact and terrain shadows;
   *  - with ray-traced shadows tracing, the traced occlusion (`ren_RayAo`) in the compute pass.
   * Direct3D 9 keeps the original look.
   */
  class AmbientOcclusionRenderer
  {
  public:
    [[nodiscard]] static AmbientOcclusionRenderer& Get();

    /** The option is not Off and the device has an occlusion kernel (the compute one, or GTAO's GPU programs). */
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
    void
    Render(const GeomCamera3& camera, int x, int y, int width, int height, float shadowReach, const Shadow* shadow);

  private:
    /** Re-bakes terrain shadows when the map's heightfield or the sun changed; false when there are none. */
    [[nodiscard]] bool PrepareTerrainShadows(const float sun[3]);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    bool mGtaoPossible = false; // the GPU programs GTAO draws with exist (Direct3D 11, 12, Vulkan)
    std::shared_ptr<gpg::gal::GpuProgram> mCompute;
    std::string mRaySource; // the compute source, with FAF_RAY_QUERY defined where the device traces rays (ren_RayAo)
    std::shared_ptr<gpg::gal::GpuProgram> mBake;
    std::shared_ptr<gpg::gal::GpuBuffer> mHeights;
    std::shared_ptr<gpg::gal::GpuBuffer> mTerrainShadow;
    const void* mBakedField = nullptr;
    std::uint64_t mBakedRevision = 0U;
    float mBakedSun[3]{};
    std::int32_t mFieldWidth = 0;
    std::int32_t mFieldHeight = 0;
    std::uint32_t mShadowCellSize = 1U;
    std::uint32_t mShadowAcross = 0U;
    std::uint32_t mShadowDown = 0U;
    std::shared_ptr<gpg::gal::GpuProgram> mComposite;
    std::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;
  };
} // namespace moho
