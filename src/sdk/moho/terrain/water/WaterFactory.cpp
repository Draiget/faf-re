#include "moho/terrain/water/WaterFactory.h"

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/terrain/water/HighFidelityWater.h"
#include "moho/terrain/water/LowFidelityWater.h"

namespace
{
  struct WaterSurfaceRuntimeView
  {
    void* mVtable = nullptr;
  };
  static_assert(sizeof(WaterSurfaceRuntimeView) == sizeof(moho::WaterSurface), "WaterSurfaceRuntimeView size must match");

  class WaterSurfaceVTableProbe final : public moho::WaterSurface
  {
  public:
    bool InitVerts(moho::TerrainWaterResourceView*) override
    {
      return false;
    }

    bool RenderWaterLayerAlphaMask(const moho::GeomCamera3*) override
    {
      return false;
    }

    bool RenderWaterSurface(
      std::int32_t,
      float,
      const moho::GeomCamera3*,
      const moho::CWaterShaderProperties*,
      boost::weak_ptr<gpg::gal::TextureD3D9>,
      boost::weak_ptr<gpg::gal::TextureD3D9>
    ) override
    {
      return false;
    }
  };

  [[nodiscard]] void* RecoveredWaterSurfaceVTable() noexcept
  {
    static WaterSurfaceVTableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }

  void WriteWaterSurfaceVTable(moho::WaterSurface* const surface) noexcept
  {
    auto& runtimeView = reinterpret_cast<WaterSurfaceRuntimeView&>(*surface);
    runtimeView.mVtable = RecoveredWaterSurfaceVTable();
  }

  /**
   * Address: 0x0080F930 (FUN_0080F930)
   *
   * IDA signature:
   * Moho::WaterSurface_vtbl **__usercall sub_80F930@<eax>(Moho::WaterSurface_vtbl **result@<eax>)
   *
   * What it does:
   * Writes the `WaterSurface` base-interface vtable lane and returns the same
   * object pointer.
   */
  [[maybe_unused]] moho::WaterSurface* InitializeWaterSurfaceVTableReturnLane(moho::WaterSurface* const surface) noexcept
  {
    WriteWaterSurfaceVTable(surface);
    return surface;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0080F920 (FUN_0080F920, ??0WaterSurface@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes one water-surface base interface object.
   */
  WaterSurface::WaterSurface() = default;

  /**
   * Address: 0x00811120 (FUN_00811120, func_CreateWaterFidelity)
   *
   * What it does:
   * Allocates one low/high-fidelity water surface by `graphics_Fidelity`,
   * logs the selected path, and initializes water render sheets.
   */
  WaterSurface* CreateWaterFidelity(TerrainWaterResourceView* const terrainResource)
  {
    WaterSurface* result = nullptr;
    if (graphics_Fidelity < 0) {
      return nullptr;
    }

    if (graphics_Fidelity <= 1) {
      result = new LowFidelityWater();
      gpg::Logf("creating low fidelity water");
    } else {
      if (graphics_Fidelity != 2) {
        return nullptr;
      }

      result = new HighFidelityWater();
      gpg::Logf("creating high fidelity water");
    }

    if (result != nullptr) {
      result->InitVerts(terrainResource);
    }
    return result;
  }
} // namespace moho
