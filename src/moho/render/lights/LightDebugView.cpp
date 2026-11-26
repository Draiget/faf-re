#include "moho/render/lights/LightDebugView.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

#include <memory>
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/lights/LightFeeds.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"

namespace moho::lights
{
  int ren_DynLightsView = 0;

  static TConVar<int> gTConVar_ren_DynLightsView(
    "ren_DynLightsView",
    "Debug view of the dynamic light grid: 1 draws every grid cell that lists a light on the ground (green = 1 light, "
    "red = the 8 a cell "
    "holds) and a marker on each light; 0 (the default) draws nothing.",
    &ren_DynLightsView
  );

  namespace
  {
    struct Screen
    {
      float x, y;
      bool ok;
    };

    Screen ToScreen(
      GeomCamera3& camera,
      const float x,
      const float y,
      const float z
    )
    {
      const Wm3::Vector3f world(x, y, z);
      // Row 1 of the viewport matrix is the depth the LOD tests use: positive in front of the camera.
      if (!(camera.viewport.ProjectViewportDepthRow1(world) > 0.0f)) {
        return {0.0f, 0.0f, false};
      }
      const Wm3::Vector2f p = camera.Project(world);
      return {p.x, p.y, std::isfinite(p.x) && std::isfinite(p.y)};
    }

    std::uint32_t HeatColour(
      const std::uint32_t count
    )
    {
      const float t = std::min(1.0f, static_cast<float>(count - 1u) / 15.0f);
      const auto r = static_cast<std::uint32_t>(40.0f + 215.0f * t);
      const auto g = static_cast<std::uint32_t>(220.0f - 160.0f * t);
      return 0x60000000u | (r << 16) | (g << 8) | 0x30u; // ARGB, translucent
    }
  } // namespace

  void DrawDebugView(
    GeomCamera3& camera,
    CD3DPrimBatcher* const primBatcher
  )
  {
    if (ren_DynLightsView == 0 || primBatcher == nullptr) {
      return;
    }
    const LightGridImage& image = FrameImage();
    if (image.lightCount == 0) {
      return;
    }

    // Ground height for the cell corners.
    const CHeightField* heightField = nullptr;
    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      if (const STIMap* const map = session->GetSTIMap(); map != nullptr) {
        heightField = map->GetHeightField();
      }
    }
    const auto ground = [heightField](const float x, const float z) {
      return heightField != nullptr ? heightField->GetElevation(x, z) : 0.0f;
    };

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(camera));
    primBatcher->SetViewMatrix(VMatrix4::Identity());
    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    const GridLayout& l = image.layout;
    for (std::uint32_t cz = 0; cz < l.cellsZ; ++cz) {
      for (std::uint32_t cx = 0; cx < l.cellsX; ++cx) {
        const std::uint32_t count = image.CellCount(cx, cz);
        if (count == 0) {
          continue;
        }
        const float x0 = l.originX + static_cast<float>(cx) * l.cellSize;
        const float z0 = l.originZ + static_cast<float>(cz) * l.cellSize;
        const float x1 = x0 + l.cellSize;
        const float z1 = z0 + l.cellSize;
        const Screen a = ToScreen(camera, x0, ground(x0, z0), z0);
        const Screen b = ToScreen(camera, x1, ground(x1, z0), z0);
        const Screen c = ToScreen(camera, x1, ground(x1, z1), z1);
        const Screen d = ToScreen(camera, x0, ground(x0, z1), z1);
        if (!(a.ok && b.ok && c.ok && d.ok)) {
          continue;
        }
        const std::uint32_t colour = HeatColour(count);
        const CD3DPrimBatcher::Vertex va{a.x, a.y, 0.0f, colour, 0.0f, 0.0f};
        const CD3DPrimBatcher::Vertex vb{b.x, b.y, 0.0f, colour, 1.0f, 0.0f};
        const CD3DPrimBatcher::Vertex vc{c.x, c.y, 0.0f, colour, 1.0f, 1.0f};
        const CD3DPrimBatcher::Vertex vd{d.x, d.y, 0.0f, colour, 0.0f, 1.0f};
        primBatcher->DrawQuad(va, vb, vc, vd);
      }
    }

    // A marker on each light: a small white diamond at its position.
    for (std::uint32_t i = 0; i < image.lightCount; ++i) {
      const float* a = &image.data[static_cast<std::size_t>(i) * kTexelsPerLight * 4u];
      const Screen s = ToScreen(camera, a[0], a[1], a[2]);
      if (!s.ok) {
        continue;
      }
      constexpr float h = 4.0f;
      constexpr std::uint32_t white = 0xFFFFFFFFu;
      const CD3DPrimBatcher::Vertex v0{s.x, s.y - h, 0.0f, white, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex v1{s.x + h, s.y, 0.0f, white, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex v2{s.x, s.y + h, 0.0f, white, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex v3{s.x - h, s.y, 0.0f, white, 0.0f, 1.0f};
      primBatcher->DrawQuad(v0, v1, v2, v3);
    }
    primBatcher->Flush();
  }
} // namespace moho::lights
