#include "editor/view/EdMapScene.h"

#include "editor/tools/EdSymmetrize.h"
#include "editor/tools/EdShaderProfiles.h"
#include "editor/doc/EdLighting.h"
#include "editor/tools/EdGroundKind.h"
#include "editor/tools/EdRecipes.h"
#include "editor/tools/EdMapStats.h"
#include "editor/tools/EdPathing.h"
#include "editor/tools/EdCameraFrame.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdScatter.h"
#include "editor/tools/EdSlopeRules.h"
#include "editor/tools/EdSymmetryFollow.h"
#include "editor/doc/EdUnitFate.h"

#include <utility>
#include <algorithm>
#include <chrono>
#include <random>
#include <cmath>
#include <cstdlib>
#include <functional>
#include <map>
#include <set>
#include <cstring>

#include <windowsx.h>
#include <ranges>

#include "editor/EdTools.h"
#include "moho/misc/StartupHelpers.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "moho/app/CScApp.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "editor/ui/EdKeymap.h"
#include "moho/math/QuaternionMath.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdHeightFile.h"
#include "editor/tools/EdMaskBrush.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "editor/tools/EdSymmetryCheck.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/IEdRenderHook.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/render/RCamManager.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/SimpleRenderWorldView.h"
#include "moho/render/WRenViewport.h"
#include "editor/view/EdLiveTerrain.h"

namespace moho
{
  extern bool ren_Ui; // the game's interface drawn (console `ren_Ui`; RuntimeTuningGlobals.cpp)
}
#include "gpg/core/utils/SharedPtrUtils.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DDeviceResources.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  extern bool ren_TerrainSurface; // the height field's surface drawn (WRenViewport.cpp)
} // namespace moho

namespace faf::editor
{
  /** The renderer's editor hook (IEdRenderHook, called at the end of WRenViewport::RenderUI): the brush rings. */
  class EdMapScene::RingHook final : public moho::IEdRenderHook
  {
  public:
    explicit RingHook(
      EdMapScene& scene
    )
      : mScene(scene)
    {}
    void Render() override
    {
      // Drawn by the main view's own overlay pass (EdMainView) when it ran this frame; here only otherwise.
      if (!mScene.mOverlaysDrawn) {
        mScene.DrawBrushRings();
      }
      mScene.mOverlaysDrawn = false;
    }

  private:
    EdMapScene& mScene;
  };

  namespace
  {
    constexpr float kPi = 3.14159265f;
    constexpr float kMinPitch = 0.12f;
    constexpr float kMaxPitch = kPi * 0.5f;
  } // namespace

  /**
   * The minimap's world view: the simple view's drawing, said to be a minimap (IsMiniMap), so the terrain draws its
   * minimap pass as the game's own minimap does. Held by its own type: the interface has no virtual destructor.
   */
  class EdMiniMapView final : public moho::IRenderWorldView
  {
  public:
    explicit EdMiniMapView(
      moho::GeomCamera3* const cameraView
    )
      : mInner(cameraView)
    {}
    void Render(
      moho::CD3DPrimBatcher* const batcher,
      const int gameTick,
      const float tickFraction,
      const float frameSeconds
    ) override
    {
      mInner.Render(batcher, gameTick, tickFraction, frameSeconds);
    }
    void RenderCommandGraph(
      moho::CD3DPrimBatcher* const batcher,
      const int gameTick,
      const float tickFraction,
      const float frameSeconds
    ) override
    {
      mInner.RenderCommandGraph(batcher, gameTick, tickFraction, frameSeconds);
    }
    [[nodiscard]] moho::CameraImpl* GetCamera() override
    {
      return mInner.GetCamera();
    }
    [[nodiscard]] moho::GeomCamera3* GetCameraView() override
    {
      return mInner.GetCameraView();
    }
    [[nodiscard]] Wm3::Vector3f* GetCameraOffset() override
    {
      return mInner.GetCameraOffset();
    }
    [[nodiscard]] float CameraGetTargetZoom() override
    {
      return mInner.CameraGetTargetZoom();
    }
    [[nodiscard]] float GetMaxZoom() override
    {
      return mInner.GetMaxZoom();
    }
    [[nodiscard]] float CameraGetZoom() override
    {
      return mInner.CameraGetZoom();
    }
    [[nodiscard]] bool IsMiniMap() override
    {
      return true;
    }
    void SetOrthographic(
      const bool enabled
    ) override
    {
      mInner.SetOrthographic(enabled);
    }
    [[nodiscard]] bool CanShake() override
    {
      return false;
    }
    /** True: the renderer skips this view this frame (the panels draw its last copy). */
    [[nodiscard]] bool Func2() override
    {
      return mSkip;
    }
    void SetSkip(
      const bool skip
    ) noexcept
    {
      mSkip = skip;
    }

  private:
    moho::SimpleRenderWorldView mInner;
    bool mSkip = false;
  };

  /**
   * The main view: the simple view's drawing, with the editor's overlays (rings, slope, markers ...) drawn in its own
   * overlay pass. They used to draw at the end of the UI pass, over every view, so the minimap (drawn after the main
   * view) got the main view's overlays laid over it.
   */
  class EdMainView final : public moho::IRenderWorldView
  {
  public:
    EdMainView(
      moho::GeomCamera3* const cameraView,
      EdMapScene& scene
    )
      : mInner(cameraView)
      , mScene(scene)
    {}
    void Render(
      moho::CD3DPrimBatcher* const batcher,
      const int gameTick,
      const float tickFraction,
      const float frameSeconds
    ) override
    {
      mInner.Render(batcher, gameTick, tickFraction, frameSeconds);
      mScene.DrawViewOverlays();
    }
    void RenderCommandGraph(
      moho::CD3DPrimBatcher* const batcher,
      const int gameTick,
      const float tickFraction,
      const float frameSeconds
    ) override
    {
      mInner.RenderCommandGraph(batcher, gameTick, tickFraction, frameSeconds);
    }
    [[nodiscard]] moho::CameraImpl* GetCamera() override
    {
      return mInner.GetCamera();
    }
    [[nodiscard]] moho::GeomCamera3* GetCameraView() override
    {
      return mInner.GetCameraView();
    }
    [[nodiscard]] Wm3::Vector3f* GetCameraOffset() override
    {
      return mInner.GetCameraOffset();
    }
    [[nodiscard]] float CameraGetTargetZoom() override
    {
      // The editor camera's distance, as the game camera's zoom is (the simple view says 0): the shadow map reaches
      // ren_ShadowCoeff times it and is drawn up to ren_ShadowLOD; at 0 its volume is empty and nothing has shadows.
      return mScene.GetCameraPose().distance;
    }
    [[nodiscard]] float GetMaxZoom() override
    {
      return mInner.GetMaxZoom();
    }
    [[nodiscard]] float CameraGetZoom() override
    {
      return mInner.CameraGetZoom();
    }
    [[nodiscard]] bool IsMiniMap() override
    {
      return mInner.IsMiniMap();
    }
    void SetOrthographic(
      const bool enabled
    ) override
    {
      mInner.SetOrthographic(enabled);
    }
    [[nodiscard]] bool CanShake() override
    {
      return mInner.CanShake();
    }
    [[nodiscard]] bool Func2() override
    {
      return mInner.Func2();
    }

  private:
    moho::SimpleRenderWorldView mInner;
    EdMapScene& mScene;
  };

  void EdMapScene::DrawViewOverlays()
  {
    DrawBrushRings();
    if (moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->GetPrimBatcher()->Flush();
    }
    mOverlaysDrawn = true;
  }

  // The constructor and destructor come after EdMiniMapView and EdMainView: they destroy the unique_ptr members, and
  // C++23's constexpr unique_ptr instantiates that delete where it is first used, so the views must be complete there.
  EdMapScene::EdMapScene(
    EdDocument& document
  )
    : mDocument(document)
  {}

  EdMapScene::~EdMapScene()
  {
    Detach();
  }

  namespace
  {
    /**
     * A run of overlay cells (`scale` world units each) as quads on the ground, cut every 8 units: one long quad
     * between the heights at its two ends cut through ridges and floated over valleys (the slope and terrain-type views
     * showed streaks of ground through them).
     */
    template <class GroundVertex>
    void AddGroundRun(
      std::vector<moho::CD3DPrimBatcher::Vertex>& quads,
      const GroundVertex& groundVertex,
      const TerrainTypeRun& run,
      const std::uint32_t color,
      const float scale,
      const float pieceUnits = 8.0f
    )
    {
      const float z0 = static_cast<float>(run.z) * scale;
      const float z1 = z0 + scale;
      // `pieceUnits` a quad: short enough to follow the ground, few enough to draw a whole map.
      const int piece = std::max(1, static_cast<int>(pieceUnits / scale));
      for (int x = run.x0; x < run.x1; x += piece) {
        const float x0 = static_cast<float>(x) * scale;
        const float x1 = static_cast<float>(std::min(x + piece, run.x1)) * scale;
        quads.push_back(groundVertex(x0, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z1, color, 0.3f));
        quads.push_back(groundVertex(x0, z1, color, 0.3f));
      }
    }
  } // namespace

  void EdMapScene::DrawBrushRings()
  {
    const std::optional<EdDocument::PlayableRect> area = mMap != nullptr ? mDocument.PlayableArea() : std::nullopt;
    if (
      mMap == nullptr || mCamera == nullptr || mTools == nullptr ||
      (!mTools->TerrainToolActive() && !mTools->TextureToolActive() && !mTools->PropsToolActive() &&
       !mTools->SelectToolActive() && mSelection.empty() && !area && mDocument.SaveData().Markers().empty() &&
       mDocument.SaveData().Chains().empty() && !mTools->ShowGrid() && !mTools->DecalsToolActive() &&
       !mTools->UnitsToolActive() && !mTools->EditingBorder() && !mTools->WaterToolActive() &&
       mTools->SymmetryHover() < 0 && mTools->CheckPins().empty() && !mTools->ShowingPathing() &&
       !mTools->ShowSlope() && !mTools->ShowHeights() && !mTools->ShowKmGrid() && !mRulerShown && !mBoxing &&
       mMeshWire.empty()) ||
      moho::ren_Viewport == nullptr
    ) {
      return;
    }
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (field == nullptr) {
      return;
    }
    // A hovered toolbar symmetry button: its mode's lines (and the moving preview below) instead of the current one's.
    const HeightBrush brush = mTools->PreviewHeightBrush();

    moho::CD3DPrimBatcher* const batcher = moho::ren_Viewport->GetPrimBatcher();
    (void)batcher->Setup("TAlphaBlendLinearSampleNoDepth");
    batcher->SetViewProjMatrix(mCamera->CameraGetView());
    batcher->SetTexture(moho::CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    // On the ground, a little above it so the lines don't sink into slopes between samples.
    const auto groundVertex =
      [field](const float x, const float z, const std::uint32_t color, const float lift = 0.4f) {
      const int sx = std::clamp(static_cast<int>(std::lround(x)), 0, field->width - 1);
      const int sz = std::clamp(static_cast<int>(std::lround(z)), 0, field->height - 1);
      moho::CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = static_cast<float>(field->data[sz * field->width + sx]) / 128.0f + lift;
      vertex.mZ = z;
      vertex.mColor = color;
      return vertex;
    };

    // The mirror lines of the symmetry, along the ground, and the turn centre as a vertical axis.
    const float w = static_cast<float>(field->width - 1);
    const float h = static_cast<float>(field->height - 1);
    constexpr std::uint32_t kMirrorColor = 0xC03CC8FFu;
    // A translucent wall stands on each line, so the line reads from any angle. The walls are drawn after
    // the lines in one call: the batcher keeps one kind of primitive per batch, so a quad after each line
    // segment made a draw call of every segment (60 fps went to 10).
    std::vector<moho::CD3DPrimBatcher::Vertex> walls;
    constexpr std::uint32_t kWallColor = 0x283CC8FFu;
    const float wallHeight = std::max(w, h) * 0.04f;
    const auto groundLine = [&](const float x0, const float z0, const float x1, const float z1) {
      const float length = std::hypot(x1 - x0, z1 - z0);
      const int steps = std::max(1, static_cast<int>(length / 4.0f));
      for (int s = 0; s < steps; ++s) {
        const float t0 = static_cast<float>(s) / steps;
        const float t1 = static_cast<float>(s + 1) / steps;
        const moho::CD3DPrimBatcher::Vertex a =
          groundVertex(x0 + (x1 - x0) * t0, z0 + (z1 - z0) * t0, kMirrorColor, 0.6f);
        const moho::CD3DPrimBatcher::Vertex b =
          groundVertex(x0 + (x1 - x0) * t1, z0 + (z1 - z0) * t1, kMirrorColor, 0.6f);
        batcher->DrawLine(a, b);
        moho::CD3DPrimBatcher::Vertex wa = a;
        moho::CD3DPrimBatcher::Vertex wb = b;
        wa.mColor = kWallColor;
        wb.mColor = kWallColor;
        moho::CD3DPrimBatcher::Vertex ta = wa;
        moho::CD3DPrimBatcher::Vertex tb = wb;
        ta.mY += wallHeight;
        tb.mY += wallHeight;
        walls.insert(walls.end(), {wa, wb, tb, ta});
      }
    };
    // The symmetry's centre (Terrain tool > Symmetry centre; the map's middle unless moved).
    const float symX = w * 0.5f + SymmetryCentreOffsetX();
    const float symZ = h * 0.5f + SymmetryCentreOffsetZ();
    const float symReach = std::max(w, h);
    const auto turnAxis = [&]() {
      moho::CD3DPrimBatcher::Vertex top = groundVertex(symX, symZ, kMirrorColor, 0.0f);
      moho::CD3DPrimBatcher::Vertex bottom = top;
      top.mY += std::max(w, h) * 0.15f;
      batcher->DrawLine(bottom, top);
    };
    const bool square = field->width == field->height;
    switch (brush.symmetry) {
    case Symmetry::LeftRight:
      groundLine(symX, 0.0f, symX, h);
      break;
    case Symmetry::TopBottom:
      groundLine(0.0f, symZ, w, symZ);
      break;
    case Symmetry::DiagonalBack:
      if (square) {
        groundLine(symX - symReach, symZ - symReach, symX + symReach, symZ + symReach);
      }
      break;
    case Symmetry::DiagonalForward:
      if (square) {
        groundLine(symX + symReach, symZ - symReach, symX - symReach, symZ + symReach);
      }
      break;
    case Symmetry::HalfTurn:
      turnAxis();
      break;
    case Symmetry::BothAxes:
      groundLine(symX, 0.0f, symX, h);
      groundLine(0.0f, symZ, w, symZ);
      break;
    case Symmetry::BothDiagonals:
      if (square) {
        groundLine(symX - symReach, symZ - symReach, symX + symReach, symZ + symReach);
        groundLine(symX + symReach, symZ - symReach, symX - symReach, symZ + symReach);
      }
      break;
    case Symmetry::QuarterTurns:
      if (square) {
        turnAxis();
      }
      break;
    case Symmetry::NWay:
      // The turn centre and the sectors' edges, from the centre to the map's edge.
      if (square) {
        turnAxis();
        const int turns = std::clamp(brush.turns, 2, kMaxSymmetryCopies);
        for (int k = 0; k < turns; ++k) {
          const float angle = 2.0f * kPi * static_cast<float>(k) / static_cast<float>(turns);
          const float dx = std::cos(angle);
          const float dz = std::sin(angle);
          // To the square's edge along this ray.
          const float reach = 0.5f * w / std::max(std::fabs(dx), std::fabs(dz));
          groundLine(symX, symZ, symX + dx * reach, symZ + dz * reach);
        }
      }
      break;
    default:
      break;
    }

    if (!walls.empty()) {
      batcher->DrawQuads(walls.data(), static_cast<std::uint32_t>(walls.size() / 4));
    }

    // The hovered mode in motion: a ring loops through the source part and every copy follows as the mode copies
    // it; a tick shows each one's heading, so a mirror (copies turn the other way) reads apart from a turn.
    if (mTools->SymmetryHover() >= 0) {
      const float seconds =
        static_cast<float>(std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count());
      const float t = std::fmod(seconds, 600.0f) * 0.9f;
      const auto pathAt = [&](const float time, float& x, float& z) {
        // A loop in the first quarter-turn sector's middle (the source part of every mode).
        x = w * (0.30f + 0.11f * std::cos(time));
        z = h * (0.24f + 0.08f * std::sin(time * 2.0f));
      };
      float x = 0.0f;
      float z = 0.0f;
      float ahead[2] = {};
      pathAt(t, x, z);
      pathAt(t + 0.18f, ahead[0], ahead[1]);
      float cx[kMaxSymmetryCopies];
      float cz[kMaxSymmetryCopies];
      float tx[kMaxSymmetryCopies];
      float tz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      const int tips =
        HeightBrushCentres(field->width, field->height, ahead[0], ahead[1], brush.symmetry, brush.turns, tx, tz);
      const float radius = std::max(w, h) * 0.035f;
      for (int c = 0; c < copies; ++c) {
        const std::uint32_t colour = c == 0 ? 0xFFFFFFFFu : 0xFF5CD2FFu;
        constexpr int kSegments = 40;
        for (const float r : {radius, radius * 0.94f}) {
          for (int s = 0; s < kSegments; ++s) {
            const float a0 = 2.0f * kPi * static_cast<float>(s) / kSegments;
            const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / kSegments;
            batcher->DrawLine(
              groundVertex(cx[c] + std::cos(a0) * r, cz[c] + std::sin(a0) * r, colour, 1.0f),
              groundVertex(cx[c] + std::cos(a1) * r, cz[c] + std::sin(a1) * r, colour, 1.0f)
            );
          }
        }
        if (c < tips) {
          // The heading: from the ring's middle towards where it goes next, as long as the radius.
          const float dx = tx[c] - cx[c];
          const float dz = tz[c] - cz[c];
          const float length = std::max(0.001f, std::hypot(dx, dz));
          for (const float side : {-0.6f, 0.0f, 0.6f}) {
            const float nx = -dz / length * side;
            const float nz = dx / length * side;
            batcher->DrawLine(
              groundVertex(cx[c] + nx, cz[c] + nz, colour, 1.0f),
              groundVertex(cx[c] + dx / length * radius + nx, cz[c] + dz / length * radius + nz, colour, 1.0f)
            );
          }
        }
      }
    }

    // The playable area: the ground outside it darkened as the game shows it, its border in amber.
    if (area) {
      if (mOutsideStale || mOutsideFor != area) {
        BuildOutsideQuads(*area);
      }
      if (!mOutsideQuads.empty()) {
        batcher->DrawQuads(mOutsideQuads.data(), static_cast<std::uint32_t>(mOutsideQuads.size() / 4));
      }
      constexpr std::uint32_t kBorderColor = 0xF0FFB030u;
      const float x0 = static_cast<float>(area->x0);
      const float z0 = static_cast<float>(area->z0);
      const float x1 = static_cast<float>(area->x1);
      const float z1 = static_cast<float>(area->z1);
      const auto border = [&](const float ax, const float az, const float bx, const float bz) {
        const int steps = std::max(1, static_cast<int>(std::hypot(bx - ax, bz - az) / 4.0f));
        for (int s = 0; s < steps; ++s) {
          const float t0 = static_cast<float>(s) / steps;
          const float t1 = static_cast<float>(s + 1) / steps;
          batcher->DrawLine(
            groundVertex(ax + (bx - ax) * t0, az + (bz - az) * t0, kBorderColor, 0.8f),
            groundVertex(ax + (bx - ax) * t1, az + (bz - az) * t1, kBorderColor, 0.8f)
          );
        }
      };
      border(x0, z0, x1, z0);
      border(x1, z0, x1, z1);
      border(x1, z1, x0, z1);
      border(x0, z1, x0, z0);
      // Being edited: the edge under the cursor lit, handles on the corners and the edges' middles.
      if (mTools->EditingBorder()) {
        float gx = 0.0f;
        float gz = 0.0f;
        const int hot = CursorGround(gx, gz) ? BorderEdgesAt(gx, gz) : 0;
        constexpr std::uint32_t kHot = 0xFFFFE040u;
        const auto litEdge = [&](const float ax, const float az, const float bx, const float bz) {
          for (const float lift : {1.0f, 1.4f, 1.8f}) {
            const int steps = std::max(1, static_cast<int>(std::hypot(bx - ax, bz - az) / 4.0f));
            for (int s = 0; s < steps; ++s) {
              const float t0 = static_cast<float>(s) / steps;
              const float t1 = static_cast<float>(s + 1) / steps;
              batcher->DrawLine(
                groundVertex(ax + (bx - ax) * t0, az + (bz - az) * t0, kHot, lift),
                groundVertex(ax + (bx - ax) * t1, az + (bz - az) * t1, kHot, lift)
              );
            }
          }
        };
        if ((hot & 1) != 0)
          litEdge(x0, z0, x0, z1);
        if ((hot & 2) != 0)
          litEdge(x0, z0, x1, z0);
        if ((hot & 4) != 0)
          litEdge(x1, z0, x1, z1);
        if ((hot & 8) != 0)
          litEdge(x0, z1, x1, z1);
        const float r = std::max(2.0f, mDistance * 0.006f);
        std::vector<moho::CD3DPrimBatcher::Vertex> handles;
        for (const auto& [hx, hz] :
             {std::pair{x0, z0},
              std::pair{x1, z0},
              std::pair{x1, z1},
              std::pair{x0, z1},
              std::pair{(x0 + x1) * 0.5f, z0},
              std::pair{x1, (z0 + z1) * 0.5f},
              std::pair{(x0 + x1) * 0.5f, z1},
              std::pair{x0, (z0 + z1) * 0.5f}}) {
          handles.push_back(groundVertex(hx - r, hz - r, kBorderColor, 1.2f));
          handles.push_back(groundVertex(hx + r, hz - r, kBorderColor, 1.2f));
          handles.push_back(groundVertex(hx + r, hz + r, kBorderColor, 1.2f));
          handles.push_back(groundVertex(hx - r, hz + r, kBorderColor, 1.2f));
        }
        batcher->DrawQuads(handles.data(), static_cast<std::uint32_t>(handles.size() / 4));
      }
    } else if (mTools->EditingBorder()) {
      // No border yet: the map's own edge, dashed, so the mode shows where one would go (the Properties panel adds it).
      constexpr std::uint32_t kEdge = 0xC0FFB030u;
      const auto dashed = [&](const float ax, const float az, const float bx, const float bz) {
        const int steps = std::max(2, static_cast<int>(std::hypot(bx - ax, bz - az) / 6.0f));
        for (int s = 0; s < steps; s += 2) {
          const float t0 = static_cast<float>(s) / steps;
          const float t1 = static_cast<float>(s + 1) / steps;
          batcher->DrawLine(
            groundVertex(ax + (bx - ax) * t0, az + (bz - az) * t0, kEdge, 0.8f),
            groundVertex(ax + (bx - ax) * t1, az + (bz - az) * t1, kEdge, 0.8f)
          );
        }
      };
      dashed(0.0f, 0.0f, w, 0.0f);
      dashed(w, 0.0f, w, h);
      dashed(w, h, 0.0f, h);
      dashed(0.0f, h, 0.0f, 0.0f);
    }

    // The build grid around the cursor: cell edges on whole steps, fading out with the distance.
    if (mTools->ShowGrid()) {
      float gx = 0.0f;
      float gz = 0.0f;
      if (CursorGround(gx, gz)) {
        const float step = mTools->GridStep();
        const int reach = std::max(4, static_cast<int>(std::ceil(28.0f / step)));
        const float radius = static_cast<float>(reach) * step;
        const float ox = std::floor(gx / step) * step;
        const float oz = std::floor(gz / step) * step;
        const auto shade = [&](const float x, const float z) {
          const float fade = std::clamp(1.0f - std::hypot(x - gx, z - gz) / radius, 0.0f, 1.0f);
          return (static_cast<std::uint32_t>(fade * fade * 200.0f) << 24) | 0x00FFFFFFu;
        };
        for (int k = -reach; k <= reach; ++k) {
          for (int s = -reach; s < reach; ++s) {
            // A segment of the line x = ox + k step, and one of z = oz + k step.
            const float lx = ox + static_cast<float>(k) * step;
            const float z0 = oz + static_cast<float>(s) * step;
            const float z1 = z0 + step;
            const float lz = oz + static_cast<float>(k) * step;
            const float x0 = ox + static_cast<float>(s) * step;
            const float x1 = x0 + step;
            if (shade(lx, z0) > 0x00FFFFFFu || shade(lx, z1) > 0x00FFFFFFu) {
              batcher->DrawLine(groundVertex(lx, z0, shade(lx, z0), 0.25f), groundVertex(lx, z1, shade(lx, z1), 0.25f));
            }
            if (shade(x0, lz) > 0x00FFFFFFu || shade(x1, lz) > 0x00FFFFFFu) {
              batcher->DrawLine(groundVertex(x0, lz, shade(x0, lz), 0.25f), groundVertex(x1, lz, shade(x1, lz), 0.25f));
            }
          }
        }
      }
    }

    // The brush's weight on each sample under it (FAF Studio's weight overlay): a dot per sample (or per few on a
    // wide brush), brighter where the brush works harder, so shapes, falloff and stamps show before a dab.
    if (mTools->TerrainToolActive() && mTools->ShowBrushWeight()) {
      float gx = 0.0f;
      float gz = 0.0f;
      if (CursorGround(gx, gz)) {
        const HeightBrush& weightBrush = brush;
        const int reach = static_cast<int>(std::ceil(weightBrush.radius));
        const int stride = std::max(1, reach / 32);
        const float half = 0.16f * static_cast<float>(stride) + 0.12f;
        std::vector<moho::CD3DPrimBatcher::Vertex> dots;
        const int cx = static_cast<int>(std::lround(gx));
        const int cz = static_cast<int>(std::lround(gz));
        for (int dz = -reach; dz <= reach; dz += stride) {
          for (int dx = -reach; dx <= reach; dx += stride) {
            const int sx = cx + dx;
            const int sz = cz + dz;
            if (sx < 0 || sz < 0 || sx >= field->width || sz >= field->height) {
              continue;
            }
            const float weight = BrushWeightAt(weightBrush, static_cast<float>(sx) - gx, static_cast<float>(sz) - gz);
            if (weight <= 0.02f) {
              continue;
            }
            const std::uint32_t colour =
              (static_cast<std::uint32_t>(40.0f + 200.0f * std::min(weight, 1.0f)) << 24) | 0x0040E0FFu;
            const float fx = static_cast<float>(sx);
            const float fz = static_cast<float>(sz);
            dots.push_back(groundVertex(fx - half, fz - half, colour, 0.5f));
            dots.push_back(groundVertex(fx + half, fz - half, colour, 0.5f));
            dots.push_back(groundVertex(fx + half, fz + half, colour, 0.5f));
            dots.push_back(groundVertex(fx - half, fz + half, colour, 0.5f));
          }
        }
        if (!dots.empty()) {
          batcher->DrawQuads(dots.data(), static_cast<std::uint32_t>(dots.size() / 4));
        }
      }
    }

    // The mesh terrain's wires (Mesh terrain panel), a little above their own heights.
    if (mMeshWireShown && !mMeshWire.empty()) {
      for (std::size_t i = 0; i + 1 < mMeshWire.size(); i += 2) {
        moho::CD3DPrimBatcher::Vertex a{};
        moho::CD3DPrimBatcher::Vertex b{};
        a.mX = mMeshWire[i][0];
        a.mY = mMeshWire[i][1] + 0.2f;
        a.mZ = mMeshWire[i][2];
        b.mX = mMeshWire[i + 1][0];
        b.mY = mMeshWire[i + 1][1] + 0.2f;
        b.mZ = mMeshWire[i + 1][2];
        a.mColor = b.mColor = 0xA0FFD060u;
        batcher->DrawLine(a, b);
      }
    }
    // The Units tool: every placed unit's footprint (green) and skirt (blue) (FAF Studio's placer outlines), and the
    // line being dragged.
    if (mTools->UnitsToolActive()) {
      if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
        for (const UnitRef& ref : mUnitRefs) {
          moho::RResId id{};
          id.name.assign(ref.type.c_str());
          const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(id);
          if (bp == nullptr) {
            continue;
          }
          const float x = ref.position.x;
          const float z = ref.position.z;
          const float fx = static_cast<float>(bp->mFootprint.mSizeX) * 0.5f;
          const float fz = static_cast<float>(bp->mFootprint.mSizeZ) * 0.5f;
          const auto rect = [&](const float x0, const float z0, const float x1, const float z1, const std::uint32_t c) {
            batcher->DrawLine(groundVertex(x0, z0, c, 0.4f), groundVertex(x1, z0, c, 0.4f));
            batcher->DrawLine(groundVertex(x1, z0, c, 0.4f), groundVertex(x1, z1, c, 0.4f));
            batcher->DrawLine(groundVertex(x1, z1, c, 0.4f), groundVertex(x0, z1, c, 0.4f));
            batcher->DrawLine(groundVertex(x0, z1, c, 0.4f), groundVertex(x0, z0, c, 0.4f));
          };
          rect(x - fx, z - fz, x + fx, z + fz, 0x9060E060u);
          if (bp->Physics.SkirtSizeX > 0.0f && bp->Physics.SkirtSizeZ > 0.0f) {
            const float sx0 = x - fx + bp->Physics.SkirtOffsetX;
            const float sz0 = z - fz + bp->Physics.SkirtOffsetZ;
            rect(sx0, sz0, sx0 + bp->Physics.SkirtSizeX, sz0 + bp->Physics.SkirtSizeZ, 0x9060A0FFu);
          }
        }
      }
      if (float lx = 0.0f, lz = 0.0f; mUnitLining && CursorGround(lx, lz)) {
        batcher->DrawLine(
          groundVertex(mUnitLineFrom[0], mUnitLineFrom[1], 0xF0FFFFFFu, 0.8f), groundVertex(lx, lz, 0xF0FFFFFFu, 0.8f)
        );
      }
    }
    // The Units tool's fit (FAF Studio's ghost): the picked unit's footprint at the cursor, green where it fits by
    // the game's rules, red where it doesn't.
    if (mTools->UnitsToolActive()) {
      float gx = 0.0f;
      float gz = 0.0f;
      if (CursorGround(gx, gz)) {
        int sizeX = 1;
        int sizeZ = 1;
        const std::string problem = UnitFitAt(mTools->UnitType(), gx, gz, sizeX, sizeZ);
        const float x0 = (sizeX > 1 ? SnapFootprint(gx, sizeX) : gx) - sizeX * 0.5f;
        const float z0 = (sizeZ > 1 ? SnapFootprint(gz, sizeZ) : gz) - sizeZ * 0.5f;
        const std::uint32_t colour = problem.empty() ? 0xE040E060u : 0xE0FF4040u;
        const float corners[5][2] = {{x0, z0}, {x0 + sizeX, z0}, {x0 + sizeX, z0 + sizeZ}, {x0, z0 + sizeZ}, {x0, z0}};
        for (int e = 0; e < 4; ++e) {
          batcher->DrawLine(
            groundVertex(corners[e][0], corners[e][1], colour, 0.6f),
            groundVertex(corners[e + 1][0], corners[e + 1][1], colour, 0.6f)
          );
        }
        mTools->SetUnitFitNote(problem);
      }
    }
    // Under every Mass and Hydrocarbon marker shown, the extractor's or the plant's footprint (solid) and skirt
    // (faint) (FAF Studio's resource footprints): red when the game's build rules refuse it there, orange when another
    // resource stands in it, yellow when it isn't on the build grid.
    if (mResourceFrames++ % 30 == 0) {
      mResourceProblems.clear();
      for (const ResourceFit& fit : ResourceFits("ueb1103", "ueb1102")) {
        if (!fit.problem.empty()) {
          mResourceProblems[fit.marker] = fit.problem;
        }
      }
    }
    for (const ResourceMark& mark : ResourceMarks()) {
      static constexpr std::uint32_t kStateColour[4] = {0u, 0xF0FF4040u, 0xF0FFA030u, 0xF0FFE040u};
      const std::uint32_t colour = mark.state != 0 ? kStateColour[mark.state] : mark.mass ? 0xC060E060u : 0xC060C0E0u;
      const auto rect = [&](const float (&r)[4], const std::uint32_t c) {
        batcher->DrawLine(groundVertex(r[0], r[1], c, 0.3f), groundVertex(r[2], r[1], c, 0.3f));
        batcher->DrawLine(groundVertex(r[2], r[1], c, 0.3f), groundVertex(r[2], r[3], c, 0.3f));
        batcher->DrawLine(groundVertex(r[2], r[3], c, 0.3f), groundVertex(r[0], r[3], c, 0.3f));
        batcher->DrawLine(groundVertex(r[0], r[3], c, 0.3f), groundVertex(r[0], r[1], c, 0.3f));
      };
      rect(mark.footprint, colour);
      if (mark.skirt[2] > mark.skirt[0]) {
        rect(mark.skirt, (colour & 0x00FFFFFFu) | 0x70000000u);
      }
    }
    // The map's areas (the save's AREA_n), outlined in teal with their names' corner post.
    if (mTools->MarkersToolActive()) {
      for (const SaveEntry& area : mDocument.SaveData().Areas()) {
        const std::vector<double> edges = ValueNumbers(area.Get("rectangle"));
        if (edges.size() < 4) {
          continue;
        }
        const float ax0 = static_cast<float>(edges[0]);
        const float az0 = static_cast<float>(edges[1]);
        const float ax1 = static_cast<float>(edges[2]);
        const float az1 = static_cast<float>(edges[3]);
        const std::vector<std::string>& picked = mTools->AreaSelection();
        const bool isPicked = std::find(picked.begin(), picked.end(), area.name) != picked.end();
        const std::uint32_t kArea = isPicked ? 0xF0FFD060u : 0xD040D0C0u;
        if (isPicked) {
          // The handles: corners and the edges' middles, a square each a size that reads at any distance.
          const float r = std::max(0.8f, mDistance / 220.0f);
          const float hx[3] = {ax0, (ax0 + ax1) * 0.5f, ax1};
          const float hz[3] = {az0, (az0 + az1) * 0.5f, az1};
          for (int i = 0; i < 3; ++i) {
            for (int j = 0; j < 3; ++j) {
              if (i == 1 && j == 1) {
                continue;
              }
              const float cx = hx[i];
              const float cz = hz[j];
              batcher->DrawLine(groundVertex(cx - r, cz - r, kArea, 1.0f), groundVertex(cx + r, cz - r, kArea, 1.0f));
              batcher->DrawLine(groundVertex(cx + r, cz - r, kArea, 1.0f), groundVertex(cx + r, cz + r, kArea, 1.0f));
              batcher->DrawLine(groundVertex(cx + r, cz + r, kArea, 1.0f), groundVertex(cx - r, cz + r, kArea, 1.0f));
              batcher->DrawLine(groundVertex(cx - r, cz + r, kArea, 1.0f), groundVertex(cx - r, cz - r, kArea, 1.0f));
            }
          }
        }
        const auto edge = [&](const float fx, const float fz, const float tx, const float tz) {
          const int steps = std::max(2, static_cast<int>(std::hypot(tx - fx, tz - fz) / 4.0f));
          for (int s = 0; s < steps; ++s) {
            const float t0 = static_cast<float>(s) / steps;
            const float t1 = static_cast<float>(s + 1) / steps;
            batcher->DrawLine(
              groundVertex(fx + (tx - fx) * t0, fz + (tz - fz) * t0, kArea, 0.9f),
              groundVertex(fx + (tx - fx) * t1, fz + (tz - fz) * t1, kArea, 0.9f)
            );
          }
        };
        edge(ax0, az0, ax1, az0);
        edge(ax1, az0, ax1, az1);
        edge(ax1, az1, ax0, az1);
        edge(ax0, az1, ax0, az0);
      }
    }
    // Resource splats under the markers, then the markers: all of them with the Markers tool, the start positions
    // and resources otherwise.
    DrawWaterBodyGuides(*batcher, *field);
    DrawResourceSplats(*batcher, *field);
    DrawMarkers(*batcher, mTools->MarkersToolActive() || mTools->SelectToolActive());
    // An adaptive map: each resource tied to an army, a dashed line to that army's start (FAForeverMapEditor draws the
    // same).
    if (mDocument.Adaptive() && (mTools->MarkersToolActive() || mTools->SelectToolActive())) {
      if (mAdaptiveText != mDocument.TablesText()) {
        mAdaptiveText = mDocument.TablesText();
        if (!ParseAdaptiveTables(mAdaptiveText, mAdaptive)) {
          mAdaptive = AdaptiveTables{};
        }
      }
      const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
      const auto position = [&](const std::string& name, float& x, float& z) {
        for (const SaveEntry& marker : markers) {
          float y = 0.0f;
          if (marker.name == name && !MarkerHidden(marker) && ShownMarkerPosition(marker, x, y, z)) {
            return true;
          }
        }
        return false;
      };
      constexpr std::uint32_t kTie = 0xC0FFA040u;
      for (const auto* const byArmy : {&mAdaptive.mexArmy, &mAdaptive.hydroArmy}) {
        for (std::size_t a = 0; a < byArmy->size(); ++a) {
          float sx = 0.0f, sz = 0.0f;
          if (!position("ARMY_" + std::to_string(a + 1), sx, sz)) {
            continue;
          }
          for (const std::string& name : (*byArmy)[a]) {
            float x = 0.0f, z = 0.0f;
            if (!position(name, x, z)) {
              continue;
            }
            const int dashes = std::clamp(static_cast<int>(std::hypot(x - sx, z - sz) / 2.0f), 1, 200);
            for (int d = 0; d < dashes; d += 2) {
              const float t0 = static_cast<float>(d) / dashes;
              const float t1 = static_cast<float>(d + 1) / dashes;
              batcher->DrawLine(
                groundVertex(x + (sx - x) * t0, z + (sz - z) * t0, kTie, 1.0f),
                groundVertex(x + (sx - x) * t1, z + (sz - z) * t1, kTie, 1.0f)
              );
            }
          }
        }
      }
    }

    // The selected props are outlined (UpdatePropHighlight); the ones past the outline cap, or while the props aren't
    // shown, get a ring in yellow.
    if (!mSelection.empty() && mMap->mProps != nullptr) {
      constexpr std::uint32_t kSelectedColor = 0xF0FFE040u;
      for (std::size_t i = mProps.empty() ? 0 : kMaxOutlinedProps; i < mSelection.size(); ++i) {
        const int index = mSelection[i];
        if (index < 0 || static_cast<std::size_t>(index) >= mMap->mProps->mEntries.size()) {
          continue;
        }
        const Wm3::Vec3f& p = mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_;
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(
            groundVertex(p.x + std::cos(a0) * 2.0f, p.z + std::sin(a0) * 2.0f, kSelectedColor),
            groundVertex(p.x + std::cos(a1) * 2.0f, p.z + std::sin(a1) * 2.0f, kSelectedColor)
          );
        }
      }
    }
    if (mTools->DecalsToolActive() || (mTools->SelectToolActive() && !mDecalSelection.empty())) {
      DrawDecalOutlines(*batcher, *field);
    }
    // The selected units, ringed in yellow.
    if (mTools->UnitsToolActive() || mTools->SelectToolActive()) {
      for (const auto& [army, name] : mUnitSelection) {
        const int index = UnitRefIndex(army, name);
        if (index < 0) {
          continue;
        }
        const Wm3::Vec3f& p = mUnitRefs[static_cast<std::size_t>(index)].position;
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(
            groundVertex(p.x + std::cos(a0) * 1.5f, p.z + std::sin(a0) * 1.5f, 0xF0FFE040u),
            groundVertex(p.x + std::cos(a1) * 1.5f, p.z + std::sin(a1) * 1.5f, 0xF0FFE040u)
          );
        }
        // Its range rings (FAF Studio's unitrings.lua): weapons, vision, radar.
        if (mTools->ShowRangeRings()) {
          const UnitRings& rings = RingsOf(mUnitRefs[static_cast<std::size_t>(index)].type);
          const std::pair<float, std::uint32_t> circles[] = {
            {rings.weaponMax, 0xD0FF4040u},
            {rings.weaponMin, 0xC0FF9A30u},
            {rings.vision, 0x9040FF60u},
            {rings.radar, 0x904890FFu}
          };
          for (const auto& [radius, colour] : circles) {
            if (radius <= 0.5f) {
              continue;
            }
            const int segments = std::clamp(static_cast<int>(radius * 0.8f), 32, 160);
            for (int s = 0; s < segments; ++s) {
              const float a0 = 2.0f * kPi * static_cast<float>(s) / static_cast<float>(segments);
              const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / static_cast<float>(segments);
              batcher->DrawLine(
                groundVertex(p.x + std::cos(a0) * radius, p.z + std::sin(a0) * radius, colour),
                groundVertex(p.x + std::cos(a1) * radius, p.z + std::sin(a1) * radius, colour)
              );
            }
          }
        }
      }
    }
    // The slope view: each cell rated by the sim's rule (EdSlopeRules: a unit footprint's steps, a structure's area or
    // its levelled skirt's ring) and coloured green to red up to the limit, darker red beyond; rebuilt when the heights
    // or the rule change. Flat cells are left out.
    // The heights view uses the same bands and drawing: each cell's height instead of its slope.
    const auto slopeStarted = std::chrono::steady_clock::now();
    const bool heightsView = mTools->ShowHeights() && !mTools->ShowSlope();
    if (mTools->ShowSlope() || heightsView) {
      const EdTools::SlopeView& rule = mTools->SlopeSettings();
      const std::uint64_t key = (heightsView ? (std::uint64_t{1} << 48) : 0U) |
        (static_cast<std::uint64_t>(rule.Kind()) << 40) | (static_cast<std::uint64_t>(rule.Window()) << 32) |
        static_cast<std::uint32_t>(std::lround(rule.Limit() * 1000.0f));
      if (mSlopeSteps.empty() || key != mSlopeKey || ++mSlopeFrames % 15 == 0) {
        std::uint64_t hash = 1469598103934665603ULL ^ key;
        const std::size_t count = static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
        for (std::size_t i = 0; i < count; i += 7) {
          hash = (hash ^ field->data[i]) * 1099511628211ULL;
        }
        if (hash != mSlopeHeights || mSlopeSteps.empty()) {
          mSlopeHeights = hash;
          mSlopeKey = key;
          const auto started = std::chrono::steady_clock::now();
          const int cellsX = field->width - 1;
          const int cellsZ = field->height - 1;
          const auto sample = [field](const int x, const int z) {
            const int cx = std::clamp(x, 0, field->width - 1);
            const int cz = std::clamp(z, 0, field->height - 1);
            return static_cast<int>(
              field->data
                [static_cast<std::size_t>(cz) * static_cast<std::size_t>(field->width) + static_cast<std::size_t>(cx)]
            );
          };
          std::vector<std::uint8_t> steps(static_cast<std::size_t>(cellsX) * static_cast<std::size_t>(cellsZ), 0);
          std::size_t beyond = 0;
          if (heightsView) {
            // Band 1 the sea's ground, 2 .. 13 the land from its lowest to its highest (a cell's mean of its corners).
            const WaterState water = mDocument.WaterNow();
            const int sea = water.enabled ? static_cast<int>(std::lround(water.elevation * 128.0f)) : -1;
            int lo = 65535;
            int hi = 0;
            const std::size_t samples =
              static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
            for (std::size_t i = 0; i < samples; ++i) {
              const int h = static_cast<int>(field->data[i]);
              if (h > sea) {
                lo = std::min(lo, h);
                hi = std::max(hi, h);
              }
            }
            const float span = static_cast<float>(std::max(1, hi - lo));
            for (int z = 0; z < cellsZ; ++z) {
              for (int x = 0; x < cellsX; ++x) {
                const int mean = (sample(x, z) + sample(x + 1, z) + sample(x, z + 1) + sample(x + 1, z + 1)) / 4;
                const int band = mean <= sea
                  ? 1
                  : 2 + std::clamp(static_cast<int>(static_cast<float>(mean - lo) / span * 12.0f), 0, 11);
                steps[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)] =
                  static_cast<std::uint8_t>(band);
                beyond += band == 1 ? 1U : 0U;
              }
            }
          } else {
            std::vector<std::uint16_t> tile(static_cast<std::size_t>(sloperules::kTile) * sloperules::kTile);
            for (int tz = 0; tz * sloperules::kTile < cellsZ; ++tz) {
              for (int tx = 0; tx * sloperules::kTile < cellsX; ++tx) {
                sloperules::RateTile(
                  rule.Kind(), rule.Window(), tx * sloperules::kTile, tz * sloperules::kTile, sample, tile.data()
                );
                for (int j = 0; j < sloperules::kTile; ++j) {
                  const int z = tz * sloperules::kTile + j;
                  if (z >= cellsZ) {
                    break;
                  }
                  for (int i = 0; i < sloperules::kTile; ++i) {
                    const int x = tx * sloperules::kTile + i;
                    if (x >= cellsX) {
                      break;
                    }
                    const float units =
                      static_cast<float>(tile[static_cast<std::size_t>(j) * sloperules::kTile + i]) / 128.0f;
                    const int step = sloperules::ColorStep(units, rule.Limit());
                    steps
                      [static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)] =
                        static_cast<std::uint8_t>(step);
                    beyond += step > sloperules::kSteps ? 1U : 0U;
                  }
                }
              }
            }
          }
          mSlopeSteps = std::move(steps);
          mSlopeCellsX = cellsX;
          mSlopeCellsZ = cellsZ;
          mSlopeQuadsFor = 0; // the drawing is rebuilt below
          gpg::Logf(
            "editor: slope view (%s, %d x %d, up to %.2f) rated in %.2f s: %.1f %% of the cells beyond the limit",
            rule.Kind() == 0     ? "units"
              : rule.Kind() == 2 ? "levelled skirt"
                                 : "whole area",
            rule.Window(),
            rule.Window(),
            static_cast<double>(rule.Limit()),
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(),
            100.0 * static_cast<double>(beyond) / std::max<double>(1.0, static_cast<double>(mSlopeSteps.size()))
          );
        }
      }
      // The ground the view shows (the corners' box; the whole map when sky shows) sets the block size: about 256
      // blocks across it, kept until the view needs a quarter more or would fit at the next finer size (so zooming
      // doesn't flip it back and forth). A block shows its steepest cell, so a thin cliff never disappears.
      const EdTools::ViewFrame& frame = mTools->View();
      float vx0 = 0.0f;
      float vz0 = 0.0f;
      float vx1 = static_cast<float>(mSlopeCellsX);
      float vz1 = static_cast<float>(mSlopeCellsZ);
      if (frame.valid && frame.corners == 4) {
        vx0 = std::min({frame.cornerX[0], frame.cornerX[1], frame.cornerX[2], frame.cornerX[3]});
        vx1 = std::max({frame.cornerX[0], frame.cornerX[1], frame.cornerX[2], frame.cornerX[3]});
        vz0 = std::min({frame.cornerZ[0], frame.cornerZ[1], frame.cornerZ[2], frame.cornerZ[3]});
        vz1 = std::max({frame.cornerZ[0], frame.cornerZ[1], frame.cornerZ[2], frame.cornerZ[3]});
      }
      const float span = std::max(
        1.0f,
        std::max(
          std::min(vx1, static_cast<float>(mSlopeCellsX)) - std::max(vx0, 0.0f),
          std::min(vz1, static_cast<float>(mSlopeCellsZ)) - std::max(vz0, 0.0f)
        )
      );
      int block = mSlopeBlock < 1 ? 1 : mSlopeBlock;
      while (block < 16 && span / static_cast<float>(block) > 320.0f) {
        block *= 2;
      }
      while (block > 1 && span / static_cast<float>(block / 2) <= 200.0f) {
        block /= 2;
      }
      // Green to yellow to red up to the limit (ARGB), darker red beyond it: bands 1 (flat) .. 6, 7 beyond.
      const auto colourOf = [heightsView](const int band) -> std::uint32_t {
        if (heightsView) {
          // The sea's ground blue; the land green, yellow, brown, then pale at the top.
          if (band <= 1) {
            return 0xA02F6FB8u;
          }
          static constexpr float kStops[4][3] = {{60, 150, 70}, {210, 200, 90}, {150, 110, 70}, {240, 240, 240}};
          const float t = static_cast<float>(band - 2) / 11.0f * 3.0f;
          const int i = std::min(2, static_cast<int>(t));
          const float f = t - static_cast<float>(i);
          const auto mix = [&](const int c) {
            return static_cast<std::uint32_t>(kStops[i][c] + (kStops[i + 1][c] - kStops[i][c]) * f);
          };
          return 0x9C000000u | (mix(0) << 16) | (mix(1) << 8) | mix(2);
        }
        if (band >= 7) {
          return 0xB0D02828u;
        }
        const float t = static_cast<float>(band - 1) / 5.0f;
        const float r = t < 0.5f ? 70.0f + (235.0f - 70.0f) * t * 2.0f : 235.0f;
        const float g =
          t < 0.5f ? 200.0f + (215.0f - 200.0f) * t * 2.0f : 215.0f - (215.0f - 110.0f) * (t - 0.5f) * 2.0f;
        const float a = 70.0f + 70.0f * t;
        return (static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(r) << 16) |
          (static_cast<std::uint32_t>(g) << 8) | 50u;
      };
      // The quads, by block row: built once per rating and block size; flat blocks too (the lightest band), so no
      // holes.
      if (!mSlopeSteps.empty() && (mSlopeQuadsFor != mSlopeHeights || block != mSlopeBlock)) {
        mSlopeBlock = block;
        const int bw = (mSlopeCellsX + block - 1) / block;
        const int bh = (mSlopeCellsZ + block - 1) / block;
        std::vector<std::uint8_t> bands(static_cast<std::size_t>(bw) * static_cast<std::size_t>(bh), 1);
        for (int z = 0; z < mSlopeCellsZ; ++z) {
          for (int x = 0; x < mSlopeCellsX; ++x) {
            const int step = mSlopeSteps
              [static_cast<std::size_t>(z) * static_cast<std::size_t>(mSlopeCellsX) + static_cast<std::size_t>(x)];
            const int band = heightsView ? step : step > sloperules::kSteps ? 7 : 1 + step * 5 / sloperules::kSteps;
            std::uint8_t& cell = bands
              [static_cast<std::size_t>(z / block) * static_cast<std::size_t>(bw) +
               static_cast<std::size_t>(x / block)];
            cell = static_cast<std::uint8_t>(std::max<int>(cell, band));
          }
        }
        mSlopeRuns = TerrainTypeRuns(bands.data(), bw, bh, 0);
        mSlopeRows.assign(static_cast<std::size_t>(bh), {});
        const float piece = std::max(8.0f, 4.0f * static_cast<float>(block));
        for (const TerrainTypeRun& run : mSlopeRuns) {
          AddGroundRun(
            mSlopeRows[static_cast<std::size_t>(run.z)],
            groundVertex,
            run,
            colourOf(run.code),
            static_cast<float>(block),
            piece
          );
        }
        mSlopeQuadsFor = mSlopeHeights;
      }
      // Only the rows and pieces over the visible ground; while the camera and the drawing hold still, last frame's
      // list.
      const float pad = static_cast<float>(mSlopeBlock) * 2.0f;
      const int row0 = std::max(0, static_cast<int>((vz0 - pad) / static_cast<float>(mSlopeBlock)));
      const int row1 = std::min(
        static_cast<int>(mSlopeRows.size()) - 1, static_cast<int>((vz1 + pad) / static_cast<float>(mSlopeBlock))
      );
      const std::array<float, 4> visible{vx0, vz0, vx1, vz1};
      const bool same =
        visible == mSlopeVisible && mSlopeVisibleFor == mSlopeQuadsFor && mSlopeVisibleBlock == mSlopeBlock;
      mSlopeVisible = visible;
      mSlopeVisibleFor = mSlopeQuadsFor;
      mSlopeVisibleBlock = mSlopeBlock;
      if (!same) {
        mSlopeQuads.clear();
      }
      for (int row = same ? row1 + 1 : row0; row <= row1; ++row) {
        const std::vector<moho::CD3DPrimBatcher::Vertex>& quads = mSlopeRows[static_cast<std::size_t>(row)];
        for (std::size_t q = 0; q + 3 < quads.size(); q += 4) {
          if (quads[q + 1].mX >= vx0 - pad && quads[q].mX <= vx1 + pad) {
            mSlopeQuads.insert(
              mSlopeQuads.end(),
              quads.begin() + static_cast<std::ptrdiff_t>(q),
              quads.begin() + static_cast<std::ptrdiff_t>(q + 4)
            );
          }
        }
      }
      if (!mSlopeQuads.empty()) {
        batcher->DrawQuads(mSlopeQuads.data(), static_cast<std::uint32_t>(mSlopeQuads.size() / 4));
      }
      // What the view costs: once, after 300 frames, its average time a frame and what it drew.
      mSlopeSeconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - slopeStarted).count();
      if (++mSlopeDrawn == 300) {
        gpg::Logf(
          "editor: slope view drawing: %.2f ms a frame (300 frames), %zu quads, blocks of %d cells, %zu runs",
          mSlopeSeconds / 300.0 * 1000.0,
          mSlopeQuads.size() / 4,
          mSlopeBlock,
          mSlopeRuns.size()
        );
      }
    } else if (!mSlopeSteps.empty()) {
      mSlopeSteps.clear();
      mSlopeRuns.clear();
      mSlopeRows.clear();
      mSlopeQuads.clear();
      mSlopeQuadsFor = 0;
    }
    // The km grid (lines every 51.2 units) and the map's centre lines, along the ground.
    if (mTools->ShowKmGrid()) {
      const float mapW = static_cast<float>(field->width - 1);
      const float mapH = static_cast<float>(field->height - 1);
      const auto line = [&](const float ax, const float az, const float bx, const float bz, const std::uint32_t color) {
        const float length = std::hypot(bx - ax, bz - az);
        const int steps = std::max(1, static_cast<int>(length / 4.0f));
        for (int s = 0; s < steps; ++s) {
          const float t0 = static_cast<float>(s) / static_cast<float>(steps);
          const float t1 = static_cast<float>(s + 1) / static_cast<float>(steps);
          batcher->DrawLine(
            groundVertex(ax + (bx - ax) * t0, az + (bz - az) * t0, color, 0.6f),
            groundVertex(ax + (bx - ax) * t1, az + (bz - az) * t1, color, 0.6f)
          );
        }
      };
      for (float x = kUnitsPerKm; x < mapW; x += kUnitsPerKm) {
        line(x, 0.0f, x, mapH, 0x90FFFFFFu);
      }
      for (float z = kUnitsPerKm; z < mapH; z += kUnitsPerKm) {
        line(0.0f, z, mapW, z, 0x90FFFFFFu);
      }
      line(mapW * 0.5f, 0.0f, mapW * 0.5f, mapH, 0xE040C0FFu);
      line(0.0f, mapH * 0.5f, mapW, mapH * 0.5f, 0xE040C0FFu);
    }
    // The mask generator's mask on the terrain: a red cross on each cell where it is, as strong as it is.
    if (mOverlayMask.w > 1 && mOverlayMask.h > 1) {
      const float span = static_cast<float>(std::max(field->width, field->height) - 1);
      const float step = std::max(4.0f, span / 64.0f);
      for (float z = step * 0.5f; z < static_cast<float>(field->height - 1); z += step) {
        for (float x = step * 0.5f; x < static_cast<float>(field->width - 1); x += step) {
          const float v = std::clamp(field::SampleWorld(mOverlayMask, x, z), 0.0f, 1.0f);
          if (v < 0.05f) {
            continue;
          }
          const auto alpha = static_cast<std::uint32_t>(60.0f + 195.0f * v);
          const std::uint32_t colour = (alpha << 24) | 0x00FF3030u;
          const float r = step * 0.35f;
          batcher->DrawLine(groundVertex(x - r, z - r, colour, 0.5f), groundVertex(x + r, z + r, colour, 0.5f));
          batcher->DrawLine(groundVertex(x - r, z + r, colour, 0.5f), groundVertex(x + r, z - r, colour, 0.5f));
        }
      }
    }
    // The chains: a line through each one's markers in order, and a small post at its first. The current chain (the
    // selected marker's, else the one the Markers tool names) is yellow with a ring on each member (FAF Studio's
    // chain view); "Selected chain only" draws just that one, with any tool.
    if (mTools->MarkersToolActive() || mTools->ChainOnly()) {
      std::string current = mTools->ChainName();
      if (!mMarkerSelection.empty()) {
        for (const MarkerChain& chain : mDocument.SaveData().Chains()) {
          if (std::find(chain.markers.begin(), chain.markers.end(), mMarkerSelection.front()) != chain.markers.end()) {
            current = chain.name;
            break;
          }
        }
        if (current != mTools->ChainName() && mTools->MarkersToolActive()) {
          mTools->SetChainName(current); // Draw a chain goes on with the selected marker's chain
        }
      }
      for (const MarkerChain& chain : mDocument.SaveData().Chains()) {
        const bool isCurrent = chain.name == current;
        if (mTools->ChainOnly() && !isCurrent) {
          continue;
        }
        const std::uint32_t chainColour = isCurrent ? 0xFFFFE040u : 0xFFFF50D0u;
        bool havePrevious = false;
        moho::CD3DPrimBatcher::Vertex previous{};
        for (std::size_t i = 0; i < chain.markers.size(); ++i) {
          const auto found = std::find_if(
            mDocument.SaveData().Markers().begin(), mDocument.SaveData().Markers().end(), [&](const SaveEntry& marker) {
            return marker.name == chain.markers[i];
          }
          );
          float x = 0.0f, y = 0.0f, z = 0.0f;
          if (found == mDocument.SaveData().Markers().end() || !ShownMarkerPosition(*found, x, y, z)) {
            continue;
          }
          // Pink (the current one yellow), doubled a little above: apart from the path nodes' blue, green and white.
          moho::CD3DPrimBatcher::Vertex vertex = groundVertex(x, z, chainColour, 2.0f);
          if (isCurrent) {
            constexpr int kRing = 12;
            for (int r = 0; r < kRing; ++r) {
              const float a0 = 6.2831853f * static_cast<float>(r) / kRing;
              const float a1 = 6.2831853f * static_cast<float>(r + 1) / kRing;
              batcher->DrawLine(
                groundVertex(x + 3.0f * std::cos(a0), z + 3.0f * std::sin(a0), chainColour, 1.0f),
                groundVertex(x + 3.0f * std::cos(a1), z + 3.0f * std::sin(a1), chainColour, 1.0f)
              );
            }
          }
          if (havePrevious) {
            batcher->DrawLine(previous, vertex);
            moho::CD3DPrimBatcher::Vertex from = previous;
            moho::CD3DPrimBatcher::Vertex to = vertex;
            from.mY += 0.6f;
            to.mY += 0.6f;
            batcher->DrawLine(from, to);
          } else {
            moho::CD3DPrimBatcher::Vertex top = vertex;
            top.mY += 8.0f;
            batcher->DrawLine(vertex, top);
          }
          previous = vertex;
          havePrevious = true;
        }
      }
    }
    // Box select: the rectangle's edges where they meet the ground.
    if (mBoxing) {
      constexpr std::uint32_t kBox = 0xF0FFFFFFu;
      const POINT corners[5] = {mBoxFrom, {mBoxTo.x, mBoxFrom.y}, mBoxTo, {mBoxFrom.x, mBoxTo.y}, mBoxFrom};
      for (int edge = 0; edge < 4; ++edge) {
        constexpr int kSamples = 32;
        bool havePrevious = false;
        moho::CD3DPrimBatcher::Vertex previous{};
        for (int s = 0; s <= kSamples; ++s) {
          const float t = static_cast<float>(s) / static_cast<float>(kSamples);
          const float sx =
            static_cast<float>(corners[edge].x) + static_cast<float>(corners[edge + 1].x - corners[edge].x) * t;
          const float sy =
            static_cast<float>(corners[edge].y) + static_cast<float>(corners[edge + 1].y - corners[edge].y) * t;
          float gx = 0.0f;
          float gz = 0.0f;
          if (!GroundAt(sx, sy, gx, gz)) {
            havePrevious = false;
            continue;
          }
          const moho::CD3DPrimBatcher::Vertex vertex = groundVertex(gx, gz, kBox, 0.8f);
          if (havePrevious) {
            batcher->DrawLine(previous, vertex);
          }
          previous = vertex;
          havePrevious = true;
        }
      }
    }
    // The ruler: a line on the ground between its ends, with posts at them.
    if (mRulerShown) {
      constexpr std::uint32_t kRuler = 0xF0FFDC60u;
      for (const std::array<float, 4>& seg : mRulerDone) {
        const float segLength = std::hypot(seg[2] - seg[0], seg[3] - seg[1]);
        const int segSteps = std::max(1, static_cast<int>(segLength / 2.0f));
        for (int s = 0; s < segSteps; ++s) {
          const float t0 = static_cast<float>(s) / static_cast<float>(segSteps);
          const float t1 = static_cast<float>(s + 1) / static_cast<float>(segSteps);
          batcher->DrawLine(
            groundVertex(seg[0] + (seg[2] - seg[0]) * t0, seg[1] + (seg[3] - seg[1]) * t0, kRuler, 0.8f),
            groundVertex(seg[0] + (seg[2] - seg[0]) * t1, seg[1] + (seg[3] - seg[1]) * t1, kRuler, 0.8f)
          );
        }
        moho::CD3DPrimBatcher::Vertex bottom = groundVertex(seg[0], seg[1], kRuler, 0.0f);
        moho::CD3DPrimBatcher::Vertex top = bottom;
        top.mY += 6.0f;
        batcher->DrawLine(bottom, top);
      }
      const float length = std::hypot(mRulerTo[0] - mRulerFrom[0], mRulerTo[1] - mRulerFrom[1]);
      const int steps = std::max(1, static_cast<int>(length / 2.0f));
      for (int s = 0; s < steps; ++s) {
        const float t0 = static_cast<float>(s) / static_cast<float>(steps);
        const float t1 = static_cast<float>(s + 1) / static_cast<float>(steps);
        batcher->DrawLine(
          groundVertex(
            mRulerFrom[0] + (mRulerTo[0] - mRulerFrom[0]) * t0,
            mRulerFrom[1] + (mRulerTo[1] - mRulerFrom[1]) * t0,
            kRuler,
            0.8f
          ),
          groundVertex(
            mRulerFrom[0] + (mRulerTo[0] - mRulerFrom[0]) * t1,
            mRulerFrom[1] + (mRulerTo[1] - mRulerFrom[1]) * t1,
            kRuler,
            0.8f
          )
        );
      }
      for (const float* const end : {mRulerFrom, mRulerTo}) {
        moho::CD3DPrimBatcher::Vertex bottom = groundVertex(end[0], end[1], kRuler, 0.0f);
        moho::CD3DPrimBatcher::Vertex top = bottom;
        top.mY += 6.0f;
        batcher->DrawLine(bottom, top);
      }
    }
    // The Water tool's wave generators: a post each and an arrow the way its waves go (the picked ones yellow).
    if (mTools->WaterToolActive()) {
      const std::vector<WaveRecord> waves = mDocument.WavesNow();
      mTools->SetWaveSelectionCount(static_cast<int>(mWaveSelection.size()));
      for (std::size_t i = 0; i < waves.size(); ++i) {
        const WaveRecord& wave = waves[i];
        const bool picked =
          std::find(mWaveSelection.begin(), mWaveSelection.end(), static_cast<int>(i)) != mWaveSelection.end();
        const std::uint32_t colour = picked ? 0xF0FFE040u : 0xC040D0FFu;
        moho::CD3DPrimBatcher::Vertex base{};
        base.mX = wave.position[0];
        base.mY = wave.position[1];
        base.mZ = wave.position[2];
        base.mColor = colour;
        moho::CD3DPrimBatcher::Vertex top = base;
        top.mY += 3.0f;
        batcher->DrawLine(base, top);
        const float speed = std::hypot(wave.velocity[0], wave.velocity[2]);
        if (speed > 1e-4f) {
          moho::CD3DPrimBatcher::Vertex tip = base;
          tip.mX += wave.velocity[0] / speed * 6.0f;
          tip.mZ += wave.velocity[2] / speed * 6.0f;
          batcher->DrawLine(base, tip);
        }
      }
    }
    // The Water tool's mask brush: the chosen mask where it isn't at its default, in bands (2 x 2 units a cell).
    if (mTools->WaterMaskPainting()) {
      int width = 0;
      int height = 0;
      const WaterMask mask = mTools->WaterMaskKind();
      const std::uint8_t* const cells = mDocument.WaterMaskCells(mask, width, height);
      if (
        cells != nullptr &&
        (mWaterMaskRunsRevision != mDocument.WaterMaskRevision() || mWaterMaskRunsKind != std::to_underlying(mask))
      ) {
        const std::vector<std::uint8_t> bands = WaterMaskBands(cells, width, height, mask);
        mWaterMaskRuns = TerrainTypeRuns(bands.data(), width, height, 0);
        mWaterMaskRunsRevision = mDocument.WaterMaskRevision();
        mWaterMaskRunsKind = std::to_underlying(mask);
      }
      // Foam white, flatness blue, depth bias amber; the higher the value, the stronger.
      const std::uint32_t tint = mask == WaterMask::Foam ? 0x00FFFFFFu
        : mask == WaterMask::Flatness                    ? 0x0050A0FFu
                                                         : 0x00FFB040u;
      std::vector<moho::CD3DPrimBatcher::Vertex> quads;
      quads.reserve(mWaterMaskRuns.size() * 8);
      for (const TerrainTypeRun& run : mWaterMaskRuns) {
        const std::uint32_t alpha = 0x30u + static_cast<std::uint32_t>(run.code) * 0x16u;
        AddGroundRun(quads, groundVertex, run, tint | (alpha << 24), 2.0f);
      }
      if (!quads.empty()) {
        batcher->DrawQuads(quads.data(), static_cast<std::uint32_t>(quads.size() / 4));
      }
    }
    // The terrain types (the Texture tool painting them): each run of cells in its type's colour, Default left out.
    if (mTools->ShowTerrainTypes()) {
      int width = 0;
      int height = 0;
      const std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
      if (cells != nullptr && mTypeRunsRevision != mDocument.TerrainTypeRevision()) {
        mTypeRuns = TerrainTypeRuns(cells, width, height);
        mTypeRunsRevision = mDocument.TerrainTypeRevision();
      }
      std::vector<moho::CD3DPrimBatcher::Vertex> quads;
      quads.reserve(mTypeRuns.size() * 8);
      for (const TerrainTypeRun& run : mTypeRuns) {
        AddGroundRun(quads, groundVertex, run, (mTools->TerrainTypeColor(run.code) & 0x00FFFFFFu) | 0x90000000u, 1.0f);
      }
      if (!quads.empty()) {
        batcher->DrawQuads(quads.data(), static_cast<std::uint32_t>(quads.size() / 4));
      }
    }
    // The Check's pathing: where the land unit can't go, and where no start reaches.
    if (mTools->ShowingPathing()) {
      std::vector<moho::CD3DPrimBatcher::Vertex> quads;
      quads.reserve(mTools->PathingQuads().size() * 4);
      for (const EdTools::PathQuad& q : mTools->PathingQuads()) {
        quads.push_back(groundVertex(q.x0, q.z0, q.color, 0.3f));
        quads.push_back(groundVertex(q.x1, q.z0, q.color, 0.3f));
        quads.push_back(groundVertex(q.x1, q.z1, q.color, 0.3f));
        quads.push_back(groundVertex(q.x0, q.z1, q.color, 0.3f));
      }
      if (!quads.empty()) {
        batcher->DrawQuads(quads.data(), static_cast<std::uint32_t>(quads.size() / 4));
      }
    }
    // The Check's findings: a ring and a post in its colour (red errors, amber warnings, blue notes).
    for (const EdTools::CheckPin& pin : mTools->CheckPins()) {
      const std::uint32_t color = pin.level == 0 ? 0xF0FF5848u : pin.level == 1 ? 0xF0FFC040u : 0xF08CB4F0u;
      const float r = std::max(3.0f, mDistance * 0.012f);
      for (int s = 0; s < 24; ++s) {
        const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
        const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
        batcher->DrawLine(
          groundVertex(pin.x + std::cos(a0) * r, pin.z + std::sin(a0) * r, color, 1.0f),
          groundVertex(pin.x + std::cos(a1) * r, pin.z + std::sin(a1) * r, color, 1.0f)
        );
      }
      moho::CD3DPrimBatcher::Vertex top = groundVertex(pin.x, pin.z, color, 0.0f);
      moho::CD3DPrimBatcher::Vertex bottom = top;
      top.mY += r * 3.0f;
      batcher->DrawLine(bottom, top);
    }
    // While a move is under way: where each moved thing started, dim, and a line to where it is now.
    {
      std::vector<std::pair<Wm3::Vec3f, Wm3::Vec3f>> moved;
      if (mModal.on) {
        // G or R: the old places and lines to the new; a locked axis drawn through the middle, the map across.
        for (std::size_t k = 0; k < mModal.start.x.size() && k < mModal.now.x.size(); ++k) {
          moved.push_back(
            {Wm3::Vec3f{mModal.start.x[k], 0.0f, mModal.start.z[k]}, Wm3::Vec3f{mModal.now.x[k], 0.0f, mModal.now.z[k]}}
          );
        }
        if (mModal.input.axis != 0 && !mModal.input.rotate) {
          const bool alongX = mModal.input.axis == 'X';
          const std::uint32_t colour = alongX ? 0xE0FF5D5Du : 0xE04FD18Bu; // the gizmo's X red, Z green
          const float extent = mMapExtent;
          const int pieces = 256;
          for (int p = 0; p < pieces; ++p) {
            const float a = -extent + 2.0f * extent * static_cast<float>(p) / pieces;
            const float b = -extent + 2.0f * extent * static_cast<float>(p + 1) / pieces;
            const float x0 = alongX ? mModal.cx + a : mModal.cx, z0 = alongX ? mModal.cz : mModal.cz + a;
            const float x1 = alongX ? mModal.cx + b : mModal.cx, z1 = alongX ? mModal.cz : mModal.cz + b;
            if (x0 < 0.0f || z0 < 0.0f || x1 > extent || z1 > extent) {
              continue;
            }
            batcher->DrawLine(groundVertex(x0, z0, colour, 0.8f), groundVertex(x1, z1, colour, 0.8f));
          }
        }
      } else if (mDragMarkers && mMarkersMoved) {
        for (std::size_t i = 0; i < mMarkerSelection.size() && i < mMarkerDragStart.size(); ++i) {
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (marker.name == mMarkerSelection[i] && ShownMarkerPosition(marker, x, y, z)) {
              moved.push_back(
                {Wm3::Vec3f{mMarkerDragStart[i][0], mMarkerDragStart[i][1], mMarkerDragStart[i][2]},
                 Wm3::Vec3f{x, y, z}}
              );
            }
          }
        }
      } else if (mDragUnits && mUnitsMoved) {
        for (std::size_t i = 0; i < mUnitSelection.size() && i < mUnitDragStart.size(); ++i) {
          if (const int index = UnitRefIndex(mUnitSelection[i].first, mUnitSelection[i].second); index >= 0) {
            moved.push_back({mUnitDragStart[i], mUnitRefs[static_cast<std::size_t>(index)].position});
          }
        }
      } else if (mDragDecals && mDecalsMoved && mDocument.Decals() != nullptr) {
        for (std::size_t i = 0; i < mDecalSelection.size() && i < mDecalDragStart.size(); ++i) {
          if (
            const moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), mDecalSelection[i]);
            decal != nullptr
          ) {
            moved.push_back(
              {Wm3::Vec3f{mDecalDragStart[i][0], mDecalDragStart[i][1], mDecalDragStart[i][2]}, decal->mPosition}
            );
          }
        }
      } else if (mDragSelection && mObjectStroke && mMap->mProps != nullptr) {
        for (std::size_t i = 0; i < mSelection.size() && i < mDragStart.size(); ++i) {
          const Wm3::Vec3f& now = mMap->mProps->mEntries[static_cast<std::size_t>(mSelection[i])].mTransform.pos_;
          if (std::fabs(now.x - mDragStart[i].x) + std::fabs(now.z - mDragStart[i].z) > 0.01f) {
            moved.push_back({mDragStart[i], now});
          }
        }
      }
      constexpr std::uint32_t kGhost = 0x90FFFFFFu;
      for (const auto& [from, to] : moved) {
        const float r = 1.5f;
        batcher->DrawLine(
          groundVertex(from.x - r, from.z - r, kGhost, 0.6f), groundVertex(from.x + r, from.z - r, kGhost, 0.6f)
        );
        batcher->DrawLine(
          groundVertex(from.x + r, from.z - r, kGhost, 0.6f), groundVertex(from.x + r, from.z + r, kGhost, 0.6f)
        );
        batcher->DrawLine(
          groundVertex(from.x + r, from.z + r, kGhost, 0.6f), groundVertex(from.x - r, from.z + r, kGhost, 0.6f)
        );
        batcher->DrawLine(
          groundVertex(from.x - r, from.z + r, kGhost, 0.6f), groundVertex(from.x - r, from.z - r, kGhost, 0.6f)
        );
        // Dashed, start to now.
        const float length = std::hypot(to.x - from.x, to.z - from.z);
        const int dashes = std::clamp(static_cast<int>(length / 1.5f), 1, 400);
        for (int d = 0; d < dashes; d += 2) {
          const float t0 = static_cast<float>(d) / dashes;
          const float t1 = static_cast<float>(d + 1) / dashes;
          batcher->DrawLine(
            groundVertex(from.x + (to.x - from.x) * t0, from.z + (to.z - from.z) * t0, kGhost, 0.6f),
            groundVertex(from.x + (to.x - from.x) * t1, from.z + (to.z - from.z) * t1, kGhost, 0.6f)
          );
        }
      }
    }
    // `/hoverprop <index>` (test runs): the Select tool, the camera close over that prop once, and the cursor on it.
    if (
      mTestHoverProp >= 0 && mCamera != nullptr && mMap->mProps != nullptr &&
      static_cast<std::size_t>(mTestHoverProp) < mMap->mProps->mEntries.size()
    ) {
      const moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(mTestHoverProp)];
      const Wm3::Vec3f at = entry.mTransform.pos_;
      if (!mTestHoverPropFramed) {
        mTestHoverPropFramed = true;
        mTools->SetTool(0);
        if (mTestSelectHoverProp) {
          // `/propswap` too: that prop selected, alone (the Properties panel shows it).
          mMarkerSelection.clear();
          mUnitSelection.clear();
          mDecalSelection.clear();
          mSelection = {mTestHoverProp};
        }
        if (mTestSelectNearest > 0) {
          // `/selectprops <n>`: that prop and the n - 1 nearest others selected, alone.
          std::vector<std::pair<float, int>> byDistance;
          for (std::size_t i = 0; i < mMap->mProps->mEntries.size(); ++i) {
            const Wm3::Vec3f p = mMap->mProps->mEntries[i].mTransform.pos_;
            byDistance.emplace_back(std::hypot(p.x - at.x, p.z - at.z), static_cast<int>(i));
          }
          const std::size_t n = std::min(byDistance.size(), static_cast<std::size_t>(mTestSelectNearest));
          std::partial_sort(byDistance.begin(), byDistance.begin() + static_cast<std::ptrdiff_t>(n), byDistance.end());
          mMarkerSelection.clear();
          mUnitSelection.clear();
          mDecalSelection.clear();
          mSelection.clear();
          for (std::size_t i = 0; i < n; ++i) {
            mSelection.push_back(byDistance[i].second);
          }
          gpg::Logf("editor: /selectprops: %zu props selected around prop %d", n, mTestHoverProp);
        }
        mTargetX = at.x;
        mTargetZ = at.z;
        mDistance = 40.0f;
        ApplyCamera();
      }
      const Wm3::Vector2f screen = mCamera->Project(at);
      // With `/selectprops` the cursor stays clear of them, at the view's top left corner (nothing outlined for hover).
      mCursor =
        mTestSelectNearest > 0 ? POINT{20, 20} : POINT{static_cast<LONG>(screen.x), static_cast<LONG>(screen.y)};
      mCursorInView = true; // a test run's cursor, as a real one over the view
    }
    // `/hovermarker` (test runs): the cursor on that marker, as a real mouse over it would be.
    if (!mTestHover.empty() && mCamera != nullptr) {
      if (mTestHover == "near" && !mMarkerSelection.empty()) {
        // The marker nearest the selected one (on the screen with it), not itself.
        float sx = 0.0f, sy = 0.0f, sz = 0.0f;
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          if (marker.name == mMarkerSelection.front()) {
            (void)ShownMarkerPosition(marker, sx, sy, sz);
          }
        }
        float best = 1e9f;
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float x = 0.0f, y = 0.0f, z = 0.0f;
          // Clear of the selected one's gizmo (8 units), which a cursor on it would pick first.
          if (
            marker.name != mMarkerSelection.front() && ShownMarkerPosition(marker, x, y, z) &&
            std::hypot(x - sx, z - sz) > 8.0f && std::hypot(x - sx, z - sz) < best
          ) {
            best = std::hypot(x - sx, z - sz);
            mTestHover = marker.name;
          }
        }
        mMarkerSelection.clear(); // no gizmo over the view (it would take the cursor first)
      }
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (marker.name == mTestHover && ShownMarkerPosition(marker, x, y, z)) {
          const Wm3::Vector2f at = mCamera->Project(Wm3::Vec3f{x, y, z});
          mCursor = POINT{static_cast<LONG>(at.x), static_cast<LONG>(at.y)};
          mCursorInView = true;
        }
      }
      // Once, after the camera has settled: what a click there would pick (the Select tool's pick filter applies).
      if (++mTestHoverFrames == 90) {
        const PickHit hit = PickAnything(mCursor);
        const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        const char* const kinds[] = {"nothing", "prop", "marker", "unit", "decal"};
        gpg::Logf(
          "editor: /hovermarker: a click would pick %s%s%s",
          kinds[std::to_underlying(hit.kind)],
          hit.kind == PickKind::Marker ? " " : "",
          hit.kind == PickKind::Marker && hit.index >= 0 && static_cast<std::size_t>(hit.index) < markers.size()
            ? markers[static_cast<std::size_t>(hit.index)].name.c_str()
            : ""
        );
      }
    }
    // The marker under the cursor, drawn in the hover colour next frame (the Select and Markers tools).
    std::string hoverMarker;
    int hoverProp = -1;
    if (
      mTools->MarkersToolActive() && !mDragMarkers && mGizmoDrag == GizmoPart::None &&
      PickGizmo(mCursor) == GizmoPart::None
    ) {
      float mx = 0.0f;
      float mz = 0.0f;
      if (CursorGround(mx, mz)) {
        const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        const int hit = PickMarker(mx, mz);
        if (hit >= 0 && static_cast<std::size_t>(hit) < markers.size()) {
          hoverMarker = markers[static_cast<std::size_t>(hit)].name;
        }
      }
    }
    // The Select tool: a ring around what a click would pick (Blender's hover highlight); a marker shows its own helper
    // lit.
    if (
      mTools->SelectToolActive() && !mDragMarkers && !mDragUnits && !mDragDecals && !mDragSelection &&
      mGizmoDrag == GizmoPart::None && PickGizmo(mCursor) == GizmoPart::None
    ) {
      float hx = 0.0f;
      float hz = 0.0f;
      float radius = 0.0f;
      const PickHit hover = PickAnything(mCursor);
      constexpr std::uint32_t kHover = 0xE0FFFFFFu;
      // A prop: its own shape lit over it (UpdatePropHighlight, made next frame outside the draw), no ring.
      hoverProp = hover.kind == PickKind::Prop ? hover.index : -1;
      const moho::CWldTerrainDecal* const hoverDecal = hover.kind == PickKind::Decal && mDocument.Decals() != nullptr
        ? FindDecal(*mDocument.Decals(), hover.index)
        : nullptr;
      if (hover.kind == PickKind::Marker) {
        // A marker: its own helper drawn in the hover colour (DrawMarkers), no ring round it (user ask 2026-11-11).
        const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        if (hover.index >= 0 && static_cast<std::size_t>(hover.index) < markers.size()) {
          hoverMarker = markers[static_cast<std::size_t>(hover.index)].name;
        }
      } else if (hoverDecal != nullptr) {
        // A decal: its own outline, along the ground.
        float cx[4], cz[4];
        DecalCorners(FootprintOf(*hoverDecal), cx, cz);
        for (int side = 0; side < 4; ++side) {
          const int next = (side + 1) % 4;
          const int steps =
            std::clamp(static_cast<int>(std::hypot(cx[next] - cx[side], cz[next] - cz[side]) / 2.0f), 1, 64);
          for (int s = 0; s < steps; ++s) {
            const float t0 = static_cast<float>(s) / steps;
            const float t1 = static_cast<float>(s + 1) / steps;
            batcher->DrawLine(
              groundVertex(cx[side] + (cx[next] - cx[side]) * t0, cz[side] + (cz[next] - cz[side]) * t0, kHover, 0.8f),
              groundVertex(cx[side] + (cx[next] - cx[side]) * t1, cz[side] + (cz[next] - cz[side]) * t1, kHover, 0.8f)
            );
          }
        }
      } else if (hover.kind != PickKind::Prop && PickPlace(hover, hx, hz, radius)) {
        for (int s = 0; s < 32; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 32.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 32.0f;
          batcher->DrawLine(
            groundVertex(hx + std::cos(a0) * radius, hz + std::sin(a0) * radius, kHover, 0.8f),
            groundVertex(hx + std::cos(a1) * radius, hz + std::sin(a1) * radius, kHover, 0.8f)
          );
        }
      }
    }
    if (hoverMarker != mHoverMarker && !hoverMarker.empty() && !mTestHover.empty()) {
      gpg::Logf("editor: /hovermarker: the cursor is over marker %s", hoverMarker.c_str());
    }
    mHoverMarker = std::move(hoverMarker);
    mHoverPropWanted = hoverProp;
    // The play's selected units (in front of a play): a red ring each, and where a drag puts them.
    {
      std::vector<EdTools::ViewRing> live;
      for (const std::uint32_t id : mLiveSelection) {
        for (const LiveUnit& unit : mLiveNow) {
          if (unit.id == id) {
            live.push_back({unit.x, unit.z, 3.0f, 0xF0FF5040u});
            if (mDragLive) {
              live.push_back({unit.x + mLiveToX - mLiveFromX, unit.z + mLiveToZ - mLiveFromZ, 3.0f, 0x90FFFFFFu});
            }
          }
        }
      }
      for (const EdTools::ViewRing& ring : live) {
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(
            groundVertex(ring.x + std::cos(a0) * ring.radius, ring.z + std::sin(a0) * ring.radius, ring.colour, 1.0f),
            groundVertex(ring.x + std::cos(a1) * ring.radius, ring.z + std::sin(a1) * ring.radius, ring.colour, 1.0f)
          );
        }
      }
    }
    // Rings a panel asks for (a choice's markers or units under the mouse in the Adaptive Map window): two circles
    // each.
    for (const EdTools::ViewRing& ring : mTools->ViewRings()) {
      for (const float r : {ring.radius, ring.radius * 0.8f}) {
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(
            groundVertex(ring.x + std::cos(a0) * r, ring.z + std::sin(a0) * r, ring.colour, 1.0f),
            groundVertex(ring.x + std::cos(a1) * r, ring.z + std::sin(a1) * r, ring.colour, 1.0f)
          );
        }
      }
    }
    DrawGizmo(*batcher);
    // The kept paths (whatever the tool): their curves, reach and points while the Paths panel is up.
    if (mPathEdit != nullptr) {
      DrawKeptPaths(*batcher, *field);
    }
    DrawUnitPreview(*batcher);
    DrawMeshTerrain(*batcher);
    if (!mTools->TerrainToolActive() && !mTools->TextureToolActive() && !mTools->PropsToolActive()) {
      batcher->Flush();
      return;
    }

    // Plane mode: the picked points as small posts, and the triangle between them.
    if (brush.mode == HeightBrushMode::Plane) {
      float px[3], ph[3], pz[3];
      const int points = mTools->PlanePoints(px, ph, pz);
      constexpr std::uint32_t kPlaneColor = 0xF0FFD24Au;
      for (int i = 0; i < points; ++i) {
        moho::CD3DPrimBatcher::Vertex bottom = groundVertex(px[i], pz[i], kPlaneColor, 0.0f);
        moho::CD3DPrimBatcher::Vertex top = bottom;
        top.mY += 6.0f;
        batcher->DrawLine(bottom, top);
        if (i > 0 || points == 3) {
          const int j = i > 0 ? i - 1 : 2;
          batcher->DrawLine(
            groundVertex(px[j], pz[j], kPlaneColor, 1.0f), groundVertex(px[i], pz[i], kPlaneColor, 1.0f)
          );
        }
      }
    }

    // Path: the clicked points as posts and the curve through them. Ramp: the drag from its start to the cursor.
    if (brush.mode == HeightBrushMode::Path || mRampDrag) {
      std::vector<TerrainPathPoint> points =
        brush.mode == HeightBrushMode::Path ? mTools->PathPoints() : std::vector<TerrainPathPoint>{};
      float cx = 0.0f;
      float cz = 0.0f;
      if (mRampDrag && CursorGround(cx, cz)) {
        points = {mRampFrom, {cx, cz, 0.0f}};
      }
      constexpr std::uint32_t kPathColor = 0xF04AD2FFu;
      for (const TerrainPathPoint& point : points) {
        moho::CD3DPrimBatcher::Vertex bottom = groundVertex(point.x, point.z, kPathColor, 0.0f);
        moho::CD3DPrimBatcher::Vertex top = bottom;
        top.mY += 6.0f;
        batcher->DrawLine(bottom, top);
      }
      const PathOptions options = mTools->CurrentPathOptions();
      const std::vector<TerrainPathPoint> curve = SamplePath(points, options.closed && !mRampDrag, 2.0f);
      for (std::size_t i = 1; i < curve.size(); ++i) {
        batcher->DrawLine(
          groundVertex(curve[i - 1].x, curve[i - 1].z, kPathColor, 1.0f),
          groundVertex(curve[i].x, curve[i].z, kPathColor, 1.0f)
        );
      }
    }

    // The Texture tool: the paint layer's weight, green over the ground where it is full.
    if (mTools->TextureToolActive() && mTools->ShowLayerWeight() && !mDocument.Masks().texels.empty()) {
      if (mWeightStale || mWeightLayer != mTools->MaskLayer()) {
        BuildWeightQuads(mTools->MaskLayer());
      }
      if (!mWeightQuads.empty()) {
        batcher->DrawQuads(mWeightQuads.data(), static_cast<std::uint32_t>(mWeightQuads.size() / 4));
      }
    }

    // The symmetry check's differing vertices, as red blocks on the ground.
    if (mCheckDone && mTools->ShowDifferences() && mTools->CheckIsCurrent()) {
      constexpr std::uint32_t kDifferenceColor = 0x90FF3030u;
      for (const SampleRect& block : mDifferences) {
        const float x0 = static_cast<float>(block.x0);
        const float z0 = static_cast<float>(block.z0);
        const float x1 = static_cast<float>(block.x1);
        const float z1 = static_cast<float>(block.z1);
        batcher->DrawQuad(
          groundVertex(x0, z0, kDifferenceColor, 0.3f),
          groundVertex(x1, z0, kDifferenceColor, 0.3f),
          groundVertex(x1, z1, kDifferenceColor, 0.3f),
          groundVertex(x0, z1, kDifferenceColor, 0.3f)
        );
      }
    }

    float groundX = 0.0f;
    float groundZ = 0.0f;
    if (!CursorGround(groundX, groundZ)) {
      batcher->Flush();
      return;
    }
    float centreX[kMaxSymmetryCopies];
    float centreZ[kMaxSymmetryCopies];
    const int centres =
      HeightBrushCentres(field->width, field->height, groundX, groundZ, brush.symmetry, brush.turns, centreX, centreZ);
    constexpr int kSegments = 64;
    const float inner = brush.radius * (1.0f - std::clamp(brush.falloff, 0.0f, 1.0f));
    for (int c = 0; c < centres; ++c) {
      // The cursor's copy in white, the mirrored ones in the panel's orange; the inner ring where falloff starts.
      const std::uint32_t outerColor = c == 0 ? 0xF0FFFFFFu : 0xE0FF9A3Cu;
      const std::uint32_t innerColor = c == 0 ? 0x90FFFFFFu : 0x80FF9A3Cu;
      for (int ring = 0; ring < (inner > 0.5f ? 2 : 1); ++ring) {
        const float radius = ring == 0 ? brush.radius : inner;
        const std::uint32_t color = ring == 0 ? outerColor : innerColor;
        for (int s = 0; s < kSegments; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / kSegments;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / kSegments;
          batcher->DrawLine(
            groundVertex(centreX[c] + std::cos(a0) * radius, centreZ[c] + std::sin(a0) * radius, color),
            groundVertex(centreX[c] + std::cos(a1) * radius, centreZ[c] + std::sin(a1) * radius, color)
          );
        }
      }
    }
    batcher->Flush();
  }

  void EdMapScene::Attach(
    moho::CWldMap& map
  )
  {
    if (
      moho::ren_Viewport == nullptr || map.mTerrainRes == nullptr || map.mTerrainRes->mMap == nullptr ||
      mDocument.Lua() == nullptr
    ) {
      return;
    }
    // The map first: the world view's terrain renderer is made over `REN_GetTerrainRes()` (AddWorldView).
    moho::REN_SetWldMap(&map);
    const moho::STIMap& terrain = *map.mTerrainRes->mMap;
    // The camera publishes a script object, so it needs a Lua state: the document's, which outlives it
    // (the document calls Detach before it drops its map and state).
    mCamera = moho::CAM_GetManager()->CreateCamera("Map editor camera", terrain, mDocument.Lua());
    const Wm3::AxisAlignedBox3f bounds = terrain.GetBounds3D();
    mMapExtent = std::max(bounds.Max.x - bounds.Min.x, bounds.Max.z - bounds.Min.z);
    mMap = &map;
    mWidth = 0;
    mHeight = 0;
    // The same map again (the editor's view back in front of a play, or the play over): the camera where it was left
    // (user ask 2026-11-11); another map starts framed whole.
    if (mCameraKept && mCameraKeptFor == mDocument.Path()) {
      ApplyCamera();
      gpg::Logf(
        "editor: the editor's camera as it was left: at %.1f,%.1f, %.1f away",
        static_cast<double>(mTargetX),
        static_cast<double>(mTargetZ),
        static_cast<double>(mDistance)
      );
    } else {
      FrameWholeMap();
    }
    mWorldView = std::make_unique<EdMainView>(const_cast<moho::GeomCamera3*>(&mCamera->CameraGetView()), *this);
    moho::ren_Viewport->AddWorldView(mWorldView.get(), 0, 0);
    if (mRingHook == nullptr) {
      mRingHook = std::make_unique<RingHook>(*this);
    }
    moho::ED_SetHook(mRingHook.get());
    gpg::Logf("editor: the viewport shows %s", mDocument.Path().c_str());
    // The symmetry the map was made with, from its heights, for the brushes and the object tools.
    if (mTools != nullptr) {
      const DetectedSymmetry& found = mDocument.Facts().symmetry;
      const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
      const float middleX = field != nullptr ? 0.5f * static_cast<float>(field->width - 1) : found.centreX;
      const float middleZ = field != nullptr ? 0.5f * static_cast<float>(field->height - 1) : found.centreZ;
      mTools->SetDetectedSymmetry(found, found.centreX - middleX, found.centreZ - middleZ);
      gpg::Logf(
        "editor: symmetry found: mode %d (%d turns), %.1f%% of points, %d starts and %d resource markers fit, centre "
        "%.1f,%.1f (middle %.1f,%.1f)",
        std::to_underlying(found.symmetry),
        found.turns,
        static_cast<double>(found.matched) * 100.0,
        found.startsMatched,
        found.resourcesMatched,
        static_cast<double>(found.centreX),
        static_cast<double>(found.centreZ),
        static_cast<double>(middleX),
        static_cast<double>(middleZ)
      );
    }
  }

  void EdMapScene::Detach()
  {
    if (mMap == nullptr) {
      return;
    }
    // The camera (mTargetX/Z, mHeading, mPitch, mDistance) stays for this map's next Attach.
    mCameraKept = true;
    mCameraKeptFor = mDocument.Path();
    // A stroke in progress ends here, so undo has it whole.
    EndStroke();
    EndMaskStroke();
    EndTypeStroke();
    EndObjectStroke();
    mSelection.clear();
    // The props first: their blueprints are the kept rules', which the next play takes.
    DeleteProps();
    moho::ED_SetHook(nullptr);
    // In front of a play: the session's world views and interface drawn again, its units shown as the game has them.
    if (mOverPlay) {
      moho::gViewportOnlyView = nullptr;
      moho::ren_Ui = mUiWas;
      SetLiveUnitsHidden(false);
      (void)LiveUnits();
      mLiveNow.clear();
      mLiveSelection.clear();
      mDragLive = false;
      if (mTools != nullptr) {
        mTools->SetLiveSelection({});
      }
      gpg::Logf("editor: the game's view again");
    }
    DropMiniMap();
    if (moho::ren_Viewport != nullptr && mWorldView != nullptr) {
      moho::ren_Viewport->RemoveWorldView(mWorldView.get());
    }
    if (moho::sWldMap == mMap) {
      moho::REN_SetWldMap(mOverPlay ? mSessionMap : nullptr); // the play's map back, if one runs behind
    }
    mOverPlay = false;
    mSessionMap = nullptr;
    mDocument.SetLiveMap(nullptr);
    mWorldView.reset();
    // ~CameraImpl takes the camera out of the camera manager (as RenderPreviewImage relies on).
    delete mCamera;
    mCamera = nullptr;
    mMap = nullptr;
    mDrag = Drag::None;
    mPainting = false;
    mErosionStroke.reset();
    mWaterBodiesStale = true;
    mWaterBodyHandle = -2;
  }

  void EdMapScene::PaintStroke(
    const float frameSeconds
  )
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || !CursorGround(groundX, groundZ)) {
      return;
    }
    HeightBrush brush = mTools->CurrentHeightBrush();
    brush.flattenTo = mFlattenTo;
    brush.seed = ++mWaterErodeSeed; // Water erode: new droplets every step
    brush.noiseSeed = mNoiseSeed;   // Noise: one pattern for the stroke
    // A right-button stroke does the opposite: Raise lowers, Lower raises, Water erode deposits.
    if (mPaintInverted) {
      brush.mode = InvertedHeightMode(brush.mode);
    }
    if (brush.mode == HeightBrushMode::Ramp || brush.mode == HeightBrushMode::Path) {
      return; // (they act on the mouse's release and the panel's Apply)
    }
    // The erosion brushes keep the map as floats for the whole stroke (ground moves in fractions of a word).
    if (IsErosionMode(brush.mode) && mErosionStroke == nullptr) {
      mErosionStroke = MakeErosionStroke();
    }
    // Stamps go down per dab along the stroke (one per click without a spacing).
    if (brush.mode == HeightBrushMode::Stamp) {
      if (brush.stamp == nullptr) {
        return;
      }
      if (const std::vector<SampleRect> rects = PaintStamps(brush, groundX, groundZ); !rects.empty()) {
        mDocument.SetModified(true);
        RefreshHeights(rects);
      }
      return;
    }
    // The airbrush off: dabs a third of the radius apart along the mouse's way, each a fixed step's worth.
    if (!mTools->Airbrush() && !IsErosionMode(brush.mode) && brush.mode != HeightBrushMode::WaterErode) {
      const float spacing = std::max(1.0f, brush.radius / 3.0f);
      if (!mDabbed) {
        mDabbed = true;
        mDabTravelled = spacing; // the first point is a dab
        mDabLastX = groundX;
        mDabLastZ = groundZ;
      }
      const std::vector<StampDab> dabs = StampDabsAlong(mDabLastX, mDabLastZ, groundX, groundZ, spacing, mDabTravelled);
      mDabLastX = groundX;
      mDabLastZ = groundZ;
      std::vector<SampleRect> written;
      for (const StampDab& dab : dabs) {
        for (const SampleRect& rect : HeightBrushRects(field->width, field->height, dab.x, dab.z, brush)) {
          mDocument.Heights().BeforeWrite(field->data, rect);
        }
        const std::vector<SampleRect> rects =
          ApplyHeightBrush(field->data, field->width, field->height, dab.x, dab.z, brush, 0.05f);
        written.insert(written.end(), rects.begin(), rects.end());
      }
      if (!written.empty()) {
        mDocument.SetModified(true);
        RefreshHeights(written);
      }
      return;
    }
    // Undo keeps the tiles this step writes, as they are, before it writes them.
    for (const SampleRect& rect : HeightBrushRects(field->width, field->height, groundX, groundZ, brush)) {
      mDocument.Heights().BeforeWrite(field->data, rect);
    }
    const std::vector<SampleRect> rects = ApplyHeightBrush(
      field->data,
      field->width,
      field->height,
      groundX,
      groundZ,
      brush,
      std::min(frameSeconds, 0.1f),
      IsErosionMode(brush.mode) ? mErosionStroke.get() : nullptr
    );
    if (!rects.empty()) {
      mDocument.SetModified(true);
      RefreshHeights(rects);
    }
  }

  const EdMapScene::UnitRings& EdMapScene::RingsOf(
    const std::string& type
  )
  {
    if (const auto found = mUnitRings.find(type); found != mUnitRings.end()) {
      return found->second;
    }
    UnitRings rings;
    if (moho::RRuleGameRules* const rules = Rules(); rules != nullptr) {
      moho::RResId id{};
      id.name.assign(type.c_str());
      if (const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(id); blueprint != nullptr) {
        rings.vision = static_cast<float>(blueprint->Intel.VisionRadius);
        rings.radar = static_cast<float>(blueprint->Intel.RadarRadius);
        rings.weaponMin = 1.0e9f;
        for (const moho::RUnitBlueprintWeapon& weapon : blueprint->Weapons.WeaponBlueprints) {
          if (weapon.DummyWeapon != 0U || weapon.MaxRadius <= 0.0f) {
            continue;
          }
          rings.weaponMax = std::max(rings.weaponMax, weapon.MaxRadius);
          if (weapon.MinRadius > 0.0f) {
            rings.weaponMin = std::min(rings.weaponMin, weapon.MinRadius);
          }
        }
        if (rings.weaponMin >= 1.0e9f) {
          rings.weaponMin = 0.0f;
        }
      }
    }
    return mUnitRings.emplace(type, rings).first->second;
  }

  int EdMapScene::GiveSelectedUnits(
    const std::string& army
  )
  {
    if (army.empty() || mUnitSelection.empty()) {
      return 0;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<std::pair<std::string, std::string>> given;
    for (const auto& [from, name] : mUnitSelection) {
      if (from == army) {
        given.emplace_back(from, name);
        continue;
      }
      SaveUnit unit;
      bool found = false;
      (void)EditArmyUnits(from, [&](UnitGroup& group) {
        if (const SaveUnit* const u = FindUnit(group, name); u != nullptr) {
          unit = *u;
          found = RemoveUnit(group, name);
        }
      });
      if (found && EditArmyUnits(army, [&](UnitGroup& group) {
        AddUnit(group, unit);
      })) {
        given.emplace_back(army, name);
      }
    }
    const int moved = static_cast<int>(std::count_if(given.begin(), given.end(), [&](const auto& g) {
      return g.first == army;
    }));
    if (moved > 0) {
      mDocument.SaveDataEdited(std::move(before));
      ReloadUnits();
      mUnitSelection = std::move(given);
      gpg::Logf("editor: %d units given to %s", moved, army.c_str());
    }
    return moved;
  }

  int EdMapScene::MirrorSelection()
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return 0;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    // A place's copies and each copy's heading (the copies of a point a unit ahead), copy 0 the original.
    struct Copy
    {
      float x;
      float z;
      float heading;
      int index; // which copy of the symmetry (1..n-1)
    };
    const auto copiesOf = [&](const float x, const float z, const float heading) {
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies], ax[kMaxSymmetryCopies], az[kMaxSymmetryCopies];
      const int n = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      (void)HeightBrushCentres(
        field->width, field->height, x + std::cos(heading), z + std::sin(heading), brush.symmetry, brush.turns, ax, az
      );
      std::vector<Copy> out;
      for (int c = 1; c < n; ++c) {
        if (
          cx[c] >= 0.0f && cz[c] >= 0.0f && cx[c] <= static_cast<float>(field->width - 1) &&
          cz[c] <= static_cast<float>(field->height - 1)
        ) {
          out.push_back({cx[c], cz[c], std::atan2(az[c] - cz[c], ax[c] - cx[c]), c});
        }
      }
      return out;
    };
    const auto ground = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    int made = 0;
    // Markers and units: the save file.
    if (!mMarkerSelection.empty() || !mUnitSelection.empty()) {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      int changed = 0;
      std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
      const std::vector<std::string> selectedMarkers = mMarkerSelection;
      for (const std::string& name : selectedMarkers) {
        const auto found = std::find_if(markers.begin(), markers.end(), [&](const SaveEntry& m) {
          return m.name == name;
        });
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (found == markers.end() || !ShownMarkerPosition(*found, x, y, z)) {
          continue;
        }
        const SaveEntry original = *found;
        const MarkerType* const type = FindMarkerType(MarkerTypeOf(original));
        if (type == nullptr || std::string(type->type) == "Blank Marker") {
          continue; // (a start position is an army: placed on its own)
        }
        for (const Copy& copy : copiesOf(x, z, 0.0f)) {
          SaveEntry marker = original;
          marker.name = NextMarkerName(markers, *type);
          marker.Set("position", Vector3Value(copy.x, ground(copy.x, copy.z), copy.z));
          if (!marker.Get("adjacentTo").empty()) {
            marker.Set("adjacentTo", StringValue(""));
          }
          markers.push_back(std::move(marker));
          ++changed;
        }
      }
      int highest = 0;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup group;
        if (ParseUnitGroup(entry.Get("Units"), group)) {
          highest = std::max(highest, HighestUnitNumber(group));
        }
      }
      // The army of each copy (FAF Studio's ArmyMode 'map'): the start position nearest the copy of the army's start.
      const auto armyImage = [&](const std::string& army, const int index) {
        if (!mMirrorMapArmies) {
          return army;
        }
        float sx = 0.0f, sy = 0.0f, sz = 0.0f;
        bool have = false;
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          if (marker.name == army && MarkerPosition(marker, sx, sy, sz)) {
            have = true;
            break;
          }
        }
        if (!have) {
          return army;
        }
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        const int n = HeightBrushCentres(field->width, field->height, sx, sz, brush.symmetry, brush.turns, cx, cz);
        if (index <= 0 || index >= n) {
          return army;
        }
        std::string best = army;
        float bestDistance = 12.0f;
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float mx = 0.0f, my = 0.0f, mz = 0.0f;
          if (MarkerTypeOf(marker) == "Blank Marker" && MarkerPosition(marker, mx, my, mz)) {
            const float d = std::hypot(mx - cx[index], mz - cz[index]);
            if (d < bestDistance) {
              bestDistance = d;
              best = marker.name;
            }
          }
        }
        return best;
      };
      for (const auto& [army, name] : std::vector<std::pair<std::string, std::string>>(mUnitSelection)) {
        SaveUnit unit;
        bool found = false;
        (void)EditArmyUnits(army, [&](UnitGroup& group) {
          if (const SaveUnit* const u = FindUnit(group, name); u != nullptr) {
            unit = *u;
            found = true;
          }
        });
        if (!found) {
          continue;
        }
        for (const Copy& copy : copiesOf(unit.position[0], unit.position[2], unit.orientation[1])) {
          SaveUnit mirrored = unit;
          mirrored.name = "UNIT_" + std::to_string(++highest);
          mirrored.position[0] = copy.x;
          mirrored.position[2] = copy.z;
          mirrored.position[1] = UnitRestHeight(copy.x, copy.z);
          mirrored.orientation[1] = copy.heading;
          if (EditArmyUnits(armyImage(army, copy.index), [&](UnitGroup& group) {
            AddUnit(group, mirrored);
          })) {
            ++changed;
          }
        }
      }
      if (changed > 0) {
        mDocument.SaveDataEdited(std::move(before));
        ReloadUnits();
        mOutsideStale = true;
        made += changed;
      }
    }
    // Props.
    if (!mSelection.empty() && mMap->mProps != nullptr) {
      EdDocument::PropSnapshot before = mDocument.PropsNow();
      const auto& records = mDocument.FileRecords().props;
      const std::vector<int> selected = mSelection;
      int changed = 0;
      for (const int index : selected) {
        if (index < 0 || static_cast<std::size_t>(index) >= mMap->mProps->mEntries.size()) {
          continue;
        }
        const moho::CWldPropEntry source = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
        const PropRecord record = static_cast<std::size_t>(index) < records.size()
          ? records[static_cast<std::size_t>(index)]
          : PropRecordFor(source.mBlueprintPath.c_str(), source.mTransform);
        const Wm3::Quatf& q = source.mTransform.orient_;
        const float heading = 2.0f * std::atan2(q.y, q.w); // a prop turned about the up axis only
        for (const Copy& copy : copiesOf(source.mTransform.pos_.x, source.mTransform.pos_.z, heading)) {
          moho::CWldPropEntry entry = source;
          entry.mTransform.pos_ = Wm3::Vec3f{copy.x, ground(copy.x, copy.z), copy.z};
          entry.mTransform.orient_ =
            Wm3::Quatf(std::cos(copy.heading * 0.5f), 0.0f, std::sin(copy.heading * 0.5f), 0.0f);
          PropRecord mirrored = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
          mirrored.values[12] = record.values[12];
          mirrored.values[13] = record.values[13];
          mirrored.values[14] = record.values[14];
          entry.mTransform = mirrored.loaded;
          mDocument.AddProp(entry, mirrored);
          mProps.push_back(MakePropInstance(entry));
          ++changed;
        }
      }
      if (changed > 0) {
        mDocument.PropsEdited(std::move(before));
        mDocument.SetModified(true);
        made += changed;
      }
    }
    // Decals.
    if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr && !mDecalSelection.empty()) {
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      int changed = 0;
      for (const int index : std::vector<int>(mDecalSelection)) {
        const moho::CWldTerrainDecal* const decal = FindDecal(*decals, index);
        if (decal == nullptr) {
          continue;
        }
        const DecalState source = CaptureDecal(*decal);
        for (const Copy& copy : copiesOf(source.position[0], source.position[2], source.orientation[1])) {
          DecalState state = source;
          state.index = -1;
          state.position[0] = copy.x;
          state.position[1] = ground(copy.x, copy.z);
          state.position[2] = copy.z;
          state.orientation[1] = copy.heading;
          if (AddDecal(*decals, state) != nullptr) {
            ++changed;
          }
        }
      }
      if (changed > 0) {
        mDocument.DecalsEdited(std::move(before));
        made += changed;
      }
    }
    gpg::Logf("editor: the selection mirrored: %d copies", made);
    return made;
  }

  std::string EdMapScene::TestPath(
    const std::string& spec
  )
  {
    if (mMap == nullptr || mTools == nullptr) {
      return "no map";
    }
    std::vector<std::string> parts;
    for (std::size_t at = 0; at <= spec.size();) {
      const std::size_t comma = std::min(spec.find(',', at), spec.size());
      parts.push_back(spec.substr(at, comma - at));
      at = comma + 1;
    }
    PathOptions options = mTools->CurrentPathOptions();
    static const char* const kModes[] = {"carve", "raise", "level", "ramp", "river"};
    for (int m = 0; m < kPathModeCount; ++m) {
      if (!parts.empty() && parts[0] == kModes[m]) {
        options.mode = static_cast<PathMode>(m);
      }
    }
    std::vector<TerrainPathPoint> points;
    for (std::size_t i = 1; i + 1 < parts.size(); i += 2) {
      const float x = static_cast<float>(std::atof(parts[i].c_str()));
      const float z = static_cast<float>(std::atof(parts[i + 1].c_str()));
      points.push_back(
        {x,
         z,
         mMap->mTerrainRes->GetHeightAt(
           static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
         )}
      );
    }
    return ApplyPathNow(points, options);
  }

  int EdMapScene::PickWave(
    const float x,
    const float z
  ) const
  {
    int best = -1;
    float bestDistance = 6.0f;
    const std::vector<WaveRecord> waves = mDocument.WavesNow();
    for (std::size_t i = 0; i < waves.size(); ++i) {
      const float d = std::hypot(waves[i].position[0] - x, waves[i].position[2] - z);
      if (d < bestDistance) {
        bestDistance = d;
        best = static_cast<int>(i);
      }
    }
    return best;
  }

  std::string EdMapScene::ApplyPathNow(
    const std::vector<TerrainPathPoint>& points,
    const PathOptions& options
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || points.size() < 2 || mPainting) {
      return "A path needs two points or more.";
    }
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, PathRect(field->width, field->height, points, options));
    const SampleRect rect = ApplyTerrainPath(field->data, field->width, field->height, points, options);
    const std::size_t before = mDocument.Heights().UndoCount();
    mDocument.Heights().EndStroke(field->data);
    if (mDocument.Heights().UndoCount() == before || rect.x1 < rect.x0) {
      return "The path changed nothing.";
    }
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    mDocument.SetModified(true);
    RefreshHeights({rect});
    HeightChange change;
    mDocument.Heights().ForEachNewest([&change](const std::uint16_t was, const std::uint16_t now) {
      AddHeightChange(change, was, now);
    });
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%s through %zu points, %.0f wide: %zu samples, %.0f taken away, %.0f put down",
      PathModeName(options.mode),
      points.size(),
      static_cast<double>(options.width),
      change.samples,
      change.removed,
      change.added
    );
    gpg::Logf("editor: %s", text);
    return text;
  }

  std::vector<SampleRect> EdMapScene::PaintStamps(
    const HeightBrush& brush,
    const float x,
    const float z
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return {};
    }
    const EdTools::StampStroke settings = mTools->CurrentStampStroke();
    // Dabs `spacing` of the stamp's width apart, in samples (at least one).
    const float spacing = settings.spacing > 0.0f ? std::max(1.0f, 2.0f * brush.radius * settings.spacing) : 0.0f;
    if (!mStamped) {
      mStamped = true;
      mStampTravelled = std::max(spacing, 1.0f); // the first point is a dab
      mStampLastX = x;
      mStampLastZ = z;
      mStampBaseSet = false;
      mStampRandom.seed(++mStampStrokes);
    }
    const std::vector<StampDab> dabs = StampDabsAlong(mStampLastX, mStampLastZ, x, z, spacing, mStampTravelled);
    mStampLastX = x;
    mStampLastZ = z;
    std::uniform_real_distribution<float> unit(0.0f, 1.0f);
    std::vector<SampleRect> written;
    for (const StampDab& at : dabs) {
      HeightBrush dab = brush;
      dab.stampTurn = settings.turn + (settings.randomTurn ? unit(mStampRandom) * 360.0f : 0.0f);
      if (settings.sizeJitter > 0.0f) {
        dab.radius *= 1.0f + (unit(mStampRandom) * 2.0f - 1.0f) * settings.sizeJitter;
      }
      float dx = at.x;
      float dz = at.z;
      if (settings.placeJitter > 0.0f) {
        const float angle = unit(mStampRandom) * 6.2831853f;
        const float reach = brush.radius * settings.placeJitter * std::sqrt(unit(mStampRandom));
        dx += std::cos(angle) * reach;
        dz += std::sin(angle) * reach;
      }
      // Max, Min and Replace measure from the ground under the dab (or the stroke's first dab).
      const float here =
        static_cast<float>(field->data
                             [static_cast<std::size_t>(std::clamp(static_cast<int>(dz), 0, field->height - 1)) *
                                static_cast<std::size_t>(field->width) +
                              static_cast<std::size_t>(std::clamp(static_cast<int>(dx), 0, field->width - 1))]);
      if (!mStampBaseSet) {
        mStampBase = here;
        mStampBaseSet = true;
      }
      dab.stampBase = settings.baseFromStroke ? mStampBase : here;
      for (const SampleRect& rect : HeightBrushRects(field->width, field->height, dx, dz, dab)) {
        mDocument.Heights().BeforeWrite(field->data, rect);
      }
      const std::vector<SampleRect> rects =
        ApplyHeightBrush(field->data, field->width, field->height, dx, dz, dab, 0.1f);
      written.insert(written.end(), rects.begin(), rects.end());
    }
    return written;
  }

  void EdMapScene::EndStroke()
  {
    // The ground under the cursor before and after, so a log shows which way a stroke went.
    if (mMap != nullptr && mDocument.Heights().Stroking()) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (CursorGround(groundX, groundZ)) {
        const float now = mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(groundX)), static_cast<std::int32_t>(std::lround(groundZ))
        );
        gpg::Logf(
          "editor: height stroke%s: %.2f to %.2f under the cursor",
          mPaintInverted ? " (right button, inverted)" : "",
          static_cast<double>(mStrokeStartHeight),
          static_cast<double>(now)
        );
      }
    }
    if (mMap != nullptr && mDocument.Heights().Stroking()) {
      if (const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField()) {
        const std::size_t before = mDocument.Heights().UndoCount();
        mDocument.Heights().EndStroke(field->data);
        if (mDocument.Heights().UndoCount() > before) {
          mDocument.EditEnded(EdDocument::EditKind::Heights);
          gpg::Logf("editor: height stroke changed %zu samples", mDocument.Heights().NewestChangedSamples());
          // What the stroke did to the ground (the erosion brushes move it; the panel shows how much).
          HeightChange change;
          mDocument.Heights().ForEachNewest([&change](const std::uint16_t was, const std::uint16_t now) {
            AddHeightChange(change, was, now);
          });
          char stats[200];
          (void)std::snprintf(
            stats,
            sizeof(stats),
            "Last stroke: %zu samples; %.0f taken away, %.0f put down (net %+.0f cubic units); deepest %.1f, highest "
            "%+.1f",
            change.samples,
            change.removed,
            change.added,
            change.added - change.removed,
            static_cast<double>(change.deepest),
            static_cast<double>(change.highest)
          );
          gpg::Logf("editor: %s", stats);
          if (mTools != nullptr) {
            mTools->SetStrokeStats(stats);
          }
        }
        // A check that was made is kept up to date as the map changes.
        if (mCheckDone) {
          RunSymmetryCheck();
        }
      }
    }
    mErosionStroke.reset();
    if (mPainting) {
      ++mNoiseSeed;
    }
    mPainting = false;
  }

  bool EdMapScene::Undo()
  {
    EdDocument::EditKind kind{};
    if (mMap == nullptr || mPainting || mPaintingMask || mObjectStroke || !mDocument.PopUndo(kind)) {
      return false;
    }
    const bool done = kind == EdDocument::EditKind::Masks ? UndoMasks(false)
      : kind == EdDocument::EditKind::Layers              ? UndoLayers(false)
      : kind == EdDocument::EditKind::Props               ? UndoProps(false)
      : kind == EdDocument::EditKind::SaveData            ? UndoSaveData(false)
      : kind == EdDocument::EditKind::Decals              ? UndoDecals(false)
      : kind == EdDocument::EditKind::Water               ? UndoWater(false)
      : kind == EdDocument::EditKind::Lighting            ? UndoLighting(false)
      : kind == EdDocument::EditKind::Skybox              ? UndoSkybox(false)
      : kind == EdDocument::EditKind::Waves               ? UndoWaves(false)
      : kind == EdDocument::EditKind::TerrainTypes        ? UndoTerrainTypes(false)
      : kind == EdDocument::EditKind::LayerConversion     ? UndoConversion(false)
      : kind == EdDocument::EditKind::Look                ? UndoLook(false)
      : kind == EdDocument::EditKind::WaterMasks          ? UndoWaterMasks(false)
      : kind == EdDocument::EditKind::HeightsAndMasks     ? UndoHeightsAndMasks(false)
      : kind == EdDocument::EditKind::GraphBuild          ? UndoGraphBuild(false)
      : kind == EdDocument::EditKind::Layout              ? mDocument.UndoLayout(false)
      : kind == EdDocument::EditKind::Mission             ? mDocument.UndoMission(false)
      : kind == EdDocument::EditKind::MapInfo             ? mDocument.UndoMapInfo(false)
      : kind == EdDocument::EditKind::Paths               ? mDocument.UndoPaths(false)
                                                          : UndoHeights(false);
    if (done) {
      mDocument.PushRedo(kind);
    }
    return done;
  }

  bool EdMapScene::Redo()
  {
    EdDocument::EditKind kind{};
    if (mMap == nullptr || mPainting || mPaintingMask || mObjectStroke || !mDocument.PopRedo(kind)) {
      return false;
    }
    const bool done = kind == EdDocument::EditKind::Masks ? UndoMasks(true)
      : kind == EdDocument::EditKind::Layers              ? UndoLayers(true)
      : kind == EdDocument::EditKind::Props               ? UndoProps(true)
      : kind == EdDocument::EditKind::SaveData            ? UndoSaveData(true)
      : kind == EdDocument::EditKind::Decals              ? UndoDecals(true)
      : kind == EdDocument::EditKind::Water               ? UndoWater(true)
      : kind == EdDocument::EditKind::Lighting            ? UndoLighting(true)
      : kind == EdDocument::EditKind::Skybox              ? UndoSkybox(true)
      : kind == EdDocument::EditKind::Waves               ? UndoWaves(true)
      : kind == EdDocument::EditKind::TerrainTypes        ? UndoTerrainTypes(true)
      : kind == EdDocument::EditKind::LayerConversion     ? UndoConversion(true)
      : kind == EdDocument::EditKind::Look                ? UndoLook(true)
      : kind == EdDocument::EditKind::WaterMasks          ? UndoWaterMasks(true)
      : kind == EdDocument::EditKind::HeightsAndMasks     ? UndoHeightsAndMasks(true)
      : kind == EdDocument::EditKind::GraphBuild          ? UndoGraphBuild(true)
      : kind == EdDocument::EditKind::Layout              ? mDocument.UndoLayout(true)
      : kind == EdDocument::EditKind::Mission             ? mDocument.UndoMission(true)
      : kind == EdDocument::EditKind::MapInfo             ? mDocument.UndoMapInfo(true)
      : kind == EdDocument::EditKind::Paths               ? mDocument.UndoPaths(true)
                                                          : UndoHeights(true);
    if (done) {
      mDocument.PushUndo(kind);
    }
    return done;
  }

  namespace
  {
    /** Slot `slot`'s albedo (or normal map) material: lower, strata 0-7, upper. */
    moho::CStratumMaterial& SlotMaterial(
      moho::StratumMaterial& strata,
      const int slot,
      const bool normals
    )
    {
      moho::CStratumMaterial* const albedo[10] = {
        &strata.mLowerAlbedoTexture,
        &strata.mStratum0AlbedoTexture,
        &strata.mStratum1AlbedoTexture,
        &strata.mStratum2AlbedoTexture,
        &strata.mStratum3AlbedoTexture,
        &strata.mStratum4AlbedoTexture,
        &strata.mStratum5AlbedoTexture,
        &strata.mStratum6AlbedoTexture,
        &strata.mStratum7AlbedoTexture,
        &strata.mUpperAlbedoTexture,
      };
      moho::CStratumMaterial* const normal[10] = {
        &strata.mLowerNormalTexture,
        &strata.mStratum0NormalTexture,
        &strata.mStratum1NormalTexture,
        &strata.mStratum2NormalTexture,
        &strata.mStratum3NormalTexture,
        &strata.mStratum4NormalTexture,
        &strata.mStratum5NormalTexture,
        &strata.mStratum6NormalTexture,
        &strata.mStratum7NormalTexture,
        &strata.mUpperNormalTexture,
      };
      return *(normals ? normal : albedo)[std::clamp(slot, 0, 9)];
    }
  } // namespace

  std::vector<EdTools::LayerSlot> EdMapScene::LayerSlots() const
  {
    std::vector<EdTools::LayerSlot> slots;
    if (mMap == nullptr) {
      return slots;
    }
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    for (int slot = 0; slot < 10; ++slot) {
      const moho::CStratumMaterial& albedo = SlotMaterial(strata, slot, false);
      const moho::CStratumMaterial& normals = SlotMaterial(strata, slot, true);
      slots.push_back({albedo.mPath.c_str(), normals.mPath.c_str(), albedo.mSize, normals.mSize});
    }
    return slots;
  }

  void EdMapScene::SetLayerSlot(
    const int slot,
    const std::string& albedo,
    const std::string& normals,
    const float albedoSize,
    const float normalsSize
  )
  {
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    const auto set = [](moho::CStratumMaterial& material, const std::string& path, const float size) {
      if (path != material.mPath.c_str()) {
        material.mPath.assign(path.c_str());
        // Dropped, so SetSize loads the new file.
        material.mTextureSheet.reset();
      }
      material.mSize = size > 0.0f ? size : 1.0f;
    };
    set(SlotMaterial(strata, slot, false), albedo, albedoSize);
    set(SlotMaterial(strata, slot, true), normals, normalsSize);
    // Loads what has no texture yet and scales every layer to the map (StratumMaterial::SetSizeTo).
    strata.SetSizeTo(mMap->mTerrainRes);
    // In front of a play: its terrain's layer the same (WPE.41).
    if (mOverPlay && mSessionMap != nullptr && mSessionMap->mTerrainRes != nullptr) {
      moho::StratumMaterial& live = mSessionMap->mTerrainRes->GetStratumMaterial();
      set(SlotMaterial(live, slot, false), albedo, albedoSize);
      set(SlotMaterial(live, slot, true), normals, normalsSize);
      live.SetSizeTo(mSessionMap->mTerrainRes);
    }
    mDocument.SetLayerFact(slot, albedo);
    mDocument.SetModified(true);
  }

  void EdMapScene::PreviewLayerSlot(
    const int slot,
    const std::vector<std::uint8_t>& albedo,
    const std::vector<std::uint8_t>& normals,
    const float emptySize
  )
  {
    if (mMap == nullptr || slot < 0 || slot > 9) {
      return;
    }
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    const auto show = [&](moho::CStratumMaterial& material, const std::vector<std::uint8_t>& bytes) {
      if (bytes.empty()) {
        return;
      }
      // A texture made from the bytes (copied), as the engine's own in-memory sheets are (CD3DDeviceResources
      // 0x00441810); the path stays the map's, so saving writes what the map names.
      std::shared_ptr<moho::RD3DTextureResource> sheet(
        new moho::RD3DTextureResource("editor:material", const_cast<std::uint8_t*>(bytes.data()), bytes.size())
      );
      material.mTextureSheet = sheet;
      if (material.mPath.empty() && material.mSize <= 1.0f) {
        material.mSize = emptySize;
      }
    };
    show(SlotMaterial(strata, slot, false), albedo);
    if (slot < 9) {
      show(SlotMaterial(strata, slot, true), normals);
    }
    strata.SetSizeTo(mMap->mTerrainRes);
  }

  void EdMapScene::RestoreLayerSlot(
    const int slot
  )
  {
    if (mMap == nullptr || slot < 0 || slot > 9) {
      return;
    }
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    for (const bool normals : {false, true}) {
      moho::CStratumMaterial& material = SlotMaterial(strata, slot, normals);
      material.mTextureSheet.reset();
    }
    // Loads the files the slot names again (StratumMaterial::SetSizeTo).
    strata.SetSizeTo(mMap->mTerrainRes);
  }

  void EdMapScene::ChangeLayerSlot(
    const int slot,
    const EdTools::LayerSlot& value
  )
  {
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    if (slot < 0 || static_cast<std::size_t>(slot) >= slots.size() || slots[static_cast<std::size_t>(slot)] == value) {
      return;
    }
    const EdTools::LayerSlot& before = slots[static_cast<std::size_t>(slot)];
    std::vector<EdDocument::LayerEdit>& undo = mDocument.LayerUndo();
    // Dragging a size makes one undo step: a change of the same slot's size right after the last one joins it.
    const bool joins = !undo.empty() && undo.back().slot == slot && undo.back().albedoAfter == value.albedo &&
      undo.back().normalsAfter == value.normals && undo.back().albedoAfter == before.albedo &&
      undo.back().albedoSizeAfter == before.albedoSize && value.albedo == before.albedo && mLayerDragJoin;
    if (joins) {
      undo.back().albedoSizeAfter = value.albedoSize;
      undo.back().normalsSizeAfter = value.normalsSize;
    } else {
      EdDocument::LayerEdit edit;
      edit.slot = slot;
      edit.albedoBefore = before.albedo;
      edit.normalsBefore = before.normals;
      edit.albedoSizeBefore = before.albedoSize;
      edit.normalsSizeBefore = before.normalsSize;
      edit.albedoAfter = value.albedo;
      edit.normalsAfter = value.normals;
      edit.albedoSizeAfter = value.albedoSize;
      edit.normalsSizeAfter = value.normalsSize;
      undo.push_back(edit);
      mDocument.EditEnded(EdDocument::EditKind::Layers);
    }
    mLayerDragJoin = value.albedo == before.albedo && value.normals == before.normals;
    SetLayerSlot(slot, value.albedo, value.normals, value.albedoSize, value.normalsSize);
    gpg::Logf(
      "editor: layer %d is %s at size %.2f",
      slot,
      value.albedo.empty() ? "(empty)" : value.albedo.c_str(),
      static_cast<double>(value.albedoSize)
    );
  }

  LayerConvertPlan EdMapScene::PlanConversion(
    const std::string& shader,
    const LayerConvertOptions& options
  )
  {
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    LayerPaint paint;
    if (field != nullptr && !masks.texels.empty()) {
      const std::vector<EdTools::LayerSlot> slots = LayerSlots();
      std::array<bool, 8> textured{};
      for (std::size_t i = 0; i < 8 && i + 1 < slots.size(); ++i) {
        textured[i] = !slots[i + 1].albedo.empty();
      }
      paint = ReadLayerPaint(
        masks.texels.data(),
        masks.width,
        masks.height,
        MaskTerrain{field->data, field->width, field->height},
        RemappedStrata(TerrainShader()),
        textured
      );
    }
    return PlanLayerConversion(TerrainShader(), shader, paint, options);
  }

  bool EdMapScene::ConvertLayers(
    const std::string& shader,
    const LayerConvertOptions& options,
    std::vector<std::string>& report
  )
  {
    report.clear();
    if (mMap == nullptr || mPainting || mPaintingMask) {
      report.emplace_back("No map to convert.");
      return false;
    }
    const LayerConvertPlan plan = PlanConversion(shader, options);
    if (!plan.refused.empty()) {
      report.push_back("Not converted: " + plan.refused);
      return false;
    }
    EdDocument::MaskGrid& masks = mDocument.Masks();
    EdDocument::ConversionEdit edit;
    edit.masksBefore = masks.texels;
    const std::size_t changed = ConvertMasks(masks.texels.data(), masks.texels.size(), plan, options);
    edit.masksAfter = masks.texels;
    // The layer slots follow their paint.
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    for (int j = 0; j < 8; ++j) {
      const int source = plan.arrangement[static_cast<std::size_t>(j)];
      if (source == j || static_cast<std::size_t>(source + 1) >= slots.size()) {
        continue;
      }
      EdDocument::LayerEdit layer;
      layer.slot = j + 1;
      const EdTools::LayerSlot& before = slots[static_cast<std::size_t>(j + 1)];
      const EdTools::LayerSlot& after = slots[static_cast<std::size_t>(source + 1)];
      layer.albedoBefore = before.albedo;
      layer.normalsBefore = before.normals;
      layer.albedoSizeBefore = before.albedoSize;
      layer.normalsSizeBefore = before.normalsSize;
      layer.albedoAfter = after.albedo;
      layer.normalsAfter = after.normals;
      layer.albedoSizeAfter = after.albedoSize;
      layer.normalsSizeAfter = after.normalsSize;
      edit.layers.push_back(layer);
    }
    EdDocument::LayerEdit switched;
    switched.slot = -1;
    switched.albedoBefore = TerrainShader();
    switched.albedoAfter = shader;
    edit.layers.push_back(switched);
    for (const EdDocument::LayerEdit& layer : edit.layers) {
      if (layer.slot >= 0) {
        SetLayerSlot(layer.slot, layer.albedoAfter, layer.normalsAfter, layer.albedoSizeAfter, layer.normalsSizeAfter);
      }
    }
    SetTerrainShaderName(shader, true);
    UploadMasks({SampleRect{0, 0, masks.width - 1, masks.height - 1}}, 0xFFu);
    UpdateCoverage();
    mDocument.ConversionUndo().push_back(std::move(edit));
    mDocument.ConversionRedo().clear();
    mDocument.EditEnded(EdDocument::EditKind::LayerConversion);
    mDocument.SetModified(true);
    report = plan.lines;
    for (const std::string& warning : plan.warnings) {
      report.push_back("Look at: " + warning);
    }
    report.push_back(std::to_string(changed) + " mask texels changed. One undo step.");
    for (const std::string& line : report) {
      gpg::Logf("editor: convert layers %s -> %s: %s", plan.from.c_str(), plan.to.c_str(), line.c_str());
    }
    return true;
  }

  bool EdMapScene::MoveLayer(
    const int from,
    const int to
  )
  {
    if (mMap == nullptr || mPainting || mPaintingMask || from == to || from < 0 || from > 7 || to < 0 || to > 7) {
      return false;
    }
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty()) {
      return false;
    }
    const std::array<int, 8> arrangement = LayerMoveArrangement(from, to);
    EdDocument::ConversionEdit edit;
    edit.masksBefore = masks.texels;
    const std::size_t changed =
      MoveLayerMasks(masks.texels.data(), masks.texels.size(), arrangement, RemappedStrata(TerrainShader()));
    edit.masksAfter = masks.texels;
    // The textures follow their paint.
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    for (int j = 0; j < 8; ++j) {
      const int source = arrangement[static_cast<std::size_t>(j)];
      if (source == j || static_cast<std::size_t>(std::max(j, source) + 1) >= slots.size()) {
        continue;
      }
      const EdTools::LayerSlot& before = slots[static_cast<std::size_t>(j + 1)];
      const EdTools::LayerSlot& after = slots[static_cast<std::size_t>(source + 1)];
      EdDocument::LayerEdit layer;
      layer.slot = j + 1;
      layer.albedoBefore = before.albedo;
      layer.normalsBefore = before.normals;
      layer.albedoSizeBefore = before.albedoSize;
      layer.normalsSizeBefore = before.normalsSize;
      layer.albedoAfter = after.albedo;
      layer.normalsAfter = after.normals;
      layer.albedoSizeAfter = after.albedoSize;
      layer.normalsSizeAfter = after.normalsSize;
      edit.layers.push_back(layer);
    }
    for (const EdDocument::LayerEdit& layer : edit.layers) {
      SetLayerSlot(layer.slot, layer.albedoAfter, layer.normalsAfter, layer.albedoSizeAfter, layer.normalsSizeAfter);
    }
    UploadMasks({SampleRect{0, 0, masks.width - 1, masks.height - 1}}, 0xFFu);
    UpdateCoverage();
    mDocument.ConversionUndo().push_back(std::move(edit));
    mDocument.ConversionRedo().clear();
    mDocument.EditEnded(EdDocument::EditKind::LayerConversion);
    mDocument.SetModified(true);
    gpg::Logf("editor: layer %d moved to %d: %zu mask texels changed, one undo step", from + 1, to + 1, changed);
    return true;
  }

  bool EdMapScene::UndoConversion(
    const bool redo
  )
  {
    std::vector<EdDocument::ConversionEdit>& from = redo ? mDocument.ConversionRedo() : mDocument.ConversionUndo();
    std::vector<EdDocument::ConversionEdit>& to = redo ? mDocument.ConversionUndo() : mDocument.ConversionRedo();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (from.empty() || mMap == nullptr || masks.texels.size() != from.back().masksBefore.size()) {
      return false;
    }
    EdDocument::ConversionEdit edit = std::move(from.back());
    from.pop_back();
    masks.texels = redo ? edit.masksAfter : edit.masksBefore;
    for (const EdDocument::LayerEdit& layer : edit.layers) {
      if (layer.slot < 0) {
        SetTerrainShaderName(redo ? layer.albedoAfter : layer.albedoBefore, true);
      } else if (redo) {
        SetLayerSlot(layer.slot, layer.albedoAfter, layer.normalsAfter, layer.albedoSizeAfter, layer.normalsSizeAfter);
      } else {
        SetLayerSlot(
          layer.slot, layer.albedoBefore, layer.normalsBefore, layer.albedoSizeBefore, layer.normalsSizeBefore
        );
      }
    }
    UploadMasks({SampleRect{0, 0, masks.width - 1, masks.height - 1}}, 0xFFu);
    UpdateCoverage();
    to.push_back(std::move(edit));
    gpg::Logf("editor: %s the layer conversion", redo ? "redid" : "undid");
    return true;
  }

  bool EdMapScene::UndoLayers(
    const bool redo
  )
  {
    std::vector<EdDocument::LayerEdit>& from = redo ? mDocument.LayerRedo() : mDocument.LayerUndo();
    std::vector<EdDocument::LayerEdit>& to = redo ? mDocument.LayerUndo() : mDocument.LayerRedo();
    if (from.empty() || mMap == nullptr) {
      return false;
    }
    // One step: the last edit, and the ones made with it.
    const int batch = from.back().batch;
    int count = 0;
    do {
      const EdDocument::LayerEdit edit = from.back();
      from.pop_back();
      to.push_back(edit);
      ++count;
      if (edit.slot < 0) {
        SetTerrainShaderName(redo ? edit.albedoAfter : edit.albedoBefore);
      } else if (redo) {
        SetLayerSlot(edit.slot, edit.albedoAfter, edit.normalsAfter, edit.albedoSizeAfter, edit.normalsSizeAfter);
      } else {
        SetLayerSlot(edit.slot, edit.albedoBefore, edit.normalsBefore, edit.albedoSizeBefore, edit.normalsSizeBefore);
      }
    } while (batch != 0 && !from.empty() && from.back().batch == batch);
    mLayerDragJoin = false;
    if (count > 1) {
      gpg::Logf("editor: %s %d layer changes made together", redo ? "redid" : "undid", count);
    }
    return true;
  }

  std::vector<LayerSettings> EdMapScene::LayerSettingsNow() const
  {
    std::vector<LayerSettings> layers;
    for (const EdTools::LayerSlot& slot : LayerSlots()) {
      layers.push_back({slot.albedo, slot.normals, slot.albedoSize, slot.normalsSize});
    }
    return layers;
  }

  int EdMapScene::ApplyLayerSettings(
    const std::string& shader,
    const std::vector<std::pair<int, LayerSettings>>& layers
  )
  {
    if (mMap == nullptr) {
      return 0;
    }
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    const int batch = ++mLayerBatch;
    int changed = 0;
    std::vector<EdDocument::LayerEdit>& undo = mDocument.LayerUndo();
    if (!shader.empty() && shader != TerrainShader()) {
      if (!mShaders.empty() && std::find(mShaders.begin(), mShaders.end(), shader) == mShaders.end()) {
        gpg::Warnf("editor: the terrain shader %s isn't one this game has; set anyway", shader.c_str());
      }
      EdDocument::LayerEdit edit;
      edit.slot = -1;
      edit.albedoBefore = TerrainShader();
      edit.albedoAfter = shader;
      edit.batch = batch;
      undo.push_back(edit);
      SetTerrainShaderName(shader);
      ++changed;
    }
    for (const auto& [slot, layer] : layers) {
      if (slot < 0 || static_cast<std::size_t>(slot) >= slots.size()) {
        continue;
      }
      const EdTools::LayerSlot& before = slots[static_cast<std::size_t>(slot)];
      const EdTools::LayerSlot after{layer.albedo, layer.normals, layer.albedoSize, layer.normalsSize};
      if (before == after) {
        continue;
      }
      EdDocument::LayerEdit edit;
      edit.slot = slot;
      edit.albedoBefore = before.albedo;
      edit.normalsBefore = before.normals;
      edit.albedoSizeBefore = before.albedoSize;
      edit.normalsSizeBefore = before.normalsSize;
      edit.albedoAfter = after.albedo;
      edit.normalsAfter = after.normals;
      edit.albedoSizeAfter = after.albedoSize;
      edit.normalsSizeAfter = after.normalsSize;
      edit.batch = batch;
      undo.push_back(edit);
      SetLayerSlot(slot, after.albedo, after.normals, after.albedoSize, after.normalsSize);
      ++changed;
    }
    if (changed > 0) {
      mDocument.EditEnded(EdDocument::EditKind::Layers);
    }
    mLayerDragJoin = false;
    return changed;
  }

  bool EdMapScene::UndoMasks(
    const bool redo
  )
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    std::vector<SampleRect> rects;
    if (
      masks.texels.empty() ||
      !(redo ? mDocument.MaskUndo().Redo(masks.texels.data(), rects)
             : mDocument.MaskUndo().Undo(masks.texels.data(), rects))
    ) {
      return false;
    }
    UploadMasks(rects, 0xFFu);
    mDocument.SetModified(true);
    UpdateCoverage();
    return true;
  }

  bool EdMapScene::UndoHeights(
    const bool redo
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    std::vector<SampleRect> rects;
    if (
      field == nullptr || mPainting ||
      !(redo ? mDocument.Heights().Redo(field->data, rects) : mDocument.Heights().Undo(field->data, rects))
    ) {
      return false;
    }
    RefreshHeights(rects);
    mDocument.SetModified(true);
    if (mCheckDone) {
      RunSymmetryCheck();
    }
    return true;
  }

  void EdMapScene::LoadMasks()
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (!masks.texels.empty() || mMap == nullptr) {
      return;
    }
    moho::IWldTerrainRes* const terrain = mMap->mTerrainRes;
    // Edit mode, as the original editor ran: the masks become textures that can be written (and the water
    // map is rebuilt from the heights).
    if (!terrain->IsInEditMode()) {
      moho::CBackgroundTaskControl control{nullptr};
      terrain->EnterEditMode(control);
    }
    const moho::StratumMaterial& strata = terrain->GetStratumMaterial();
    masks.width = static_cast<int>(strata.mStratumMaskWidth);
    masks.height = static_cast<int>(strata.mStratumMaskHeight);
    if (masks.width < 1 || masks.height < 1) {
      return;
    }
    const std::size_t count = static_cast<std::size_t>(masks.width) * static_cast<std::size_t>(masks.height);
    masks.texels.assign(count, 0);
    mMaskPlane.assign(count, 0);
    for (int layer = 0; layer < 8; ++layer) {
      terrain->GetStratumMask(layer, mMaskPlane.data());
      for (std::size_t i = 0; i < count; ++i) {
        masks.texels[i] |= static_cast<std::uint64_t>(mMaskPlane[i]) << (8 * layer);
      }
    }
    mDocument.MaskUndo().Reset(masks.width, masks.height);
    mDocument.MasksRead();
    UpdateCoverage();
    const std::uint8_t remapped = RemappedStrata(TerrainShader());
    // A stratum the map's shader reads through saturate(2m-1) with paint and none of it showing (every byte 1..127)
    // was painted for a shader that reads masks as they are (C1). Said in the log, so the Problems panel has it too.
    // Hidden bytes next to ones that show are only soft edges (GPG's own maps have them) and aren't reported.
    if (
      const MaskRangeReport range = CheckMaskRange(masks.texels.data(), masks.texels.size(), remapped);
      range.Total() > 0
    ) {
      std::string strata;
      for (int layer = 0; layer < 8; ++layer) {
        if (range.PaintedForAnotherRange(layer)) {
          strata += (strata.empty() ? "" : ", ") + std::to_string(layer + 1);
        }
      }
      gpg::Warnf(
        "editor: masks: %d painted texels of layer%s %s show nothing under %s (all bytes 1-127, which its "
        "saturate(2m-1) hides: painted for a shader that reads masks as they are)",
        range.Total(),
        !strata.contains(',') ? "" : "s",
        strata.c_str(),
        TerrainShader().c_str()
      );
    }
    // How much of the map each layer covers (the share of full weight the shader shows), for the log.
    std::string cover;
    for (int layer = 0; layer < 8; ++layer) {
      std::uint64_t sum = 0;
      for (const std::uint64_t texel : masks.texels) {
        sum += static_cast<std::uint64_t>(MaskWeight(MaskByte(texel, layer), (remapped & (1U << layer)) != 0));
      }
      char part[32];
      (void)std::snprintf(
        part,
        sizeof(part),
        "%s%d: %.1f%%",
        layer == 0 ? "" : ", ",
        layer + 1,
        100.0 * static_cast<double>(sum) / (255.0 * static_cast<double>(count))
      );
      cover += part;
    }
    gpg::Logf(
      "editor: stratum masks %d x %d read for painting (shader %s, strata read as 2m-1 0x%02X; cover %s)",
      masks.width,
      masks.height,
      TerrainShader().c_str(),
      static_cast<unsigned>(remapped),
      cover.c_str()
    );
  }

  void EdMapScene::UploadMasks(
    const std::vector<SampleRect>& rects,
    const unsigned layers
  )
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mMap == nullptr) {
      return;
    }
    mMaskPlane.resize(masks.texels.size());
    // In front of a play whose masks are the same size (the play was loaded from this map's files): the same rows into
    // its terrain (WPE.41).
    moho::IWldTerrainRes* live = nullptr;
    if (mOverPlay && mSessionMap != nullptr && mSessionMap->mTerrainRes != nullptr) {
      const moho::StratumMaterial& strata = mSessionMap->mTerrainRes->GetStratumMaterial();
      if (
        strata.mStratumMaskWidth == static_cast<std::uint32_t>(masks.width) &&
        strata.mStratumMaskHeight == static_cast<std::uint32_t>(masks.height)
      ) {
        live = mSessionMap->mTerrainRes;
      } else if (!mLiveMaskSizeWarned) {
        mLiveMaskSizeWarned = true;
        gpg::Warnf(
          "editor: the play's masks are %ux%u, the map's %dx%d: mask edits stay in the editor",
          strata.mStratumMaskWidth,
          strata.mStratumMaskHeight,
          masks.width,
          masks.height
        );
      }
    }
    for (int layer = 0; layer < 8; ++layer) {
      if ((layers & (1u << layer)) == 0) {
        continue;
      }
      for (const SampleRect& rect : rects) {
        for (int z = rect.z0; z <= rect.z1; ++z) {
          const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(masks.width);
          for (int x = rect.x0; x <= rect.x1; ++x) {
            mMaskPlane[row + static_cast<std::size_t>(x)] =
              MaskByte(masks.texels[row + static_cast<std::size_t>(x)], layer);
          }
        }
        mMap->mTerrainRes->UpdateStratumMask(layer, mMaskPlane.data(), rect.x0, rect.z0, rect.x1 + 1, rect.z1 + 1);
        if (live != nullptr) {
          live->UpdateStratumMask(layer, mMaskPlane.data(), rect.x0, rect.z0, rect.x1 + 1, rect.z1 + 1);
        }
      }
    }
  }

  void EdMapScene::BuildWeightQuads(
    const int layer
  )
  {
    mWeightQuads.clear();
    mWeightLayer = layer;
    mWeightStale = false;
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || masks.texels.empty()) {
      return;
    }
    // Blocks of 4 x 4 texels (16 thousand quads on a 20 km map), coloured by their average weight.
    constexpr int kBlock = 4;
    // The weight the map's shader shows (C1).
    const bool remappedLayer = (RemappedStrata(TerrainShader()) & (1U << layer)) != 0;
    const float perTexel = static_cast<float>(field->width - 1) / static_cast<float>(masks.width);
    const auto groundAt = [field](const float x, const float z, const std::uint32_t color) {
      const int sx = std::clamp(static_cast<int>(std::lround(x)), 0, field->width - 1);
      const int sz = std::clamp(static_cast<int>(std::lround(z)), 0, field->height - 1);
      moho::CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = static_cast<float>(field->data[sz * field->width + sx]) / 128.0f + 0.3f;
      vertex.mZ = z;
      vertex.mColor = color;
      return vertex;
    };
    for (int bz = 0; bz < masks.height; bz += kBlock) {
      for (int bx = 0; bx < masks.width; bx += kBlock) {
        unsigned sum = 0;
        int count = 0;
        for (int z = bz; z < std::min(masks.height, bz + kBlock); ++z) {
          for (int x = bx; x < std::min(masks.width, bx + kBlock); ++x) {
            sum += static_cast<unsigned>(MaskWeight(
              MaskByte(
                masks.texels
                  [static_cast<std::size_t>(z) * static_cast<std::size_t>(masks.width) + static_cast<std::size_t>(x)],
                layer
              ),
              remappedLayer
            ));
            ++count;
          }
        }
        const unsigned weight = count > 0 ? sum / static_cast<unsigned>(count) : 0U;
        if (weight < 8U) {
          continue;
        }
        const std::uint32_t color = ((weight * 150U / 255U) << 24) | 0x0040FF60u;
        const float x0 = static_cast<float>(bx) * perTexel;
        const float z0 = static_cast<float>(bz) * perTexel;
        const float x1 = static_cast<float>(std::min(masks.width, bx + kBlock)) * perTexel;
        const float z1 = static_cast<float>(std::min(masks.height, bz + kBlock)) * perTexel;
        mWeightQuads.push_back(groundAt(x0, z0, color));
        mWeightQuads.push_back(groundAt(x1, z0, color));
        mWeightQuads.push_back(groundAt(x1, z1, color));
        mWeightQuads.push_back(groundAt(x0, z1, color));
      }
    }
  }

  void EdMapScene::UpdateCoverage()
  {
    mWeightStale = true;
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    mCoverageValid = !masks.texels.empty();
    if (mCoverageValid) {
      faf::editor::MaskCoverage(masks.texels.data(), masks.texels.size(), mCoverage, RemappedStrata(TerrainShader()));
    }
  }

  bool EdMapScene::MaskCoverage(
    float (&coverage)[8]
  ) const
  {
    if (!mCoverageValid || mDocument.Masks().texels.empty()) {
      return false;
    }
    for (int i = 0; i < 8; ++i) {
      coverage[i] = mCoverage[i];
    }
    return true;
  }

  void EdMapScene::WholeMaskChanged(
    const SampleRect& whole
  )
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    mDocument.MaskUndo().EndStroke(masks.texels.data());
    mDocument.EditEnded(EdDocument::EditKind::Masks);
    UploadMasks({whole}, 0xFFu);
    mDocument.SetModified(true);
    UpdateCoverage();
    mLayerDragJoin = false;
  }

  std::expected<std::string, std::string> EdMapScene::ClearMaskLayer(
    const int layer
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      return std::unexpected("No map's masks to change.");
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    for (std::uint64_t& texel : masks.texels) {
      texel = WithMaskByte(texel, layer, 0);
    }
    WholeMaskChanged(whole);
    return "Cleared the mask of layer " + std::to_string(layer + 1);
  }

  int EdMapScene::TerrainTypesFromTextures(
    const std::array<int, 9>& types,
    const bool onlyDefault,
    std::string& message
  )
  {
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    int width = 0;
    int height = 0;
    std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
    if (masks.texels.empty() || cells == nullptr) {
      message = cells == nullptr ? "The map has no terrain type grid." : "No map's masks to read.";
      return -1;
    }
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    const int painted = ShaderProfileOf(TerrainShader()).painted;
    std::array<bool, 9> textured{};
    for (int layer = 0; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
      textured[static_cast<std::size_t>(layer)] =
        !slots[static_cast<std::size_t>(layer)].albedo.empty() && layer <= painted;
    }
    std::vector<std::uint8_t> before = mDocument.TerrainTypesNow();
    const std::size_t changed = TerrainTypesFromLayers(
      masks.texels.data(),
      masks.width,
      masks.height,
      RemappedStrata(TerrainShader()),
      textured,
      types,
      cells,
      width,
      height,
      onlyDefault
    );
    if (changed > 0) {
      mDocument.TerrainTypesEdited(std::move(before));
      mDocument.TerrainTypesChanged();
      mDocument.SetModified(true);
    }
    message = std::to_string(changed) + " terrain type cells changed";
    return static_cast<int>(changed);
  }

  std::expected<std::string, std::string> EdMapScene::FillMaskLayer(
    const int layer
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      return std::unexpected("No map's masks to change.");
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    // 255 shows full in either range (saturate(2 * 1 - 1) = 1).
    for (std::uint64_t& texel : masks.texels) {
      texel = WithMaskByte(texel, layer, 255);
    }
    WholeMaskChanged(whole);
    return "Filled the paint of layer " + std::to_string(layer + 1);
  }

  std::expected<std::string, std::string> EdMapScene::ImportMaskLayer(
    const int layer,
    const std::filesystem::path& file
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      return std::unexpected("No map's masks to change.");
    }
    const auto read = ReadHeightImage(file, masks.width, masks.height);
    if (!read) {
      return std::unexpected("Mask import failed: " + read.error());
    }
    const HeightImage image = ResampleHeights(*read, masks.width, masks.height);
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    // The image's grey is the weight that shows; the byte is stored for the map's shader (C1).
    const bool remappedLayer = (RemappedStrata(TerrainShader()) & (1U << layer)) != 0;
    for (std::size_t i = 0; i < masks.texels.size(); ++i) {
      masks.texels[i] = WithMaskByte(
        masks.texels[i],
        layer,
        MaskStoredFor(static_cast<float>(image.words[i] >> 8), remappedLayer, MaskByte(masks.texels[i], layer))
      );
    }
    WholeMaskChanged(whole);
    return "Imported the mask of layer " + std::to_string(layer + 1) + " from " + file.string();
  }

  std::expected<std::string, std::string> EdMapScene::SetMaskLayer(
    const int layer,
    const TexImage& image
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask || layer < 0 || layer > 7 || image.size <= 0) {
      return std::unexpected("No map's masks to change.");
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const bool remappedLayer = (RemappedStrata(TerrainShader()) & (1U << layer)) != 0;
    for (int y = 0; y < masks.height; ++y) {
      for (int x = 0; x < masks.width; ++x) {
        // The image covers the whole map: its rows run along z as the mask's do.
        float c[4];
        image.Sample(
          (static_cast<float>(x) + 0.5f) / static_cast<float>(masks.width),
          (static_cast<float>(y) + 0.5f) / static_cast<float>(masks.height),
          c
        );
        const float grey = image.channels == 1 ? c[0] : c[0] * 0.2126f + c[1] * 0.7152f + c[2] * 0.0722f;
        std::uint64_t& texel = masks.texels[static_cast<std::size_t>(y) * masks.width + x];
        texel = WithMaskByte(
          texel, layer, MaskStoredFor(std::clamp(grey, 0.0f, 1.0f) * 255.0f, remappedLayer, MaskByte(texel, layer))
        );
      }
    }
    WholeMaskChanged(whole);
    return "Set the mask of stratum " + std::to_string(layer + 1) + " from the material graph";
  }

  std::expected<std::string, std::string> EdMapScene::ExportMaskLayer(
    const int layer,
    const std::filesystem::path& file
  )
  {
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty()) {
      return std::unexpected("No map's masks to export.");
    }
    HeightImage image;
    image.width = masks.width;
    image.height = masks.height;
    image.words.resize(masks.texels.size());
    // The weight that shows, not the stored byte (C1).
    const bool remappedLayer = (RemappedStrata(TerrainShader()) & (1U << layer)) != 0;
    for (std::size_t i = 0; i < masks.texels.size(); ++i) {
      image.words[i] = static_cast<std::uint16_t>(MaskWeight(MaskByte(masks.texels[i], layer), remappedLayer) * 257.0f);
    }
    if (const auto wrote = WriteHeightImage(file, image); !wrote) {
      return std::unexpected("Mask export failed: " + wrote.error());
    }
    return "Exported the mask of layer " + std::to_string(layer + 1) + " to " + file.string();
  }

  std::vector<std::string> EdMapScene::TerrainShaders()
  {
    if (!mShaders.empty()) {
      return mShaders;
    }
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::CD3DEffect* const effect =
      device != nullptr && device->GetResources() != nullptr ? device->GetResources()->FindEffect("terrain") : nullptr;
    if (effect == nullptr) {
      return {};
    }
    // Every technique of the terrain effect it marks composite: the shaders a map may name, as the engine
    // checks when it draws a map (ResolveTerrainCompositeShaderUsage).
    fa::vector<fa::string> techniques;
    effect->EnumerateValidTechniques(techniques);
    const fa::string usage("usage", 5U);
    const fa::string undefined("undefined", 9U);
    for (const fa::string& name : techniques) {
      const fa::string found = effect->GetStringAnnotation(name, usage, undefined);
      if (std::strcmp(found.c_str(), "composite") == 0) {
        mShaders.emplace_back(name.c_str());
      }
    }
    std::string list;
    for (const std::string& shader : mShaders) {
      list += (list.empty() ? "" : ", ") + shader;
    }
    gpg::Logf("editor: %zu terrain shaders: %s", mShaders.size(), list.c_str());
    return mShaders;
  }

  void EdMapScene::SetTerrainShaderName(
    const std::string& shader,
    const bool converted
  )
  {
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    // The masks stay as they are: the brushes encode for the new shader from now on (C1), and paint stored for the
    // old one shows differently when the two read masks differently.
    if (
      const std::uint8_t before = RemappedStrata(strata.mShaderName.c_str()), after = RemappedStrata(shader);
      !converted && before != after && !mDocument.Masks().texels.empty()
    ) {
      gpg::Warnf(
        "editor: terrain shader %s reads masks differently from %s (strata as 2m-1: 0x%02X, was 0x%02X): the "
        "paint so far shows differently",
        shader.c_str(),
        strata.mShaderName.c_str(),
        static_cast<unsigned>(after),
        static_cast<unsigned>(before)
      );
    }
    strata.mShaderName.assign(shader.c_str());
    // ResolveTerrainCompositeShaderUsage (0x0089F350) checks the new name once before it is drawn or saved.
    strata.byte0 = 0;
    strata.byte1 = 1;
    mDocument.SetModified(true);
    gpg::Logf("editor: terrain shader %s", shader.c_str());
    if (!mDocument.Masks().texels.empty()) {
      UpdateCoverage(); // the share each layer shows under the new shader
    }
  }

  std::string EdMapScene::TerrainShader() const
  {
    return mMap != nullptr ? std::string(mMap->mTerrainRes->GetStratumMaterial().mShaderName.c_str()) : std::string{};
  }

  void EdMapScene::ChangeTerrainShader(
    const std::string& shader
  )
  {
    if (mMap == nullptr || shader == TerrainShader()) {
      return;
    }
    EdDocument::LayerEdit edit;
    edit.slot = -1;
    edit.albedoBefore = TerrainShader();
    edit.albedoAfter = shader;
    mDocument.LayerUndo().push_back(edit);
    mDocument.EditEnded(EdDocument::EditKind::Layers);
    SetTerrainShaderName(shader);
  }

  void EdMapScene::PaintMask(
    const float frameSeconds
  )
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || masks.texels.empty() || !CursorGround(groundX, groundZ)) {
      return;
    }
    MaskBrush brush = mTools->CurrentMaskBrush();
    brush.step = ++mMaskSteps;
    // A new stroke: a new scatter pattern (the stroke model starts from the texels as they are, ApplyMaskBrush).
    if (mMaskStroke.before.empty()) {
      ++mMaskStrokes;
    }
    brush.scatterSeed = mMaskStrokes;
    // Stored for the map's shader (most read saturate(2m-1)): the brush works in the weight that shows.
    brush.remapped = RemappedStrata(TerrainShader());
    // A right-button stroke does the opposite: Paint erases, Erase paints.
    if (mPaintInverted) {
      brush.mode = brush.mode == MaskBrushMode::Paint ? MaskBrushMode::Erase
        : brush.mode == MaskBrushMode::Erase          ? MaskBrushMode::Paint
                                                      : brush.mode;
    }
    const MaskTerrain terrain{field->data, field->width, field->height};
    std::vector<SampleRect> rects;
    if (mTools->CurrentMaskStamp().on && (brush.mode == MaskBrushMode::Paint || brush.mode == MaskBrushMode::Erase)) {
      rects = MaskStampTo(brush, groundX, groundZ);
    } else {
      for (const SampleRect& rect : MaskBrushRects(masks.width, masks.height, terrain, groundX, groundZ, brush)) {
        mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
      }
      rects = ApplyMaskBrush(
        masks.texels.data(),
        masks.width,
        masks.height,
        terrain,
        groundX,
        groundZ,
        brush,
        std::min(frameSeconds, 0.1f),
        &mMaskStroke
      );
    }
    if (!rects.empty()) {
      mDocument.SetModified(true);
      mWeightStale = true;
      // The painted layer, and those above it when Paint lowers them.
      unsigned layers = 1u << brush.layer;
      if (brush.mode == MaskBrushMode::Paint && brush.lowerAbove) {
        layers |= 0xFFu & ~((2u << brush.layer) - 1u);
      }
      UploadMasks(rects, layers);
    }
  }

  std::vector<SampleRect> EdMapScene::MaskStampTo(
    MaskBrush brush,
    const float x,
    const float z
  )
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const EdTools::MaskStamp stamp = mTools->CurrentMaskStamp();
    // A new stroke (the stroke model's snapshot is empty): the first point is a dab.
    const float spacing = std::max(1.0f, 2.0f * brush.shape.radius * stamp.spacing);
    if (!mMaskStamped || mMaskStroke.before.empty()) {
      mMaskStamped = true;
      mMaskStampTravelled = spacing;
      mMaskStampLastX = x;
      mMaskStampLastZ = z;
      mMaskStampRandom.seed(mMaskStrokes * 7919u + 13u);
    }
    const std::vector<StampDab> dabs =
      StampDabsAlong(mMaskStampLastX, mMaskStampLastZ, x, z, spacing, mMaskStampTravelled);
    mMaskStampLastX = x;
    mMaskStampLastZ = z;
    // Each dab once, at full strength, in the stroke model: dabs that overlap don't pile up.
    brush.buildUp = false;
    std::uniform_real_distribution<float> unit(0.0f, 1.0f);
    const MaskTerrain terrain{field->data, field->width, field->height};
    std::vector<SampleRect> written;
    for (const StampDab& at : dabs) {
      MaskBrush dab = brush;
      if (stamp.randomTurn) {
        dab.shape.shapeAngle += unit(mMaskStampRandom) * 360.0f;
      }
      float dx = at.x;
      float dz = at.z;
      if (stamp.jitter > 0.0f) {
        dab.shape.radius *= 1.0f + (unit(mMaskStampRandom) * 2.0f - 1.0f) * stamp.jitter;
        const float angle = unit(mMaskStampRandom) * 6.2831853f;
        const float reach = brush.shape.radius * stamp.jitter * std::sqrt(unit(mMaskStampRandom));
        dx += std::cos(angle) * reach;
        dz += std::sin(angle) * reach;
      }
      for (const SampleRect& rect : MaskBrushRects(masks.width, masks.height, terrain, dx, dz, dab)) {
        mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
      }
      const std::vector<SampleRect> rects =
        ApplyMaskBrush(masks.texels.data(), masks.width, masks.height, terrain, dx, dz, dab, 1.0f, &mMaskStroke);
      written.insert(written.end(), rects.begin(), rects.end());
      ++mMaskStampDabs;
    }
    return written;
  }

  void EdMapScene::TestMaskStamp(
    const int layer,
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (mTools == nullptr || field == nullptr || masks.texels.empty()) {
      return;
    }
    const std::vector<std::uint64_t> start = masks.texels;
    MaskBrush brush = mTools->CurrentMaskBrush();
    brush.layer = std::clamp(layer, 0, 7);
    brush.remapped = RemappedStrata(TerrainShader());
    brush.scatterSeed = ++mMaskStrokes;
    mDocument.MaskUndo().BeginStroke();
    mMaskStroke = MaskStroke{};
    mMaskStamped = false;
    mMaskStampDabs = 0;
    std::vector<SampleRect> all;
    for (int step = 0; step <= 32; ++step) {
      const float t = static_cast<float>(step) / 32.0f;
      brush.step = ++mMaskSteps;
      const std::vector<SampleRect> rects = MaskStampTo(brush, x0 + (x1 - x0) * t, z0 + (z1 - z0) * t);
      all.insert(all.end(), rects.begin(), rects.end());
    }
    std::size_t changed = 0;
    for (std::size_t i = 0; i < start.size(); ++i) {
      changed += MaskByte(masks.texels[i], brush.layer) != MaskByte(start[i], brush.layer) ? 1 : 0;
    }
    mDocument.MaskUndo().EndStroke(masks.texels.data());
    mDocument.EditEnded(EdDocument::EditKind::Masks);
    mMaskStroke = MaskStroke{};
    mMaskStamped = false;
    UploadMasks(all, 0xFFu);
    gpg::Logf(
      "editor: mask stamp test: layer %d, %d dabs from (%.0f, %.0f) to (%.0f, %.0f), %zu texels changed",
      brush.layer + 1,
      mMaskStampDabs,
      x0,
      z0,
      x1,
      z1,
      changed
    );
  }

  void EdMapScene::TestMaskStroke(
    const int layer,
    const float x,
    const float z,
    const float seconds
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (mTools == nullptr || field == nullptr || masks.texels.empty()) {
      return;
    }
    const std::vector<std::uint64_t> start = masks.texels;
    MaskBrush brush = mTools->CurrentMaskBrush();
    brush.layer = std::clamp(layer, 0, 7);
    brush.remapped = RemappedStrata(TerrainShader());
    brush.scatterSeed = ++mMaskStrokes;
    const MaskTerrain terrain{field->data, field->width, field->height};
    mDocument.MaskUndo().BeginStroke();
    std::vector<SampleRect> all;
    for (float done = 0.0f; done < seconds; done += 1.0f / 60.0f) {
      brush.step = ++mMaskSteps;
      for (const SampleRect& rect : MaskBrushRects(masks.width, masks.height, terrain, x, z, brush)) {
        mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
      }
      const std::vector<SampleRect> rects = ApplyMaskBrush(
        masks.texels.data(), masks.width, masks.height, terrain, x, z, brush, 1.0f / 60.0f, &mMaskStroke
      );
      all.insert(all.end(), rects.begin(), rects.end());
    }
    std::size_t changed = 0;
    int strongest = 0;
    for (std::size_t i = 0; i < start.size(); ++i) {
      if (MaskByte(masks.texels[i], brush.layer) != MaskByte(start[i], brush.layer)) {
        ++changed;
        strongest = std::max(
          strongest,
          static_cast<int>(
            MaskWeight(MaskByte(masks.texels[i], brush.layer), (brush.remapped & (1U << brush.layer)) != 0)
          )
        );
      }
    }
    if (!all.empty()) {
      mDocument.SetModified(true);
      mWeightStale = true;
      UploadMasks(all, 0xFFu);
    }
    EndMaskStroke();
    gpg::Logf(
      "editor: mask test: layer %d at %.0f,%.0f for %.1f s (target %.2f, scatter %.2f, %s): %zu texels changed, the "
      "strongest weight %d of 255",
      brush.layer + 1,
      static_cast<double>(x),
      static_cast<double>(z),
      static_cast<double>(seconds),
      static_cast<double>(brush.target),
      static_cast<double>(brush.scatter),
      brush.buildUp ? "build up" : "stroke model",
      changed,
      strongest
    );
  }

  void EdMapScene::EndMaskStroke()
  {
    mMaskStroke = MaskStroke{};
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (mDocument.MaskUndo().Stroking() && !masks.texels.empty()) {
      const std::size_t before = mDocument.MaskUndo().UndoCount();
      mDocument.MaskUndo().EndStroke(masks.texels.data());
      if (mDocument.MaskUndo().UndoCount() > before) {
        mDocument.EditEnded(EdDocument::EditKind::Masks);
      }
      UpdateCoverage();
      if (mCheckDone && mTools != nullptr && mTools->TextureToolActive()) {
        RunSymmetryCheck();
      }
    }
    mPaintingMask = false;
    mLayerDragJoin = false;
  }

  void EdMapScene::ApplyRules()
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (mTools == nullptr || field == nullptr || masks.texels.empty() || mPaintingMask || mTools->Rules().empty()) {
      return;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    (void)ApplyMaskRules(
      masks.texels.data(),
      masks.width,
      masks.height,
      MaskTerrain{field->data, field->width, field->height},
      mTools->Rules()
    );
    WholeMaskChanged(whole);
    gpg::Logf("editor: %zu texture rules applied to the whole map", mTools->Rules().size());
  }

  int EdMapScene::WriteWaterLinkedMask(
    const field::Grid* const mask,
    const int layer,
    const float strength,
    std::vector<std::uint8_t>& base,
    std::vector<std::uint8_t>& last,
    std::string& message
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask || layer < 1 || layer > 8) {
      message = "No map's masks to write into.";
      return -1;
    }
    const std::size_t n = masks.texels.size();
    const int byte = layer - 1;
    const bool range = (RemappedStrata(TerrainShader()) & (1U << byte)) != 0;
    if (mask == nullptr && base.size() != n) {
      message = "Nothing of it is on the layer.";
      return 0;
    }
    // An undo took the last result away (most texels differ from it): start again from the layer as it is.
    if (last.size() == n) {
      std::size_t differ = 0;
      for (std::size_t i = 0; i < n; ++i) {
        differ += MaskByte(masks.texels[i], byte) != last[i] ? 1 : 0;
      }
      if (differ * 10 > n * 9) {
        base.clear();
        last.clear();
      }
    }
    if (base.size() != n) {
      if (mask == nullptr) {
        message = "Nothing of it is on the layer.";
        return 0;
      }
      base.resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        base[i] = MaskByte(masks.texels[i], byte);
      }
      last.clear();
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
    const float cell = mapSize / static_cast<float>(masks.width);
    int changed = 0;
    for (int z = 0; z < masks.height; ++z) {
      for (int x = 0; x < masks.width; ++x) {
        const std::size_t i = static_cast<std::size_t>(z) * static_cast<std::size_t>(masks.width) + x;
        std::uint64_t& texel = masks.texels[i];
        const std::uint8_t now = MaskByte(texel, byte);
        if (last.size() == n && now != last[i]) {
          continue; // painted since the last apply: the user's
        }
        std::uint8_t stored = base[i];
        if (mask != nullptr) {
          const float m =
            std::clamp(
              SampleField(*mask, (static_cast<float>(x) + 0.5f) * cell, (static_cast<float>(z) + 0.5f) * cell),
              0.0f,
              1.0f
            ) *
            std::clamp(strength, 0.0f, 1.0f);
          const float b = MaskWeight(base[i], range) / 255.0f;
          stored = MaskStoredFor((b + (1.0f - b) * m) * 255.0f, range, now);
        }
        if (stored != now) {
          texel = WithMaskByte(texel, byte, stored);
          ++changed;
        }
      }
    }
    if (mask == nullptr) {
      base.clear();
      last.clear();
    } else {
      last.resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        last[i] = MaskByte(masks.texels[i], byte);
      }
    }
    WholeMaskChanged(whole);
    message = std::string(mask == nullptr ? "Took the water mask off layer " : "Wrote the water mask into layer ") +
      std::to_string(layer) + ": " + std::to_string(changed) + " texels changed";
    return changed;
  }

  int EdMapScene::WriteMasksTogether(
    const std::vector<std::pair<int, field::Grid>>& layers,
    const MaskWriteMode mode,
    const bool takeAway,
    std::string& message
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      message = "No map's masks to write into.";
      return -1;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
    // From the top layer down, so "higher layers take away" reads the new paint above.
    std::vector<std::pair<int, field::Grid>> ordered = layers;
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
      return a.first > b.first;
    });
    std::size_t changed = 0;
    for (const auto& [layer, mask] : ordered) {
      changed += WriteMaskLayer(
        masks.texels.data(),
        masks.width,
        masks.height,
        mapSize,
        layer,
        RemappedStrata(TerrainShader()),
        mask,
        mode,
        1.0f,
        takeAway
      );
    }
    WholeMaskChanged(whole);
    message = std::to_string(ordered.size()) + " layers written: " + std::to_string(changed) +
      " texels changed (one undo step)";
    return static_cast<int>(changed);
  }

  int EdMapScene::WriteGeneratedMask(
    const field::Grid& mask,
    const int layer,
    const MaskWriteMode mode,
    const float strength,
    const bool takeAway,
    std::string& message,
    const bool ownStep
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      message = "No map's masks to write into.";
      return -1;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
    const std::size_t changed = WriteMaskLayer(
      masks.texels.data(),
      masks.width,
      masks.height,
      mapSize,
      layer,
      RemappedStrata(TerrainShader()),
      mask,
      mode,
      strength,
      takeAway
    );
    // The brush's symmetry, on this layer only: its byte copied from the source part to every copy.
    if (mTools != nullptr) {
      const HeightBrush brush = mTools->CurrentHeightBrush();
      if (brush.symmetry != Symmetry::None) {
        const int byte = layer - 1;
        std::vector<std::uint64_t> one(masks.texels.size());
        for (std::size_t i = 0; i < one.size(); ++i) {
          one[i] = MaskByte(masks.texels[i], byte);
        }
        (void)MakeMasksSymmetric(one.data(), masks.width, masks.height, brush.symmetry, brush.turns);
        for (std::size_t i = 0; i < one.size(); ++i) {
          masks.texels[i] = WithMaskByte(masks.texels[i], byte, static_cast<std::uint8_t>(one[i]));
        }
      }
    }
    if (ownStep) {
      WholeMaskChanged(whole);
    } else {
      // The caller ends the step (a terrain graph's Build).
      mDocument.MaskUndo().EndStroke(masks.texels.data());
      UploadMasks({whole}, 0xFFu);
      mDocument.SetModified(true);
      UpdateCoverage();
    }
    message = "Wrote the mask into layer " + std::to_string(layer) + ": " + std::to_string(changed) + " texels changed";
    return static_cast<int>(changed);
  }

  int EdMapScene::WriteRecipeMasks(
    const std::map<int, field::Grid>& target,
    const std::array<bool, 9>& textured,
    const int cap,
    std::array<float, 9>& shares,
    std::string& message,
    const bool ownStep
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      message = "No map's masks to write into.";
      return -1;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
    const std::size_t changed = WriteRecipe(
      masks.texels.data(),
      masks.width,
      masks.height,
      mapSize,
      RemappedStrata(TerrainShader()),
      cap,
      textured,
      target,
      shares
    );
    // The brush's symmetry: the recipe's layers copied together from the source part, so each copy keeps the cascade.
    if (mTools != nullptr) {
      const HeightBrush brush = mTools->CurrentHeightBrush();
      std::uint64_t layers = 0;
      for (const auto& [layer, weight] : target) {
        if (layer >= 1 && layer <= 8) {
          layers |= std::uint64_t{0xFF} << (8 * (layer - 1));
        }
      }
      if (brush.symmetry != Symmetry::None && layers != 0) {
        std::vector<std::uint64_t> part(masks.texels.size());
        for (std::size_t i = 0; i < part.size(); ++i) {
          part[i] = masks.texels[i] & layers;
        }
        (void)MakeMasksSymmetric(part.data(), masks.width, masks.height, brush.symmetry, brush.turns);
        for (std::size_t i = 0; i < part.size(); ++i) {
          masks.texels[i] = (masks.texels[i] & ~layers) | (part[i] & layers);
        }
      }
    }
    if (ownStep) {
      WholeMaskChanged(whole);
    } else {
      // The caller ends the step (with the heights of the same build).
      mDocument.MaskUndo().EndStroke(masks.texels.data());
      UploadMasks({whole}, 0xFFu);
      mDocument.SetModified(true);
      UpdateCoverage();
    }
    message = std::to_string(changed) + " texels changed";
    return static_cast<int>(changed);
  }

  void EdMapScene::RunSymmetryCheck()
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return;
    }
    mCheckedWith = mTools->CurrentHeightBrush();
    if (mTools->TextureToolActive()) {
      LoadMasks();
      const EdDocument::MaskGrid& masks = mDocument.Masks();
      if (masks.texels.empty()) {
        return;
      }
      MaskSymmetryReport report =
        CheckMaskSymmetry(masks.texels.data(), masks.width, masks.height, mCheckedWith.symmetry, mCheckedWith.turns);
      // The overlay is drawn in height samples.
      const int perTexel = std::max(1, (field->width - 1) / masks.width);
      mDifferences.clear();
      for (const SampleRect& block : report.blocks) {
        mDifferences.push_back(
          {block.x0 * perTexel,
           block.z0 * perTexel,
           std::min(field->width - 1, (block.x1 + 1) * perTexel),
           std::min(field->height - 1, (block.z1 + 1) * perTexel)}
        );
      }
      mCheckDone = true;
      mTools->SetCheckResult(report.checked, report.differing, report.largest, mCheckedWith, true);
      gpg::Logf(
        "editor: mask symmetry check (mode %d): %d of %d texels differ, by up to %d of 255",
        std::to_underlying(mCheckedWith.symmetry),
        report.differing,
        report.checked,
        report.largest
      );
      return;
    }
    SymmetryReport report =
      CheckSymmetry(field->data, field->width, field->height, mCheckedWith.symmetry, mCheckedWith.turns);
    mDifferences = std::move(report.blocks);
    mCheckDone = true;
    mTools->SetCheckResult(report.checked, report.differing, report.largest, mCheckedWith);
    gpg::Logf(
      "editor: symmetry check (mode %d, %d turns): %d of %d vertices differ, by up to %d words; %zu blocks marked",
      std::to_underlying(mCheckedWith.symmetry),
      mCheckedWith.turns,
      report.differing,
      report.checked,
      report.largest,
      mDifferences.size()
    );
  }

  void EdMapScene::RepairSymmetry()
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mPainting) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    if (EffectiveSymmetry(brush.symmetry, field->width, field->height) == Symmetry::None) {
      return;
    }
    // Make symmetric's options; the detected centre when the chosen symmetry is the detected one.
    float offsetX = 0.0f;
    float offsetZ = 0.0f;
    SymmetrizeOptions options = mTools->CurrentSymmetrize(offsetX, offsetZ);
    options.centreX = 0.5f * static_cast<float>(field->width - 1) + offsetX;
    options.centreZ = 0.5f * static_cast<float>(field->height - 1) + offsetZ;
    if (mTools->TextureToolActive()) {
      LoadMasks();
      EdDocument::MaskGrid& masks = mDocument.Masks();
      if (masks.texels.empty()) {
        return;
      }
      if (SymmetrizeMaskLayers(options)) {
        RunSymmetryCheck();
      }
      return;
    }
    // One undo step over the whole map.
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    const auto made = SymmetrizeHeights(field->data, field->width, field->height, options);
    mDocument.Heights().EndStroke(field->data);
    if (!made) {
      gpg::Warnf("editor: make symmetric: %s", made.error().c_str());
      return;
    }
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    RefreshHeights({whole});
    mDocument.SetModified(true);
    gpg::Logf(
      "editor: made the heights symmetric (mode %d, part %d, combine %d, seam %.0f, centre %.1f,%.1f)",
      std::to_underlying(options.symmetry),
      options.part + 1,
      std::to_underlying(options.combine),
      static_cast<double>(options.seam),
      static_cast<double>(options.centreX),
      static_cast<double>(options.centreZ)
    );
    if (mTools->SymmetrizeMasksToo()) {
      (void)SymmetrizeMaskLayers(options);
    }
    if (mTools->SymmetrizeTypesToo()) {
      int typesWidth = 0;
      int typesHeight = 0;
      if (std::uint8_t* const cells = mDocument.TerrainTypeCells(typesWidth, typesHeight); cells != nullptr) {
        std::vector<std::uint8_t> before = mDocument.TerrainTypesNow();
        if (
          const auto cellsMade = SymmetrizeCells(cells, typesWidth, typesHeight, field->width, field->height, options)
        ) {
          mDocument.TerrainTypesEdited(std::move(before));
          mDocument.TerrainTypesChanged();
          gpg::Logf("editor: made the terrain types symmetric (%d x %d cells)", typesWidth, typesHeight);
        } else {
          gpg::Warnf("editor: make symmetric, terrain types: %s", cellsMade.error().c_str());
        }
      }
    }
    RunSymmetryCheck();
  }

  bool EdMapScene::SymmetrizeMaskLayers(
    const SymmetrizeOptions& options
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (field == nullptr || masks.texels.empty()) {
      return false;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    const auto made =
      SymmetrizeMasks(masks.texels.data(), masks.width, masks.height, field->width, field->height, options);
    WholeMaskChanged(whole);
    if (!made) {
      gpg::Warnf("editor: make symmetric, masks: %s", made.error().c_str());
      return false;
    }
    gpg::Logf("editor: made the texture masks symmetric (%d x %d texels)", masks.width, masks.height);
    return true;
  }

  std::expected<std::string, std::string> EdMapScene::ImportHeights(
    const std::filesystem::path& file,
    const float scale
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting) {
      return std::unexpected("No map is open in the view.");
    }
    auto read = ReadHeightImage(file, field->width, field->height);
    if (!read) {
      return std::unexpected("Import failed: " + read.error());
    }
    HeightImage& image = *read;
    const int readWidth = image.width;
    const int readHeight = image.height;
    image = ResampleHeights(image, field->width, field->height);
    ScaleHeights(image, scale);
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    std::copy(image.words.begin(), image.words.end(), field->data);
    mDocument.Heights().EndStroke(field->data);
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    RefreshHeights({whole});
    mDocument.SetModified(true);
    if (mCheckDone) {
      RunSymmetryCheck();
    }
    return "Imported heights from " + file.string() + " (" + std::to_string(readWidth) + " x " +
      std::to_string(readHeight) + (readWidth != field->width || readHeight != field->height ? ", resampled" : "") +
      ")";
  }

  std::expected<std::string, std::string> EdMapScene::FlattenWhole(
    const float height
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting) {
      return std::unexpected("No map is open in the view.");
    }
    // Heights are stored in 1/128 units in 16 bits.
    const auto word = static_cast<std::uint16_t>(std::clamp(std::lround(height * 128.0f), 0L, 65535L));
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    std::fill(field->data, field->data + static_cast<std::size_t>(field->width) * field->height, word);
    mDocument.Heights().EndStroke(field->data);
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    RefreshHeights({whole});
    mDocument.SetModified(true);
    if (mCheckDone) {
      RunSymmetryCheck();
    }
    char text[96];
    (void)std::snprintf(text, sizeof(text), "Flattened the map to height %.2f", static_cast<float>(word) / 128.0f);
    gpg::Logf("editor: %s", text);
    return text;
  }

  std::expected<void, std::string> EdMapScene::WriteHeightRect(
    const int x0,
    const int z0,
    const int w,
    const int h,
    const std::vector<float>& heights
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting) {
      return std::unexpected("no map is open in the view");
    }
    if (w <= 0 || h <= 0 || heights.size() < static_cast<std::size_t>(w) * static_cast<std::size_t>(h)) {
      return std::unexpected("the list has fewer than w x h heights");
    }
    const SampleRect rect{
      std::max(0, x0), std::max(0, z0), std::min(field->width - 1, x0 + w - 1), std::min(field->height - 1, z0 + h - 1)
    };
    if (rect.x0 > rect.x1 || rect.z0 > rect.z1) {
      return std::unexpected("the rectangle is off the map");
    }
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, rect);
    for (int z = rect.z0; z <= rect.z1; ++z) {
      for (int x = rect.x0; x <= rect.x1; ++x) {
        const float value = heights[static_cast<std::size_t>(z - z0) * w + static_cast<std::size_t>(x - x0)];
        field->data[static_cast<std::size_t>(z) * field->width + x] =
          static_cast<std::uint16_t>(std::clamp(std::lround(value * 128.0f), 0L, 65535L));
      }
    }
    mDocument.Heights().EndStroke(field->data);
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    RefreshHeights({rect});
    mDocument.SetModified(true);
    return {};
  }

  std::expected<void, std::string> EdMapScene::WriteMaskRect(
    const int layer,
    const int x0,
    const int z0,
    const int w,
    const int h,
    const std::vector<float>& weights
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      return std::unexpected("no map's paint to change");
    }
    if (layer < 1 || layer > 8) {
      return std::unexpected("layer is 1 to 8");
    }
    if (w <= 0 || h <= 0 || weights.size() < static_cast<std::size_t>(w) * static_cast<std::size_t>(h)) {
      return std::unexpected("the list has fewer than w x h weights");
    }
    const SampleRect rect{
      std::max(0, x0), std::max(0, z0), std::min(masks.width - 1, x0 + w - 1), std::min(masks.height - 1, z0 + h - 1)
    };
    if (rect.x0 > rect.x1 || rect.z0 > rect.z1) {
      return std::unexpected("the rectangle is off the paint");
    }
    const int slot = layer - 1;
    const bool remapped = (RemappedStrata(TerrainShader()) & (1U << slot)) != 0;
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
    for (int z = rect.z0; z <= rect.z1; ++z) {
      for (int x = rect.x0; x <= rect.x1; ++x) {
        const float weight = weights[static_cast<std::size_t>(z - z0) * w + static_cast<std::size_t>(x - x0)];
        std::uint64_t& texel = masks.texels[static_cast<std::size_t>(z) * masks.width + x];
        texel = WithMaskByte(
          texel, slot, MaskStoredFor(std::clamp(weight, 0.0f, 1.0f) * 255.0f, remapped, MaskByte(texel, slot))
        );
      }
    }
    WholeMaskChanged(rect);
    return {};
  }

  bool EdMapScene::MaskSize(
    int& width,
    int& height
  )
  {
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    width = masks.width;
    height = masks.height;
    return !masks.texels.empty();
  }

  float EdMapScene::LayerWeightAt(
    const int layer,
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || layer < 1 || layer > 8) {
      return -1.0f;
    }
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    const float extent = static_cast<float>(field->width - 1);
    if (masks.texels.empty() || x < 0.0f || z < 0.0f || x > extent || z > static_cast<float>(field->height - 1)) {
      return -1.0f;
    }
    const int tx = std::clamp(static_cast<int>(x / extent * static_cast<float>(masks.width)), 0, masks.width - 1);
    const int tz = std::clamp(
      static_cast<int>(z / static_cast<float>(field->height - 1) * static_cast<float>(masks.height)),
      0,
      masks.height - 1
    );
    const bool remapped = (RemappedStrata(TerrainShader()) & (1U << (layer - 1))) != 0;
    return MaskWeight(MaskByte(masks.texels[static_cast<std::size_t>(tz) * masks.width + tx], layer - 1), remapped) /
      255.0f;
  }

  bool EdMapScene::HeightRange(
    float& low,
    float& high,
    float& mean
  ) const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || field->width <= 0 || field->height <= 0) {
      return false;
    }
    const std::size_t count = static_cast<std::size_t>(field->width) * field->height;
    std::uint16_t lo = 65535;
    std::uint16_t hi = 0;
    double sum = 0.0;
    for (std::size_t i = 0; i < count; ++i) {
      lo = std::min(lo, field->data[i]);
      hi = std::max(hi, field->data[i]);
      sum += field->data[i];
    }
    low = static_cast<float>(lo) / 128.0f;
    high = static_cast<float>(hi) / 128.0f;
    mean = static_cast<float>(sum / static_cast<double>(count) / 128.0);
    return true;
  }

  std::expected<std::string, std::string> EdMapScene::ExportHeights(
    const std::filesystem::path& file,
    const int width,
    const float scale
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return std::unexpected("No map is open in the view.");
    }
    HeightImage image;
    image.width = field->width;
    image.height = field->height;
    image.words.assign(
      field->data, field->data + static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height)
    );
    if (width > 1 && width != field->width) {
      // The map's proportions kept: a rectangular map's image is as much shorter.
      const int height = std::max(
        2, static_cast<int>(std::lround(static_cast<double>(width - 1) * (field->height - 1) / (field->width - 1))) + 1
      );
      image = ResampleHeights(image, width, height);
    }
    ScaleHeights(image, scale);
    if (const auto wrote = WriteHeightImage(file, image, mTools != nullptr && mTools->ExportEightBit()); !wrote) {
      return std::unexpected("Export failed: " + wrote.error());
    }
    return "Exported heights to " + file.string() + " (" + std::to_string(image.width) + " x " +
      std::to_string(image.height) + ")";
  }

  std::shared_ptr<TerrainSource> EdMapScene::TerrainHeights()
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || field->width < 2 || field->height < 2) {
      return nullptr;
    }
    auto terrain = std::make_shared<TerrainSource>();
    terrain->width = field->width;
    terrain->height = field->height;
    terrain->units = 1.0f; // a sample per game unit
    terrain->heights.resize(static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height));
    for (std::size_t i = 0; i < terrain->heights.size(); ++i) {
      terrain->heights[i] = static_cast<float>(field->data[i]) / 128.0f;
    }
    // The stratum masks as painted (read from the map once, then the editor's own).
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    terrain->maskWidth = masks.width;
    terrain->maskHeight = masks.height;
    terrain->masks = masks.texels;
    return terrain;
  }

  bool EdMapScene::TestRaise(
    const float x,
    const float z,
    const float seconds
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return false;
    }
    return TestBrush(HeightBrushMode::Raise, x, z, seconds, false);
  }

  bool EdMapScene::TestBrush(
    const HeightBrushMode mode,
    const float x,
    const float z,
    const float seconds,
    const bool panelBrush
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return false;
    }
    const std::vector<std::uint16_t> start(field->data, field->data + field->width * field->height);
    HeightBrush brush = mTools != nullptr ? mTools->CurrentHeightBrush() : HeightBrush{};
    brush.mode = mode;
    brush.strength = 1.0f;
    // TestRaise (the play tests): the default brush, as before; /brushtest: the panel's brush.
    const bool raise = !panelBrush;
    if (raise) {
      brush = HeightBrush{};
      brush.mode = mode;
      brush.strength = 1.0f;
    }
    // Flatten and Plateau: the ground under the stroke's first point, as a stroke takes it.
    brush.flattenTo =
      static_cast<float>(field->data
                           [static_cast<std::size_t>(std::clamp(static_cast<int>(z), 0, field->height - 1)) *
                              static_cast<std::size_t>(field->width) +
                            static_cast<std::size_t>(std::clamp(static_cast<int>(x), 0, field->width - 1))]);
    brush.noiseSeed = mNoiseSeed++;
    const ErosionStrokePtr stroke = IsErosionMode(mode) ? MakeErosionStroke() : nullptr;
    const std::size_t undoBefore = mDocument.Heights().UndoCount();
    mDocument.Heights().BeginStroke();
    for (const SampleRect& rect : HeightBrushRects(field->width, field->height, x, z, brush)) {
      mDocument.Heights().BeforeWrite(field->data, rect);
    }
    std::vector<SampleRect> rects;
    const float stepSeconds = raise ? 0.1f : 1.0f / 60.0f;
    if (mode == HeightBrushMode::Stamp && brush.stamp != nullptr) {
      // A drag of 40 samples along +x over `seconds`, as the mouse would make it.
      mStamped = false;
      mDabbed = false;
      int dabSteps = 0;
      for (float done = 0.0f; done <= seconds; done += stepSeconds, ++dabSteps) {
        const std::vector<SampleRect> step = PaintStamps(brush, x + 40.0f * std::min(1.0f, done / seconds), z);
        rects.insert(rects.end(), step.begin(), step.end());
      }
      mStamped = false;
      mDabbed = false;
      gpg::Logf("editor: brush test: stamp stroke of %d steps put down %zu rectangles", dabSteps, rects.size());
    }
    for (float left = mode == HeightBrushMode::Stamp ? 0.0f : seconds; left > 0.0f; left -= stepSeconds) {
      if (!raise) {
        // Each step saves what it writes first, as PaintStroke does.
        for (const SampleRect& rect : HeightBrushRects(field->width, field->height, x, z, brush)) {
          mDocument.Heights().BeforeWrite(field->data, rect);
        }
        brush.seed = ++mWaterErodeSeed;
      }
      const std::vector<SampleRect> step = ApplyHeightBrush(
        field->data, field->width, field->height, x, z, brush, std::min(left, stepSeconds), stroke.get()
      );
      rects.insert(rects.end(), step.begin(), step.end());
    }
    mDocument.Heights().EndStroke(field->data);
    // One step in the editor's undo order, as a stroke of the mouse makes it (EndStroke()).
    if (mDocument.Heights().UndoCount() > undoBefore) {
      mDocument.EditEnded(EdDocument::EditKind::Heights);
    }
    if (!raise) {
      std::size_t changed = 0;
      std::int64_t words = 0;
      float farthest = 0.0f;
      for (int sz = 0; sz < field->height; ++sz) {
        for (int sx = 0; sx < field->width; ++sx) {
          const std::size_t i = static_cast<std::size_t>(sz) * static_cast<std::size_t>(field->width) + sx;
          if (field->data[i] != start[i]) {
            ++changed;
            words += static_cast<std::int64_t>(field->data[i]) - static_cast<std::int64_t>(start[i]);
            // The nearest of the brush's copies.
            float centreX[kMaxSymmetryCopies];
            float centreZ[kMaxSymmetryCopies];
            const int centres =
              HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
            float nearest = 1.0e9f;
            for (int c = 0; c < centres; ++c) {
              nearest =
                std::min(nearest, std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]));
            }
            farthest = std::max(farthest, nearest);
          }
        }
      }
      gpg::Logf(
        "editor: brush test: mode %d at %.0f,%.0f, radius %.0f, symmetry %d: %zu samples changed, ground %+.1f units, "
        "farthest change %.1f from a centre",
        std::to_underlying(mode),
        static_cast<double>(x),
        static_cast<double>(z),
        static_cast<double>(brush.radius),
        std::to_underlying(brush.symmetry),
        changed,
        static_cast<double>(words) / 128.0,
        static_cast<double>(farthest)
      );
    }
    if (rects.empty()) {
      return false;
    }
    mDocument.SetModified(true);
    RefreshHeights(rects);
    return true;
  }

  void EdMapScene::TestLiveMask(
    const float x,
    const float z
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty()) {
      LoadMasks();
    }
    if (masks.texels.empty()) {
      gpg::Warnf("editor: mask test: the map has no masks");
      return;
    }
    const float perSample = static_cast<float>(masks.width) / static_cast<float>(field->width - 1);
    const int cx = std::clamp(static_cast<int>(x * perSample), 12, masks.width - 13);
    const int cz = std::clamp(static_cast<int>(z * perSample), 12, masks.height - 13);
    const SampleRect rect{cx - 12, cz - 12, cx + 12, cz + 12};
    constexpr int kLayer = 3; // stratum 4
    const auto read = [&](moho::IWldTerrainRes& terrain) {
      const moho::StratumMaterial& strata = terrain.GetStratumMaterial();
      std::vector<std::uint8_t> plane(static_cast<std::size_t>(strata.mStratumMaskWidth) * strata.mStratumMaskHeight);
      if (plane.empty() || strata.mStratumMaskWidth != static_cast<std::uint32_t>(masks.width)) {
        return -1;
      }
      terrain.GetStratumMask(kLayer, plane.data());
      return static_cast<int>(
        plane[static_cast<std::size_t>(cz) * static_cast<std::size_t>(masks.width) + static_cast<std::size_t>(cx)]
      );
    };
    const bool live = mOverPlay && mSessionMap != nullptr && mSessionMap->mTerrainRes != nullptr;
    const int playBefore = live ? read(*mSessionMap->mTerrainRes) : -2;
    for (int tz = rect.z0; tz <= rect.z1; ++tz) {
      for (int tx = rect.x0; tx <= rect.x1; ++tx) {
        std::uint64_t& texel =
          masks.texels
            [static_cast<std::size_t>(tz) * static_cast<std::size_t>(masks.width) + static_cast<std::size_t>(tx)];
        texel = WithMaskByte(texel, kLayer, 255);
      }
    }
    mDocument.SetModified(true);
    UploadMasks({rect}, 1u << kLayer);
    gpg::Logf(
      "editor: mask test: stratum 4 at texel %d,%d: the editor's %d, the play's %d -> %d",
      cx,
      cz,
      read(*mMap->mTerrainRes),
      playBefore,
      live ? read(*mSessionMap->mTerrainRes) : -2
    );
  }

  void EdMapScene::RefreshHeights(
    const std::vector<SampleRect>& rects
  )
  {
    mWeightStale = true; // the overlays lie on the ground
    mOutsideStale = true;
    mWaterBodiesStale = true;
    moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    // The samples are written in place; the field's own setter, given them back, refreshes its tiers of
    // min/max heights and its revision (the shadow and vision passes watch it). Then the terrain redraws
    // those rectangles: tiles and normal map, one sample wider for the normals at their edge.
    std::vector<gpg::Rect2i> changed;
    changed.reserve(rects.size());
    for (const SampleRect& rect : rects) {
      field->SetElevationRectRaw(
        gpg::Rect2i{rect.x0, rect.z0, rect.x1, rect.z1},
        field->data + rect.x0 + static_cast<std::ptrdiff_t>(rect.z0) * field->width,
        field->width
      );
      changed.push_back(
        gpg::Rect2i{
          std::max(0, rect.x0 - 1),
          std::max(0, rect.z0 - 1),
          std::min(field->width - 1, rect.x1 + 1),
          std::min(field->height - 1, rect.z1 + 1)
        }
      );
    }
    mMap->mTerrainRes->NotifyMapChanges(changed.data(), changed.size());
    // What stands there follows the ground (Studio's Resnap).
    ReseatOnGround(rects);
    // In front of a play: the same heights into it (its rendered terrain now, its sim at its next beat; WPE.40).
    if (mOverPlay && mSessionMap != nullptr) {
      auto live = rects | std::views::transform([&](const SampleRect& rect) {
        return HeightRect{rect.x0, rect.z0, rect.x1, rect.z1};
      }) |
        std::ranges::to<std::vector<HeightRect>>();
      LiveHeights(*mSessionMap, *field, live);
    }
  }

  void EdMapScene::Update(
    const float frameSeconds,
    const bool playIdle,
    const bool editorViewInPlay
  )
  {
    if (playIdle) {
      DropLiveHeights(); // a play's height queue doesn't outlive it
    }
    // The mesh terrain's models and the height field's switch follow the mode every frame (not only while the
    // overlays draw).
    if (mMap != nullptr) {
      SyncMeshView();
    } else if (mMeshHidesTerrain) {
      mMeshHidesTerrain = false;
      moho::ren_TerrainSurface = true;
    }
    // The editor's map shows between plays, and in front of a running play when its view is asked for (user ask
    // 2026-11-11: switch between the editor's view and the game's while it plays).
    moho::CWldMap* const wanted =
      (playIdle || editorViewInPlay) && mDocument.GetState() == EdDocument::State::Open ? mDocument.Map() : nullptr;
    if (mMap != nullptr && mMap != wanted) {
      if (mOverPlay && !playIdle) {
        gpg::Logf(
          "editor: leaving the play's front: %s",
          !editorViewInPlay ? "the game's view asked for" : "the document isn't open"
        );
      }
      Detach();
    }
    // A play's session clears the renderer's map when it ends (0x00893BE6); attach once it has. In front of a play the
    // renderer's map is the session's: kept to give back, the session's world views and interface left undrawn.
    if (mMap == nullptr && wanted != nullptr && (moho::sWldMap == nullptr || !playIdle)) {
      moho::CWldMap* const sessionMap = playIdle ? nullptr : moho::sWldMap;
      Attach(*wanted);
      if (mMap != nullptr && !playIdle) {
        mSessionMap = sessionMap;
        mDocument.SetLiveMap(sessionMap);
        mLiveMaskSizeWarned = false;
        mOverPlay = true;
        mUiWas = moho::ren_Ui;
        moho::ren_Ui = false;
        moho::gViewportOnlyView = mWorldView.get();
        gpg::Logf("editor: the editor's view in front of the play (the game runs on behind it)");
      }
    }
    if (mMap == nullptr) {
      return;
    }
    // The play ended while the editor's view was in front: its teardown cleared the renderer's map; this one's again.
    if (mOverPlay && playIdle) {
      mOverPlay = false;
      mSessionMap = nullptr;
      mDocument.SetLiveMap(nullptr);
      moho::gViewportOnlyView = nullptr;
      moho::ren_Ui = mUiWas;
      moho::REN_SetWldMap(mMap);
      gpg::Logf("editor: the play ended behind the editor's view");
    }
    // The play's own units, while its game runs behind this view: picked, selected, moved (EdLiveUnits).
    if (mOverPlay) {
      if (mTools != nullptr) {
        SetLiveUnitsHidden(!mTools->ShowGameUnits());
      }
      mLiveNow = LiveUnits();
      mLiveSelection.erase(
        std::remove_if(
          mLiveSelection.begin(),
          mLiveSelection.end(),
          [&](const std::uint32_t id) {
        return std::none_of(mLiveNow.begin(), mLiveNow.end(), [&](const LiveUnit& u) {
          return u.id == id;
        });
      }
        ),
        mLiveSelection.end()
      );
    } else if (!mLiveNow.empty() || !mLiveSelection.empty()) {
      mLiveNow.clear();
      mLiveSelection.clear();
      mDragLive = false;
    }
    if (mTools != nullptr) {
      mTools->SetLiveSelection(mLiveSelection);
    }
    UpdateDeposits();
    UpdateMarkerModels();
    UpdateEffects();
    if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
      const int width = device->GetHeadWidth(0);
      const int height = device->GetHeadHeight(0);
      if (width != mWidth || height != mHeight) {
        mWidth = width;
        mHeight = height;
        mCamera->CameraSetViewport(
          Wm3::Vector2f(0.0f, 0.0f), Wm3::Vector2f(static_cast<float>(width), static_cast<float>(height))
        );
        ApplyCamera();
      }
    }
    UpdateMiniMap();
    if (!mPropsDone) {
      // `/holdmodels <seconds>` (test runs): the models made that long after the map shows, so the view's
      // "Loading models" notice can be seen on a machine where the blueprints are ready at once.
      static const double hold = [] {
        fa::vector<fa::string> value;
        return moho::CFG_GetArgOption("/holdmodels", 1, &value) && !value.empty() ? std::atof(value[0].c_str()) : 0.0;
      }();
      static const auto started = std::chrono::steady_clock::now();
      if (hold <= 0.0 || std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count() >= hold) {
        CreateProps();
      }
    }
    UpdatePropPreview();
    UpdatePropHighlight();
    MoveWithKeys(frameSeconds);
    if (mPainting) {
      PaintStroke(frameSeconds);
    }
    if (mDecalBrushing) {
      if (float gx = 0.0f, gz = 0.0f; CursorGround(gx, gz)) {
        DecalBrushAt(gx, gz);
      }
    }
    if (mPaintingMask) {
      PaintMask(frameSeconds);
    }
    if (mPaintingTypes) {
      PaintTypes();
    }
    RefreshWaterBodies();
    // The ruler's far end, and the status bar's cursor: where it is on the ground, how high, how steep.
    if (mTools != nullptr) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      const moho::CHeightField* const heights = mMap->mTerrainRes->GetHeightField();
      if (
        heights != nullptr && CursorGround(groundX, groundZ) && groundX >= 0.0f && groundZ >= 0.0f &&
        groundX < static_cast<float>(heights->width - 1) && groundZ < static_cast<float>(heights->height - 1)
      ) {
        if (mRuling) {
          if ((::GetKeyState(VK_LBUTTON) & 0x8000) != 0) {
            mRulerTo[0] = groundX;
            mRulerTo[1] = groundZ;
            mTools->SetRulerText(RulerText());
          } else {
            mRuling = false;
            ::ReleaseCapture();
            gpg::Logf(
              "editor: ruler from %.1f, %.1f to %.1f, %.1f: %s",
              static_cast<double>(mRulerFrom[0]),
              static_cast<double>(mRulerFrom[1]),
              static_cast<double>(mRulerTo[0]),
              static_cast<double>(mRulerTo[1]),
              mTools->RulerText().c_str()
            );
          }
        }
        const float height =
          mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(groundX), static_cast<std::int32_t>(groundZ));
        const float slope =
          CellSlope(heights->data, heights->width, static_cast<int>(groundX), static_cast<int>(groundZ), 1.0f / 128.0f);
        char text[96];
        (void)std::snprintf(
          text,
          sizeof(text),
          "x %.1f  z %.1f  height %.2f  slope %.2f",
          static_cast<double>(groundX),
          static_cast<double>(groundZ),
          static_cast<double>(height),
          static_cast<double>(slope)
        );
        mTools->SetCursorText(text);
      } else {
        mTools->SetCursorText({});
      }
    }
    // The view's frame for its overlays (the compass, the minimap), and the minimap's ask to look somewhere.
    if (mTools != nullptr) {
      EdTools::ViewFrame& frame = mTools->View();
      frame = {};
      if (mMap != nullptr && mCamera != nullptr && mWidth > 0 && mHeight > 0) {
        float lookX = 0.0f;
        float lookZ = 0.0f;
        int moveFrom = -1;
        int moveTo = -1;
        if (mTools->TakeLayerMove(moveFrom, moveTo)) {
          (void)MoveLayer(moveFrom, moveTo);
        }
        if (mTools->TakeCameraAsk(lookX, lookZ)) {
          mTargetX = lookX;
          mTargetZ = lookZ;
          ApplyCamera();
        }
        const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
        frame.minX = bounds.Min.x;
        frame.minZ = bounds.Min.z;
        frame.maxX = bounds.Max.x;
        frame.maxZ = bounds.Max.z;
        // Up and right on the ground: the heading's, or the camera's own around the view's middle.
        frame.upX = -std::sin(mHeading);
        frame.upZ = -std::cos(mHeading);
        frame.rightX = -frame.upZ;
        frame.rightZ = frame.upX;
        const float cx = static_cast<float>(mWidth) * 0.5f;
        const float cy = static_cast<float>(mHeight) * 0.5f;
        float centerX = 0.0f, centerZ = 0.0f, upX = 0.0f, upZ = 0.0f, rightX = 0.0f, rightZ = 0.0f;
        if (
          GroundAt(cx, cy, centerX, centerZ) && GroundAt(cx, cy - 40.0f, upX, upZ) &&
          GroundAt(cx + 40.0f, cy, rightX, rightZ)
        ) {
          const float upLength = std::hypot(upX - centerX, upZ - centerZ);
          const float rightLength = std::hypot(rightX - centerX, rightZ - centerZ);
          if (upLength > 1e-4f && rightLength > 1e-4f) {
            frame.upX = (upX - centerX) / upLength;
            frame.upZ = (upZ - centerZ) / upLength;
            frame.rightX = (rightX - centerX) / rightLength;
            frame.rightZ = (rightZ - centerZ) / rightLength;
          }
        }
        // The ground under the corners; a top corner showing sky takes the first ground below it.
        const float w = static_cast<float>(mWidth);
        const float h = static_cast<float>(mHeight);
        const float corners[4][2] = {{0.0f, 0.0f}, {w, 0.0f}, {w, h}, {0.0f, h}};
        for (const auto& corner : corners) {
          float y = corner[1];
          float gx = 0.0f;
          float gz = 0.0f;
          bool hit = GroundAt(corner[0], y, gx, gz);
          while (!hit && corner[1] == 0.0f && y < h * 0.6f) {
            y += h * 0.05f;
            hit = GroundAt(corner[0], y, gx, gz);
          }
          if (hit) {
            frame.cornerX[frame.corners] = gx;
            frame.cornerZ[frame.corners] = gz;
            ++frame.corners;
          }
        }
        // The ground's forward from the view's far edge to its near one (the corners'), and right square to it: the
        // compass's axes stay a right angle apart (picked 40 px apart near the horizon, they skewed; user report).
        if (frame.corners == 4) {
          const float farX = (frame.cornerX[0] + frame.cornerX[1]) * 0.5f;
          const float farZ = (frame.cornerZ[0] + frame.cornerZ[1]) * 0.5f;
          const float nearX = (frame.cornerX[2] + frame.cornerX[3]) * 0.5f;
          const float nearZ = (frame.cornerZ[2] + frame.cornerZ[3]) * 0.5f;
          const float length = std::hypot(farX - nearX, farZ - nearZ);
          if (length > 1e-3f) {
            frame.upX = (farX - nearX) / length;
            frame.upZ = (farZ - nearZ) / length;
          }
        }
        {
          // Right: square to up, on the side the view's bottom edge runs (bottom-left to bottom-right).
          float rightX = -frame.upZ;
          float rightZ = frame.upX;
          const float edgeX = frame.corners == 4 ? frame.cornerX[2] - frame.cornerX[3] : frame.rightX;
          const float edgeZ = frame.corners == 4 ? frame.cornerZ[2] - frame.cornerZ[3] : frame.rightZ;
          if (rightX * edgeX + rightZ * edgeZ < 0.0f) {
            rightX = -rightX;
            rightZ = -rightZ;
          }
          frame.rightX = rightX;
          frame.rightZ = rightZ;
        }
        frame.valid = true;
      }
    }
    // The type under the cursor, for the panel.
    if (mTools != nullptr && mTools->PaintingTerrainTypes()) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      int width = 0;
      int height = 0;
      const std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
      int under = -1;
      if (
        cells != nullptr && CursorGround(groundX, groundZ) && groundX >= 0.0f && groundZ >= 0.0f &&
        groundX < static_cast<float>(width) && groundZ < static_cast<float>(height)
      ) {
        under = cells
          [static_cast<std::size_t>(groundZ) * static_cast<std::size_t>(width) + static_cast<std::size_t>(groundX)];
      }
      mTools->SetTerrainTypeUnderCursor(under);
    }
    if (
      mObjectStroke && mTools != nullptr && mTools->PropsToolActive() &&
      (mTools->CurrentPropMode() == EdTools::PropMode::Scatter || mTools->CurrentPropMode() == EdTools::PropMode::Erase)
    ) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (CursorGround(groundX, groundZ)) {
        if (mTools->CurrentPropMode() == EdTools::PropMode::Erase || (::GetKeyState(VK_SHIFT) & 0x8000) != 0) {
          EraseProps(groundX, groundZ);
        } else {
          // Scatter by area (FAF Studio's): the brush filled up to a density, never closer than the spacing.
          const float radius = mTools->CurrentHeightBrush().radius;
          if (mTools->PropScatterByArea() && mMap->mProps != nullptr) {
            std::vector<std::pair<float, float>> nearby;
            for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
              if (
                std::hypot(entry.mTransform.pos_.x - groundX, entry.mTransform.pos_.z - groundZ) <
                radius + mTools->PropSpacing()
              ) {
                nearby.emplace_back(entry.mTransform.pos_.x, entry.mTransform.pos_.z);
              }
            }
            mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
            for (const auto& [px, pz] : AreaScatter(
                   groundX, groundZ, radius, mTools->PropAreaDensity(), mTools->PropSpacing(), nearby, mScatterSeed, 6
                 )) {
              PlaceProps(px, pz);
            }
            mScatterDue = 0.0f;
          }
          mScatterDue += mTools->PropScatterByArea() ? 0.0f : mTools->PropDensity() * std::min(frameSeconds, 0.1f);
          while (mScatterDue >= 1.0f) {
            mScatterDue -= 1.0f;
            mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
            const float angle = static_cast<float>(mScatterSeed >> 8) / 16777216.0f * 6.2831853f;
            mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
            const float distance = std::sqrt(static_cast<float>(mScatterSeed >> 8) / 16777216.0f) * radius;
            PlaceProps(groundX + std::cos(angle) * distance, groundZ + std::sin(angle) * distance);
          }
        }
      }
    }
    if (mTools != nullptr && mTools->SelectToolActive()) {
      mTools->SetSelectInfo(SelectionText(), HoverText(), SelectedKind() != PickKind::None);
    }
    if (mTools != nullptr && mMap != nullptr) {
      moho::IDecalManager* const decals = mDocument.Decals();
      mTools->SetMapCounts(
        static_cast<int>(mDocument.SaveData().Markers().size()),
        mMap->mProps != nullptr ? static_cast<int>(mMap->mProps->mEntries.size()) : 0,
        static_cast<int>(mUnitRefs.size()),
        decals != nullptr ? decals->GetDecalCount() : 0
      );
    }
    // The Show menu: prop and unit models hidden by culling their instances (each frame while hidden, so new ones
    // follow).
    if (mTools != nullptr) {
      const bool hideProps = !mTools->ShowProps();
      if (hideProps || mPropsCulled) {
        for (moho::MeshInstance* const instance : mProps) {
          if (instance != nullptr) {
            instance->Cull(hideProps);
          }
        }
        mPropsCulled = hideProps;
      }
      // Units: all hidden by the Show menu, or the ones a previewed lobby setting doesn't create (the Adaptive Map
      // window).
      const bool hideUnits = !mTools->ShowUnits();
      const auto& previewHidden = mTools->PreviewHiddenUnits();
      if (hideUnits || mUnitsCulled || !previewHidden.empty() || mPreviewCulled) {
        std::size_t previewed = 0;
        for (std::size_t i = 0; i < mUnits.size() && i < mUnitRefs.size(); ++i) {
          if (mUnits[i] != nullptr) {
            const bool byPreview =
              !previewHidden.empty() && previewHidden.contains({mUnitRefs[i].army, mUnitRefs[i].name});
            previewed += byPreview ? 1 : 0;
            mUnits[i]->Cull(hideUnits || byPreview);
          }
        }
        if (previewed != mPreviewCulledCount) {
          gpg::Logf("editor: the lobby preview hides %zu of the %zu units drawn", previewed, mUnits.size());
          mPreviewCulledCount = previewed;
        }
        mUnitsCulled = hideUnits;
        mPreviewCulled = !previewHidden.empty();
      }
    }
    if (mTools != nullptr && mTools->TextureToolActive()) {
      LoadMasks();
    }
    if (mTools != nullptr && mTools->TakeRulesRequest()) {
      ApplyRules();
    }
    if (mTools != nullptr) {
      if (mTools->TakeCheckRequest()) {
        RunSymmetryCheck();
      }
      if (mTools->TakeRepairRequest()) {
        RepairSymmetry();
      }
      if (EdTools::ErosionAsk ask = EdTools::ErosionAsk::None; true) {
        std::string solver;
        ErosionValues values;
        if (mTools->TakeErosionAsk(ask, solver, values)) {
          std::string status;
          if (ask == EdTools::ErosionAsk::Revert) {
            status = RevertErosionPreview() ? "Reverted." : "Nothing to revert (other edits came after the preview).";
            gpg::Logf("editor: erosion: %s", status.c_str());
          } else {
            status = RunErosion(solver, values, ask == EdTools::ErosionAsk::Preview);
          }
          mTools->SetErosionStatus(status, mErosionPreviewShown);
        }
      }
      if (mTools->TakeGiveUnits()) {
        (void)GiveSelectedUnits(mTools->UnitArmy());
      }
      if (mTools->TakeWaveDelete() && !mWaveSelection.empty()) {
        std::vector<WaveRecord> before = mDocument.WavesNow();
        std::vector<WaveRecord> after;
        for (std::size_t i = 0; i < before.size(); ++i) {
          if (std::find(mWaveSelection.begin(), mWaveSelection.end(), static_cast<int>(i)) == mWaveSelection.end()) {
            after.push_back(before[i]);
          }
        }
        const std::size_t removed = before.size() - after.size();
        mDocument.ApplyWaves(after);
        mDocument.WavesEdited(std::move(before));
        mWaveSelection.clear();
        gpg::Logf("editor: %zu wave generators deleted, %zu now", removed, after.size());
      }
      if (mTools->TakePathApply()) {
        mTools->SetStrokeStats(ApplyPathNow(mTools->PathPoints(), mTools->CurrentPathOptions()));
        mTools->ClearPathPoints();
      }
      if (const EdTools::ScAsk sc = mTools->TakeScAsk(); sc != EdTools::ScAsk::None) {
        mTools->SetScStatus(RunScTool(sc));
      }
      TickPads(frameSeconds);
      TickPaths();
      TickUnitPreview(frameSeconds);
      if (const EdTools::InteropAsk ask = mTools->TakeInteropAsk(); ask != EdTools::InteropAsk::None) {
        mTools->SetInteropStatus(RunInterop(ask));
      }
      TickInterop(frameSeconds);
      if (EdTools::FillOptions fill; mTools->TakeFillRequest(fill)) {
        mTools->SetFillMessage(ScatterOverMap(fill));
      }
      ArrangeOp arrange = ArrangeOp::Count;
      float step = 1.0f;
      if (mTools->TakeArrangeRequest(arrange, step)) {
        std::string message = ArrangeSelection(arrange, step);
        gpg::Logf("editor: %s: %s", ArrangeTitle(arrange), message.empty() ? "done" : message.c_str());
        mTools->SetArrangeMessage(std::move(message));
      }
    }
    // A session runs the camera manager from its own frame; between plays the editor does.
    moho::CAM_GetManager()->Frame(0.0f, frameSeconds);
  }

  moho::RRuleGameRules* EdMapScene::Rules() const
  {
    if (moho::RRuleGameRules* const kept = moho::RULE_PeekKept(); kept != nullptr) {
      return kept;
    }
    return mOverPlay ? moho::RULE_PeekLent() : nullptr;
  }

  void EdMapScene::CreateProps()
  {
    // The rules every play uses, kept between plays and built at startup; until they are ready, next frame.
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr || mMap == nullptr) {
      return;
    }
    mPropsDone = true;
    CreateUnits();
    if (mMap->mProps == nullptr) {
      return;
    }
    int missing = 0;
    for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
      moho::MeshInstance* const instance = MakePropInstance(entry);
      missing += instance == nullptr ? 1 : 0;
      mProps.push_back(instance);
    }
    gpg::Logf(
      "editor: %zu props drawn, %d without a blueprint or mesh",
      mProps.size() - static_cast<std::size_t>(missing),
      missing
    );
  }

  void EdMapScene::CreateUnits()
  {
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr) {
      return;
    }
    int drawn = 0;
    int missing = 0;
    int unreadable = 0;
    int wrecks = 0;
    for (const SaveEntry& army : mDocument.SaveData().Armies()) {
      UnitGroup group;
      if (const auto read = ParseUnitGroup(army.Get("Units"), group); !read) {
        ++unreadable;
        gpg::Warnf("editor: %s's units unreadable: %s", army.name.c_str(), read.error().c_str());
        continue;
      }
      std::vector<const SaveUnit*> units;
      CollectUnits(group, units);
      for (const SaveUnit* const unit : units) {
        // Blueprint ids are lower case (`ueb2101`).
        std::string lower = unit->type;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        moho::RResId id{};
        id.name.assign(lower.c_str());
        moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(id);
        moho::RMeshBlueprint* mesh =
          blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
        if (mesh == nullptr) {
          ++missing;
          continue;
        }
        // A unit that becomes a wreck in a game is drawn as its wreck: the `<mesh>_wreck` blueprint FAF's
        // Blueprints.lua makes for every unit (ExtractWreckageBlueprint: the Wreckage shader), which the game's wreck
        // props take.
        if (
          const UnitFate fate = FateOfUnit(UnitGroupPath(group, unit->name), true, mDocument.Script());
          fate.kind == UnitFate::Kind::Wreck || fate.kind == UnitFate::Kind::ScriptWreck
        ) {
          moho::RResId wreckId{};
          wreckId.name.assign((std::string(blueprint->Display.MeshBlueprint.name.c_str()) + "_wreck").c_str());
          if (moho::RMeshBlueprint* const wreck = rules->GetMeshBlueprint(wreckId); wreck != nullptr) {
            mesh = wreck;
            ++wrecks;
          }
        }
        const float scale = blueprint->Display.UniformScale;
        moho::MeshInstance* const instance = renderer->CreateMeshInstance(
          0, -1, mesh, Wm3::Vec3f{scale, scale, scale}, false, std::shared_ptr<moho::MeshMaterial>()
        );
        if (instance == nullptr) {
          ++missing;
          continue;
        }
        // As CreateUnitHPR turns Orientation's three angles (heading, pitch, roll) into the unit's rotation.
        moho::VTransform transform{};
        transform.pos_ = Wm3::Vec3f{unit->position[0], unit->position[1], unit->position[2]};
        Wm3::Vector3f rows[3];
        (void)moho::BuildRotationMatrixFromEulerHPR(
          rows, unit->orientation[0], unit->orientation[1], unit->orientation[2]
        );
        (void)moho::MatrixRowsToQuatCanonical(rows, &transform.orient_);
        instance->SetStance(transform, transform);
        instance->isHidden = 0;
        mUnits.push_back(instance);
        UnitRef ref{
          army.name,
          unit->name,
          transform.pos_,
          {unit->orientation[0], unit->orientation[1], unit->orientation[2]},
          lower
        };
        mUnitRefs.push_back(std::move(ref));
        ++drawn;
      }
    }
    gpg::Logf(
      "editor: %d units drawn (%d as wrecks), %d without a blueprint or mesh, %d armies unreadable",
      drawn,
      wrecks,
      missing,
      unreadable
    );
  }

  moho::MeshInstance* EdMapScene::MakePropInstance(
    const moho::CWldPropEntry& entry
  ) const
  {
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr) {
      return nullptr;
    }
    // The blueprint as a prop's entity finds it: the file name normalized into a resource id.
    moho::RResId id{};
    gpg::STR_CopyFilename(&id.name, &entry.mBlueprintPath);
    moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
    moho::RMeshBlueprint* const mesh =
      blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
    if (mesh == nullptr) {
      return nullptr;
    }
    const float scale = blueprint->Display.UniformScale;
    moho::MeshInstance* const instance = renderer->CreateMeshInstance(
      0, -1, mesh, Wm3::Vec3f{scale, scale, scale}, false, std::shared_ptr<moho::MeshMaterial>()
    );
    if (instance != nullptr) {
      instance->SetStance(entry.mTransform, entry.mTransform);
      instance->isHidden = 0;
    }
    return instance;
  }

  void EdMapScene::RebuildProps()
  {
    DeleteProps();
    CreateProps();
    const int count = mMap != nullptr && mMap->mProps != nullptr ? static_cast<int>(mMap->mProps->mEntries.size()) : 0;
    mSelection.erase(
      std::remove_if(
        mSelection.begin(),
        mSelection.end(),
        [count](const int index) {
      return index >= count;
    }
      ),
      mSelection.end()
    );
  }

  bool EdMapScene::UndoProps(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.PropRedo() : mDocument.PropUndo();
    auto& to = redo ? mDocument.PropUndo() : mDocument.PropRedo();
    if (from.empty() || mMap == nullptr) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.RestoreProps(redo ? step.second : step.first);
    to.push_back(std::move(step));
    mSelection.clear();
    RebuildProps();
    return true;
  }

  bool EdMapScene::UndoTerrainTypes(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.TerrainTypesRedo() : mDocument.TerrainTypesUndo();
    auto& to = redo ? mDocument.TerrainTypesUndo() : mDocument.TerrainTypesRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyTerrainTypes(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf("editor: %s a terrain type stroke", redo ? "redid" : "undid");
    return true;
  }

  void EdMapScene::ChangeArmySettings(
    const std::string& army,
    const ArmySettings& settings
  )
  {
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    for (SaveEntry& entry : mDocument.SaveData().Armies()) {
      if (entry.name == army) {
        WriteArmySettings(entry, settings);
      }
    }
    if (before.armies == mDocument.SaveData().Armies()) {
      return;
    }
    mDocument.SaveDataEdited(std::move(before));
    gpg::Logf(
      "editor: army %s: mass %.0f, energy %.0f, faction %d, colour %d, %zu alliances",
      army.c_str(),
      settings.mass,
      settings.energy,
      settings.faction,
      settings.color,
      settings.alliances.size()
    );
  }

  void EdMapScene::ChangeUnitGroups(
    const std::string& army,
    const EdTools::GroupAsk ask,
    const std::vector<std::string>& path,
    const std::string& name
  )
  {
    std::string where;
    for (const std::string& part : path) {
      where += (where.empty() ? "" : "/") + part;
    }
    if (ask == EdTools::GroupAsk::Select) {
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup root;
        if (entry.name != army || !ParseUnitGroup(entry.Get("Units"), root)) {
          continue;
        }
        mUnitSelection.clear();
        if (const UnitGroup* const group = GroupAt(root, path); group != nullptr) {
          for (const std::string& unit : UnitNamesIn(*group)) {
            mUnitSelection.emplace_back(army, unit);
          }
        }
        gpg::Logf("editor: group %s of %s: %zu units selected", where.c_str(), army.c_str(), mUnitSelection.size());
      }
      return;
    }
    // The selected units of this army, for a move.
    std::vector<std::string> selected;
    for (const auto& [owner, unit] : mUnitSelection) {
      if (owner == army) {
        selected.push_back(unit);
      }
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    bool done = false;
    const char* what = "";
    (void)EditArmyUnits(army, [&](UnitGroup& root) {
      switch (ask) {
      case EdTools::GroupAsk::Add:
        done = AddGroup(root, path, name);
        what = "added";
        break;
      case EdTools::GroupAsk::Rename:
        done = RenameGroup(root, path, name);
        what = "renamed";
        break;
      case EdTools::GroupAsk::Remove:
        done = RemoveGroup(root, path);
        what = "removed";
        break;
      case EdTools::GroupAsk::MoveSelected:
        done = MoveUnitsTo(root, selected, path) > 0;
        what = "given the selected units";
        break;
      default:
        break;
      }
    });
    if (!done) {
      gpg::Warnf("editor: group %s of %s not %s (a name taken, or nothing to do)", where.c_str(), army.c_str(), what);
      mDocument.RestoreSaveData(before);
      return;
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    gpg::Logf(
      "editor: group %s of %s %s%s%s", where.c_str(), army.c_str(), what, name.empty() ? "" : ": ", name.c_str()
    );
  }

  void EdMapScene::SetUnitsWreck(
    const std::string& army,
    const std::vector<std::string>& names,
    const bool wreck
  )
  {
    if (MoveUnitsToGroup(army, names, {wreck ? "WRECKAGE" : "INITIAL"})) {
      gpg::Logf("editor: (%s from the start)", wreck ? "wrecks" : "units");
    }
  }

  bool EdMapScene::MoveUnitsToGroup(
    const std::string& army,
    const std::vector<std::string>& names,
    const std::vector<std::string>& path
  )
  {
    std::string where;
    for (const std::string& part : path) {
      where += (where.empty() ? "" : "/") + part;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    int moved = 0;
    bool made = false;
    (void)EditArmyUnits(army, [&](UnitGroup& root) {
      // The groups on the way, made when missing.
      for (std::size_t depth = 0; depth < path.size(); ++depth) {
        const std::vector<std::string> head(path.begin(), path.begin() + static_cast<std::ptrdiff_t>(depth + 1));
        if (GroupAt(root, head) == nullptr) {
          made = AddGroup(
                   root,
                   std::vector<std::string>(path.begin(), path.begin() + static_cast<std::ptrdiff_t>(depth)),
                   path[depth]
                 ) ||
            made;
        }
      }
      moved = names.empty() ? 0 : MoveUnitsTo(root, names, path);
    });
    if (moved == 0 && !made) {
      mDocument.RestoreSaveData(before);
      gpg::Warnf("editor: %s: nothing moved to %s", army.c_str(), where.c_str());
      return false;
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    gpg::Logf("editor: %d units of %s moved to %s%s", moved, army.c_str(), where.c_str(), made ? " (made)" : "");
    return true;
  }

  void EdMapScene::CtrlKey(
    const char key
  )
  {
    if (mMap == nullptr) {
      return;
    }
    if (AreaCtrlKey(key)) {
      return;
    }
    if ((key == 'C' || key == 'D' || key == 'X') && CopySelection() == 0) {
      return;
    }
    if (key == 'X') {
      // Cut: what was copied goes (not its mirrored copies, which the clipboard doesn't hold), as its own undo step.
      const std::size_t held =
        mClipboard.markers.size() + mClipboard.props.size() + mClipboard.units.size() + mClipboard.decals.size();
      mNoFollow = true;
      DeleteSelected();
      mNoFollow = false;
      gpg::Logf("editor: %zu cut", held);
      return;
    }
    if (key == 'D') {
      PasteAt(mClipboard.centre[0] + 8.0f, mClipboard.centre[1] + 8.0f);
    } else if (key == 'V') {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (CursorGround(groundX, groundZ)) {
        PasteAt(groundX, groundZ);
      }
    }
  }

  std::size_t EdMapScene::CopySelection()
  {
    Clipboard copied;
    float sumX = 0.0f;
    float sumZ = 0.0f;
    const auto add = [&](const float x, const float z) {
      sumX += x;
      sumZ += z;
    };
    if (mTools == nullptr || mMap == nullptr) {
      return 0;
    }
    // The tool's own kind; the Select tool copies every kind it has selected (markers, props, units and decals at
    // once).
    const bool all = mTools->SelectToolActive();
    const PickKind selected = all ? SelectedKind() : PickKind::None;
    const bool markers = all ? !mMarkerSelection.empty() : mTools->MarkersToolActive();
    const bool props = all ? !mSelection.empty() : false;
    const bool units = all ? !mUnitSelection.empty() : mTools->UnitsToolActive();
    const bool decals = all ? !mDecalSelection.empty() : mTools->DecalsToolActive();
    (void)selected;
    int kinds = 0;
    if (markers) {
      ++kinds;
      copied.kind = Clipboard::Kind::Markers;
      for (const SaveEntry& marker : SelectedMarkers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (ShownMarkerPosition(marker, x, y, z)) {
          copied.markers.push_back(marker);
          add(x, z);
        }
      }
    }
    if (props && mMap->mProps != nullptr) {
      ++kinds;
      copied.kind = Clipboard::Kind::Props;
      const auto& records = mDocument.FileRecords().props;
      for (const int index : mSelection) {
        if (index < 0 || static_cast<std::size_t>(index) >= mMap->mProps->mEntries.size()) {
          continue;
        }
        const moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
        PropRecord record = static_cast<std::size_t>(index) < records.size()
          ? records[static_cast<std::size_t>(index)]
          : PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
        copied.props.emplace_back(entry, record);
        add(entry.mTransform.pos_.x, entry.mTransform.pos_.z);
      }
    }
    if (units && (all || !markers)) {
      ++kinds;
      copied.kind = Clipboard::Kind::Units;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup group;
        if (!ParseUnitGroup(entry.Get("Units"), group)) {
          continue;
        }
        std::vector<const SaveUnit*> all;
        CollectUnits(group, all);
        for (const SaveUnit* const unit : all) {
          if (
            std::find(mUnitSelection.begin(), mUnitSelection.end(), std::pair{entry.name, unit->name}) !=
            mUnitSelection.end()
          ) {
            copied.units.emplace_back(entry.name, *unit);
            add(unit->position[0], unit->position[2]);
          }
        }
      }
    }
    if (decals && mDocument.Decals() != nullptr) {
      ++kinds;
      copied.kind = Clipboard::Kind::Decals;
      for (const int index : mDecalSelection) {
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), index); decal != nullptr) {
          const DecalState state = CaptureDecal(*decal);
          copied.decals.push_back(state);
          add(state.position[0], state.position[2]);
        }
      }
    }
    if (kinds > 1) {
      copied.kind = Clipboard::Kind::Mixed;
    }
    const std::size_t count = copied.markers.size() + copied.props.size() + copied.units.size() + copied.decals.size();
    if (count == 0) {
      return 0;
    }
    copied.centre[0] = sumX / static_cast<float>(count);
    copied.centre[1] = sumZ / static_cast<float>(count);
    mClipboard = std::move(copied);
    gpg::Logf("editor: %zu copied", count);
    return count;
  }

  bool EdMapScene::CloneSelectionForDrag(
    const bool shift
  )
  {
    mDragIsCopy = false;
    if (!shift) {
      return false;
    }
    const Clipboard kept = mClipboard;
    const std::size_t copied = CopySelection();
    if (copied == 0) {
      mClipboard = kept;
      return false;
    }
    PasteAt(mClipboard.centre[0], mClipboard.centre[1]);
    mClipboard = kept;
    mDragIsCopy = true; // a copy in place would take the original's mirrored copies as its own
    gpg::Logf("editor: Shift+drag: %zu copied in place, the copies move", copied);
    return true;
  }

  void EdMapScene::PasteAt(
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mClipboard.kind == Clipboard::Kind::None) {
      return;
    }
    const float dx = x - mClipboard.centre[0];
    const float dz = z - mClipboard.centre[1];
    const float maxX = static_cast<float>(field->width - 1);
    const float maxZ = static_cast<float>(field->height - 1);
    const auto onMap = [&](const float px, const float pz) {
      return px >= 0.0f && pz >= 0.0f && px <= maxX && pz <= maxZ;
    };
    const auto ground = [this](const float px, const float pz) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(px)), static_cast<std::int32_t>(std::lround(pz))
      );
    };
    std::size_t pasted = 0;
    // Each kind the clipboard holds (a mixed copy has several), one undo step each.
    const Clipboard::Kind kinds[] = {
      Clipboard::Kind::Markers, Clipboard::Kind::Props, Clipboard::Kind::Units, Clipboard::Kind::Decals
    };
    for (const Clipboard::Kind kind : kinds) {
      const bool has = kind == Clipboard::Kind::Markers ? !mClipboard.markers.empty()
        : kind == Clipboard::Kind::Props                ? !mClipboard.props.empty()
        : kind == Clipboard::Kind::Units                ? !mClipboard.units.empty()
                                                        : !mClipboard.decals.empty();
      if (!has) {
        continue;
      }
      const std::size_t pastedBefore = pasted;
      switch (kind) {
      case Clipboard::Kind::Markers: {
        // New names (a start position also clear of the armies, and added as one); path links kept between the copies.
        EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
        std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        std::vector<std::pair<std::string, std::string>> renamed;
        mMarkerSelection.clear();
        for (SaveEntry marker : mClipboard.markers) {
          float mx = 0.0f, my = 0.0f, mz = 0.0f;
          (void)ShownMarkerPosition(marker, mx, my, mz);
          const float px = mx + dx;
          const float pz = mz + dz;
          const MarkerType* const type = FindMarkerType(MarkerTypeOf(marker));
          if (!onMap(px, pz) || type == nullptr) {
            continue;
          }
          std::vector<SaveEntry> taken = markers;
          const bool start = std::string(type->type) == "Blank Marker";
          if (start) {
            for (const std::string& army : mDocument.ArmyNamesInUse()) {
              taken.push_back({army, {}});
            }
          }
          const std::string name = NextMarkerName(taken, *type);
          renamed.emplace_back(marker.name, name);
          marker.name = name;
          marker.Set("position", Vector3Value(px, ground(px, pz), pz));
          if (!marker.Get("adjacentTo").empty()) {
            marker.Set("adjacentTo", StringValue(""));
          }
          if (start) {
            mDocument.AddArmy(name);
          }
          markers.push_back(marker);
          mMarkerSelection.push_back(name);
          ++pasted;
        }
        for (const SaveEntry& original : mClipboard.markers) {
          const auto from = std::find_if(renamed.begin(), renamed.end(), [&](const auto& pair) {
            return pair.first == original.name;
          });
          if (from == renamed.end()) {
            continue;
          }
          for (const std::string& link : MarkerLinks(original)) {
            if (
              const auto to = std::find_if(
                renamed.begin(),
                renamed.end(),
                [&](const auto& pair) {
              return pair.first == link;
            }
              );
              to != renamed.end()
            ) {
              (void)SetMarkerLink(markers, from->second, to->second, true);
            }
          }
        }
        if (pasted > pastedBefore) {
          mDocument.SaveDataEdited(std::move(before));
          mOutsideStale = true;
        }
        break;
      }
      case Clipboard::Kind::Props: {
        EdDocument::PropSnapshot before = mDocument.PropsNow();
        mSelection.clear();
        for (const auto& [source, record] : mClipboard.props) {
          moho::CWldPropEntry entry = source;
          entry.mTransform.pos_.x += dx;
          entry.mTransform.pos_.z += dz;
          if (!onMap(entry.mTransform.pos_.x, entry.mTransform.pos_.z)) {
            continue;
          }
          entry.mTransform.pos_.y = ground(entry.mTransform.pos_.x, entry.mTransform.pos_.z);
          // The copy's record: the new place, the source's rotation and scale floats.
          PropRecord copy = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
          for (int value = 3; value < 15; ++value) {
            copy.values[value] = record.values[value];
          }
          entry.mTransform = copy.loaded;
          mDocument.AddProp(entry, copy);
          mProps.push_back(MakePropInstance(entry));
          mSelection.push_back(static_cast<int>(mMap->mProps->mEntries.size()) - 1);
          ++pasted;
        }
        if (pasted > pastedBefore) {
          mDocument.PropsEdited(std::move(before));
          mDocument.SetModified(true);
        }
        break;
      }
      case Clipboard::Kind::Units: {
        int highest = 0;
        for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
          UnitGroup group;
          if (ParseUnitGroup(entry.Get("Units"), group)) {
            highest = std::max(highest, HighestUnitNumber(group));
          }
        }
        EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
        std::vector<std::pair<std::string, std::string>> placed;
        for (const auto& [army, source] : mClipboard.units) {
          SaveUnit unit = source;
          unit.position[0] += dx;
          unit.position[2] += dz;
          if (!onMap(unit.position[0], unit.position[2])) {
            continue;
          }
          unit.position[1] = UnitRestHeight(unit.position[0], unit.position[2]);
          unit.name = "UNIT_" + std::to_string(++highest);
          if (EditArmyUnits(army, [&](UnitGroup& group) {
            AddUnit(group, unit);
          })) {
            placed.emplace_back(army, unit.name);
          }
        }
        if (!placed.empty()) {
          mDocument.SaveDataEdited(std::move(before));
          ReloadUnits();
          mUnitSelection = placed;
          pasted = placed.size();
        }
        break;
      }
      case Clipboard::Kind::Decals: {
        moho::IDecalManager* const decals = mDocument.Decals();
        if (decals == nullptr) {
          break;
        }
        EdDocument::DecalSnapshot before = mDocument.DecalsNow();
        mDecalSelection.clear();
        for (DecalState state : mClipboard.decals) {
          state.index = -1;
          state.position[0] += dx;
          state.position[2] += dz;
          if (!onMap(state.position[0], state.position[2])) {
            continue;
          }
          state.position[1] = ground(state.position[0], state.position[2]);
          if (const moho::CWldTerrainDecal* const decal = AddDecal(*decals, state); decal != nullptr) {
            mDecalSelection.push_back(decal->mIndex);
            ++pasted;
          }
        }
        if (pasted > pastedBefore) {
          mDocument.DecalsEdited(std::move(before));
        }
        break;
      }
      default:
        break;
      }
    }
    gpg::Logf(
      "editor: %zu pasted at %.1f, %.1f (one undo step)", pasted, static_cast<double>(x), static_cast<double>(z)
    );
  }

  bool EdMapScene::BoxSelectable() const
  {
    return mTools != nullptr && mMap != nullptr &&
      (mTools->SelectToolActive() || mTools->MarkersToolActive() ||
       (mTools->UnitsToolActive() && !mTools->UnitPlaceMode()) ||
       (mTools->DecalsToolActive() && mTools->DecalSelectMode()));
  }

  void EdMapScene::FinishBoxSelect(
    const bool add
  )
  {
    if (!BoxSelectable() || mCamera == nullptr) {
      return;
    }
    const float x0 = static_cast<float>(std::min(mBoxFrom.x, mBoxTo.x));
    const float x1 = static_cast<float>(std::max(mBoxFrom.x, mBoxTo.x));
    const float y0 = static_cast<float>(std::min(mBoxFrom.y, mBoxTo.y));
    const float y1 = static_cast<float>(std::max(mBoxFrom.y, mBoxTo.y));
    // Where a point of the world is on the screen, as the gizmo's arms are picked.
    const auto inside = [&](const Wm3::Vec3f& point) {
      const Wm3::Vector2f screen = mCamera->Project(point);
      return screen.x >= x0 && screen.x <= x1 && screen.y >= y0 && screen.y <= y1;
    };
    const auto groundY = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
    };
    std::size_t count = 0;
    const char* kind = "";
    if (mTools->MarkersToolActive()) {
      kind = "markers";
      if (!add) {
        mMarkerSelection.clear();
        mTools->AreaSelection().clear();
      }
      // The areas whose four corners are in the box.
      for (const SaveEntry& area : mDocument.SaveData().Areas()) {
        const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
        if (e.size() < 4) {
          continue;
        }
        bool all = true;
        for (const auto& [cx, cz] :
             {std::pair{e[0], e[1]}, std::pair{e[2], e[1]}, std::pair{e[2], e[3]}, std::pair{e[0], e[3]}}) {
          const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(cx), static_cast<std::int32_t>(cz));
          all = all && inside(Wm3::Vec3f{static_cast<float>(cx), y, static_cast<float>(cz)});
        }
        std::vector<std::string>& picked = mTools->AreaSelection();
        if (all && std::find(picked.begin(), picked.end(), area.name) == picked.end()) {
          picked.push_back(area.name);
        }
      }
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (MarkerHidden(marker) || !ShownMarkerPosition(marker, x, y, z) || !inside(Wm3::Vec3f{x, y, z})) {
          continue;
        }
        if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) == mMarkerSelection.end()) {
          mMarkerSelection.push_back(marker.name);
        }
        ++count;
      }
    } else if (mTools->UnitsToolActive()) {
      kind = "units";
      if (!add) {
        mUnitSelection.clear();
      }
      for (const UnitRef& unit : mUnitRefs) {
        if (!inside(unit.position)) {
          continue;
        }
        const std::pair<std::string, std::string> key{unit.army, unit.name};
        if (std::find(mUnitSelection.begin(), mUnitSelection.end(), key) == mUnitSelection.end()) {
          mUnitSelection.push_back(key);
        }
        ++count;
      }
    } else if (mTools->DecalsToolActive()) {
      kind = "decals";
      if (!add) {
        mDecalSelection.clear();
      }
      if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
        for (std::int32_t i = 0; i < decals->GetDecalCount(); ++i) {
          const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
          if (decal == nullptr) {
            continue;
          }
          float cx = 0.0f, cz = 0.0f;
          DecalCentre(FootprintOf(*decal), cx, cz);
          if (!inside(Wm3::Vec3f{cx, groundY(cx, cz), cz})) {
            continue;
          }
          if (std::find(mDecalSelection.begin(), mDecalSelection.end(), decal->mIndex) == mDecalSelection.end()) {
            mDecalSelection.push_back(decal->mIndex);
          }
          ++count;
        }
      }
    } else if (mTools->SelectToolActive() && mMap->mProps != nullptr && mTools->Pickable().props) {
      kind = "props";
      if (!add) {
        mSelection.clear();
      }
      const auto& entries = mMap->mProps->mEntries;
      for (std::size_t i = 0; i < entries.size(); ++i) {
        if (!inside(entries[i].mTransform.pos_)) {
          continue;
        }
        if (std::find(mSelection.begin(), mSelection.end(), static_cast<int>(i)) == mSelection.end()) {
          mSelection.push_back(static_cast<int>(i));
        }
        ++count;
      }
    }
    gpg::Logf(
      "editor: box select (%.0f, %.0f to %.0f, %.0f): %zu %s%s",
      static_cast<double>(x0),
      static_cast<double>(y0),
      static_cast<double>(x1),
      static_cast<double>(y1),
      count,
      kind,
      add ? ", added" : ""
    );
  }

  const char* EdMapScene::SelectableKind() const
  {
    if (mTools == nullptr || mMap == nullptr) {
      return "";
    }
    if (mTools->MarkersToolActive()) {
      return "markers";
    }
    if (mTools->UnitsToolActive()) {
      return "units";
    }
    if (mTools->DecalsToolActive()) {
      return "decals";
    }
    if (mTools->SelectToolActive() && mMap->mProps != nullptr && mTools->Pickable().props) {
      return "props";
    }
    return "";
  }

  int EdMapScene::SelectWhole(
    const SelectMode mode
  )
  {
    const std::string kind = SelectableKind();
    if (kind.empty()) {
      return -1;
    }
    std::vector<std::string> keys;
    std::vector<bool> selectable;
    std::vector<std::size_t> selected;
    if (kind == "markers") {
      const auto& markers = mDocument.SaveData().Markers();
      for (std::size_t i = 0; i < markers.size(); ++i) {
        keys.push_back(MarkerTypeOf(markers[i]));
        selectable.push_back(!MarkerHidden(markers[i]));
        if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), markers[i].name) != mMarkerSelection.end()) {
          selected.push_back(i);
        }
      }
      mMarkerSelection.clear();
      for (const std::size_t i : SelectByMode(keys, selectable, selected, mode)) {
        mMarkerSelection.push_back(markers[i].name);
      }
      gpg::Logf("editor: select %s: %zu %s", SelectModeName(mode), mMarkerSelection.size(), kind.c_str());
      return static_cast<int>(mMarkerSelection.size());
    }
    if (kind == "units") {
      for (std::size_t i = 0; i < mUnitRefs.size(); ++i) {
        keys.push_back(mUnitRefs[i].type);
        const std::pair<std::string, std::string> key{mUnitRefs[i].army, mUnitRefs[i].name};
        if (std::find(mUnitSelection.begin(), mUnitSelection.end(), key) != mUnitSelection.end()) {
          selected.push_back(i);
        }
      }
      mUnitSelection.clear();
      for (const std::size_t i : SelectByMode(keys, selectable, selected, mode)) {
        mUnitSelection.emplace_back(mUnitRefs[i].army, mUnitRefs[i].name);
      }
      gpg::Logf("editor: select %s: %zu %s", SelectModeName(mode), mUnitSelection.size(), kind.c_str());
      return static_cast<int>(mUnitSelection.size());
    }
    if (kind == "decals") {
      std::vector<int> indices;
      if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
        for (std::int32_t i = 0; i < decals->GetDecalCount(); ++i) {
          const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
          if (decal == nullptr) {
            continue;
          }
          if (std::find(mDecalSelection.begin(), mDecalSelection.end(), decal->mIndex) != mDecalSelection.end()) {
            selected.push_back(indices.size());
          }
          keys.emplace_back(decal->mNames[0].c_str());
          indices.push_back(decal->mIndex);
        }
      }
      mDecalSelection.clear();
      for (const std::size_t i : SelectByMode(keys, selectable, selected, mode)) {
        mDecalSelection.push_back(indices[i]);
      }
      gpg::Logf("editor: select %s: %zu %s", SelectModeName(mode), mDecalSelection.size(), kind.c_str());
      return static_cast<int>(mDecalSelection.size());
    }
    const auto& entries = mMap->mProps->mEntries;
    for (std::size_t i = 0; i < entries.size(); ++i) {
      keys.emplace_back(entries[i].mBlueprintPath.c_str());
    }
    for (const int i : mSelection) {
      selected.push_back(static_cast<std::size_t>(i));
    }
    mSelection.clear();
    for (const std::size_t i : SelectByMode(keys, selectable, selected, mode)) {
      mSelection.push_back(static_cast<int>(i));
    }
    gpg::Logf("editor: select %s: %zu %s", SelectModeName(mode), mSelection.size(), kind.c_str());
    return static_cast<int>(mSelection.size());
  }

  bool EdMapScene::FrameSelection()
  {
    if (mMap == nullptr) {
      return false;
    }
    float x0 = 1e30f, z0 = 1e30f, x1 = -1e30f, z1 = -1e30f;
    int count = 0;
    const auto add = [&](const float x, const float z) {
      x0 = std::min(x0, x);
      z0 = std::min(z0, z);
      x1 = std::max(x1, x);
      z1 = std::max(z1, z);
      ++count;
    };
    if (mMap->mProps != nullptr) {
      const auto& entries = mMap->mProps->mEntries;
      for (const int i : mSelection) {
        if (i >= 0 && static_cast<std::size_t>(i) < entries.size()) {
          add(
            entries[static_cast<std::size_t>(i)].mTransform.pos_.x,
            entries[static_cast<std::size_t>(i)].mTransform.pos_.z
          );
        }
      }
    }
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end() &&
        ShownMarkerPosition(marker, x, y, z)
      ) {
        add(x, z);
      }
    }
    for (const UnitRef& unit : mUnitRefs) {
      if (
        std::find(mUnitSelection.begin(), mUnitSelection.end(), std::make_pair(unit.army, unit.name)) !=
        mUnitSelection.end()
      ) {
        add(unit.position.x, unit.position.z);
      }
    }
    if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
      for (std::int32_t i = 0; i < decals->GetDecalCount(); ++i) {
        const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
        if (
          decal != nullptr &&
          std::find(mDecalSelection.begin(), mDecalSelection.end(), decal->mIndex) != mDecalSelection.end()
        ) {
          float cx = 0.0f, cz = 0.0f;
          DecalCentre(FootprintOf(*decal), cx, cz);
          add(cx, cz);
        }
      }
    }
    if (count == 0) {
      return false;
    }
    const float extent = std::max(x1 - x0, z1 - z0);
    FramePoint(0.5f * (x0 + x1), 0.5f * (z0 + z1), std::max(60.0f, extent * 1.4f));
    gpg::Logf(
      "editor: focus selection: %d objects around %.0f, %.0f (%.0f across)",
      count,
      static_cast<double>(0.5f * (x0 + x1)),
      static_cast<double>(0.5f * (z0 + z1)),
      static_cast<double>(extent)
    );
    return true;
  }

  void EdMapScene::SetCameraPose(
    const CameraPose& pose
  )
  {
    if (mMap == nullptr) {
      return;
    }
    mTargetX = pose.targetX;
    mTargetZ = pose.targetZ;
    mHeading = pose.heading;
    mPitch = pose.pitch;
    mDistance = pose.distance;
    ApplyCamera();
  }

  void EdMapScene::StepCamera(
    const float turn,
    const float zoom
  )
  {
    if (mMap == nullptr) {
      return;
    }
    mHeading += turn;
    mDistance *= zoom;
    ApplyCamera();
  }

  void EdMapScene::FaceNorth()
  {
    if (mMap != nullptr) {
      mHeading = kPi; // as FrameWholeMap: the map's top at the top
      ApplyCamera();
    }
  }

  void EdMapScene::LookDown()
  {
    if (mMap != nullptr) {
      mPitch = kMaxPitch;
      ApplyCamera();
    }
  }

  bool EdMapScene::CanTurnSelectedProps() const
  {
    // Any selection now (props, markers, units, decals), under the Select tool.
    return mMap != nullptr && mTools != nullptr && mTools->SelectToolActive() &&
      (!mSelection.empty() || !mMarkerSelection.empty() || !mUnitSelection.empty() || !mDecalSelection.empty());
  }

  bool EdMapScene::TurnSelectedProps(
    const float direction
  )
  {
    if (!CanTurnSelectedProps()) {
      return false;
    }
    // The command's sign, the Select tool's step.
    const float step = mTools->TurnStepDegrees() * 0.017453293f;
    return TurnEverySelected(direction < 0.0f ? -step : step);
  }

  void EdMapScene::ContinueRuler(
    const float x,
    const float z
  )
  {
    if (!mRulerShown) {
      SetRuler(x, z, x, z);
      return;
    }
    mRulerDone.push_back({mRulerFrom[0], mRulerFrom[1], mRulerTo[0], mRulerTo[1]});
    mRulerFrom[0] = mRulerTo[0];
    mRulerFrom[1] = mRulerTo[1];
    mRulerTo[0] = x;
    mRulerTo[1] = z;
    if (mTools != nullptr) {
      mTools->SetRulerText(RulerText());
      gpg::Logf(
        "editor: ruler on to %.1f, %.1f: %s",
        static_cast<double>(x),
        static_cast<double>(z),
        mTools->RulerText().c_str()
      );
    }
  }

  void EdMapScene::SetRuler(
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    mRulerShown = true;
    mRuling = false;
    mRulerDone.clear();
    mRulerFrom[0] = x0;
    mRulerFrom[1] = z0;
    mRulerTo[0] = x1;
    mRulerTo[1] = z1;
    if (mTools != nullptr) {
      mTools->SetRulerText(RulerText());
      gpg::Logf(
        "editor: ruler from %.1f, %.1f to %.1f, %.1f: %s",
        static_cast<double>(x0),
        static_cast<double>(z0),
        static_cast<double>(x1),
        static_cast<double>(z1),
        mTools->RulerText().c_str()
      );
    }
  }

  void EdMapScene::PaintTypes()
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    int width = 0;
    int height = 0;
    std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || cells == nullptr || field == nullptr || !CursorGround(groundX, groundZ)) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, groundX, groundZ, brush.symmetry, brush.turns, centreX, centreZ);
    int changed = 0;
    for (int c = 0; c < copies; ++c) {
      changed +=
        PaintTerrainType(cells, width, height, centreX[c], centreZ[c], brush.radius, mTools->TerrainTypeCode());
    }
    if (changed > 0) {
      mDocument.TerrainTypesChanged();
      mDocument.SetModified(true);
    }
  }

  void EdMapScene::EndTypeStroke()
  {
    if (mPaintingTypes && !mTypesBefore.empty() && mTypesBefore != mDocument.TerrainTypesNow()) {
      int width = 0;
      int height = 0;
      const std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
      std::size_t changed = 0;
      for (std::size_t i = 0; cells != nullptr && i < mTypesBefore.size(); ++i) {
        changed += mTypesBefore[i] != cells[i] ? 1U : 0U;
      }
      mDocument.TerrainTypesEdited(std::move(mTypesBefore));
      gpg::Logf(
        "editor: terrain type %d painted on %zu cells",
        static_cast<int>(mTools != nullptr ? mTools->TerrainTypeCode() : 0),
        changed
      );
    }
    mTypesBefore.clear();
    mPaintingTypes = false;
  }

  bool EdMapScene::UndoWaves(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.WavesRedo() : mDocument.WavesUndo();
    auto& to = redo ? mDocument.WavesUndo() : mDocument.WavesRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyWaves(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf("editor: %s a wave edit: %d wave generators", redo ? "redid" : "undid", mDocument.WaveCount());
    return true;
  }

  bool EdMapScene::UndoSkybox(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.SkyboxRedo() : mDocument.SkyboxUndo();
    auto& to = redo ? mDocument.SkyboxUndo() : mDocument.SkyboxRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplySkybox(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf("editor: %s a sky edit: %zu planets", redo ? "redid" : "undid", mDocument.SkyboxNow().planets.size());
    return true;
  }

  bool EdMapScene::UndoLighting(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.LightingRedo() : mDocument.LightingUndo();
    auto& to = redo ? mDocument.LightingUndo() : mDocument.LightingRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyLighting(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf(
      "editor: %s a lighting edit: multiplier %.2f",
      redo ? "redid" : "undid",
      static_cast<double>(mDocument.LightingNow().multiplier)
    );
    return true;
  }

  std::uint64_t EdMapScene::HeightsHash() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    std::uint64_t hash = 1469598103934665603ULL;
    if (field != nullptr) {
      const std::size_t count = static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
      for (std::size_t i = 0; i < count; ++i) {
        hash = (hash ^ field->data[i]) * 1099511628211ULL;
      }
    }
    return hash;
  }

  std::vector<PadMarker> EdMapScene::PadMarkers() const
  {
    std::vector<PadMarker> list;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (ShownMarkerPosition(marker, x, y, z)) {
        list.push_back({marker.name, MarkerTypeOf(marker), x, z});
      }
    }
    return list;
  }

  std::string EdMapScene::RunScTool(
    const EdTools::ScAsk ask
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mPainting) {
      return "No map, or a stroke is under way.";
    }
    auto* const words = reinterpret_cast<std::uint16_t*>(field->data);
    const float scale = 1.0f / 128.0f;
    // The last pads are still on the map unless their step was undone.
    if (!mPadResult.Empty() && mDocument.UndoOrder().size() < mPadDepth) {
      mPadResult = PadResult{};
    }
    const auto heightsStep = [&](const SampleRect& rect, const auto& change) {
      mDocument.Heights().BeginStroke();
      mDocument.Heights().BeforeWrite(field->data, rect);
      const int changed = change();
      mDocument.Heights().EndStroke(field->data);
      if (changed > 0) {
        mDocument.EditEnded(EdDocument::EditKind::Heights);
        RefreshHeights({rect});
        mDocument.SetModified(true);
      }
      return changed;
    };
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    char text[256];
    switch (ask) {
    case EdTools::ScAsk::PadsApply: {
      const PadSettings& settings = mTools->PadSettingsNow();
      const std::vector<Pad> pads = CollectPads(PadMarkers(), settings);
      PadResult result;
      std::string error;
      const PadResult previous = mPadResult;
      const int changed = heightsStep(whole, [&] {
        const auto applied = ApplyPads(words, field->width, field->height, scale, pads, settings, previous, result);
        if (!applied) {
          error = applied.error();
          return -1;
        }
        return *applied;
      });
      if (changed < 0) {
        return "Pads: " + error;
      }
      mPadResult = std::move(result);
      mPadDepth = mDocument.UndoOrder().size();
      int groups = 0;
      for (const Pad& pad : pads) {
        groups = std::max(groups, pad.group);
      }
      (void)std::snprintf(
        text,
        sizeof(text),
        changed > 0 ? "Pads: %zu pads (%d shared heights), %d samples changed, one undo step."
                    : "Pads: %zu pads (%d shared heights), %d samples changed: the ground already had them.",
        pads.size(),
        groups,
        changed
      );
      gpg::Logf("editor: sc tools: %s", text);
      return text;
    }
    case EdTools::ScAsk::PadsRemove: {
      if (mPadResult.Empty()) {
        return "There are no pads to remove.";
      }
      const int changed = heightsStep(whole, [&] {
        return RemovePads(words, field->width, field->height, scale, mPadResult);
      });
      mPadResult = PadResult{};
      (void)std::snprintf(text, sizeof(text), "Pads removed: %d samples changed, one undo step.", changed);
      gpg::Logf("editor: sc tools: %s", text);
      return text;
    }
    case EdTools::ScAsk::SlopeReport:
    case EdTools::ScAsk::SlopeApply: {
      const SlopeLimitSettings& slope = mTools->SlopeSettingsNow();
      const std::vector<float> before = BlockedShares(words, field->width, field->height, scale, slope.limit);
      std::string report = "Ground units can't cross (rating over " + std::to_string(slope.limit).substr(0, 4) + "):";
      if (ask == EdTools::ScAsk::SlopeApply) {
        std::string error;
        const int changed = heightsStep(whole, [&] {
          const auto limited = LimitSlopes(words, field->width, field->height, scale, slope);
          if (!limited) {
            error = limited.error();
            return -1;
          }
          return *limited;
        });
        if (changed < 0) {
          return "Slope limit: " + error;
        }
        const std::vector<float> after = BlockedShares(words, field->width, field->height, scale, slope.limit);
        for (std::size_t c = 0; c < after.size() && c < before.size(); ++c) {
          (void)std::snprintf(
            text,
            sizeof(text),
            "\n  %s %.1f%% -> %.1f%%",
            SlopeClasses()[c].name,
            static_cast<double>(before[c] * 100.0f),
            static_cast<double>(after[c] * 100.0f)
          );
          report += text;
        }
        (void)std::snprintf(text, sizeof(text), "\n%d samples changed, one undo step.", changed);
        report += text;
      } else {
        for (std::size_t c = 0; c < before.size(); ++c) {
          (void)std::snprintf(
            text, sizeof(text), "\n  %s %.1f%%", SlopeClasses()[c].name, static_cast<double>(before[c] * 100.0f)
          );
          report += text;
        }
      }
      mTools->SetSlopeReport(report);
      gpg::Logf("editor: sc tools: %s", report.c_str());
      return {};
    }
    case EdTools::ScAsk::Ramp: {
      if (!mRulerShown) {
        mTools->SetRampReport("Lay the ruler first (Alt+drag over the route).");
        return {};
      }
      const float limit = mTools->SlopeSettingsNow().limit;
      const RampReport ramp = RampProfile(
        words,
        field->width,
        field->height,
        scale,
        {{mRulerFrom[0], mRulerFrom[1]}, {mRulerTo[0], mRulerTo[1]}},
        1.0f,
        3.0f,
        limit
      );
      std::string report;
      (void)std::snprintf(
        text,
        sizeof(text),
        "%.0f units, %.1f to %.1f high; steepest grade %.2f, mean %.2f; %.0f%% over %.2f",
        static_cast<double>(ramp.length),
        static_cast<double>(ramp.minHeight),
        static_cast<double>(ramp.maxHeight),
        static_cast<double>(ramp.maxGrade),
        static_cast<double>(ramp.meanGrade),
        static_cast<double>(ramp.over * 100.0f),
        static_cast<double>(limit)
      );
      report = text;
      for (const RampReport::Run& run : ramp.runs) {
        (void)std::snprintf(
          text,
          sizeof(text),
          "\n  too steep from %.0f to %.0f along it (%.2f at %.0f, %.0f)",
          static_cast<double>(run.from),
          static_cast<double>(run.to),
          static_cast<double>(run.grade),
          static_cast<double>(run.x),
          static_cast<double>(run.z)
        );
        report += text;
      }
      mTools->SetRampReport(report);
      gpg::Logf("editor: sc tools: ramp: %s", report.c_str());
      return {};
    }
    default:
      return {};
    }
  }

  void EdMapScene::TickPads(
    const float frameSeconds
  )
  {
    // Auto: the pads re-applied half a second after the markers stopped moving.
    if (mTools == nullptr) {
      return;
    }
    if (mPadResult.Empty()) {
      mTools->SetPadsState(false, false);
      return;
    }
    if (mDocument.UndoOrder().size() < mPadDepth) {
      mPadResult = PadResult{};
      mTools->SetPadsState(false, false);
      return;
    }
    const PadSettings& settings = mTools->PadSettingsNow();
    const std::string signature = PadSignature(CollectPads(PadMarkers(), settings), settings);
    const bool stale = signature != mPadResult.signature;
    mTools->SetPadsState(true, stale);
    if (signature != mPadQuietSignature) {
      mPadQuietSignature = signature;
      mPadQuietSeconds = 0.0f;
      return;
    }
    mPadQuietSeconds += frameSeconds;
    if (stale && settings.autoApply && mPadQuietSeconds > 0.5f && !mDragMarkers && mDocument.RedoOrder().empty()) {
      mTools->SetScStatus(RunScTool(EdTools::ScAsk::PadsApply));
    }
  }

  bool EdMapScene::GraphPreviewNewest() const
  {
    return mGraphPreviewDepth > 0 && mDocument.UndoOrder().size() == mGraphPreviewDepth &&
      !mDocument.UndoOrder().empty() && mDocument.UndoOrder().back() == EdDocument::EditKind::Heights &&
      HeightsHash() == mGraphPreviewHash;
  }

  bool EdMapScene::GraphGround(
    TerrainGround& out
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || field->width < 2 || field->height < 2) {
      return false;
    }
    const std::size_t count = static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
    if (!GraphPreviewNewest() || mGraphBase == nullptr || mGraphBase->size() != count) {
      // The ground is the map as it is now (nothing of the graph's is on it, or it was edited since).
      mGraphPreviewDepth = 0;
      auto base = std::make_shared<std::vector<float>>(count);
      const auto* const words = reinterpret_cast<const std::uint16_t*>(field->data);
      for (std::size_t k = 0; k < count; ++k) {
        (*base)[k] = static_cast<float>(words[k]) / 128.0f;
      }
      mGraphBase = std::move(base);
      mGraphBaseHash = HeightsHash();
    }
    out = TerrainGround{};
    out.width = field->width;
    out.height = field->height;
    out.heights = mGraphBase;
    out.revision = mGraphBaseHash;
    const WaterState water = mDocument.WaterNow();
    out.water = water.enabled ? water.elevation : 0.0f;
    const PadSettings& settings = mTools->PadSettingsNow();
    const std::vector<Pad> pads = CollectPads(PadMarkers(), settings);
    for (const Pad& pad : pads) {
      out.pads.insert(
        out.pads.end(),
        {static_cast<double>(pad.x),
         static_cast<double>(pad.z),
         static_cast<double>(pad.half),
         static_cast<double>(pad.skirt),
         0.0,
         static_cast<double>(pad.group)}
      );
    }
    out.padSignature = PadSignature(pads, settings);
    out.waterOn = water.enabled;
    // The paint: each layer's kind from its texture (or what the Recipes panel chose), and the shader's facts.
    const ShaderProfile profile = ShaderProfileOf(TerrainShader());
    std::array<GroundKind, 9> kinds{};
    const std::vector<EdTools::LayerSlot> slots = LayerSlots();
    for (int layer = 0; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
      const std::string& albedo = slots[static_cast<std::size_t>(layer)].albedo;
      if (albedo.empty()) {
        continue;
      }
      out.textured[static_cast<std::size_t>(layer)] = true;
      float rgb[3] = {};
      kinds[static_cast<std::size_t>(layer)] =
        GroundKindOf(albedo, mTools->Library().AverageColour(albedo, rgb) ? rgb : nullptr).kind;
      if (const int chosen = mTools->RecipeOverrides()[static_cast<std::size_t>(layer)]; chosen >= 0) {
        kinds[static_cast<std::size_t>(layer)] = static_cast<GroundKind>(chosen);
      }
    }
    out.painted = profile.painted;
    out.biplanar = profile.summary.contains("biplanar");
    out.plan = PlanRecipe(kinds, out.textured, profile.painted, out.biplanar);
    out.hasPaint = true;
    out.pbr = profile.family == ShaderFamily::Pbr || profile.family == ShaderFamily::Splat;
    out.splat = profile.family == ShaderFamily::Splat;
    out.macro = profile.summary.contains("macro");
    out.specular = profile.summary.contains("specular");
    out.roughness = out.pbr && profile.painted == 7;
    // Heights from another tool: the Import / Export window's file (or a node's own) mapped as that window says.
    {
      const std::string windowFile = mTools->InteropFile(false);
      const ImportSettings mapping = mTools->InteropSettings();
      const FileStamp stamp = StampOf(windowFile);
      char key[256];
      (void)std::snprintf(
        key,
        sizeof(key),
        "%s|%llu|%lld|%d|%g|%g|%g|%d|%d|%d",
        windowFile.c_str(),
        static_cast<unsigned long long>(stamp.size),
        stamp.written,
        std::to_underlying(mapping.mapping),
        static_cast<double>(mapping.low),
        static_cast<double>(mapping.high),
        static_cast<double>(mapping.scale),
        mapping.flipX ? 1 : 0,
        mapping.flipZ ? 1 : 0,
        mapping.turns
      );
      out.externalKey = key;
      // The Layout workspace's drawing and the editor's symmetry, for the Map layout nodes.
      const HeightBrush brush = mTools->CurrentHeightBrush();
      const char* const mode = SymmetryOpModeName(brush.symmetry);
      out.layout = &mDocument.Layout();
      out.layoutSymmetry = mode != nullptr ? mode : "";
      out.layoutTurns = brush.turns;
      out.layoutKey =
        std::to_string(mDocument.Layout().revision) + "|" + out.layoutSymmetry + "|" + std::to_string(brush.turns);
      const int width = field->width;
      const int height = field->height;
      out.loadExternal = [windowFile, mapping, width, height](
                           const std::string& file, field::Grid& grid
                         ) -> std::expected<void, std::string> {
        const std::string path = file.empty() ? windowFile : file;
        if (path.empty()) {
          return std::unexpected("no heightmap: choose one in Terrain > Import / Export, or type a file in the node");
        }
        const auto image = ReadHeightImage(path, width, height);
        if (!image) {
          return std::unexpected(path + ": " + image.error());
        }
        ImportSettings settings = mapping;
        settings.blend = ImportSettings::Blend::Replace;
        settings.strength = 1.0f;
        const std::vector<std::uint16_t> words = ImportedHeights(
          *image, std::vector<std::uint16_t>(static_cast<std::size_t>(width) * height, 0), width, height, settings
        );
        grid = field::Grid(width, height, 1.0f, 0.0f, 0.0f);
        for (std::size_t k = 0; k < words.size(); ++k) {
          grid.v[k] = static_cast<float>(words[k]) / 128.0f;
        }
        return {};
      };
      // A 16 bit image of any size, 0..1 (the Image node); resampled to the map's samples.
      out.loadImage = [width, height](const std::string& file, field::Grid& grid) -> std::expected<void, std::string> {
        const auto read = ReadHeightImage(file, 0, 0);
        if (!read) {
          return std::unexpected(file + ": " + read.error());
        }
        const HeightImage image = ResampleHeights(*read, width, height);
        grid = field::Grid(width, height, 1.0f, 0.0f, 0.0f);
        for (std::size_t k = 0; k < image.words.size(); ++k) {
          grid.v[k] = static_cast<float>(image.words[k]) / 65535.0f;
        }
        return {};
      };
      // A layer's paint as the map shows it (the Texture layer node), read when the node runs (on this thread).
      out.paintKey = std::to_string(MasksHash());
      out.layerMask = [this, width](const int layer, field::Grid& grid) -> std::expected<void, std::string> {
        if (layer < 1 || layer > 8) {
          return std::unexpected("layers are 1 to 8");
        }
        LoadMasks();
        const EdDocument::MaskGrid& masks = mDocument.Masks();
        if (masks.texels.empty() || masks.width < 2 || masks.height < 2) {
          return std::unexpected("the map has no paint masks");
        }
        const bool remapped = (RemappedStrata(TerrainShader()) & (1U << (layer - 1))) != 0;
        // Each texel covers its share of the map: its sample in the middle of that square.
        const float cell = static_cast<float>(width - 1) / static_cast<float>(masks.width);
        grid = field::Grid(masks.width, masks.height, cell, cell * 0.5f, cell * 0.5f);
        for (std::size_t i = 0; i < masks.texels.size(); ++i) {
          grid.v[i] = MaskWeight(MaskByte(masks.texels[i], layer - 1), remapped) / 255.0f;
        }
        return {};
      };
      // Named masks: files beside the window's heightmap, by name (FAF Studio's adopted files).
      out.loadExternalMask =
        [windowFile, width, height](const std::string& name, field::Grid& grid) -> std::expected<void, std::string> {
        if (windowFile.empty()) {
          return std::unexpected("no heightmap chosen in Terrain > Import / Export: named masks are found beside it");
        }
        std::vector<std::string> files;
        std::error_code ignored;
        for (const auto& item :
             std::filesystem::directory_iterator(std::filesystem::path(windowFile).parent_path(), ignored)) {
          files.push_back(item.path().string());
        }
        const std::string found = FindNamedMask(files, name);
        if (found.empty()) {
          return std::unexpected(
            "no mask named " + name + " beside " + std::filesystem::path(windowFile).filename().string()
          );
        }
        const auto read = ReadHeightImage(found, 0, 0);
        if (!read) {
          return std::unexpected(found + ": " + read.error());
        }
        const HeightImage image = ResampleHeights(*read, width, height);
        grid = field::Grid(width, height, 1.0f, 0.0f, 0.0f);
        for (std::size_t k = 0; k < image.words.size(); ++k) {
          grid.v[k] = static_cast<float>(image.words[k]) / 65535.0f;
        }
        return {};
      };
    }
    // The map's light.
    const LightingState lighting = mDocument.LightingNow();
    SunAnglesOf(lighting.sunDirection, out.sunAzimuth, out.sunAltitude);
    out.lightMultiplier = lighting.multiplier;
    for (std::size_t c = 0; c < 3; ++c) {
      out.sunColour[c] = lighting.sunColor[c];
      out.ambient[c] = lighting.sunAmbience[c];
      out.shadowFill[c] = lighting.shadowFill[c];
    }
    return true;
  }

  std::size_t EdMapScene::PropCountNow() const
  {
    return mMap != nullptr && mMap->mProps != nullptr ? mMap->mProps->mEntries.size() : 0;
  }

  std::string EdMapScene::ApplyGraphBuild(
    const field::Grid& heights,
    const bool plain,
    const TerrainBuildWrites& writes
  )
  {
    if (writes.Empty()) {
      return heights.w > 1 ? ApplyGraphHeights(heights, plain, false) : "Nothing to build.";
    }
    // The heights' stroke, the mask strokes and the terrain types, ended as one step (BuildEdited).
    std::uint16_t parts = 0;
    std::string message;
    if (heights.w > 1) {
      message = ApplyGraphHeights(heights, plain, false, false);
      parts |= mDocument.Heights().LastStrokeKept() ? 1 : 0;
    } else if (GraphPreviewNewest()) {
      (void)RevertGraphPreview();
    }
    int strokes = 0;
    std::string paintText;
    LoadMasks();
    const bool masks = !mDocument.Masks().texels.empty();
    if (!writes.kinds.empty()) {
      std::array<float, 9> shares{};
      std::string text;
      if (masks && WriteRecipeMasks(writes.kinds, writes.textured, writes.cap, shares, text, false) >= 0) {
        strokes += mDocument.MaskUndo().LastStrokeKept() ? 1 : 0;
        paintText += " Ground kinds: " + text + ".";
      } else {
        paintText += " The ground kinds weren't written: " + (masks ? text : std::string("the map has no masks")) + ".";
      }
    }
    for (const TerrainBuildWrites::Layer& layer : writes.layers) {
      std::string text;
      if (
        masks && strokes < 31 &&
        WriteGeneratedMask(layer.mask, layer.layer, layer.mode, layer.strength, layer.takeAway, text, false) >= 0
      ) {
        strokes += mDocument.MaskUndo().LastStrokeKept() ? 1 : 0;
        paintText += " Layer " + std::to_string(layer.layer) + ": " + text + ".";
      }
    }
    parts |= static_cast<std::uint8_t>(strokes << 1);
    if (!writes.types.empty() || (writes.kindsTypes && !writes.kinds.empty())) {
      int width = 0;
      int height = 0;
      std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
      if (cells != nullptr && width > 0 && height > 0) {
        std::vector<std::uint8_t> before = mDocument.TerrainTypesNow();
        std::size_t changed = 0;
        // The ground kinds' types first: each cell what its paint shows most, by the layers' textures' types.
        if (writes.kindsTypes && !writes.kinds.empty() && masks && mTools != nullptr) {
          const std::vector<EdTools::LayerSlot> slots = LayerSlots();
          std::array<int, 9> layerTypes{};
          for (int layer = 0; layer <= 8 && layer < static_cast<int>(slots.size()); ++layer) {
            layerTypes[static_cast<std::size_t>(layer)] =
              DefaultTerrainTypeFor(slots[static_cast<std::size_t>(layer)].albedo, mTools->TerrainTypeList());
          }
          const EdDocument::MaskGrid& grid = mDocument.Masks();
          changed += TerrainTypesFromLayers(
            grid.texels.data(),
            grid.width,
            grid.height,
            RemappedStrata(TerrainShader()),
            writes.textured,
            layerTypes,
            cells,
            width,
            height,
            false
          );
        }
        const float sizeX = static_cast<float>(mDocument.Facts().sizeX);
        const float sizeZ = static_cast<float>(mDocument.Facts().sizeZ);
        for (const TerrainBuildWrites::Types& t : writes.types) {
          for (int j = 0; j < height; ++j) {
            const double z = (static_cast<double>(j) + 0.5) * sizeZ / height;
            for (int i = 0; i < width; ++i) {
              const double x = (static_cast<double>(i) + 0.5) * sizeX / width;
              if (field::SampleWorld(t.mask, x, z) > t.threshold) {
                std::uint8_t& cell = cells[static_cast<std::size_t>(j) * width + i];
                changed += cell != static_cast<std::uint8_t>(t.code) ? 1u : 0u;
                cell = static_cast<std::uint8_t>(t.code);
              }
            }
          }
        }
        if (mDocument.TerrainTypesNow() != before) {
          mDocument.TerrainTypesEdited(std::move(before), false);
          mDocument.TerrainTypesChanged();
          parts |= 64;
        }
        paintText += " Terrain types: " + std::to_string(changed) + " cells.";
      }
    }
    const bool anyProps = std::any_of(writes.scatters.begin(), writes.scatters.end(), [](const auto& s) {
      return !s.decals;
    });
    if (anyProps && mMap != nullptr && mMap->mProps != nullptr) {
      BeginObjectStroke();
      int placed = 0;
      for (const TerrainBuildWrites::Scatter& scatter : writes.scatters) {
        if (scatter.decals) {
          continue;
        }
        std::string note;
        placed += ScatterFromGraph(scatter, note);
        if (!note.empty()) {
          paintText += " " + note + ".";
        }
      }
      if (EndObjectStroke(false)) {
        parts |= 128;
      }
      paintText += " Props: " + std::to_string(placed) + " placed.";
    }
    // Decal scatters: one decals change joined to the build.
    if (
      mMap != nullptr && mDocument.Decals() != nullptr &&
      std::any_of(writes.scatters.begin(), writes.scatters.end(), [](const auto& s) {
      return s.decals;
    })
    ) {
      EdDocument::DecalSnapshot decalsBefore = mDocument.DecalsNow();
      int placed = 0;
      for (const TerrainBuildWrites::Scatter& scatter : writes.scatters) {
        if (!scatter.decals) {
          continue;
        }
        std::string note;
        placed += ScatterDecalsFromGraph(scatter, note);
        if (!note.empty()) {
          paintText += " " + note + ".";
        }
      }
      if (placed > 0) {
        mDocument.DecalsEdited(std::move(decalsBefore), false);
        parts |= 512;
      }
      paintText += " Decals: " + std::to_string(placed) + " placed.";
    }
    if (parts != 0) {
      mDocument.BuildEdited(parts);
    }
    for (const std::string& note : writes.notes) {
      paintText += " Left out: " + note + ".";
    }
    std::string text = (message.empty() ? std::string("Built.") : message) + paintText + " One undo step.";
    gpg::Logf("editor: generate: %s", text.c_str());
    return text;
  }

  bool EdMapScene::UndoGraphBuild(
    const bool redo
  )
  {
    std::vector<std::uint16_t>& from = redo ? mDocument.BuildRedo() : mDocument.BuildUndo();
    std::vector<std::uint16_t>& to = redo ? mDocument.BuildUndo() : mDocument.BuildRedo();
    if (from.empty()) {
      return false;
    }
    const std::uint16_t parts = from.back();
    from.pop_back();
    const int strokes = (parts >> 1) & 31;
    // Undo in the reverse order of the build (paths, water, props, types, masks, heights); redo in its order.
    if (!redo) {
      if ((parts & 1024) != 0) {
        (void)mDocument.UndoPaths(false);
      }
      if ((parts & 512) != 0) {
        (void)UndoDecals(false);
      }
      if ((parts & 256) != 0) {
        (void)UndoWater(false);
      }
      if ((parts & 128) != 0) {
        (void)UndoProps(false);
      }
      if ((parts & 64) != 0) {
        (void)UndoTerrainTypes(false);
      }
      for (int s = 0; s < strokes; ++s) {
        (void)UndoMasks(false);
      }
      if ((parts & 1) != 0) {
        (void)UndoHeights(false);
      }
    } else {
      if ((parts & 1) != 0) {
        (void)UndoHeights(true);
      }
      for (int s = 0; s < strokes; ++s) {
        (void)UndoMasks(true);
      }
      if ((parts & 64) != 0) {
        (void)UndoTerrainTypes(true);
      }
      if ((parts & 128) != 0) {
        (void)UndoProps(true);
      }
      if ((parts & 256) != 0) {
        (void)UndoWater(true);
      }
      if ((parts & 512) != 0) {
        (void)UndoDecals(true);
      }
      if ((parts & 1024) != 0) {
        (void)mDocument.UndoPaths(true);
      }
    }
    to.push_back(parts);
    return true;
  }

  std::string EdMapScene::ApplyGraphHeights(
    const field::Grid& result,
    const bool plain,
    const bool preview,
    const bool endStep,
    std::size_t* changedOut
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting || result.w < 2 || result.h < 2) {
      return "No map, or a stroke is under way.";
    }
    const bool replaced = GraphPreviewNewest() && Undo();
    mGraphPreviewDepth = 0;
    const int width = field->width;
    const int height = field->height;
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    auto* const words = reinterpret_cast<std::uint16_t*>(field->data);
    std::vector<float> target;
    if (result.w == width && result.h == height) {
      target = result.v;
    } else {
      // A coarse result onto the map's samples.
      auto fine = std::make_shared<field::Grid>(width, height, 1.0f, 0.0f, 0.0f);
      for (std::size_t k = 0; k < count; ++k) {
        fine->v[k] = static_cast<float>(words[k]) / 128.0f;
      }
      field::GridPtr source = std::make_shared<field::Grid>(result);
      if (!plain) {
        // Only the change the graph made at the coarse samples: the fine detail of the ground stays.
        field::OpArgs down;
        down.in["a"] = fine;
        down.in["like"] = source;
        field::Grid coarseBase;
        const auto ran = field::RunOpCpu("resample", down, coarseBase);
        if (!ran || !coarseBase.SameShape(result)) {
          return "Preview: " + (ran ? std::string() : ran.error());
        }
        auto delta = std::make_shared<field::Grid>(result);
        for (std::size_t k = 0; k < delta->v.size(); ++k) {
          delta->v[k] -= coarseBase.v[k];
        }
        source = delta;
      }
      field::OpArgs up;
      up.in["a"] = source;
      up.in["like"] = fine;
      field::Grid upsampled;
      // A finer result (after an Oversample node) is averaged down; a coarser one put up smoothly.
      const char* const op = result.w > width ? "downsample" : "upsample";
      const auto ran = field::RunOpCpu(op, up, upsampled);
      if (!ran || upsampled.v.size() != count) {
        return "Preview: " + (ran ? std::string() : ran.error());
      }
      target = std::move(upsampled.v);
      if (!plain) {
        for (std::size_t k = 0; k < count; ++k) {
          target[k] += fine->v[k];
        }
      }
    }
    std::size_t changed = 0;
    std::vector<std::uint16_t> next(count);
    for (std::size_t k = 0; k < count; ++k) {
      next[k] = static_cast<std::uint16_t>(std::clamp(std::lround(target[k] * 128.0f), 0L, 65535L));
      changed += next[k] != words[k] ? 1u : 0u;
    }
    const SampleRect whole{0, 0, width - 1, height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    std::copy(next.begin(), next.end(), words);
    mDocument.Heights().EndStroke(field->data);
    if (changedOut != nullptr) {
      *changedOut = changed;
    }
    if (changed > 0) {
      if (endStep) {
        mDocument.EditEnded(EdDocument::EditKind::Heights);
      }
      RefreshHeights({whole});
      mDocument.SetModified(true);
      if (mCheckDone) {
        RunSymmetryCheck();
      }
      if (preview) {
        mGraphPreviewDepth = mDocument.UndoOrder().size();
        mGraphPreviewHash = HeightsHash();
      }
    }
    const char* const how = changed == 0 ? ""
      : replaced ? (preview ? ", in place of the last preview" : ", one undo step in place of the preview")
                 : ", one undo step";
    char text[256];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%s: %zu samples changed%s%s.",
      preview ? "Preview on the map" : "Built",
      changed,
      result.w == width ? "" : " (a coarse run, upsampled)",
      how
    );
    gpg::Logf("editor: generate: %s", text);
    return text;
  }

  bool EdMapScene::RevertGraphPreview()
  {
    if (!GraphPreviewNewest()) {
      mGraphPreviewDepth = 0;
      return false;
    }
    mGraphPreviewDepth = 0;
    const bool undone = Undo();
    gpg::Logf("editor: generate: the preview %s", undone ? "was taken off" : "couldn't be taken off");
    return undone;
  }

  bool EdMapScene::ImportIsNewest(
    const bool exact
  ) const
  {
    // `exact` also checks the heights are the ones the import left (a whole-map hash: on asks, not every frame).
    return mImportDepth > 0 && mDocument.UndoOrder().size() == mImportDepth && !mDocument.UndoOrder().empty() &&
      mDocument.UndoOrder().back() == EdDocument::EditKind::Heights && (!exact || HeightsHash() == mImportHash);
  }

  std::string EdMapScene::InteropImport(
    const bool live
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mPainting) {
      return "No map, or a stroke is under way.";
    }
    const std::string file = mTools->InteropFile(false);
    ImportSettings settings = mTools->InteropSettings();
    auto read = ReadHeightImageWith(file, field->width, field->height, settings.read);
    if (!read) {
      return "Import failed: " + read.error();
    }
    HeightImage& image = *read;
    // FAF Studio's further options: the playable area as the region, the pads' spots, the mask image, the sea.
    if (settings.regionPlayable) {
      if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea(); area.has_value()) {
        settings.region = true;
        settings.regionX0 = area->x0;
        settings.regionZ0 = area->z0;
        settings.regionX1 = area->x1;
        settings.regionZ1 = area->z1;
      }
    }
    if (settings.pads != 0) {
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float mx = 0.0f, my = 0.0f, mz = 0.0f;
        const std::string type = MarkerTypeOf(marker);
        if ((type == "Blank Marker" || type == "Mass" || type == "Hydrocarbon") && MarkerPosition(marker, mx, my, mz)) {
          settings.padPoints.push_back({mx, mz});
        }
      }
    }
    if (!settings.maskFile.empty()) {
      const auto readMask = ReadHeightImage(settings.maskFile, field->width, field->height);
      if (!readMask) {
        return "Import failed: the mask image: " + readMask.error();
      }
      const HeightImage mask = ResampleHeights(*readMask, field->width, field->height);
      settings.maskWeights.resize(mask.words.size());
      for (std::size_t i = 0; i < mask.words.size(); ++i) {
        settings.maskWeights[i] = static_cast<float>(mask.words[i]) / 65535.0f;
      }
    }
    if (settings.seaPin) {
      settings.seaLevel = mDocument.WaterNow().elevation;
    }
    // The link's import replaces its last one while that is still the newest step: the history keeps one.
    const bool replace = live && mImportLive && ImportIsNewest() && Undo();
    auto* const words = reinterpret_cast<std::uint16_t*>(field->data);
    const std::size_t count = static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
    const std::vector<std::uint16_t> current(words, words + count);
    std::vector<std::uint16_t> next = ImportedHeights(image, current, field->width, field->height, settings);
    if (settings.symmetric) {
      // Made symmetric as the toolbar's symmetry says (its first part copied over the rest).
      const HeightBrush brush = mTools->CurrentHeightBrush();
      if (brush.symmetry != Symmetry::None) {
        SymmetrizeOptions options;
        options.symmetry = brush.symmetry;
        options.turns = brush.turns;
        (void)SymmetrizeHeights(next.data(), field->width, field->height, options);
      }
    }
    std::size_t changed = 0;
    for (std::size_t k = 0; k < count; ++k) {
      changed += next[k] != current[k] ? 1u : 0u;
    }
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    std::copy(next.begin(), next.end(), words);
    mDocument.Heights().EndStroke(field->data);
    if (changed > 0) {
      mDocument.EditEnded(EdDocument::EditKind::Heights);
      RefreshHeights({whole});
      mDocument.SetModified(true);
      if (mCheckDone) {
        RunSymmetryCheck();
      }
      mImportDepth = mDocument.UndoOrder().size();
      mImportHash = HeightsHash();
      mImportLive = live;
    } else if (replace) {
      // The file went back to what the map had before the link: the undone step stays undone.
      mImportDepth = 0;
    }
    char text[512];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%s %s (%d x %d%s): %zu samples changed%s.",
      live ? "Linked" : "Imported",
      std::filesystem::path(file).filename().string().c_str(),
      image.width,
      image.height,
      image.width != field->width || image.height != field->height ? ", resampled" : "",
      changed,
      changed == 0 ? ""
        : replace  ? ", in place of the last link import"
                   : ", one undo step"
    );
    gpg::Logf("editor: interop: %s", text);
    // How it compares with the reference maps of this size (FAF Studio's Advice): relief and mean slope.
    std::string advice;
    {
      float low = 1e30f;
      float high = -1e30f;
      double slopeSum = 0.0;
      std::size_t slopes = 0;
      for (int z = 0; z + 1 < field->height; z += 2) {
        for (int x = 0; x + 1 < field->width; x += 2) {
          const float h = GroundHeightAt(static_cast<float>(x), static_cast<float>(z));
          low = std::min(low, h);
          high = std::max(high, h);
          const float dx = GroundHeightAt(static_cast<float>(x + 1), static_cast<float>(z)) - h;
          const float dz = GroundHeightAt(static_cast<float>(x), static_cast<float>(z + 1)) - h;
          slopeSum += std::atan(std::sqrt(dx * dx + dz * dz)) * 57.29578;
          ++slopes;
        }
      }
      if (slopes > 0) {
        advice = ReferenceAdvice(field->width - 1, high - low, static_cast<float>(slopeSum / slopes));
        gpg::Logf("editor: interop: %s", advice.c_str());
      }
    }
    return advice.empty() ? std::string(text) : std::string(text) + " " + advice;
  }

  std::string EdMapScene::RunInterop(
    const EdTools::InteropAsk ask
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return "No map is open in the view.";
    }
    char text[512];
    switch (ask) {
    case EdTools::InteropAsk::Probe: {
      const std::string file = mTools->InteropFile(false);
      const auto read = ReadHeightImage(file, field->width, field->height);
      if (!read) {
        mTools->SetInteropProbe("Can't read it: " + read.error());
        return {};
      }
      const HeightImage& image = *read;
      std::uint16_t darkest = 0, brightest = 0;
      HeightImageRange(image, darkest, brightest);
      const ImportSettings& s = mTools->InteropSettings();
      const bool stretched = s.mapping == ImportSettings::Mapping::Normalised;
      const float low = stretched ? s.low : static_cast<float>(darkest) * s.scale / 128.0f;
      const float high = stretched ? s.high : static_cast<float>(brightest) * s.scale / 128.0f;
      std::uint16_t mapLow = 0, mapHigh = 0;
      HeightImage map;
      map.width = field->width;
      map.height = field->height;
      map.words.assign(
        reinterpret_cast<const std::uint16_t*>(field->data),
        reinterpret_cast<const std::uint16_t*>(field->data) + static_cast<std::size_t>(field->width) * field->height
      );
      HeightImageRange(map, mapLow, mapHigh);
      (void)std::snprintf(
        text,
        sizeof(text),
        "%d x %d%s, values %u to %u: heights %.1f to %.1f (the map has %.1f to %.1f).",
        image.width,
        image.height,
        image.width != field->width || image.height != field->height ? " (resampled to the map's)" : "",
        static_cast<unsigned>(darkest),
        static_cast<unsigned>(brightest),
        static_cast<double>(low),
        static_cast<double>(high),
        static_cast<double>(mapLow) / 128.0,
        static_cast<double>(mapHigh) / 128.0
      );
      mTools->SetInteropProbe(text);
      gpg::Logf("editor: interop: probe: %s", text);
      return {};
    }
    case EdTools::InteropAsk::Import:
      return InteropImport(false);
    case EdTools::InteropAsk::Revert: {
      if (!ImportIsNewest()) {
        return "Nothing to revert (other edits came after the import).";
      }
      const bool undone = Undo();
      mImportDepth = 0;
      gpg::Logf("editor: interop: reverted the last import");
      return undone ? "Reverted the last import." : "Couldn't revert now (a stroke is under way).";
    }
    case EdTools::InteropAsk::Export:
    case EdTools::InteropAsk::SendAndWatch: {
      const std::string file = mTools->InteropFile(true);
      const float scale = mTools->InteropExportScale();
      const auto exported = ExportHeights(file, mTools->InteropExportWidth(), scale);
      if (!exported) {
        return exported.error();
      }
      std::string message = *exported;
      if (mTools->InteropSidecar()) {
        ExportFacts facts;
        facts.map = mDocument.FolderName();
        facts.mapWidth = field->width - 1;
        facts.mapHeight = field->height - 1;
        const int width = mTools->InteropExportWidth();
        facts.imageWidth = width > 1 ? width : field->width;
        facts.imageHeight = width > 1
          ? std::max(
              2,
              static_cast<int>(std::lround(static_cast<double>(width - 1) * (field->height - 1) / (field->width - 1))) +
                1
            )
          : field->height;
        facts.scale = scale;
        std::uint16_t low = 0, high = 0;
        HeightImage map;
        map.words.assign(
          reinterpret_cast<const std::uint16_t*>(field->data),
          reinterpret_cast<const std::uint16_t*>(field->data) + static_cast<std::size_t>(field->width) * field->height
        );
        HeightImageRange(map, low, high);
        facts.lowest = static_cast<float>(low) / 128.0f;
        facts.highest = static_cast<float>(high) / 128.0f;
        const WaterState water = mDocument.WaterNow();
        facts.sea = water.enabled ? water.elevation : 0.0f;
        facts.symmetry = EdTools::SymmetryName(mTools->SymmetryIndex());
        const std::filesystem::path sidecar = std::filesystem::path(file).string() + ".json";
        if (std::FILE* out = std::fopen(sidecar.string().c_str(), "wb"); out != nullptr) {
          const std::string json = ExportSidecar(facts);
          (void)std::fwrite(json.data(), 1, json.size(), out);
          (void)std::fclose(out);
          message += ", with " + sidecar.filename().string();
        } else {
          message += "; the sidecar couldn't be written";
        }
        // The sheet for Gaea / World Machine (size in km, heights in metres).
        const std::filesystem::path sheet = std::filesystem::path(file).string() + ".txt";
        if (std::FILE* out = std::fopen(sheet.string().c_str(), "wb"); out != nullptr) {
          const std::string text = ExportSheet(facts);
          (void)std::fwrite(text.data(), 1, text.size(), out);
          (void)std::fclose(out);
          message += " and " + sheet.filename().string();
        }
      }
      gpg::Logf("editor: interop: %s", message.c_str());
      if (ask == EdTools::InteropAsk::SendAndWatch) {
        // The same file back as heights, exactly: its words divided by the export's scale, nothing turned or blended.
        ImportSettings& s = mTools->InteropSettings();
        s = ImportSettings{};
        s.mapping = ImportSettings::Mapping::Absolute;
        s.scale = 1.0f / std::max(0.01f, scale);
        mTools->SetInteropFile(false, file);
        mTools->SetInteropLive(true);
        mLinkOn = false; // restarts on the file as it is now
        message += ". Watching it: save it from the other tool and the map follows.";
      }
      return message + ".";
    }
    default:
      return {};
    }
  }

  void EdMapScene::TickInterop(
    const float frameSeconds
  )
  {
    if (mTools == nullptr) {
      return;
    }
    mLinkClock += static_cast<double>(frameSeconds);
    const bool on = mTools->InteropLive();
    const std::string file = on ? mTools->InteropFile(false) : std::string();
    if (!on || file.empty()) {
      mLinkOn = false;
      mTools->SetInteropState(ImportIsNewest(false), {});
      return;
    }
    // Four looks a second at the file's size and time.
    mLinkPollSeconds += frameSeconds;
    if (mLinkOn && file == mLinkFile && mLinkPollSeconds < 0.25f) {
      return;
    }
    mLinkPollSeconds = 0.0f;
    const FileStamp stamp = StampOf(file);
    if (!mLinkOn || file != mLinkFile) {
      // Linking starts from the file as it is: the next save imports.
      mLinkOn = true;
      mLinkFile = file;
      mLinkImports = 0;
      mLink.Start(stamp);
    } else if (mLink.Poll(stamp, mLinkClock) && !mPainting) {
      mTools->SetInteropStatus(InteropImport(true));
      ++mLinkImports;
    }
    std::string note = stamp.written == 0 ? "the file is missing"
      : mLinkImports == 0                 ? "watching"
                                          : std::to_string(mLinkImports) + (mLinkImports == 1 ? " import" : " imports");
    mTools->SetInteropState(ImportIsNewest(false), std::move(note));
  }

  bool EdMapScene::UndoHeightsAndMasks(
    const bool redo
  )
  {
    // Both stacks took one entry for the step; both give it back.
    const bool heights = UndoHeights(redo);
    const bool masks = UndoMasks(redo);
    return heights || masks;
  }

  std::uint64_t EdMapScene::MasksHash()
  {
    LoadMasks();
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::uint64_t texel : mDocument.Masks().texels) {
      hash = (hash ^ texel) * 1099511628211ULL;
    }
    return hash;
  }

  bool EdMapScene::RevertErosionPreview()
  {
    if (!mErosionPreviewShown) {
      return false;
    }
    mErosionPreviewShown = false;
    // Only while the preview is still the newest edit: else it stays, as any edit would.
    if (
      mDocument.UndoOrder().size() == mErosionPreviewDepth && !mDocument.UndoOrder().empty() &&
      mDocument.UndoOrder().back() == EdDocument::EditKind::Heights
    ) {
      return Undo();
    }
    return false;
  }

  std::string EdMapScene::RunErosion(
    const std::string& solverId,
    const ErosionValues& values,
    const bool preview
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    const ErosionSolver* const solver = FindErosionSolver(solverId);
    if (field == nullptr || solver == nullptr || mPainting) {
      return "No map, or a stroke is under way.";
    }
    (void)RevertErosionPreview();
    const int step = preview ? ErosionPreviewStep(field->width, field->height) : 1;
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    const auto started = std::chrono::steady_clock::now();
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    const EdTools::ErosionMaskChoice& choice = mTools->ErosionMasksChosen();
    const bool wantMasks = !preview && (choice.on[0] || choice.on[1] || choice.on[2] || choice.on[3]);
    ErosionMasks made_masks;
    const auto made = ErodeHeights(
      reinterpret_cast<std::uint16_t*>(field->data),
      field->width,
      field->height,
      1.0f / 128.0f,
      *solver,
      values,
      step,
      wantMasks ? &made_masks : nullptr
    );
    mDocument.Heights().EndStroke(field->data);
    if (!made) {
      gpg::Warnf("editor: erosion: %s", made.error().c_str());
      return "The solver stopped: " + made.error();
    }
    // The chosen masks into their layers, in the same undo step as the heights.
    int painted = 0;
    if (wantMasks) {
      LoadMasks();
      EdDocument::MaskGrid& masks = mDocument.Masks();
      if (!masks.texels.empty()) {
        const SampleRect all{0, 0, masks.width - 1, masks.height - 1};
        mDocument.MaskUndo().BeginStroke();
        mDocument.MaskUndo().BeforeWrite(masks.texels.data(), all);
        const std::vector<float>* const lists[4] = {
          &made_masks.wear, &made_masks.deposit, &made_masks.flow, &made_masks.accum
        };
        const std::uint32_t remapped = RemappedStrata(TerrainShader());
        for (int m = 0; m < 4; ++m) {
          const std::vector<float>& list = *lists[m];
          const int layer = std::clamp(choice.layer[m], 1, 8) - 1;
          if (!choice.on[m] || list.size() != static_cast<std::size_t>(field->width) * field->height) {
            continue;
          }
          const bool remappedLayer = (remapped & (1U << layer)) != 0;
          // The mask grid's texel (x, y) over the map's samples, bilinear.
          for (int y = 0; y < masks.height; ++y) {
            const float sz = (static_cast<float>(y) + 0.5f) / masks.height * static_cast<float>(field->height - 1);
            const int z0 = std::min(field->height - 2, static_cast<int>(sz));
            const float fz = sz - static_cast<float>(z0);
            for (int x = 0; x < masks.width; ++x) {
              const float sx = (static_cast<float>(x) + 0.5f) / masks.width * static_cast<float>(field->width - 1);
              const int x0 = std::min(field->width - 2, static_cast<int>(sx));
              const float fx = sx - static_cast<float>(x0);
              const auto at = [&](const int i, const int j) {
                return list[static_cast<std::size_t>(j) * field->width + i];
              };
              const float v = (at(x0, z0) * (1.0f - fx) + at(x0 + 1, z0) * fx) * (1.0f - fz) +
                (at(x0, z0 + 1) * (1.0f - fx) + at(x0 + 1, z0 + 1) * fx) * fz;
              std::uint64_t& texel = masks.texels[static_cast<std::size_t>(y) * masks.width + x];
              texel = WithMaskByte(
                texel, layer, MaskStoredFor(std::clamp(v, 0.0f, 1.0f) * 255.0f, remappedLayer, MaskByte(texel, layer))
              );
            }
          }
          ++painted;
        }
        mDocument.MaskUndo().EndStroke(masks.texels.data());
        UploadMasks({all}, 0xFFu);
        UpdateCoverage();
      }
    }
    mDocument.EditEnded(painted > 0 ? EdDocument::EditKind::HeightsAndMasks : EdDocument::EditKind::Heights);
    RefreshHeights({whole});
    mDocument.SetModified(true);
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    const std::size_t changed = mDocument.Heights().NewestChangedSamples();
    if (preview) {
      mErosionPreviewShown = true;
      mErosionPreviewDepth = mDocument.UndoOrder().size();
    }
    gpg::Logf(
      "editor: erosion %s (%s, every %d%s sample): %zu samples changed in %.2f s, %d masks painted",
      preview ? "preview" : "applied",
      solver->label,
      step,
      step == 1 ? "st" : "th",
      changed,
      seconds,
      painted
    );
    char text[160];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%s: %zu samples changed in %.1f s%s",
      preview ? "Preview" : "Applied",
      changed,
      seconds,
      preview ? "; Revert takes it off" : "; one undo step"
    );
    return text;
  }

  bool EdMapScene::UndoWaterMasks(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.WaterMaskRedo() : mDocument.WaterMaskUndo();
    auto& to = redo ? mDocument.WaterMaskUndo() : mDocument.WaterMaskRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyWaterMasks(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf("editor: %s a water mask stroke", redo ? "redid" : "undid");
    return true;
  }

  int EdMapScene::DabWaterMask(
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    int width = 0, height = 0;
    std::uint8_t* const cells =
      mTools != nullptr ? mDocument.WaterMaskCells(mTools->WaterMaskKind(), width, height) : nullptr;
    if (field == nullptr || cells == nullptr) {
      return 0;
    }
    const WaterMaskBrush brush = mTools->WaterMaskBrushNow();
    const HeightBrush symmetry = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, symmetry.symmetry, symmetry.turns, cx, cz);
    // Each copy's cells on their own: one box around copies across the map would rebuild half of it.
    int changed = 0;
    for (int c = 0; c < copies; ++c) {
      const WaterMaskRect rect = PaintWaterMask(cells, width, height, cx[c], cz[c], brush);
      if (!rect.Empty()) {
        mDocument.WaterMasksChanged(rect.x0, rect.z0, rect.x1, rect.z1);
        changed += (rect.x1 - rect.x0) * (rect.z1 - rect.z0);
      }
    }
    return changed;
  }

  void EdMapScene::TestWaterMask(
    const std::string& spec
  )
  {
    // `foam|flatness|bias,<value>,<radius>[,keep]`
    std::vector<std::string> parts;
    for (std::size_t from = 0;;) {
      const std::size_t comma = spec.find(',', from);
      parts.push_back(spec.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
      if (comma == std::string::npos) {
        break;
      }
      from = comma + 1;
    }
    const WaterMask mask = parts[0] == "flatness" ? WaterMask::Flatness
      : parts[0] == "bias"                        ? WaterMask::DepthBias
                                                  : WaterMask::Foam;
    const int value = parts.size() > 1 ? std::atoi(parts[1].c_str()) : 255;
    const float radius = parts.size() > 2 ? std::strtof(parts[2].c_str(), nullptr) : 40.0f;
    const bool keep = parts.size() > 3 && parts[3] == "keep";
    mTools->SetWaterMaskPaint(mask, value, radius);
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const auto count = [&](const char* const when) {
      const EdDocument::WaterMaskSnapshot now = mDocument.WaterMasksNow();
      const std::vector<std::uint8_t>& cells = mask == WaterMask::Foam ? now.foam
        : mask == WaterMask::Flatness                                  ? now.flatness
                                                                       : now.depthBias;
      std::size_t changed = 0;
      for (const std::uint8_t cell : cells) {
        changed += cell != WaterMaskDefault(mask) ? 1u : 0u;
      }
      gpg::Logf(
        "editor: water mask test %s: %s %dx%d, %zu cells off its default %d; undo: %s",
        when,
        WaterMaskName(mask),
        now.width,
        now.height,
        changed,
        static_cast<int>(WaterMaskDefault(mask)),
        mDocument.UndoStepName() != nullptr ? mDocument.UndoStepName() : "-"
      );
    };
    count("before");
    // A stroke as the view makes one: a press, three dabs along x, a release.
    const float x = static_cast<float>(field->width) * 0.4f;
    const float z = static_cast<float>(field->height) * 0.45f;
    mWaterMaskBefore = mDocument.WaterMasksNow();
    for (int dab = 0; dab < 3; ++dab) {
      (void)DabWaterMask(x + static_cast<float>(dab) * radius * 0.5f, z);
    }
    mDocument.WaterMasksEdited(std::move(mWaterMaskBefore));
    count("painted");
    if (!keep) {
      (void)Undo();
      count("after undo");
    }
  }

  bool EdMapScene::UndoLook(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.LookRedo() : mDocument.LookUndo();
    auto& to = redo ? mDocument.LookUndo() : mDocument.LookRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyLookEnvironment(redo ? step.second : step.first);
    to.push_back(std::move(step));
    gpg::Logf("editor: %s a look", redo ? "redid" : "undid");
    return true;
  }

  bool EdMapScene::UndoWater(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.WaterRedo() : mDocument.WaterUndo();
    auto& to = redo ? mDocument.WaterUndo() : mDocument.WaterRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.ApplyWater(redo ? step.second : step.first);
    to.push_back(std::move(step));
    const WaterState now = mDocument.WaterNow();
    gpg::Logf("editor: %s a water edit: level %.2f", redo ? "redid" : "undid", static_cast<double>(now.elevation));
    return true;
  }

  bool EdMapScene::UndoDecals(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.DecalRedo() : mDocument.DecalUndo();
    auto& to = redo ? mDocument.DecalUndo() : mDocument.DecalRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.RestoreDecals(redo ? step.second : step.first);
    to.push_back(std::move(step));
    // Selected decals that no longer exist leave the selection.
    if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
      mDecalSelection.erase(
        std::remove_if(
          mDecalSelection.begin(),
          mDecalSelection.end(),
          [&](const int index) {
        return FindDecal(*decals, index) == nullptr;
      }
        ),
        mDecalSelection.end()
      );
      gpg::Logf("editor: %s a decal edit: %d decals", redo ? "redid" : "undid", decals->GetDecalCount());
    }
    return true;
  }

  bool EdMapScene::UndoSaveData(
    const bool redo
  )
  {
    auto& from = redo ? mDocument.SaveDataRedo() : mDocument.SaveDataUndo();
    auto& to = redo ? mDocument.SaveDataUndo() : mDocument.SaveDataRedo();
    if (from.empty()) {
      return false;
    }
    auto step = std::move(from.back());
    from.pop_back();
    mDocument.RestoreSaveData(redo ? step.second : step.first);
    to.push_back(std::move(step));
    mOutsideStale = true;
    ReloadUnits();
    gpg::Logf(
      "editor: %s a save edit (markers, areas, armies, units): %zu markers, %zu units",
      redo ? "redid" : "undid",
      mDocument.SaveData().Markers().size(),
      mUnitRefs.size()
    );
    return true;
  }

  void EdMapScene::ChangePlayableArea(
    const std::optional<EdDocument::PlayableRect>& area
  )
  {
    if (mMap == nullptr || mDocument.PlayableArea() == area) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    mDocument.SetPlayableArea(area);
    mDocument.SaveDataEdited(std::move(before));
    mOutsideStale = true;
    if (area) {
      gpg::Logf("editor: playable area %d, %d to %d, %d", area->x0, area->z0, area->x1, area->z1);
    } else {
      gpg::Logf("editor: no playable area");
    }
  }

  void EdMapScene::BuildOutsideQuads(
    const EdDocument::PlayableRect& area
  )
  {
    mOutsideQuads.clear();
    mOutsideFor = area;
    mOutsideStale = false;
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    // The ground outside the area under a dark veil, in blocks of 8 units cut at the border.
    constexpr int kBlock = 8;
    constexpr std::uint32_t kVeil = 0x99000000u;
    const int width = field->width - 1;
    const int height = field->height - 1;
    const auto groundAt = [field](const float x, const float z) {
      const int sx = std::clamp(static_cast<int>(std::lround(x)), 0, field->width - 1);
      const int sz = std::clamp(static_cast<int>(std::lround(z)), 0, field->height - 1);
      moho::CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = static_cast<float>(field->data[sz * field->width + sx]) / 128.0f + 0.25f;
      vertex.mZ = z;
      vertex.mColor = kVeil;
      return vertex;
    };
    for (int z0 = 0; z0 < height; z0 += kBlock) {
      for (int x0 = 0; x0 < width; x0 += kBlock) {
        const int x1 = std::min(width, x0 + kBlock);
        const int z1 = std::min(height, z0 + kBlock);
        // The part of the block outside the area: the block itself when it misses the area, else up to four strips.
        const auto quad = [&](const int qx0, const int qz0, const int qx1, const int qz1) {
          if (qx0 >= qx1 || qz0 >= qz1) {
            return;
          }
          mOutsideQuads.push_back(groundAt(static_cast<float>(qx0), static_cast<float>(qz0)));
          mOutsideQuads.push_back(groundAt(static_cast<float>(qx1), static_cast<float>(qz0)));
          mOutsideQuads.push_back(groundAt(static_cast<float>(qx1), static_cast<float>(qz1)));
          mOutsideQuads.push_back(groundAt(static_cast<float>(qx0), static_cast<float>(qz1)));
        };
        const int ix0 = std::max(x0, area.x0);
        const int iz0 = std::max(z0, area.z0);
        const int ix1 = std::min(x1, area.x1);
        const int iz1 = std::min(z1, area.z1);
        if (ix0 >= ix1 || iz0 >= iz1) {
          quad(x0, z0, x1, z1);
          continue;
        }
        quad(x0, z0, x1, iz0);
        quad(x0, iz1, x1, z1);
        quad(x0, iz0, ix0, iz1);
        quad(ix1, iz0, x1, iz1);
      }
    }
  }

  namespace
  {
    /** How far a marker's symmetric copy may sit from the exact mirrored point (placement rounds copies to the half
     * unit). */
    constexpr float kCopyReach = 1.5f;
  } // namespace

  bool EdMapScene::GizmoOrigin(
    Wm3::Vec3f& origin
  ) const
  {
    if (mTools == nullptr || mMap == nullptr) {
      return false;
    }
    float sx = 0.0f, sy = 0.0f, sz = 0.0f;
    int count = 0;
    PickKind kind = PickKind::None;
    if (mTools->MarkersToolActive()) {
      kind = PickKind::Marker;
    } else if (mTools->UnitsToolActive() && !mTools->UnitPlaceMode()) {
      kind = PickKind::Unit;
    } else if (mTools->DecalsToolActive() && mTools->DecalSelectMode()) {
      kind = PickKind::Decal;
    } else if (mTools->SelectToolActive()) {
      kind = SelectedKind();
    }
    if (kind == PickKind::Marker) {
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (
          std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end() &&
          ShownMarkerPosition(marker, x, y, z)
        ) {
          sx += x;
          sy += y;
          sz += z;
          ++count;
        }
      }
    } else if (kind == PickKind::Unit) {
      for (const auto& [army, name] : mUnitSelection) {
        const int index = UnitRefIndex(army, name);
        if (index >= 0) {
          const Wm3::Vec3f& p = mUnitRefs[static_cast<std::size_t>(index)].position;
          sx += p.x;
          sy += p.y;
          sz += p.z;
          ++count;
        }
      }
    } else if (kind == PickKind::Decal) {
      if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
        for (const int index : mDecalSelection) {
          if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, index); decal != nullptr) {
            float cx = 0.0f, cz = 0.0f;
            DecalCentre(FootprintOf(*decal), cx, cz);
            sx += cx;
            sy += decal->mPosition.y;
            sz += cz;
            ++count;
          }
        }
      }
    } else if (kind == PickKind::Prop && mMap->mProps != nullptr) {
      for (const int index : mSelection) {
        const Wm3::Vec3f& p = mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_;
        sx += p.x;
        sy += p.y;
        sz += p.z;
        ++count;
      }
    }
    if (count == 0) {
      return false;
    }
    origin = Wm3::Vec3f{sx / static_cast<float>(count), sy / static_cast<float>(count), sz / static_cast<float>(count)};
    return true;
  }

  namespace
  {
    Wm3::Vec3f GizmoAxis(
      const EdMapScene::GizmoPart part
    )
    {
      switch (part) {
      case EdMapScene::GizmoPart::X:
        return Wm3::Vec3f{1.0f, 0.0f, 0.0f};
      case EdMapScene::GizmoPart::Y:
        return Wm3::Vec3f{0.0f, 1.0f, 0.0f};
      case EdMapScene::GizmoPart::Z:
        return Wm3::Vec3f{0.0f, 0.0f, 1.0f};
      default:
        return Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      }
    }

    /** A corner's two arms (Free: the ground's X and Z). */
    void GizmoPlaneAxes(
      const EdMapScene::GizmoPart part,
      Wm3::Vec3f& u,
      Wm3::Vec3f& v
    )
    {
      u = part == EdMapScene::GizmoPart::ZY ? Wm3::Vec3f{0.0f, 0.0f, 1.0f} : Wm3::Vec3f{1.0f, 0.0f, 0.0f};
      v = part == EdMapScene::GizmoPart::Free ? Wm3::Vec3f{0.0f, 0.0f, 1.0f} : Wm3::Vec3f{0.0f, 1.0f, 0.0f};
    }

    /** How far out along its arms a corner reaches, as a share of the arms' length. */
    constexpr float kGizmoCorner = 0.34f;

    /** The distance on screen from `p` to the segment a-b. */
    float SegmentDistance(
      const Wm3::Vector2f& p,
      const Wm3::Vector2f& a,
      const Wm3::Vector2f& b
    )
    {
      const float dx = b.x - a.x;
      const float dy = b.y - a.y;
      const float length2 = dx * dx + dy * dy;
      const float t = length2 > 0.0f ? std::clamp(((p.x - a.x) * dx + (p.y - a.y) * dy) / length2, 0.0f, 1.0f) : 0.0f;
      return std::hypot(p.x - (a.x + dx * t), p.y - (a.y + dy * t));
    }
  } // namespace

  EdMapScene::GizmoPart EdMapScene::PickGizmo(
    const POINT at
  ) const
  {
    Wm3::Vec3f origin;
    if (mCamera == nullptr || !GizmoOrigin(origin)) {
      return GizmoPart::None;
    }
    const float length = GizmoLength();
    const Wm3::Vector2f cursor(static_cast<float>(at.x), static_cast<float>(at.y));
    const Wm3::Vector2f centre = mCamera->Project(origin);
    if (std::hypot(cursor.x - centre.x, cursor.y - centre.y) < 10.0f) {
      return GizmoPart::Free;
    }
    // An arm right under the cursor wins over the corner beside it.
    GizmoPart best = GizmoPart::None;
    float bestDistance = 6.0f;
    for (const GizmoPart part : {GizmoPart::X, GizmoPart::Y, GizmoPart::Z}) {
      const Wm3::Vec3f axis = GizmoAxis(part);
      const Wm3::Vector2f tip = mCamera->Project(
        Wm3::Vec3f{origin.x + axis.x * length, origin.y + axis.y * length, origin.z + axis.z * length}
      );
      // The arm from a quarter of its length, so the middle stays the free square's.
      const Wm3::Vector2f from(centre.x + (tip.x - centre.x) * 0.25f, centre.y + (tip.y - centre.y) * 0.25f);
      const float d = SegmentDistance(cursor, from, tip);
      if (d < bestDistance) {
        bestDistance = d;
        best = part;
      }
    }
    if (best != GizmoPart::None) {
      return best;
    }
    // Inside a corner's square, from the middle out along its two arms (convex: the cursor on the same side of each
    // edge). The ground's first, then the upright ones; one seen edge-on (no area on screen) is left out.
    for (const GizmoPart part : {GizmoPart::Free, GizmoPart::XY, GizmoPart::ZY}) {
      Wm3::Vec3f u;
      Wm3::Vec3f v;
      GizmoPlaneAxes(part, u, v);
      const float a = length * kGizmoCorner;
      const Wm3::Vector2f q[4] = {
        centre,
        mCamera->Project(Wm3::Vec3f{origin.x + u.x * a, origin.y + u.y * a, origin.z + u.z * a}),
        mCamera->Project(
          Wm3::Vec3f{origin.x + (u.x + v.x) * a, origin.y + (u.y + v.y) * a, origin.z + (u.z + v.z) * a}
        ),
        mCamera->Project(Wm3::Vec3f{origin.x + v.x * a, origin.y + v.y * a, origin.z + v.z * a})
      };
      int positive = 0;
      int negative = 0;
      float area = 0.0f;
      for (int i = 0; i < 4; ++i) {
        const Wm3::Vector2f& e0 = q[i];
        const Wm3::Vector2f& e1 = q[(i + 1) % 4];
        const float cross = (e1.x - e0.x) * (cursor.y - e0.y) - (e1.y - e0.y) * (cursor.x - e0.x);
        positive += cross > 0.0f ? 1 : 0;
        negative += cross < 0.0f ? 1 : 0;
        area += e0.x * e1.y - e1.x * e0.y;
      }
      if (std::fabs(area) > 40.0f && (positive == 4 || negative == 4)) {
        return part;
      }
    }
    return GizmoPart::None;
  }

  void EdMapScene::DrawGizmo(
    moho::CD3DPrimBatcher& batcher
  )
  {
    Wm3::Vec3f origin;
    if (mCamera == nullptr || !GizmoOrigin(origin)) {
      return;
    }
    const GizmoPart hot = mGizmoDrag != GizmoPart::None ? mGizmoDrag : PickGizmo(mCursor);
    const float length = GizmoLength();
    const auto vertex = [](const Wm3::Vec3f& p, const std::uint32_t color) {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = p.x;
      v.mY = p.y;
      v.mZ = p.z;
      v.mColor = color;
      return v;
    };
    const auto add = [](const Wm3::Vec3f& a, const Wm3::Vec3f& d, const float s) {
      return Wm3::Vec3f{a.x + d.x * s, a.y + d.y * s, a.z + d.z * s};
    };
    constexpr std::uint32_t kHot = 0xFFFFE040u;
    const std::pair<GizmoPart, std::uint32_t> arms[] = {
      {GizmoPart::X, 0xFFFF4848u}, {GizmoPart::Y, 0xFF48E048u}, {GizmoPart::Z, 0xFF4880FFu}
    };
    // Each arm as a bundle of lines around its axis (the batcher draws one-pixel lines), so it reads thick from any
    // side.
    const float thick = length * 0.012f;
    for (const auto& [part, color] : arms) {
      const std::uint32_t c = part == hot ? kHot : color;
      const Wm3::Vec3f axis = GizmoAxis(part);
      const Wm3::Vec3f across1 = part == GizmoPart::Y ? Wm3::Vec3f{1.0f, 0.0f, 0.0f} : Wm3::Vec3f{0.0f, 1.0f, 0.0f};
      const Wm3::Vec3f across2 = part == GizmoPart::Z ? Wm3::Vec3f{1.0f, 0.0f, 0.0f} : Wm3::Vec3f{0.0f, 0.0f, 1.0f};
      const Wm3::Vec3f tip = add(origin, axis, length);
      const Wm3::Vec3f from = add(origin, axis, length * 0.15f);
      const Wm3::Vec3f back = add(origin, axis, length * 0.78f);
      for (int k = 0; k < 5; ++k) {
        const float u = k == 1 ? thick : k == 2 ? -thick : 0.0f;
        const float v = k == 3 ? thick : k == 4 ? -thick : 0.0f;
        const Wm3::Vec3f offset{
          across1.x * u + across2.x * v, across1.y * u + across2.y * v, across1.z * u + across2.z * v
        };
        batcher.DrawLine(vertex(add(from, offset, 1.0f), c), vertex(add(back, offset, 1.0f), c));
      }
      // The head: a cone of lines from the tip back around the arm.
      for (int s = 0; s < 12; ++s) {
        const float angle = 2.0f * kPi * static_cast<float>(s) / 12.0f;
        const float u = std::cos(angle) * length * 0.07f;
        const float v = std::sin(angle) * length * 0.07f;
        const Wm3::Vec3f rim{
          back.x + across1.x * u + across2.x * v,
          back.y + across1.y * u + across2.y * v,
          back.z + across1.z * u + across2.z * v
        };
        batcher.DrawLine(vertex(tip, c), vertex(rim, c));
      }
    }
    // The corners between two arms (CryEngine's and Blender's plane handles): two lines, each leaving one arm at a
    // third of its length in that arm's colour and meeting the other's, so the corner hangs on both arms; hovered or
    // dragged, they turn yellow over a filled square. Free (X and Z) moves over the ground, XY and ZY up and down too.
    const auto colorOf = [](const Wm3::Vec3f& axis) {
      return axis.x > 0.5f ? 0xFFFF4848u : axis.y > 0.5f ? 0xFF48E048u : 0xFF4880FFu;
    };
    for (const GizmoPart part : {GizmoPart::Free, GizmoPart::XY, GizmoPart::ZY}) {
      Wm3::Vec3f u;
      Wm3::Vec3f v;
      GizmoPlaneAxes(part, u, v);
      const bool cornerHot = hot == part;
      const float a = length * kGizmoCorner;
      const Wm3::Vec3f onU = add(origin, u, a);
      const Wm3::Vec3f onV = add(origin, v, a);
      const Wm3::Vec3f corner = add(onU, v, a);
      if (cornerHot) {
        moho::CD3DPrimBatcher::Vertex quad[4] = {
          vertex(origin, 0x70FFE040u), vertex(onU, 0x70FFE040u), vertex(corner, 0x70FFE040u), vertex(onV, 0x70FFE040u)
        };
        batcher.DrawQuads(quad, 1);
      }
      // Each line doubled a hair apart, so it reads as heavy as the arms' bundles.
      const float n = length * 0.006f;
      for (const float k : {-n, 0.0f, n}) {
        const Wm3::Vec3f lift{(u.x + v.x) * k, (u.y + v.y) * k, (u.z + v.z) * k};
        const std::uint32_t fromU = cornerHot ? kHot : colorOf(u);
        const std::uint32_t fromV = cornerHot ? kHot : colorOf(v);
        batcher.DrawLine(vertex(add(onU, lift, 1.0f), fromU), vertex(add(corner, lift, 1.0f), fromU));
        batcher.DrawLine(vertex(add(onV, lift, 1.0f), fromV), vertex(add(corner, lift, 1.0f), fromV));
      }
    }
    // The free square, on the ground plane through the middle.
    const bool planeHot = hot == GizmoPart::Free;
    const std::uint32_t free = planeHot ? kHot : 0xFFF0F0F0u;
    const float s = length * 0.08f;
    const Wm3::Vec3f corners[4] = {
      {origin.x - s, origin.y, origin.z - s},
      {origin.x + s, origin.y, origin.z - s},
      {origin.x + s, origin.y, origin.z + s},
      {origin.x - s, origin.y, origin.z + s}
    };
    for (int i = 0; i < 4; ++i) {
      batcher.DrawLine(vertex(corners[i], free), vertex(corners[(i + 1) % 4], free));
    }
  }

  void EdMapScene::BeginGizmoDrag(
    const GizmoPart part,
    const POINT at
  )
  {
    mGizmoDrag = part;
    mGizmoFrom = at;
    (void)GizmoOrigin(mGizmoStart);
    mGizmoDragLength = GizmoLength();
    if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), mGizmoGroundX, mGizmoGroundZ)) {
      mGizmoGroundX = mGizmoStart.x;
      mGizmoGroundZ = mGizmoStart.z;
    }
    gpg::Logf(
      "editor: move gizmo %s drag from %.2f, %.2f, %.2f",
      part == GizmoPart::X      ? "X"
        : part == GizmoPart::Y  ? "Y"
        : part == GizmoPart::Z  ? "Z"
        : part == GizmoPart::XY ? "XY"
        : part == GizmoPart::ZY ? "ZY"
                                : "free",
      static_cast<double>(mGizmoStart.x),
      static_cast<double>(mGizmoStart.y),
      static_cast<double>(mGizmoStart.z)
    );
  }

  Wm3::Vec3f EdMapScene::GizmoDisplacement(
    const POINT at
  ) const
  {
    if (mGizmoDrag == GizmoPart::Free) {
      float x = 0.0f;
      float z = 0.0f;
      if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), x, z)) {
        return Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      }
      return Wm3::Vec3f{x - mGizmoGroundX, 0.0f, z - mGizmoGroundZ};
    }
    if (mGizmoDrag == GizmoPart::XY || mGizmoDrag == GizmoPart::ZY) {
      // Both arms on screen at the drag's start: the cursor's move is s along one and t along the other (two
      // equations).
      Wm3::Vec3f u;
      Wm3::Vec3f v;
      GizmoPlaneAxes(mGizmoDrag, u, v);
      const float L = mGizmoDragLength;
      const Wm3::Vector2f o = mCamera->Project(mGizmoStart);
      const Wm3::Vector2f pu =
        mCamera->Project(Wm3::Vec3f{mGizmoStart.x + u.x * L, mGizmoStart.y + u.y * L, mGizmoStart.z + u.z * L});
      const Wm3::Vector2f pv =
        mCamera->Project(Wm3::Vec3f{mGizmoStart.x + v.x * L, mGizmoStart.y + v.y * L, mGizmoStart.z + v.z * L});
      const float ax = pu.x - o.x;
      const float ay = pu.y - o.y;
      const float bx = pv.x - o.x;
      const float by = pv.y - o.y;
      const float det = ax * by - ay * bx;
      if (std::fabs(det) < 4.0f) {
        return Wm3::Vec3f{0.0f, 0.0f, 0.0f}; // the plane is seen edge-on: no usable direction
      }
      const float dx = static_cast<float>(at.x - mGizmoFrom.x);
      const float dy = static_cast<float>(at.y - mGizmoFrom.y);
      const float s = (dx * by - dy * bx) / det * L;
      const float t = (ax * dy - ay * dx) / det * L;
      return Wm3::Vec3f{u.x * s + v.x * t, u.y * s + v.y * t, u.z * s + v.z * t};
    }
    // The arm on screen at the drag's start; the cursor's move along it, in world units.
    const Wm3::Vec3f axis = GizmoAxis(mGizmoDrag);
    const Wm3::Vector2f from = mCamera->Project(mGizmoStart);
    const Wm3::Vector2f to = mCamera->Project(
      Wm3::Vec3f{
        mGizmoStart.x + axis.x * mGizmoDragLength,
        mGizmoStart.y + axis.y * mGizmoDragLength,
        mGizmoStart.z + axis.z * mGizmoDragLength
      }
    );
    const float sx = to.x - from.x;
    const float sy = to.y - from.y;
    const float length2 = sx * sx + sy * sy;
    if (length2 < 4.0f) {
      return Wm3::Vec3f{0.0f, 0.0f, 0.0f}; // the arm points at the camera: no usable direction
    }
    const float dx = static_cast<float>(at.x - mGizmoFrom.x);
    const float dy = static_cast<float>(at.y - mGizmoFrom.y);
    const float t = (dx * sx + dy * sy) / length2 * mGizmoDragLength;
    return Wm3::Vec3f{axis.x * t, axis.y * t, axis.z * t};
  }

  float EdMapScene::UnitRestHeight(
    const float x,
    const float z
  ) const
  {
    const float ground = mMap->mTerrainRes->GetHeightAt(
      static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
    );
    const WaterState water = mDocument.WaterNow();
    return water.enabled ? std::max(ground, water.elevation) : ground;
  }

  Wm3::Vec3f EdMapScene::GizmoPlace(
    const Wm3::Vec3f& start,
    const Wm3::Vec3f& move,
    const bool resource,
    const bool unit
  ) const
  {
    float x = start.x + move.x;
    float z = start.z + move.z;
    if (mGizmoDrag != GizmoPart::Y) {
      if (resource) {
        x = std::floor(x) + 0.5f;
        z = std::floor(z) + 0.5f;
      } else {
        x = SnapToGrid(x);
        z = SnapToGrid(z);
      }
    }
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    x = std::clamp(x, 0.0f, static_cast<float>(field->width - 1));
    z = std::clamp(z, 0.0f, static_cast<float>(field->height - 1));
    const float ground = unit ? UnitRestHeight(x, z)
                              : mMap->mTerrainRes->GetHeightAt(
                                  static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
                                );
    float y = 0.0f;
    if (mGizmoDrag == GizmoPart::Y || mGizmoDrag == GizmoPart::XY || mGizmoDrag == GizmoPart::ZY) {
      y = std::max(start.y + move.y, ground);
    } else if (mTools != nullptr && mTools->KeepOnGround()) {
      y = ground;
    } else {
      y = std::max(start.y, ground);
    }
    return Wm3::Vec3f{x, y, z};
  }

  float EdMapScene::SnapToGrid(
    const float value
  ) const
  {
    if (mTools == nullptr || !mTools->SnapToGrid()) {
      return value;
    }
    const float step = mTools->GridStep();
    return std::floor(value / step) * step + step * 0.5f;
  }

  int EdMapScene::BorderEdgesAt(
    const float groundX,
    const float groundZ
  ) const
  {
    const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea();
    if (!area) {
      return 0;
    }
    const float reach = std::max(4.0f, mDistance * 0.015f);
    const bool alongZ =
      groundZ > static_cast<float>(area->z0) - reach && groundZ < static_cast<float>(area->z1) + reach;
    const bool alongX =
      groundX > static_cast<float>(area->x0) - reach && groundX < static_cast<float>(area->x1) + reach;
    int edges = 0;
    edges |= alongZ && std::fabs(groundX - static_cast<float>(area->x0)) < reach ? 1 : 0;
    edges |= alongX && std::fabs(groundZ - static_cast<float>(area->z0)) < reach ? 2 : 0;
    edges |= alongZ && std::fabs(groundX - static_cast<float>(area->x1)) < reach ? 4 : 0;
    edges |= alongX && std::fabs(groundZ - static_cast<float>(area->z1)) < reach ? 8 : 0;
    return edges;
  }

  bool EdMapScene::ShownMarkerPosition(
    const SaveEntry& marker,
    float& x,
    float& y,
    float& z
  ) const
  {
    if (!MarkerPosition(marker, x, y, z)) {
      return false;
    }
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || MarkerTypeOf(marker) == "Camera Info") {
      return true;
    }
    // Between the four samples around it, as the ground is drawn.
    const float gx = std::clamp(x, 0.0f, static_cast<float>(field->width - 1));
    const float gz = std::clamp(z, 0.0f, static_cast<float>(field->height - 1));
    const int x0 = std::min(static_cast<int>(gx), field->width - 2);
    const int z0 = std::min(static_cast<int>(gz), field->height - 2);
    const float fx = gx - static_cast<float>(x0);
    const float fz = gz - static_cast<float>(z0);
    const auto at = [field](const int sx, const int sz) {
      return static_cast<float>(field->data[sz * field->width + sx]) / 128.0f;
    };
    const float top = at(x0, z0) + (at(x0 + 1, z0) - at(x0, z0)) * fx;
    const float bottom = at(x0, z0 + 1) + (at(x0 + 1, z0 + 1) - at(x0, z0 + 1)) * fx;
    y = top + (bottom - top) * fz;
    return true;
  }

  EdMapScene::PickHit EdMapScene::PickAnything(
    const POINT at
  ) const
  {
    PickHit best;
    if (mMap == nullptr || mCamera == nullptr) {
      return best;
    }
    // On screen: each thing as a short upright line from its base, so a click on a tree's crown or a unit's body
    // picks it from any angle; its distance in pixels as a share of its kind's reach, the nearest winning.
    const Wm3::Vector2f cursor(static_cast<float>(at.x), static_cast<float>(at.y));
    float bestScore = 1.0f;
    const auto consider =
      [&](const PickKind kind, const int index, const Wm3::Vec3f& base, const float height, const float reach) {
      const Wm3::Vector2f a = mCamera->Project(base);
      if (std::fabs(a.x - cursor.x) > 400.0f || std::fabs(a.y - cursor.y) > 400.0f) {
        return; // far off: not worth the second projection
      }
      const Wm3::Vector2f b = mCamera->Project(Wm3::Vec3f{base.x, base.y + height, base.z});
      // The reach in pixels, or a unit and a half of the ground when the camera is closer than that.
      const Wm3::Vector2f side = mCamera->Project(Wm3::Vec3f{base.x + 1.5f, base.y, base.z});
      const float pixels = std::max(reach, std::hypot(side.x - a.x, side.y - a.y));
      const float score = SegmentDistance(cursor, a, b) / pixels;
      if (score < bestScore) {
        bestScore = score;
        best = PickHit{kind, index};
      }
    };
    // What the Select tool's Pick pills let through (all of it without the tools).
    const PickFilter pickable = mTools != nullptr ? mTools->Pickable() : PickFilter{};
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (
        pickable.Marker(MarkerGroupOf(markers[i])) && !MarkerHidden(markers[i]) &&
        ShownMarkerPosition(markers[i], x, y, z)
      ) {
        consider(PickKind::Marker, static_cast<int>(i), Wm3::Vec3f{x, y, z}, 4.0f, 14.0f);
      }
    }
    for (std::size_t i = 0; i < mUnitRefs.size() && pickable.units && (mTools == nullptr || mTools->ShowUnits()); ++i) {
      if (
        mTools != nullptr && !mTools->PreviewHiddenUnits().empty() &&
        mTools->PreviewHiddenUnits().contains({mUnitRefs[i].army, mUnitRefs[i].name})
      ) {
        continue; // hidden by the lobby preview
      }
      consider(PickKind::Unit, static_cast<int>(i), mUnitRefs[i].position, 2.5f, 16.0f);
    }
    if (mMap->mProps != nullptr && pickable.props && (mTools == nullptr || mTools->ShowProps())) {
      const auto& entries = mMap->mProps->mEntries;
      for (std::size_t i = 0; i < entries.size(); ++i) {
        consider(PickKind::Prop, static_cast<int>(i), entries[i].mTransform.pos_, 3.0f, 12.0f);
      }
    }
    // Nothing near: the decal under the cursor.
    float gx = 0.0f;
    float gz = 0.0f;
    if (best.kind == PickKind::None && pickable.decals && GroundAt(cursor.x, cursor.y, gx, gz)) {
      if (const int decal = PickDecal(gx, gz); decal >= 0) {
        best = PickHit{PickKind::Decal, decal};
      }
    }
    return best;
  }

  bool EdMapScene::PickPlace(
    const PickHit& hit,
    float& x,
    float& z,
    float& radius
  ) const
  {
    switch (hit.kind) {
    case PickKind::Marker: {
      const SaveEntry& marker = mDocument.SaveData().Markers()[static_cast<std::size_t>(hit.index)];
      float y = 0.0f;
      const std::string type = MarkerTypeOf(marker);
      radius = type == "Blank Marker" ? 7.0f : type == "Hydrocarbon" ? 4.5f : 3.0f;
      return ShownMarkerPosition(marker, x, y, z);
    }
    case PickKind::Unit:
      x = mUnitRefs[static_cast<std::size_t>(hit.index)].position.x;
      z = mUnitRefs[static_cast<std::size_t>(hit.index)].position.z;
      radius = 2.2f;
      return true;
    case PickKind::Prop:
      x = mMap->mProps->mEntries[static_cast<std::size_t>(hit.index)].mTransform.pos_.x;
      z = mMap->mProps->mEntries[static_cast<std::size_t>(hit.index)].mTransform.pos_.z;
      radius = 2.6f;
      return true;
    case PickKind::Decal:
      if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, hit.index); decal != nullptr) {
          const DecalFootprint footprint = FootprintOf(*decal);
          DecalCentre(footprint, x, z);
          radius = 0.5f * std::hypot(footprint.sizeX, footprint.sizeZ);
          return true;
        }
      }
      return false;
    default:
      return false;
    }
  }

  EdMapScene::PickKind EdMapScene::SelectedKind() const
  {
    const auto has = [&](const PickKind kind) {
      switch (kind) {
      case PickKind::Prop:
        return !mSelection.empty();
      case PickKind::Marker:
        return !mMarkerSelection.empty();
      case PickKind::Unit:
        return !mUnitSelection.empty();
      case PickKind::Decal:
        return !mDecalSelection.empty();
      default:
        return false;
      }
    };
    if (has(mSelectKind)) {
      return mSelectKind;
    }
    for (const PickKind kind : {PickKind::Marker, PickKind::Unit, PickKind::Prop, PickKind::Decal}) {
      if (has(kind)) {
        return kind;
      }
    }
    return PickKind::None;
  }

  void EdMapScene::ClearAllSelections()
  {
    mSelection.clear();
    mMarkerSelection.clear();
    mUnitSelection.clear();
    mDecalSelection.clear();
  }

  void EdMapScene::BeginSelectionDrag(
    const HWND window,
    const PickKind kind,
    const GizmoPart part,
    const POINT at,
    const float groundX,
    const float groundZ
  )
  {
    if (part != GizmoPart::None) {
      BeginGizmoDrag(part, at);
    }
    switch (kind) {
    case PickKind::Prop:
      if (mMap->mProps == nullptr) {
        return;
      }
      BeginObjectStroke();
      mDragSelection = true;
      mDragFromX = groundX;
      mDragFromZ = groundZ;
      mDragStart.clear();
      for (const int index : mSelection) {
        mDragStart.push_back(mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_);
      }
      mPropFollow = FollowDrag() ? PropPartners() : std::vector<std::vector<int>>{};
      break;
    case PickKind::Marker:
      mDragMarkers = true;
      mMarkersMoved = false;
      mMarkerDragFromX = groundX;
      mMarkerDragFromZ = groundZ;
      mMarkerBefore = mDocument.SaveDataNow();
      mMarkerDragStart.clear();
      BeginAreaFollow();
      mMarkerFollow = FollowDrag() ? MarkerPartners() : std::vector<std::vector<std::string>>{};
      for (const std::string& selected : mMarkerSelection) {
        std::array<float, 3> start{};
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          if (marker.name == selected) {
            (void)ShownMarkerPosition(marker, start[0], start[1], start[2]);
          }
        }
        mMarkerDragStart.push_back(start);
      }
      break;
    case PickKind::Unit:
      mDragUnits = true;
      mUnitsMoved = false;
      mUnitDragFromX = groundX;
      mUnitDragFromZ = groundZ;
      mUnitBefore = mDocument.SaveDataNow();
      mUnitDragStart.clear();
      for (const auto& [army, name] : mUnitSelection) {
        const int index = UnitRefIndex(army, name);
        mUnitDragStart.push_back(
          index >= 0 ? mUnitRefs[static_cast<std::size_t>(index)].position : Wm3::Vec3f{0.0f, 0.0f, 0.0f}
        );
      }
      mUnitFollow = FollowDrag() ? UnitPartners() : decltype(mUnitFollow){};
      break;
    case PickKind::Decal: {
      moho::IDecalManager* const decals = mDocument.Decals();
      if (decals == nullptr) {
        return;
      }
      mDragDecals = true;
      mDecalsMoved = false;
      mDecalDragFromX = groundX;
      mDecalDragFromZ = groundZ;
      mDecalBefore = mDocument.DecalsNow();
      mDecalDragStart.clear();
      for (const int index : mDecalSelection) {
        std::array<float, 3> start{};
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, index); decal != nullptr) {
          start = {decal->mPosition.x, decal->mPosition.y, decal->mPosition.z};
        }
        mDecalDragStart.push_back(start);
      }
      mDecalFollow = FollowDrag() ? DecalPartners() : std::vector<std::vector<int>>{};
      break;
    }
    default:
      mGizmoDrag = GizmoPart::None;
      return;
    }
    ::SetCapture(window);
    ::SetFocus(window);
  }

  std::string EdMapScene::SelectionText() const
  {
    char text[160];
    switch (SelectedKind()) {
    case PickKind::Marker:
      (void)std::snprintf(
        text,
        sizeof(text),
        "%zu marker%s: %s%s",
        mMarkerSelection.size(),
        mMarkerSelection.size() == 1 ? "" : "s",
        mMarkerSelection.front().c_str(),
        mMarkerSelection.size() > 1 ? ", ..." : ""
      );
      return text;
    case PickKind::Unit:
      (void)std::snprintf(
        text,
        sizeof(text),
        "%zu unit%s: %s (%s)%s",
        mUnitSelection.size(),
        mUnitSelection.size() == 1 ? "" : "s",
        mUnitSelection.front().second.c_str(),
        mUnitSelection.front().first.c_str(),
        mUnitSelection.size() > 1 ? ", ..." : ""
      );
      return text;
    case PickKind::Prop: {
      const std::string blueprint =
        mMap->mProps->mEntries[static_cast<std::size_t>(mSelection.front())].mBlueprintPath.c_str();
      const std::size_t slash = blueprint.find_last_of('/');
      (void)std::snprintf(
        text,
        sizeof(text),
        "%zu prop%s: %s%s",
        mSelection.size(),
        mSelection.size() == 1 ? "" : "s",
        slash == std::string::npos ? blueprint.c_str() : blueprint.c_str() + slash + 1,
        mSelection.size() > 1 ? ", ..." : ""
      );
      return text;
    }
    case PickKind::Decal:
      (void)std::snprintf(
        text, sizeof(text), "%zu decal%s", mDecalSelection.size(), mDecalSelection.size() == 1 ? "" : "s"
      );
      return text;
    default:
      return "Nothing selected";
    }
  }

  SelectionProperties EdMapScene::SelectionPropertiesNow() const
  {
    SelectionProperties out;
    if (mMap == nullptr) {
      return out;
    }
    switch (SelectedKind()) {
    case PickKind::Marker:
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        if (marker.name != mMarkerSelection.front()) {
          continue;
        }
        out.kind = SelectionProperties::Kind::Marker;
        out.count = static_cast<int>(mMarkerSelection.size());
        out.name = marker.name;
        out.type = MarkerTypeOf(marker);
        (void)MarkerPosition(marker, out.position[0], out.position[1], out.position[2]);
        const std::vector<double> turn = ValueNumbers(marker.Get("orientation"));
        out.heading = turn.size() >= 2 ? static_cast<float>(turn[1]) * 180.0f / kPi : 0.0f;
        for (const auto& [key, value] : marker.properties) {
          if (key != "position" && key != "orientation" && key != "type") {
            out.fields.emplace_back(key, value);
          }
        }
      }
      break;
    case PickKind::Unit: {
      const int index = UnitRefIndex(mUnitSelection.front().first, mUnitSelection.front().second);
      if (index < 0) {
        break;
      }
      const UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
      out.kind = SelectionProperties::Kind::Unit;
      out.count = static_cast<int>(mUnitSelection.size());
      out.name = ref.name;
      out.owner = ref.army;
      out.position[0] = ref.position.x;
      out.position[1] = ref.position.y;
      out.position[2] = ref.position.z;
      out.heading = ref.orientation[1] * 180.0f / kPi;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup group;
        if (entry.name == ref.army && ParseUnitGroup(entry.Get("Units"), group)) {
          if (const SaveUnit* const unit = FindUnit(group, ref.name); unit != nullptr) {
            out.type = unit->type;
          }
        }
      }
      break;
    }
    case PickKind::Prop: {
      const moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(mSelection.front())];
      out.kind = SelectionProperties::Kind::Prop;
      out.count = static_cast<int>(mSelection.size());
      out.type = entry.mBlueprintPath.c_str();
      const std::size_t slash = out.type.find_last_of('/');
      out.name = slash == std::string::npos ? out.type : out.type.substr(slash + 1);
      out.position[0] = entry.mTransform.pos_.x;
      out.position[1] = entry.mTransform.pos_.y;
      out.position[2] = entry.mTransform.pos_.z;
      out.heading = 2.0f * std::atan2(entry.mTransform.orient_.y, entry.mTransform.orient_.w) * 180.0f / kPi;
      out.details = PropDetails(out.type);
      const std::array<float, 3> scale = mDocument.PropScale(static_cast<std::size_t>(mSelection.front()));
      out.scale[0] = scale[0];
      out.scale[1] = scale[1];
      out.scale[2] = scale[2];
      break;
    }
    case PickKind::Decal:
      if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, mDecalSelection.front()); decal != nullptr) {
          const DecalState state = CaptureDecal(*decal);
          const DecalFootprint footprint = FootprintOf(*decal);
          out.kind = SelectionProperties::Kind::Decal;
          out.count = static_cast<int>(mDecalSelection.size());
          out.name = "decal " + std::to_string(mDecalSelection.front());
          out.type = state.names[0];
          DecalCentre(footprint, out.position[0], out.position[2]);
          out.position[1] = state.position[1];
          out.heading = footprint.yaw * 180.0f / kPi;
          out.size[0] = footprint.sizeX;
          out.size[1] = footprint.sizeZ;
        }
      }
      break;
    default:
      break;
    }
    // A heading in -180..180.
    while (out.heading > 180.0f) {
      out.heading -= 360.0f;
    }
    while (out.heading <= -180.0f) {
      out.heading += 360.0f;
    }
    return out;
  }

  void EdMapScene::ApplyPropertyEdit(
    const PropertyEdit& edit
  )
  {
    const SelectionProperties now = SelectionPropertiesNow();
    const float* const v = edit.values;
    const float radians = v[0] * kPi / 180.0f;
    // A heading typed for a selection of several: every selected object turns by what the first one turned (Studio's
    // gizmo turns the whole selection), not only the first.
    if (edit.what == PropertyEdit::What::Heading && now.count > 1) {
      float delta = v[0] - now.heading;
      while (delta > 180.0f) {
        delta -= 360.0f;
      }
      while (delta <= -180.0f) {
        delta += 360.0f;
      }
      (void)TurnEverySelected(delta * kPi / 180.0f);
      return;
    }
    switch (now.kind) {
    case SelectionProperties::Kind::Marker:
      if (edit.what == PropertyEdit::What::Position) {
        EditMarker(now.name, "position", Vector3Value(v[0], v[1], v[2]));
      } else if (edit.what == PropertyEdit::What::Heading) {
        EditMarker(now.name, "orientation", Vector3Value(0.0, radians, 0.0));
      } else if (edit.what == PropertyEdit::What::Name) {
        EditMarker(now.name, "name", edit.value);
      } else if (edit.what == PropertyEdit::What::Field) {
        EditMarker(now.name, edit.key, edit.value);
      } else if (edit.what == PropertyEdit::What::CameraView) {
        (void)LookThroughCamera(now.name);
      } else if (edit.what == PropertyEdit::What::CameraFromView) {
        (void)SetCameraMarkerFromView(now.name);
      }
      break;
    case SelectionProperties::Kind::Unit: {
      if (edit.what != PropertyEdit::What::Position && edit.what != PropertyEdit::What::Heading) {
        break;
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      const bool changed = EditArmyUnits(now.owner, [&](UnitGroup& group) {
        if (SaveUnit* const unit = FindUnit(group, now.name); unit != nullptr) {
          if (edit.what == PropertyEdit::What::Position) {
            unit->position[0] = v[0];
            unit->position[1] = v[1];
            unit->position[2] = v[2];
          } else {
            unit->orientation[1] = radians;
          }
        }
      });
      if (changed && !(before.armies == mDocument.SaveData().Armies())) {
        mDocument.SaveDataEdited(std::move(before));
        ReloadUnits();
        gpg::Logf(
          "editor: unit %s: %s", now.name.c_str(), edit.what == PropertyEdit::What::Position ? "moved" : "turned"
        );
      }
      break;
    }
    case SelectionProperties::Kind::Prop: {
      if (edit.what == PropertyEdit::What::Scale && mMap->mProps != nullptr) {
        for (const int index : mSelection) {
          if (index >= 0) {
            mDocument.SetPropScale(static_cast<std::size_t>(index), {v[0], v[1], v[2]});
          }
        }
        gpg::Logf(
          "editor: %zu props: scale in the file %.2f %.2f %.2f",
          mSelection.size(),
          static_cast<double>(v[0]),
          static_cast<double>(v[1]),
          static_cast<double>(v[2])
        );
        break;
      }
      if (edit.what == PropertyEdit::What::Blueprint && !edit.value.empty() && mMap->mProps != nullptr) {
        // Every selected prop becomes the chosen one where it stands (user ask 2026-11-11, WPE.55), as one undo step.
        BeginObjectStroke();
        int changed = 0;
        for (const int index : mSelection) {
          if (index < 0 || static_cast<std::size_t>(index) >= mMap->mProps->mEntries.size()) {
            continue;
          }
          moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
          if (edit.value == entry.mBlueprintPath.c_str()) {
            continue;
          }
          entry.mBlueprintPath.assign(edit.value.c_str());
          const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
          entry.mTransform = record.loaded;
          mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
          if (static_cast<std::size_t>(index) < mProps.size()) {
            delete mProps[static_cast<std::size_t>(index)];
            mProps[static_cast<std::size_t>(index)] = MakePropInstance(entry);
          }
          ++changed;
        }
        if (changed > 0) {
          DeletePropHighlight(); // it was the old model's
          mObjectsChanged = true;
          mDocument.SetModified(true);
        }
        EndObjectStroke();
        gpg::Logf("editor: %d props now %s", changed, edit.value.c_str());
        break;
      }
      if (edit.what != PropertyEdit::What::Position && edit.what != PropertyEdit::What::Heading) {
        break;
      }
      const int index = mSelection.front();
      BeginObjectStroke();
      if (edit.what == PropertyEdit::What::Position) {
        MovePropTo(index, Wm3::Vec3f{v[0], v[1], v[2]});
      } else {
        moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
        entry.mTransform.orient_ = Wm3::Quatf(std::cos(radians * 0.5f), 0.0f, std::sin(radians * 0.5f), 0.0f);
        const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
        entry.mTransform = record.loaded;
        mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
        if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
          mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
        }
        mObjectsChanged = true;
        mDocument.SetModified(true);
      }
      EndObjectStroke();
      gpg::Logf("editor: prop %d: %s", index, edit.what == PropertyEdit::What::Position ? "moved" : "turned");
      break;
    }
    case SelectionProperties::Kind::Decal: {
      moho::IDecalManager* const decals = mDocument.Decals();
      if (
        decals == nullptr ||
        (edit.what != PropertyEdit::What::Position && edit.what != PropertyEdit::What::Heading &&
         edit.what != PropertyEdit::What::Size)
      ) {
        break;
      }
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      std::vector<DecalState> states = before;
      for (DecalState& state : states) {
        if (state.index != mDecalSelection.front()) {
          continue;
        }
        // Kept about its middle: the decal's corner follows from the middle, size and heading.
        float cx = now.position[0];
        float cz = now.position[2];
        float sizeX = now.size[0];
        float sizeZ = now.size[1];
        float yaw = now.heading * kPi / 180.0f;
        if (edit.what == PropertyEdit::What::Position) {
          cx = v[0];
          cz = v[2];
          state.position[1] = v[1];
        } else if (edit.what == PropertyEdit::What::Heading) {
          yaw = radians;
        } else {
          sizeX = std::max(0.1f, v[0]);
          sizeZ = std::max(0.1f, v[1]);
        }
        const DecalFootprint footprint = DecalAround(cx, cz, sizeX, sizeZ, yaw);
        state.position[0] = footprint.x;
        state.position[2] = footprint.z;
        state.scale[0] = footprint.sizeX;
        state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
        state.scale[2] = footprint.sizeZ;
        state.orientation[1] = yaw;
      }
      RestoreDecals(*decals, states);
      if (!(mDocument.DecalsNow() == before)) {
        mDocument.DecalsEdited(std::move(before));
        gpg::Logf("editor: decal %d edited", mDecalSelection.front());
      }
      break;
    }
    default:
      break;
    }
  }

  std::vector<EdMapScene::ResourceMark> EdMapScene::ResourceMarks() const
  {
    std::vector<ResourceMark> out;
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (rules == nullptr || mTools == nullptr) {
      return out;
    }
    const std::set<std::string>& hidden = mTools->HiddenMarkerTypes();
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const std::string type = MarkerTypeOf(marker);
      if ((type != "Mass" && type != "Hydrocarbon") || hidden.contains(type)) {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      moho::RResId id{};
      id.name.assign(type == "Mass" ? "ueb1103" : "ueb1102");
      const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(id);
      if (bp == nullptr) {
        continue;
      }
      ResourceMark mark;
      mark.marker = marker.name;
      mark.mass = type == "Mass";
      mark.x = x;
      mark.z = z;
      mark.sizeX = std::max<int>(1, bp->mFootprint.mSizeX);
      mark.sizeZ = std::max<int>(1, bp->mFootprint.mSizeZ);
      const float fx = mark.sizeX * 0.5f;
      const float fz = mark.sizeZ * 0.5f;
      mark.footprint[0] = x - fx;
      mark.footprint[1] = z - fz;
      mark.footprint[2] = x + fx;
      mark.footprint[3] = z + fz;
      if (bp->Physics.SkirtSizeX > 0.0f && bp->Physics.SkirtSizeZ > 0.0f) {
        mark.skirt[0] = x - fx + bp->Physics.SkirtOffsetX;
        mark.skirt[1] = z - fz + bp->Physics.SkirtOffsetZ;
        mark.skirt[2] = mark.skirt[0] + bp->Physics.SkirtSizeX;
        mark.skirt[3] = mark.skirt[1] + bp->Physics.SkirtSizeZ;
      }
      out.push_back(std::move(mark));
    }
    for (ResourceMark& mark : out) {
      bool stacked = false;
      for (const ResourceMark& other : out) {
        stacked = stacked ||
          (&other != &mark && std::fabs(other.x - mark.x) < mark.sizeX * 0.5f &&
           std::fabs(other.z - mark.z) < mark.sizeZ * 0.5f);
      }
      const bool offGrid = std::fabs(SnapFootprint(mark.x, mark.sizeX) - mark.x) > 0.01f ||
        std::fabs(SnapFootprint(mark.z, mark.sizeZ) - mark.z) > 0.01f;
      mark.state = mResourceProblems.contains(mark.marker) ? 1 : stacked ? 2 : offGrid ? 3 : 0;
    }
    return out;
  }

  AreaBounds EdMapScene::AreaLimitBounds() const
  {
    AreaBounds bounds;
    if (mTools == nullptr || mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return bounds;
    }
    if (mTools->AreaLimit() == 1) {
      if (const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField(); field != nullptr) {
        bounds = {0.0f, 0.0f, static_cast<float>(field->width - 1), static_cast<float>(field->height - 1)};
      }
    } else if (mTools->AreaLimit() == 2) {
      if (const std::optional<EdDocument::PlayableRect> playable = mDocument.PlayableArea(); playable.has_value()) {
        bounds = {
          static_cast<float>(playable->x0),
          static_cast<float>(playable->z0),
          static_cast<float>(playable->x1),
          static_cast<float>(playable->z1)
        };
      }
    }
    return bounds;
  }

  HCURSOR EdMapScene::EditorCursor(
    const int kind
  )
  {
    // 32 x 32: a crosshair round the hot spot (16, 16) with a gap and the brush's sign at the lower right, or the pin;
    // the lines invert the screen under them (AND 1, XOR 1), so they show on any ground.
    static HCURSOR made[kEditorCursors] = {};
    const int k = std::clamp(kind, 0, kEditorCursors - 1);
    HCURSOR& cursor = made[k];
    if (cursor != nullptr) {
      return cursor;
    }
    std::uint8_t andMask[128];
    std::uint8_t xorMask[128];
    std::memset(andMask, 0xFF, sizeof(andMask));
    std::memset(xorMask, 0x00, sizeof(xorMask));
    const auto dot = [&](const int x, const int y) {
      const int bit = y * 32 + x;
      andMask[bit / 8] |= static_cast<std::uint8_t>(0x80 >> (bit % 8));
      xorMask[bit / 8] |= static_cast<std::uint8_t>(0x80 >> (bit % 8));
    };
    if (k == 5) {
      // The marker pin: a ring head and a stem to its point at the bottom, the hot spot.
      for (int a = 0; a < 48; ++a) {
        const double t = a * 6.2831853 / 48.0;
        dot(
          16 + static_cast<int>(std::lround(5.0 * std::cos(t))), 9 + static_cast<int>(std::lround(5.0 * std::sin(t)))
        );
      }
      for (int y = 14; y <= 30; ++y) {
        dot(16, y);
      }
      cursor = ::CreateCursor(::GetModuleHandleW(nullptr), 16, 30, 32, 32, andMask, xorMask);
      return cursor != nullptr ? cursor : ::LoadCursorW(nullptr, IDC_CROSS);
    }
    for (int d = 3; d <= 11; ++d) {
      dot(16 + d, 16);
      dot(16 - d, 16);
      dot(16, 16 + d);
      dot(16, 16 - d);
    }
    // The sign at the lower right, round (26, 26).
    switch (k) {
    case 0: // raise: +
    case 1: // lower: -
      for (int d = -3; d <= 3; ++d) {
        dot(26 + d, 26);
        dot(26 + d, 27);
        if (k == 0) {
          dot(26, 26 + d);
          dot(27, 26 + d);
        }
      }
      break;
    case 2: // flatten: a level bar on two feet
      for (int d = -4; d <= 4; ++d) {
        dot(26 + d, 24);
      }
      for (int d = 25; d <= 28; ++d) {
        dot(22, d);
        dot(30, d);
      }
      break;
    case 3: // smooth: a wave
      for (int d = -4; d <= 4; ++d) {
        dot(26 + d, 26 + static_cast<int>(std::lround(1.6 * std::sin(d * 0.8))));
      }
      break;
    default: // noise: scattered dots
      for (const auto& [x, y] :
           {std::pair{23, 23},
            std::pair{27, 24},
            std::pair{30, 26},
            std::pair{24, 27},
            std::pair{28, 29},
            std::pair{22, 30},
            std::pair{26, 31}}) {
        dot(x, y);
      }
      break;
    }
    cursor = ::CreateCursor(::GetModuleHandleW(nullptr), 16, 16, 32, 32, andMask, xorMask);
    return cursor != nullptr ? cursor : ::LoadCursorW(nullptr, IDC_CROSS);
  }

  EdMapScene::AreaHit EdMapScene::AreaUnder(
    const POINT at
  ) const
  {
    AreaHit hit;
    if (mTools == nullptr || mCamera == nullptr || mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return hit;
    }
    const auto rectOf = [](const SaveEntry& area, float (&r)[4]) {
      const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
      if (e.size() < 4) {
        return false;
      }
      r[0] = static_cast<float>(std::min(e[0], e[2]));
      r[1] = static_cast<float>(std::min(e[1], e[3]));
      r[2] = static_cast<float>(std::max(e[0], e[2]));
      r[3] = static_cast<float>(std::max(e[1], e[3]));
      return true;
    };
    const auto screen = [&](const float x, const float z) {
      const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
      return mCamera->Project(Wm3::Vec3f{x, y, z});
    };
    const Wm3::Vector2f cursor(static_cast<float>(at.x), static_cast<float>(at.y));
    const std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    const std::vector<std::string>& picked = mTools->AreaSelection();
    // A handle of a picked area first.
    for (const std::string& name : picked) {
      for (const SaveEntry& area : areas) {
        float r[4];
        if (area.name != name || !rectOf(area, r)) {
          continue;
        }
        const float hx[3] = {r[0], (r[0] + r[2]) * 0.5f, r[2]};
        const float hz[3] = {r[1], (r[1] + r[3]) * 0.5f, r[3]};
        const int edgeX[3] = {1, 0, 4};
        const int edgeZ[3] = {2, 0, 8};
        for (int i = 0; i < 3; ++i) {
          for (int j = 0; j < 3; ++j) {
            if (i == 1 && j == 1) {
              continue;
            }
            const Wm3::Vector2f h = screen(hx[i], hz[j]);
            if (std::hypot(h.x - cursor.x, h.y - cursor.y) <= 9.0f) {
              return AreaHit{name, edgeX[i] | edgeZ[j]};
            }
          }
        }
      }
    }
    // An outline within reach: the smallest area's.
    float bestArea = 1e30f;
    for (const SaveEntry& area : areas) {
      float r[4];
      if (!rectOf(area, r)) {
        continue;
      }
      const Wm3::Vector2f c[4] = {screen(r[0], r[1]), screen(r[2], r[1]), screen(r[2], r[3]), screen(r[0], r[3])};
      float closest = 1e9f;
      for (int e = 0; e < 4; ++e) {
        closest = std::min(closest, SegmentDistance(cursor, c[e], c[(e + 1) % 4]));
      }
      const float size = (r[2] - r[0]) * (r[3] - r[1]);
      if (closest <= 7.0f && size < bestArea) {
        bestArea = size;
        hit = AreaHit{area.name, 16};
      }
    }
    return hit;
  }

  POINT EdMapScene::ScreenOf(
    const float x,
    const float z
  ) const
  {
    const float y = mMap != nullptr && mMap->mTerrainRes != nullptr
      ? mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z))
      : 0.0f;
    const Wm3::Vector2f at = mCamera->Project(Wm3::Vec3f{x, y, z});
    return POINT{static_cast<LONG>(std::lround(at.x)), static_cast<LONG>(std::lround(at.y))};
  }

  int EdMapScene::ViewCursor() const
  {
    if (mTools == nullptr || mMap == nullptr || mCamera == nullptr) {
      return 0;
    }
    const POINT at = mCursor;
    if (mTools->MarkersToolActive()) {
      if (const AreaHit hit = AreaUnder(at); hit.part != 0) {
        switch (hit.part) {
        case 16:
          return 32646; // IDC_SIZEALL
        case 1 | 2:
        case 4 | 8:
          return 32642; // IDC_SIZENWSE
        case 4 | 2:
        case 1 | 8:
          return 32643; // IDC_SIZENESW
        case 1:
        case 4:
          return 32644; // IDC_SIZEWE
        default:
          return 32645; // IDC_SIZENS
        }
      }
      if (mTools->DrawingAreas()) {
        return 32515; // IDC_CROSS
      }
      if (PickGizmo(at) != GizmoPart::None || !mHoverMarker.empty()) {
        return 32646; // over a marker or the gizmo: a drag moves it
      }
      return 6; // a click places a marker: the pin
    }
    if (mTools->TerrainToolActive()) {
      // The brush's crosshair with its kind's sign (Studio's five brush cursors): raise, lower, flatten, smooth, noise.
      switch (mTools->PreviewHeightBrush().mode) {
      case HeightBrushMode::Lower:
      case HeightBrushMode::Erode:
      case HeightBrushMode::WaterErode:
      case HeightBrushMode::Rain:
        return 2;
      case HeightBrushMode::Flatten:
      case HeightBrushMode::SetHeight:
      case HeightBrushMode::Terrace:
      case HeightBrushMode::Plane:
      case HeightBrushMode::Plateau:
      case HeightBrushMode::Ramp:
        return 3;
      case HeightBrushMode::Smooth:
        return 4;
      case HeightBrushMode::Noise:
        return 5;
      default: // raise, stamp, deposit, sharpen, path
        return 1;
      }
    }
    if (mTools->SelectToolActive()) {
      if (PickGizmo(at) != GizmoPart::None || PickAnything(at).kind != PickKind::None) {
        return 32646;
      }
      return 0;
    }
    if (
      mTools->PropsToolActive() || mTools->DecalsToolActive() || mTools->UnitsToolActive() ||
      mTools->TextureToolActive()
    ) {
      return 32515;
    }
    return 0;
  }

  bool EdMapScene::AreaMouseDown(
    const HWND window,
    const POINT at,
    const float groundX,
    const float groundZ,
    const bool add
  )
  {
    if (mTools == nullptr || mCamera == nullptr || mMap == nullptr) {
      return false;
    }
    std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    std::vector<std::string>& picked = mTools->AreaSelection();
    const auto rectOf = [](const SaveEntry& area, float (&r)[4]) {
      const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
      if (e.size() < 4) {
        return false;
      }
      r[0] = static_cast<float>(std::min(e[0], e[2]));
      r[1] = static_cast<float>(std::min(e[1], e[3]));
      r[2] = static_cast<float>(std::max(e[0], e[2]));
      r[3] = static_cast<float>(std::max(e[1], e[3]));
      return true;
    };
    const auto screen = [&](const float x, const float z) {
      const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
      return mCamera->Project(Wm3::Vec3f{x, y, z});
    };
    const Wm3::Vector2f cursor(static_cast<float>(at.x), static_cast<float>(at.y));
    const auto begin = [&](const int kind) {
      mAreaDrag = kind;
      mAreaFrom[0] = groundX;
      mAreaFrom[1] = groundZ;
      mAreaStart.clear();
      for (const std::string& name : picked) {
        std::array<float, 4> start{};
        for (const SaveEntry& area : areas) {
          float r[4];
          if (area.name == name && rectOf(area, r)) {
            start = {r[0], r[1], r[2], r[3]};
          }
        }
        mAreaStart.push_back(start);
      }
      ::SetCapture(window);
      ::SetFocus(window);
    };
    // Drawing: a new area from here (Studio's Place area tool).
    if (mTools->DrawingAreas()) {
      mAreaBefore = mDocument.SaveDataNow();
      int n = 1;
      const auto taken = [&areas](const std::string& name) {
        return std::any_of(areas.begin(), areas.end(), [&name](const SaveEntry& a) {
          return a.name == name;
        });
      };
      while (taken("AREA_" + std::to_string(n))) {
        ++n;
      }
      SaveEntry area{"AREA_" + std::to_string(n), {}};
      const float x = std::round(groundX);
      const float z = std::round(groundZ);
      area.Set("rectangle", RectangleValue(x, z, x + 1.0, z + 1.0));
      areas.push_back(std::move(area));
      picked = {areas.back().name};
      mAreaDragName = areas.back().name;
      begin(32);
      return true;
    }
    // A handle of a picked area: resize that one.
    for (const std::string& name : picked) {
      for (const SaveEntry& area : areas) {
        float r[4];
        if (area.name != name || !rectOf(area, r)) {
          continue;
        }
        const float hx[3] = {r[0], (r[0] + r[2]) * 0.5f, r[2]};
        const float hz[3] = {r[1], (r[1] + r[3]) * 0.5f, r[3]};
        const int edgeX[3] = {1, 0, 4};
        const int edgeZ[3] = {2, 0, 8};
        for (int i = 0; i < 3; ++i) {
          for (int j = 0; j < 3; ++j) {
            if (i == 1 && j == 1) {
              continue;
            }
            const Wm3::Vector2f h = screen(hx[i], hz[j]);
            if (std::hypot(h.x - cursor.x, h.y - cursor.y) <= 9.0f) {
              mAreaBefore = mDocument.SaveDataNow();
              mAreaDragName = name;
              begin(edgeX[i] | edgeZ[j]);
              return true;
            }
          }
        }
      }
    }
    // An outline within reach: pick that area (the smallest when several), then a drag moves the picked ones.
    const SaveEntry* best = nullptr;
    float bestArea = 1e30f;
    for (const SaveEntry& area : areas) {
      float r[4];
      if (!rectOf(area, r)) {
        continue;
      }
      const Wm3::Vector2f c[4] = {screen(r[0], r[1]), screen(r[2], r[1]), screen(r[2], r[3]), screen(r[0], r[3])};
      float closest = 1e9f;
      for (int e = 0; e < 4; ++e) {
        closest = std::min(closest, SegmentDistance(cursor, c[e], c[(e + 1) % 4]));
      }
      const float size = (r[2] - r[0]) * (r[3] - r[1]);
      if (closest <= 7.0f && size < bestArea) {
        bestArea = size;
        best = &area;
      }
    }
    if (best == nullptr) {
      const int marker = PickMarker(groundX, groundZ);
      const bool onSelected = marker >= 0 &&
        std::find(
          mMarkerSelection.begin(),
          mMarkerSelection.end(),
          mDocument.SaveData().Markers()[static_cast<std::size_t>(marker)].name
        ) != mMarkerSelection.end();
      if (!add && !onSelected) {
        picked.clear();
      }
      return false;
    }
    const std::string name = best->name;
    const bool already = std::find(picked.begin(), picked.end(), name) != picked.end();
    if (add && already) {
      picked.erase(std::find(picked.begin(), picked.end(), name));
      return true;
    }
    if (!already) {
      if (!add) {
        picked.clear();
      }
      picked.push_back(name);
    }
    mAreaBefore = mDocument.SaveDataNow();
    mAreaDragName = name;
    begin(16);
    return true;
  }

  void EdMapScene::AreaMouseMove(
    const POINT at
  )
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    if (mTools == nullptr || !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
      return;
    }
    const AreaBounds bounds = AreaLimitBounds();
    std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    const std::vector<std::string>& picked = mTools->AreaSelection();
    const float gx = std::round(groundX);
    const float gz = std::round(groundZ);
    if (mAreaDrag == 16) {
      const float dx = std::round(groundX - mAreaFrom[0]);
      const float dz = std::round(groundZ - mAreaFrom[1]);
      for (std::size_t i = 0; i < picked.size() && i < mAreaStart.size(); ++i) {
        for (SaveEntry& area : areas) {
          if (area.name != picked[i]) {
            continue;
          }
          float r[4] = {mAreaStart[i][0] + dx, mAreaStart[i][1] + dz, mAreaStart[i][2] + dx, mAreaStart[i][3] + dz};
          LimitArea(r, bounds, true);
          area.Set("rectangle", RectangleValue(r[0], r[1], r[2], r[3]));
        }
      }
      return;
    }
    for (SaveEntry& area : areas) {
      if (area.name != mAreaDragName) {
        continue;
      }
      const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
      if (e.size() < 4) {
        return;
      }
      float r[4] = {
        static_cast<float>(e[0]), static_cast<float>(e[1]), static_cast<float>(e[2]), static_cast<float>(e[3])
      };
      if (mAreaDrag == 32) {
        // A new area: from where the drag began to the cursor, whichever way.
        r[0] = std::min(std::round(mAreaFrom[0]), gx);
        r[2] = std::max(std::round(mAreaFrom[0]), gx);
        r[1] = std::min(std::round(mAreaFrom[1]), gz);
        r[3] = std::max(std::round(mAreaFrom[1]), gz);
      } else {
        if ((mAreaDrag & 1) != 0) {
          r[0] = std::min(gx, r[2] - 1.0f);
        }
        if ((mAreaDrag & 4) != 0) {
          r[2] = std::max(gx, r[0] + 1.0f);
        }
        if ((mAreaDrag & 2) != 0) {
          r[1] = std::min(gz, r[3] - 1.0f);
        }
        if ((mAreaDrag & 8) != 0) {
          r[3] = std::max(gz, r[1] + 1.0f);
        }
      }
      LimitArea(r, bounds, false);
      area.Set("rectangle", RectangleValue(r[0], r[1], r[2], r[3]));
      return;
    }
  }

  void EdMapScene::AreaMouseUp()
  {
    const int kind = std::exchange(mAreaDrag, 0);
    ::ReleaseCapture();
    std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    if (kind == 32) {
      // A click, not a drag: no area.
      for (auto it = areas.begin(); it != areas.end(); ++it) {
        const std::vector<double> e = ValueNumbers(it->Get("rectangle"));
        if (it->name == mAreaDragName && e.size() >= 4 && (e[2] - e[0] < 2.0 || e[3] - e[1] < 2.0)) {
          areas.erase(it);
          mTools->AreaSelection().clear();
          break;
        }
      }
    }
    if (mAreaBefore.areas != areas) {
      mDocument.SaveDataEdited(std::move(mAreaBefore));
      gpg::Logf(
        "editor: areas: %s %s",
        kind == 32     ? "drew"
          : kind == 16 ? "moved"
                       : "resized",
        kind == 16 ? (std::to_string(mTools->AreaSelection().size()) + " areas").c_str() : mAreaDragName.c_str()
      );
    }
    mAreaBefore = {};
  }

  std::string EdMapScene::TestAreaTools()
  {
    if (mTools == nullptr || mCamera == nullptr || mMap == nullptr || mMap->mTerrainRes == nullptr) {
      return "no map";
    }
    const auto screenOf = [&](const float x, const float z) {
      const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
      const Wm3::Vector2f at = mCamera->Project(Wm3::Vec3f{x, y, z});
      return POINT{static_cast<LONG>(std::lround(at.x)), static_cast<LONG>(std::lround(at.y))};
    };
    const auto rectOf = [&](const std::string& name) {
      std::string text = "-";
      for (const SaveEntry& area : mDocument.SaveData().Areas()) {
        if (area.name == name) {
          const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
          char buffer[96];
          (void)std::snprintf(buffer, sizeof(buffer), "%.0f,%.0f,%.0f,%.0f", e[0], e[1], e[2], e[3]);
          text = buffer;
        }
      }
      return text;
    };
    const auto drag = [&](const float fx, const float fz, const float tx, const float tz) {
      const POINT from = screenOf(fx, fz);
      const POINT to = screenOf(tx, tz);
      float gx = 0.0f, gz = 0.0f;
      if (!GroundAt(static_cast<float>(from.x), static_cast<float>(from.y), gx, gz)) {
        return false;
      }
      if (!AreaMouseDown(nullptr, from, gx, gz, false)) {
        return false;
      }
      AreaMouseMove(to);
      AreaMouseUp();
      return true;
    };
    const float c = std::round(mTargetX);
    const float d = std::round(mTargetZ);
    const std::size_t count = mDocument.SaveData().Areas().size();
    std::string log;
    // Draw.
    mTools->SetDrawingAreas(true);
    const bool drew = drag(c - 20.0f, d - 20.0f, c + 30.0f, d + 10.0f);
    mTools->SetDrawingAreas(false);
    const std::string name = mTools->AreaSelection().empty() ? "" : mTools->AreaSelection().front();
    log += std::string("drew ") + (drew ? name + " " + rectOf(name) : "nothing");
    // Move by its left edge (a quarter down, clear of the handles).
    const bool moved = drag(c - 20.0f, d - 12.0f, c - 4.0f, d - 4.0f);
    log += std::string("; moved by the outline: ") + (moved ? rectOf(name) : "no");
    // Resize by the bottom right handle.
    float r[4] = {0, 0, 0, 0};
    for (const SaveEntry& area : mDocument.SaveData().Areas()) {
      if (area.name == name) {
        const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
        for (int i = 0; i < 4; ++i) {
          r[i] = static_cast<float>(e[static_cast<std::size_t>(i)]);
        }
      }
    }
    const bool resized = drag(r[2], r[3], r[2] + 10.0f, r[3] + 6.0f);
    log += std::string("; resized by its corner: ") + (resized ? rectOf(name) : "no");
    // Kept inside the map: moved far past the left edge.
    mTools->SetAreaLimit(1);
    const POINT edge = screenOf(r[0], (r[1] + r[3]) * 0.5f - 7.0f);
    float gx = 0.0f, gz = 0.0f;
    if (
      GroundAt(static_cast<float>(edge.x), static_cast<float>(edge.y), gx, gz) &&
      AreaMouseDown(nullptr, edge, gx, gz, false)
    ) {
      mAreaFrom[0] += 4000.0f; // as if the drag had gone 4000 units left
      AreaMouseMove(edge);
      AreaMouseUp();
    }
    mTools->SetAreaLimit(0);
    log += "; pushed 4000 left, kept inside the map: " + rectOf(name);
    // Duplicate, then delete both.
    CtrlKey('D');
    const std::size_t afterDuplicate = mDocument.SaveData().Areas().size();
    mTools->AreaSelection() = {name, mTools->AreaSelection().empty() ? name : mTools->AreaSelection().front()};
    (void)DeleteSelectedAreas();
    char tail[160];
    (void)std::snprintf(
      tail,
      sizeof(tail),
      "; areas %zu, %zu after drawing and duplicating, %zu after deleting both",
      count,
      afterDuplicate,
      mDocument.SaveData().Areas().size()
    );
    return log + tail;
  }

  bool EdMapScene::DeleteSelectedAreas()
  {
    if (mTools == nullptr || mTools->AreaSelection().empty()) {
      return false;
    }
    std::vector<std::string>& picked = mTools->AreaSelection();
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    const std::size_t was = areas.size();
    areas.erase(
      std::remove_if(
        areas.begin(),
        areas.end(),
        [&picked](const SaveEntry& a) {
      return std::find(picked.begin(), picked.end(), a.name) != picked.end();
    }
      ),
      areas.end()
    );
    picked.clear();
    if (areas.size() != was) {
      mDocument.SaveDataEdited(std::move(before));
      gpg::Logf("editor: areas: %zu deleted", was - areas.size());
    }
    return true;
  }

  void EdMapScene::BeginAreaFollow()
  {
    mAreaFollowNames.clear();
    mAreaFollowStart.clear();
    if (mTools == nullptr || !mTools->MarkersToolActive()) {
      return;
    }
    for (const std::string& name : mTools->AreaSelection()) {
      for (const SaveEntry& area : mDocument.SaveData().Areas()) {
        const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
        if (area.name == name && e.size() >= 4) {
          mAreaFollowNames.push_back(name);
          mAreaFollowStart.push_back(
            {static_cast<float>(e[0]), static_cast<float>(e[1]), static_cast<float>(e[2]), static_cast<float>(e[3])}
          );
        }
      }
    }
  }

  void EdMapScene::FollowAreas(
    const float dx,
    const float dz
  )
  {
    if (mAreaFollowNames.empty()) {
      return;
    }
    const AreaBounds bounds = AreaLimitBounds();
    const float mx = std::round(dx);
    const float mz = std::round(dz);
    for (std::size_t i = 0; i < mAreaFollowNames.size(); ++i) {
      for (SaveEntry& area : mDocument.SaveData().Areas()) {
        if (area.name != mAreaFollowNames[i]) {
          continue;
        }
        float r[4] = {
          mAreaFollowStart[i][0] + mx,
          mAreaFollowStart[i][1] + mz,
          mAreaFollowStart[i][2] + mx,
          mAreaFollowStart[i][3] + mz
        };
        LimitArea(r, bounds, true);
        area.Set("rectangle", RectangleValue(r[0], r[1], r[2], r[3]));
      }
    }
  }

  void EdMapScene::PasteAreas(
    const float dx,
    const float dz
  )
  {
    std::vector<std::string>& picked = mTools->AreaSelection();
    std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    const AreaBounds bounds = AreaLimitBounds();
    picked.clear();
    for (const SaveEntry& copied : mAreaClipboard) {
      const std::vector<double> e = ValueNumbers(copied.Get("rectangle"));
      if (e.size() < 4) {
        continue;
      }
      int n = 1;
      const auto taken = [&areas](const std::string& name) {
        return std::any_of(areas.begin(), areas.end(), [&name](const SaveEntry& a) {
          return a.name == name;
        });
      };
      while (taken("AREA_" + std::to_string(n))) {
        ++n;
      }
      SaveEntry area = copied;
      area.name = "AREA_" + std::to_string(n);
      float r[4] = {
        static_cast<float>(e[0]) + dx,
        static_cast<float>(e[1]) + dz,
        static_cast<float>(e[2]) + dx,
        static_cast<float>(e[3]) + dz
      };
      LimitArea(r, bounds, true);
      area.Set("rectangle", RectangleValue(r[0], r[1], r[2], r[3]));
      picked.push_back(area.name);
      areas.push_back(std::move(area));
    }
    mDocument.SaveDataEdited(std::move(before));
  }

  bool EdMapScene::AreaCtrlKey(
    const char key
  )
  {
    // True: the key was the areas' alone; false: the markers (or the other tools) go on with it.
    if (mTools == nullptr || !mTools->MarkersToolActive()) {
      return false;
    }
    std::vector<std::string>& picked = mTools->AreaSelection();
    const std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
    const bool withMarkers = !mMarkerSelection.empty();
    if (key == 'C' || key == 'X' || key == 'D') {
      mAreaClipboard.clear();
      for (const SaveEntry& area : areas) {
        if (std::find(picked.begin(), picked.end(), area.name) != picked.end()) {
          mAreaClipboard.push_back(area);
        }
      }
      if (mAreaClipboard.empty()) {
        return false; // markers only: the area clipboard is empty, so a paste brings no old areas
      }
      if (!withMarkers) {
        mClipboard = Clipboard{}; // areas only: no old markers come with a paste
      }
      if (key == 'X') {
        // Cut: the areas go now; the markers' own cut follows when there are markers.
        const std::size_t cut = mAreaClipboard.size();
        (void)DeleteSelectedAreas();
        gpg::Logf("editor: areas: %zu cut", cut);
        return !withMarkers;
      }
      if (key == 'D') {
        PasteAreas(8.0f, 8.0f); // as the markers' duplicate: 8 units down and right
        gpg::Logf("editor: areas: %zu duplicated", picked.size());
        return !withMarkers;
      }
      gpg::Logf("editor: areas: %zu copied", mAreaClipboard.size());
      return !withMarkers;
    }
    if (key != 'V' || mAreaClipboard.empty()) {
      return false;
    }
    // Paste: with copied markers, the areas keep their places beside them (both by the markers' middle at the
    // cursor); alone, the areas' middle at the cursor.
    float gx = 0.0f, gz = 0.0f;
    if (!CursorGround(gx, gz)) {
      return true;
    }
    const bool markersToo = !mClipboard.markers.empty();
    float cx = 0.0f, cz = 0.0f;
    if (markersToo) {
      cx = mClipboard.centre[0];
      cz = mClipboard.centre[1];
    } else {
      for (const SaveEntry& area : mAreaClipboard) {
        const std::vector<double> e = ValueNumbers(area.Get("rectangle"));
        if (e.size() >= 4) {
          cx += static_cast<float>(e[0] + e[2]) * 0.5f;
          cz += static_cast<float>(e[1] + e[3]) * 0.5f;
        }
      }
      cx /= static_cast<float>(mAreaClipboard.size());
      cz /= static_cast<float>(mAreaClipboard.size());
    }
    PasteAreas(std::round(gx - cx), std::round(gz - cz));
    gpg::Logf("editor: areas: %zu pasted", picked.size());
    return !markersToo;
  }

  std::vector<EdMapScene::ViewLabel> EdMapScene::ViewLabels() const
  {
    std::vector<ViewLabel> out;
    if (!mNamesShown || mCamera == nullptr || mWidth <= 0 || mHeight <= 0) {
      return out;
    }
    // Close: every name; far: the selected and the hovered.
    const bool close = mDistance < 260.0f;
    const std::set<std::string>& hidden = mTools->HiddenMarkerTypes();
    const auto add =
      [&](const float x, const float y, const float z, const std::string& text, const std::uint32_t rgb) {
      const Wm3::Vector2f at = mCamera->Project(Wm3::Vec3f{x, y, z});
      if (
        at.x >= 0.0f && at.y >= 0.0f && at.x < static_cast<float>(mWidth) && at.y < static_cast<float>(mHeight) &&
        out.size() < 400
      ) {
        out.push_back({at.x, at.y, text, rgb});
      }
    };
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const bool selected =
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end();
      const bool hovered = marker.name == mHoverMarker;
      if (!selected && !hovered && (!close || hidden.contains(MarkerTypeOf(marker)))) {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (ShownMarkerPosition(marker, x, y, z)) {
        add(x, y + 2.5f, z, marker.name, selected ? 0xFFD060u : 0xF0F0F0u);
      }
    }
    if (close || mTools->MarkersToolActive()) {
      for (const SaveEntry& area : mDocument.SaveData().Areas()) {
        const std::vector<double> edges = ValueNumbers(area.Get("rectangle"));
        if (edges.size() < 4 || mMap == nullptr) {
          continue;
        }
        const float x = static_cast<float>(edges[0]) + 2.0f;
        const float z = static_cast<float>(edges[1]) + 2.0f;
        float y = 0.0f;
        if (
          const moho::CHeightField* const field =
            mMap->mTerrainRes != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
          field != nullptr
        ) {
          const int sx = std::clamp(static_cast<int>(x), 0, field->width - 1);
          const int sz = std::clamp(static_cast<int>(z), 0, field->height - 1);
          y = static_cast<float>(field->data[sz * field->width + sx]) / 128.0f;
        }
        add(x, y + 1.0f, z, area.name, 0x40D0C0u);
      }
    }
    return out;
  }

  std::string EdMapScene::HoverText() const
  {
    float gx = 0.0f;
    float gz = 0.0f;
    if (mMap == nullptr || !CursorGround(gx, gz)) {
      return {};
    }
    const PickHit hit = PickAnything(mCursor);
    switch (hit.kind) {
    case PickKind::Marker: {
      const SaveEntry& marker = mDocument.SaveData().Markers()[static_cast<std::size_t>(hit.index)];
      return marker.name + " (" + MarkerTypeOf(marker) + ")";
    }
    case PickKind::Unit:
      return mUnitRefs[static_cast<std::size_t>(hit.index)].name + " (" +
        mUnitRefs[static_cast<std::size_t>(hit.index)].army + ")";
    case PickKind::Prop: {
      const std::string blueprint = mMap->mProps->mEntries[static_cast<std::size_t>(hit.index)].mBlueprintPath.c_str();
      const std::size_t slash = blueprint.find_last_of('/');
      return "prop " + (slash == std::string::npos ? blueprint : blueprint.substr(slash + 1));
    }
    case PickKind::Decal:
      return "decal " + std::to_string(hit.index);
    default:
      return {};
    }
  }

  int EdMapScene::PickMarker(
    const float x,
    const float z
  ) const
  {
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const float reach = std::max(2.5f, mDistance * 0.006f); // about the size the markers are drawn at
    int best = -1;
    float bestDistance = reach;
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float mx = 0.0f, my = 0.0f, mz = 0.0f;
      if (!ShownMarkerPosition(markers[i], mx, my, mz) || MarkerHidden(markers[i])) {
        continue;
      }
      const float d = std::hypot(mx - x, mz - z);
      if (d < bestDistance) {
        bestDistance = d;
        best = static_cast<int>(i);
      }
    }
    return best;
  }

  bool EdMapScene::MarkerHidden(
    const SaveEntry& marker
  ) const
  {
    if (mTools == nullptr) {
      return false;
    }
    // By type (the Markers panel), or by name (a resource a previewed lobby setting doesn't spawn).
    return (!mTools->HiddenMarkerTypes().empty() && mTools->HiddenMarkerTypes().contains(MarkerTypeOf(marker))) ||
      (!mTools->PreviewHiddenMarkers().empty() && mTools->PreviewHiddenMarkers().contains(marker.name));
  }

  void EdMapScene::SelectMarkers(
    const std::vector<std::string>& names,
    const bool add
  )
  {
    if (!add) {
      mMarkerSelection.clear();
    }
    for (const std::string& name : names) {
      const auto at = std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name);
      if (at == mMarkerSelection.end()) {
        mMarkerSelection.push_back(name);
      } else if (add) {
        mMarkerSelection.erase(at);
      }
    }
  }

  void EdMapScene::FrameMarker(
    const std::string& name,
    const float distance
  )
  {
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (marker.name == name && ShownMarkerPosition(marker, x, y, z)) {
        mTargetX = x;
        mTargetZ = z;
        mDistance = std::min(mDistance, distance);
        ApplyCamera();
        mMarkerSelection = {name}; // and selected, so Properties shows it
        gpg::Logf(
          "editor: the view goes to %s at %.0f, %.0f", name.c_str(), static_cast<double>(x), static_cast<double>(z)
        );
        return;
      }
    }
  }

  void EdMapScene::FramePoint(
    const float x,
    const float z,
    const float distance
  )
  {
    mTargetX = x;
    mTargetZ = z;
    mDistance = std::min(mDistance, distance);
    ApplyCamera();
  }

  void EdMapScene::SelectUnit(
    const std::string& army,
    const std::string& name
  )
  {
    for (const UnitRef& unit : mUnitRefs) {
      if (unit.army == army && unit.name == name) {
        mUnitSelection = {{army, name}};
        mTargetX = unit.position.x;
        mTargetZ = unit.position.z;
        mDistance = std::min(mDistance, 80.0f);
        ApplyCamera();
        gpg::Logf("editor: %s of %s selected", name.c_str(), army.c_str());
        return;
      }
    }
    gpg::Warnf("editor: /selectunit: no unit %s in %s", name.c_str(), army.c_str());
  }

  std::expected<MarkerImport, std::string> EdMapScene::ImportMarkerFile(
    const std::string& text
  )
  {
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry> markers = mDocument.SaveData().Markers();
    MarkerImport result;
    if (const auto read = MarkersFromFafmapmarkers(text, markers, result, mDocument.ArmyNamesInUse()); !read) {
      return std::unexpected(read.error());
    }
    if (!result.names.empty()) {
      // A start position is an army, as when one is placed: the scenario's list and the save's Armies get it.
      for (const SaveEntry& marker : markers) {
        if (
          MarkerTypeOf(marker) == "Blank Marker" &&
          std::find(result.names.begin(), result.names.end(), marker.name) != result.names.end()
        ) {
          mDocument.AddArmy(marker.name);
        }
      }
      mDocument.SaveData().Markers() = std::move(markers);
      mDocument.SaveDataEdited(std::move(before));
      mMarkerSelection = result.names;
      mOutsideStale = true;
    }
    return result;
  }

  std::vector<SaveEntry> EdMapScene::SelectedMarkers() const
  {
    std::vector<SaveEntry> selected;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()) {
        selected.push_back(marker);
      }
    }
    return selected;
  }

  std::string EdMapScene::SelectedCameraMarker() const
  {
    for (const std::string& name : mMarkerSelection) {
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        if (marker.name == name && MarkerTypeOf(marker) == "Camera Info") {
          return name;
        }
      }
    }
    return {};
  }

  bool EdMapScene::LookThroughCamera(
    const std::string& name
  )
  {
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      if (marker.name != name) {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!MarkerPosition(marker, x, y, z)) {
        return false;
      }
      const std::vector<double> turn = ValueNumbers(marker.Get("orientation"));
      const std::vector<double> zoom = ValueNumbers(marker.Get("zoom"));
      CameraPose pose = GetCameraPose();
      pose.targetX = x;
      pose.targetZ = z;
      if (turn.size() > 1) {
        pose.heading = static_cast<float>(turn[0]);
        pose.pitch = static_cast<float>(turn[1]);
      }
      if (!zoom.empty() && zoom[0] > 0.0) {
        pose.distance = static_cast<float>(zoom[0]);
      }
      SetCameraPose(pose);
      gpg::Logf(
        "editor: view through camera %s: focus %.1f, %.1f, heading %.2f, pitch %.2f, zoom %.1f",
        name.c_str(),
        static_cast<double>(pose.targetX),
        static_cast<double>(pose.targetZ),
        static_cast<double>(pose.heading),
        static_cast<double>(pose.pitch),
        static_cast<double>(pose.distance)
      );
      return true;
    }
    return false;
  }

  bool EdMapScene::SetCameraMarkerFromView(
    const std::string& name
  )
  {
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (SaveEntry& marker : markers) {
      if (marker.name != name || MarkerTypeOf(marker) != "Camera Info") {
        continue;
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      const CameraPose pose = GetCameraPose();
      marker.Set("position", Vector3Value(pose.targetX, GroundHeightAt(pose.targetX, pose.targetZ), pose.targetZ));
      marker.Set("orientation", Vector3Value(pose.heading, pose.pitch, 0.0));
      marker.Set("zoom", FloatValue(pose.distance));
      mDocument.SaveDataEdited(std::move(before));
      gpg::Logf(
        "editor: camera %s set from the view: focus %.1f, %.1f, heading %.2f, pitch %.2f, zoom %.1f",
        name.c_str(),
        static_cast<double>(pose.targetX),
        static_cast<double>(pose.targetZ),
        static_cast<double>(pose.heading),
        static_cast<double>(pose.pitch),
        static_cast<double>(pose.distance)
      );
      return true;
    }
    return false;
  }

  void EdMapScene::EditMarker(
    const std::string& name,
    const std::string& key,
    const std::string& value
  )
  {
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (SaveEntry& marker : markers) {
      if (marker.name != name) {
        continue;
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      // `settype`: the marker becomes another type (its colour, prop and the type's own properties with it).
      if (key == "settype") {
        const MarkerType* const type = FindMarkerType(value);
        if (type == nullptr || MarkerTypeOf(marker) == value) {
          return;
        }
        marker = WithMarkerType(marker, *type);
        mDocument.SaveDataEdited(std::move(before));
        gpg::Logf("editor: marker %s is a %s now", name.c_str(), value.c_str());
        return;
      }
      if (key == "name") {
        // A free name only; links naming the marker follow it.
        for (const SaveEntry& other : markers) {
          if (other.name == value) {
            gpg::Warnf("editor: a marker named %s already exists", value.c_str());
            return;
          }
        }
        // A start position names its army: not one the scenario already has (an extra army has no marker).
        if (
          const std::vector<std::string> armies = mDocument.ArmyNamesInUse();
          MarkerTypeOf(marker) == "Blank Marker" && std::find(armies.begin(), armies.end(), value) != armies.end()
        ) {
          gpg::Warnf("editor: an army named %s already exists", value.c_str());
          return;
        }
        for (SaveEntry& other : markers) {
          std::vector<std::string> links = MarkerLinks(other);
          if (std::find(links.begin(), links.end(), name) == links.end()) {
            continue;
          }
          std::string joined;
          for (const std::string& link : links) {
            joined += (joined.empty() ? "" : " ") + (link == name ? value : link);
          }
          other.Set("adjacentTo", StringValue(joined));
        }
        if (MarkerTypeOf(marker) == "Blank Marker") {
          mDocument.RenameArmy(name, value);
        }
        // The chains name it too.
        for (MarkerChain& chain : mDocument.SaveData().Chains()) {
          std::replace(chain.markers.begin(), chain.markers.end(), name, value);
        }
        marker.name = value;
        std::replace(mMarkerSelection.begin(), mMarkerSelection.end(), name, value);
      } else {
        marker.Set(key, value);
      }
      mDocument.SaveDataEdited(std::move(before));
      return;
    }
  }

  void EdMapScene::LinkSelectionTo(
    const std::string& target
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const auto position = [&](const std::string& name, float& x, float& z, std::string& type) {
      for (const SaveEntry& marker : markers) {
        float y = 0.0f;
        if (marker.name == name && IsPathNode(marker) && ShownMarkerPosition(marker, x, y, z)) {
          type = MarkerTypeOf(marker);
          return true;
        }
      }
      return false;
    };
    float targetX = 0.0f, targetZ = 0.0f;
    std::string targetType;
    if (field == nullptr || mTools == nullptr || !position(target, targetX, targetZ, targetType)) {
      mMarkerSelection = {target};
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float targetCopyX[kMaxSymmetryCopies], targetCopyZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(
      field->width, field->height, targetX, targetZ, brush.symmetry, brush.turns, targetCopyX, targetCopyZ
    );
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    int made = 0;
    int removed = 0;
    // Selected nodes that are symmetric copies of each other (a placement selects all its copies) count once: the copy
    // nearest the target pairs with it, and the other copies pair with the target's copies.
    std::set<std::string> covered;
    for (const std::string& selected : mMarkerSelection) {
      float sourceX = 0.0f, sourceZ = 0.0f;
      std::string sourceType;
      if (selected == target || covered.contains(selected) || !position(selected, sourceX, sourceZ, sourceType)) {
        continue;
      }
      std::string source = selected;
      covered.insert(selected);
      float groupX[kMaxSymmetryCopies], groupZ[kMaxSymmetryCopies];
      const int members =
        HeightBrushCentres(field->width, field->height, sourceX, sourceZ, brush.symmetry, brush.turns, groupX, groupZ);
      float nearest = std::hypot(sourceX - targetX, sourceZ - targetZ);
      for (int m = 1; m < members; ++m) {
        const int i = MarkerNear(markers, sourceType, groupX[m], groupZ[m], kCopyReach);
        if (i < 0) {
          continue;
        }
        const std::string& name = markers[static_cast<std::size_t>(i)].name;
        if (
          name == target || std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()
        ) {
          continue;
        }
        covered.insert(name);
        const float d = std::hypot(groupX[m] - targetX, groupZ[m] - targetZ);
        if (d < nearest) {
          nearest = d;
          source = name;
        }
      }
      (void)position(source, sourceX, sourceZ, sourceType);
      // One click toggles the pair; its symmetric copies follow it (each copy of the source to the same copy of the
      // target).
      const bool link = !MarkersLinked(markers, source, target);
      float sourceCopyX[kMaxSymmetryCopies], sourceCopyZ[kMaxSymmetryCopies];
      (void)HeightBrushCentres(
        field->width, field->height, sourceX, sourceZ, brush.symmetry, brush.turns, sourceCopyX, sourceCopyZ
      );
      for (int c = 0; c < copies; ++c) {
        const int a = c == 0 ? -1 : MarkerNear(markers, sourceType, sourceCopyX[c], sourceCopyZ[c], kCopyReach);
        const int b = c == 0 ? -1 : MarkerNear(markers, targetType, targetCopyX[c], targetCopyZ[c], kCopyReach);
        if (c != 0 && (a < 0 || b < 0)) {
          continue;
        }
        const std::string from = c == 0 ? source : markers[static_cast<std::size_t>(a)].name;
        const std::string to = c == 0 ? target : markers[static_cast<std::size_t>(b)].name;
        if (SetMarkerLink(markers, from, to, link)) {
          ++(link ? made : removed);
        }
      }
    }
    const std::size_t sources = mMarkerSelection.size();
    mMarkerSelection = {target};
    if (made + removed > 0) {
      mDocument.SaveDataEdited(std::move(before));
      gpg::Logf("editor: path links to %s: %d made, %d removed", target.c_str(), made, removed);
    } else {
      gpg::Logf("editor: %s selected (no path links changed from %zu selected)", target.c_str(), sources);
    }
  }

  void EdMapScene::ChangeTeams(
    const std::vector<ScenarioTeam>& teams
  )
  {
    if (teams == mDocument.Teams()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    mDocument.SetTeams(teams);
    mDocument.SaveDataEdited(std::move(before));
    std::string order;
    for (const std::string& army : mDocument.Armies()) {
      order += (order.empty() ? "" : " ") + army;
    }
    gpg::Logf("editor: teams: %zu, slots %s", teams.size(), order.c_str());
  }

  void EdMapScene::ChangeExtraArmies(
    const std::string& armies
  )
  {
    std::vector<std::string> names;
    std::size_t at = 0;
    while (at < armies.size()) {
      const std::size_t space = armies.find(' ', at);
      const std::string word = armies.substr(at, space == std::string::npos ? std::string::npos : space - at);
      if (!word.empty()) {
        names.push_back(word);
      }
      at = space == std::string::npos ? armies.size() : space + 1;
    }
    if (names == mDocument.ExtraArmies()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    mDocument.SetExtraArmies(names);
    mDocument.SaveDataEdited(std::move(before));
    gpg::Logf("editor: extra armies %s", armies.c_str());
  }

  void EdMapScene::PlaceMarkers(
    const float x,
    const float z,
    const bool connect
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr) {
      return;
    }
    const MarkerType& type = mTools->PlaceMarkerType();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    // Laying a path: the selected node of this type and its symmetric copies, which the new copies link to.
    // Of the selected nodes (a placement selects all its copies) the one nearest the click.
    std::string previous;
    float previousX[kMaxSymmetryCopies], previousZ[kMaxSymmetryCopies];
    if (connect) {
      float nearest = 0.0f;
      for (const SaveEntry& marker : markers) {
        float px = 0.0f, py = 0.0f, pz = 0.0f;
        if (
          !IsPathNode(marker) || MarkerTypeOf(marker) != type.type || !ShownMarkerPosition(marker, px, py, pz) ||
          std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) == mMarkerSelection.end()
        ) {
          continue;
        }
        const float d = std::hypot(px - x, pz - z);
        if (previous.empty() || d < nearest) {
          nearest = d;
          previous = marker.name;
          (void)HeightBrushCentres(
            field->width, field->height, px, pz, brush.symmetry, brush.turns, previousX, previousZ
          );
        }
      }
    }
    int linked = 0;
    // A click that places nothing (off the map) keeps the selection, so a path being laid isn't lost.
    std::vector<std::string> selectedBefore = std::move(mMarkerSelection);
    mMarkerSelection.clear();
    for (int c = 0; c < copies; ++c) {
      if (
        centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
        centreZ[c] > static_cast<float>(field->height - 1)
      ) {
        continue;
      }
      // Resources on the half unit, as the game's saves place them; other markers on the grid when snapping.
      const bool resource = std::string(type.type) == "Mass" || std::string(type.type) == "Hydrocarbon";
      const float px = resource ? std::floor(centreX[c]) + 0.5f : SnapToGrid(centreX[c]);
      const float pz = resource ? std::floor(centreZ[c]) + 0.5f : SnapToGrid(centreZ[c]);
      const float py = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(px), static_cast<std::int32_t>(pz));
      // Names in use: the markers', and for a start position also every army the scenario lists (an extra army
      // such as ARMY_9 has no marker but its name is taken).
      std::vector<SaveEntry> taken = markers;
      if (std::string(type.type) == "Blank Marker") {
        for (const std::string& army : mDocument.ArmyNamesInUse()) {
          taken.push_back({army, {}});
        }
        for (const std::string& army : mDocument.ExtraArmies()) {
          taken.push_back({army, {}});
        }
      }
      SaveEntry marker = NewMarker(type, NextMarkerName(taken, type), px, py, pz);
      const std::string name = marker.name;
      mMarkerSelection.push_back(name);
      // A start position is an army: the scenario's list and the save's Armies get it.
      if (std::string(type.type) == "Blank Marker") {
        mDocument.AddArmy(marker.name);
      }
      markers.push_back(std::move(marker));
      if (!previous.empty()) {
        const int from = c == 0 ? -1 : MarkerNear(markers, type.type, previousX[c], previousZ[c], kCopyReach);
        const std::string fromName =
          c == 0 ? previous : (from >= 0 ? markers[static_cast<std::size_t>(from)].name : std::string());
        if (!fromName.empty() && fromName != name && SetMarkerLink(markers, fromName, name, true)) {
          ++linked;
        }
      }
    }
    if (linked > 0) {
      gpg::Logf("editor: %d path links made", linked);
    }
    // Draw chain: the new marker joins the chain's end; each symmetric copy its own chain (<name>_m<copy>).
    if (mTools->DrawingChain() && !mMarkerSelection.empty() && !mTools->ChainName().empty()) {
      std::vector<MarkerChain>& chains = mDocument.SaveData().Chains();
      for (std::size_t c = 0; c < mMarkerSelection.size(); ++c) {
        const std::string chainName = c == 0 ? mTools->ChainName() : mTools->ChainName() + "_m" + std::to_string(c);
        auto chain = std::find_if(chains.begin(), chains.end(), [&](const MarkerChain& each) {
          return each.name == chainName;
        });
        if (chain == chains.end()) {
          chains.push_back({chainName, {}});
          chain = chains.end() - 1;
        }
        chain->markers.push_back(mMarkerSelection[c]);
      }
      gpg::Logf("editor: chain %s has %zu markers", mTools->ChainName().c_str(), [&] {
        for (const MarkerChain& chain : chains) {
          if (chain.name == mTools->ChainName()) {
            return chain.markers.size();
          }
        }
        return 0uz;
      }());
    }
    if (!mMarkerSelection.empty()) {
      mDocument.SaveDataEdited(std::move(before));
      float fx = 0.0f, fy = 0.0f, fz = 0.0f;
      for (const SaveEntry& marker : markers) {
        if (marker.name == mMarkerSelection.front()) {
          (void)ShownMarkerPosition(marker, fx, fy, fz);
        }
      }
      gpg::Logf(
        "editor: %zu %s markers placed (the first at %.2f, %.2f), %zu markers now",
        mMarkerSelection.size(),
        type.type,
        static_cast<double>(fx),
        static_cast<double>(fz),
        markers.size()
      );
    } else {
      mMarkerSelection = std::move(selectedBefore);
    }
  }

  void EdMapScene::UpdateEffects()
  {
    // Each Effect marker plays its effect where it stands (its height above the ground, its scale), as the map's script
    // will in the game (WithScriptEffects).
    std::set<std::string> seen;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      if (MarkerTypeOf(marker) != "Effect") {
        continue;
      }
      float x = 0.0f;
      float y = 0.0f;
      float z = 0.0f;
      if (!ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      seen.insert(marker.name);
      const std::string effect = ValueString(marker.Get("effect"));
      EffectDecoration& decoration = mEffects[marker.name];
      if (decoration.effect != effect || (decoration.previews.empty() && !effect.empty())) {
        decoration.effect = effect;
        decoration.previews.clear();
        // Each path (';' between: the emitters an effect plays together) a preview of its own.
        std::size_t at = 0;
        while (at < effect.size()) {
          const std::size_t semicolon = effect.find(';', at);
          const std::string path =
            effect.substr(at, semicolon == std::string::npos ? std::string::npos : semicolon - at);
          at = semicolon == std::string::npos ? effect.size() : semicolon + 1;
          std::string text;
          if (path.empty() || !ReadGameFile(path, text)) {
            continue;
          }
          auto preview = std::make_unique<EdParticlePreview>();
          if (const auto emitter = ParseEmitter(text)) {
            preview->SetEmitter(*emitter);
          } else if (const auto flat = ParseFlatBlueprint(text)) {
            preview->SetFlat(*flat);
          } else {
            continue;
          }
          preview->Restart();
          decoration.previews.push_back(std::move(preview));
        }
        moho::gAppIdleClock = true; // the renderer's clock between sessions, so the particles age
      }
      const std::vector<double> height = ValueNumbers(marker.Get("height"));
      const std::vector<double> scale = ValueNumbers(marker.Get("scale"));
      for (const auto& preview : decoration.previews) {
        preview->SetPlace(x, y + (height.empty() ? 0.0f : static_cast<float>(height[0])), z);
        preview->SetScale(scale.empty() || scale[0] <= 0.0 ? 1.0f : static_cast<float>(scale[0]));
        preview->Frame();
      }
    }
    for (auto it = mEffects.begin(); it != mEffects.end();) {
      it = !seen.contains(it->first) ? mEffects.erase(it) : std::next(it);
    }
  }

  void EdMapScene::PlaceEffect(
    const std::string& effect
  )
  {
    const MarkerType* type = FindMarkerType("Effect");
    if (mMap == nullptr || type == nullptr || effect.empty()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const float x = SnapToGrid(mTargetX);
    const float z = SnapToGrid(mTargetZ);
    const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
    SaveEntry marker = NewMarker(*type, NextMarkerName(markers, *type), x, y, z);
    marker.Set("effect", StringValue(effect));
    mMarkerSelection = {marker.name};
    gpg::Logf(
      "editor: effect decoration %s placed at %.1f, %.1f: %s",
      marker.name.c_str(),
      static_cast<double>(x),
      static_cast<double>(z),
      effect.c_str()
    );
    markers.push_back(std::move(marker));
    mDocument.SaveDataEdited(std::move(before));
  }

  void EdMapScene::FillPathGrid(
    const int kind,
    const int count,
    const bool replace
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (kind <= 0 || field == nullptr) {
      FillAirGrid(count, replace);
      return;
    }
    const char* const typeName = kind == 1 ? "Land Path Node" : "Water Path Node";
    // The kind's passability, as the map check measures it (a T1 tank's or a frigate's footprint).
    const MapFacts& facts = mDocument.Facts();
    const PathFootprint footprint =
      kind == 1 ? PathFootprint{0x1, 0.75f, 0.0f, 0.0f} : PathFootprint{0x8, 0.0f, 1.5f, 0.0f};
    const std::vector<std::uint8_t> cells =
      PassableCells(field->data, field->width, field->height, facts.water, facts.waterElevation, footprint);
    const int cellsX = field->width - 1;
    const int cellsZ = field->height - 1;
    std::vector<int> areas;
    (void)ConnectAreas(cells, cellsX, cellsZ, areas);
    const auto areaAt = [&](const float x, const float z) {
      const int cx = std::clamp(static_cast<int>(x), 0, cellsX - 1);
      const int cz = std::clamp(static_cast<int>(z), 0, cellsZ - 1);
      return areas[static_cast<std::size_t>(cz) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(cx)];
    };
    float x0 = 0.0f;
    float z0 = 0.0f;
    float x1 = static_cast<float>(cellsX);
    float z1 = static_cast<float>(cellsZ);
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      x0 = static_cast<float>(area->x0);
      z0 = static_cast<float>(area->z0);
      x1 = static_cast<float>(area->x1);
      z1 = static_cast<float>(area->z1);
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    std::size_t removed = 0;
    if (replace) {
      const std::size_t count0 = markers.size();
      markers.erase(
        std::remove_if(
          markers.begin(),
          markers.end(),
          [typeName](const SaveEntry& marker) {
        return MarkerTypeOf(marker) == typeName;
      }
        ),
        markers.end()
      );
      removed = count0 - markers.size();
    }
    std::vector<SaveEntry> grid =
      PathNodeGrid(markers, typeName, count, x0, z0, x1, z1, [&](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
    }, [&](const float x, const float z) {
      return areaAt(x, z) != 0;
    }, [&](const float ax, const float az, const float bx, const float bz) {
      const int area = areaAt(ax, az);
      const int steps = std::max(2, static_cast<int>(std::hypot(bx - ax, bz - az)));
      for (int s = 0; s <= steps; ++s) {
        const float t = static_cast<float>(s) / static_cast<float>(steps);
        if (areaAt(ax + (bx - ax) * t, az + (bz - az) * t) != area) {
          return false;
        }
      }
      return true;
    });
    mMarkerSelection.clear();
    for (SaveEntry& node : grid) {
      mMarkerSelection.push_back(node.name);
      markers.push_back(std::move(node));
    }
    mDocument.SaveDataEdited(std::move(before));
    gpg::Logf(
      "editor: %s graph: %zu nodes of a %d x %d grid stand on its ground (%zu removed first), %zu markers now",
      typeName,
      mMarkerSelection.size(),
      count,
      count,
      removed,
      markers.size()
    );
  }

  std::string EdMapScene::UnitFitAt(
    const std::string& type,
    const float x,
    const float z,
    int& sizeX,
    int& sizeZ
  ) const
  {
    sizeX = 1;
    sizeZ = 1;
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (field == nullptr || rules == nullptr || type.empty()) {
      return {};
    }
    std::string lower = type;
    for (char& c : lower) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    moho::RResId id{};
    id.name.assign(lower.c_str());
    const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(id);
    if (blueprint == nullptr) {
      return {};
    }
    const moho::SFootprint& footprint = blueprint->mFootprint;
    sizeX = std::max<int>(1, footprint.mSizeX);
    sizeZ = std::max<int>(1, footprint.mSizeZ);
    FitFacts facts;
    facts.structure = blueprint->Physics.MotionType == moho::RULEUMT_None;
    facts.maxVariation = blueprint->Physics.MaxGroundVariation;
    const auto word = [field](const int wx, const int wz) {
      const int cx = std::clamp(wx, 0, field->width - 1);
      const int cz = std::clamp(wz, 0, field->height - 1);
      return static_cast<int>(field->data[static_cast<std::size_t>(cz) * field->width + cx]);
    };
    if (facts.structure && facts.maxVariation > 0.0f) {
      const int n = std::max(sizeX, sizeZ);
      const int cx = static_cast<int>(std::floor(x - sizeX * 0.5f));
      const int cz = static_cast<int>(std::floor(z - sizeZ * 0.5f));
      const int kind = blueprint->Physics.FlattenSkirt != 0U ? sloperules::kKindRing : sloperules::kKindBuild;
      facts.groundVaries = static_cast<float>(sloperules::CellRating(kind, n, cx, cz, word)) / 128.0f;
    }
    const MapFacts& map = mDocument.Facts();
    const float ground = static_cast<float>(word(static_cast<int>(x), static_cast<int>(z))) / 128.0f;
    facts.waterDepth = map.water ? std::max(0.0f, map.waterElevation - ground) : 0.0f;
    const auto caps = static_cast<unsigned>(footprint.mOccupancyCaps);
    facts.landOnly = (caps & 0x0Eu) == 0U; // no seabed, sub or water bits
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      facts.outsidePlayable = x - sizeX * 0.5f < static_cast<float>(area->x0) ||
        z - sizeZ * 0.5f < static_cast<float>(area->z0) || x + sizeX * 0.5f > static_cast<float>(area->x1) ||
        z + sizeZ * 0.5f > static_cast<float>(area->z1);
    }
    for (const UnitRef& unit : mUnitRefs) {
      if (
        std::fabs(unit.position.x - x) < sizeX * 0.5f + 0.5f && std::fabs(unit.position.z - z) < sizeZ * 0.5f + 0.5f
      ) {
        facts.overlaps = facts.structure;
        break;
      }
    }
    return FitProblem(facts);
  }

  void EdMapScene::FillAirGrid(
    const int count,
    const bool replace
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    float x0 = 0.0f;
    float z0 = 0.0f;
    float x1 = static_cast<float>(field->width - 1);
    float z1 = static_cast<float>(field->height - 1);
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      x0 = static_cast<float>(area->x0);
      z0 = static_cast<float>(area->z0);
      x1 = static_cast<float>(area->x1);
      z1 = static_cast<float>(area->z1);
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    std::size_t removed = 0;
    if (replace) {
      const std::size_t count0 = markers.size();
      markers.erase(
        std::remove_if(
          markers.begin(),
          markers.end(),
          [](const SaveEntry& marker) {
        return MarkerTypeOf(marker) == "Air Path Node";
      }
        ),
        markers.end()
      );
      removed = count0 - markers.size();
    }
    std::vector<SaveEntry> grid = AirNodeGrid(markers, count, x0, z0, x1, z1, [&](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
    });
    if (grid.empty()) {
      return;
    }
    mMarkerSelection.clear();
    for (SaveEntry& node : grid) {
      mMarkerSelection.push_back(node.name);
      markers.push_back(std::move(node));
    }
    mDocument.SaveDataEdited(std::move(before));
    gpg::Logf(
      "editor: air node grid %d x %d over %.0f, %.0f to %.0f, %.0f (%zu air nodes removed), %zu markers now",
      count,
      count,
      static_cast<double>(x0),
      static_cast<double>(z0),
      static_cast<double>(x1),
      static_cast<double>(z1),
      removed,
      markers.size()
    );
  }

  void EdMapScene::DeleteSelectedMarkers()
  {
    if (mMarkerSelection.empty()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    // Follow symmetry: the mirrored copies go too.
    if (FollowOn()) {
      for (const std::vector<std::string>& copies : MarkerPartners()) {
        for (const std::string& name : copies) {
          if (
            !name.empty() && std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()
          ) {
            mMarkerSelection.push_back(name);
          }
        }
      }
    }
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const std::size_t count = markers.size();
    for (const SaveEntry& marker : markers) {
      if (
        MarkerTypeOf(marker) == "Blank Marker" &&
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()
      ) {
        mDocument.RemoveArmy(marker.name);
      }
    }
    markers.erase(
      std::remove_if(
        markers.begin(),
        markers.end(),
        [&](const SaveEntry& marker) {
      return std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end();
    }
      ),
      markers.end()
    );
    if (markers.size() != count) {
      for (const std::string& name : mMarkerSelection) {
        (void)RemoveLinksTo(markers, name);
        for (MarkerChain& chain : mDocument.SaveData().Chains()) {
          chain.markers.erase(std::remove(chain.markers.begin(), chain.markers.end(), name), chain.markers.end());
        }
      }
    }
    mMarkerSelection.clear();
    if (markers.size() != count) {
      mDocument.SaveDataEdited(std::move(before));
      gpg::Logf("editor: %zu markers deleted, %zu now", count - markers.size(), markers.size());
    }
  }

  void EdMapScene::DrawMarkers(
    moho::CD3DPrimBatcher& batcher,
    const bool all
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    if (field == nullptr || markers.empty()) {
      return;
    }
    const auto vertex = [](const float x, const float y, const float z, const std::uint32_t color) {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = x;
      v.mY = y;
      v.mZ = z;
      v.mColor = color;
      return v;
    };
    // Path nodes' links first, faint, each pair once.
    if (all) {
      std::map<std::string, std::array<float, 3>> positions;
      for (const SaveEntry& marker : markers) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (!MarkerHidden(marker) && ShownMarkerPosition(marker, x, y, z)) {
          positions[marker.name] = {x, y, z};
        }
      }
      std::set<std::pair<std::string, std::string>> drawn;
      const auto selected = [&](const std::string& name) {
        return std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) != mMarkerSelection.end();
      };
      for (const SaveEntry& marker : markers) {
        const auto from = positions.find(marker.name);
        if (from == positions.end()) {
          continue;
        }
        for (const std::string& link : MarkerLinks(marker)) {
          const auto to = positions.find(link);
          if (to == positions.end() || !drawn.insert(std::minmax(marker.name, link)).second) {
            continue;
          }
          const std::uint32_t alpha = selected(marker.name) || selected(link) ? 0xF0000000u : 0x70000000u;
          const std::uint32_t color = (MarkerColor(marker) & 0x00FFFFFFu) | alpha;
          batcher.DrawLine(
            vertex(from->second[0], from->second[1] + 2.0f, from->second[2], color),
            vertex(to->second[0], to->second[1] + 2.0f, to->second[2], color)
          );
        }
      }
    }
    for (const SaveEntry& marker : markers) {
      const std::string type = MarkerTypeOf(marker);
      const bool start = type == "Blank Marker";
      const bool resource = type == "Mass" || type == "Hydrocarbon";
      // A selected marker shows whatever the tool (a Camera Info marker's view frame with it).
      const bool picked =
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end();
      if ((!all && !start && !resource && !picked) || MarkerHidden(marker)) {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      // Under the cursor: its helper in the hover colour, drawn twice over (no ring round it; user ask 2026-11-11).
      const bool hovered = !mHoverMarker.empty() && marker.name == mHoverMarker;
      const std::uint32_t color = hovered ? 0xFFFFF59Du : MarkerColor(marker);
      // Half a size of n + 0.5: a marker in a cell's middle (where Snap and the game's resources put it) has its
      // square's edges on the grid's lines.
      const float r = start ? 4.5f : (type == "Hydrocarbon" ? 2.5f : 1.5f);
      const float base = y + 0.5f;
      // A square on the ground, square to the grid, and a post above it.
      for (const float grow : {0.0f, hovered ? 0.25f : -1.0f}) {
        if (grow < 0.0f) {
          continue;
        }
        const float s = r + grow;
        batcher.DrawLine(vertex(x - s, base, z - s, color), vertex(x + s, base, z - s, color));
        batcher.DrawLine(vertex(x + s, base, z - s, color), vertex(x + s, base, z + s, color));
        batcher.DrawLine(vertex(x + s, base, z + s, color), vertex(x - s, base, z + s, color));
        batcher.DrawLine(vertex(x - s, base, z + s, color), vertex(x - s, base, z - s, color));
        batcher.DrawLine(vertex(x + grow, base, z, color), vertex(x + grow, base + (start ? 10.0f : 4.0f), z, color));
      }
      if (
        type == "Camera Info" &&
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()
      ) {
        DrawCameraFrame(batcher, *field, marker);
      }
      if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()) {
        constexpr std::uint32_t kSelected = 0xF0FFE040u;
        for (int s = 0; s < 20; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 20.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 20.0f;
          batcher.DrawLine(
            vertex(x + std::cos(a0) * (r + 1.5f), base, z + std::sin(a0) * (r + 1.5f), kSelected),
            vertex(x + std::cos(a1) * (r + 1.5f), base, z + std::sin(a1) * (r + 1.5f), kSelected)
          );
        }
      }
    }
  }

  void EdMapScene::DrawCameraFrame(
    moho::CD3DPrimBatcher& batcher,
    const moho::CHeightField& field,
    const SaveEntry& marker
  )
  {
    // FAF Studio's camframe.lua: from the eye to where the view's corners meet the ground, that outline laid on the
    // ground, and a line to the focus. Heading and pitch from `orientation`, the view's width at the focus `zoom`.
    float fx = 0.0f, fy = 0.0f, fz = 0.0f;
    if (!MarkerPosition(marker, fx, fy, fz)) {
      return;
    }
    const std::vector<double> turn = ValueNumbers(marker.Get("orientation"));
    const std::vector<double> zoomValue = ValueNumbers(marker.Get("zoom"));
    const float heading = turn.size() > 0 ? static_cast<float>(turn[0]) : mHeading;
    const float pitch = turn.size() > 1 ? static_cast<float>(turn[1]) : mPitch;
    const float zoom = !zoomValue.empty() && zoomValue[0] > 0.0 ? static_cast<float>(zoomValue[0]) : 100.0f;
    const float maxZoom = mCamera != nullptr ? mCamera->GetMaxZoom() : mMapExtent * 2.0f;
    const float aspect =
      mWidth > 0 && mHeight > 0 ? static_cast<float>(mWidth) / static_cast<float>(mHeight) : 16.0f / 9.0f;
    const CameraFrustum frustum =
      CameraFrustumOf({fx, fy, fz}, heading, pitch, zoom, CameraFovFor(zoom, maxZoom), aspect);
    // The ground between the samples, nothing off the terrain.
    const auto ground = [&field](const float x, const float z) -> std::optional<float> {
      if (x < 0.0f || z < 0.0f || x > static_cast<float>(field.width - 1) || z > static_cast<float>(field.height - 1)) {
        return std::nullopt;
      }
      const int ix = std::min(static_cast<int>(x), field.width - 2);
      const int iz = std::min(static_cast<int>(z), field.height - 2);
      const float tx = x - static_cast<float>(ix);
      const float tz = z - static_cast<float>(iz);
      const auto at = [&field](const int sx, const int sz) {
        return static_cast<float>(field.data[static_cast<std::size_t>(sz) * field.width + sx]) / 128.0f;
      };
      return (at(ix, iz) * (1.0f - tx) + at(ix + 1, iz) * tx) * (1.0f - tz) +
        (at(ix, iz + 1) * (1.0f - tx) + at(ix + 1, iz + 1) * tx) * tz;
    };
    const float reach = std::max(mMapExtent * 3.0f, frustum.distance * 4.0f + 300.0f);
    const std::array<CameraHit, 4> corners = CameraCorners(frustum, ground, reach, 600);
    const auto vertex = [](const float x, const float y, const float z, const std::uint32_t color) {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = x;
      v.mY = y;
      v.mZ = z;
      v.mColor = color;
      return v;
    };
    constexpr std::uint32_t kEdge = 0xB0FFE060u;
    constexpr std::uint32_t kOutline = 0xFFFFE060u;
    constexpr std::uint32_t kCentre = 0x60FFE060u;
    constexpr float kLift = 0.15f;
    const CameraVec& eye = frustum.eye;
    for (const CameraHit& corner : corners) {
      batcher.DrawLine(
        vertex(eye[0], eye[1], eye[2], kEdge), vertex(corner.point[0], corner.point[1], corner.point[2], kEdge)
      );
    }
    batcher.DrawLine(vertex(eye[0], eye[1], eye[2], kCentre), vertex(fx, fy, fz, kCentre));
    // The outline on the ground, in short steps so it follows the hills (a far corner is laid down on it).
    for (std::size_t i = 0; i < 4; ++i) {
      const CameraVec& a = corners[i].point;
      const CameraVec& b = corners[(i + 1) % 4].point;
      const float length = std::hypot(b[0] - a[0], b[2] - a[2]);
      const int steps = std::clamp(static_cast<int>(length / 4.0f), 1, 256);
      float px = a[0], pz = a[2];
      float py = ground(px, pz).value_or(a[1]) + kLift;
      for (int s = 1; s <= steps; ++s) {
        const float t = static_cast<float>(s) / static_cast<float>(steps);
        const float x = a[0] + (b[0] - a[0]) * t;
        const float z = a[2] + (b[2] - a[2]) * t;
        const std::optional<float> g = ground(x, z);
        const float y = (g ? *g : a[1] + (b[1] - a[1]) * t) + kLift;
        batcher.DrawLine(vertex(px, py, pz, kOutline), vertex(x, y, z, kOutline));
        px = x;
        py = y;
        pz = z;
      }
    }
  }

  void EdMapScene::DeleteDeposits()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (const auto& [name, instance] : mDeposits) {
        delete instance;
      }
    }
    mDeposits.clear();
  }

  void EdMapScene::UpdateDeposits()
  {
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr || mMap == nullptr) {
      return;
    }
    // The two deposit props' meshes, found once.
    struct Deposit
    {
      moho::RMeshBlueprint* mesh = nullptr;
      float scale = 1.0f;
    };
    static Deposit mass;
    static Deposit hydro;
    static bool looked = false;
    if (!looked) {
      looked = true;
      for (auto [path, deposit] :
           {std::pair<const char*, Deposit*>{"/env/common/props/massDeposit01_prop.bp", &mass},
            std::pair<const char*, Deposit*>{"/env/common/props/hydrocarbonDeposit01_prop.bp", &hydro}}) {
        moho::RResId id{};
        const fa::string file(path);
        gpg::STR_CopyFilename(&id.name, &file);
        if (moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id); blueprint != nullptr) {
          deposit->mesh = rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint);
          deposit->scale = blueprint->Display.UniformScale;
        }
        gpg::Logf("editor: deposit prop %s: %s", path, deposit->mesh != nullptr ? "found" : "missing");
      }
    }
    // The markers that have one now: a resource marker with `resource` on, shown (the game places it on the ground).
    std::map<std::string, std::pair<const Deposit*, Wm3::Vec3f>> wanted;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const std::string type = MarkerTypeOf(marker);
      if (type != "Mass" && type != "Hydrocarbon") {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!marker.Get("resource").contains("true") || MarkerHidden(marker) || !ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      const Deposit* const deposit = type == "Mass" ? &mass : &hydro;
      if (deposit->mesh != nullptr) {
        wanted[marker.name] = {deposit, Wm3::Vec3f{x, y, z}};
      }
    }
    for (auto it = mDeposits.begin(); it != mDeposits.end();) {
      if (!wanted.contains(it->first)) {
        delete it->second;
        it = mDeposits.erase(it);
      } else {
        ++it;
      }
    }
    for (const auto& [name, place] : wanted) {
      moho::MeshInstance*& instance = mDeposits[name];
      if (instance == nullptr) {
        const float scale = place.first->scale;
        instance = renderer->CreateMeshInstance(
          0, -1, place.first->mesh, Wm3::Vec3f{scale, scale, scale}, false, std::shared_ptr<moho::MeshMaterial>()
        );
        if (instance == nullptr) {
          mDeposits.erase(name);
          continue;
        }
        instance->isHidden = 0;
      }
      // The game turns each at random (CreatePropHPR with Random(0, 360)); here they keep the file's heading, none.
      moho::VTransform transform{};
      transform.pos_ = place.second;
      transform.orient_ = Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f};
      instance->SetStance(transform, transform);
    }
  }

  void EdMapScene::UpdateMarkerModels()
  {
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    const bool shown =
      mTools != nullptr && mTools->MarkerModels() && (mTools->MarkersToolActive() || mTools->SelectToolActive());
    if (rules == nullptr || renderer == nullptr || mMap == nullptr || !shown) {
      DeleteMarkerModels();
      return;
    }
    // Every marker but the resources (their deposits are drawn as the game places them): its prop, where it stands.
    std::map<std::string, std::pair<std::string, Wm3::Vec3f>> wanted;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const std::string type = MarkerTypeOf(marker);
      if (type == "Mass" || type == "Hydrocarbon" || MarkerHidden(marker)) {
        continue;
      }
      std::string prop = ValueString(marker.Get("prop"));
      if (prop.empty()) {
        if (const MarkerType* const known = FindMarkerType(type); known != nullptr && known->prop != nullptr) {
          prop = known->prop;
        }
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (prop.empty() || !ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      wanted[marker.name] = {prop, Wm3::Vec3f{x, y, z}};
    }
    for (auto it = mMarkerModels.begin(); it != mMarkerModels.end();) {
      const auto want = wanted.find(it->first);
      if (want == wanted.end() || want->second.first != it->second.first) {
        delete it->second.second;
        it = mMarkerModels.erase(it);
      } else {
        ++it;
      }
    }
    // Prop blueprints' meshes, looked up once each.
    static std::map<std::string, std::pair<moho::RMeshBlueprint*, float>> meshes;
    for (const auto& [name, place] : wanted) {
      auto& kept = mMarkerModels[name];
      if (kept.second == nullptr) {
        auto found = meshes.find(place.first);
        if (found == meshes.end()) {
          moho::RResId id{};
          const fa::string file(place.first.c_str());
          gpg::STR_CopyFilename(&id.name, &file);
          moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
          moho::RMeshBlueprint* mesh =
            blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
          // A mesh whose first level names no model file (no <name>_lod0.scm beside the blueprint) has nothing to draw:
          // asked for, the engine warns "GetResource: Invalid name" and returns no instance, again every frame.
          const bool noModel = mesh != nullptr && (mesh->mLods.empty() || mesh->mLods.begin()->mMeshName.empty());
          if (noModel) {
            mesh = nullptr;
          }
          found = meshes
                    .emplace(
                      place.first,
                      std::pair<moho::RMeshBlueprint*, float>{
                        mesh, blueprint != nullptr ? blueprint->Display.UniformScale : 1.0f
                      }
                    )
                    .first;
          gpg::Logf(
            "editor: marker model %s: %s",
            place.first.c_str(),
            found->second.first != nullptr ? "found" : (noModel ? "no model file (drawn as its marker)" : "missing")
          );
        }
        if (found->second.first == nullptr) {
          mMarkerModels.erase(name);
          continue;
        }
        const float scale = found->second.second;
        kept.first = place.first;
        kept.second = renderer->CreateMeshInstance(
          0, -1, found->second.first, Wm3::Vec3f{scale, scale, scale}, false, std::shared_ptr<moho::MeshMaterial>()
        );
        if (kept.second == nullptr) {
          mMarkerModels.erase(name);
          continue;
        }
        kept.second->isHidden = 0;
      }
      moho::VTransform transform{};
      transform.pos_ = place.second;
      transform.orient_ = Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f};
      kept.second->SetStance(transform, transform);
    }
  }

  void EdMapScene::DeleteMarkerModels()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (auto& [name, model] : mMarkerModels) {
        delete model.second;
      }
    }
    mMarkerModels.clear();
  }

  void EdMapScene::DrawResourceSplats(
    moho::CD3DPrimBatcher& batcher,
    const moho::CHeightField& field
  )
  {
    if (!mSplatsLoaded) {
      mSplatsLoaded = true;
      mMassSplat = moho::CD3DBatchTexture::FromFile("/env/common/splats/mass_marker.dds", 0);
      mHydroSplat = moho::CD3DBatchTexture::FromFile("/env/common/splats/hydrocarbon_marker.dds", 0);
      gpg::Logf(
        "editor: resource splats %s, %s",
        mMassSplat ? "mass loaded" : "mass missing",
        mHydroSplat ? "hydrocarbon loaded" : "hydrocarbon missing"
      );
    }
    // The ground's height between samples, a little above it so the splat doesn't sink into the terrain's mesh.
    const auto height = [&field](const float x, const float z) {
      const float cx = std::clamp(x, 0.0f, static_cast<float>(field.width - 1));
      const float cz = std::clamp(z, 0.0f, static_cast<float>(field.height - 1));
      const int x0 = std::min(static_cast<int>(cx), field.width - 2);
      const int z0 = std::min(static_cast<int>(cz), field.height - 2);
      const float fx = cx - static_cast<float>(x0);
      const float fz = cz - static_cast<float>(z0);
      const auto at = [&](const int sx, const int sz) {
        return static_cast<float>(field.data[sz * field.width + sx]) / 128.0f;
      };
      const float top = at(x0, z0) + (at(x0 + 1, z0) - at(x0, z0)) * fx;
      const float bottom = at(x0, z0 + 1) + (at(x0 + 1, z0 + 1) - at(x0, z0 + 1)) * fx;
      return top + (bottom - top) * fz + 0.12f;
    };
    std::vector<moho::CD3DPrimBatcher::Vertex> mass;
    std::vector<moho::CD3DPrimBatcher::Vertex> hydro;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      const std::string type = MarkerTypeOf(marker);
      const bool isMass = type == "Mass";
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if ((!isMass && type != "Hydrocarbon") || MarkerHidden(marker) || !ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      // A grid of one-unit cells, so the splat follows the ground's shape.
      const int cells = isMass ? 2 : 6;
      const float half = static_cast<float>(cells) * 0.5f;
      std::vector<moho::CD3DPrimBatcher::Vertex>& out = isMass ? mass : hydro;
      for (int j = 0; j < cells; ++j) {
        for (int i = 0; i < cells; ++i) {
          const auto corner = [&](const int ci, const int cj) {
            moho::CD3DPrimBatcher::Vertex v{};
            v.mX = x - half + static_cast<float>(ci);
            v.mZ = z - half + static_cast<float>(cj);
            v.mY = height(v.mX, v.mZ);
            v.mColor = 0xFFFFFFFFu;
            v.mU = static_cast<float>(ci) / static_cast<float>(cells);
            v.mV = static_cast<float>(cj) / static_cast<float>(cells);
            return v;
          };
          out.insert(out.end(), {corner(i, j), corner(i + 1, j), corner(i + 1, j + 1), corner(i, j + 1)});
        }
      }
    }
    if (mass.empty() && hydro.empty()) {
      return;
    }
    // Depth-tested, so a hill hides the splats behind it; then back to the overlay's own setup.
    batcher.Flush();
    const moho::CD3DPrimBatcher::TextureBinding before = batcher.GetTextureBinding();
    (void)batcher.Setup("TAlphaBlendLinearSample");
    batcher.SetViewProjMatrix(mCamera->CameraGetView());
    if (mMassSplat && !mass.empty()) {
      batcher.SetTexture(mMassSplat);
      batcher.DrawQuads(mass.data(), static_cast<std::uint32_t>(mass.size() / 4));
      batcher.Flush();
    }
    if (mHydroSplat && !hydro.empty()) {
      batcher.SetTexture(mHydroSplat);
      batcher.DrawQuads(hydro.data(), static_cast<std::uint32_t>(hydro.size() / 4));
      batcher.Flush();
    }
    (void)batcher.Setup("TAlphaBlendLinearSampleNoDepth");
    batcher.SetViewProjMatrix(mCamera->CameraGetView());
    batcher.SetTextureBinding(before);
  }

  int EdMapScene::PickDecal(
    const float x,
    const float z
  ) const
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    if (decals == nullptr) {
      return -1;
    }
    // From the last: later decals are drawn over earlier ones.
    for (std::int32_t i = decals->GetDecalCount(); i-- > 0;) {
      const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
      if (decal != nullptr && DecalContains(FootprintOf(*decal), x, z)) {
        return decal->mIndex;
      }
    }
    return -1;
  }

  float EdMapScene::NextDecalSizeFactor()
  {
    const float variation = mTools != nullptr ? mTools->DecalSizeVariation() : 0.0f;
    if (variation <= 0.0f) {
      return 1.0f;
    }
    mDecalSeed = mDecalSeed * 1664525U + 1013904223U;
    return 1.0f + (static_cast<float>(mDecalSeed >> 8) / 16777216.0f * 2.0f - 1.0f) * variation;
  }

  int EdMapScene::PlaceDecalCopies(
    const float x,
    const float z,
    const float yaw,
    const float sizeFactor
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    moho::IDecalManager* const decals = mDocument.Decals();
    if (mTools == nullptr || field == nullptr || decals == nullptr) {
      return 0;
    }
    const std::string& texture = mTools->DecalTexturePath();
    const std::string pair = mTools->DecalPairPath();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const std::string normals = mTools->DecalNormalsPath();
    // Each copy's middle and heading (the cursor's carried through the symmetry; EdDecalShape's DecalCopyPlaces).
    int placed = 0;
    for (const DecalPlace& place :
         DecalCopyPlaces(field->width, field->height, x, z, yaw, brush.symmetry, brush.turns)) {
      const float heading = place.heading;
      const DecalFootprint footprint =
        DecalAround(place.x, place.z, mTools->DecalSizeX() * sizeFactor, mTools->DecalSizeZ() * sizeFactor, heading);
      DecalState state;
      state.type = DecalTypeForTexture(texture);
      state.names[0] = texture;
      state.scale[0] = footprint.sizeX;
      state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
      state.scale[2] = footprint.sizeZ;
      state.position[0] = footprint.x;
      state.position[1] = mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(place.x)), static_cast<std::int32_t>(std::lround(place.z))
      );
      state.position[2] = footprint.z;
      state.orientation[1] = heading;
      state.cutoff = mTools->DecalCutoff();
      // An albedo's spec map is its second texture, as the game's maps keep them.
      state.names[1] = pair;
      if (const moho::CWldTerrainDecal* const decal = AddDecal(*decals, state); decal != nullptr) {
        mDecalSelection.push_back(decal->mIndex);
        ++placed;
      }
      // Its normals as a decal of their own at the same place (FAF Studio's separate normals decal).
      if (!normals.empty()) {
        DecalState second = state;
        second.type = DecalTypeForTexture(normals);
        second.names[0] = normals;
        second.names[1].clear();
        if (const moho::CWldTerrainDecal* const decal = AddDecal(*decals, second); decal != nullptr) {
          mDecalSelection.push_back(decal->mIndex);
        }
      }
    }
    return placed;
  }

  int EdMapScene::WriteGeneratedWaterMask(
    const field::Grid& mask,
    const WaterMask kind,
    const int mode,
    const float strength,
    std::string& message
  )
  {
    int width = 0;
    int height = 0;
    std::uint8_t* const cells = mDocument.WaterMaskCells(kind, width, height);
    if (cells == nullptr || mask.Count() == 0) {
      message = "No water masks on this map.";
      return 0;
    }
    EdDocument::WaterMaskSnapshot before = mDocument.WaterMasksNow();
    const int changed = WriteIntoWaterMask(cells, width, height, [&mask](const float x, const float z) {
      return field::SampleWorld(mask, x, z);
    }, mode, strength);
    mDocument.WaterMasksChanged(0, 0, width, height);
    if (!(before == mDocument.WaterMasksNow())) {
      mDocument.WaterMasksEdited(std::move(before));
    }
    message = std::string("The water's ") + WaterMaskName(kind) + ": " + std::to_string(changed) + " cells changed.";
    return changed;
  }

  int EdMapScene::MirrorHalf()
  {
    return MirrorHalf(MirrorHalfOptions{});
  }

  int EdMapScene::SymmetryParts() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return 1;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    if (brush.symmetry == Symmetry::None) {
      return 1;
    }
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    // A point off the axes: every copy is its own.
    return HeightBrushCentres(
      field->width, field->height, field->width * 0.31f, field->height * 0.17f, brush.symmetry, brush.turns, cx, cz
    );
  }

  int EdMapScene::MirrorHalf(
    const MirrorHalfOptions& options
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mMap->mProps == nullptr) {
      return 0;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    if (brush.symmetry == Symmetry::None) {
      return 0;
    }
    // A place is in the source part when it is that one (`options.source`) of its copies ordered by z then x.
    const auto inFirst = [&](const float x, const float z) {
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      const int n = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      int rank = 0;
      for (int c = 1; c < n; ++c) {
        if (cz[c] < z - 0.01f || (std::fabs(cz[c] - z) <= 0.01f && cx[c] < x - 0.01f)) {
          ++rank;
        }
      }
      return rank == options.source;
    };
    // Props: those outside the source part go (replace), those in it become the selection.
    mSelection.clear();
    std::vector<int> drop;
    if (options.props) {
      for (std::size_t i = 0; i < mMap->mProps->mEntries.size(); ++i) {
        const moho::CWldPropEntry& entry = mMap->mProps->mEntries[i];
        if (inFirst(entry.mTransform.pos_.x, entry.mTransform.pos_.z)) {
          mSelection.push_back(static_cast<int>(i));
        } else if (options.replace) {
          drop.push_back(static_cast<int>(i));
        }
      }
    }
    const std::vector<int> keepProps = mSelection;
    mSelection = drop;
    const int droppedProps = static_cast<int>(drop.size());
    if (!drop.empty()) {
      DeleteSelection();
    }
    // The kept props' indices moved down by the ones removed before them.
    mSelection.clear();
    for (const int index : keepProps) {
      const auto before = std::count_if(drop.begin(), drop.end(), [index](const int d) {
        return d < index;
      });
      mSelection.push_back(index - static_cast<int>(before));
    }
    // Decals the same way.
    mDecalSelection.clear();
    std::vector<int> keepDecals;
    if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr && options.decals) {
      for (std::int32_t i = 0; i < decals->GetDecalCount(); ++i) {
        const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
        if (decal == nullptr) {
          continue;
        }
        float cx = 0.0f, cz = 0.0f;
        DecalCentre(FootprintOf(*decal), cx, cz);
        if (inFirst(cx, cz)) {
          keepDecals.push_back(decal->mIndex);
        } else if (options.replace) {
          mDecalSelection.push_back(decal->mIndex);
        }
      }
    }
    const int droppedDecals = static_cast<int>(mDecalSelection.size());
    if (!mDecalSelection.empty()) {
      DeleteSelectedDecals();
    }
    mDecalSelection = keepDecals;
    // Markers (not the starts: an army each).
    mMarkerSelection.clear();
    std::vector<std::string> keepMarkers;
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!options.markers || MarkerTypeOf(marker) == "Blank Marker" || !ShownMarkerPosition(marker, x, y, z)) {
        continue;
      }
      if (inFirst(x, z)) {
        keepMarkers.push_back(marker.name);
      } else if (options.replace) {
        mMarkerSelection.push_back(marker.name);
      }
    }
    const int droppedMarkers = static_cast<int>(mMarkerSelection.size());
    if (!mMarkerSelection.empty()) {
      DeleteSelectedMarkers();
    }
    mMarkerSelection = keepMarkers;
    // Units: those outside the source part go (replace), those in it are copied.
    mUnitSelection.clear();
    int droppedUnits = 0;
    if (options.units) {
      std::vector<std::pair<std::string, std::string>> drop;
      for (const UnitRef& ref : mUnitRefs) {
        if (inFirst(ref.position.x, ref.position.z)) {
          mUnitSelection.emplace_back(ref.army, ref.name);
        } else if (options.replace) {
          drop.emplace_back(ref.army, ref.name);
        }
      }
      if (!drop.empty()) {
        const auto keep = mUnitSelection;
        mUnitSelection = drop;
        droppedUnits = static_cast<int>(drop.size());
        DeleteSelectedUnits();
        mUnitSelection = keep;
      }
    }
    mMirrorMapArmies = options.mapArmies;
    int made = MirrorSelection();
    mMirrorMapArmies = false;
    // Areas: each in the source part gets its copies (the rectangle's corners mapped); AREA_1 stays as it is.
    int areasMade = 0;
    int areasDropped = 0;
    if (options.areas) {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
      std::vector<SaveEntry> copies;
      std::vector<SaveEntry> kept;
      int next = 1;
      for (const SaveEntry& a : areas) {
        if (a.name.starts_with("AREA_")) {
          next = std::max(next, std::atoi(a.name.c_str() + 5) + 1);
        }
      }
      for (const SaveEntry& a : areas) {
        const std::vector<double> r = ValueNumbers(a.Get("rectangle"));
        if (a.name == "AREA_1" || r.size() < 4) {
          kept.push_back(a);
          continue;
        }
        const float cx = static_cast<float>((r[0] + r[2]) * 0.5);
        const float cz = static_cast<float>((r[1] + r[3]) * 0.5);
        if (!inFirst(cx, cz)) {
          if (options.replace) {
            ++areasDropped;
          } else {
            kept.push_back(a);
          }
          continue;
        }
        kept.push_back(a);
        float ax[kMaxSymmetryCopies], az[kMaxSymmetryCopies], bx[kMaxSymmetryCopies], bz[kMaxSymmetryCopies];
        const int n = HeightBrushCentres(
          field->width,
          field->height,
          static_cast<float>(r[0]),
          static_cast<float>(r[1]),
          brush.symmetry,
          brush.turns,
          ax,
          az
        );
        (void)HeightBrushCentres(
          field->width,
          field->height,
          static_cast<float>(r[2]),
          static_cast<float>(r[3]),
          brush.symmetry,
          brush.turns,
          bx,
          bz
        );
        for (int c = 1; c < n; ++c) {
          SaveEntry copy = a;
          copy.name = "AREA_" + std::to_string(next++);
          copy.Set(
            "rectangle",
            RectangleValue(
              std::min(ax[c], bx[c]), std::min(az[c], bz[c]), std::max(ax[c], bx[c]), std::max(az[c], bz[c])
            )
          );
          copies.push_back(std::move(copy));
          ++areasMade;
        }
      }
      if (areasMade > 0 || areasDropped > 0) {
        kept.insert(kept.end(), copies.begin(), copies.end());
        areas = std::move(kept);
        mDocument.SaveDataEdited(std::move(before));
      }
      made += areasMade;
    }
    gpg::Logf(
      "editor: mirror half from part %d (%s, units %s): removed %d props, %d decals, %d markers, %d units, %d areas; "
      "%d copies made (%d areas)",
      options.source,
      options.replace ? "replace" : "add",
      options.mapArmies ? "to the mirrored armies" : "kept in their armies",
      droppedProps,
      droppedDecals,
      droppedMarkers,
      droppedUnits,
      areasDropped,
      made,
      areasMade
    );
    return made;
  }

  void EdMapScene::PlaceDecals(
    const float x,
    const float z
  )
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    if (mTools == nullptr || decals == nullptr) {
      return;
    }
    const std::string& texture = mTools->DecalTexturePath();
    if (texture.empty()) {
      gpg::Warnf("editor: pick a decal texture first");
      return;
    }
    float yaw = mTools->DecalTurnDegrees() * kPi / 180.0f;
    if (mTools->RandomDecalTurn()) {
      mDecalSeed = mDecalSeed * 1664525U + 1013904223U;
      yaw = static_cast<float>(mDecalSeed >> 8) / 16777216.0f * 2.0f * kPi;
    }
    const float factor = NextDecalSizeFactor();
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    mDecalSelection.clear();
    (void)PlaceDecalCopies(x, z, yaw, factor);
    if (!mDecalSelection.empty()) {
      mDocument.DecalsEdited(std::move(before));
      gpg::Logf(
        "editor: %zu decals placed (%s, %.1f x %.1f), %d decals now",
        mDecalSelection.size(),
        texture.c_str(),
        static_cast<double>(mTools->DecalSizeX() * factor),
        static_cast<double>(mTools->DecalSizeZ() * factor),
        decals->GetDecalCount()
      );
    }
  }

  void EdMapScene::DecalBrushAt(
    const float x,
    const float z
  )
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (mTools == nullptr || decals == nullptr || field == nullptr) {
      return;
    }
    const EdTools::DecalBrush& b = mTools->DecalBrushSettings();
    // A dab each half radius along the drag.
    if (std::hypot(x - mDecalBrushLastX, z - mDecalBrushLastZ) < std::max(1.0f, b.radius * 0.5f)) {
      return;
    }
    mDecalBrushLastX = x;
    mDecalBrushLastZ = z;
    if (mTools->DecalScatterMode()) {
      if (mTools->DecalTexturePath().empty()) {
        return;
      }
      // The points in the source circle; PlaceDecalCopies mirrors each (so the scatter is symmetric).
      const auto points = ScatterInCircle(x, z, b.radius, b.count, b.apart, mDecalBrushPoints, mDecalSeed);
      for (const auto& [px, pz] : points) {
        float yaw = mTools->DecalTurnDegrees() * kPi / 180.0f;
        if (mTools->RandomDecalTurn()) {
          mDecalSeed = mDecalSeed * 1664525U + 1013904223U;
          yaw = static_cast<float>(mDecalSeed >> 8) / 16777216.0f * 2.0f * kPi;
        }
        (void)PlaceDecalCopies(px, pz, yaw, NextDecalSizeFactor());
        mDecalBrushPoints.emplace_back(px, pz);
      }
      return;
    }
    // Erase: every decal whose centre is in the circle or one of its symmetric copies.
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
    const std::string& only = mTools->DecalTexturePath();
    for (const DecalState& state : CaptureDecals(*decals)) {
      if (b.onlyThisTexture && state.names[0] != only) {
        continue;
      }
      bool inside = false;
      for (int c = 0; c < copies && !inside; ++c) {
        inside = std::hypot(state.position[0] - cx[c], state.position[2] - cz[c]) <= b.radius;
      }
      if (inside) {
        if (moho::CWldTerrainDecal* const decal = FindDecal(*decals, state.index); decal != nullptr) {
          decals->DestroyDecal(decal);
        }
      }
    }
  }

  std::vector<std::pair<float, float>> EdMapScene::DecalPathCopy(
    const std::vector<std::pair<float, float>>& path,
    const int c,
    int& copies
  ) const
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    std::vector<std::pair<float, float>> copy;
    copies = 1;
    for (const auto& [x, z] : path) {
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      if (
        c >= copies || cx[c] < 0.0f || cz[c] < 0.0f || cx[c] > static_cast<float>(field->width - 1) ||
        cz[c] > static_cast<float>(field->height - 1)
      ) {
        return {};
      }
      copy.emplace_back(cx[c], cz[c]);
    }
    return copy;
  }

  void EdMapScene::PlaceDecalPath()
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    if (mTools == nullptr || decals == nullptr || mDecalPath.size() < 2) {
      return;
    }
    const std::string& texture = mTools->DecalTexturePath();
    if (texture.empty()) {
      gpg::Warnf("editor: pick a decal texture first");
      return;
    }
    const std::string pair = mTools->DecalPairPath();
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    mDecalSelection.clear();
    int copies = 1;
    (void)DecalPathCopy(mDecalPath, 0, copies);
    for (int c = 0; c < copies; ++c) {
      int unused = 0;
      const std::vector<std::pair<float, float>> path = DecalPathCopy(mDecalPath, c, unused);
      for (const DecalFootprint& footprint :
           DecalsAlongPath(path, mTools->DecalSizeX(), mTools->DecalSizeZ(), mTools->DecalOverlap())) {
        float cx = 0.0f, cz = 0.0f;
        DecalCentre(footprint, cx, cz);
        DecalState state;
        state.type = DecalTypeForTexture(texture);
        state.names[0] = texture;
        state.names[1] = pair;
        state.scale[0] = footprint.sizeX;
        state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
        state.scale[2] = footprint.sizeZ;
        state.position[0] = footprint.x;
        state.position[1] = mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(cx)), static_cast<std::int32_t>(std::lround(cz))
        );
        state.position[2] = footprint.z;
        state.orientation[1] = footprint.yaw;
        state.cutoff = mTools->DecalCutoff();
        if (const moho::CWldTerrainDecal* const decal = AddDecal(*decals, state); decal != nullptr) {
          mDecalSelection.push_back(decal->mIndex);
        }
      }
    }
    if (!mDecalSelection.empty()) {
      mDocument.DecalsEdited(std::move(before));
      gpg::Logf(
        "editor: path of %zu points: %zu decals placed (%s, %.1f x %.1f, overlap %.2f), %d decals now",
        mDecalPath.size(),
        mDecalSelection.size(),
        texture.c_str(),
        static_cast<double>(mTools->DecalSizeX()),
        static_cast<double>(mTools->DecalSizeZ()),
        static_cast<double>(mTools->DecalOverlap()),
        decals->GetDecalCount()
      );
    }
    mDecalPath.clear();
  }

  void EdMapScene::DeleteSelectedDecals()
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    if (decals == nullptr || mDecalSelection.empty()) {
      return;
    }
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    int deleted = 0;
    // Follow symmetry: the mirrored copies go too.
    if (FollowOn()) {
      std::vector<int> doomed = mDecalSelection;
      for (const std::vector<int>& copies : DecalPartners()) {
        for (const int partner : copies) {
          if (partner >= 0 && std::find(doomed.begin(), doomed.end(), partner) == doomed.end()) {
            doomed.push_back(partner);
          }
        }
      }
      mDecalSelection = std::move(doomed);
    }
    for (const int index : mDecalSelection) {
      if (moho::CWldTerrainDecal* const decal = FindDecal(*decals, index); decal != nullptr) {
        decals->DestroyDecal(decal);
        ++deleted;
      }
    }
    mDecalSelection.clear();
    if (deleted > 0) {
      mDocument.DecalsEdited(std::move(before));
      gpg::Logf("editor: %d decals deleted, %d now", deleted, decals->GetDecalCount());
    }
  }

  void EdMapScene::DrawDecalOutlines(
    moho::CD3DPrimBatcher& batcher,
    const moho::CHeightField& field
  )
  {
    moho::IDecalManager* const decals = mDocument.Decals();
    if (decals == nullptr || mTools == nullptr) {
      return;
    }
    // An outline along the ground: each side in short pieces that follow the terrain.
    const auto outline = [&](const DecalFootprint& footprint, const std::uint32_t color) {
      float x[4], z[4];
      DecalCorners(footprint, x, z);
      for (int side = 0; side < 4; ++side) {
        const int next = (side + 1) % 4;
        const int steps = std::clamp(static_cast<int>(std::hypot(x[next] - x[side], z[next] - z[side]) / 2.0f), 1, 64);
        for (int s = 0; s < steps; ++s) {
          const auto at = [&](const float t) {
            moho::CD3DPrimBatcher::Vertex v{};
            v.mX = x[side] + (x[next] - x[side]) * t;
            v.mZ = z[side] + (z[next] - z[side]) * t;
            const int sx = std::clamp(static_cast<int>(std::lround(v.mX)), 0, field.width - 1);
            const int sz = std::clamp(static_cast<int>(std::lround(v.mZ)), 0, field.height - 1);
            v.mY = static_cast<float>(field.data[sz * field.width + sx]) / 128.0f + 0.5f;
            v.mColor = color;
            return v;
          };
          batcher.DrawLine(at(static_cast<float>(s) / steps), at(static_cast<float>(s + 1) / steps));
        }
      }
    };
    for (const int index : mDecalSelection) {
      if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, index); decal != nullptr) {
        outline(FootprintOf(*decal), 0xF0FFE040u);
      }
    }
    if (!mTools->DecalsToolActive()) {
      return;
    }
    float gx = 0.0f;
    float gz = 0.0f;
    if (mDragDecals || !CursorGround(gx, gz)) {
      mDecalPathPreview = 0;
      return;
    }
    if (mTools->DecalPathMode()) {
      // The curve through the points and the cursor, its points, and the decals along it (every copy).
      std::vector<std::pair<float, float>> path = mDecalPath;
      path.emplace_back(gx, gz);
      int copies = 1;
      (void)DecalPathCopy(path, 0, copies);
      mDecalPathPreview = 0;
      for (int c = 0; c < copies; ++c) {
        int unused = 0;
        const std::vector<std::pair<float, float>> copy = DecalPathCopy(path, c, unused);
        if (copy.size() < 2) {
          continue;
        }
        const std::uint32_t lineColor = c == 0 ? 0xF0FFB030u : 0xB0FF9A3Cu;
        const int samples = static_cast<int>(copy.size() - 1) * 16;
        for (int s = 0; s < samples; ++s) {
          const auto a = PathPoint(copy, static_cast<float>(s) / 16.0f);
          const auto b = PathPoint(copy, static_cast<float>(s + 1) / 16.0f);
          const auto ground = [&](const std::pair<float, float>& p) {
            moho::CD3DPrimBatcher::Vertex v{};
            v.mX = p.first;
            v.mZ = p.second;
            const int sx = std::clamp(static_cast<int>(std::lround(p.first)), 0, field.width - 1);
            const int sz = std::clamp(static_cast<int>(std::lround(p.second)), 0, field.height - 1);
            v.mY = static_cast<float>(field.data[sz * field.width + sx]) / 128.0f + 0.8f;
            v.mColor = lineColor;
            return v;
          };
          batcher.DrawLine(ground(a), ground(b));
        }
        for (std::size_t k = 0; k + 1 < copy.size(); ++k) {
          // The laid points as small squares (the last is the cursor).
          outline(DecalAround(copy[k].first, copy[k].second, 1.5f, 1.5f, 0.0f), 0xF0FFFFFFu);
        }
        const std::vector<DecalFootprint> along =
          DecalsAlongPath(copy, mTools->DecalSizeX(), mTools->DecalSizeZ(), mTools->DecalOverlap());
        mDecalPathPreview += static_cast<int>(along.size());
        for (const DecalFootprint& footprint : along) {
          outline(footprint, c == 0 ? 0x90FFFFFFu : 0x80FF9A3Cu);
        }
      }
      // What Place would lay: without the cursor's point.
      if (!mDecalPath.empty()) {
        int laid = 0;
        for (int c = 0; c < copies; ++c) {
          int unused = 0;
          laid += static_cast<int>(
            DecalsAlongPath(
              DecalPathCopy(mDecalPath, c, unused), mTools->DecalSizeX(), mTools->DecalSizeZ(), mTools->DecalOverlap()
            )
              .size()
          );
        }
        mDecalPathPreview = laid;
      }
    } else if (mTools->DecalPlaceMode()) {
      // The decal to come, and its symmetric copies.
      const HeightBrush brush = mTools->CurrentHeightBrush();
      const float yaw = mTools->DecalTurnDegrees() * kPi / 180.0f;
      float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
        aheadZ[kMaxSymmetryCopies];
      const int copies =
        HeightBrushCentres(field.width, field.height, gx, gz, brush.symmetry, brush.turns, centreX, centreZ);
      (void)HeightBrushCentres(
        field.width, field.height, gx + std::cos(yaw), gz + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
      );
      for (int c = 0; c < copies; ++c) {
        const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
        outline(
          DecalAround(centreX[c], centreZ[c], mTools->DecalSizeX(), mTools->DecalSizeZ(), heading),
          c == 0 ? 0xF0FFFFFFu : 0xE0FF9A3Cu
        );
      }
    } else if (const int hover = PickDecal(gx, gz); hover >= 0) {
      if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, hover); decal != nullptr) {
        outline(FootprintOf(*decal), 0xC0FFFFFFu);
      }
    }
  }

  int EdMapScene::PickProp(
    const float x,
    const float z
  ) const
  {
    if (mMap == nullptr || mMap->mProps == nullptr) {
      return -1;
    }
    // Within a few units of the ground point, more when the camera is far.
    const float reach = std::max(2.5f, mDistance * 0.012f);
    int best = -1;
    float bestDistance = reach;
    const auto& entries = mMap->mProps->mEntries;
    for (std::size_t i = 0; i < entries.size(); ++i) {
      const float d = std::hypot(entries[i].mTransform.pos_.x - x, entries[i].mTransform.pos_.z - z);
      if (d < bestDistance) {
        bestDistance = d;
        best = static_cast<int>(i);
      }
    }
    return best;
  }

  void EdMapScene::BeginObjectStroke()
  {
    mObjectBefore = mDocument.PropsNow();
    mObjectStroke = true;
    mObjectsChanged = false;
  }

  bool EdMapScene::EndObjectStroke(
    const bool ownStep
  )
  {
    const bool kept = mObjectStroke && mObjectsChanged;
    if (kept) {
      const std::size_t before = mObjectBefore.entries.size();
      mDocument.PropsEdited(std::move(mObjectBefore), ownStep);
      gpg::Logf(
        "editor: prop edit: %zu props before, %zu now",
        before,
        mMap != nullptr && mMap->mProps != nullptr ? mMap->mProps->mEntries.size() : 0U
      );
      if (!mPaintCounts.empty()) {
        std::string painted;
        for (const auto& [path, count] : mPaintCounts) {
          painted +=
            (painted.empty() ? "" : ", ") + std::to_string(count) + " " + path.substr(path.find_last_of('/') + 1);
        }
        gpg::Logf("editor: painted from the list (before symmetry copies): %s", painted.c_str());
      }
    }
    mPaintCounts.clear();
    mObjectBefore = {};
    mObjectStroke = false;
    mObjectsChanged = false;
    mDragSelection = false;
    return kept;
  }

  void EdMapScene::MovePropTo(
    const int index,
    const Wm3::Vec3f& position
  )
  {
    auto& entries = mMap->mProps->mEntries;
    if (index < 0 || static_cast<std::size_t>(index) >= entries.size()) {
      return;
    }
    moho::CWldPropEntry& entry = entries[static_cast<std::size_t>(index)];
    if (std::memcmp(&entry.mTransform.pos_, &position, sizeof(position)) == 0) {
      return; // a click without a move changes nothing
    }
    entry.mTransform.pos_ = position;
    if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
      mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
    }
    mObjectsChanged = true;
    mDocument.SetModified(true);
  }

  void EdMapScene::TurnSelection(
    const float radians
  )
  {
    if (mSelection.empty() || mMap == nullptr) {
      return;
    }
    BeginObjectStroke();
    const std::vector<std::vector<int>> partners = FollowOn() ? PropPartners() : std::vector<std::vector<int>>{};
    const Wm3::Quatf turn(std::cos(radians * 0.5f), 0.0f, std::sin(radians * 0.5f), 0.0f);
    auto& entries = mMap->mProps->mEntries;
    const auto setOrient = [&](const int index, const Wm3::Quatf& orient) {
      moho::CWldPropEntry& entry = entries[static_cast<std::size_t>(index)];
      entry.mTransform.orient_ = orient;
      const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
      entry.mTransform = record.loaded;
      mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
      if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
        mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
      }
    };
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const HeightBrush brush = mTools != nullptr ? mTools->CurrentHeightBrush() : HeightBrush{};
    for (std::size_t i = 0; i < mSelection.size(); ++i) {
      const int index = mSelection[i];
      setOrient(index, turn * entries[static_cast<std::size_t>(index)].mTransform.orient_);
      // Its mirrored copies take the image of its new heading.
      if (i < partners.size() && field != nullptr) {
        const moho::CWldPropEntry& entry = entries[static_cast<std::size_t>(index)];
        const float heading = 2.0f * std::atan2(entry.mTransform.orient_.y, entry.mTransform.orient_.w);
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies], ch[kMaxSymmetryCopies];
        const int copies = SymmetricPlaces(
          field->width,
          field->height,
          brush.symmetry,
          brush.turns,
          entry.mTransform.pos_.x,
          entry.mTransform.pos_.z,
          heading,
          cx,
          cz,
          ch
        );
        for (int c = 1; c < copies && static_cast<std::size_t>(c - 1) < partners[i].size(); ++c) {
          if (const int partner = partners[i][static_cast<std::size_t>(c - 1)]; partner >= 0) {
            setOrient(partner, Wm3::Quatf(std::cos(ch[c] * 0.5f), 0.0f, std::sin(ch[c] * 0.5f), 0.0f));
          }
        }
      }
    }
    mObjectsChanged = true;
    mDocument.SetModified(true);
    EndObjectStroke();
  }

  bool EdMapScene::FollowOn() const
  {
    return !mNoFollow && mTools != nullptr && mMap != nullptr && mTools->FollowSymmetry() &&
      mTools->CurrentHeightBrush().symmetry != Symmetry::None;
  }

  std::vector<std::vector<int>> EdMapScene::PropPartners() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mMap->mProps == nullptr) {
      return {};
    }
    std::vector<FollowItem> items;
    items.reserve(mMap->mProps->mEntries.size());
    for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
      std::string key = entry.mBlueprintPath.c_str();
      for (char& c : key) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      items.push_back({entry.mTransform.pos_.x, entry.mTransform.pos_.z, std::move(key)});
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    return FindSymmetryPartners(items, mSelection, field->width, field->height, brush.symmetry, brush.turns, 1.5f);
  }

  std::vector<std::vector<std::string>> EdMapScene::MarkerPartners() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return {};
    }
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    std::vector<FollowItem> items;
    std::vector<int> selected;
    items.reserve(markers.size());
    for (const SaveEntry& marker : markers) {
      const std::vector<double> at = ValueNumbers(marker.Get("position"));
      items.push_back(
        {at.size() >= 3 ? static_cast<float>(at[0]) : -1e9f,
         at.size() >= 3 ? static_cast<float>(at[2]) : -1e9f,
         MarkerTypeOf(marker)}
      );
    }
    for (const std::string& name : mMarkerSelection) {
      for (std::size_t i = 0; i < markers.size(); ++i) {
        if (markers[i].name == name) {
          selected.push_back(static_cast<int>(i));
        }
      }
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const std::vector<std::vector<int>> found =
      FindSymmetryPartners(items, selected, field->width, field->height, brush.symmetry, brush.turns, 1.5f);
    std::vector<std::vector<std::string>> names(found.size());
    for (std::size_t s = 0; s < found.size(); ++s) {
      for (const int index : found[s]) {
        names[s].push_back(index >= 0 ? markers[static_cast<std::size_t>(index)].name : std::string());
      }
    }
    return names;
  }

  void EdMapScene::FollowPropMove(
    const std::size_t selected,
    const Wm3::Vec3f& position
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (selected >= mPropFollow.size() || field == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, position.x, position.z, brush.symmetry, brush.turns, cx, cz);
    for (int c = 1; c < copies && static_cast<std::size_t>(c - 1) < mPropFollow[selected].size(); ++c) {
      if (const int partner = mPropFollow[selected][static_cast<std::size_t>(c - 1)]; partner >= 0) {
        MovePropTo(
          partner,
          Wm3::Vec3f{
            cx[c],
            mMap->mTerrainRes->GetHeightAt(
              static_cast<std::int32_t>(std::lround(cx[c])), static_cast<std::int32_t>(std::lround(cz[c]))
            ),
            cz[c]
          }
        );
      }
    }
  }

  void EdMapScene::FollowMarkerMove(
    const std::size_t selected,
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (selected >= mMarkerFollow.size() || field == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (int c = 1; c < copies && static_cast<std::size_t>(c - 1) < mMarkerFollow[selected].size(); ++c) {
      const std::string& name = mMarkerFollow[selected][static_cast<std::size_t>(c - 1)];
      if (name.empty()) {
        continue;
      }
      for (SaveEntry& marker : markers) {
        if (marker.name == name) {
          const float y =
            mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(cx[c]), static_cast<std::int32_t>(cz[c]));
          marker.Set("position", Vector3Value(cx[c], y, cz[c]));
        }
      }
    }
  }

  namespace
  {
    moho::VTransform UnitTransform(const Wm3::Vec3f& position, const float (&orientation)[3]); // below
  } // namespace

  std::string EdMapScene::ArrangeSelection(
    const ArrangeOp op,
    const float step
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || op >= ArrangeOp::Count) {
      return "no map is open";
    }
    const float maxX = static_cast<float>(field->width - 1);
    const float maxZ = static_cast<float>(field->height - 1);
    const auto ground = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    const auto tooFew = [&](const std::size_t count) -> std::string {
      if (static_cast<int>(count) >= ArrangeMinimum(op)) {
        return {};
      }
      return std::string(ArrangeTitle(op)) + " needs " + std::to_string(ArrangeMinimum(op)) + " or more selected";
    };
    ArrangePlaces places;
    std::string error;
    // The Markers tool's picked areas go with the markers (or alone).
    const std::vector<std::string> areaNames =
      mTools != nullptr && mTools->MarkersToolActive() ? mTools->AreaSelection() : std::vector<std::string>{};
    const PickKind kind = SelectedKind() == PickKind::None && !areaNames.empty() ? PickKind::Marker : SelectedKind();
    switch (kind) {
    case PickKind::Prop: {
      if (mMap->mProps == nullptr || !(error = tooFew(mSelection.size())).empty()) {
        break;
      }
      auto& entries = mMap->mProps->mEntries;
      for (const int index : mSelection) {
        const moho::VTransform& t = entries[static_cast<std::size_t>(index)].mTransform;
        places.x.push_back(t.pos_.x);
        places.z.push_back(t.pos_.z);
        places.heading.push_back(2.0f * std::atan2(t.orient_.y, t.orient_.w));
      }
      const std::vector<float> headings = places.heading;
      if (!Arrange(op, places, step)) {
        break;
      }
      BeginObjectStroke();
      for (std::size_t i = 0; i < mSelection.size(); ++i) {
        const int index = mSelection[i];
        const float x = std::clamp(places.x[i], 0.0f, maxX);
        const float z = std::clamp(places.z[i], 0.0f, maxZ);
        MovePropTo(index, Wm3::Vec3f{x, ground(x, z), z});
        if (places.heading[i] != headings[i]) {
          // A mirror: the prop faces the mirrored way (its own tilt dropped, as Q/E's copies are).
          moho::CWldPropEntry& entry = entries[static_cast<std::size_t>(index)];
          entry.mTransform.orient_ =
            Wm3::Quatf(std::cos(places.heading[i] * 0.5f), 0.0f, std::sin(places.heading[i] * 0.5f), 0.0f);
          const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
          entry.mTransform = record.loaded;
          mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
          if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
            mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
          }
          mObjectsChanged = true;
        }
      }
      EndObjectStroke();
      return {};
    }
    case PickKind::Marker: {
      if (!(error = tooFew(mMarkerSelection.size() + areaNames.size())).empty()) {
        break;
      }
      std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
      std::vector<std::size_t> indices;
      for (const std::string& name : mMarkerSelection) {
        for (std::size_t i = 0; i < markers.size(); ++i) {
          float x = 0.0f, y = 0.0f, z = 0.0f;
          if (markers[i].name == name && ShownMarkerPosition(markers[i], x, y, z)) {
            indices.push_back(i);
            places.x.push_back(x);
            places.z.push_back(z);
          }
        }
      }
      std::vector<SaveEntry>& areas = mDocument.SaveData().Areas();
      std::vector<std::size_t> areaIndices;
      std::vector<std::array<float, 4>> areaRects;
      for (const std::string& name : areaNames) {
        for (std::size_t i = 0; i < areas.size(); ++i) {
          const std::vector<double> e = ValueNumbers(areas[i].Get("rectangle"));
          if (areas[i].name == name && e.size() >= 4) {
            areaIndices.push_back(i);
            areaRects.push_back(
              {static_cast<float>(e[0]), static_cast<float>(e[1]), static_cast<float>(e[2]), static_cast<float>(e[3])}
            );
            places.x.push_back(static_cast<float>(e[0] + e[2]) * 0.5f);
            places.z.push_back(static_cast<float>(e[1] + e[3]) * 0.5f);
          }
        }
      }
      const std::vector<float> beforeX = places.x;
      const std::vector<float> beforeZ = places.z;
      if (!Arrange(op, places, step)) {
        error = tooFew(indices.size() + areaIndices.size());
        break;
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      const AreaBounds bounds = AreaLimitBounds();
      for (std::size_t a = 0; a < areaIndices.size(); ++a) {
        const std::size_t k = indices.size() + a;
        const float dx = std::round(places.x[k] - beforeX[k]);
        const float dz = std::round(places.z[k] - beforeZ[k]);
        float r[4] = {areaRects[a][0] + dx, areaRects[a][1] + dz, areaRects[a][2] + dx, areaRects[a][3] + dz};
        LimitArea(r, bounds, true);
        areas[areaIndices[a]].Set("rectangle", RectangleValue(r[0], r[1], r[2], r[3]));
      }
      for (std::size_t k = 0; k < indices.size(); ++k) {
        SaveEntry& marker = markers[indices[k]];
        float x = std::clamp(places.x[k], 0.0f, maxX);
        float z = std::clamp(places.z[k], 0.0f, maxZ);
        if (const std::string type = MarkerTypeOf(marker); type == "Mass" || type == "Hydrocarbon") {
          x = std::floor(x) + 0.5f; // on a cell's middle, as a drag puts them
          z = std::floor(z) + 0.5f;
        }
        marker.Set("position", Vector3Value(x, ground(x, z), z));
      }
      mDocument.SaveDataEdited(std::move(before));
      mOutsideStale = true;
      return {};
    }
    case PickKind::Unit: {
      if (!(error = tooFew(mUnitSelection.size())).empty()) {
        break;
      }
      std::vector<std::pair<std::string, std::string>> units;
      for (const auto& [army, name] : mUnitSelection) {
        if (const int index = UnitRefIndex(army, name); index >= 0) {
          units.emplace_back(army, name);
          places.x.push_back(mUnitRefs[static_cast<std::size_t>(index)].position.x);
          places.z.push_back(mUnitRefs[static_cast<std::size_t>(index)].position.z);
        }
      }
      // Units keep their headings: only their places are arranged.
      if (!Arrange(op, places, step)) {
        error = tooFew(units.size());
        break;
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      for (std::size_t k = 0; k < units.size(); ++k) {
        const float x = std::clamp(places.x[k], 0.0f, maxX);
        const float z = std::clamp(places.z[k], 0.0f, maxZ);
        const float y = UnitRestHeight(x, z);
        (void)EditArmyUnits(units[k].first, [&](UnitGroup& group) {
          if (SaveUnit* const unit = FindUnit(group, units[k].second); unit != nullptr) {
            unit->position[0] = x;
            unit->position[1] = y;
            unit->position[2] = z;
          }
        });
      }
      mDocument.SaveDataEdited(std::move(before));
      ReloadUnits();
      return {};
    }
    case PickKind::Decal: {
      moho::IDecalManager* const decals = mDocument.Decals();
      if (decals == nullptr || !(error = tooFew(mDecalSelection.size())).empty()) {
        break;
      }
      // By their middles (a decal's position is a corner); each keeps its size and heading.
      std::vector<moho::CWldTerrainDecal*> chosen;
      for (const int index : mDecalSelection) {
        if (moho::CWldTerrainDecal* const decal = FindDecal(*decals, index); decal != nullptr) {
          float cx = 0.0f, cz = 0.0f;
          DecalCentre(FootprintOf(*decal), cx, cz);
          chosen.push_back(decal);
          places.x.push_back(cx);
          places.z.push_back(cz);
        }
      }
      if (!Arrange(op, places, step)) {
        error = tooFew(chosen.size());
        break;
      }
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      for (std::size_t k = 0; k < chosen.size(); ++k) {
        const DecalFootprint own = FootprintOf(*chosen[k]);
        const DecalFootprint placed = DecalAround(
          std::clamp(places.x[k], 0.0f, maxX), std::clamp(places.z[k], 0.0f, maxZ), own.sizeX, own.sizeZ, own.yaw
        );
        chosen[k]->SetPosition(Wm3::Vec3f{placed.x, chosen[k]->mPosition.y, placed.z});
      }
      mDocument.DecalsEdited(std::move(before));
      return {};
    }
    default:
      return "nothing is selected";
    }
    return error.empty() ? std::string(ArrangeTitle(op)) + " can't arrange this selection" : error;
  }

  std::vector<FindObject> EdMapScene::FindObjects() const
  {
    std::vector<FindObject> objects;
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return objects;
    }
    const HeightBrush brush = mTools != nullptr ? mTools->CurrentHeightBrush() : HeightBrush{};
    const auto first = [&](const float x, const float z) {
      return InFirstPart(field->width, field->height, brush.symmetry, brush.turns, x, z);
    };
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!ShownMarkerPosition(markers[i], x, y, z)) {
        continue;
      }
      const bool selected =
        std::find(mMarkerSelection.begin(), mMarkerSelection.end(), markers[i].name) != mMarkerSelection.end();
      objects.push_back({FindKind::Marker, MarkerTypeOf(markers[i]), static_cast<int>(i), selected, first(x, z)});
    }
    for (std::size_t i = 0; i < mUnitRefs.size(); ++i) {
      const UnitRef& ref = mUnitRefs[i];
      const bool selected =
        std::find(
          mUnitSelection.begin(), mUnitSelection.end(), std::pair<std::string, std::string>{ref.army, ref.name}
        ) != mUnitSelection.end();
      objects.push_back(
        {FindKind::Unit, ref.type, static_cast<int>(i), selected, first(ref.position.x, ref.position.z)}
      );
    }
    if (mMap->mProps != nullptr) {
      const auto& entries = mMap->mProps->mEntries;
      for (std::size_t i = 0; i < entries.size(); ++i) {
        const bool selected = std::find(mSelection.begin(), mSelection.end(), static_cast<int>(i)) != mSelection.end();
        objects.push_back(
          {FindKind::Prop,
           entries[i].mBlueprintPath.c_str(),
           static_cast<int>(i),
           selected,
           first(entries[i].mTransform.pos_.x, entries[i].mTransform.pos_.z)}
        );
      }
    }
    if (moho::IDecalManager* const decals = mDocument.Decals(); decals != nullptr) {
      for (int i = 0; i < decals->GetDecalCount(); ++i) {
        const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
        if (decal == nullptr) {
          continue;
        }
        float cx = 0.0f, cz = 0.0f;
        DecalCentre(FootprintOf(*decal), cx, cz);
        const bool selected =
          std::find(mDecalSelection.begin(), mDecalSelection.end(), decal->mIndex) != mDecalSelection.end();
        objects.push_back(
          {FindKind::Decal,
           decal->mNames[0].c_str(),
           decal->mIndex,
           selected,
           first(cx, cz),
           static_cast<int>(decal->mType)}
        );
      }
    }
    return objects;
  }

  std::string EdMapScene::FindApply(
    const FindKind kind,
    const std::string& type,
    const FindScope scope,
    const FindAction action,
    const std::string& replacement
  )
  {
    const std::vector<FindObject> objects = FindObjects();
    const std::vector<int> matches = FindMatches(objects, kind, type, scope);
    if (matches.empty()) {
      return "nothing matches";
    }
    if (action == FindAction::Replace && (replacement.empty() || replacement == type)) {
      return "choose another type to replace it with";
    }
    const std::string label = FindTypeLabel(kind, type);
    const std::size_t count = matches.size();
    // The matches as the selection of their kind (Select matches keeps it; delete and replace work on it).
    ClearAllSelections();
    for (const int match : matches) {
      const FindObject& object = objects[static_cast<std::size_t>(match)];
      switch (kind) {
      case FindKind::Marker:
        mMarkerSelection.push_back(mDocument.SaveData().Markers()[static_cast<std::size_t>(object.ref)].name);
        break;
      case FindKind::Unit:
        mUnitSelection.emplace_back(
          mUnitRefs[static_cast<std::size_t>(object.ref)].army, mUnitRefs[static_cast<std::size_t>(object.ref)].name
        );
        break;
      case FindKind::Prop:
        mSelection.push_back(object.ref);
        break;
      default:
        mDecalSelection.push_back(object.ref);
        break;
      }
    }
    mSelectKind = kind == FindKind::Marker ? PickKind::Marker
      : kind == FindKind::Unit             ? PickKind::Unit
      : kind == FindKind::Prop             ? PickKind::Prop
                                           : PickKind::Decal;
    if (action == FindAction::Select) {
      return std::to_string(count) + " " + label + " selected";
    }
    if (action == FindAction::Delete) {
      // Exactly the matches: follow symmetry would take copies outside the chosen part or selection too.
      mNoFollow = true;
      switch (kind) {
      case FindKind::Marker:
        DeleteSelectedMarkers();
        break;
      case FindKind::Unit:
        DeleteSelectedUnits();
        break;
      case FindKind::Prop:
        DeleteSelection();
        break;
      default:
        DeleteSelectedDecals();
        break;
      }
      mNoFollow = false;
      ClearAllSelections();
      return std::to_string(count) + " " + label + " deleted";
    }
    switch (kind) {
    case FindKind::Prop: {
      PropertyEdit edit;
      edit.what = PropertyEdit::What::Blueprint;
      edit.value = replacement;
      ApplyPropertyEdit(edit);
      break;
    }
    case FindKind::Unit: {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      for (const auto& [army, name] : mUnitSelection) {
        (void)EditArmyUnits(army, [&, name = name](UnitGroup& group) {
          if (SaveUnit* const unit = FindUnit(group, name); unit != nullptr) {
            unit->type = replacement;
          }
        });
      }
      mDocument.SaveDataEdited(std::move(before));
      ReloadUnits();
      break;
    }
    case FindKind::Marker: {
      const MarkerType* const to = FindMarkerType(replacement);
      if (to == nullptr || std::string(to->type) == "Blank Marker" || type == "Blank Marker") {
        return "start positions are kept: they belong to the armies";
      }
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
      for (const int match : matches) {
        SaveEntry& marker = markers[static_cast<std::size_t>(objects[static_cast<std::size_t>(match)].ref)];
        float x = 0.0f, y = 0.0f, z = 0.0f;
        (void)ShownMarkerPosition(marker, x, y, z);
        // The new type's properties, its name, place, turn and path links kept.
        SaveEntry made = NewMarker(*to, marker.name, x, y, z);
        for (const char* const key : {"orientation", "adjacentTo"}) {
          if (const std::string kept = marker.Get(key); !kept.empty()) {
            made.Set(key, kept);
          }
        }
        marker = std::move(made);
      }
      mDocument.SaveDataEdited(std::move(before));
      mOutsideStale = true;
      break;
    }
    default: {
      moho::IDecalManager* const decals = mDocument.Decals();
      if (decals == nullptr) {
        return "no decals";
      }
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      std::vector<DecalState> states = before;
      // The other texture's normal map and type, from a decal that has it.
      const auto model = std::find_if(states.begin(), states.end(), [&](const DecalState& state) {
        return state.names[0] == replacement;
      });
      if (model == states.end()) {
        return "no decal on the map has " + replacement;
      }
      const DecalState example = *model;
      if (
        const auto own = std::find_if(
          states.begin(),
          states.end(),
          [&](const DecalState& state) {
        return state.names[0] == type;
      }
        );
        own != states.end() && own->type != example.type
      ) {
        return "a decal is replaced only by one of its kind (albedo by albedo, normals by normals)";
      }
      for (DecalState& state : states) {
        if (std::find(mDecalSelection.begin(), mDecalSelection.end(), state.index) != mDecalSelection.end()) {
          state.names[0] = example.names[0];
          state.names[1] = example.names[1];
          state.type = example.type;
        }
      }
      RestoreDecals(*decals, states);
      mDocument.DecalsEdited(std::move(before));
      break;
    }
    }
    return std::to_string(count) + " " + label + " now " + FindTypeLabel(kind, replacement);
  }

  void EdMapScene::TestFind(
    const std::string& spec
  )
  {
    // `kind,<part of the type>,map|selection|half,select|delete|<part of the other type>`: the first type of the kind
    // whose name has the part; the result logged, then undone.
    std::vector<std::string> parts;
    for (std::size_t from = 0;;) {
      const std::size_t comma = spec.find(',', from);
      parts.push_back(spec.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
      if (comma == std::string::npos) {
        break;
      }
      from = comma + 1;
    }
    if (parts.size() < 4) {
      gpg::Logf("editor: find test: want kind,type,scope,action");
      return;
    }
    FindKind kind = FindKind::Count;
    for (int k = 0; k < std::to_underlying(FindKind::Count); ++k) {
      if (
        parts[0] == FindKindName(static_cast<FindKind>(k)) ||
        parts[0] == std::string(FindKindName(static_cast<FindKind>(k))) + "s"
      ) {
        kind = static_cast<FindKind>(k);
      }
    }
    const std::vector<FindTypeCount> types = CountFindTypes(FindObjects());
    int group = -1;
    const auto pick = [&](const std::string& part, const std::string& not_) -> std::string {
      for (const FindTypeCount& t : types) {
        if (t.kind == kind && t.type != not_ && t.type.contains(part) && (group < 0 || t.group == group)) {
          group = t.group;
          return t.type;
        }
      }
      return {};
    };
    const std::string type = pick(parts[1], {});
    const FindScope scope = parts[2] == "selection" ? FindScope::Selection
      : parts[2] == "half"                          ? FindScope::FirstPart
                                                    : FindScope::Map;
    const FindAction action = parts[3] == "select" ? FindAction::Select
      : parts[3] == "delete"                       ? FindAction::Delete
                                                   : FindAction::Replace;
    std::string replacement;
    if (action == FindAction::Replace) {
      replacement = kind == FindKind::Marker ? parts[3] : pick(parts[3], type);
    }
    int total = 0;
    for (const FindTypeCount& t : types) {
      total += t.kind == kind ? 1 : 0;
    }
    const auto count = [&](const std::string& of) {
      int n = 0;
      for (const FindObject& object : FindObjects()) {
        n += object.kind == kind && object.type == of ? 1 : 0;
      }
      return n;
    };
    const int before = count(type);
    const int otherBefore = replacement.empty() ? 0 : count(replacement);
    gpg::Logf(
      "editor: find test: %d %s types; %s: %d on the map, %zu in scope %s",
      total,
      FindKindName(kind),
      type.c_str(),
      before,
      FindMatches(FindObjects(), kind, type, scope).size(),
      parts[2].c_str()
    );
    const std::string message = FindApply(kind, type, scope, action, replacement);
    gpg::Logf(
      "editor: find test: %s; %s now %d%s",
      message.c_str(),
      type.c_str(),
      count(type),
      replacement.empty()
        ? ""
        : (", " + replacement + " " + std::to_string(otherBefore) + " -> " + std::to_string(count(replacement))).c_str()
    );
    if (action != FindAction::Select) {
      const bool undone = Undo();
      gpg::Logf(
        "editor: find test: undo %s; %s back to %d", undone ? "took it back" : "had nothing", type.c_str(), count(type)
      );
    }
  }

  void EdMapScene::TestArrange(
    const std::string& spec
  )
  {
    // `kind,op[,step]`: the first five of the kind (props from the map's middle, mass markers) selected and arranged.
    const std::size_t comma = spec.find(',');
    const std::string kind = spec.substr(0, comma);
    std::string rest = comma == std::string::npos ? std::string() : spec.substr(comma + 1);
    float step = 4.0f;
    if (const std::size_t second = rest.find(','); second != std::string::npos) {
      step = std::strtof(rest.c_str() + second + 1, nullptr);
      rest.resize(second);
    }
    const ArrangeOp op = ArrangeFromId(rest);
    if (op == ArrangeOp::Count) {
      gpg::Logf("editor: arrange test: no op %s", rest.c_str());
      return;
    }
    ClearAllSelections();
    std::string listed;
    const auto list = [&](const float x, const float z) {
      char text[48];
      std::snprintf(text, sizeof(text), "%s(%.2f, %.2f)", listed.empty() ? "" : " ", x, z);
      listed += text;
    };
    if (kind == "props" && mMap != nullptr && mMap->mProps != nullptr) {
      mSelectKind = PickKind::Prop;
      for (int i = 0; i < static_cast<int>(mMap->mProps->mEntries.size()) && mSelection.size() < 5; i += 97) {
        mSelection.push_back(i);
      }
    } else if (kind == "markers") {
      mSelectKind = PickKind::Marker;
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        if (MarkerTypeOf(marker) == "Mass" && mMarkerSelection.size() < 5) {
          mMarkerSelection.push_back(marker.name);
        }
      }
    } else {
      gpg::Logf("editor: arrange test: kind %s isn't props or markers", kind.c_str());
      return;
    }
    const std::string message = ArrangeSelection(op, step);
    if (!message.empty()) {
      gpg::Logf("editor: arrange test: %s", message.c_str());
      return;
    }
    if (kind == "props") {
      for (const int index : mSelection) {
        const moho::VTransform& t = mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform;
        list(t.pos_.x, t.pos_.z);
      }
    } else {
      for (const std::string& name : mMarkerSelection) {
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float x = 0.0f, y = 0.0f, z = 0.0f;
          if (marker.name == name && ShownMarkerPosition(marker, x, y, z)) {
            list(x, z);
          }
        }
      }
    }
    gpg::Logf("editor: arrange test: %s %s: %s", kind.c_str(), ArrangeTitle(op), listed.c_str());
    const bool undone = Undo();
    gpg::Logf("editor: arrange test: undo %s", undone ? "took it back" : "had nothing");
  }

  bool EdMapScene::BeginModal(
    const bool rotate
  )
  {
    float gx = 0.0f, gz = 0.0f;
    if (mMap == nullptr || !CursorGround(gx, gz)) {
      return false;
    }
    Modal m;
    m.kind = SelectedKind();
    m.input.rotate = rotate;
    switch (m.kind) {
    case PickKind::Prop:
      if (mMap->mProps == nullptr) {
        return false;
      }
      for (std::size_t s = 0; s < mSelection.size(); ++s) {
        const moho::VTransform& t = mMap->mProps->mEntries[static_cast<std::size_t>(mSelection[s])].mTransform;
        m.sel.push_back(s);
        m.refs.push_back(mSelection[s]);
        m.start.x.push_back(t.pos_.x);
        m.start.z.push_back(t.pos_.z);
        m.start.heading.push_back(2.0f * std::atan2(t.orient_.y, t.orient_.w));
      }
      break;
    case PickKind::Marker:
      for (std::size_t s = 0; s < mMarkerSelection.size(); ++s) {
        for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
          float x = 0.0f, y = 0.0f, z = 0.0f;
          if (marker.name == mMarkerSelection[s] && ShownMarkerPosition(marker, x, y, z)) {
            m.sel.push_back(s);
            m.markers.push_back(marker.name);
            m.start.x.push_back(x);
            m.start.z.push_back(z);
            m.start.heading.push_back(0.0f);
          }
        }
      }
      break;
    case PickKind::Unit:
      for (std::size_t s = 0; s < mUnitSelection.size(); ++s) {
        if (const int index = UnitRefIndex(mUnitSelection[s].first, mUnitSelection[s].second); index >= 0) {
          const UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
          m.sel.push_back(s);
          m.units.push_back(mUnitSelection[s]);
          m.start.x.push_back(ref.position.x);
          m.start.z.push_back(ref.position.z);
          m.start.heading.push_back(ref.orientation[1]); // the save's Orientation y is the heading
        }
      }
      break;
    case PickKind::Decal:
      if (mDocument.Decals() == nullptr) {
        return false;
      }
      for (std::size_t s = 0; s < mDecalSelection.size(); ++s) {
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), mDecalSelection[s]); decal) {
          float cx = 0.0f, cz = 0.0f;
          DecalCentre(FootprintOf(*decal), cx, cz);
          m.sel.push_back(s);
          m.refs.push_back(mDecalSelection[s]);
          m.start.x.push_back(cx);
          m.start.z.push_back(cz);
          m.start.heading.push_back(0.0f);
        }
      }
      break;
    default:
      return false;
    }
    if (m.start.x.empty()) {
      return false;
    }
    for (std::size_t k = 0; k < m.start.x.size(); ++k) {
      m.cx += m.start.x[k];
      m.cz += m.start.z[k];
    }
    m.cx /= static_cast<float>(m.start.x.size());
    m.cz /= static_cast<float>(m.start.z.size());
    m.fromX = gx;
    m.fromZ = gz;
    m.input.startAngle = std::atan2(gz - m.cz, gx - m.cx);
    m.input.nowAngle = m.input.startAngle;
    m.now = m.start;
    // The edit's before, and the mirrored copies that follow it.
    const bool follow = FollowOn();
    switch (m.kind) {
    case PickKind::Prop:
      BeginObjectStroke();
      mPropFollow = follow ? PropPartners() : std::vector<std::vector<int>>{};
      break;
    case PickKind::Marker:
      m.saveBefore = mDocument.SaveDataNow();
      mMarkerFollow = follow ? MarkerPartners() : std::vector<std::vector<std::string>>{};
      break;
    case PickKind::Unit:
      m.saveBefore = mDocument.SaveDataNow();
      mUnitFollow = follow ? UnitPartners() : decltype(mUnitFollow){};
      break;
    default:
      m.decalBefore = mDocument.DecalsNow();
      mDecalFollow = follow ? DecalPartners() : std::vector<std::vector<int>>{};
      break;
    }
    m.on = true;
    mModal = std::move(m);
    UpdateModal();
    gpg::Logf(
      "editor: %s %zu: X or Z locks an axis, a number types it, a click or Enter keeps it, Escape puts it back",
      rotate ? "turning" : "moving",
      mModal.start.x.size()
    );
    return true;
  }

  void EdMapScene::UpdateModal()
  {
    if (!mModal.on) {
      return;
    }
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    float gx = 0.0f, gz = 0.0f;
    if (CursorGround(gx, gz)) {
      mModal.input.cursorDX = gx - mModal.fromX;
      mModal.input.cursorDZ = gz - mModal.fromZ;
      mModal.input.nowAngle = std::atan2(gz - mModal.cz, gx - mModal.cx);
    }
    const ModalDelta delta = ModalDeltaFor(mModal.input);
    ArrangePlaces places = ApplyModalDelta(mModal.start, mModal.cx, mModal.cz, delta);
    const float maxX = static_cast<float>(field->width - 1);
    const float maxZ = static_cast<float>(field->height - 1);
    for (std::size_t k = 0; k < places.x.size(); ++k) {
      places.x[k] = std::clamp(places.x[k], 0.0f, maxX);
      places.z[k] = std::clamp(places.z[k], 0.0f, maxZ);
    }
    const auto ground = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    const bool turned = delta.turn != 0.0f;
    for (std::size_t k = 0; k < places.x.size(); ++k) {
      const float x = places.x[k];
      const float z = places.z[k];
      switch (mModal.kind) {
      case PickKind::Prop: {
        const int index = mModal.refs[k];
        MovePropTo(index, Wm3::Vec3f{x, ground(x, z), z});
        moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
        const float heading = places.heading[k];
        entry.mTransform.orient_ = Wm3::Quatf(std::cos(heading * 0.5f), 0.0f, std::sin(heading * 0.5f), 0.0f);
        if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
          mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
        }
        if (turned) {
          mObjectsChanged = true;
        }
        FollowPropMove(mModal.sel[k], entry.mTransform.pos_);
        break;
      }
      case PickKind::Marker: {
        for (SaveEntry& marker : mDocument.SaveData().Markers()) {
          if (marker.name != mModal.markers[k]) {
            continue;
          }
          float mx = x, mz = z;
          if (const std::string type = MarkerTypeOf(marker); type == "Mass" || type == "Hydrocarbon") {
            mx = std::floor(mx) + 0.5f;
            mz = std::floor(mz) + 0.5f;
          }
          marker.Set("position", Vector3Value(mx, ground(mx, mz), mz));
          places.x[k] = mx;
          places.z[k] = mz;
          FollowMarkerMove(mModal.sel[k], mx, mz);
          break;
        }
        break;
      }
      case PickKind::Unit: {
        const int index = UnitRefIndex(mModal.units[k].first, mModal.units[k].second);
        if (index < 0) {
          break;
        }
        UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
        ref.position = Wm3::Vec3f{x, UnitRestHeight(x, z), z};
        ref.orientation[1] = places.heading[k];
        if (moho::MeshInstance* const instance = mUnits[static_cast<std::size_t>(index)]; instance != nullptr) {
          const moho::VTransform transform = UnitTransform(ref.position, ref.orientation);
          instance->SetStance(transform, transform);
        }
        FollowUnitMove(mModal.sel[k], ref.position);
        break;
      }
      default: {
        // Decals move by their middles and keep their own heading.
        if (moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), mModal.refs[k]); decal != nullptr) {
          const DecalFootprint own = FootprintOf(*decal);
          const DecalFootprint placed = DecalAround(x, z, own.sizeX, own.sizeZ, own.yaw);
          decal->SetPosition(Wm3::Vec3f{placed.x, decal->mPosition.y, placed.z});
          FollowDecalMove(mModal.sel[k], decal->mPosition);
        }
        break;
      }
      }
    }
    mModal.now = std::move(places);
    mModal.moved = mModal.moved || delta.dx != 0.0f || delta.dz != 0.0f || turned;
    if (mTools != nullptr) {
      mTools->SetHudOverride(
        ModalHudText(mModal.input, delta) + (mModal.input.rotate ? "" : "   X / Z lock") +
        "   Enter keeps, Esc puts back"
      );
    }
  }

  void EdMapScene::EndModal(
    const bool keep
  )
  {
    if (!mModal.on) {
      return;
    }
    mModal.on = false;
    if (mTools != nullptr) {
      mTools->SetHudOverride({});
    }
    const bool moved = mModal.moved;
    switch (mModal.kind) {
    case PickKind::Prop:
      // The turned props' records (what gets saved) as Q/E keeps them.
      if (mModal.input.rotate) {
        for (const int index : mModal.refs) {
          moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(index)];
          const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
          entry.mTransform = record.loaded;
          mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
        }
      }
      EndObjectStroke();
      break;
    case PickKind::Marker:
      if (moved) {
        mDocument.SaveDataEdited(std::move(mModal.saveBefore));
        mOutsideStale = true;
      }
      break;
    case PickKind::Unit:
      if (moved) {
        // The units and their followed copies written to the save.
        std::vector<std::pair<std::string, std::string>> touched = mModal.units;
        for (const auto& copies : mUnitFollow) {
          for (const auto& copy : copies) {
            if (!copy.second.empty()) {
              touched.push_back(copy);
            }
          }
        }
        for (const auto& [army, name] : touched) {
          const int index = UnitRefIndex(army, name);
          if (index < 0) {
            continue;
          }
          const UnitRef ref = mUnitRefs[static_cast<std::size_t>(index)];
          (void)EditArmyUnits(army, [&, name = name](UnitGroup& group) {
            if (SaveUnit* const unit = FindUnit(group, name); unit != nullptr) {
              unit->position[0] = ref.position.x;
              unit->position[1] = ref.position.y;
              unit->position[2] = ref.position.z;
              unit->orientation[1] = ref.orientation[1];
            }
          });
        }
        mDocument.SaveDataEdited(std::move(mModal.saveBefore));
        ReloadUnits();
      }
      break;
    default:
      if (moved) {
        mDocument.DecalsEdited(std::move(mModal.decalBefore));
      }
      break;
    }
    mPropFollow.clear();
    mMarkerFollow.clear();
    mUnitFollow.clear();
    mDecalFollow.clear();
    // Escape: the edit was kept as one step; undoing it puts back everything it touched, copies too.
    const bool undone = !keep && moved && Undo();
    gpg::Logf(
      "editor: %s %zu %s",
      mModal.input.rotate ? "turn of" : "move of",
      mModal.start.x.size(),
      keep ? "kept" : (undone ? "put back" : "had nothing to put back")
    );
  }

  void EdMapScene::TestModal(
    const std::string& spec
  )
  {
    // `kind,g|r,<keys>[,cancel]`: five of the kind selected (props from the map's middle, mass markers, units), the
    // cursor kept where it is, the keys typed, then Enter or Escape; the first one's place logged before and after.
    std::vector<std::string> parts;
    for (std::size_t from = 0;;) {
      const std::size_t comma = spec.find(',', from);
      parts.push_back(spec.substr(from, comma == std::string::npos ? std::string::npos : comma - from));
      if (comma == std::string::npos) {
        break;
      }
      from = comma + 1;
    }
    if (parts.size() < 3) {
      gpg::Logf("editor: modal test: want kind,g|r,keys[,cancel]");
      return;
    }
    ClearAllSelections();
    if (parts[0] == "props" && mMap->mProps != nullptr) {
      mSelectKind = PickKind::Prop;
      for (int i = 0; i < static_cast<int>(mMap->mProps->mEntries.size()) && mSelection.size() < 5; i += 97) {
        mSelection.push_back(i);
      }
    } else if (parts[0] == "markers") {
      mSelectKind = PickKind::Marker;
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        if (MarkerTypeOf(marker) == "Mass" && mMarkerSelection.size() < 5) {
          mMarkerSelection.push_back(marker.name);
        }
      }
    } else {
      mSelectKind = PickKind::Unit;
      for (const UnitRef& ref : mUnitRefs) {
        if (mUnitSelection.size() < 5) {
          mUnitSelection.emplace_back(ref.army, ref.name);
        }
      }
    }
    // The cursor over the view's middle (it stays there: the typed number decides).
    mCursor = POINT{400, 300};
    mCursorInView = true;
    if (!BeginModal(parts[1] == "r")) {
      gpg::Logf("editor: modal test: G/R didn't begin (no ground under the cursor?)");
      return;
    }
    const auto place = [this](const std::size_t k) {
      char text[96];
      (void)std::snprintf(
        text,
        sizeof(text),
        "(%.2f, %.2f, heading %.1f)",
        static_cast<double>(mModal.now.x[k]),
        static_cast<double>(mModal.now.z[k]),
        static_cast<double>(mModal.now.heading[k] * 180.0f / kPi)
      );
      return std::string(text);
    };
    const std::string before = place(0);
    for (const char c : parts[2]) {
      if (c == 'x' || c == 'z') {
        mModal.input.axis = static_cast<char>(c - 'a' + 'A');
      } else {
        (void)TypeIntoNumber(mModal.input.typed, c);
      }
    }
    UpdateModal();
    const std::string during = place(0);
    const std::string hud = ModalHudText(mModal.input, ModalDeltaFor(mModal.input));
    if (parts.size() > 3 && parts[3] == "hold") {
      // Left running, for a picture of the ghosts, the axis and the HUD.
      gpg::Logf(
        "editor: modal test: %s held: HUD \"%s\"; first %s -> %s",
        parts[0].c_str(),
        hud.c_str(),
        before.c_str(),
        during.c_str()
      );
      return;
    }
    const bool cancel = parts.size() > 3 && parts[3] == "cancel";
    // Where the first one is after it ends, read back from the map.
    const std::size_t first = 0;
    const PickKind kind = mModal.kind;
    const int ref = mModal.refs.empty() ? -1 : mModal.refs[first];
    const std::string marker = mModal.markers.empty() ? std::string() : mModal.markers[first];
    const auto unit = mModal.units.empty() ? std::pair<std::string, std::string>{} : mModal.units[first];
    EndModal(!cancel);
    float x = 0.0f, z = 0.0f, heading = 0.0f;
    if (kind == PickKind::Prop) {
      const moho::VTransform& t = mMap->mProps->mEntries[static_cast<std::size_t>(ref)].mTransform;
      x = t.pos_.x;
      z = t.pos_.z;
      heading = 2.0f * std::atan2(t.orient_.y, t.orient_.w);
    } else if (kind == PickKind::Marker) {
      for (const SaveEntry& m : mDocument.SaveData().Markers()) {
        float y = 0.0f;
        if (m.name == marker) {
          (void)ShownMarkerPosition(m, x, y, z);
        }
      }
    } else if (const int index = UnitRefIndex(unit.first, unit.second); index >= 0) {
      x = mUnitRefs[static_cast<std::size_t>(index)].position.x;
      z = mUnitRefs[static_cast<std::size_t>(index)].position.z;
      heading = mUnitRefs[static_cast<std::size_t>(index)].orientation[1];
    }
    gpg::Logf(
      "editor: modal test: %s %s keys \"%s\": HUD \"%s\"; first %s -> %s; after %s: (%.2f, %.2f, heading %.1f)",
      parts[0].c_str(),
      parts[1].c_str(),
      parts[2].c_str(),
      hud.c_str(),
      before.c_str(),
      during.c_str(),
      cancel ? "Escape" : "Enter",
      static_cast<double>(x),
      static_cast<double>(z),
      static_cast<double>(heading * 180.0f / kPi)
    );
  }

  bool EdMapScene::FollowDrag()
  {
    const bool on = FollowOn() && !mDragIsCopy;
    mDragIsCopy = false;
    return on;
  }

  std::vector<std::vector<std::pair<std::string, std::string>>> EdMapScene::UnitPartners() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return {};
    }
    std::vector<FollowItem> items;
    items.reserve(mUnitRefs.size());
    for (const UnitRef& ref : mUnitRefs) {
      items.push_back({ref.position.x, ref.position.z, ref.type});
    }
    std::vector<int> selected;
    for (const auto& [army, name] : mUnitSelection) {
      selected.push_back(UnitRefIndex(army, name));
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const std::vector<std::vector<int>> found =
      FindSymmetryPartners(items, selected, field->width, field->height, brush.symmetry, brush.turns, 1.5f);
    std::vector<std::vector<std::pair<std::string, std::string>>> keys(found.size());
    for (std::size_t s = 0; s < found.size(); ++s) {
      for (const int index : found[s]) {
        if (index >= 0) {
          const UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
          keys[s].emplace_back(ref.army, ref.name);
        } else {
          keys[s].emplace_back();
        }
      }
    }
    return keys;
  }

  std::vector<std::vector<int>> EdMapScene::DecalPartners() const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    moho::IDecalManager* const decals = mDocument.Decals();
    if (field == nullptr || decals == nullptr) {
      return {};
    }
    // Matched at their middles: a decal's position is a corner, which a mirror moves to another corner.
    std::vector<FollowItem> items;
    std::vector<int> indices;
    for (int i = 0; i < decals->GetDecalCount(); ++i) {
      const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
      if (decal == nullptr) {
        continue;
      }
      float cx = 0.0f, cz = 0.0f;
      DecalCentre(FootprintOf(*decal), cx, cz);
      std::string key = decal->mNames[0].c_str();
      for (char& c : key) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      items.push_back({cx, cz, std::move(key)});
      indices.push_back(decal->mIndex);
    }
    std::vector<int> selected;
    for (const int index : mDecalSelection) {
      const auto at = std::find(indices.begin(), indices.end(), index);
      selected.push_back(at != indices.end() ? static_cast<int>(at - indices.begin()) : -1);
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    std::vector<std::vector<int>> found =
      FindSymmetryPartners(items, selected, field->width, field->height, brush.symmetry, brush.turns, 1.5f);
    for (std::vector<int>& copies : found) {
      for (int& index : copies) {
        index = index >= 0 ? indices[static_cast<std::size_t>(index)] : -1;
      }
    }
    return found;
  }

  void EdMapScene::FollowUnitMove(
    const std::size_t selected,
    const Wm3::Vec3f& position
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (selected >= mUnitFollow.size() || field == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, position.x, position.z, brush.symmetry, brush.turns, cx, cz);
    for (int c = 1; c < copies && static_cast<std::size_t>(c - 1) < mUnitFollow[selected].size(); ++c) {
      const auto& [army, name] = mUnitFollow[selected][static_cast<std::size_t>(c - 1)];
      const int index = name.empty() ? -1 : UnitRefIndex(army, name);
      if (index < 0) {
        continue;
      }
      UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
      ref.position = Wm3::Vec3f{
        cx[c],
        mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(cx[c])), static_cast<std::int32_t>(std::lround(cz[c]))
        ),
        cz[c]
      };
      if (moho::MeshInstance* const instance = mUnits[static_cast<std::size_t>(index)]; instance != nullptr) {
        const moho::VTransform transform = UnitTransform(ref.position, ref.orientation);
        instance->SetStance(transform, transform);
      }
    }
  }

  void EdMapScene::FollowDecalMove(
    const std::size_t selected,
    const Wm3::Vec3f& corner
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    moho::IDecalManager* const decals = mDocument.Decals();
    if (
      selected >= mDecalFollow.size() || field == nullptr || decals == nullptr || selected >= mDecalSelection.size()
    ) {
      return;
    }
    const moho::CWldTerrainDecal* const leader = FindDecal(*decals, mDecalSelection[selected]);
    if (leader == nullptr) {
      return;
    }
    DecalFootprint footprint = FootprintOf(*leader);
    footprint.x = corner.x;
    footprint.z = corner.z;
    float mx = 0.0f, mz = 0.0f;
    DecalCentre(footprint, mx, mz);
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, mx, mz, brush.symmetry, brush.turns, cx, cz);
    for (int c = 1; c < copies && static_cast<std::size_t>(c - 1) < mDecalFollow[selected].size(); ++c) {
      const int partner = mDecalFollow[selected][static_cast<std::size_t>(c - 1)];
      moho::CWldTerrainDecal* const decal = partner >= 0 ? FindDecal(*decals, partner) : nullptr;
      if (decal == nullptr) {
        continue;
      }
      // The copy keeps its own size and heading; its middle goes to the image of the leader's.
      const DecalFootprint own = FootprintOf(*decal);
      const DecalFootprint placed = DecalAround(cx[c], cz[c], own.sizeX, own.sizeZ, own.yaw);
      decal->SetPosition(Wm3::Vec3f{placed.x, decal->mPosition.y, placed.z});
    }
  }

  void EdMapScene::TestFollow(
    const std::string& kind
  )
  {
    if (!FollowOn()) {
      gpg::Logf("editor: follow test: no symmetry chosen (or Follow symmetry off)");
      return;
    }
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    if (kind == "props" && mMap->mProps != nullptr) {
      const std::size_t before = mMap->mProps->mEntries.size();
      // The first prop that has a mirrored copy.
      for (int index = 0; index < static_cast<int>(before); ++index) {
        mSelection = {index};
        const std::vector<std::vector<int>> partners = PropPartners();
        if (partners.empty() || partners[0].empty() || partners[0][0] < 0) {
          continue;
        }
        const int partner = partners[0][0];
        const Wm3::Vec3f from = mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_;
        const Wm3::Vec3f to{from.x + 6.0f, from.y, from.z + 4.0f};
        BeginObjectStroke();
        mPropFollow = partners;
        MovePropTo(index, to);
        FollowPropMove(0, to);
        EndObjectStroke();
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        (void)HeightBrushCentres(field->width, field->height, to.x, to.z, brush.symmetry, brush.turns, cx, cz);
        const Wm3::Vec3f moved = mMap->mProps->mEntries[static_cast<std::size_t>(partner)].mTransform.pos_;
        gpg::Logf(
          "editor: follow test: prop %d moved by (6, 4); its copy %d is at %.2f, %.2f (the image: %.2f, %.2f)",
          index,
          partner,
          static_cast<double>(moved.x),
          static_cast<double>(moved.z),
          static_cast<double>(cx[1]),
          static_cast<double>(cz[1])
        );
        DeleteSelection();
        gpg::Logf(
          "editor: follow test: deleted with its copy: %zu props -> %zu", before, mMap->mProps->mEntries.size()
        );
        return;
      }
      gpg::Logf("editor: follow test: no prop with a mirrored copy");
      return;
    }
    if (kind == "markers") {
      std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
      const std::size_t before = markers.size();
      for (const SaveEntry& marker : markers) {
        if (MarkerTypeOf(marker) != "Mass") {
          continue;
        }
        mMarkerSelection = {marker.name};
        const std::vector<std::vector<std::string>> partners = MarkerPartners();
        if (partners.empty() || partners[0].empty() || partners[0][0].empty()) {
          continue;
        }
        const std::string leader = marker.name;
        const std::string partner = partners[0][0];
        const std::vector<double> at = ValueNumbers(marker.Get("position"));
        const float x = static_cast<float>(at[0]) + 6.0f;
        const float z = static_cast<float>(at[2]) + 4.0f;
        mMarkerFollow = partners;
        for (SaveEntry& m : markers) {
          if (m.name == leader) {
            m.Set("position", Vector3Value(x, static_cast<float>(at[1]), z));
          }
        }
        FollowMarkerMove(0, x, z);
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        (void)HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
        for (const SaveEntry& m : markers) {
          if (m.name == partner) {
            const std::vector<double> p = ValueNumbers(m.Get("position"));
            gpg::Logf(
              "editor: follow test: %s moved by (6, 4); its copy %s is at %.2f, %.2f (the image: %.2f, %.2f)",
              leader.c_str(),
              partner.c_str(),
              p[0],
              p[2],
              static_cast<double>(cx[1]),
              static_cast<double>(cz[1])
            );
          }
        }
        DeleteSelectedMarkers();
        gpg::Logf(
          "editor: follow test: deleted with its copy: %zu markers -> %zu",
          before,
          mDocument.SaveData().Markers().size()
        );
        return;
      }
      gpg::Logf("editor: follow test: no mass marker with a mirrored copy");
      return;
    }
    if (kind == "units") {
      // A map whose units have no mirrored copies (SCMP_009's wrecks): the first unit gets one, in its own army, at
      // its image, the way a symmetric map would have it.
      bool paired = false;
      for (const UnitRef& unit : mUnitRefs) {
        mUnitSelection = {{unit.army, unit.name}};
        const auto partners = UnitPartners();
        paired = paired || (!partners.empty() && !partners[0].empty() && !partners[0][0].second.empty());
      }
      if (!paired && !mUnitRefs.empty()) {
        const UnitRef first = mUnitRefs.front();
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        if (
          HeightBrushCentres(
            field->width, field->height, first.position.x, first.position.z, brush.symmetry, brush.turns, cx, cz
          ) > 1
        ) {
          (void)EditArmyUnits(first.army, [&](UnitGroup& group) {
            if (const SaveUnit* const unit = FindUnit(group, first.name); unit != nullptr) {
              SaveUnit copy = *unit;
              copy.name = "UNIT_99001";
              copy.position[0] = cx[1];
              copy.position[2] = cz[1];
              AddUnit(group, copy);
            }
          });
          ReloadUnits();
          gpg::Logf(
            "editor: follow test: %s/%s given a copy at its image %.2f, %.2f",
            first.army.c_str(),
            first.name.c_str(),
            static_cast<double>(cx[1]),
            static_cast<double>(cz[1])
          );
        }
      }
      const std::size_t before = mUnitRefs.size();
      for (const UnitRef& unit : mUnitRefs) {
        mUnitSelection = {{unit.army, unit.name}};
        const auto partners = UnitPartners();
        if (partners.empty() || partners[0].empty() || partners[0][0].second.empty()) {
          continue;
        }
        const std::pair<std::string, std::string> leader{unit.army, unit.name};
        const std::pair<std::string, std::string> partner = partners[0][0];
        const int index = UnitRefIndex(leader.first, leader.second);
        const Wm3::Vec3f to{unit.position.x + 6.0f, unit.position.y, unit.position.z + 4.0f};
        mUnitFollow = partners;
        mUnitRefs[static_cast<std::size_t>(index)].position = to;
        FollowUnitMove(0, to);
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        (void)HeightBrushCentres(field->width, field->height, to.x, to.z, brush.symmetry, brush.turns, cx, cz);
        const Wm3::Vec3f moved =
          mUnitRefs[static_cast<std::size_t>(UnitRefIndex(partner.first, partner.second))].position;
        gpg::Logf(
          "editor: follow test: unit %s/%s moved by (6, 4); its copy %s/%s is at %.2f, %.2f (the image: %.2f, %.2f)",
          leader.first.c_str(),
          leader.second.c_str(),
          partner.first.c_str(),
          partner.second.c_str(),
          static_cast<double>(moved.x),
          static_cast<double>(moved.z),
          static_cast<double>(cx[1]),
          static_cast<double>(cz[1])
        );
        DeleteSelectedUnits();
        gpg::Logf("editor: follow test: deleted with its copy: %zu units -> %zu", before, mUnitRefs.size());
        return;
      }
      gpg::Logf("editor: follow test: no unit with a mirrored copy (%zu units)", before);
      return;
    }
    if (kind == "decals") {
      moho::IDecalManager* const decals = mDocument.Decals();
      if (decals == nullptr) {
        return;
      }
      const int before = decals->GetDecalCount();
      for (int i = 0; i < before; ++i) {
        const moho::CWldTerrainDecal* const decal = decals->GetDecal(i);
        if (decal == nullptr) {
          continue;
        }
        mDecalSelection = {decal->mIndex};
        const std::vector<std::vector<int>> partners = DecalPartners();
        if (partners.empty() || partners[0].empty() || partners[0][0] < 0) {
          continue;
        }
        const int partner = partners[0][0];
        mDecalFollow = partners;
        moho::CWldTerrainDecal* const leader = FindDecal(*decals, mDecalSelection[0]);
        leader->SetPosition(Wm3::Vec3f{leader->mPosition.x + 6.0f, leader->mPosition.y, leader->mPosition.z + 4.0f});
        FollowDecalMove(0, leader->mPosition);
        float lx = 0.0f, lz = 0.0f, px = 0.0f, pz = 0.0f;
        DecalCentre(FootprintOf(*leader), lx, lz);
        DecalCentre(FootprintOf(*FindDecal(*decals, partner)), px, pz);
        float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
        (void)HeightBrushCentres(field->width, field->height, lx, lz, brush.symmetry, brush.turns, cx, cz);
        gpg::Logf(
          "editor: follow test: decal %d moved by (6, 4); its copy %d's middle is at %.2f, %.2f (the image: %.2f, "
          "%.2f)",
          mDecalSelection[0],
          partner,
          static_cast<double>(px),
          static_cast<double>(pz),
          static_cast<double>(cx[1]),
          static_cast<double>(cz[1])
        );
        DeleteSelectedDecals();
        gpg::Logf("editor: follow test: deleted with its copy: %d decals -> %d", before, decals->GetDecalCount());
        return;
      }
      gpg::Logf("editor: follow test: no decal with a mirrored copy (%d decals)", before);
    }
  }

  void EdMapScene::DeleteSelection()
  {
    if (mSelection.empty() || mMap == nullptr) {
      return;
    }
    BeginObjectStroke();
    std::vector<int> doomed = mSelection;
    // Follow symmetry: the mirrored copies go too.
    if (FollowOn()) {
      for (const std::vector<int>& copies : PropPartners()) {
        for (const int partner : copies) {
          if (partner >= 0) {
            doomed.push_back(partner);
          }
        }
      }
    }
    std::sort(doomed.begin(), doomed.end(), std::greater<>());
    doomed.erase(std::unique(doomed.begin(), doomed.end()), doomed.end());
    for (const int index : doomed) {
      if (static_cast<std::size_t>(index) < mProps.size()) {
        delete mProps[static_cast<std::size_t>(index)];
        mProps.erase(mProps.begin() + index);
      }
      mDocument.DeletePropAt(static_cast<std::size_t>(index));
    }
    mSelection.clear();
    mObjectsChanged = true;
    mDocument.SetModified(true);
    gpg::Logf("editor: %zu props deleted", doomed.size());
    EndObjectStroke();
  }

  void EdMapScene::PlaceProps(
    const float x,
    const float z,
    const float fixedYaw
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr) {
      return;
    }
    const auto roll = [this] {
      mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
      return static_cast<float>(mScatterSeed >> 8) / 16777216.0f;
    };
    // Scatter with a paint list: a prop of it by chance, its turn and scale between its own; else the chosen prop.
    std::string blueprint = mTools->PropBlueprint();
    float scale = 1.0f;
    float yaw = 0.0f;
    const std::vector<PropPaintEntry>& list = mFillList != nullptr ? *mFillList : mTools->PaintList();
    if (fixedYaw <= -100.0f && (mFilling || mTools->CurrentPropMode() == EdTools::PropMode::Scatter) && !list.empty()) {
      const int pick = PickPaintEntry(list, roll());
      if (pick < 0) {
        return;
      }
      const PropPaintEntry& entry = list[static_cast<std::size_t>(pick)];
      // A blueprint the game hasn't got (a set from another mod) is skipped, not placed as a missing prop.
      if (mTools->HasPropBlueprints() && mTools->PropBlueprintNamed(entry.blueprint).empty()) {
        return;
      }
      blueprint = entry.blueprint;
      const float degrees =
        static_cast<float>(entry.rotationMin) + roll() * static_cast<float>(entry.rotationMax - entry.rotationMin);
      yaw = degrees * (kPi / 180.0f);
      scale = entry.scaleMin + roll() * (entry.scaleMax - entry.scaleMin);
      ++mPaintCounts[blueprint];
    } else {
      // The turn: random or none.
      const float random = roll() * 6.2831853f;
      yaw = fixedYaw > -100.0f ? fixedYaw : mTools->RandomPropTurn() ? random : 0.0f;
    }
    if (blueprint.empty()) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    // Each copy's heading is the cursor's heading carried through the symmetry (the copies of a point one unit ahead).
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
      aheadZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    // The model's front (+Z) under the turn is (sin, cos) on the ground.
    (void)HeightBrushCentres(
      field->width, field->height, x + std::sin(yaw), z + std::cos(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
    );
    for (int c = 0; c < copies; ++c) {
      if (
        centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
        centreZ[c] > static_cast<float>(field->height - 1)
      ) {
        continue;
      }
      const float heading = std::atan2(aheadX[c] - centreX[c], aheadZ[c] - centreZ[c]);
      centreX[c] = SnapToGrid(centreX[c]);
      centreZ[c] = SnapToGrid(centreZ[c]);
      moho::CWldPropEntry entry;
      entry.mBlueprintPath.assign(blueprint.c_str());
      // On the ground the view shows (a mesh terrain map's mesh while it is shown).
      entry.mTransform.pos_ = Wm3::Vec3f{centreX[c], PlacementHeight(centreX[c], centreZ[c]), centreZ[c]};
      entry.mTransform.orient_ = Wm3::Quatf(std::cos(heading * 0.5f), 0.0f, std::sin(heading * 0.5f), 0.0f);
      // The prop as the file will give it back (its record is what gets saved).
      PropRecord record = PropRecordFor(blueprint, entry.mTransform);
      // The file's scale (the game's loader reads and drops it, CWldProps::Load 0x008918E0).
      record.values[12] = record.values[13] = record.values[14] = scale;
      entry.mTransform = record.loaded;
      mDocument.AddProp(entry, record);
      mProps.push_back(MakePropInstance(entry));
      // Only a prop really placed makes the stroke an undo step (copies off the map are skipped).
      mObjectsChanged = true;
      mDocument.SetModified(true);
    }
  }

  int EdMapScene::ScatterFromGraph(
    const TerrainBuildWrites::Scatter& scatter,
    std::string& note
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mMap->mProps == nullptr) {
      return 0;
    }
    // The node's blueprints with their weights, turned freely, scaled between its bounds; else the Props tool's.
    std::vector<PropPaintEntry> list;
    std::string unknown;
    for (const auto& [blueprint, weight] : scatter.entries) {
      // A blueprint the game hasn't got is named (PlaceProps would skip it without a word).
      if (mTools->HasPropBlueprints() && mTools->PropBlueprintNamed(blueprint).empty()) {
        unknown += (unknown.empty() ? "" : ", ") + blueprint;
        continue;
      }
      PropPaintEntry entry;
      entry.blueprint = blueprint;
      entry.chance = weight;
      entry.scaleMin = scatter.scaleMin;
      entry.scaleMax = scatter.scaleMax;
      list.push_back(std::move(entry));
    }
    if (!unknown.empty()) {
      note = "Scatter: the game has no " + unknown;
      if (list.empty()) {
        return 0;
      }
    }
    if (list.empty() && mTools->PaintList().empty() && mTools->PropBlueprint().empty()) {
      note = "Scatter: no blueprints in the node and no prop in the Props tool";
      return 0;
    }
    // The playable area (else the whole map), the margin in from its edge.
    float x0 = scatter.margin;
    float z0 = scatter.margin;
    float x1 = static_cast<float>(field->width - 1) - scatter.margin;
    float z1 = static_cast<float>(field->height - 1) - scatter.margin;
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea(); area.has_value()) {
      x0 = std::max(x0, static_cast<float>(area->x0) + scatter.margin);
      z0 = std::max(z0, static_cast<float>(area->z0) + scatter.margin);
      x1 = std::min(x1, static_cast<float>(area->x1) - scatter.margin);
      z1 = std::min(z1, static_cast<float>(area->z1) - scatter.margin);
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const WaterState water = mDocument.WaterNow();
    const auto height = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    // The density mask's chance, by a hash of the place and the seed (the same build places the same props).
    const auto chance = [&](const float x, const float z) {
      std::uint32_t h = scatter.seed * 2654435761u ^ static_cast<std::uint32_t>(std::lround(x * 16.0f)) * 40503u ^
        static_cast<std::uint32_t>(std::lround(z * 16.0f)) * 2246822519u;
      h ^= h >> 15;
      h *= 2654435761u;
      h ^= h >> 13;
      return static_cast<float>(h & 0xFFFFFFu) / 16777216.0f;
    };
    const auto accept = [&](const float x, const float z) {
      if (!InFirstPart(field->width, field->height, brush.symmetry, brush.turns, x, z)) {
        return false;
      }
      if (!scatter.underWater && water.enabled && height(x, z) <= water.elevation) {
        return false;
      }
      if (
        const float slope =
          SlopeDegrees(height(x - 1.0f, z), height(x + 1.0f, z), height(x, z - 1.0f), height(x, z + 1.0f));
        slope > scatter.slopeMax || slope < scatter.slopeMin
      ) {
        return false;
      }
      const float density =
        scatter.density.w > 1 ? std::clamp(field::SampleWorld(scatter.density, x, z), 0.0f, 1.0f) : 1.0f;
      if (chance(x, z) >= density * scatter.fill) {
        return false;
      }
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      for (int c = 1; c < copies; ++c) {
        if (std::hypot(cx[c] - x, cz[c] - z) < scatter.minDist) {
          return false;
        }
      }
      return true;
    };
    ScatterOptions options;
    options.x0 = x0;
    options.z0 = z0;
    options.x1 = x1;
    options.z1 = z1;
    // A candidate in every spacing-sized cell; the mask, the ground and the count decide.
    options.density = 10000.0f / std::max(1.0f, scatter.minDist * scatter.minDist);
    options.spacing = scatter.minDist;
    options.seed = scatter.seed;
    options.limit = scatter.count;
    const std::vector<std::pair<float, float>> points = ScatterPoints(options, accept);
    const std::size_t before = mMap->mProps->mEntries.size();
    mFilling = true;
    mFillList = list.empty() ? nullptr : &list;
    mScatterSeed = scatter.seed;
    for (const auto& [x, z] : points) {
      PlaceProps(x, z);
    }
    mFillList = nullptr;
    mFilling = false;
    return static_cast<int>(mMap->mProps->mEntries.size() - before);
  }

  int EdMapScene::ScatterDecalsFromGraph(
    const TerrainBuildWrites::Scatter& scatter,
    std::string& note
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    moho::IDecalManager* const decals = mDocument.Decals();
    if (field == nullptr || mTools == nullptr || decals == nullptr) {
      return 0;
    }
    // The node's textures with their weights, else the Decals tool's texture.
    std::vector<std::pair<std::string, int>> list = scatter.entries;
    if (list.empty()) {
      if (mTools->DecalTexturePath().empty()) {
        note = "Decal scatter: no textures in the node and none picked in the Decals tool";
        return 0;
      }
      list.emplace_back(mTools->DecalTexturePath(), 100);
    }
    int total = 0;
    for (const auto& entry : list) {
      total += std::max(1, entry.second);
    }
    float x0 = scatter.margin;
    float z0 = scatter.margin;
    float x1 = static_cast<float>(field->width - 1) - scatter.margin;
    float z1 = static_cast<float>(field->height - 1) - scatter.margin;
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea(); area.has_value()) {
      x0 = std::max(x0, static_cast<float>(area->x0) + scatter.margin);
      z0 = std::max(z0, static_cast<float>(area->z0) + scatter.margin);
      x1 = std::min(x1, static_cast<float>(area->x1) - scatter.margin);
      z1 = std::min(z1, static_cast<float>(area->z1) - scatter.margin);
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const WaterState water = mDocument.WaterNow();
    const auto height = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    // A number 0..1 by a hash of the place, the seed and a salt (the same build places the same decals).
    const auto hash01 = [&](const float x, const float z, const std::uint32_t salt) {
      std::uint32_t h = (scatter.seed + salt * 977u) * 2654435761u ^
        static_cast<std::uint32_t>(std::lround(x * 16.0f)) * 40503u ^
        static_cast<std::uint32_t>(std::lround(z * 16.0f)) * 2246822519u;
      h ^= h >> 15;
      h *= 2654435761u;
      h ^= h >> 13;
      return static_cast<float>(h & 0xFFFFFFu) / 16777216.0f;
    };
    const auto accept = [&](const float x, const float z) {
      if (!InFirstPart(field->width, field->height, brush.symmetry, brush.turns, x, z)) {
        return false;
      }
      if (!scatter.underWater && water.enabled && height(x, z) <= water.elevation) {
        return false;
      }
      if (
        const float slope =
          SlopeDegrees(height(x - 1.0f, z), height(x + 1.0f, z), height(x, z - 1.0f), height(x, z + 1.0f));
        slope > scatter.slopeMax || slope < scatter.slopeMin
      ) {
        return false;
      }
      const float density =
        scatter.density.w > 1 ? std::clamp(field::SampleWorld(scatter.density, x, z), 0.0f, 1.0f) : 1.0f;
      if (hash01(x, z, 0) >= density * scatter.fill) {
        return false;
      }
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      for (int c = 1; c < copies; ++c) {
        if (std::hypot(cx[c] - x, cz[c] - z) < scatter.minDist) {
          return false;
        }
      }
      return true;
    };
    ScatterOptions options;
    options.x0 = x0;
    options.z0 = z0;
    options.x1 = x1;
    options.z1 = z1;
    options.density = 10000.0f / std::max(1.0f, scatter.minDist * scatter.minDist);
    options.spacing = scatter.minDist;
    options.seed = scatter.seed;
    options.limit = scatter.count;
    const std::vector<std::pair<float, float>> points = ScatterPoints(options, accept);
    const std::string toolTexture = mTools->DecalTexturePath();
    const std::string toolPair = mTools->DecalPairPath();
    int placed = 0;
    for (const auto& [x, z] : points) {
      // The texture by the weights, a free turn, a scale between the node's bounds.
      int pick = static_cast<int>(hash01(x, z, 1) * static_cast<float>(total));
      const std::pair<std::string, int>* chosen = &list.front();
      for (const auto& entry : list) {
        pick -= std::max(1, entry.second);
        if (pick < 0) {
          chosen = &entry;
          break;
        }
      }
      const float yaw = hash01(x, z, 2) * 2.0f * kPi;
      const float scale = scatter.scaleMin + (scatter.scaleMax - scatter.scaleMin) * hash01(x, z, 3);
      float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
        aheadZ[kMaxSymmetryCopies];
      const int copies =
        HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
      (void)HeightBrushCentres(
        field->width, field->height, x + std::cos(yaw), z + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
      );
      for (int c = 0; c < copies; ++c) {
        if (
          centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
          centreZ[c] > static_cast<float>(field->height - 1)
        ) {
          continue;
        }
        const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
        const DecalFootprint footprint = DecalAround(
          centreX[c],
          centreZ[c],
          (scatter.decalSize > 0.0f ? scatter.decalSize : mTools->DecalSizeX()) * scale,
          (scatter.decalSize > 0.0f ? scatter.decalSize : mTools->DecalSizeZ()) * scale,
          heading
        );
        DecalState state;
        state.type = DecalTypeForTexture(chosen->first);
        state.names[0] = chosen->first;
        state.names[1] = chosen->first == toolTexture ? toolPair : std::string();
        state.scale[0] = footprint.sizeX;
        state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
        state.scale[2] = footprint.sizeZ;
        state.position[0] = footprint.x;
        state.position[1] = height(centreX[c], centreZ[c]);
        state.position[2] = footprint.z;
        state.orientation[1] = heading;
        state.cutoff = mTools->DecalCutoff();
        if (AddDecal(*decals, state) != nullptr) {
          ++placed;
        }
      }
    }
    gpg::Logf("editor: generate: %d decals scattered (%zu textures)", placed, list.size());
    return placed;
  }

  std::string EdMapScene::ScatterOverMap(
    const EdTools::FillOptions& fill
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mMap->mProps == nullptr) {
      return "no map is open";
    }
    if (!fill.decals && mTools->PaintList().empty() && mTools->PropBlueprint().empty()) {
      return "choose a prop or fill the paint list first";
    }
    if (fill.decals && mTools->DecalTexturePath().empty()) {
      return "pick a decal texture in the Decals tool first";
    }
    // The playable area (else the whole map), the margin in from its edge.
    const float m = std::max(1.0f, fill.margin);
    float x0 = m, z0 = m;
    float x1 = static_cast<float>(field->width - 1) - m, z1 = static_cast<float>(field->height - 1) - m;
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea(); area.has_value()) {
      x0 = std::max(x0, static_cast<float>(area->x0) + m);
      z0 = std::max(z0, static_cast<float>(area->z0) + m);
      x1 = std::min(x1, static_cast<float>(area->x1) - m);
      z1 = std::min(z1, static_cast<float>(area->z1) - m);
    }
    // The mask generator's rules as the density (FAF Studio's "density from mask rules").
    field::Grid rules;
    if (fill.maskRules && (!mMaskRulesSource || !mMaskRulesSource(rules))) {
      return "the mask generator has no rules to read";
    }
    // Room round the props already there: a grid of buckets of their places.
    const float keep = fill.keepAway;
    std::map<std::pair<int, int>, std::vector<std::pair<float, float>>> existing;
    if (keep > 0.0f) {
      for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
        existing[{static_cast<int>(entry.mTransform.pos_.x / keep), static_cast<int>(entry.mTransform.pos_.z / keep)}]
          .emplace_back(entry.mTransform.pos_.x, entry.mTransform.pos_.z);
      }
    }
    int high = 0, nearby = 0, sparse = 0;
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const WaterState water = mDocument.WaterNow();
    const auto height = [this](const float x, const float z) {
      return mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
      );
    };
    int wet = 0, steep = 0, crowded = 0;
    const auto accept = [&](const float x, const float z) {
      // Drawn once, in the first part; the copies come from PlaceProps.
      if (!InFirstPart(field->width, field->height, brush.symmetry, brush.turns, x, z)) {
        return false;
      }
      if (fill.dry && water.enabled && height(x, z) <= water.elevation) {
        ++wet;
        return false;
      }
      if (
        const float slope =
          SlopeDegrees(height(x - 1.0f, z), height(x + 1.0f, z), height(x, z - 1.0f), height(x, z + 1.0f));
        slope > fill.maxSlope || slope < fill.minSlope
      ) {
        ++steep;
        return false;
      }
      if (fill.heightWindow && (height(x, z) < fill.heightLow || height(x, z) > fill.heightHigh)) {
        ++high;
        return false;
      }
      if (rules.w > 1) {
        // The mask's strength as the chance, by a hash of the place (the same seed, the same props).
        std::uint32_t h = static_cast<std::uint32_t>(std::lround(x * 16.0f)) * 40503u ^
          static_cast<std::uint32_t>(std::lround(z * 16.0f)) * 2246822519u ^ mScatterSeed;
        h ^= h >> 15;
        h *= 2654435761u;
        h ^= h >> 13;
        if (
          static_cast<float>(h & 0xFFFFFFu) / 16777216.0f >= std::clamp(field::SampleWorld(rules, x, z), 0.0f, 1.0f)
        ) {
          ++sparse;
          return false;
        }
      }
      if (keep > 0.0f) {
        const int bx = static_cast<int>(x / keep);
        const int bz = static_cast<int>(z / keep);
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            const auto found = existing.find({bx + dx, bz + dz});
            if (found == existing.end()) {
              continue;
            }
            for (const auto& [px, pz] : found->second) {
              if (std::hypot(px - x, pz - z) < keep) {
                ++nearby;
                return false;
              }
            }
          }
        }
      }
      // A point whose own copy would stand nearer than the spacing (by a mirror line) is left out.
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      for (int c = 1; c < copies; ++c) {
        if (std::hypot(cx[c] - x, cz[c] - z) < fill.spacing) {
          ++crowded;
          return false;
        }
      }
      return true;
    };
    ScatterOptions options;
    options.x0 = x0;
    options.z0 = z0;
    options.x1 = x1;
    options.z1 = z1;
    options.density = fill.density;
    options.spacing = fill.spacing;
    mScatterSeed = fill.seed > 0 ? static_cast<std::uint32_t>(fill.seed) : mScatterSeed * 1664525U + 1013904223U;
    options.seed = mScatterSeed;
    const std::vector<std::pair<float, float>> points = ScatterPoints(options, accept);
    std::size_t placed = 0;
    if (fill.countOnly) {
      // Count (FAF Studio's dry run): nothing is placed.
    } else if (fill.decals) {
      EdDocument::DecalSnapshot before = mDocument.DecalsNow();
      mDecalSelection.clear();
      for (const auto& [x, z] : points) {
        placed += static_cast<std::size_t>(std::max(0, PlaceDecalCopies(x, z, 0.0f, NextDecalSizeFactor())));
      }
      if (placed > 0) {
        mDocument.DecalsEdited(std::move(before));
      }
    } else {
      const std::size_t before = mMap->mProps->mEntries.size();
      BeginObjectStroke();
      mFilling = true;
      for (const auto& [x, z] : points) {
        PlaceProps(x, z);
      }
      mFilling = false;
      EndObjectStroke();
      placed = mMap->mProps->mEntries.size() - before;
    }
    char text[320];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%s%zu %s (%zu points and their copies); left out: %d under water, %d by the slope, %d by the height, %d by the "
      "mask, %d near props there, %d by a mirror line",
      fill.countOnly ? "Count: " : "",
      fill.countOnly ? points.size() : placed,
      fill.countOnly ? "points would be placed" : (fill.decals ? "decals placed" : "props placed"),
      points.size(),
      wet,
      steep,
      high,
      sparse,
      nearby,
      crowded
    );
    gpg::Logf("editor: fill the map: %s", text);
    return text;
  }

  void EdMapScene::TestFill(
    const std::string& spec
  )
  {
    // `<density>,<spacing>[,keep]`: the map's commonest prop filled over the map, its copies checked, then undone.
    EdTools::FillOptions fill;
    fill.density = std::strtof(spec.c_str(), nullptr);
    if (const std::size_t comma = spec.find(','); comma != std::string::npos) {
      fill.spacing = std::strtof(spec.c_str() + comma + 1, nullptr);
    }
    const bool keep = spec.contains("keep");
    std::string blueprint;
    for (const FindTypeCount& t : CountFindTypes(FindObjects())) {
      if (t.kind == FindKind::Prop) {
        blueprint = t.type;
        break;
      }
    }
    if (blueprint.empty() || mMap == nullptr || mMap->mProps == nullptr) {
      gpg::Logf("editor: fill test: no prop on the map");
      return;
    }
    mTools->SetPropTool(blueprint, 1);
    const std::size_t before = mMap->mProps->mEntries.size();
    const std::string message = ScatterOverMap(fill);
    const auto& entries = mMap->mProps->mEntries;
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    int first = 0, whole = 0;
    for (std::size_t i = before; i < entries.size(); ++i) {
      const Wm3::Vec3f& p = entries[i].mTransform.pos_;
      if (!InFirstPart(field->width, field->height, brush.symmetry, brush.turns, p.x, p.z)) {
        continue;
      }
      ++first;
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field->width, field->height, p.x, p.z, brush.symmetry, brush.turns, cx, cz);
      bool all = true;
      for (int c = 1; c < copies && all; ++c) {
        bool found = false;
        for (std::size_t j = before; j < entries.size() && !found; ++j) {
          found = std::hypot(entries[j].mTransform.pos_.x - cx[c], entries[j].mTransform.pos_.z - cz[c]) <= 1.0f;
        }
        all = found;
      }
      whole += all ? 1 : 0;
    }
    gpg::Logf(
      "editor: fill test: %s with %.0f per 100 x 100, %.1f apart: %s; %d of the %d in the first part have every copy",
      blueprint.c_str(),
      static_cast<double>(fill.density),
      static_cast<double>(fill.spacing),
      message.c_str(),
      whole,
      first
    );
    if (!keep) {
      const bool undone = Undo();
      gpg::Logf(
        "editor: fill test: undo %s; %zu props (%zu before)",
        undone ? "took it back" : "had nothing",
        mMap->mProps->mEntries.size(),
        before
      );
    }
  }

  void EdMapScene::EraseProps(
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || mMap->mProps == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    auto& entries = mMap->mProps->mEntries;
    for (std::size_t i = entries.size(); i-- > 0;) {
      bool inside = false;
      for (int c = 0; c < copies && !inside; ++c) {
        inside = std::hypot(entries[i].mTransform.pos_.x - centreX[c], entries[i].mTransform.pos_.z - centreZ[c]) <
          brush.radius;
      }
      if (!inside) {
        continue;
      }
      // "Only the picked prop": the others stay.
      if (mTools->EraseOnlyThisProp() && mTools->PropBlueprint() != entries[i].mBlueprintPath.c_str()) {
        continue;
      }
      if (i < mProps.size()) {
        delete mProps[i];
        mProps.erase(mProps.begin() + static_cast<std::ptrdiff_t>(i));
      }
      mDocument.DeletePropAt(i);
      mObjectsChanged = true;
    }
    mSelection.clear();
    if (mObjectsChanged) {
      mDocument.SetModified(true);
    }
  }

  void EdMapScene::RollPropYaw()
  {
    mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
    mNextPropYaw = static_cast<float>(mScatterSeed >> 8) / 16777216.0f * 6.2831853f;
  }

  void EdMapScene::DeletePropPreview()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mPreview) {
        delete instance;
      }
    }
    mPreview.clear();
    mPreviewBlueprint.clear();
  }

  void EdMapScene::UpdatePropPreview()
  {
    const auto hide = [this] {
      for (moho::MeshInstance* const instance : mPreview) {
        if (instance != nullptr) {
          instance->isHidden = 1;
        }
      }
    };
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    float gx = 0.0f;
    float gz = 0.0f;
    if (
      field == nullptr || mTools == nullptr || !mTools->PropsToolActive() ||
      mTools->CurrentPropMode() != EdTools::PropMode::Single || mTools->PropBlueprint().empty() ||
      (::GetKeyState(VK_SHIFT) & 0x8000) != 0 || !CursorGround(gx, gz)
    ) {
      hide();
      return;
    }
    // Where the click would put each copy, as PlaceProps does.
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const float yaw = mTools->RandomPropTurn() ? mNextPropYaw : 0.0f;
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
      aheadZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, gx, gz, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(
      field->width, field->height, gx + std::sin(yaw), gz + std::cos(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
    );
    const auto transformOf = [&](const int c) {
      const float heading = std::atan2(aheadX[c] - centreX[c], aheadZ[c] - centreZ[c]);
      const float x = SnapToGrid(centreX[c]);
      const float z = SnapToGrid(centreZ[c]);
      moho::CWldPropEntry entry;
      entry.mBlueprintPath.assign(mTools->PropBlueprint().c_str());
      entry.mTransform.pos_ = Wm3::Vec3f{
        x,
        mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
        ),
        z
      };
      entry.mTransform.orient_ = Wm3::Quatf(std::cos(heading * 0.5f), 0.0f, std::sin(heading * 0.5f), 0.0f);
      return entry;
    };
    if (mPreviewBlueprint != mTools->PropBlueprint() || static_cast<int>(mPreview.size()) != copies) {
      DeletePropPreview();
      for (int c = 0; c < copies; ++c) {
        mPreview.push_back(MakePropInstance(transformOf(c)));
      }
      mPreviewBlueprint = mTools->PropBlueprint();
    }
    for (int c = 0; c < copies; ++c) {
      moho::MeshInstance* const instance = mPreview[static_cast<std::size_t>(c)];
      if (instance == nullptr) {
        continue;
      }
      const bool onMap = centreX[c] >= 0.0f && centreZ[c] >= 0.0f &&
        centreX[c] <= static_cast<float>(field->width - 1) && centreZ[c] <= static_cast<float>(field->height - 1);
      const moho::CWldPropEntry entry = transformOf(c);
      instance->SetStance(entry.mTransform, entry.mTransform);
      instance->isHidden = onMap ? 0 : 1;
    }
  }

  std::string EdMapScene::PropDetails(
    const std::string& path
  ) const
  {
    if (path == mDetailsFor) {
      return mDetails;
    }
    mDetailsFor = path;
    mDetails.clear();
    moho::RRuleGameRules* const rules = Rules();
    if (rules == nullptr || path.empty()) {
      return mDetails;
    }
    const fa::string file(path.c_str());
    moho::RResId id{};
    gpg::STR_CopyFilename(&id.name, &file);
    const moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
    if (blueprint == nullptr) {
      return mDetails;
    }
    const moho::RMeshBlueprint* const mesh = rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint);
    char text[512];
    std::string lods;
    if (mesh != nullptr) {
      for (const moho::RMeshBlueprintLOD& lod : mesh->mLods) {
        const std::string name = lod.mMeshName.c_str();
        const std::size_t slash = name.find_last_of('/');
        char one[160];
        (void)std::snprintf(
          one,
          sizeof(one),
          "%s%s to %.0f",
          lods.empty() ? "" : ", ",
          name.substr(slash == std::string::npos ? 0 : slash + 1).c_str(),
          static_cast<double>(lod.mLodCutoff)
        );
        lods += one;
      }
    }
    (void)std::snprintf(
      text,
      sizeof(text),
      "Reclaim %.0f mass, %.0f energy. Scale %.2f. %zu LOD%s: %s",
      static_cast<double>(blueprint->Economy.ReclaimMassMax),
      static_cast<double>(blueprint->Economy.ReclaimEnergyMax),
      static_cast<double>(blueprint->Display.UniformScale),
      mesh != nullptr ? static_cast<std::size_t>(mesh->mLods.size()) : 0U,
      mesh != nullptr && mesh->mLods.size() == 1 ? "" : "s",
      lods.empty() ? "(no mesh)" : lods.c_str()
    );
    mDetails = text;
    return mDetails;
  }

  void EdMapScene::DeleteUnits()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mUnits) {
        delete instance;
      }
    }
    mUnits.clear();
    mUnitRefs.clear();
    DropUnitPreview();
  }

  void EdMapScene::ReloadUnits()
  {
    DeleteUnits();
    CreateUnits();
    mUnitSelection.erase(
      std::remove_if(
        mUnitSelection.begin(),
        mUnitSelection.end(),
        [&](const auto& unit) {
      return UnitRefIndex(unit.first, unit.second) < 0;
    }
      ),
      mUnitSelection.end()
    );
  }

  int EdMapScene::UnitRefIndex(
    const std::string& army,
    const std::string& name
  ) const
  {
    for (std::size_t i = 0; i < mUnitRefs.size(); ++i) {
      if (mUnitRefs[i].name == name && mUnitRefs[i].army == army) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  int EdMapScene::PickUnit(
    const float x,
    const float z
  ) const
  {
    const float reach = std::max(3.0f, mDistance * 0.01f);
    int best = -1;
    float bestDistance = reach;
    for (std::size_t i = 0; i < mUnitRefs.size(); ++i) {
      const float d = std::hypot(mUnitRefs[i].position.x - x, mUnitRefs[i].position.z - z);
      if (d < bestDistance) {
        bestDistance = d;
        best = static_cast<int>(i);
      }
    }
    return best;
  }

  bool EdMapScene::EditArmyUnits(
    const std::string& army,
    const std::function<void(UnitGroup&)>& change
  )
  {
    for (SaveEntry& entry : mDocument.SaveData().Armies()) {
      if (entry.name != army) {
        continue;
      }
      UnitGroup group;
      if (const auto read = ParseUnitGroup(entry.Get("Units"), group); !read) {
        gpg::Warnf("editor: %s's units unreadable, not changed: %s", army.c_str(), read.error().c_str());
        return false;
      }
      change(group);
      entry.Set("Units", FormatUnitGroup(group, 12));
      return true;
    }
    gpg::Warnf("editor: _save.lua has no army %s", army.c_str());
    return false;
  }

  namespace
  {
    /** A unit's transform as CreateUnitHPR makes it from its position and Orientation (heading, pitch, roll). */
    moho::VTransform UnitTransform(
      const Wm3::Vec3f& position,
      const float (&orientation)[3]
    )
    {
      moho::VTransform transform{};
      transform.pos_ = position;
      Wm3::Vector3f rows[3];
      (void)moho::BuildRotationMatrixFromEulerHPR(rows, orientation[0], orientation[1], orientation[2]);
      (void)moho::MatrixRowsToQuatCanonical(rows, &transform.orient_);
      return transform;
    }
  } // namespace

  void EdMapScene::PlaceUnits(
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr) {
      return;
    }
    const std::string type = mTools->UnitType();
    const std::string army = mTools->UnitArmy();
    if (type.empty() || army.empty()) {
      gpg::Warnf("editor: pick a unit type and an army first");
      return;
    }
    // The next free UNIT_n over every army.
    int highest = 0;
    for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
      UnitGroup group;
      if (ParseUnitGroup(entry.Get("Units"), group)) {
        highest = std::max(highest, HighestUnitNumber(group));
      }
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float yaw = 0.0f;
    if (mTools->RandomUnitTurn()) {
      mUnitSeed = mUnitSeed * 1664525U + 1013904223U;
      yaw = static_cast<float>(mUnitSeed >> 8) / 16777216.0f * 2.0f * kPi;
    }
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
      aheadZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    // A unit's front (+Z) under its turn is (sin, cos) on the ground, as for props.
    (void)HeightBrushCentres(
      field->width, field->height, x + std::sin(yaw), z + std::cos(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
    );
    // Each copy's army: a player army's copy goes to the army whose start position is nearest its start's copy (the
    // symmetric player); an army without a start position (civilians) keeps its copies.
    std::string armyOf[kMaxSymmetryCopies];
    for (int c = 0; c < copies; ++c) {
      armyOf[c] = army;
    }
    {
      std::vector<std::pair<std::string, std::array<float, 2>>> starts;
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float mx = 0.0f, my = 0.0f, mz = 0.0f;
        if (MarkerTypeOf(marker) == "Blank Marker" && ShownMarkerPosition(marker, mx, my, mz)) {
          starts.push_back({marker.name, {mx, mz}});
        }
      }
      for (const auto& [name, position] : starts) {
        if (name != army) {
          continue;
        }
        float startX[kMaxSymmetryCopies], startZ[kMaxSymmetryCopies];
        (void)HeightBrushCentres(
          field->width, field->height, position[0], position[1], brush.symmetry, brush.turns, startX, startZ
        );
        for (int c = 1; c < copies; ++c) {
          float nearest = 1e30f;
          for (const auto& [other, at] : starts) {
            const float d = std::hypot(at[0] - startX[c], at[1] - startZ[c]);
            if (d < nearest) {
              nearest = d;
              armyOf[c] = other;
            }
          }
        }
      }
    }
    std::optional<EdDocument::SaveSnapshot> before;
    if (!mUnitBatch) {
      before.emplace(mDocument.SaveDataNow());
    }
    std::vector<std::pair<std::string, std::string>> placed;
    for (int c = 0; c < copies; ++c) {
      if (
        centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
        centreZ[c] > static_cast<float>(field->height - 1)
      ) {
        continue;
      }
      SaveUnit unit;
      unit.name = "UNIT_" + std::to_string(++highest);
      unit.type = type;
      unit.position[0] = SnapToGrid(centreX[c]);
      unit.position[2] = SnapToGrid(centreZ[c]);
      // A structure snaps by its footprint (FAF Studio's unitfit): odd sizes on a cell's middle, even on a corner.
      int fitX = 1;
      int fitZ = 1;
      const std::string fit = UnitFitAt(type, unit.position[0], unit.position[2], fitX, fitZ);
      if (mTools->SnapToGrid() && (fitX > 1 || fitZ > 1)) {
        unit.position[0] = SnapFootprint(centreX[c], fitX);
        unit.position[2] = SnapFootprint(centreZ[c], fitZ);
      }
      if (!fit.empty()) {
        gpg::Warnf("editor: %s placed where it doesn't fit: %s", type.c_str(), fit.c_str());
      }
      unit.position[1] = UnitRestHeight(unit.position[0], unit.position[2]);
      // The saves keep a unit's turn in Orientation's second value.
      unit.orientation[1] = std::atan2(aheadX[c] - centreX[c], aheadZ[c] - centreZ[c]);
      const std::string name = unit.name;
      if (EditArmyUnits(armyOf[c], [&](UnitGroup& group) {
        AddUnit(group, unit);
      })) {
        placed.emplace_back(armyOf[c], name);
      }
    }
    if (mUnitBatch) {
      mUnitBatchPlaced.insert(mUnitBatchPlaced.end(), placed.begin(), placed.end());
      return;
    }
    if (!placed.empty()) {
      mDocument.SaveDataEdited(std::move(*before));
      ReloadUnits();
      mUnitSelection = placed;
      std::string where;
      for (const auto& [owner, name] : placed) {
        where += (where.empty() ? "" : ", ") + name + " in " + owner;
      }
      gpg::Logf(
        "editor: %zu %s units placed (%s), %zu units now", placed.size(), type.c_str(), where.c_str(), mUnitRefs.size()
      );
    }
  }

  std::vector<SaveUnit> EdMapScene::UnitsToExport(
    const std::string& army
  ) const
  {
    std::vector<SaveUnit> units;
    for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
      UnitGroup group;
      if (!ParseUnitGroup(entry.Get("Units"), group)) {
        continue;
      }
      std::vector<const SaveUnit*> all;
      CollectUnits(group, all);
      for (const SaveUnit* const unit : all) {
        const bool chosen = mUnitSelection.empty()
          ? entry.name == army
          : std::find(mUnitSelection.begin(), mUnitSelection.end(), std::pair{entry.name, unit->name}) !=
            mUnitSelection.end();
        if (chosen) {
          units.push_back(*unit);
        }
      }
    }
    return units;
  }

  std::expected<void, std::string> EdMapScene::ImportUnitFile(
    const std::string& text,
    const std::string& army,
    std::vector<std::string>& names,
    bool& moved
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return std::unexpected("no map shown");
    }
    std::vector<SaveUnit> units;
    float centre[3];
    if (const auto read = UnitsFromScunits(text, units, centre); !read) {
      return std::unexpected(read.error());
    }
    if (units.empty()) {
      return std::unexpected("the file has no units");
    }
    const float width = static_cast<float>(field->width - 1);
    const float height = static_cast<float>(field->height - 1);
    moved = FitUnitsOnMap(units, centre, width, height);
    // The next free UNIT_n over every army, as placing does.
    int highest = 0;
    for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
      UnitGroup group;
      if (ParseUnitGroup(entry.Get("Units"), group)) {
        highest = std::max(highest, HighestUnitNumber(group));
      }
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    names.clear();
    const bool added = EditArmyUnits(army, [&](UnitGroup& group) {
      for (SaveUnit& unit : units) {
        unit.name = "UNIT_" + std::to_string(++highest);
        unit.position[0] = std::clamp(unit.position[0], 0.0f, width);
        unit.position[2] = std::clamp(unit.position[2], 0.0f, height);
        // On the ground (or the sea over it), as FAFME's import snaps them.
        unit.position[1] = UnitRestHeight(unit.position[0], unit.position[2]);
        names.push_back(unit.name);
        AddUnit(group, unit);
      }
    });
    if (!added) {
      names.clear();
      return std::unexpected("the army's units can't be changed");
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    mUnitSelection.clear();
    for (const std::string& name : names) {
      mUnitSelection.emplace_back(army, name);
    }
    return {};
  }

  void EdMapScene::DeleteSelectedUnits()
  {
    if (mUnitSelection.empty()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    int deleted = 0;
    // Follow symmetry: the mirrored copies go too.
    if (FollowOn()) {
      std::vector<std::pair<std::string, std::string>> doomed = mUnitSelection;
      for (const auto& copies : UnitPartners()) {
        for (const auto& copy : copies) {
          if (!copy.second.empty() && std::find(doomed.begin(), doomed.end(), copy) == doomed.end()) {
            doomed.push_back(copy);
          }
        }
      }
      mUnitSelection = std::move(doomed);
    }
    for (const auto& [army, name] : mUnitSelection) {
      bool removed = false;
      if (
        EditArmyUnits(
          army,
          [&](UnitGroup& group) {
        removed = RemoveUnit(group, name);
      }
        ) &&
        removed
      ) {
        ++deleted;
      }
    }
    mUnitSelection.clear();
    if (deleted > 0) {
      mDocument.SaveDataEdited(std::move(before));
      ReloadUnits();
      gpg::Logf("editor: %d units deleted, %zu now", deleted, mUnitRefs.size());
    }
  }

  void EdMapScene::TestUndoPropSwap()
  {
    const bool undone = UndoProps(false);
    const std::string path = mMap != nullptr && mMap->mProps != nullptr && mTestHoverProp >= 0 &&
        static_cast<std::size_t>(mTestHoverProp) < mMap->mProps->mEntries.size()
      ? mMap->mProps->mEntries[static_cast<std::size_t>(mTestHoverProp)].mBlueprintPath.c_str()
      : "";
    gpg::Logf(
      "editor: /propswapundo: %s; prop %d is %s", undone ? "undone" : "nothing to undo", mTestHoverProp, path.c_str()
    );
  }

  void EdMapScene::UpdatePropHighlight()
  {
    // The props to outline and their colour: the selected ones in the selection's yellow, the one under the cursor in
    // the hover amber (over its selected colour: it shows what a click picks).
    constexpr std::uint32_t kHoverOutline = 0xFFFFB040u;
    constexpr std::uint32_t kSelectedOutline = 0xFFFFE040u;
    std::vector<std::pair<int, std::uint32_t>> wanted;
    if (!mProps.empty() && mMap != nullptr && mMap->mProps != nullptr) {
      const std::size_t count = mMap->mProps->mEntries.size();
      for (std::size_t i = 0; i < mSelection.size() && i < kMaxOutlinedProps; ++i) {
        if (
          mSelection[i] >= 0 && static_cast<std::size_t>(mSelection[i]) < count && mSelection[i] != mHoverPropWanted
        ) {
          wanted.emplace_back(mSelection[i], kSelectedOutline);
        }
      }
      if (mHoverPropWanted >= 0 && static_cast<std::size_t>(mHoverPropWanted) < count) {
        wanted.emplace_back(mHoverPropWanted, kHoverOutline);
      }
    }
    // A prop's index changes when props are added or removed: an outline is kept for its index while the entry there
    // has the same blueprint (its place is read from the entry each frame), and remade otherwise.
    std::vector<bool> used(mOutlines.size(), false);
    std::size_t made = 0;
    for (const auto& [prop, colour] : wanted) {
      const moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(prop)];
      std::size_t at = mOutlines.size();
      for (std::size_t i = 0; i < mOutlines.size(); ++i) {
        if (!used[i] && mOutlines[i].prop == prop && mOutlines[i].blueprint == entry.mBlueprintPath.c_str()) {
          at = i;
          break;
        }
      }
      if (at == mOutlines.size()) {
        PropOutline outline;
        if (!MakePropOutline(prop, outline)) {
          continue;
        }
        mOutlines.push_back(outline);
        used.push_back(false);
        ++made;
      }
      used[at] = true;
      PropOutline& outline = mOutlines[at];
      outline.shell->SetColor(colour);
      for (moho::MeshInstance* const instance : {outline.shell, outline.over}) {
        if (instance != nullptr) {
          instance->isHidden = 0;
          instance->SetStance(entry.mTransform, entry.mTransform);
        }
      }
    }
    // Outlines not wanted now: hidden, the 8 newest kept for the cursor coming back, the rest deleted.
    std::size_t spare = 0;
    for (std::size_t i = mOutlines.size(); i-- > 0;) {
      if (used[i]) {
        continue;
      }
      if (spare < 8) {
        ++spare;
        for (moho::MeshInstance* const instance : {mOutlines[i].shell, mOutlines[i].over}) {
          if (instance != nullptr) {
            instance->isHidden = 1;
          }
        }
        continue;
      }
      if (moho::MeshRenderer::GetInstance() != nullptr) {
        delete mOutlines[i].shell;
        delete mOutlines[i].over;
      }
      mOutlines.erase(mOutlines.begin() + static_cast<std::ptrdiff_t>(i));
    }
    if (made > 0) {
      std::size_t shown = 0;
      for (const bool u : used) {
        shown += u ? 1 : 0;
      }
      gpg::Logf("editor: %zu props outlined (%zu selected, hover %d)", shown, mSelection.size(), mHoverPropWanted);
    }
  }

  bool EdMapScene::MakePropOutline(
    const int prop,
    PropOutline& out
  )
  {
    const moho::CWldPropEntry& entry = mMap->mProps->mEntries[static_cast<std::size_t>(prop)];
    {
      moho::RRuleGameRules* const rules = Rules();
      moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
      if (rules == nullptr || renderer == nullptr) {
        return false;
      }
      moho::RResId id{};
      gpg::STR_CopyFilename(&id.name, &entry.mBlueprintPath);
      moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
      moho::RMeshBlueprint* const mesh =
        blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
      if (mesh == nullptr) {
        return false;
      }
      // The outline (WPE.57), two more instances of the prop's mesh with the editor's techniques appended to mesh.fx
      // (ren_EditorMeshOutline): EditorOutline, its front faces pushed out a few pixels' worth at any zoom in the
      // instance's colour, drawn after the water over everything; then EditorPropOver, the prop again with its own
      // textures over the shell's middle, so only the rim stays (both over what stands in front, as a highlight). A
      // prop drawn alpha-tested (its shader "...Alpha": most props, the trees' leaf cards among them) gets the hull cut
      // out by its albedo's alpha, so the outline follows the leaves, not the cards.
      const moho::RMeshBlueprintLOD* const lod =
        mesh->mLods.begin() != mesh->mLods.end() ? mesh->mLods.begin() : nullptr;
      if (lod == nullptr) {
        return false;
      }
      // A swaying prop (UndulatingNormalMappedAlpha: the trees) gets the swaying shell and redraw, so they move with
      // it; its shell a hairline (each leaf card gets a rim; a wide rim on every card painted a tree group amber).
      const std::string shader = lod->mShaderName.c_str();
      const bool alphaTested = shader.contains("Alpha");
      const bool sways = shader.contains("Undulating");
      const char* const shellTechnique = sways ? "EditorOutlineAlphaSway"
        : alphaTested                          ? "EditorOutlineAlpha"
                                               : "EditorOutline";
      const std::shared_ptr<moho::MeshMaterial> hull = moho::MeshMaterial::Create(
        fa::string(shellTechnique), lod->mAlbedoName, fa::string(), fa::string(), fa::string(), fa::string(), nullptr
      );
      const std::shared_ptr<moho::MeshMaterial> over = moho::MeshMaterial::Create(
        fa::string(sways ? "EditorPropOverSway" : "EditorPropOver"),
        lod->mAlbedoName,
        lod->mNormalsName,
        lod->mSpecularName,
        lod->mLookupName,
        lod->mSecondaryName,
        nullptr
      );
      const float scale = blueprint->Display.UniformScale;
      out.shell = renderer->CreateMeshInstance(
        0, static_cast<std::int32_t>(0xFFFFB040u), mesh, Wm3::Vec3f{scale, scale, scale}, false, hull
      );
      if (out.shell == nullptr) {
        return false;
      }
      out.over = renderer->CreateMeshInstance(0, -1, mesh, Wm3::Vec3f{scale, scale, scale}, false, over);
      out.prop = prop;
      out.blueprint = entry.mBlueprintPath.c_str();
      gpg::Logf(
        "editor: prop %d outlined (%s, shader %s: %s)",
        prop,
        entry.mBlueprintPath.c_str(),
        shader.c_str(),
        shellTechnique
      );
      return true;
    }
  }

  void EdMapScene::DeletePropHighlight()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (const PropOutline& outline : mOutlines) {
        delete outline.shell;
        delete outline.over;
      }
    }
    mOutlines.clear();
  }

  void EdMapScene::DeleteProps()
  {
    DeletePropHighlight();
    DeletePropPreview();
    DeleteUnits();
    DeleteDeposits();
    DeleteMarkerModels();
    DeleteMeshInstances();
    if (mMeshHidesTerrain) {
      mMeshHidesTerrain = false;
      moho::ren_TerrainSurface = true;
    }
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mProps) {
        delete instance;
      }
    }
    mProps.clear();
    mPropsDone = false;
  }

  void EdMapScene::UpdateMiniMap()
  {
    if (mTools == nullptr || mMap == nullptr || moho::ren_Viewport == nullptr) {
      return;
    }
    const float* const rect = mTools->MinimapRect();
    if (rect[2] < 8.0f || rect[3] < 8.0f) {
      DropMiniMap();
      return;
    }
    if (mMiniView == nullptr) {
      mMiniCamera =
        moho::CAM_GetManager()->CreateCamera("Map editor minimap", *mMap->mTerrainRes->mMap, mDocument.Lua());
      mMiniCamera->CameraSetOrtho(true);
      mMiniView = std::make_unique<EdMiniMapView>(const_cast<moho::GeomCamera3*>(&mMiniCamera->CameraGetView()));
      // After the main view (depth 0), so it draws over its corner.
      moho::ren_Viewport->AddWorldView(mMiniView.get(), 0, 1);
      mMiniRect[2] = 0.0f;
      gpg::Logf("editor: the minimap draws the map from above");
    }
    // Drawn again every 20 frames, when its rectangle changes, or every frame while the panels can't keep a copy: the
    // map changes slowly, and a second world view costs as much as the first.
    mMiniDrewLast = mMiniDrawNow;
    const bool moved =
      rect[0] != mMiniRect[0] || rect[1] != mMiniRect[1] || rect[2] != mMiniRect[2] || rect[3] != mMiniRect[3];
    mMiniDrawNow = !mMiniCached || moved || ++mMiniFrame % 20 == 0;
    mMiniView->SetSkip(!mMiniDrawNow);
    if (moved) {
      for (int i = 0; i < 4; ++i) {
        mMiniRect[i] = rect[i];
      }
      mMiniCamera->CameraSetViewport(Wm3::Vector2f(rect[0], rect[1]), Wm3::Vector2f(rect[2], rect[3]));
      // The whole map across the rectangle: an orthographic camera spans its target zoom across its width.
      const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
      const float x = (bounds.Min.x + bounds.Max.x) * 0.5f;
      const float z = (bounds.Min.z + bounds.Max.z) * 0.5f;
      const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
      mMiniCamera->TargetManual(Wm3::Vec3f{x, y, z}, kPi, kPi * 0.5f, bounds.Max.x - bounds.Min.x, 0.0f);
    }
  }

  void EdMapScene::DropMiniMap()
  {
    if (mMiniView != nullptr && moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->RemoveWorldView(mMiniView.get());
    }
    mMiniView.reset();
    // ~CameraImpl takes the camera out of the camera manager.
    delete mMiniCamera;
    mMiniCamera = nullptr;
    mMiniRect[2] = 0.0f;
  }

  bool EdMapScene::CursorGround(
    float& x,
    float& z
  ) const
  {
    return mCursorInView && GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), x, z);
  }

  bool EdMapScene::GroundAt(
    const float x,
    const float y,
    float& outX,
    float& outZ
  ) const
  {
    if (mCamera == nullptr) {
      return false;
    }
    const Wm3::Vector3f point = mCamera->CameraScreenToSurface(Wm3::Vector2f(x, y));
    // A ray that misses the map (the sky past the horizon) gives no usable point.
    const float margin = mMapExtent;
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    if (
      !std::isfinite(point.x) || !std::isfinite(point.z) || point.x < bounds.Min.x - margin ||
      point.x > bounds.Max.x + margin || point.z < bounds.Min.z - margin || point.z > bounds.Max.z + margin
    ) {
      return false;
    }
    outX = point.x;
    outZ = point.z;
    // On a mesh terrain map shown: where the ray from the eye first meets the mesh (FAF Studio's mesh pick), not the
    // height field's point under it.
    if (mMeshMode != 0 && MeshInView()) {
      const Wm3::Vec3f eye = mCamera->CameraGetView().tranform.pos_;
      const Wm3::Vec3f to{point.x - eye.x, point.y - eye.y, point.z - eye.z};
      const float length = std::sqrt(to.x * to.x + to.y * to.y + to.z * to.z);
      if (length > 1.0f) {
        const int steps = std::clamp(static_cast<int>(length * 1.5f / 2.0f), 8, 4000);
        const auto at = [&](const float t) {
          return Wm3::Vec3f{eye.x + to.x * t, eye.y + to.y * t, eye.z + to.z * t};
        };
        // Above the mesh: the ray point's height over the highest surface below it.
        const auto above = [&](const Wm3::Vec3f& p, bool& found) {
          float y = 0.0f;
          found = mMeshMap.HeightAt(p.x, p.z, p.y, y);
          return p.y - y;
        };
        float lo = 0.0f;
        for (int i = 1; i <= steps; ++i) {
          const float t = 1.5f * static_cast<float>(i) / static_cast<float>(steps);
          bool found = false;
          const float gap = above(at(t), found);
          const float stepDrop = std::fabs(to.y) * 1.5f / static_cast<float>(steps) + 0.25f;
          if (found && gap <= stepDrop) {
            // Narrowed down between the last point above and this one.
            float hi = t;
            for (int k = 0; k < 12; ++k) {
              const float mid = (lo + hi) * 0.5f;
              bool midFound = false;
              const float midGap = above(at(mid), midFound);
              if (midFound && midGap <= 0.05f) {
                hi = mid;
              } else {
                lo = mid;
              }
            }
            outX = at(hi).x;
            outZ = at(hi).z;
            return true;
          }
          lo = t;
        }
      }
    }
    return true;
  }

  void EdMapScene::MoveWithKeys(
    const float frameSeconds
  )
  {
    const float ahead = (mForward ? 1.0f : 0.0f) - (mBack ? 1.0f : 0.0f);
    const float aside = (mRight ? 1.0f : 0.0f) - (mLeft ? 1.0f : 0.0f);
    if ((ahead == 0.0f && aside == 0.0f) || mWidth <= 0 || mHeight <= 0) {
      return;
    }
    // Screen up and screen right as directions on the ground, from the camera itself; the heading's
    // when the view's middle is off the map.
    const float cx = static_cast<float>(mWidth) * 0.5f;
    const float cy = static_cast<float>(mHeight) * 0.5f;
    float centerX = 0.0f, centerZ = 0.0f, upX = 0.0f, upZ = 0.0f, rightX = 0.0f, rightZ = 0.0f;
    float forwardX = -std::sin(mHeading);
    float forwardZ = -std::cos(mHeading);
    float sideX = -forwardZ;
    float sideZ = forwardX;
    if (
      GroundAt(cx, cy, centerX, centerZ) && GroundAt(cx, cy - 40.0f, upX, upZ) &&
      GroundAt(cx + 40.0f, cy, rightX, rightZ)
    ) {
      const float upLength = std::hypot(upX - centerX, upZ - centerZ);
      const float rightLength = std::hypot(rightX - centerX, rightZ - centerZ);
      if (upLength > 1e-4f && rightLength > 1e-4f) {
        forwardX = (upX - centerX) / upLength;
        forwardZ = (upZ - centerZ) / upLength;
        sideX = (rightX - centerX) / rightLength;
        sideZ = (rightZ - centerZ) / rightLength;
      }
    }
    const float speed = mDistance * (mFast ? 2.4f : 0.8f) * std::min(frameSeconds, 0.1f);
    mTargetX += (forwardX * ahead + sideX * aside) * speed;
    mTargetZ += (forwardZ * ahead + sideZ * aside) * speed;
    ApplyCamera();
  }

  void EdMapScene::FrameWholeMap()
  {
    if (mMap == nullptr) {
      return;
    }
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    mTargetX = (bounds.Min.x + bounds.Max.x) * 0.5f;
    mTargetZ = (bounds.Min.z + bounds.Max.z) * 0.5f;
    mHeading = kPi;
    mPitch = 1.1f;
    mDistance = mMapExtent * 1.05f;
    ApplyCamera();
  }

  void EdMapScene::ApplyCamera()
  {
    if (mCamera == nullptr) {
      return;
    }
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    mTargetX = std::clamp(mTargetX, bounds.Min.x, bounds.Max.x);
    mTargetZ = std::clamp(mTargetZ, bounds.Min.z, bounds.Max.z);
    mTargetY = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(mTargetX), static_cast<std::int32_t>(mTargetZ));
    mPitch = std::clamp(mPitch, kMinPitch, kMaxPitch);
    mDistance = std::clamp(mDistance, 15.0f, mMapExtent * 2.5f);
    mCamera->TargetManual(Wm3::Vec3f{mTargetX, mTargetY, mTargetZ}, mHeading, mPitch, mDistance, 0.0f);
  }

  bool EdMapScene::OnWindowMessage(
    const HWND window,
    const UINT message,
    const WPARAM wParam,
    const LPARAM lParam
  )
  {
    if (mMap == nullptr) {
      return false;
    }
    const POINT at{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
    if (message == WM_MOUSEMOVE || message == WM_LBUTTONDOWN || message == WM_RBUTTONDOWN) {
      mCursor = at;
      mCursorInView = true; // the view's own message
    }
    // G or R running: the cursor moves or turns the selection; a click keeps it, a right click puts it back.
    if (mModal.on) {
      switch (message) {
      case WM_MOUSEMOVE:
        UpdateModal();
        return true;
      case WM_LBUTTONDOWN:
        EndModal(true);
        return true;
      case WM_RBUTTONDOWN:
        EndModal(false);
        return true;
      case WM_LBUTTONUP:
      case WM_RBUTTONUP:
        return true;
      default:
        break;
      }
    }
    // The tool's cursor over the view (FAF Studio's cursors), not while a play has it.
    if (message == WM_SETCURSOR && LOWORD(lParam) == HTCLIENT && mMap != nullptr && !OverPlay()) {
      if (const int cursor = ViewCursor(); cursor != 0) {
        ::SetCursor(
          cursor <= kEditorCursors ? EditorCursor(cursor - 1) : ::LoadCursorW(nullptr, MAKEINTRESOURCEW(cursor))
        );
        return true;
      }
      return false;
    }
    switch (message) {
    case WM_LBUTTONDOWN: {
      // Alt+drag measures, whatever the tool.
      if ((::GetKeyState(VK_MENU) & 0x8000) != 0) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          // Alt+Shift: the path goes on from the last end (Studio's ruler); Alt alone starts a new one.
          const bool more = (wParam & MK_SHIFT) != 0 && mRulerShown;
          if (more) {
            mRulerDone.push_back({mRulerFrom[0], mRulerFrom[1], mRulerTo[0], mRulerTo[1]});
            mRulerFrom[0] = mRulerTo[0];
            mRulerFrom[1] = mRulerTo[1];
          } else {
            mRulerDone.clear();
            mRulerFrom[0] = groundX;
            mRulerFrom[1] = groundZ;
          }
          mRuling = true;
          mRulerShown = true;
          mRulerTo[0] = groundX;
          mRulerTo[1] = groundZ;
          if (mTools != nullptr) {
            mTools->SetRulerText(RulerText());
          }
          ::SetCapture(window);
        }
        return true;
      }
      // Path editing (the Paths panel's "Edit on the map") takes the click next.
      if (mPathEdit != nullptr && mPathEdit->editing) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (
          GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
          PathMouseDown(window, groundX, groundZ, (wParam & MK_SHIFT) != 0, (wParam & MK_CONTROL) != 0)
        ) {
          return true;
        }
      }
      // An editor mod's tool takes the click first.
      if (viewClickHook) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (
          GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
          viewClickHook(groundX, groundZ, (wParam & MK_SHIFT) != 0, (wParam & MK_CONTROL) != 0)
        ) {
          return true;
        }
      }
      if (mRulerShown && !mRuling) {
        // A click without Alt puts the ruler away.
        mRulerShown = false;
        mRulerDone.clear();
        if (mTools != nullptr) {
          mTools->SetRulerText({});
        }
      }
      // The Water tool's wave generators: pick (Ctrl adds), Shift removes, a drag moves the picked.
      if (mTools != nullptr && mTools->WavePicking()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          return true;
        }
        const int hit = PickWave(groundX, groundZ);
        if ((wParam & MK_SHIFT) != 0) {
          if (hit >= 0) {
            std::vector<WaveRecord> before = mDocument.WavesNow();
            std::vector<WaveRecord> after = before;
            after.erase(after.begin() + hit);
            mDocument.ApplyWaves(after);
            mDocument.WavesEdited(std::move(before));
            mWaveSelection.clear();
            gpg::Logf("editor: wave generator %d removed, %zu now", hit, after.size());
          }
          return true;
        }
        if (hit < 0) {
          if ((wParam & MK_CONTROL) == 0) {
            mWaveSelection.clear();
          }
          return true;
        }
        if (std::find(mWaveSelection.begin(), mWaveSelection.end(), hit) == mWaveSelection.end()) {
          if ((wParam & MK_CONTROL) == 0) {
            mWaveSelection.clear();
          }
          mWaveSelection.push_back(hit);
        }
        mWaveDrag = true;
        mWaveDragFromX = groundX;
        mWaveDragFromZ = groundZ;
        ::SetCapture(window);
        return true;
      }
      // The Water tool's mask brush: a drag paints the chosen mask (one undo step a stroke).
      if (mTools != nullptr && mTools->WaterMaskPainting()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          mWaterMaskBefore = mDocument.WaterMasksNow();
          mPaintingWaterMask = true;
          (void)DabWaterMask(groundX, groundZ);
          ::SetCapture(window);
          ::SetFocus(window);
        }
        return true;
      }
      if (WaterBodyPress(window, at)) {
        return true;
      }
      // The map border, edited from any tool: a press on an edge (or a corner, two of them) drags it.
      if (mTools != nullptr && mTools->EditingBorder()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          mBorderEdges = BorderEdgesAt(groundX, groundZ);
          if (mBorderEdges != 0) {
            mBorderBefore = mDocument.SaveDataNow();
            ::SetCapture(window);
            ::SetFocus(window);
            return true;
          }
        }
      }
      if (mTools != nullptr && mTools->MarkersToolActive()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea();
        if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          return true;
        }
        // The edges within reach of the cursor (a corner takes two).
        // The move gizmo first: a drag of the selected markers along an axis or freely.
        if (const GizmoPart part = PickGizmo(at); part != GizmoPart::None) {
          // Shift on the gizmo: the copy moves (Shift on a marker itself deletes it, below).
          (void)CloneSelectionForDrag((wParam & MK_SHIFT) != 0);
          BeginGizmoDrag(part, at);
          mDragMarkers = true;
          mMarkersMoved = false;
          mMarkerBefore = mDocument.SaveDataNow();
          mMarkerDragStart.clear();
          BeginAreaFollow();
          mMarkerFollow = FollowDrag() ? MarkerPartners() : std::vector<std::vector<std::string>>{};
          for (const std::string& selected : mMarkerSelection) {
            std::array<float, 3> start{};
            for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
              if (marker.name == selected) {
                (void)ShownMarkerPosition(marker, start[0], start[1], start[2]);
              }
            }
            mMarkerDragStart.push_back(start);
          }
          ::SetCapture(window);
          ::SetFocus(window);
          return true;
        }
        (void)area;
        if (AreaMouseDown(window, at, groundX, groundZ, (wParam & MK_CONTROL) != 0)) {
          return true;
        }
        mBorderEdges = BorderEdgesAt(groundX, groundZ);
        if (mBorderEdges != 0) {
          mBorderBefore = mDocument.SaveDataNow();
          ::SetCapture(window);
          ::SetFocus(window);
          return true;
        }
        // Markers: link, pick, delete, or place.
        const int hit = PickMarker(groundX, groundZ);
        std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
        const bool connect = mTools->ConnectPathNodes() || ((wParam & MK_CONTROL) != 0 && (wParam & MK_SHIFT) != 0);
        if (hit >= 0 && connect) {
          LinkSelectionTo(markers[static_cast<std::size_t>(hit)].name);
          return true;
        }
        if (hit >= 0 && (wParam & MK_SHIFT) != 0) {
          mMarkerSelection = {markers[static_cast<std::size_t>(hit)].name};
          DeleteSelectedMarkers();
          return true;
        }
        if (hit < 0) {
          // Draw chain: Ctrl starts the next chain (the first free Chain_NN, or the name's next number).
          if (mTools->DrawingChain() && (wParam & MK_CONTROL) != 0 && !connect) {
            const std::vector<MarkerChain>& chains = mDocument.SaveData().Chains();
            const auto used = [&](const std::string& name) {
              return std::any_of(chains.begin(), chains.end(), [&](const MarkerChain& chain) {
                return chain.name == name;
              });
            };
            std::string base = mTools->ChainName();
            while (!base.empty() && (std::isdigit(static_cast<unsigned char>(base.back())) != 0)) {
              base.pop_back();
            }
            if (base.empty()) {
              base = "Chain_";
            }
            for (int n = 1; n < 1000; ++n) {
              char name[96];
              (void)std::snprintf(name, sizeof(name), "%s%02d", base.c_str(), n);
              if (!used(name)) {
                mTools->SetChainName(name);
                break;
              }
            }
          }
          PlaceMarkers(groundX, groundZ, connect);
          return true;
        }
        const std::string& name = markers[static_cast<std::size_t>(hit)].name;
        if (
          (wParam & MK_CONTROL) == 0 &&
          std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()
        ) {
          mMarkerSelection.clear();
        }
        if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()) {
          mMarkerSelection.push_back(name);
        }
        mDragMarkers = true;
        mMarkersMoved = false;
        mMarkerDragFromX = groundX;
        mMarkerDragFromZ = groundZ;
        mMarkerBefore = mDocument.SaveDataNow();
        mMarkerDragStart.clear();
        BeginAreaFollow();
        mMarkerFollow = FollowDrag() ? MarkerPartners() : std::vector<std::vector<std::string>>{};
        for (const std::string& selected : mMarkerSelection) {
          std::array<float, 3> start{};
          for (const SaveEntry& marker : markers) {
            if (marker.name == selected) {
              (void)ShownMarkerPosition(marker, start[0], start[1], start[2]);
            }
          }
          mMarkerDragStart.push_back(start);
        }
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      if (mTools != nullptr && mTools->UnitsToolActive()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        const GizmoPart part = mTools->UnitPlaceMode() ? GizmoPart::None : PickGizmo(at);
        if (
          part == GizmoPart::None && !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)
        ) {
          return true;
        }
        const int hit = part == GizmoPart::None ? PickUnit(groundX, groundZ) : -1;
        if (part == GizmoPart::None && (wParam & MK_SHIFT) != 0) {
          if (hit >= 0) {
            mUnitSelection = {
              {mUnitRefs[static_cast<std::size_t>(hit)].army, mUnitRefs[static_cast<std::size_t>(hit)].name}
            };
            DeleteSelectedUnits();
          }
          return true;
        }
        if (mTools->UnitPlaceMode()) {
          // Ctrl+click: a line from the last line's end (a corner); else a drag from here (a click: one unit).
          if ((wParam & MK_CONTROL) != 0 && mLineEndKept) {
            PlaceUnitLine(mLineEnd[0], mLineEnd[1], groundX, groundZ);
            return true;
          }
          mUnitLining = true;
          mUnitLineFrom[0] = groundX;
          mUnitLineFrom[1] = groundZ;
          ::SetCapture(window);
          return true;
        }
        if (part != GizmoPart::None) {
          (void)CloneSelectionForDrag((wParam & MK_SHIFT) != 0); // Shift on the gizmo: the copy moves
          BeginGizmoDrag(part, at);
        } else {
          const bool add = (wParam & MK_CONTROL) != 0;
          if (hit < 0) {
            if (!add) {
              mUnitSelection.clear();
            }
            return true;
          }
          const std::pair<std::string, std::string> key{
            mUnitRefs[static_cast<std::size_t>(hit)].army, mUnitRefs[static_cast<std::size_t>(hit)].name
          };
          const auto selected = std::find(mUnitSelection.begin(), mUnitSelection.end(), key);
          if (add && selected != mUnitSelection.end()) {
            mUnitSelection.erase(selected);
            return true;
          }
          if (selected == mUnitSelection.end()) {
            if (!add) {
              mUnitSelection.clear();
            }
            mUnitSelection.push_back(key);
          }
        }
        // A drag moves the selection, live (along an axis when it started on the gizmo).
        mDragUnits = true;
        mUnitsMoved = false;
        mUnitDragFromX = groundX;
        mUnitDragFromZ = groundZ;
        mUnitBefore = mDocument.SaveDataNow();
        mUnitDragStart.clear();
        for (const auto& [army, name] : mUnitSelection) {
          const int index = UnitRefIndex(army, name);
          mUnitDragStart.push_back(
            index >= 0 ? mUnitRefs[static_cast<std::size_t>(index)].position : Wm3::Vec3f{0.0f, 0.0f, 0.0f}
          );
        }
        mUnitFollow = FollowDrag() ? UnitPartners() : decltype(mUnitFollow){};
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      if (mTools != nullptr && mTools->DecalsToolActive()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (
          !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) ||
          mDocument.Decals() == nullptr
        ) {
          return true;
        }
        const int hit = PickDecal(groundX, groundZ);
        // Shift on the gizmo: the copy moves; Shift on a decal itself deletes it.
        if ((wParam & MK_SHIFT) != 0 && mTools->DecalSelectMode() && PickGizmo(at) != GizmoPart::None) {
          (void)CloneSelectionForDrag(true);
        } else if ((wParam & MK_SHIFT) != 0) {
          if (hit >= 0) {
            mDecalSelection = {hit};
            DeleteSelectedDecals();
          }
          return true;
        }
        if (mTools->DecalPlaceMode()) {
          PlaceDecals(groundX, groundZ);
          return true;
        }
        if (mTools->DecalScatterMode() || mTools->DecalEraseMode()) {
          mDecalBrushing = true;
          mDecalBrushBefore = mDocument.DecalsNow();
          mDecalBrushPoints.clear();
          mDecalBrushLastX = -1.0e9f;
          mDecalBrushLastZ = -1.0e9f;
          mDecalSelection.clear();
          ::SetCapture(window);
          DecalBrushAt(groundX, groundZ);
          return true;
        }
        if (mTools->DecalPathMode()) {
          mDecalPath.emplace_back(SnapToGrid(groundX), SnapToGrid(groundZ));
          return true;
        }
        const bool add = (wParam & MK_CONTROL) != 0;
        const GizmoPart part = mTools->DecalPathMode() ? GizmoPart::None : PickGizmo(at);
        if (part != GizmoPart::None) {
          BeginGizmoDrag(part, at);
        } else if (hit < 0) {
          if (!add) {
            mDecalSelection.clear();
          }
          return true;
        }
        const auto selected = part != GizmoPart::None ? mDecalSelection.begin()
                                                      : std::find(mDecalSelection.begin(), mDecalSelection.end(), hit);
        if (part == GizmoPart::None) {
          if (add && selected != mDecalSelection.end()) {
            mDecalSelection.erase(selected);
            return true;
          }
          if (selected == mDecalSelection.end()) {
            if (!add) {
              mDecalSelection.clear();
            }
            mDecalSelection.push_back(hit);
          }
        }
        // A drag moves the selection, live (along the gizmo's axis when it started on the gizmo).
        mDragDecals = true;
        mDecalsMoved = false;
        mDecalDragFromX = groundX;
        mDecalDragFromZ = groundZ;
        mDecalBefore = mDocument.DecalsNow();
        mDecalDragStart.clear();
        for (const int index : mDecalSelection) {
          std::array<float, 3> start{};
          if (const moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), index); decal != nullptr) {
            start = {decal->mPosition.x, decal->mPosition.y, decal->mPosition.z};
          }
          mDecalDragStart.push_back(start);
        }
        mDecalFollow = FollowDrag() ? DecalPartners() : std::vector<std::vector<int>>{};
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      if (mTools != nullptr && mTools->SelectToolActive() && mOverPlay && mTools->ShowGameUnits()) {
        // In front of a play: the game's own units first (the nearest within reach of the click); Ctrl adds or takes
        // one out; a drag warps the selected ones by as much (EdLiveUnits).
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          // Entity ids start at 0 (army 0's first unit, its commander): found or not is its own flag.
          std::uint32_t hit = 0;
          bool found = false;
          float best = 4.0f;
          for (const LiveUnit& unit : mLiveNow) {
            const float d = std::hypot(unit.x - groundX, unit.z - groundZ);
            if (d < best) {
              best = d;
              hit = unit.id;
              found = true;
            }
          }
          const bool add = (wParam & MK_CONTROL) != 0;
          if (found) {
            const auto found = std::find(mLiveSelection.begin(), mLiveSelection.end(), hit);
            if (add && found != mLiveSelection.end()) {
              mLiveSelection.erase(found);
              return true;
            }
            if (found == mLiveSelection.end()) {
              if (!add) {
                mLiveSelection.clear();
              }
              mLiveSelection.push_back(hit);
            }
            ClearAllSelections();
            mDragLive = true;
            mLiveFromX = mLiveToX = groundX;
            mLiveFromZ = mLiveToZ = groundZ;
            ::SetCapture(window);
            ::SetFocus(window);
            return true;
          }
          if (!add) {
            mLiveSelection.clear();
          }
        }
      }
      if (mTools != nullptr && mTools->SelectToolActive()) {
        // The gizmo moves what is selected; else a click picks the nearest marker, unit, prop or decal (Ctrl adds or
        // takes one out; another kind starts a new selection), and a drag moves the selection.
        if (const GizmoPart part = PickGizmo(at); part != GizmoPart::None) {
          (void)CloneSelectionForDrag((wParam & MK_SHIFT) != 0);
          BeginSelectionDrag(window, SelectedKind(), part, at, 0.0f, 0.0f);
          return true;
        }
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          return true;
        }
        const PickHit hit = PickAnything(at);
        const bool add = (wParam & MK_CONTROL) != 0;
        if (hit.kind == PickKind::None) {
          if (!add) {
            ClearAllSelections();
          }
          return true;
        }
        if (!add || hit.kind != SelectedKind()) {
          // A click on what is already selected keeps the selection, so the drag moves all of it.
          bool already = false;
          switch (hit.kind) {
          case PickKind::Prop:
            already = std::find(mSelection.begin(), mSelection.end(), hit.index) != mSelection.end();
            break;
          case PickKind::Marker:
            already = std::find(
                        mMarkerSelection.begin(),
                        mMarkerSelection.end(),
                        mDocument.SaveData().Markers()[static_cast<std::size_t>(hit.index)].name
                      ) != mMarkerSelection.end();
            break;
          case PickKind::Unit:
            already = std::find(
                        mUnitSelection.begin(),
                        mUnitSelection.end(),
                        std::pair<std::string, std::string>{
                          mUnitRefs[static_cast<std::size_t>(hit.index)].army,
                          mUnitRefs[static_cast<std::size_t>(hit.index)].name
                        }
                      ) != mUnitSelection.end();
            break;
          case PickKind::Decal:
            already = std::find(mDecalSelection.begin(), mDecalSelection.end(), hit.index) != mDecalSelection.end();
            break;
          default:
            break;
          }
          if (!already || hit.kind != SelectedKind()) {
            ClearAllSelections();
          }
        }
        mSelectKind = hit.kind;
        // Ctrl on a selected one takes it out; otherwise it joins.
        const auto toggle = [add](auto& list, const auto& key) {
          const auto found = std::find(list.begin(), list.end(), key);
          if (found != list.end()) {
            if (add) {
              list.erase(found);
              return false;
            }
            return true;
          }
          list.push_back(key);
          return true;
        };
        bool kept = true;
        switch (hit.kind) {
        case PickKind::Prop:
          kept = toggle(mSelection, hit.index);
          break;
        case PickKind::Marker:
          kept = toggle(mMarkerSelection, mDocument.SaveData().Markers()[static_cast<std::size_t>(hit.index)].name);
          break;
        case PickKind::Unit:
          kept = toggle(
            mUnitSelection,
            std::pair<std::string, std::string>{
              mUnitRefs[static_cast<std::size_t>(hit.index)].army, mUnitRefs[static_cast<std::size_t>(hit.index)].name
            }
          );
          break;
        case PickKind::Decal:
          kept = toggle(mDecalSelection, hit.index);
          break;
        default:
          break;
        }
        if (kept) {
          (void)CloneSelectionForDrag((wParam & MK_SHIFT) != 0);
          BeginSelectionDrag(window, hit.kind, GizmoPart::None, at, groundX, groundZ);
        }
        return true;
      }
      if (mTools != nullptr && mTools->PropsToolActive()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (
          !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) || mMap->mProps == nullptr
        ) {
          return true;
        }
        BeginObjectStroke();
        ::SetCapture(window);
        ::SetFocus(window);
        mScatterDue = 0.0f;
        if (mTools->CurrentPropMode() == EdTools::PropMode::Line && (wParam & MK_SHIFT) == 0) {
          // Ctrl: the line goes on from the last line's end (a corner), to where the button is let go.
          const bool corner = (wParam & MK_CONTROL) != 0 && mLineEndKept;
          mPropLine = true;
          mPropLineFromX = corner ? mLineEnd[0] : groundX;
          mPropLineFromZ = corner ? mLineEnd[1] : groundZ;
        } else if ((wParam & MK_SHIFT) != 0 || mTools->CurrentPropMode() == EdTools::PropMode::Erase) {
          EraseProps(groundX, groundZ);
        } else if (mTools->CurrentPropMode() == EdTools::PropMode::Single) {
          PlaceProps(groundX, groundZ, mTools->RandomPropTurn() ? mNextPropYaw : 0.0f);
          RollPropYaw();
        } else {
          PlaceProps(groundX, groundZ);
        }
        return true;
      }
      if (mTools != nullptr && mTools->PaintingTerrainTypes()) {
        mTypesBefore = mDocument.TerrainTypesNow();
        if (!mTypesBefore.empty()) {
          mPaintingTypes = true;
          ::SetCapture(window);
          ::SetFocus(window);
        }
        return true;
      }
      if (mTools != nullptr && mTools->TextureToolActive()) {
        LoadMasks();
        // A layer the map's shader doesn't blend: the paint wouldn't show (FAF Studio's WhyNotPaintable).
        if (const ShaderProfile profile = ShaderProfileOf(TerrainShader()); mTools->MaskLayer() >= profile.painted) {
          char why[240];
          (void)std::snprintf(
            why,
            sizeof(why),
            "%s blends layers 1 to %d only: paint on layer %d wouldn't show.%s",
            TerrainShader().c_str(),
            profile.painted,
            mTools->MaskLayer() + 1,
            profile.painted == 4     ? " A shader with eight layers (TTerrainXP) paints 5 to 8."
              : profile.painted == 7 ? " Its layer 8 holds data (roughness), not paint."
                                     : ""
          );
          mTools->SetPaintNote(why);
          gpg::Warnf("editor: %s", why);
          return true;
        }
        mTools->SetPaintNote({});
        if (!mDocument.Masks().texels.empty()) {
          mPaintInverted = false;
          mPaintingMask = true;
          mDocument.MaskUndo().BeginStroke();
          ::SetCapture(window);
          ::SetFocus(window);
        }
        return true;
      }
      if (mTools == nullptr || !mTools->TerrainToolActive()) {
        return false;
      }
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
        return true;
      }
      const float groundHeight = mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(groundX)), static_cast<std::int32_t>(std::lround(groundZ))
      );
      // Plane mode: Ctrl+click picks a point of the plane instead of painting.
      if ((wParam & MK_CONTROL) != 0 && mTools->CurrentHeightBrush().mode == HeightBrushMode::Plane) {
        mTools->AddPlanePoint(groundX, groundHeight, groundZ);
        return true;
      }
      // Path: a click adds a point. Ramp: the drag's start (the slope goes down on the release).
      if (mTools->CurrentHeightBrush().mode == HeightBrushMode::Path) {
        mTools->AddPathPoint(groundX, groundHeight, groundZ);
        return true;
      }
      if (mTools->CurrentHeightBrush().mode == HeightBrushMode::Ramp) {
        mRampDrag = true;
        mRampFrom = {groundX, groundZ, groundHeight};
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      // Flatten keeps the height under the stroke's first point.
      mFlattenTo = groundHeight * 128.0f;
      mStamped = false;
      mDabbed = false;
      mPaintInverted = false;
      mStrokeStartHeight = groundHeight;
      mPainting = true;
      mDocument.Heights().BeginStroke();
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    }
    case WM_LBUTTONUP:
      mGizmoDrag = GizmoPart::None;
      if (mPathDragging) {
        ::ReleaseCapture();
        return PathMouseUp();
      }
      if (mWaveDrag) {
        mWaveDrag = false;
        ::ReleaseCapture();
        float toX = 0.0f;
        float toZ = 0.0f;
        if (CursorGround(toX, toZ) && std::hypot(toX - mWaveDragFromX, toZ - mWaveDragFromZ) >= 0.5f) {
          std::vector<WaveRecord> before = mDocument.WavesNow();
          std::vector<WaveRecord> after = before;
          for (const int index : mWaveSelection) {
            if (index >= 0 && index < static_cast<int>(after.size())) {
              after[static_cast<std::size_t>(index)].position[0] += toX - mWaveDragFromX;
              after[static_cast<std::size_t>(index)].position[2] += toZ - mWaveDragFromZ;
            }
          }
          mDocument.ApplyWaves(after);
          mDocument.WavesEdited(std::move(before));
          gpg::Logf("editor: %zu wave generators moved", mWaveSelection.size());
        }
        return true;
      }
      if (mAreaDrag != 0) {
        AreaMouseUp();
        return true;
      }
      if (mDecalBrushing) {
        mDecalBrushing = false;
        ::ReleaseCapture();
        if (!(mDocument.DecalsNow() == mDecalBrushBefore)) {
          const std::size_t was = mDecalBrushBefore.size();
          mDocument.DecalsEdited(std::move(mDecalBrushBefore));
          gpg::Logf(
            "editor: decal %s stroke: %zu decals before, %zu now",
            mTools != nullptr && mTools->DecalScatterMode() ? "scatter" : "eraser",
            was,
            mDocument.DecalsNow().size()
          );
        }
        mDecalBrushBefore.clear();
        return true;
      }
      if (mRampDrag) {
        mRampDrag = false;
        ::ReleaseCapture();
        float toX = 0.0f;
        float toZ = 0.0f;
        if (
          mMap != nullptr && mTools != nullptr && CursorGround(toX, toZ) &&
          std::hypot(toX - mRampFrom.x, toZ - mRampFrom.z) >= 1.0f
        ) {
          const float toHeight = mMap->mTerrainRes->GetHeightAt(
            static_cast<std::int32_t>(std::lround(toX)), static_cast<std::int32_t>(std::lround(toZ))
          );
          PathOptions ramp = mTools->CurrentPathOptions();
          ramp.mode = PathMode::Ramp;
          ramp.closed = false;
          mTools->SetStrokeStats(ApplyPathNow({mRampFrom, {toX, toZ, toHeight}}, ramp));
        }
        return true;
      }
      if (mPaintingWaterMask) {
        mPaintingWaterMask = false;
        ::ReleaseCapture();
        if (!(mWaterMaskBefore == mDocument.WaterMasksNow())) {
          mDocument.WaterMasksEdited(std::move(mWaterMaskBefore));
          gpg::Logf("editor: water mask stroke: %s", WaterMaskName(mTools->WaterMaskKind()));
        }
        mWaterMaskBefore = {};
        return true;
      }
      if (mDragLive) {
        // The game's units dragged: each warped by the drag (the sim's own Warp, on the ground there).
        mDragLive = false;
        ::ReleaseCapture();
        const float dx = mLiveToX - mLiveFromX;
        const float dz = mLiveToZ - mLiveFromZ;
        if (std::hypot(dx, dz) > 0.5f) {
          for (const std::uint32_t id : mLiveSelection) {
            for (const LiveUnit& unit : mLiveNow) {
              if (unit.id == id) {
                LiveUnitWarp(id, unit.x + dx, unit.z + dz);
              }
            }
          }
        }
        return true;
      }
      if (mWaterBodyHandle != -2) {
        WaterBodyRelease();
        return true;
      }
      if (mDragUnits) {
        mDragUnits = false;
        ::ReleaseCapture();
        if (mUnitsMoved) {
          std::vector<std::pair<std::string, std::string>> moved = mUnitSelection;
          for (const auto& copies : mUnitFollow) {
            for (const auto& copy : copies) {
              if (!copy.second.empty()) {
                moved.push_back(copy);
              }
            }
          }
          for (const auto& [army, name] : moved) {
            const int index = UnitRefIndex(army, name);
            if (index < 0) {
              continue;
            }
            const Wm3::Vec3f position = mUnitRefs[static_cast<std::size_t>(index)].position;
            (void)EditArmyUnits(army, [&, name = name](UnitGroup& group) {
              if (SaveUnit* const unit = FindUnit(group, name); unit != nullptr) {
                unit->position[0] = position.x;
                unit->position[1] = position.y;
                unit->position[2] = position.z;
              }
            });
          }
          mDocument.SaveDataEdited(std::move(mUnitBefore));
          if (!mUnitSelection.empty()) {
            const int index = UnitRefIndex(mUnitSelection.front().first, mUnitSelection.front().second);
            if (index >= 0) {
              const Wm3::Vec3f& p = mUnitRefs[static_cast<std::size_t>(index)].position;
              gpg::Logf(
                "editor: %zu units moved, %s to %.2f, %.2f, %.2f",
                mUnitSelection.size(),
                mUnitSelection.front().second.c_str(),
                static_cast<double>(p.x),
                static_cast<double>(p.y),
                static_cast<double>(p.z)
              );
            }
          }
        }
        mUnitBefore = {};
        return true;
      }
      if (mDragDecals) {
        mDragDecals = false;
        ::ReleaseCapture();
        if (mDecalsMoved) {
          mDocument.DecalsEdited(std::move(mDecalBefore));
          gpg::Logf("editor: %zu decals moved", mDecalSelection.size());
        }
        mDecalBefore = {};
        return true;
      }
      if (mDragMarkers) {
        mDragMarkers = false;
        ::ReleaseCapture();
        if (mMarkersMoved) {
          mDocument.SaveDataEdited(std::move(mMarkerBefore));
          for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
            float x = 0.0f, y = 0.0f, z = 0.0f;
            if (
              !mMarkerSelection.empty() && marker.name == mMarkerSelection.front() &&
              ShownMarkerPosition(marker, x, y, z)
            ) {
              gpg::Logf(
                "editor: %zu markers moved, %s to %.2f, %.2f (height %.2f)",
                mMarkerSelection.size(),
                marker.name.c_str(),
                static_cast<double>(x),
                static_cast<double>(z),
                static_cast<double>(y)
              );
            }
          }
        }
        mMarkerBefore = {};
        return true;
      }
      if (mBorderEdges != 0) {
        mBorderEdges = 0;
        ::ReleaseCapture();
        if (mBorderBefore.script != mDocument.Script() || mBorderBefore.areas != mDocument.SaveData().Areas()) {
          mDocument.SaveDataEdited(std::move(mBorderBefore));
          if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
            gpg::Logf("editor: playable area %d, %d to %d, %d", area->x0, area->z0, area->x1, area->z1);
          }
        }
        mBorderBefore = {};
        return true;
      }
      if (mUnitLining) {
        mUnitLining = false;
        ::ReleaseCapture();
        float toX = mUnitLineFrom[0];
        float toZ = mUnitLineFrom[1];
        (void)CursorGround(toX, toZ);
        if (std::hypot(toX - mUnitLineFrom[0], toZ - mUnitLineFrom[1]) < 1.0f) {
          PlaceUnits(mUnitLineFrom[0], mUnitLineFrom[1]);
          mLineEnd[0] = mUnitLineFrom[0];
          mLineEnd[1] = mUnitLineFrom[1];
          mLineEndKept = true;
        } else {
          PlaceUnitLine(mUnitLineFrom[0], mUnitLineFrom[1], toX, toZ);
        }
        return true;
      }
      if (mObjectStroke) {
        if (mPropLine) {
          mPropLine = false;
          float toX = 0.0f;
          float toZ = 0.0f;
          if (mTools != nullptr && CursorGround(toX, toZ)) {
            mLineEnd[0] = toX;
            mLineEnd[1] = toZ;
            mLineEndKept = true;
            const float dx = toX - mPropLineFromX;
            const float dz = toZ - mPropLineFromZ;
            const float length = std::hypot(dx, dz);
            const float spacing = std::max(0.5f, mTools->PropLineSpacing());
            const int count = static_cast<int>(length / spacing) + 1;
            const float along = std::atan2(dz, dx);
            for (int i = 0; i < count; ++i) {
              const float t = length > 0.0f ? static_cast<float>(i) * spacing / length : 0.0f;
              const float yaw = mTools->PropLineAlong() ? along : (mTools->RandomPropTurn() ? mNextPropYaw : 0.0f);
              PlaceProps(mPropLineFromX + dx * t, mPropLineFromZ + dz * t, yaw);
              RollPropYaw();
            }
            gpg::Logf("editor: %d props along a line of %.1f", count, static_cast<double>(length));
          }
        }
        EndObjectStroke();
        ::ReleaseCapture();
        return true;
      }
      if (mPaintingMask) {
        EndMaskStroke();
        ::ReleaseCapture();
        return true;
      }
      if (mPaintingTypes) {
        EndTypeStroke();
        ::ReleaseCapture();
        return true;
      }
      if (mPainting) {
        EndStroke();
        ::ReleaseCapture();
        return true;
      }
      return false;
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
      if (
        message == WM_RBUTTONDOWN && mTools != nullptr && mTools->WaterToolActive() &&
        mTools->WaterBodyPick() == EdTools::WaterPick::Outline
      ) {
        mTools->WaterBodyPick() = EdTools::WaterPick::None;
        return true;
      }
      // The right button with a brush that has an opposite (Raise and Lower, Paint and Erase): the opposite
      // stroke, as image editors do. Shift + right still box-selects; other brushes' right drag pans.
      if (message == WM_RBUTTONDOWN && (wParam & MK_SHIFT) == 0 && mTools != nullptr && !mPainting && !mPaintingMask) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        const HeightBrushMode height = mTools->CurrentHeightBrush().mode;
        const MaskBrushMode mask = mTools->CurrentMaskBrush().mode;
        if (
          mTools->TerrainToolActive() && (height == HeightBrushMode::Raise || height == HeightBrushMode::Lower) &&
          GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)
        ) {
          mPaintInverted = true;
          mStamped = false;
          mDabbed = false;
          mStrokeStartHeight = mMap->mTerrainRes->GetHeightAt(
            static_cast<std::int32_t>(std::lround(groundX)), static_cast<std::int32_t>(std::lround(groundZ))
          );
          mPainting = true;
          mDocument.Heights().BeginStroke();
          ::SetCapture(window);
          ::SetFocus(window);
          return true;
        }
        if (mTools->TextureToolActive() && (mask == MaskBrushMode::Paint || mask == MaskBrushMode::Erase)) {
          LoadMasks();
          if (!mDocument.Masks().texels.empty()) {
            mPaintInverted = true;
            mPaintingMask = true;
            mDocument.MaskUndo().BeginStroke();
            ::SetCapture(window);
            ::SetFocus(window);
            return true;
          }
        }
      }
      // Shift + right drag draws a selection box where the tool selects (markers, props, decals, units).
      if (message == WM_RBUTTONDOWN && (wParam & MK_SHIFT) != 0 && BoxSelectable()) {
        mBoxing = true;
        mBoxFrom = at;
        mBoxTo = at;
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      // The camera's gestures (Settings > Keys, camera mouse): by default middle drag orbits, Shift + middle and the
      // right button pan (a right click without a drag: the menu).
      if (message == WM_RBUTTONDOWN) {
        mRightDownAt = at;
        mRightPending = true;
      }
      {
        CameraGesture gesture = CameraGesture::Pan;
        if (!CameraGestureFor(
              message == WM_MBUTTONDOWN ? 2 : 1,
              (wParam & MK_CONTROL) != 0,
              (wParam & MK_SHIFT) != 0,
              ::GetKeyState(VK_MENU) < 0,
              gesture
            )) {
          return true; // that button and those keys move nothing
        }
        mDrag = gesture == CameraGesture::Orbit ? Drag::Orbit : gesture == CameraGesture::Zoom ? Drag::Zoom : Drag::Pan;
      }
      mDragFrom = at;
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
      // The end of a right-button (inverted) stroke.
      if (message == WM_RBUTTONUP && mPaintInverted && (mPainting || mPaintingMask)) {
        if (mPainting) {
          EndStroke();
        } else {
          EndMaskStroke();
        }
        mPaintInverted = false;
        ::ReleaseCapture();
        return true;
      }
      if (message == WM_RBUTTONUP && mBoxing) {
        mBoxTo = at;
        mBoxing = false;
        ::ReleaseCapture();
        FinishBoxSelect((wParam & MK_CONTROL) != 0);
        return true;
      }
      if (mDrag != Drag::None) {
        mDrag = Drag::None;
        ::ReleaseCapture();
      }
      if (
        message == WM_RBUTTONUP && std::exchange(mRightPending, false) && std::abs(at.x - mRightDownAt.x) <= 4 &&
        std::abs(at.y - mRightDownAt.y) <= 4
      ) {
        TakeContextPick(at);
        mContextAsk = true;
      }
      return true;
    case WM_MOUSEMOVE: {
      if (mPathDragging) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          PathMouseMove(groundX, groundZ);
        }
        return true;
      }
      if (mPaintingWaterMask) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          (void)DabWaterMask(groundX, groundZ);
        }
        return true;
      }
      if (mDragLive) {
        (void)GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), mLiveToX, mLiveToZ);
        return true;
      }
      if (mWaterBodyHandle != -2) {
        WaterBodyDrag(at);
        return true;
      }
      if (mBoxing) {
        mBoxTo = at;
        return true;
      }
      if (mDrag == Drag::None) {
        if (mDragUnits) {
          Wm3::Vec3f move{0.0f, 0.0f, 0.0f};
          float groundX = 0.0f;
          float groundZ = 0.0f;
          if (mGizmoDrag != GizmoPart::None) {
            move = GizmoDisplacement(at);
          } else if (
            GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mUnitDragFromX, groundZ - mUnitDragFromZ) > 0.05f
          ) {
            move = Wm3::Vec3f{groundX - mUnitDragFromX, 0.0f, groundZ - mUnitDragFromZ};
          }
          if (move.x != 0.0f || move.y != 0.0f || move.z != 0.0f) {
            for (std::size_t i = 0; i < mUnitSelection.size() && i < mUnitDragStart.size(); ++i) {
              const int index = UnitRefIndex(mUnitSelection[i].first, mUnitSelection[i].second);
              if (index < 0) {
                continue;
              }
              UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
              ref.position = GizmoPlace(mUnitDragStart[i], move, false, true);
              if (moho::MeshInstance* const instance = mUnits[static_cast<std::size_t>(index)]; instance != nullptr) {
                const moho::VTransform transform = UnitTransform(ref.position, ref.orientation);
                instance->SetStance(transform, transform);
              }
              FollowUnitMove(i, ref.position);
            }
            mUnitsMoved = true;
          }
          return true;
        }
        if (mAreaDrag != 0) {
          AreaMouseMove(at);
          return true;
        }
        if (mDragDecals && mGizmoDrag != GizmoPart::None) {
          moho::IDecalManager* const decals = mDocument.Decals();
          const Wm3::Vec3f move = GizmoDisplacement(at);
          if (decals != nullptr && (move.x != 0.0f || move.y != 0.0f || move.z != 0.0f)) {
            for (std::size_t i = 0; i < mDecalSelection.size() && i < mDecalDragStart.size(); ++i) {
              if (moho::CWldTerrainDecal* const decal = FindDecal(*decals, mDecalSelection[i]); decal != nullptr) {
                const float x =
                  mGizmoDrag == GizmoPart::Y ? mDecalDragStart[i][0] : SnapToGrid(mDecalDragStart[i][0] + move.x);
                const float z =
                  mGizmoDrag == GizmoPart::Y ? mDecalDragStart[i][2] : SnapToGrid(mDecalDragStart[i][2] + move.z);
                const float ground = mMap->mTerrainRes->GetHeightAt(
                  static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
                );
                decal->SetPosition(Wm3::Vec3f{x, std::max(mDecalDragStart[i][1] + move.y, ground), z});
                FollowDecalMove(i, decal->mPosition);
              }
            }
            mDecalsMoved = true;
          }
          return true;
        }
        if (mDragDecals) {
          float groundX = 0.0f;
          float groundZ = 0.0f;
          moho::IDecalManager* const decals = mDocument.Decals();
          if (
            decals != nullptr && GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mDecalDragFromX, groundZ - mDecalDragFromZ) > 0.05f
          ) {
            for (std::size_t i = 0; i < mDecalSelection.size() && i < mDecalDragStart.size(); ++i) {
              if (moho::CWldTerrainDecal* const decal = FindDecal(*decals, mDecalSelection[i]); decal != nullptr) {
                const float x = SnapToGrid(mDecalDragStart[i][0] + groundX - mDecalDragFromX);
                const float z = SnapToGrid(mDecalDragStart[i][2] + groundZ - mDecalDragFromZ);
                decal->SetPosition(Wm3::Vec3f{x, mDecalDragStart[i][1], z});
                FollowDecalMove(i, decal->mPosition);
              }
            }
            mDecalsMoved = true;
          }
          return true;
        }
        if (mDragMarkers && mGizmoDrag != GizmoPart::None) {
          const Wm3::Vec3f move = GizmoDisplacement(at);
          std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
          for (std::size_t i = 0; i < mMarkerSelection.size() && i < mMarkerDragStart.size(); ++i) {
            for (SaveEntry& marker : markers) {
              if (marker.name != mMarkerSelection[i]) {
                continue;
              }
              const std::string type = MarkerTypeOf(marker);
              const Wm3::Vec3f start{mMarkerDragStart[i][0], mMarkerDragStart[i][1], mMarkerDragStart[i][2]};
              const Wm3::Vec3f place = GizmoPlace(start, move, type == "Mass" || type == "Hydrocarbon");
              marker.Set("position", Vector3Value(place.x, place.y, place.z));
              FollowMarkerMove(i, place.x, place.z);
              break; // FollowMarkerMove sets other entries of `markers`; names are unique
            }
          }
          mMarkersMoved = mMarkersMoved || move.x != 0.0f || move.y != 0.0f || move.z != 0.0f;
          FollowAreas(move.x, move.z);
          return true;
        }
        if (mDragMarkers) {
          float groundX = 0.0f;
          float groundZ = 0.0f;
          if (
            GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mMarkerDragFromX, groundZ - mMarkerDragFromZ) > 0.05f
          ) {
            std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
            for (std::size_t i = 0; i < mMarkerSelection.size() && i < mMarkerDragStart.size(); ++i) {
              float x = mMarkerDragStart[i][0] + groundX - mMarkerDragFromX;
              float z = mMarkerDragStart[i][2] + groundZ - mMarkerDragFromZ;
              for (SaveEntry& marker : markers) {
                if (marker.name != mMarkerSelection[i]) {
                  continue;
                }
                const std::string type = MarkerTypeOf(marker);
                if (type == "Mass" || type == "Hydrocarbon") {
                  x = std::floor(x) + 0.5f;
                  z = std::floor(z) + 0.5f;
                } else {
                  x = SnapToGrid(x);
                  z = SnapToGrid(z);
                }
                const float y =
                  mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
                marker.Set("position", Vector3Value(x, y, z));
              }
              FollowMarkerMove(i, x, z);
            }
            FollowAreas(groundX - mMarkerDragFromX, groundZ - mMarkerDragFromZ);
            mMarkersMoved = true;
          }
          return true;
        }
        if (mBorderEdges != 0) {
          float groundX = 0.0f;
          float groundZ = 0.0f;
          std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea();
          const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
          if (
            area && field != nullptr && GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)
          ) {
            // On the game's 4-unit grid, inside the map, at least 4 units wide.
            const auto snap = [](const float value, const int limit) {
              return std::clamp(static_cast<int>(std::lround(value / 4.0f)) * 4, 0, limit);
            };
            const int w = field->width - 1;
            const int h = field->height - 1;
            EdDocument::PlayableRect next = *area;
            if ((mBorderEdges & 1) != 0)
              next.x0 = std::min(snap(groundX, w), next.x1 - 4);
            if ((mBorderEdges & 2) != 0)
              next.z0 = std::min(snap(groundZ, h), next.z1 - 4);
            if ((mBorderEdges & 4) != 0)
              next.x1 = std::max(snap(groundX, w), next.x0 + 4);
            if ((mBorderEdges & 8) != 0)
              next.z1 = std::max(snap(groundZ, h), next.z0 + 4);
            // Centred: the opposite edge as far in from its side.
            if (mTools != nullptr && mTools->BorderCentred()) {
              if ((mBorderEdges & 1) != 0)
                next.x1 = w - next.x0;
              if ((mBorderEdges & 4) != 0)
                next.x0 = w - next.x1;
              if ((mBorderEdges & 2) != 0)
                next.z1 = h - next.z0;
              if ((mBorderEdges & 8) != 0)
                next.z0 = h - next.z1;
              if (next.x1 - next.x0 < 4 || next.z1 - next.z0 < 4) {
                next = *area;
              }
            }
            if (!(next == *area)) {
              mDocument.SetPlayableArea(next);
              mOutsideStale = true;
            }
          }
          return true;
        }
        if (mDragSelection && mObjectStroke && mGizmoDrag != GizmoPart::None) {
          const Wm3::Vec3f move = GizmoDisplacement(at);
          if (move.x != 0.0f || move.y != 0.0f || move.z != 0.0f) {
            for (std::size_t i = 0; i < mSelection.size() && i < mDragStart.size(); ++i) {
              const Wm3::Vec3f place = GizmoPlace(mDragStart[i], move, false);
              MovePropTo(mSelection[i], place);
              FollowPropMove(i, place);
            }
          }
          return true;
        }
        if (mDragSelection && mObjectStroke) {
          float groundX = 0.0f;
          float groundZ = 0.0f;
          // Not until the cursor has moved: a click alone leaves the props where (and as high as) they are.
          if (
            GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mDragFromX, groundZ - mDragFromZ) > 0.05f
          ) {
            for (std::size_t i = 0; i < mSelection.size() && i < mDragStart.size(); ++i) {
              const float x = SnapToGrid(mDragStart[i].x + groundX - mDragFromX);
              const float z = SnapToGrid(mDragStart[i].z + groundZ - mDragFromZ);
              const Wm3::Vec3f place{
                x,
                mMap->mTerrainRes->GetHeightAt(
                  static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
                ),
                z
              };
              MovePropTo(mSelection[i], place);
              FollowPropMove(i, place);
            }
          }
          return true;
        }
        return mPainting || mPaintingMask || mObjectStroke;
      }
      const float dx = static_cast<float>(at.x - mDragFrom.x);
      const float dy = static_cast<float>(at.y - mDragFrom.y);
      mDragFrom = at;
      if (mDrag == Drag::Orbit) {
        mHeading -= dx * 0.006f;
        mPitch += dy * 0.006f;
      } else if (mDrag == Drag::Zoom) {
        // Down farther, up closer.
        mDistance = std::clamp(mDistance * std::pow(1.006f, dy), 15.0f, mMapExtent * 2.5f);
      } else {
        // The ground under the cursor follows it; off the map, a pan scaled by the distance.
        float fromX = 0.0f, fromZ = 0.0f, toX = 0.0f, toZ = 0.0f;
        const POINT from{at.x - static_cast<LONG>(dx), at.y - static_cast<LONG>(dy)};
        if (
          GroundAt(static_cast<float>(from.x), static_cast<float>(from.y), fromX, fromZ) &&
          GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), toX, toZ)
        ) {
          mTargetX += fromX - toX;
          mTargetZ += fromZ - toZ;
        } else {
          const float scale = mDistance * 0.0018f;
          const float sinH = std::sin(mHeading);
          const float cosH = std::cos(mHeading);
          mTargetX -= (dx * cosH - dy * sinH) * scale;
          mTargetZ -= (-dx * sinH - dy * cosH) * scale;
        }
      }
      ApplyCamera();
      return true;
    }
    case WM_MOUSEWHEEL: {
      // Toward the point under the cursor, as the game's camera zooms; the camera's tilt and turn stay.
      // Scaling the camera and its target together about that point keeps the point under the cursor.
      const float steps = static_cast<float>(GET_WHEEL_DELTA_WPARAM(wParam)) / WHEEL_DELTA;
      const float before = mDistance;
      const float after = std::clamp(before * std::pow(0.85f, steps), 15.0f, mMapExtent * 2.5f);
      POINT cursor{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
      ::ScreenToClient(window, &cursor);
      float pointX = 0.0f, pointZ = 0.0f;
      if (GroundAt(static_cast<float>(cursor.x), static_cast<float>(cursor.y), pointX, pointZ)) {
        const float scale = after / before;
        mTargetX = pointX + (mTargetX - pointX) * scale;
        mTargetZ = pointZ + (mTargetZ - pointZ) * scale;
      }
      mDistance = after;
      ApplyCamera();
      return true;
    }
    case WM_KEYDOWN:
    case WM_KEYUP: {
      const bool down = message == WM_KEYDOWN;
      // Undo, redo, copy, paste, duplicate and framing the map are commands with keys (EdApp.cpp runs them before
      // the scene sees the key); the keys here are the tools' own: paths, the camera, Delete and Q/E for a tool.
      mFast = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
      if (down && mPathEdit != nullptr && mPathEdit->editing && PathKey(wParam)) {
        return true;
      }
      // G and R: the selection follows the cursor until a click or Enter (Escape puts it back); X or Z locks an axis,
      // digits type an exact distance or angle.
      if (mModal.on) {
        if (!down) {
          return true;
        }
        if (wParam == VK_RETURN) {
          EndModal(true);
        } else if (wParam == VK_ESCAPE) {
          EndModal(false);
        } else if (wParam == 'X' || wParam == 'Z') {
          const char axis = static_cast<char>(wParam);
          mModal.input.axis = mModal.input.axis == axis ? 0 : axis;
          UpdateModal();
        } else {
          const int key = wParam == VK_OEM_PERIOD || wParam == VK_DECIMAL ? '.'
            : wParam == VK_OEM_MINUS || wParam == VK_SUBTRACT             ? '-'
            : wParam >= VK_NUMPAD0 && wParam <= VK_NUMPAD9 ? static_cast<int>('0' + (wParam - VK_NUMPAD0))
            : wParam == VK_BACK                            ? 8
                                                           : static_cast<int>(wParam);
          if (TypeIntoNumber(mModal.input.typed, key)) {
            UpdateModal();
          }
        }
        return true;
      }
      if (
        down && (wParam == 'G' || wParam == 'R') && (::GetKeyState(VK_CONTROL) & 0x8000) == 0 && mTools != nullptr &&
        mTools->SelectToolActive() && SelectedKind() != PickKind::None
      ) {
        (void)BeginModal(wParam == 'R');
        return true;
      }
      if (
        down && mTools != nullptr && mTools->DecalsToolActive() && mTools->DecalPathMode() &&
        (wParam == VK_RETURN || wParam == VK_BACK || wParam == VK_ESCAPE)
      ) {
        if (wParam == VK_RETURN) {
          PlaceDecalPath();
        } else if (wParam == VK_BACK) {
          RemoveLastDecalPathPoint();
        } else {
          ClearDecalPath();
        }
        return true;
      }
      if (
        down && mTools != nullptr && mTools->WaterToolActive() && mTools->WaterBodyPick() != EdTools::WaterPick::None &&
        (wParam == VK_RETURN || wParam == VK_ESCAPE || wParam == VK_BACK)
      ) {
        std::vector<WaterBody>& bodies = mTools->EditedWaterBodies();
        const int chosen = mTools->SelectedWaterBody();
        if (wParam == VK_BACK) {
          if (
            mTools->WaterBodyPick() == EdTools::WaterPick::Outline && chosen >= 0 &&
            chosen < static_cast<int>(bodies.size()) && !bodies[static_cast<std::size_t>(chosen)].outline.empty()
          ) {
            bodies[static_cast<std::size_t>(chosen)].outline.pop_back();
            mTools->WaterBodiesChanged(true);
          }
          return true;
        }
        if (
          wParam == VK_ESCAPE && mTools->WaterBodyIsNew() && chosen >= 0 && chosen < static_cast<int>(bodies.size())
        ) {
          bodies.erase(bodies.begin() + chosen);
          mTools->SelectWaterBody(chosen - 1);
          mTools->WaterBodiesChanged(true);
        }
        mTools->WaterBodyIsNew() = false;
        mTools->WaterBodyPick() = EdTools::WaterPick::None;
        return true;
      }
      if (down && wParam == VK_DELETE && mTools != nullptr && mTools->UnitsToolActive() && !mUnitSelection.empty()) {
        DeleteSelectedUnits();
        return true;
      }
      if (down && wParam == VK_DELETE && mTools != nullptr && mTools->DecalsToolActive() && !mDecalSelection.empty()) {
        DeleteSelectedDecals();
        return true;
      }
      if (
        down && wParam == VK_DELETE && mTools != nullptr && mTools->MarkersToolActive() && !mMarkerSelection.empty()
      ) {
        DeleteSelectedMarkers();
        return true;
      }
      // The Select tool's Delete: what it has selected, of whichever kind.
      if (down && wParam == VK_DELETE && mTools != nullptr && mTools->SelectToolActive()) {
        switch (SelectedKind()) {
        case PickKind::Marker:
          DeleteSelectedMarkers();
          return true;
        case PickKind::Unit:
          DeleteSelectedUnits();
          return true;
        case PickKind::Decal:
          DeleteSelectedDecals();
          return true;
        default:
          break;
        }
      }
      if (
        down && mTools != nullptr && mTools->SelectToolActive() && !mSelection.empty() &&
        SelectedKind() == PickKind::Prop
      ) {
        if (wParam == VK_DELETE) {
          DeleteSelection();
          return true;
        }
      }
      // Q / E turn whatever is selected (props, markers, units, decals) by the Select tool's turn step.
      if (
        down && (wParam == 'Q' || wParam == 'E') && mTools != nullptr && mTools->SelectToolActive() &&
        (!mSelection.empty() || !mMarkerSelection.empty() || !mUnitSelection.empty() || !mDecalSelection.empty())
      ) {
        const float step = mTools->TurnStepDegrees() * 0.017453293f;
        if (TurnEverySelected(wParam == 'Q' ? -step : step)) {
          return true;
        }
      }
      switch (wParam) {
      case 'W':
      case VK_UP:
        mForward = down;
        return true;
      case 'S':
      case VK_DOWN:
        mBack = down;
        return true;
      case 'A':
      case VK_LEFT:
        mLeft = down;
        return true;
      case 'D':
      case VK_RIGHT:
        mRight = down;
        return true;
      case VK_SHIFT:
        return false;
      default:
        return false;
      }
    }
    case WM_KILLFOCUS:
      mForward = mBack = mLeft = mRight = false;
      return false;
    case WM_CAPTURECHANGED:
      mDrag = Drag::None;
      if (mPainting) {
        EndStroke();
      }
      return false;
    default:
      return false;
    }
  }
} // namespace faf::editor
