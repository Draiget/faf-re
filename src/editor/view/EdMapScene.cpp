#include "editor/view/EdMapScene.h"
#include "editor/doc/EdUnitFate.h"

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

#include "editor/EdTools.h"
#include "moho/misc/StartupHelpers.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "moho/app/CScApp.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
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
      mScene.DrawBrushRings();
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

  EdMapScene::EdMapScene(
    EdDocument& document
  )
    : mDocument(document)
  {}

  EdMapScene::~EdMapScene()
  {
    Detach();
  }

  void EdMapScene::DrawBrushRings()
  {
    const std::optional<EdDocument::PlayableRect> area = mMap != nullptr ? mDocument.PlayableArea() : std::nullopt;
    if (
      mMap == nullptr || mCamera == nullptr || mTools == nullptr ||
      (!mTools->TerrainToolActive() && !mTools->TextureToolActive() && !mTools->PropsToolActive() &&
       !mTools->SelectToolActive() && mSelection.empty() && !area && mDocument.SaveData().Markers().empty() &&
       mDocument.SaveData().Chains().empty() && !mTools->ShowGrid() && !mTools->DecalsToolActive() &&
       !mTools->UnitsToolActive() && !mTools->EditingBorder() && !mTools->WaterToolActive() &&
       mTools->CheckPins().empty() && !mTools->ShowingPathing() && !mTools->ShowSlope() && !mTools->ShowKmGrid() &&
       !mRulerShown && !mBoxing) ||
      moho::ren_Viewport == nullptr
    ) {
      return;
    }
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (field == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();

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
    const auto turnAxis = [&]() {
      moho::CD3DPrimBatcher::Vertex top = groundVertex(w * 0.5f, h * 0.5f, kMirrorColor, 0.0f);
      moho::CD3DPrimBatcher::Vertex bottom = top;
      top.mY += std::max(w, h) * 0.15f;
      batcher->DrawLine(bottom, top);
    };
    const bool square = field->width == field->height;
    switch (brush.symmetry) {
    case Symmetry::LeftRight:
      groundLine(w * 0.5f, 0.0f, w * 0.5f, h);
      break;
    case Symmetry::TopBottom:
      groundLine(0.0f, h * 0.5f, w, h * 0.5f);
      break;
    case Symmetry::DiagonalBack:
      if (square) {
        groundLine(0.0f, 0.0f, w, h);
      }
      break;
    case Symmetry::DiagonalForward:
      if (square) {
        groundLine(w, 0.0f, 0.0f, h);
      }
      break;
    case Symmetry::HalfTurn:
      turnAxis();
      break;
    case Symmetry::BothAxes:
      groundLine(w * 0.5f, 0.0f, w * 0.5f, h);
      groundLine(0.0f, h * 0.5f, w, h * 0.5f);
      break;
    case Symmetry::BothDiagonals:
      if (square) {
        groundLine(0.0f, 0.0f, w, h);
        groundLine(w, 0.0f, 0.0f, h);
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
          groundLine(w * 0.5f, h * 0.5f, w * 0.5f + dx * reach, h * 0.5f + dz * reach);
        }
      }
      break;
    default:
      break;
    }

    if (!walls.empty()) {
      batcher->DrawQuads(walls.data(), static_cast<std::uint32_t>(walls.size() / 4));
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
        const int hot =
          GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz) ? BorderEdgesAt(gx, gz) : 0;
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
      if (GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz)) {
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
        std::string error;
        if (!ParseAdaptiveTables(mAdaptiveText, mAdaptive, error)) {
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
      }
    }
    // The slope view: each run of cells in its band's colour (flat ones left out), rebuilt when the heights change.
    if (mTools->ShowSlope()) {
      if (mSlopeRuns.empty() || ++mSlopeFrames % 15 == 0) {
        std::uint64_t hash = 1469598103934665603ULL;
        const std::size_t count = static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height);
        for (std::size_t i = 0; i < count; i += 7) {
          hash = (hash ^ field->data[i]) * 1099511628211ULL;
        }
        if (hash != mSlopeHeights || mSlopeRuns.empty()) {
          mSlopeHeights = hash;
          const std::vector<std::uint8_t> bands = SlopeBands(field->data, field->width, field->height, 1.0f / 128.0f);
          mSlopeRuns = TerrainTypeRuns(bands.data(), field->width - 1, field->height - 1, 0);
        }
      }
      static constexpr std::uint32_t kBand[4] = {0u, 0x70F0E040u, 0x80F09030u, 0x90F04030u};
      std::vector<moho::CD3DPrimBatcher::Vertex> quads;
      quads.reserve(mSlopeRuns.size() * 4);
      for (const TerrainTypeRun& run : mSlopeRuns) {
        const std::uint32_t color = kBand[run.code & 3];
        const float x0 = static_cast<float>(run.x0);
        const float x1 = static_cast<float>(run.x1);
        const float z0 = static_cast<float>(run.z);
        quads.push_back(groundVertex(x0, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z0 + 1.0f, color, 0.3f));
        quads.push_back(groundVertex(x0, z0 + 1.0f, color, 0.3f));
      }
      if (!quads.empty()) {
        batcher->DrawQuads(quads.data(), static_cast<std::uint32_t>(quads.size() / 4));
      }
    } else if (!mSlopeRuns.empty()) {
      mSlopeRuns.clear();
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
    // The chains: a line through each one's markers in order, and a small post at its first.
    if (mTools->MarkersToolActive()) {
      for (const MarkerChain& chain : mDocument.SaveData().Chains()) {
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
          // Pink, doubled a little above: apart from the path nodes' blue, green and white links.
          moho::CD3DPrimBatcher::Vertex vertex = groundVertex(x, z, 0xFFFF50D0u, 2.0f);
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
      quads.reserve(mTypeRuns.size() * 4);
      for (const TerrainTypeRun& run : mTypeRuns) {
        const std::uint32_t color = (mTools->TerrainTypeColor(run.code) & 0x00FFFFFFu) | 0x90000000u;
        const float x0 = static_cast<float>(run.x0);
        const float x1 = static_cast<float>(run.x1);
        const float z0 = static_cast<float>(run.z);
        quads.push_back(groundVertex(x0, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z0, color, 0.3f));
        quads.push_back(groundVertex(x1, z0 + 1.0f, color, 0.3f));
        quads.push_back(groundVertex(x0, z0 + 1.0f, color, 0.3f));
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
      if (mDragMarkers && mMarkersMoved) {
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
        }
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
      if (GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), mx, mz)) {
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
    if (!GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
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
    mWorldView =
      std::make_unique<moho::SimpleRenderWorldView>(const_cast<moho::GeomCamera3*>(&mCamera->CameraGetView()));
    moho::ren_Viewport->AddWorldView(mWorldView.get(), 0, 0);
    if (mRingHook == nullptr) {
      mRingHook = std::make_unique<RingHook>(*this);
    }
    moho::ED_SetHook(mRingHook.get());
    gpg::Logf("editor: the viewport shows %s", mDocument.Path().c_str());
    // The symmetry the map was made with, from its heights, for the brushes and the object tools.
    if (mTools != nullptr) {
      const DetectedSymmetry& found = mDocument.Facts().symmetry;
      mTools->SetDetectedSymmetry(
        found.symmetry == Symmetry::None ? -1 : static_cast<int>(found.symmetry), found.turns, found.matched
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
    if (
      mTools == nullptr || field == nullptr ||
      !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)
    ) {
      return;
    }
    HeightBrush brush = mTools->CurrentHeightBrush();
    brush.flattenTo = mFlattenTo;
    brush.seed = ++mWaterErodeSeed; // Water erode: new droplets every step
    brush.noiseSeed = mNoiseSeed;   // Noise: one pattern for the stroke
    // A right-button stroke does the opposite: Raise lowers, Lower raises, Water erode deposits.
    if (mPaintInverted) {
      brush.mode = brush.mode == HeightBrushMode::Raise ? HeightBrushMode::Lower
        : brush.mode == HeightBrushMode::Lower          ? HeightBrushMode::Raise
        : brush.mode == HeightBrushMode::WaterErode     ? HeightBrushMode::Deposit
        : brush.mode == HeightBrushMode::Smooth         ? HeightBrushMode::Sharpen
                                                        : brush.mode;
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
      if (GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
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
        strata.find(',') == std::string::npos ? "" : "s",
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

  bool EdMapScene::ClearMaskLayer(
    const int layer,
    std::string& message
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      message = "No map's masks to change.";
      return false;
    }
    const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
    mDocument.MaskUndo().BeginStroke();
    mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
    for (std::uint64_t& texel : masks.texels) {
      texel = WithMaskByte(texel, layer, 0);
    }
    WholeMaskChanged(whole);
    message = "Cleared the mask of layer " + std::to_string(layer + 1);
    return true;
  }

  bool EdMapScene::ImportMaskLayer(
    const int layer,
    const std::filesystem::path& file,
    std::string& message
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask) {
      message = "No map's masks to change.";
      return false;
    }
    HeightImage image;
    std::string error;
    if (!ReadHeightImage(file, masks.width, masks.height, image, error)) {
      message = "Mask import failed: " + error;
      return false;
    }
    image = ResampleHeights(image, masks.width, masks.height);
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
    message = "Imported the mask of layer " + std::to_string(layer + 1) + " from " + file.string();
    return true;
  }

  bool EdMapScene::SetMaskLayer(
    const int layer,
    const TexImage& image,
    std::string& message
  )
  {
    LoadMasks();
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mPaintingMask || layer < 0 || layer > 7 || image.size <= 0) {
      message = "No map's masks to change.";
      return false;
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
    message = "Set the mask of stratum " + std::to_string(layer + 1) + " from the material graph";
    return true;
  }

  bool EdMapScene::ExportMaskLayer(
    const int layer,
    const std::filesystem::path& file,
    std::string& message
  )
  {
    LoadMasks();
    const EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty()) {
      message = "No map's masks to export.";
      return false;
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
    std::string error;
    if (!WriteHeightImage(file, image, error)) {
      message = "Mask export failed: " + error;
      return false;
    }
    message = "Exported the mask of layer " + std::to_string(layer + 1) + " to " + file.string();
    return true;
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
    const std::string& shader
  )
  {
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    // The masks stay as they are: the brushes encode for the new shader from now on (C1), and paint stored for the
    // old one shows differently when the two read masks differently.
    if (
      const std::uint8_t before = RemappedStrata(strata.mShaderName.c_str()), after = RemappedStrata(shader);
      before != after && !mDocument.Masks().texels.empty()
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
    if (
      mTools == nullptr || field == nullptr || masks.texels.empty() ||
      !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)
    ) {
      return;
    }
    MaskBrush brush = mTools->CurrentMaskBrush();
    brush.step = ++mMaskSteps;
    // Stored for the map's shader (most read saturate(2m-1)): the brush works in the weight that shows.
    brush.remapped = RemappedStrata(TerrainShader());
    // A right-button stroke does the opposite: Paint erases, Erase paints.
    if (mPaintInverted) {
      brush.mode = brush.mode == MaskBrushMode::Paint ? MaskBrushMode::Erase
        : brush.mode == MaskBrushMode::Erase          ? MaskBrushMode::Paint
                                                      : brush.mode;
    }
    const MaskTerrain terrain{field->data, field->width, field->height};
    for (const SampleRect& rect : MaskBrushRects(masks.width, masks.height, terrain, groundX, groundZ, brush)) {
      mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
    }
    const std::vector<SampleRect> rects = ApplyMaskBrush(
      masks.texels.data(), masks.width, masks.height, terrain, groundX, groundZ, brush, std::min(frameSeconds, 0.1f)
    );
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

  void EdMapScene::EndMaskStroke()
  {
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
        static_cast<int>(mCheckedWith.symmetry),
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
      static_cast<int>(mCheckedWith.symmetry),
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
    if (mTools->TextureToolActive()) {
      LoadMasks();
      EdDocument::MaskGrid& masks = mDocument.Masks();
      if (masks.texels.empty()) {
        return;
      }
      const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
      mDocument.MaskUndo().BeginStroke();
      mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
      (void)MakeMasksSymmetric(masks.texels.data(), masks.width, masks.height, brush.symmetry, brush.turns);
      WholeMaskChanged(whole);
      gpg::Logf("editor: copied the source part of the masks to their other copies");
      RunSymmetryCheck();
      return;
    }
    // One undo step over the whole map.
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    (void)MakeSymmetric(field->data, field->width, field->height, brush.symmetry, brush.turns);
    mDocument.Heights().EndStroke(field->data);
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    RefreshHeights({whole});
    mDocument.SetModified(true);
    gpg::Logf("editor: copied the source part of the map to its other copies");
    RunSymmetryCheck();
  }

  bool EdMapScene::ImportHeights(
    const std::filesystem::path& file,
    const float scale,
    std::string& message
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting) {
      message = "No map is open in the view.";
      return false;
    }
    HeightImage image;
    std::string error;
    if (!ReadHeightImage(file, field->width, field->height, image, error)) {
      message = "Import failed: " + error;
      return false;
    }
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
    message = "Imported heights from " + file.string() + " (" + std::to_string(readWidth) + " x " +
      std::to_string(readHeight) + (readWidth != field->width || readHeight != field->height ? ", resampled" : "") +
      ")";
    return true;
  }

  bool EdMapScene::ExportHeights(
    const std::filesystem::path& file,
    const int width,
    const float scale,
    std::string& message
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      message = "No map is open in the view.";
      return false;
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
    std::string error;
    if (!WriteHeightImage(file, image, error)) {
      message = "Export failed: " + error;
      return false;
    }
    message = "Exported heights to " + file.string() + " (" + std::to_string(image.width) + " x " +
      std::to_string(image.height) + ")";
    return true;
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
    mDocument.Heights().BeginStroke();
    for (const SampleRect& rect : HeightBrushRects(field->width, field->height, x, z, brush)) {
      mDocument.Heights().BeforeWrite(field->data, rect);
    }
    std::vector<SampleRect> rects;
    const float stepSeconds = raise ? 0.1f : 1.0f / 60.0f;
    if (mode == HeightBrushMode::Stamp && brush.stamp != nullptr) {
      // A drag of 40 samples along +x over `seconds`, as the mouse would make it.
      mStamped = false;
      int dabSteps = 0;
      for (float done = 0.0f; done <= seconds; done += stepSeconds, ++dabSteps) {
        const std::vector<SampleRect> step = PaintStamps(brush, x + 40.0f * std::min(1.0f, done / seconds), z);
        rects.insert(rects.end(), step.begin(), step.end());
      }
      mStamped = false;
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
        static_cast<int>(mode),
        static_cast<double>(x),
        static_cast<double>(z),
        static_cast<double>(brush.radius),
        static_cast<int>(brush.symmetry),
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
    // In front of a play: the same heights into it (its rendered terrain now, its sim at its next beat; WPE.40).
    if (mOverPlay && mSessionMap != nullptr) {
      std::vector<HeightRect> live;
      live.reserve(rects.size());
      for (const SampleRect& rect : rects) {
        live.push_back({rect.x0, rect.z0, rect.x1, rect.z1});
      }
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
        heights != nullptr &&
        GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ) && groundX >= 0.0f &&
        groundZ >= 0.0f && groundX < static_cast<float>(heights->width - 1) &&
        groundZ < static_cast<float>(heights->height - 1)
      ) {
        if (mRuling) {
          if ((::GetKeyState(VK_LBUTTON) & 0x8000) != 0) {
            mRulerTo[0] = groundX;
            mRulerTo[1] = groundZ;
            mTools->SetRulerText(DistanceText(std::hypot(mRulerTo[0] - mRulerFrom[0], mRulerTo[1] - mRulerFrom[1])));
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
    // The type under the cursor, for the panel.
    if (mTools != nullptr && mTools->PaintingTerrainTypes()) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      int width = 0;
      int height = 0;
      const std::uint8_t* const cells = mDocument.TerrainTypeCells(width, height);
      int under = -1;
      if (
        cells != nullptr && GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ) &&
        groundX >= 0.0f && groundZ >= 0.0f && groundX < static_cast<float>(width) &&
        groundZ < static_cast<float>(height)
      ) {
        under = cells
          [static_cast<std::size_t>(groundZ) * static_cast<std::size_t>(width) + static_cast<std::size_t>(groundX)];
      }
      mTools->SetTerrainTypeUnderCursor(under);
    }
    if (
      mObjectStroke && mTools != nullptr && mTools->PropsToolActive() &&
      mTools->CurrentPropMode() != EdTools::PropMode::Single
    ) {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
        if (mTools->CurrentPropMode() == EdTools::PropMode::Erase || (::GetKeyState(VK_SHIFT) & 0x8000) != 0) {
          EraseProps(groundX, groundZ);
        } else {
          // Scatter: props a second at random points inside the brush.
          mScatterDue += mTools->PropDensity() * std::min(frameSeconds, 0.1f);
          const float radius = mTools->CurrentHeightBrush().radius;
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
      mTools->SetSelectInfo(SelectionText(), HoverText());
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
              !previewHidden.empty() && previewHidden.count({mUnitRefs[i].army, mUnitRefs[i].name}) != 0;
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
      std::string error;
      if (!ParseUnitGroup(army.Get("Units"), group, error)) {
        ++unreadable;
        gpg::Warnf("editor: %s's units unreadable: %s", army.name.c_str(), error.c_str());
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
          army.name, unit->name, transform.pos_, {unit->orientation[0], unit->orientation[1], unit->orientation[2]}
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
        std::string error;
        if (entry.name != army || !ParseUnitGroup(entry.Get("Units"), root, error)) {
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
    if ((key == 'C' || key == 'D') && CopySelection() == 0) {
      return;
    }
    if (key == 'D') {
      PasteAt(mClipboard.centre[0] + 8.0f, mClipboard.centre[1] + 8.0f);
    } else if (key == 'V') {
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
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
    // The tool's own kind; the Select tool copies whichever kind is selected (it had only props, so a Shift+drag or a
    // Ctrl+D of its markers, units or decals copied nothing).
    const PickKind selected = mTools->SelectToolActive() ? SelectedKind() : PickKind::None;
    if (mTools->MarkersToolActive() || selected == PickKind::Marker) {
      copied.kind = Clipboard::Kind::Markers;
      for (const SaveEntry& marker : SelectedMarkers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (ShownMarkerPosition(marker, x, y, z)) {
          copied.markers.push_back(marker);
          add(x, z);
        }
      }
    } else if (selected == PickKind::Prop && mMap->mProps != nullptr) {
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
    } else if (mTools->UnitsToolActive() || selected == PickKind::Unit) {
      copied.kind = Clipboard::Kind::Units;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup group;
        std::string error;
        if (!ParseUnitGroup(entry.Get("Units"), group, error)) {
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
    } else if ((mTools->DecalsToolActive() || selected == PickKind::Decal) && mDocument.Decals() != nullptr) {
      copied.kind = Clipboard::Kind::Decals;
      for (const int index : mDecalSelection) {
        if (const moho::CWldTerrainDecal* const decal = FindDecal(*mDocument.Decals(), index); decal != nullptr) {
          const DecalState state = CaptureDecal(*decal);
          copied.decals.push_back(state);
          add(state.position[0], state.position[2]);
        }
      }
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
    switch (mClipboard.kind) {
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
      if (pasted > 0) {
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
      if (pasted > 0) {
        mDocument.PropsEdited(std::move(before));
        mDocument.SetModified(true);
      }
      break;
    }
    case Clipboard::Kind::Units: {
      int highest = 0;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        UnitGroup group;
        std::string error;
        if (ParseUnitGroup(entry.Get("Units"), group, error)) {
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
      if (pasted > 0) {
        mDocument.DecalsEdited(std::move(before));
      }
      break;
    }
    case Clipboard::Kind::None:
      break;
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
       (mTools->DecalsToolActive() && !mTools->DecalPlaceMode() && !mTools->DecalPathMode()));
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
    } else if (mTools->SelectToolActive() && mMap->mProps != nullptr) {
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

  void EdMapScene::SetRuler(
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    mRulerShown = true;
    mRuling = false;
    mRulerFrom[0] = x0;
    mRulerFrom[1] = z0;
    mRulerTo[0] = x1;
    mRulerTo[1] = z1;
    if (mTools != nullptr) {
      mTools->SetRulerText(DistanceText(std::hypot(x1 - x0, z1 - z0)));
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
    if (
      mTools == nullptr || cells == nullptr || field == nullptr ||
      !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)
    ) {
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
    } else if (mTools->DecalsToolActive() && !mTools->DecalPlaceMode() && !mTools->DecalPathMode()) {
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
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!MarkerHidden(markers[i]) && ShownMarkerPosition(markers[i], x, y, z)) {
        consider(PickKind::Marker, static_cast<int>(i), Wm3::Vec3f{x, y, z}, 4.0f, 14.0f);
      }
    }
    for (std::size_t i = 0; i < mUnitRefs.size() && (mTools == nullptr || mTools->ShowUnits()); ++i) {
      if (
        mTools != nullptr && !mTools->PreviewHiddenUnits().empty() &&
        mTools->PreviewHiddenUnits().count({mUnitRefs[i].army, mUnitRefs[i].name}) != 0
      ) {
        continue; // hidden by the lobby preview
      }
      consider(PickKind::Unit, static_cast<int>(i), mUnitRefs[i].position, 2.5f, 16.0f);
    }
    if (mMap->mProps != nullptr && (mTools == nullptr || mTools->ShowProps())) {
      const auto& entries = mMap->mProps->mEntries;
      for (std::size_t i = 0; i < entries.size(); ++i) {
        consider(PickKind::Prop, static_cast<int>(i), entries[i].mTransform.pos_, 3.0f, 12.0f);
      }
    }
    // Nothing near: the decal under the cursor.
    float gx = 0.0f;
    float gz = 0.0f;
    if (best.kind == PickKind::None && GroundAt(cursor.x, cursor.y, gx, gz)) {
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
      break;
    case PickKind::Marker:
      mDragMarkers = true;
      mMarkersMoved = false;
      mMarkerDragFromX = groundX;
      mMarkerDragFromZ = groundZ;
      mMarkerBefore = mDocument.SaveDataNow();
      mMarkerDragStart.clear();
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
        std::string error;
        if (entry.name == ref.army && ParseUnitGroup(entry.Get("Units"), group, error)) {
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

  std::string EdMapScene::HoverText() const
  {
    float gx = 0.0f;
    float gz = 0.0f;
    if (mMap == nullptr || !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz)) {
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
    return (!mTools->HiddenMarkerTypes().empty() && mTools->HiddenMarkerTypes().count(MarkerTypeOf(marker)) != 0) ||
      (!mTools->PreviewHiddenMarkers().empty() && mTools->PreviewHiddenMarkers().count(marker.name) != 0);
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

  bool EdMapScene::ImportMarkerFile(
    const std::string& text,
    MarkerImport& result,
    std::string& error
  )
  {
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    std::vector<SaveEntry> markers = mDocument.SaveData().Markers();
    if (!MarkersFromFafmapmarkers(text, markers, result, error, mDocument.ArmyNamesInUse())) {
      return false;
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
    return true;
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
      if (selected == target || covered.count(selected) != 0 || !position(selected, sourceX, sourceZ, sourceType)) {
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
          EmitterBlueprint emitter;
          FlatBlueprint flat;
          std::string error;
          if (path.empty() || !ReadGameFile(path, text)) {
            continue;
          }
          auto preview = std::make_unique<EdParticlePreview>();
          if (ParseEmitter(text, emitter, error)) {
            preview->SetEmitter(emitter);
          } else if (ParseFlatBlueprint(text, flat, error)) {
            preview->SetFlat(flat);
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
      it = seen.count(it->first) == 0 ? mEffects.erase(it) : std::next(it);
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
      if ((!all && !start && !resource) || MarkerHidden(marker)) {
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
      if (
        marker.Get("resource").find("true") == std::string::npos || MarkerHidden(marker) ||
        !ShownMarkerPosition(marker, x, y, z)
      ) {
        continue;
      }
      const Deposit* const deposit = type == "Mass" ? &mass : &hydro;
      if (deposit->mesh != nullptr) {
        wanted[marker.name] = {deposit, Wm3::Vec3f{x, y, z}};
      }
    }
    for (auto it = mDeposits.begin(); it != mDeposits.end();) {
      if (wanted.count(it->first) == 0) {
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

  void EdMapScene::PlaceDecals(
    const float x,
    const float z
  )
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    moho::IDecalManager* const decals = mDocument.Decals();
    if (mTools == nullptr || field == nullptr || decals == nullptr) {
      return;
    }
    const std::string& texture = mTools->DecalTexturePath();
    if (texture.empty()) {
      gpg::Warnf("editor: pick a decal texture first");
      return;
    }
    const std::string pair = mTools->DecalPairPath();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float yaw = mTools->DecalTurnDegrees() * kPi / 180.0f;
    if (mTools->RandomDecalTurn()) {
      mDecalSeed = mDecalSeed * 1664525U + 1013904223U;
      yaw = static_cast<float>(mDecalSeed >> 8) / 16777216.0f * 2.0f * kPi;
    }
    // Each copy's heading is the cursor's carried through the symmetry (the copies of a point one unit ahead).
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies],
      aheadZ[kMaxSymmetryCopies];
    const int copies =
      HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(
      field->width, field->height, x + std::cos(yaw), z + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ
    );
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    mDecalSelection.clear();
    for (int c = 0; c < copies; ++c) {
      if (
        centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
        centreZ[c] > static_cast<float>(field->height - 1)
      ) {
        continue;
      }
      const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
      const DecalFootprint footprint =
        DecalAround(centreX[c], centreZ[c], mTools->DecalSizeX(), mTools->DecalSizeZ(), heading);
      DecalState state;
      state.type = DecalTypeForTexture(texture);
      state.names[0] = texture;
      state.scale[0] = footprint.sizeX;
      state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
      state.scale[2] = footprint.sizeZ;
      state.position[0] = footprint.x;
      state.position[1] = mMap->mTerrainRes->GetHeightAt(
        static_cast<std::int32_t>(std::lround(centreX[c])), static_cast<std::int32_t>(std::lround(centreZ[c]))
      );
      state.position[2] = footprint.z;
      state.orientation[1] = heading;
      state.cutoff = mTools->DecalCutoff();
      // An albedo's spec map is its second texture, as the game's maps keep them.
      state.names[1] = pair;
      if (const moho::CWldTerrainDecal* const decal = AddDecal(*decals, state); decal != nullptr) {
        mDecalSelection.push_back(decal->mIndex);
      }
    }
    if (!mDecalSelection.empty()) {
      mDocument.DecalsEdited(std::move(before));
      gpg::Logf(
        "editor: %zu decals placed (%s%s%s, %.1f x %.1f), %d decals now",
        mDecalSelection.size(),
        texture.c_str(),
        pair.empty() ? "" : " with ",
        pair.c_str(),
        static_cast<double>(mTools->DecalSizeX()),
        static_cast<double>(mTools->DecalSizeZ()),
        decals->GetDecalCount()
      );
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
    if (mDragDecals || !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz)) {
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

  void EdMapScene::EndObjectStroke()
  {
    if (mObjectStroke && mObjectsChanged) {
      const std::size_t before = mObjectBefore.entries.size();
      mDocument.PropsEdited(std::move(mObjectBefore));
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
    const Wm3::Quatf turn(std::cos(radians * 0.5f), 0.0f, std::sin(radians * 0.5f), 0.0f);
    auto& entries = mMap->mProps->mEntries;
    for (const int index : mSelection) {
      moho::CWldPropEntry& entry = entries[static_cast<std::size_t>(index)];
      entry.mTransform.orient_ = turn * entry.mTransform.orient_;
      const PropRecord record = PropRecordFor(entry.mBlueprintPath.c_str(), entry.mTransform);
      entry.mTransform = record.loaded;
      mDocument.SetPropRecord(static_cast<std::size_t>(index), record);
      if (static_cast<std::size_t>(index) < mProps.size() && mProps[static_cast<std::size_t>(index)] != nullptr) {
        mProps[static_cast<std::size_t>(index)]->SetStance(entry.mTransform, entry.mTransform);
      }
    }
    mObjectsChanged = true;
    mDocument.SetModified(true);
    EndObjectStroke();
  }

  void EdMapScene::DeleteSelection()
  {
    if (mSelection.empty() || mMap == nullptr) {
      return;
    }
    BeginObjectStroke();
    std::vector<int> doomed = mSelection;
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
    const std::vector<PropPaintEntry>& list = mTools->PaintList();
    if (fixedYaw <= -100.0f && mTools->CurrentPropMode() == EdTools::PropMode::Scatter && !list.empty()) {
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
      entry.mTransform.pos_ = Wm3::Vec3f{
        centreX[c],
        mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(centreX[c])), static_cast<std::int32_t>(std::lround(centreZ[c]))
        ),
        centreZ[c]
      };
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
      (::GetKeyState(VK_SHIFT) & 0x8000) != 0 ||
      !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz)
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
      std::string error;
      if (!ParseUnitGroup(entry.Get("Units"), group, error)) {
        gpg::Warnf("editor: %s's units unreadable, not changed: %s", army.c_str(), error.c_str());
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
      std::string error;
      if (ParseUnitGroup(entry.Get("Units"), group, error)) {
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
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
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
    if (!placed.empty()) {
      mDocument.SaveDataEdited(std::move(before));
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
      std::string error;
      if (!ParseUnitGroup(entry.Get("Units"), group, error)) {
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

  bool EdMapScene::ImportUnitFile(
    const std::string& text,
    const std::string& army,
    std::vector<std::string>& names,
    bool& moved,
    std::string& error
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      error = "no map shown";
      return false;
    }
    std::vector<SaveUnit> units;
    float centre[3];
    if (!UnitsFromScunits(text, units, centre, error)) {
      return false;
    }
    if (units.empty()) {
      error = "the file has no units";
      return false;
    }
    const float width = static_cast<float>(field->width - 1);
    const float height = static_cast<float>(field->height - 1);
    moved = FitUnitsOnMap(units, centre, width, height);
    // The next free UNIT_n over every army, as placing does.
    int highest = 0;
    for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
      UnitGroup group;
      std::string parseError;
      if (ParseUnitGroup(entry.Get("Units"), group, parseError)) {
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
      error = "the army's units can't be changed";
      names.clear();
      return false;
    }
    mDocument.SaveDataEdited(std::move(before));
    ReloadUnits();
    mUnitSelection.clear();
    for (const std::string& name : names) {
      mUnitSelection.emplace_back(army, name);
    }
    return true;
  }

  void EdMapScene::DeleteSelectedUnits()
  {
    if (mUnitSelection.empty()) {
      return;
    }
    EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
    int deleted = 0;
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
      const bool alphaTested = shader.find("Alpha") != std::string::npos;
      const bool sways = shader.find("Undulating") != std::string::npos;
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
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mProps) {
        delete instance;
      }
    }
    mProps.clear();
    mPropsDone = false;
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
    }
    switch (message) {
    case WM_LBUTTONDOWN: {
      // Alt+drag measures, whatever the tool.
      if ((::GetKeyState(VK_MENU) & 0x8000) != 0) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          mRuling = true;
          mRulerShown = true;
          mRulerFrom[0] = mRulerTo[0] = groundX;
          mRulerFrom[1] = mRulerTo[1] = groundZ;
          if (mTools != nullptr) {
            mTools->SetRulerText(DistanceText(0.0f));
          }
          ::SetCapture(window);
        }
        return true;
      }
      if (mRulerShown && !mRuling) {
        // A click without Alt puts the ruler away.
        mRulerShown = false;
        if (mTools != nullptr) {
          mTools->SetRulerText({});
        }
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
          PlaceUnits(groundX, groundZ);
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
        if (
          (wParam & MK_SHIFT) != 0 && !mTools->DecalPlaceMode() && !mTools->DecalPathMode() &&
          PickGizmo(at) != GizmoPart::None
        ) {
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
        if ((wParam & MK_SHIFT) != 0 || mTools->CurrentPropMode() == EdTools::PropMode::Erase) {
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
      // Flatten keeps the height under the stroke's first point.
      mFlattenTo = groundHeight * 128.0f;
      mStamped = false;
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
          for (const auto& [army, name] : mUnitSelection) {
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
      if (mObjectStroke) {
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
      // Middle drag orbits, Shift + middle drag pans; the right button pans.
      mDrag = (message == WM_MBUTTONDOWN && (wParam & MK_SHIFT) == 0) ? Drag::Orbit : Drag::Pan;
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
      return true;
    case WM_MOUSEMOVE: {
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
            }
            mUnitsMoved = true;
          }
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
            }
          }
          mMarkersMoved = mMarkersMoved || move.x != 0.0f || move.y != 0.0f || move.z != 0.0f;
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
            }
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
              MovePropTo(mSelection[i], GizmoPlace(mDragStart[i], move, false));
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
              MovePropTo(
                mSelection[i],
                Wm3::Vec3f{
                  x,
                  mMap->mTerrainRes->GetHeightAt(
                    static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
                  ),
                  z
                }
              );
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
        if (wParam == 'Q' || wParam == 'E') {
          TurnSelection(wParam == 'Q' ? -0.2617994f : 0.2617994f);
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
