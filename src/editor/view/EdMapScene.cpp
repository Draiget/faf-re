#include "editor/view/EdMapScene.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <map>
#include <set>
#include <cstring>

#include <windowsx.h>

#include "editor/EdTools.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
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
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace faf::editor
{
  /** The renderer's editor hook (IEdRenderHook, called at the end of WRenViewport::RenderUI): the brush rings. */
  class EdMapScene::RingHook final : public moho::IEdRenderHook
  {
  public:
    explicit RingHook(EdMapScene& scene)
      : mScene(scene)
    {}
    void Render() override { mScene.DrawBrushRings(); }

  private:
    EdMapScene& mScene;
  };

  namespace
  {
    constexpr float kPi = 3.14159265f;
    constexpr float kMinPitch = 0.12f;
    constexpr float kMaxPitch = kPi * 0.5f;
  } // namespace

  EdMapScene::EdMapScene(EdDocument& document)
    : mDocument(document)
  {}

  EdMapScene::~EdMapScene()
  {
    Detach();
  }

  void EdMapScene::DrawBrushRings()
  {
    const std::optional<EdDocument::PlayableRect> area = mMap != nullptr ? mDocument.PlayableArea() : std::nullopt;
    if (mMap == nullptr || mCamera == nullptr || mTools == nullptr ||
        (!mTools->TerrainToolActive() && !mTools->TextureToolActive() && !mTools->PropsToolActive() && mSelection.empty() && !area &&
         mDocument.SaveData().Markers().empty() && !mTools->ShowGrid() && !mTools->DecalsToolActive() && !mTools->UnitsToolActive() &&
         mTools->CheckPins().empty()) ||
        moho::ren_Viewport == nullptr) {
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
    const auto groundVertex = [field](const float x, const float z, const std::uint32_t color, const float lift = 0.4f) {
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
        const moho::CD3DPrimBatcher::Vertex a = groundVertex(x0 + (x1 - x0) * t0, z0 + (z1 - z0) * t0, kMirrorColor, 0.6f);
        const moho::CD3DPrimBatcher::Vertex b = groundVertex(x0 + (x1 - x0) * t1, z0 + (z1 - z0) * t1, kMirrorColor, 0.6f);
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
          batcher->DrawLine(groundVertex(ax + (bx - ax) * t0, az + (bz - az) * t0, kBorderColor, 0.8f),
                            groundVertex(ax + (bx - ax) * t1, az + (bz - az) * t1, kBorderColor, 0.8f));
        }
      };
      border(x0, z0, x1, z0);
      border(x1, z0, x1, z1);
      border(x1, z1, x0, z1);
      border(x0, z1, x0, z0);
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
    DrawResourceSplats(*batcher, *field);
    DrawMarkers(*batcher, mTools->MarkersToolActive());

    // The selected props, ringed in yellow.
    if (!mSelection.empty() && mMap->mProps != nullptr) {
      constexpr std::uint32_t kSelectedColor = 0xF0FFE040u;
      for (const int index : mSelection) {
        const Wm3::Vec3f& p = mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_;
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(groundVertex(p.x + std::cos(a0) * 2.0f, p.z + std::sin(a0) * 2.0f, kSelectedColor),
                            groundVertex(p.x + std::cos(a1) * 2.0f, p.z + std::sin(a1) * 2.0f, kSelectedColor));
        }
      }
    }
    if (mTools->DecalsToolActive()) {
      DrawDecalOutlines(*batcher, *field);
    }
    // The selected units, ringed in yellow.
    if (mTools->UnitsToolActive()) {
      for (const auto& [army, name] : mUnitSelection) {
        const int index = UnitRefIndex(army, name);
        if (index < 0) {
          continue;
        }
        const Wm3::Vec3f& p = mUnitRefs[static_cast<std::size_t>(index)].position;
        for (int s = 0; s < 24; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
          batcher->DrawLine(groundVertex(p.x + std::cos(a0) * 1.5f, p.z + std::sin(a0) * 1.5f, 0xF0FFE040u),
                            groundVertex(p.x + std::cos(a1) * 1.5f, p.z + std::sin(a1) * 1.5f, 0xF0FFE040u));
        }
      }
    }
    // The Check's findings: a ring and a post in its colour (red errors, amber warnings, blue notes).
    for (const EdTools::CheckPin& pin : mTools->CheckPins()) {
      const std::uint32_t color = pin.level == 0 ? 0xF0FF5848u : pin.level == 1 ? 0xF0FFC040u : 0xF08CB4F0u;
      const float r = std::max(3.0f, mDistance * 0.012f);
      for (int s = 0; s < 24; ++s) {
        const float a0 = 2.0f * kPi * static_cast<float>(s) / 24.0f;
        const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 24.0f;
        batcher->DrawLine(groundVertex(pin.x + std::cos(a0) * r, pin.z + std::sin(a0) * r, color, 1.0f),
                          groundVertex(pin.x + std::cos(a1) * r, pin.z + std::sin(a1) * r, color, 1.0f));
      }
      moho::CD3DPrimBatcher::Vertex top = groundVertex(pin.x, pin.z, color, 0.0f);
      moho::CD3DPrimBatcher::Vertex bottom = top;
      top.mY += r * 3.0f;
      batcher->DrawLine(bottom, top);
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
          batcher->DrawLine(groundVertex(px[j], pz[j], kPlaneColor, 1.0f), groundVertex(px[i], pz[i], kPlaneColor, 1.0f));
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
        batcher->DrawQuad(groundVertex(x0, z0, kDifferenceColor, 0.3f), groundVertex(x1, z0, kDifferenceColor, 0.3f),
                          groundVertex(x1, z1, kDifferenceColor, 0.3f), groundVertex(x0, z1, kDifferenceColor, 0.3f));
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
    const int centres = HeightBrushCentres(field->width, field->height, groundX, groundZ, brush.symmetry, brush.turns, centreX, centreZ);
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
          batcher->DrawLine(groundVertex(centreX[c] + std::cos(a0) * radius, centreZ[c] + std::sin(a0) * radius, color),
                            groundVertex(centreX[c] + std::cos(a1) * radius, centreZ[c] + std::sin(a1) * radius, color));
        }
      }
    }
    batcher->Flush();
  }

  void EdMapScene::Attach(moho::CWldMap& map)
  {
    if (moho::ren_Viewport == nullptr || map.mTerrainRes == nullptr || map.mTerrainRes->mMap == nullptr ||
        mDocument.Lua() == nullptr) {
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
    FrameWholeMap();
    mWorldView = std::make_unique<moho::SimpleRenderWorldView>(const_cast<moho::GeomCamera3*>(&mCamera->CameraGetView()));
    moho::ren_Viewport->AddWorldView(mWorldView.get(), 0, 0);
    if (mRingHook == nullptr) {
      mRingHook = std::make_unique<RingHook>(*this);
    }
    moho::ED_SetHook(mRingHook.get());
    gpg::Logf("editor: the viewport shows %s", mDocument.Path().c_str());
    // The symmetry the map was made with, from its heights, for the brushes and the object tools.
    if (mTools != nullptr) {
      const DetectedSymmetry& found = mDocument.Facts().symmetry;
      mTools->SetDetectedSymmetry(found.symmetry == Symmetry::None ? -1 : static_cast<int>(found.symmetry), found.turns, found.matched);
    }
  }

  void EdMapScene::Detach()
  {
    if (mMap == nullptr) {
      return;
    }
    // A stroke in progress ends here, so undo has it whole.
    EndStroke();
    EndMaskStroke();
    EndObjectStroke();
    mSelection.clear();
    // The props first: their blueprints are the kept rules', which the next play takes.
    DeleteProps();
    moho::ED_SetHook(nullptr);
    if (moho::ren_Viewport != nullptr && mWorldView != nullptr) {
      moho::ren_Viewport->RemoveWorldView(mWorldView.get());
    }
    if (moho::sWldMap == mMap) {
      moho::REN_SetWldMap(nullptr);
    }
    mWorldView.reset();
    // ~CameraImpl takes the camera out of the camera manager (as RenderPreviewImage relies on).
    delete mCamera;
    mCamera = nullptr;
    mMap = nullptr;
    mDrag = Drag::None;
    mPainting = false;
  }

  void EdMapScene::PaintStroke(const float frameSeconds)
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr ||
        !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
      return;
    }
    HeightBrush brush = mTools->CurrentHeightBrush();
    brush.flattenTo = mFlattenTo;
    // A stamp goes down once per click.
    if (brush.mode == HeightBrushMode::Stamp) {
      if (mStamped || brush.stamp == nullptr) {
        return;
      }
      mStamped = true;
    }
    // Undo keeps the tiles this step writes, as they are, before it writes them.
    for (const SampleRect& rect : HeightBrushRects(field->width, field->height, groundX, groundZ, brush)) {
      mDocument.Heights().BeforeWrite(field->data, rect);
    }
    const std::vector<SampleRect> rects =
      ApplyHeightBrush(field->data, field->width, field->height, groundX, groundZ, brush, std::min(frameSeconds, 0.1f));
    if (!rects.empty()) {
      mDocument.SetModified(true);
      RefreshHeights(rects);
    }
  }

  void EdMapScene::EndStroke()
  {
    if (mMap != nullptr && mDocument.Heights().Stroking()) {
      if (const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField()) {
        const std::size_t before = mDocument.Heights().UndoCount();
        mDocument.Heights().EndStroke(field->data);
        if (mDocument.Heights().UndoCount() > before) {
          mDocument.EditEnded(EdDocument::EditKind::Heights);
        }
        // A check that was made is kept up to date as the map changes.
        if (mCheckDone) {
          RunSymmetryCheck();
        }
      }
    }
    mPainting = false;
  }

  bool EdMapScene::Undo()
  {
    EdDocument::EditKind kind{};
    if (mMap == nullptr || mPainting || mPaintingMask || mObjectStroke || !mDocument.PopUndo(kind)) {
      return false;
    }
    const bool done = kind == EdDocument::EditKind::Masks    ? UndoMasks(false)
                      : kind == EdDocument::EditKind::Layers ? UndoLayers(false)
                      : kind == EdDocument::EditKind::Props  ? UndoProps(false)
                      : kind == EdDocument::EditKind::SaveData ? UndoSaveData(false)
                      : kind == EdDocument::EditKind::Decals   ? UndoDecals(false)
                      : kind == EdDocument::EditKind::Water    ? UndoWater(false)
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
    const bool done = kind == EdDocument::EditKind::Masks    ? UndoMasks(true)
                      : kind == EdDocument::EditKind::Layers ? UndoLayers(true)
                      : kind == EdDocument::EditKind::Props  ? UndoProps(true)
                      : kind == EdDocument::EditKind::SaveData ? UndoSaveData(true)
                      : kind == EdDocument::EditKind::Decals   ? UndoDecals(true)
                      : kind == EdDocument::EditKind::Water    ? UndoWater(true)
                                                             : UndoHeights(true);
    if (done) {
      mDocument.PushUndo(kind);
    }
    return done;
  }

  namespace
  {
    /** Slot `slot`'s albedo (or normal map) material: lower, strata 0-7, upper. */
    moho::CStratumMaterial& SlotMaterial(moho::StratumMaterial& strata, const int slot, const bool normals)
    {
      moho::CStratumMaterial* const albedo[10] = {
        &strata.mLowerAlbedoTexture,    &strata.mStratum0AlbedoTexture, &strata.mStratum1AlbedoTexture, &strata.mStratum2AlbedoTexture,
        &strata.mStratum3AlbedoTexture, &strata.mStratum4AlbedoTexture, &strata.mStratum5AlbedoTexture, &strata.mStratum6AlbedoTexture,
        &strata.mStratum7AlbedoTexture, &strata.mUpperAlbedoTexture,
      };
      moho::CStratumMaterial* const normal[10] = {
        &strata.mLowerNormalTexture,    &strata.mStratum0NormalTexture, &strata.mStratum1NormalTexture, &strata.mStratum2NormalTexture,
        &strata.mStratum3NormalTexture, &strata.mStratum4NormalTexture, &strata.mStratum5NormalTexture, &strata.mStratum6NormalTexture,
        &strata.mStratum7NormalTexture, &strata.mUpperNormalTexture,
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

  void EdMapScene::SetLayerSlot(const int slot, const std::string& albedo, const std::string& normals, const float albedoSize,
                                const float normalsSize)
  {
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    const auto set = [](moho::CStratumMaterial& material, const std::string& path, const float size) {
      if (path != material.mPath.c_str()) {
        material.mPath.assign(path.c_str());
        // Dropped, so SetSize loads the new file.
        material.mTextureSheet.release();
        material.mTextureSheet = {};
      }
      material.mSize = size > 0.0f ? size : 1.0f;
    };
    set(SlotMaterial(strata, slot, false), albedo, albedoSize);
    set(SlotMaterial(strata, slot, true), normals, normalsSize);
    // Loads what has no texture yet and scales every layer to the map (StratumMaterial::SetSizeTo).
    strata.SetSizeTo(mMap->mTerrainRes);
    mDocument.SetLayerFact(slot, albedo);
    mDocument.SetModified(true);
  }

  void EdMapScene::ChangeLayerSlot(const int slot, const EdTools::LayerSlot& value)
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
    gpg::Logf("editor: layer %d is %s at size %.2f", slot, value.albedo.empty() ? "(empty)" : value.albedo.c_str(), static_cast<double>(value.albedoSize));
  }

  bool EdMapScene::UndoLayers(const bool redo)
  {
    std::vector<EdDocument::LayerEdit>& from = redo ? mDocument.LayerRedo() : mDocument.LayerUndo();
    std::vector<EdDocument::LayerEdit>& to = redo ? mDocument.LayerUndo() : mDocument.LayerRedo();
    if (from.empty() || mMap == nullptr) {
      return false;
    }
    const EdDocument::LayerEdit edit = from.back();
    from.pop_back();
    to.push_back(edit);
    if (edit.slot < 0) {
      SetTerrainShaderName(redo ? edit.albedoAfter : edit.albedoBefore);
      return true;
    }
    if (redo) {
      SetLayerSlot(edit.slot, edit.albedoAfter, edit.normalsAfter, edit.albedoSizeAfter, edit.normalsSizeAfter);
    } else {
      SetLayerSlot(edit.slot, edit.albedoBefore, edit.normalsBefore, edit.albedoSizeBefore, edit.normalsSizeBefore);
    }
    mLayerDragJoin = false;
    return true;
  }

  bool EdMapScene::UndoMasks(const bool redo)
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    std::vector<SampleRect> rects;
    if (masks.texels.empty() ||
        !(redo ? mDocument.MaskUndo().Redo(masks.texels.data(), rects) : mDocument.MaskUndo().Undo(masks.texels.data(), rects))) {
      return false;
    }
    UploadMasks(rects, 0xFFu);
    mDocument.SetModified(true);
    UpdateCoverage();
    return true;
  }

  bool EdMapScene::UndoHeights(const bool redo)
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    std::vector<SampleRect> rects;
    if (field == nullptr || mPainting || !(redo ? mDocument.Heights().Redo(field->data, rects) : mDocument.Heights().Undo(field->data, rects))) {
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
    UpdateCoverage();
    // How much of the map each layer covers (the share of full weight), for the log.
    std::string cover;
    for (int layer = 0; layer < 8; ++layer) {
      std::uint64_t sum = 0;
      for (const std::uint64_t texel : masks.texels) {
        sum += MaskByte(texel, layer);
      }
      char part[32];
      (void)std::snprintf(part, sizeof(part), "%s%d: %.1f%%", layer == 0 ? "" : ", ", layer + 1, 100.0 * static_cast<double>(sum) / (255.0 * static_cast<double>(count)));
      cover += part;
    }
    gpg::Logf("editor: stratum masks %d x %d read for painting (cover %s)", masks.width, masks.height, cover.c_str());
  }

  void EdMapScene::UploadMasks(const std::vector<SampleRect>& rects, const unsigned layers)
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    if (masks.texels.empty() || mMap == nullptr) {
      return;
    }
    mMaskPlane.resize(masks.texels.size());
    for (int layer = 0; layer < 8; ++layer) {
      if ((layers & (1u << layer)) == 0) {
        continue;
      }
      for (const SampleRect& rect : rects) {
        for (int z = rect.z0; z <= rect.z1; ++z) {
          const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(masks.width);
          for (int x = rect.x0; x <= rect.x1; ++x) {
            mMaskPlane[row + static_cast<std::size_t>(x)] = MaskByte(masks.texels[row + static_cast<std::size_t>(x)], layer);
          }
        }
        mMap->mTerrainRes->UpdateStratumMask(layer, mMaskPlane.data(), rect.x0, rect.z0, rect.x1 + 1, rect.z1 + 1);
      }
    }
  }

  void EdMapScene::BuildWeightQuads(const int layer)
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
            sum += MaskByte(masks.texels[static_cast<std::size_t>(z) * static_cast<std::size_t>(masks.width) + static_cast<std::size_t>(x)], layer);
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
      faf::editor::MaskCoverage(masks.texels.data(), masks.texels.size(), mCoverage);
    }
  }

  bool EdMapScene::MaskCoverage(float (&coverage)[8]) const
  {
    if (!mCoverageValid || mDocument.Masks().texels.empty()) {
      return false;
    }
    for (int i = 0; i < 8; ++i) {
      coverage[i] = mCoverage[i];
    }
    return true;
  }

  void EdMapScene::WholeMaskChanged(const SampleRect& whole)
  {
    EdDocument::MaskGrid& masks = mDocument.Masks();
    mDocument.MaskUndo().EndStroke(masks.texels.data());
    mDocument.EditEnded(EdDocument::EditKind::Masks);
    UploadMasks({whole}, 0xFFu);
    mDocument.SetModified(true);
    UpdateCoverage();
    mLayerDragJoin = false;
  }

  bool EdMapScene::ClearMaskLayer(const int layer, std::string& message)
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

  bool EdMapScene::ImportMaskLayer(const int layer, const std::filesystem::path& file, std::string& message)
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
    for (std::size_t i = 0; i < masks.texels.size(); ++i) {
      masks.texels[i] = WithMaskByte(masks.texels[i], layer, static_cast<std::uint8_t>(image.words[i] >> 8));
    }
    WholeMaskChanged(whole);
    message = "Imported the mask of layer " + std::to_string(layer + 1) + " from " + file.string();
    return true;
  }

  bool EdMapScene::ExportMaskLayer(const int layer, const std::filesystem::path& file, std::string& message)
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
    for (std::size_t i = 0; i < masks.texels.size(); ++i) {
      image.words[i] = static_cast<std::uint16_t>(MaskByte(masks.texels[i], layer) * 257u);
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
    moho::CD3DEffect* const effect = device != nullptr && device->GetResources() != nullptr ? device->GetResources()->FindEffect("terrain") : nullptr;
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

  void EdMapScene::SetTerrainShaderName(const std::string& shader)
  {
    moho::StratumMaterial& strata = mMap->mTerrainRes->GetStratumMaterial();
    strata.mShaderName.assign(shader.c_str());
    // ResolveTerrainCompositeShaderUsage (0x0089F350) checks the new name once before it is drawn or saved.
    strata.byte0 = 0;
    strata.byte1 = 1;
    mDocument.SetModified(true);
    gpg::Logf("editor: terrain shader %s", shader.c_str());
  }

  std::string EdMapScene::TerrainShader() const
  {
    return mMap != nullptr ? std::string(mMap->mTerrainRes->GetStratumMaterial().mShaderName.c_str()) : std::string{};
  }

  void EdMapScene::ChangeTerrainShader(const std::string& shader)
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

  void EdMapScene::PaintMask(const float frameSeconds)
  {
    float groundX = 0.0f;
    float groundZ = 0.0f;
    EdDocument::MaskGrid& masks = mDocument.Masks();
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || masks.texels.empty() ||
        !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), groundX, groundZ)) {
      return;
    }
    MaskBrush brush = mTools->CurrentMaskBrush();
    brush.step = ++mMaskSteps;
    const MaskTerrain terrain{field->data, field->width, field->height};
    for (const SampleRect& rect : MaskBrushRects(masks.width, masks.height, terrain, groundX, groundZ, brush)) {
      mDocument.MaskUndo().BeforeWrite(masks.texels.data(), rect);
    }
    const std::vector<SampleRect> rects =
      ApplyMaskBrush(masks.texels.data(), masks.width, masks.height, terrain, groundX, groundZ, brush, std::min(frameSeconds, 0.1f));
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
    (void)ApplyMaskRules(masks.texels.data(), masks.width, masks.height, MaskTerrain{field->data, field->width, field->height}, mTools->Rules());
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
      MaskSymmetryReport report = CheckMaskSymmetry(masks.texels.data(), masks.width, masks.height, mCheckedWith.symmetry, mCheckedWith.turns);
      // The overlay is drawn in height samples.
      const int perTexel = std::max(1, (field->width - 1) / masks.width);
      mDifferences.clear();
      for (const SampleRect& block : report.blocks) {
        mDifferences.push_back({block.x0 * perTexel, block.z0 * perTexel, std::min(field->width - 1, (block.x1 + 1) * perTexel),
                                std::min(field->height - 1, (block.z1 + 1) * perTexel)});
      }
      mCheckDone = true;
      mTools->SetCheckResult(report.checked, report.differing, report.largest, mCheckedWith, true);
      gpg::Logf("editor: mask symmetry check (mode %d): %d of %d texels differ, by up to %d of 255", static_cast<int>(mCheckedWith.symmetry),
                report.differing, report.checked, report.largest);
      return;
    }
    SymmetryReport report = CheckSymmetry(field->data, field->width, field->height, mCheckedWith.symmetry, mCheckedWith.turns);
    mDifferences = std::move(report.blocks);
    mCheckDone = true;
    mTools->SetCheckResult(report.checked, report.differing, report.largest, mCheckedWith);
    gpg::Logf("editor: symmetry check (mode %d, %d turns): %d of %d vertices differ, by up to %d words; %zu blocks marked",
              static_cast<int>(mCheckedWith.symmetry), mCheckedWith.turns, report.differing, report.checked, report.largest,
              mDifferences.size());
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

  bool EdMapScene::ImportHeights(const std::filesystem::path& file, const float scale, std::string& message)
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
    message = "Imported heights from " + file.string() + " (" + std::to_string(readWidth) + " x " + std::to_string(readHeight) +
              (readWidth != field->width || readHeight != field->height ? ", resampled" : "") + ")";
    return true;
  }

  bool EdMapScene::ExportHeights(const std::filesystem::path& file, const int width, const float scale, std::string& message)
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      message = "No map is open in the view.";
      return false;
    }
    HeightImage image;
    image.width = field->width;
    image.height = field->height;
    image.words.assign(field->data, field->data + static_cast<std::size_t>(field->width) * static_cast<std::size_t>(field->height));
    if (width > 1 && width != field->width) {
      // The map's proportions kept: a rectangular map's image is as much shorter.
      const int height = std::max(2, static_cast<int>(std::lround(static_cast<double>(width - 1) * (field->height - 1) / (field->width - 1))) + 1);
      image = ResampleHeights(image, width, height);
    }
    ScaleHeights(image, scale);
    std::string error;
    if (!WriteHeightImage(file, image, error)) {
      message = "Export failed: " + error;
      return false;
    }
    message = "Exported heights to " + file.string() + " (" + std::to_string(image.width) + " x " + std::to_string(image.height) + ")";
    return true;
  }

  void EdMapScene::RefreshHeights(const std::vector<SampleRect>& rects)
  {
    mWeightStale = true; // the overlays lie on the ground
    mOutsideStale = true;
    moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    // The samples are written in place; the field's own setter, given them back, refreshes its tiers of
    // min/max heights and its revision (the shadow and vision passes watch it). Then the terrain redraws
    // those rectangles: tiles and normal map, one sample wider for the normals at their edge.
    std::vector<gpg::Rect2i> changed;
    changed.reserve(rects.size());
    for (const SampleRect& rect : rects) {
      field->SetElevationRectRaw(gpg::Rect2i{rect.x0, rect.z0, rect.x1, rect.z1},
                                 field->data + rect.x0 + static_cast<std::ptrdiff_t>(rect.z0) * field->width, field->width);
      changed.push_back(gpg::Rect2i{std::max(0, rect.x0 - 1), std::max(0, rect.z0 - 1), std::min(field->width - 1, rect.x1 + 1),
                                    std::min(field->height - 1, rect.z1 + 1)});
    }
    mMap->mTerrainRes->NotifyMapChanges(changed.data(), changed.size());
  }

  void EdMapScene::Update(const float frameSeconds, const bool playIdle)
  {
    moho::CWldMap* const wanted =
      playIdle && mDocument.GetState() == EdDocument::State::Open ? mDocument.Map() : nullptr;
    if (mMap != nullptr && mMap != wanted) {
      Detach();
    }
    // A play's session clears the renderer's map when it ends (0x00893BE6); attach once it has.
    if (mMap == nullptr && wanted != nullptr && moho::sWldMap == nullptr) {
      Attach(*wanted);
    }
    if (mMap == nullptr) {
      return;
    }
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
      CreateProps();
    }
    UpdatePropPreview();
    MoveWithKeys(frameSeconds);
    if (mPainting) {
      PaintStroke(frameSeconds);
    }
    if (mPaintingMask) {
      PaintMask(frameSeconds);
    }
    if (mObjectStroke && mTools != nullptr && mTools->PropsToolActive() && mTools->CurrentPropMode() != EdTools::PropMode::Single) {
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
    if (mTools != nullptr) {
      mTools->SetSelectionCount(static_cast<int>(mSelection.size()));
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

  void EdMapScene::CreateProps()
  {
    // The rules every play uses, kept between plays and built at startup; until they are ready, next frame.
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
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
    gpg::Logf("editor: %zu props drawn, %d without a blueprint or mesh", mProps.size() - static_cast<std::size_t>(missing), missing);
  }

  void EdMapScene::CreateUnits()
  {
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr) {
      return;
    }
    int drawn = 0;
    int missing = 0;
    int unreadable = 0;
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
        std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        moho::RResId id{};
        id.name.assign(lower.c_str());
        moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(id);
        moho::RMeshBlueprint* const mesh = blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
        if (mesh == nullptr) {
          ++missing;
          continue;
        }
        const float scale = blueprint->Display.UniformScale;
        moho::MeshInstance* const instance =
          renderer->CreateMeshInstance(0, -1, mesh, Wm3::Vec3f{scale, scale, scale}, false, boost::shared_ptr<moho::MeshMaterial>());
        if (instance == nullptr) {
          ++missing;
          continue;
        }
        // As CreateUnitHPR turns Orientation's three angles (heading, pitch, roll) into the unit's rotation.
        moho::VTransform transform{};
        transform.pos_ = Wm3::Vec3f{unit->position[0], unit->position[1], unit->position[2]};
        Wm3::Vector3f rows[3];
        (void)moho::BuildRotationMatrixFromEulerHPR(rows, unit->orientation[0], unit->orientation[1], unit->orientation[2]);
        (void)moho::MatrixRowsToQuatCanonical(rows, &transform.orient_);
        instance->SetStance(transform, transform);
        instance->isHidden = 0;
        mUnits.push_back(instance);
        UnitRef ref{army.name, unit->name, transform.pos_, {unit->orientation[0], unit->orientation[1], unit->orientation[2]}};
        mUnitRefs.push_back(std::move(ref));
        ++drawn;
      }
    }
    gpg::Logf("editor: %d units drawn, %d without a blueprint or mesh, %d armies unreadable", drawn, missing, unreadable);
  }

  moho::MeshInstance* EdMapScene::MakePropInstance(const moho::CWldPropEntry& entry) const
  {
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr) {
      return nullptr;
    }
    // The blueprint as a prop's entity finds it: the file name normalized into a resource id.
    moho::RResId id{};
    gpg::STR_CopyFilename(&id.name, &entry.mBlueprintPath);
    moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
    moho::RMeshBlueprint* const mesh = blueprint != nullptr ? rules->GetMeshBlueprint(blueprint->Display.MeshBlueprint) : nullptr;
    if (mesh == nullptr) {
      return nullptr;
    }
    const float scale = blueprint->Display.UniformScale;
    moho::MeshInstance* const instance =
      renderer->CreateMeshInstance(0, -1, mesh, Wm3::Vec3f{scale, scale, scale}, false, boost::shared_ptr<moho::MeshMaterial>());
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
    mSelection.erase(std::remove_if(mSelection.begin(), mSelection.end(), [count](const int index) { return index >= count; }), mSelection.end());
  }

  bool EdMapScene::UndoProps(const bool redo)
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

  bool EdMapScene::UndoWater(const bool redo)
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

  bool EdMapScene::UndoDecals(const bool redo)
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
      mDecalSelection.erase(std::remove_if(mDecalSelection.begin(), mDecalSelection.end(),
                                           [&](const int index) { return FindDecal(*decals, index) == nullptr; }),
                            mDecalSelection.end());
      gpg::Logf("editor: %s a decal edit: %d decals", redo ? "redid" : "undid", decals->GetDecalCount());
    }
    return true;
  }

  bool EdMapScene::UndoSaveData(const bool redo)
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
    gpg::Logf("editor: %s a save edit (markers, areas, armies, units): %zu markers, %zu units", redo ? "redid" : "undid",
              mDocument.SaveData().Markers().size(), mUnitRefs.size());
    return true;
  }

  void EdMapScene::ChangePlayableArea(const std::optional<EdDocument::PlayableRect>& area)
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

  void EdMapScene::BuildOutsideQuads(const EdDocument::PlayableRect& area)
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
    /** How far a marker's symmetric copy may sit from the exact mirrored point (placement rounds copies to the half unit). */
    constexpr float kCopyReach = 1.5f;
  } // namespace

  bool EdMapScene::GizmoOrigin(Wm3::Vec3f& origin) const
  {
    if (mTools == nullptr || mMap == nullptr) {
      return false;
    }
    float sx = 0.0f, sy = 0.0f, sz = 0.0f;
    int count = 0;
    if (mTools->MarkersToolActive()) {
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end() &&
            MarkerPosition(marker, x, y, z)) {
          sx += x;
          sy += y;
          sz += z;
          ++count;
        }
      }
    } else if (mTools->UnitsToolActive() && !mTools->UnitPlaceMode()) {
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
    } else if (mTools->DecalsToolActive() && !mTools->DecalPlaceMode() && !mTools->DecalPathMode()) {
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
    } else if (mTools->SelectToolActive() && mMap->mProps != nullptr) {
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
    Wm3::Vec3f GizmoAxis(const EdMapScene::GizmoPart part)
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

    /** The distance on screen from `p` to the segment a-b. */
    float SegmentDistance(const Wm3::Vector2f& p, const Wm3::Vector2f& a, const Wm3::Vector2f& b)
    {
      const float dx = b.x - a.x;
      const float dy = b.y - a.y;
      const float length2 = dx * dx + dy * dy;
      const float t = length2 > 0.0f ? std::clamp(((p.x - a.x) * dx + (p.y - a.y) * dy) / length2, 0.0f, 1.0f) : 0.0f;
      return std::hypot(p.x - (a.x + dx * t), p.y - (a.y + dy * t));
    }
  } // namespace

  EdMapScene::GizmoPart EdMapScene::PickGizmo(const POINT at) const
  {
    Wm3::Vec3f origin;
    if (mCamera == nullptr || !GizmoOrigin(origin)) {
      return GizmoPart::None;
    }
    const float length = GizmoLength();
    const Wm3::Vector2f cursor(static_cast<float>(at.x), static_cast<float>(at.y));
    const Wm3::Vector2f centre = mCamera->Project(origin);
    if (std::hypot(cursor.x - centre.x, cursor.y - centre.y) < 12.0f) {
      return GizmoPart::Free;
    }
    GizmoPart best = GizmoPart::None;
    float bestDistance = 9.0f;
    for (const GizmoPart part : {GizmoPart::X, GizmoPart::Y, GizmoPart::Z}) {
      const Wm3::Vec3f axis = GizmoAxis(part);
      const Wm3::Vector2f tip = mCamera->Project(Wm3::Vec3f{origin.x + axis.x * length, origin.y + axis.y * length, origin.z + axis.z * length});
      // The arm from a quarter of its length, so the middle stays the free square's.
      const Wm3::Vector2f from(centre.x + (tip.x - centre.x) * 0.25f, centre.y + (tip.y - centre.y) * 0.25f);
      const float d = SegmentDistance(cursor, from, tip);
      if (d < bestDistance) {
        bestDistance = d;
        best = part;
      }
    }
    return best;
  }

  void EdMapScene::DrawGizmo(moho::CD3DPrimBatcher& batcher)
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
    const auto add = [](const Wm3::Vec3f& a, const Wm3::Vec3f& d, const float s) { return Wm3::Vec3f{a.x + d.x * s, a.y + d.y * s, a.z + d.z * s}; };
    constexpr std::uint32_t kHot = 0xFFFFE040u;
    const std::pair<GizmoPart, std::uint32_t> arms[] = {{GizmoPart::X, 0xFFFF4848u}, {GizmoPart::Y, 0xFF48E048u}, {GizmoPart::Z, 0xFF4880FFu}};
    for (const auto& [part, color] : arms) {
      const std::uint32_t c = part == hot ? kHot : color;
      const Wm3::Vec3f axis = GizmoAxis(part);
      const Wm3::Vec3f tip = add(origin, axis, length);
      batcher.DrawLine(vertex(add(origin, axis, length * 0.15f), c), vertex(tip, c));
      // The arrow's head: four lines back from the tip, around the arm.
      const Wm3::Vec3f across1 = part == GizmoPart::Y ? Wm3::Vec3f{1.0f, 0.0f, 0.0f} : Wm3::Vec3f{0.0f, 1.0f, 0.0f};
      const Wm3::Vec3f across2 = part == GizmoPart::Z ? Wm3::Vec3f{1.0f, 0.0f, 0.0f} : Wm3::Vec3f{0.0f, 0.0f, part == GizmoPart::X ? 1.0f : 1.0f};
      const Wm3::Vec3f back = add(origin, axis, length * 0.78f);
      for (const Wm3::Vec3f& side : {across1, across2}) {
        batcher.DrawLine(vertex(tip, c), vertex(add(back, side, length * 0.07f), c));
        batcher.DrawLine(vertex(tip, c), vertex(add(back, side, -length * 0.07f), c));
      }
    }
    // The free square, on the ground plane through the middle.
    const std::uint32_t free = hot == GizmoPart::Free ? kHot : 0xFFF0F0F0u;
    const float s = length * 0.1f;
    const Wm3::Vec3f corners[4] = {{origin.x - s, origin.y, origin.z - s}, {origin.x + s, origin.y, origin.z - s},
                                   {origin.x + s, origin.y, origin.z + s}, {origin.x - s, origin.y, origin.z + s}};
    for (int i = 0; i < 4; ++i) {
      batcher.DrawLine(vertex(corners[i], free), vertex(corners[(i + 1) % 4], free));
    }
  }

  void EdMapScene::BeginGizmoDrag(const GizmoPart part, const POINT at)
  {
    mGizmoDrag = part;
    mGizmoFrom = at;
    (void)GizmoOrigin(mGizmoStart);
    mGizmoDragLength = GizmoLength();
    if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), mGizmoGroundX, mGizmoGroundZ)) {
      mGizmoGroundX = mGizmoStart.x;
      mGizmoGroundZ = mGizmoStart.z;
    }
    gpg::Logf("editor: move gizmo %s drag from %.2f, %.2f, %.2f",
              part == GizmoPart::X ? "X" : part == GizmoPart::Y ? "Y" : part == GizmoPart::Z ? "Z" : "free",
              static_cast<double>(mGizmoStart.x), static_cast<double>(mGizmoStart.y), static_cast<double>(mGizmoStart.z));
  }

  Wm3::Vec3f EdMapScene::GizmoDisplacement(const POINT at) const
  {
    if (mGizmoDrag == GizmoPart::Free) {
      float x = 0.0f;
      float z = 0.0f;
      if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), x, z)) {
        return Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      }
      return Wm3::Vec3f{x - mGizmoGroundX, 0.0f, z - mGizmoGroundZ};
    }
    // The arm on screen at the drag's start; the cursor's move along it, in world units.
    const Wm3::Vec3f axis = GizmoAxis(mGizmoDrag);
    const Wm3::Vector2f from = mCamera->Project(mGizmoStart);
    const Wm3::Vector2f to = mCamera->Project(Wm3::Vec3f{mGizmoStart.x + axis.x * mGizmoDragLength, mGizmoStart.y + axis.y * mGizmoDragLength,
                                                         mGizmoStart.z + axis.z * mGizmoDragLength});
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

  Wm3::Vec3f EdMapScene::GizmoPlace(const Wm3::Vec3f& start, const Wm3::Vec3f& move, const bool resource) const
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
    const float ground = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z)));
    float y = 0.0f;
    if (mGizmoDrag == GizmoPart::Y) {
      y = std::max(start.y + move.y, ground);
    } else if (mTools != nullptr && mTools->KeepOnGround()) {
      y = ground;
    } else {
      y = std::max(start.y, ground);
    }
    return Wm3::Vec3f{x, y, z};
  }

  float EdMapScene::SnapToGrid(const float value) const
  {
    if (mTools == nullptr || !mTools->SnapToGrid()) {
      return value;
    }
    const float step = mTools->GridStep();
    return std::floor(value / step) * step + step * 0.5f;
  }

  int EdMapScene::PickMarker(const float x, const float z) const
  {
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const float reach = std::max(2.5f, mDistance * 0.006f); // about the size the markers are drawn at
    int best = -1;
    float bestDistance = reach;
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float mx = 0.0f, my = 0.0f, mz = 0.0f;
      if (!MarkerPosition(markers[i], mx, my, mz) || MarkerHidden(markers[i])) {
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

  bool EdMapScene::MarkerHidden(const SaveEntry& marker) const
  {
    return mTools != nullptr && !mTools->HiddenMarkerTypes().empty() && mTools->HiddenMarkerTypes().count(MarkerTypeOf(marker)) != 0;
  }

  void EdMapScene::SelectMarkers(const std::vector<std::string>& names, const bool add)
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

  void EdMapScene::FrameMarker(const std::string& name, const float distance)
  {
    for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (marker.name == name && MarkerPosition(marker, x, y, z)) {
        mTargetX = x;
        mTargetZ = z;
        mDistance = std::min(mDistance, distance);
        ApplyCamera();
        gpg::Logf("editor: the view goes to %s at %.0f, %.0f", name.c_str(), static_cast<double>(x), static_cast<double>(z));
        return;
      }
    }
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

  void EdMapScene::EditMarker(const std::string& name, const std::string& key, const std::string& value)
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
        marker.name = value;
        std::replace(mMarkerSelection.begin(), mMarkerSelection.end(), name, value);
      } else {
        marker.Set(key, value);
      }
      mDocument.SaveDataEdited(std::move(before));
      return;
    }
  }

  void EdMapScene::LinkSelectionTo(const std::string& target)
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    const auto position = [&](const std::string& name, float& x, float& z, std::string& type) {
      for (const SaveEntry& marker : markers) {
        float y = 0.0f;
        if (marker.name == name && IsPathNode(marker) && MarkerPosition(marker, x, y, z)) {
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
    const int copies =
      HeightBrushCentres(field->width, field->height, targetX, targetZ, brush.symmetry, brush.turns, targetCopyX, targetCopyZ);
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
      const int members = HeightBrushCentres(field->width, field->height, sourceX, sourceZ, brush.symmetry, brush.turns, groupX, groupZ);
      float nearest = std::hypot(sourceX - targetX, sourceZ - targetZ);
      for (int m = 1; m < members; ++m) {
        const int i = MarkerNear(markers, sourceType, groupX[m], groupZ[m], kCopyReach);
        if (i < 0) {
          continue;
        }
        const std::string& name = markers[static_cast<std::size_t>(i)].name;
        if (name == target || std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()) {
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
      // One click toggles the pair; its symmetric copies follow it (each copy of the source to the same copy of the target).
      const bool link = !MarkersLinked(markers, source, target);
      float sourceCopyX[kMaxSymmetryCopies], sourceCopyZ[kMaxSymmetryCopies];
      (void)HeightBrushCentres(field->width, field->height, sourceX, sourceZ, brush.symmetry, brush.turns, sourceCopyX, sourceCopyZ);
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

  void EdMapScene::ChangeTeams(const std::vector<ScenarioTeam>& teams)
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

  void EdMapScene::ChangeExtraArmies(const std::string& armies)
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

  void EdMapScene::PlaceMarkers(const float x, const float z, const bool connect)
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr) {
      return;
    }
    const MarkerType& type = mTools->PlaceMarkerType();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
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
        if (!IsPathNode(marker) || MarkerTypeOf(marker) != type.type || !MarkerPosition(marker, px, py, pz) ||
            std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) == mMarkerSelection.end()) {
          continue;
        }
        const float d = std::hypot(px - x, pz - z);
        if (previous.empty() || d < nearest) {
          nearest = d;
          previous = marker.name;
          (void)HeightBrushCentres(field->width, field->height, px, pz, brush.symmetry, brush.turns, previousX, previousZ);
        }
      }
    }
    int linked = 0;
    // A click that places nothing (off the map) keeps the selection, so a path being laid isn't lost.
    std::vector<std::string> selectedBefore = std::move(mMarkerSelection);
    mMarkerSelection.clear();
    for (int c = 0; c < copies; ++c) {
      if (centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
          centreZ[c] > static_cast<float>(field->height - 1)) {
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
        for (const std::string& army : mDocument.Armies()) {
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
        const std::string fromName = c == 0 ? previous : (from >= 0 ? markers[static_cast<std::size_t>(from)].name : std::string());
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
          (void)MarkerPosition(marker, fx, fy, fz);
        }
      }
      gpg::Logf("editor: %zu %s markers placed (the first at %.2f, %.2f), %zu markers now", mMarkerSelection.size(), type.type,
                static_cast<double>(fx), static_cast<double>(fz), markers.size());
    } else {
      mMarkerSelection = std::move(selectedBefore);
    }
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
      if (MarkerTypeOf(marker) == "Blank Marker" &&
          std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()) {
        mDocument.RemoveArmy(marker.name);
      }
    }
    markers.erase(std::remove_if(markers.begin(), markers.end(),
                                 [&](const SaveEntry& marker) {
                                   return std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end();
                                 }),
                  markers.end());
    if (markers.size() != count) {
      for (const std::string& name : mMarkerSelection) {
        (void)RemoveLinksTo(markers, name);
      }
    }
    mMarkerSelection.clear();
    if (markers.size() != count) {
      mDocument.SaveDataEdited(std::move(before));
      gpg::Logf("editor: %zu markers deleted, %zu now", count - markers.size(), markers.size());
    }
  }

  void EdMapScene::DrawMarkers(moho::CD3DPrimBatcher& batcher, const bool all)
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
        if (!MarkerHidden(marker) && MarkerPosition(marker, x, y, z)) {
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
          batcher.DrawLine(vertex(from->second[0], from->second[1] + 2.0f, from->second[2], color),
                           vertex(to->second[0], to->second[1] + 2.0f, to->second[2], color));
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
      if (!MarkerPosition(marker, x, y, z)) {
        continue;
      }
      const std::uint32_t color = MarkerColor(marker);
      const float r = start ? 5.0f : (type == "Hydrocarbon" ? 3.0f : 1.6f);
      const float base = y + 0.5f;
      // A diamond on the ground and a post above it.
      batcher.DrawLine(vertex(x - r, base, z, color), vertex(x, base, z - r, color));
      batcher.DrawLine(vertex(x, base, z - r, color), vertex(x + r, base, z, color));
      batcher.DrawLine(vertex(x + r, base, z, color), vertex(x, base, z + r, color));
      batcher.DrawLine(vertex(x, base, z + r, color), vertex(x - r, base, z, color));
      batcher.DrawLine(vertex(x, base, z, color), vertex(x, base + (start ? 10.0f : 4.0f), z, color));
      if (std::find(mMarkerSelection.begin(), mMarkerSelection.end(), marker.name) != mMarkerSelection.end()) {
        constexpr std::uint32_t kSelected = 0xF0FFE040u;
        for (int s = 0; s < 20; ++s) {
          const float a0 = 2.0f * kPi * static_cast<float>(s) / 20.0f;
          const float a1 = 2.0f * kPi * static_cast<float>(s + 1) / 20.0f;
          batcher.DrawLine(vertex(x + std::cos(a0) * (r + 1.5f), base, z + std::sin(a0) * (r + 1.5f), kSelected),
                           vertex(x + std::cos(a1) * (r + 1.5f), base, z + std::sin(a1) * (r + 1.5f), kSelected));
        }
      }
    }
  }

  void EdMapScene::DrawResourceSplats(moho::CD3DPrimBatcher& batcher, const moho::CHeightField& field)
  {
    if (!mSplatsLoaded) {
      mSplatsLoaded = true;
      mMassSplat = moho::CD3DBatchTexture::FromFile("/env/common/splats/mass_marker.dds", 0);
      mHydroSplat = moho::CD3DBatchTexture::FromFile("/env/common/splats/hydrocarbon_marker.dds", 0);
      gpg::Logf("editor: resource splats %s, %s", mMassSplat ? "mass loaded" : "mass missing", mHydroSplat ? "hydrocarbon loaded" : "hydrocarbon missing");
    }
    // The ground's height between samples, a little above it so the splat doesn't sink into the terrain's mesh.
    const auto height = [&field](const float x, const float z) {
      const float cx = std::clamp(x, 0.0f, static_cast<float>(field.width - 1));
      const float cz = std::clamp(z, 0.0f, static_cast<float>(field.height - 1));
      const int x0 = std::min(static_cast<int>(cx), field.width - 2);
      const int z0 = std::min(static_cast<int>(cz), field.height - 2);
      const float fx = cx - static_cast<float>(x0);
      const float fz = cz - static_cast<float>(z0);
      const auto at = [&](const int sx, const int sz) { return static_cast<float>(field.data[sz * field.width + sx]) / 128.0f; };
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
      if ((!isMass && type != "Hydrocarbon") || MarkerHidden(marker) || !MarkerPosition(marker, x, y, z)) {
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

  int EdMapScene::PickDecal(const float x, const float z) const
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

  void EdMapScene::PlaceDecals(const float x, const float z)
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
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies], aheadZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(field->width, field->height, x + std::cos(yaw), z + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ);
    EdDocument::DecalSnapshot before = mDocument.DecalsNow();
    mDecalSelection.clear();
    for (int c = 0; c < copies; ++c) {
      if (centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
          centreZ[c] > static_cast<float>(field->height - 1)) {
        continue;
      }
      const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
      const DecalFootprint footprint = DecalAround(centreX[c], centreZ[c], mTools->DecalSizeX(), mTools->DecalSizeZ(), heading);
      DecalState state;
      state.type = DecalTypeForTexture(texture);
      state.names[0] = texture;
      state.scale[0] = footprint.sizeX;
      state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
      state.scale[2] = footprint.sizeZ;
      state.position[0] = footprint.x;
      state.position[1] = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(centreX[c])),
                                                         static_cast<std::int32_t>(std::lround(centreZ[c])));
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
      gpg::Logf("editor: %zu decals placed (%s%s%s, %.1f x %.1f), %d decals now", mDecalSelection.size(), texture.c_str(),
                pair.empty() ? "" : " with ", pair.c_str(), static_cast<double>(mTools->DecalSizeX()),
                static_cast<double>(mTools->DecalSizeZ()), decals->GetDecalCount());
    }
  }

  std::vector<std::pair<float, float>> EdMapScene::DecalPathCopy(const std::vector<std::pair<float, float>>& path, const int c,
                                                                  int& copies) const
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const HeightBrush brush = mTools->CurrentHeightBrush();
    std::vector<std::pair<float, float>> copy;
    copies = 1;
    for (const auto& [x, z] : path) {
      float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
      copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, cx, cz);
      if (c >= copies || cx[c] < 0.0f || cz[c] < 0.0f || cx[c] > static_cast<float>(field->width - 1) ||
          cz[c] > static_cast<float>(field->height - 1)) {
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
      for (const DecalFootprint& footprint : DecalsAlongPath(path, mTools->DecalSizeX(), mTools->DecalSizeZ(), mTools->DecalOverlap())) {
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
        state.position[1] = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(cx)), static_cast<std::int32_t>(std::lround(cz)));
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
      gpg::Logf("editor: path of %zu points: %zu decals placed (%s, %.1f x %.1f, overlap %.2f), %d decals now", mDecalPath.size(),
                mDecalSelection.size(), texture.c_str(), static_cast<double>(mTools->DecalSizeX()), static_cast<double>(mTools->DecalSizeZ()),
                static_cast<double>(mTools->DecalOverlap()), decals->GetDecalCount());
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

  void EdMapScene::DrawDecalOutlines(moho::CD3DPrimBatcher& batcher, const moho::CHeightField& field)
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
        const std::vector<DecalFootprint> along = DecalsAlongPath(copy, mTools->DecalSizeX(), mTools->DecalSizeZ(), mTools->DecalOverlap());
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
          laid += static_cast<int>(DecalsAlongPath(DecalPathCopy(mDecalPath, c, unused), mTools->DecalSizeX(), mTools->DecalSizeZ(),
                                                   mTools->DecalOverlap()).size());
        }
        mDecalPathPreview = laid;
      }
    } else if (mTools->DecalPlaceMode()) {
      // The decal to come, and its symmetric copies.
      const HeightBrush brush = mTools->CurrentHeightBrush();
      const float yaw = mTools->DecalTurnDegrees() * kPi / 180.0f;
      float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies], aheadZ[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(field.width, field.height, gx, gz, brush.symmetry, brush.turns, centreX, centreZ);
      (void)HeightBrushCentres(field.width, field.height, gx + std::cos(yaw), gz + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ);
      for (int c = 0; c < copies; ++c) {
        const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
        outline(DecalAround(centreX[c], centreZ[c], mTools->DecalSizeX(), mTools->DecalSizeZ(), heading), c == 0 ? 0xF0FFFFFFu : 0xE0FF9A3Cu);
      }
    } else if (const int hover = PickDecal(gx, gz); hover >= 0) {
      if (const moho::CWldTerrainDecal* const decal = FindDecal(*decals, hover); decal != nullptr) {
        outline(FootprintOf(*decal), 0xC0FFFFFFu);
      }
    }
  }

  int EdMapScene::PickProp(const float x, const float z) const
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
      gpg::Logf("editor: prop edit: %zu props before, %zu now", before, mMap != nullptr && mMap->mProps != nullptr ? mMap->mProps->mEntries.size() : 0U);
    }
    mObjectBefore = {};
    mObjectStroke = false;
    mObjectsChanged = false;
    mDragSelection = false;
  }

  void EdMapScene::MovePropTo(const int index, const Wm3::Vec3f& position)
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

  void EdMapScene::TurnSelection(const float radians)
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

  void EdMapScene::PlaceProps(const float x, const float z, const float fixedYaw)
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || mTools->PropBlueprint().empty()) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    // The turn: random or none; each copy's heading is the cursor's heading carried through the symmetry
    // (the copies of a point one unit ahead).
    mScatterSeed = mScatterSeed * 1664525U + 1013904223U;
    const float yaw = fixedYaw > -100.0f            ? fixedYaw
                      : mTools->RandomPropTurn() ? static_cast<float>(mScatterSeed >> 8) / 16777216.0f * 6.2831853f
                                                 : 0.0f;
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies], aheadZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(field->width, field->height, x + std::cos(yaw), z + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ);
    for (int c = 0; c < copies; ++c) {
      if (centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
          centreZ[c] > static_cast<float>(field->height - 1)) {
        continue;
      }
      const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
      centreX[c] = SnapToGrid(centreX[c]);
      centreZ[c] = SnapToGrid(centreZ[c]);
      moho::CWldPropEntry entry;
      entry.mBlueprintPath.assign(mTools->PropBlueprint().c_str());
      entry.mTransform.pos_ = Wm3::Vec3f{centreX[c],
                                         mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(centreX[c])),
                                                                        static_cast<std::int32_t>(std::lround(centreZ[c]))),
                                         centreZ[c]};
      entry.mTransform.orient_ = Wm3::Quatf(std::cos(heading * 0.5f), 0.0f, std::sin(heading * 0.5f), 0.0f);
      // The prop as the file will give it back (its record is what gets saved).
      const PropRecord record = PropRecordFor(mTools->PropBlueprint(), entry.mTransform);
      entry.mTransform = record.loaded;
      mDocument.AddProp(entry, record);
      mProps.push_back(MakePropInstance(entry));
      // Only a prop really placed makes the stroke an undo step (copies off the map are skipped).
      mObjectsChanged = true;
      mDocument.SetModified(true);
    }
  }

  void EdMapScene::EraseProps(const float x, const float z)
  {
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    if (mTools == nullptr || field == nullptr || mMap->mProps == nullptr) {
      return;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    auto& entries = mMap->mProps->mEntries;
    for (std::size_t i = entries.size(); i-- > 0;) {
      bool inside = false;
      for (int c = 0; c < copies && !inside; ++c) {
        inside = std::hypot(entries[i].mTransform.pos_.x - centreX[c], entries[i].mTransform.pos_.z - centreZ[c]) < brush.radius;
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
    if (field == nullptr || mTools == nullptr || !mTools->PropsToolActive() || mTools->CurrentPropMode() != EdTools::PropMode::Single ||
        mTools->PropBlueprint().empty() || (::GetKeyState(VK_SHIFT) & 0x8000) != 0 ||
        !GroundAt(static_cast<float>(mCursor.x), static_cast<float>(mCursor.y), gx, gz)) {
      hide();
      return;
    }
    // Where the click would put each copy, as PlaceProps does.
    const HeightBrush brush = mTools->CurrentHeightBrush();
    const float yaw = mTools->RandomPropTurn() ? mNextPropYaw : 0.0f;
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies], aheadZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, gx, gz, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(field->width, field->height, gx + std::cos(yaw), gz + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ);
    const auto transformOf = [&](const int c) {
      const float heading = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
      const float x = SnapToGrid(centreX[c]);
      const float z = SnapToGrid(centreZ[c]);
      moho::CWldPropEntry entry;
      entry.mBlueprintPath.assign(mTools->PropBlueprint().c_str());
      entry.mTransform.pos_ = Wm3::Vec3f{x, mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))), z};
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
      const bool onMap = centreX[c] >= 0.0f && centreZ[c] >= 0.0f && centreX[c] <= static_cast<float>(field->width - 1) &&
                         centreZ[c] <= static_cast<float>(field->height - 1);
      const moho::CWldPropEntry entry = transformOf(c);
      instance->SetStance(entry.mTransform, entry.mTransform);
      instance->isHidden = onMap ? 0 : 1;
    }
  }

  std::string EdMapScene::PropDetails(const std::string& path) const
  {
    if (path == mDetailsFor) {
      return mDetails;
    }
    mDetailsFor = path;
    mDetails.clear();
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
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
        (void)std::snprintf(one, sizeof(one), "%s%s to %.0f", lods.empty() ? "" : ", ", name.substr(slash == std::string::npos ? 0 : slash + 1).c_str(),
                            static_cast<double>(lod.mLodCutoff));
        lods += one;
      }
    }
    (void)std::snprintf(text, sizeof(text), "Reclaim %.0f mass, %.0f energy. Scale %.2f. %zu LOD%s: %s", static_cast<double>(blueprint->Economy.ReclaimMassMax),
                        static_cast<double>(blueprint->Economy.ReclaimEnergyMax), static_cast<double>(blueprint->Display.UniformScale),
                        mesh != nullptr ? static_cast<std::size_t>(mesh->mLods.size()) : 0U, mesh != nullptr && mesh->mLods.size() == 1 ? "" : "s",
                        lods.empty() ? "(no mesh)" : lods.c_str());
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
    mUnitSelection.erase(std::remove_if(mUnitSelection.begin(), mUnitSelection.end(),
                                        [&](const auto& unit) { return UnitRefIndex(unit.first, unit.second) < 0; }),
                         mUnitSelection.end());
  }

  int EdMapScene::UnitRefIndex(const std::string& army, const std::string& name) const
  {
    for (std::size_t i = 0; i < mUnitRefs.size(); ++i) {
      if (mUnitRefs[i].name == name && mUnitRefs[i].army == army) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  int EdMapScene::PickUnit(const float x, const float z) const
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

  bool EdMapScene::EditArmyUnits(const std::string& army, const std::function<void(UnitGroup&)>& change)
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
    moho::VTransform UnitTransform(const Wm3::Vec3f& position, const float (&orientation)[3])
    {
      moho::VTransform transform{};
      transform.pos_ = position;
      Wm3::Vector3f rows[3];
      (void)moho::BuildRotationMatrixFromEulerHPR(rows, orientation[0], orientation[1], orientation[2]);
      (void)moho::MatrixRowsToQuatCanonical(rows, &transform.orient_);
      return transform;
    }
  } // namespace

  void EdMapScene::PlaceUnits(const float x, const float z)
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
    float centreX[kMaxSymmetryCopies], centreZ[kMaxSymmetryCopies], aheadX[kMaxSymmetryCopies], aheadZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(field->width, field->height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    (void)HeightBrushCentres(field->width, field->height, x + std::cos(yaw), z + std::sin(yaw), brush.symmetry, brush.turns, aheadX, aheadZ);
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
        if (MarkerTypeOf(marker) == "Blank Marker" && MarkerPosition(marker, mx, my, mz)) {
          starts.push_back({marker.name, {mx, mz}});
        }
      }
      for (const auto& [name, position] : starts) {
        if (name != army) {
          continue;
        }
        float startX[kMaxSymmetryCopies], startZ[kMaxSymmetryCopies];
        (void)HeightBrushCentres(field->width, field->height, position[0], position[1], brush.symmetry, brush.turns, startX, startZ);
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
      if (centreX[c] < 0.0f || centreZ[c] < 0.0f || centreX[c] > static_cast<float>(field->width - 1) ||
          centreZ[c] > static_cast<float>(field->height - 1)) {
        continue;
      }
      SaveUnit unit;
      unit.name = "UNIT_" + std::to_string(++highest);
      unit.type = type;
      unit.position[0] = SnapToGrid(centreX[c]);
      unit.position[2] = SnapToGrid(centreZ[c]);
      unit.position[1] = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(unit.position[0])),
                                                        static_cast<std::int32_t>(std::lround(unit.position[2])));
      // The saves keep a unit's turn in Orientation's second value.
      unit.orientation[1] = std::atan2(aheadZ[c] - centreZ[c], aheadX[c] - centreX[c]);
      const std::string name = unit.name;
      if (EditArmyUnits(armyOf[c], [&](UnitGroup& group) { AddUnit(group, unit); })) {
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
      gpg::Logf("editor: %zu %s units placed (%s), %zu units now", placed.size(), type.c_str(), where.c_str(), mUnitRefs.size());
    }
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
      if (EditArmyUnits(army, [&](UnitGroup& group) { removed = RemoveUnit(group, name); }) && removed) {
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

  void EdMapScene::DeleteProps()
  {
    DeletePropPreview();
    DeleteUnits();
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mProps) {
        delete instance;
      }
    }
    mProps.clear();
    mPropsDone = false;
  }

  bool EdMapScene::GroundAt(const float x, const float y, float& outX, float& outZ) const
  {
    if (mCamera == nullptr) {
      return false;
    }
    const Wm3::Vector3f point = mCamera->CameraScreenToSurface(Wm3::Vector2f(x, y));
    // A ray that misses the map (the sky past the horizon) gives no usable point.
    const float margin = mMapExtent;
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    if (!std::isfinite(point.x) || !std::isfinite(point.z) || point.x < bounds.Min.x - margin ||
        point.x > bounds.Max.x + margin || point.z < bounds.Min.z - margin || point.z > bounds.Max.z + margin) {
      return false;
    }
    outX = point.x;
    outZ = point.z;
    return true;
  }

  void EdMapScene::MoveWithKeys(const float frameSeconds)
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
    if (GroundAt(cx, cy, centerX, centerZ) && GroundAt(cx, cy - 40.0f, upX, upZ) && GroundAt(cx + 40.0f, cy, rightX, rightZ)) {
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

  bool EdMapScene::OnWindowMessage(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
  {
    if (mMap == nullptr) {
      return false;
    }
    const POINT at{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
    if (message == WM_MOUSEMOVE || message == WM_LBUTTONDOWN) {
      mCursor = at;
    }
    switch (message) {
    case WM_LBUTTONDOWN: {
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
          BeginGizmoDrag(part, at);
          mDragMarkers = true;
          mMarkersMoved = false;
          mMarkerBefore = mDocument.SaveDataNow();
          mMarkerDragStart.clear();
          for (const std::string& selected : mMarkerSelection) {
            std::array<float, 3> start{};
            for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
              if (marker.name == selected) {
                (void)MarkerPosition(marker, start[0], start[1], start[2]);
              }
            }
            mMarkerDragStart.push_back(start);
          }
          ::SetCapture(window);
          ::SetFocus(window);
          return true;
        }
        const float reach = std::max(4.0f, mDistance * 0.015f);
        mBorderEdges = 0;
        if (area) {
          const bool alongZ = groundZ > static_cast<float>(area->z0) - reach && groundZ < static_cast<float>(area->z1) + reach;
          const bool alongX = groundX > static_cast<float>(area->x0) - reach && groundX < static_cast<float>(area->x1) + reach;
          mBorderEdges |= alongZ && std::fabs(groundX - static_cast<float>(area->x0)) < reach ? 1 : 0;
          mBorderEdges |= alongX && std::fabs(groundZ - static_cast<float>(area->z0)) < reach ? 2 : 0;
          mBorderEdges |= alongZ && std::fabs(groundX - static_cast<float>(area->x1)) < reach ? 4 : 0;
          mBorderEdges |= alongX && std::fabs(groundZ - static_cast<float>(area->z1)) < reach ? 8 : 0;
        }
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
        if ((wParam & MK_CONTROL) == 0 && std::find(mMarkerSelection.begin(), mMarkerSelection.end(), name) == mMarkerSelection.end()) {
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
              (void)MarkerPosition(marker, start[0], start[1], start[2]);
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
        if (part == GizmoPart::None && !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          return true;
        }
        const int hit = part == GizmoPart::None ? PickUnit(groundX, groundZ) : -1;
        if (part == GizmoPart::None && (wParam & MK_SHIFT) != 0) {
          if (hit >= 0) {
            mUnitSelection = {{mUnitRefs[static_cast<std::size_t>(hit)].army, mUnitRefs[static_cast<std::size_t>(hit)].name}};
            DeleteSelectedUnits();
          }
          return true;
        }
        if (mTools->UnitPlaceMode()) {
          PlaceUnits(groundX, groundZ);
          return true;
        }
        if (part != GizmoPart::None) {
          BeginGizmoDrag(part, at);
        } else {
          const bool add = (wParam & MK_CONTROL) != 0;
          if (hit < 0) {
            if (!add) {
              mUnitSelection.clear();
            }
            return true;
          }
          const std::pair<std::string, std::string> key{mUnitRefs[static_cast<std::size_t>(hit)].army, mUnitRefs[static_cast<std::size_t>(hit)].name};
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
          mUnitDragStart.push_back(index >= 0 ? mUnitRefs[static_cast<std::size_t>(index)].position : Wm3::Vec3f{0.0f, 0.0f, 0.0f});
        }
        ::SetCapture(window);
        ::SetFocus(window);
        return true;
      }
      if (mTools != nullptr && mTools->DecalsToolActive()) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) || mDocument.Decals() == nullptr) {
          return true;
        }
        const int hit = PickDecal(groundX, groundZ);
        if ((wParam & MK_SHIFT) != 0) {
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
        const auto selected = part != GizmoPart::None ? mDecalSelection.begin() : std::find(mDecalSelection.begin(), mDecalSelection.end(), hit);
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
      if (mTools != nullptr && mTools->SelectToolActive() && mMap->mProps != nullptr) {
        if (const GizmoPart part = PickGizmo(at); part != GizmoPart::None) {
          BeginObjectStroke();
          BeginGizmoDrag(part, at);
          mDragSelection = true;
          mDragStart.clear();
          for (const int index : mSelection) {
            mDragStart.push_back(mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_);
          }
          ::SetCapture(window);
          ::SetFocus(window);
          return true;
        }
      }
      if (mTools != nullptr && (mTools->SelectToolActive() || mTools->PropsToolActive())) {
        float groundX = 0.0f;
        float groundZ = 0.0f;
        if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) || mMap->mProps == nullptr) {
          return true;
        }
        BeginObjectStroke();
        ::SetCapture(window);
        ::SetFocus(window);
        if (mTools->SelectToolActive()) {
          const int hit = PickProp(groundX, groundZ);
          const bool add = (wParam & MK_CONTROL) != 0;
          if (hit < 0) {
            if (!add) {
              mSelection.clear();
            }
          } else if (std::find(mSelection.begin(), mSelection.end(), hit) == mSelection.end()) {
            if (!add) {
              mSelection.clear();
            }
            mSelection.push_back(hit);
          }
          // A drag moves the selection over the ground.
          mDragSelection = hit >= 0;
          mDragFromX = groundX;
          mDragFromZ = groundZ;
          mDragStart.clear();
          for (const int index : mSelection) {
            mDragStart.push_back(mMap->mProps->mEntries[static_cast<std::size_t>(index)].mTransform.pos_);
          }
          return true;
        }
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
      if (mTools != nullptr && mTools->TextureToolActive()) {
        LoadMasks();
        if (!mDocument.Masks().texels.empty()) {
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
      const float groundHeight =
        mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(groundX)), static_cast<std::int32_t>(std::lround(groundZ)));
      // Plane mode: Ctrl+click picks a point of the plane instead of painting.
      if ((wParam & MK_CONTROL) != 0 && mTools->CurrentHeightBrush().mode == HeightBrushMode::Plane) {
        mTools->AddPlanePoint(groundX, groundHeight, groundZ);
        return true;
      }
      // Flatten keeps the height under the stroke's first point.
      mFlattenTo = groundHeight * 128.0f;
      mStamped = false;
      mPainting = true;
      mDocument.Heights().BeginStroke();
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    }
    case WM_LBUTTONUP:
      mGizmoDrag = GizmoPart::None;
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
              gpg::Logf("editor: %zu units moved, %s to %.2f, %.2f, %.2f", mUnitSelection.size(), mUnitSelection.front().second.c_str(),
                        static_cast<double>(p.x), static_cast<double>(p.y), static_cast<double>(p.z));
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
            if (!mMarkerSelection.empty() && marker.name == mMarkerSelection.front() && MarkerPosition(marker, x, y, z)) {
              gpg::Logf("editor: %zu markers moved, %s to %.2f, %.2f (height %.2f)", mMarkerSelection.size(), marker.name.c_str(),
                        static_cast<double>(x), static_cast<double>(z), static_cast<double>(y));
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
      if (mPainting) {
        EndStroke();
        ::ReleaseCapture();
        return true;
      }
      return false;
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
      // Middle drag orbits, Shift + middle drag pans; the right button pans.
      mDrag = (message == WM_MBUTTONDOWN && (wParam & MK_SHIFT) == 0) ? Drag::Orbit : Drag::Pan;
      mDragFrom = at;
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
      if (mDrag != Drag::None) {
        mDrag = Drag::None;
        ::ReleaseCapture();
      }
      return true;
    case WM_MOUSEMOVE: {
      if (mDrag == Drag::None) {
        if (mDragUnits) {
          Wm3::Vec3f move{0.0f, 0.0f, 0.0f};
          float groundX = 0.0f;
          float groundZ = 0.0f;
          if (mGizmoDrag != GizmoPart::None) {
            move = GizmoDisplacement(at);
          } else if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
                     std::hypot(groundX - mUnitDragFromX, groundZ - mUnitDragFromZ) > 0.05f) {
            move = Wm3::Vec3f{groundX - mUnitDragFromX, 0.0f, groundZ - mUnitDragFromZ};
          }
          if (move.x != 0.0f || move.y != 0.0f || move.z != 0.0f) {
            for (std::size_t i = 0; i < mUnitSelection.size() && i < mUnitDragStart.size(); ++i) {
              const int index = UnitRefIndex(mUnitSelection[i].first, mUnitSelection[i].second);
              if (index < 0) {
                continue;
              }
              UnitRef& ref = mUnitRefs[static_cast<std::size_t>(index)];
              ref.position = GizmoPlace(mUnitDragStart[i], move, false);
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
                const float x = mGizmoDrag == GizmoPart::Y ? mDecalDragStart[i][0] : SnapToGrid(mDecalDragStart[i][0] + move.x);
                const float z = mGizmoDrag == GizmoPart::Y ? mDecalDragStart[i][2] : SnapToGrid(mDecalDragStart[i][2] + move.z);
                const float ground = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z)));
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
          if (decals != nullptr && GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
              std::hypot(groundX - mDecalDragFromX, groundZ - mDecalDragFromZ) > 0.05f) {
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
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mMarkerDragFromX, groundZ - mMarkerDragFromZ) > 0.05f) {
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
              const float y = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
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
        if (area && field != nullptr && GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
          // On the game's 4-unit grid, inside the map, at least 4 units wide.
          const auto snap = [](const float value, const int limit) { return std::clamp(static_cast<int>(std::lround(value / 4.0f)) * 4, 0, limit); };
          const int w = field->width - 1;
          const int h = field->height - 1;
          EdDocument::PlayableRect next = *area;
          if ((mBorderEdges & 1) != 0) next.x0 = std::min(snap(groundX, w), next.x1 - 4);
          if ((mBorderEdges & 2) != 0) next.z0 = std::min(snap(groundZ, h), next.z1 - 4);
          if ((mBorderEdges & 4) != 0) next.x1 = std::max(snap(groundX, w), next.x0 + 4);
          if ((mBorderEdges & 8) != 0) next.z1 = std::max(snap(groundZ, h), next.z0 + 4);
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
        if (GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ) &&
            std::hypot(groundX - mDragFromX, groundZ - mDragFromZ) > 0.05f) {
          for (std::size_t i = 0; i < mSelection.size() && i < mDragStart.size(); ++i) {
            const float x = SnapToGrid(mDragStart[i].x + groundX - mDragFromX);
            const float z = SnapToGrid(mDragStart[i].z + groundZ - mDragFromZ);
            MovePropTo(mSelection[i], Wm3::Vec3f{x, mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))), z});
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
        if (GroundAt(static_cast<float>(from.x), static_cast<float>(from.y), fromX, fromZ) &&
            GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), toX, toZ)) {
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
      if (down && (::GetKeyState(VK_CONTROL) & 0x8000) != 0 && (wParam == 'Z' || wParam == 'Y')) {
        const bool redo = wParam == 'Y' || (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
        (void)(redo ? Redo() : Undo());
        return true;
      }
      mFast = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
      if (down && mTools != nullptr && mTools->DecalsToolActive() && mTools->DecalPathMode() &&
          (wParam == VK_RETURN || wParam == VK_BACK || wParam == VK_ESCAPE)) {
        if (wParam == VK_RETURN) {
          PlaceDecalPath();
        } else if (wParam == VK_BACK) {
          RemoveLastDecalPathPoint();
        } else {
          ClearDecalPath();
        }
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
      if (down && wParam == VK_DELETE && mTools != nullptr && mTools->MarkersToolActive() && !mMarkerSelection.empty()) {
        DeleteSelectedMarkers();
        return true;
      }
      if (down && mTools != nullptr && mTools->SelectToolActive() && !mSelection.empty()) {
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
      case VK_HOME:
        if (down) {
          FrameWholeMap();
        }
        return true;
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
