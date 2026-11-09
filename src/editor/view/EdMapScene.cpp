#include "editor/view/EdMapScene.h"

#include <algorithm>
#include <cmath>

#include <windowsx.h>

#include "editor/EdTools.h"
#include "editor/doc/EdDocument.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdHeightFile.h"
#include "editor/tools/EdSymmetryCheck.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/render/IEdRenderHook.h"
#include "moho/render/RCamManager.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
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
    if (mMap == nullptr || mCamera == nullptr || mTools == nullptr || !mTools->TerrainToolActive() || moho::ren_Viewport == nullptr) {
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
    const auto groundLine = [&](const float x0, const float z0, const float x1, const float z1) {
      const float length = std::hypot(x1 - x0, z1 - z0);
      const int steps = std::max(1, static_cast<int>(length / 4.0f));
      for (int s = 0; s < steps; ++s) {
        const float t0 = static_cast<float>(s) / steps;
        const float t1 = static_cast<float>(s + 1) / steps;
        batcher->DrawLine(groundVertex(x0 + (x1 - x0) * t0, z0 + (z1 - z0) * t0, kMirrorColor, 0.6f),
                          groundVertex(x0 + (x1 - x0) * t1, z0 + (z1 - z0) * t1, kMirrorColor, 0.6f));
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
  }

  void EdMapScene::Detach()
  {
    if (mMap == nullptr) {
      return;
    }
    // A stroke in progress ends here, so undo has it whole.
    EndStroke();
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
        mDocument.Heights().EndStroke(field->data);
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
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    std::vector<SampleRect> rects;
    if (field == nullptr || mPainting || !mDocument.Heights().Undo(field->data, rects)) {
      return false;
    }
    RefreshHeights(rects);
    mDocument.SetModified(true);
    if (mCheckDone) {
      RunSymmetryCheck();
    }
    return true;
  }

  bool EdMapScene::Redo()
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    std::vector<SampleRect> rects;
    if (field == nullptr || mPainting || !mDocument.Heights().Redo(field->data, rects)) {
      return false;
    }
    RefreshHeights(rects);
    mDocument.SetModified(true);
    if (mCheckDone) {
      RunSymmetryCheck();
    }
    return true;
  }

  void EdMapScene::RunSymmetryCheck()
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return;
    }
    mCheckedWith = mTools->CurrentHeightBrush();
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
    // One undo step over the whole map.
    const SampleRect whole{0, 0, field->width - 1, field->height - 1};
    mDocument.Heights().BeginStroke();
    mDocument.Heights().BeforeWrite(field->data, whole);
    (void)MakeSymmetric(field->data, field->width, field->height, brush.symmetry, brush.turns);
    mDocument.Heights().EndStroke(field->data);
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
    MoveWithKeys(frameSeconds);
    if (mPainting) {
      PaintStroke(frameSeconds);
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
    if (mMap->mProps == nullptr) {
      return;
    }
    int missing = 0;
    for (const moho::CWldPropEntry& entry : mMap->mProps->mEntries) {
      // The blueprint as a prop's entity finds it: the file name normalized into a resource id.
      moho::RResId id{};
      gpg::STR_CopyFilename(&id.name, &entry.mBlueprintPath);
      moho::RPropBlueprint* const blueprint = rules->GetPropBlueprint(id);
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
      instance->SetStance(entry.mTransform, entry.mTransform);
      instance->isHidden = 0;
      mProps.push_back(instance);
    }
    gpg::Logf("editor: %zu props drawn, %d without a blueprint or mesh", mProps.size(), missing);
  }

  void EdMapScene::DeleteProps()
  {
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
      if (mTools == nullptr || !mTools->TerrainToolActive()) {
        return false;
      }
      float groundX = 0.0f;
      float groundZ = 0.0f;
      if (!GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)) {
        return true;
      }
      // Flatten keeps the height under the stroke's first point.
      mFlattenTo =
        mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(std::lround(groundX)), static_cast<std::int32_t>(std::lround(groundZ))) *
        128.0f;
      mPainting = true;
      mDocument.Heights().BeginStroke();
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    }
    case WM_LBUTTONUP:
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
        return mPainting;
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
