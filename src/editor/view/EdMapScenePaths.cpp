// The kept paths in the view (FAF Studio's paths.lua and pathtool.lua): editing their points with the mouse, drawing
// them, and their preview, apply, unapply and bake on the map. The model and its build are tools/EdKeptPaths.cpp.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/tools/EdDecalShape.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdMaskBrush.h"
#include "gpg/core/utils/Logging.h"
#include "moho/mesh/Mesh.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <functional>

namespace faf::editor
{
  namespace
  {
    constexpr float kPathPi = 3.14159265f;

    float FieldHeight(
      const moho::CHeightField& field,
      float x,
      float z
    )
    {
      x = std::clamp(x, 0.0f, static_cast<float>(field.width - 1));
      z = std::clamp(z, 0.0f, static_cast<float>(field.height - 1));
      const int ix = std::min(static_cast<int>(x), field.width - 2);
      const int iz = std::min(static_cast<int>(z), field.height - 2);
      const float tx = x - static_cast<float>(ix);
      const float tz = z - static_cast<float>(iz);
      const auto at = [&field](const int sx, const int sz) {
        return static_cast<float>(field.data[static_cast<std::size_t>(sz) * field.width + sx]) / 128.0f;
      };
      return (at(ix, iz) * (1.0f - tx) + at(ix + 1, iz) * tx) * (1.0f - tz) +
        (at(ix, iz + 1) * (1.0f - tx) + at(ix + 1, iz + 1) * tx) * tz;
    }

    moho::CD3DPrimBatcher::Vertex At(
      const float x,
      const float y,
      const float z,
      const std::uint32_t colour
    )
    {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = x;
      v.mY = y;
      v.mZ = z;
      v.mColor = colour;
      return v;
    }

    /** The point's index under (x, z) within `reach`, or -1. */
    int PickPoint(
      const KeptPath& path,
      const float x,
      const float z,
      const float reach
    )
    {
      int best = -1;
      float bestD = reach;
      for (std::size_t i = 0; i < path.points.size(); ++i) {
        const float d = std::hypot(path.points[i].x - x, path.points[i].z - z);
        if (d < bestD) {
          bestD = d;
          best = static_cast<int>(i);
        }
      }
      return best;
    }

    /** The segment (its first control point) nearest (x, z) within `reach`, or -1. */
    int PickSegment(
      const KeptPath& path,
      const float x,
      const float z,
      const float reach
    )
    {
      const KeptPathSamples S = SampleKeptPath(path, 1.0f);
      int best = -1;
      float bestD = reach;
      for (std::size_t k = 0; k < S.Count(); ++k) {
        const float d = std::hypot(S.x[k] - x, S.z[k] - z);
        if (d < bestD) {
          bestD = d;
          best = S.seg[k];
        }
      }
      return best;
    }
  } // namespace

  float EdMapScene::GroundHeightAt(
    const float x,
    const float z
  ) const
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    return field != nullptr ? FieldHeight(*field, x, z) : 0.0f;
  }

  std::vector<KeptPathImage> EdMapScene::PathImages() const
  {
    std::vector<KeptPathImage> images;
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return images;
    }
    const HeightBrush brush = mTools->CurrentHeightBrush();
    if (brush.symmetry == Symmetry::None) {
      return images;
    }
    const int width = field->width;
    const int height = field->height;
    const Symmetry symmetry = brush.symmetry;
    const int turns = brush.turns;
    // Copy c of every point is image c; a reflection turns a triangle's winding over.
    float ax[kMaxSymmetryCopies], az[kMaxSymmetryCopies];
    float bx[kMaxSymmetryCopies], bz[kMaxSymmetryCopies];
    float cx[kMaxSymmetryCopies], cz[kMaxSymmetryCopies];
    const float mx = static_cast<float>(width - 1) * 0.5f;
    const float mz = static_cast<float>(height - 1) * 0.5f;
    const int copies = HeightBrushCentres(width, height, mx * 0.6f, mz * 0.5f, symmetry, turns, ax, az);
    (void)HeightBrushCentres(width, height, mx * 0.6f + 8.0f, mz * 0.5f, symmetry, turns, bx, bz);
    (void)HeightBrushCentres(width, height, mx * 0.6f, mz * 0.5f + 8.0f, symmetry, turns, cx, cz);
    const auto winding =
      [](const float x0, const float z0, const float x1, const float z1, const float x2, const float z2) {
      return (x1 - x0) * (z2 - z0) - (z1 - z0) * (x2 - x0);
    };
    const float own = winding(ax[0], az[0], bx[0], bz[0], cx[0], cz[0]);
    for (int c = 1; c < copies; ++c) {
      KeptPathImage image;
      image.mirror = winding(ax[c], az[c], bx[c], bz[c], cx[c], cz[c]) * own < 0.0f;
      image.map = [width, height, symmetry, turns, c](const float x, const float z, float& ox, float& oz) {
        float px[kMaxSymmetryCopies], pz[kMaxSymmetryCopies];
        const int n = HeightBrushCentres(width, height, x, z, symmetry, turns, px, pz);
        ox = c < n ? px[c] : x;
        oz = c < n ? pz[c] : z;
      };
      images.push_back(std::move(image));
    }
    return images;
  }

  bool EdMapScene::RevertPathPreview()
  {
    if (!mPathPreviewShown) {
      return false;
    }
    mPathPreviewShown = false;
    if (mPathEdit != nullptr) {
      mPathEdit->previewShown = false;
    }
    // Only while the preview is still the newest edit: else it stays, as any edit would.
    if (
      mDocument.UndoOrder().size() == mPathPreviewDepth && !mDocument.UndoOrder().empty() &&
      mDocument.UndoOrder().back() == EdDocument::EditKind::Heights
    ) {
      return Undo();
    }
    return false;
  }

  std::string EdMapScene::PreviewKeptPath(
    const std::vector<std::string>& ids
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting || mPaintingMask || mObjectStroke) {
      return "No map, or a stroke is under way.";
    }
    (void)RevertPathPreview();
    KeptPathGround ground;
    ground.words = reinterpret_cast<const std::uint16_t*>(field->data);
    ground.width = field->width;
    ground.height = field->height;
    ground.water = mDocument.WaterNow().elevation;
    ground.images = PathImages();
    // Each path previewed on the ground the ones before it made: the heights written one after another.
    mDocument.Heights().BeginStroke();
    int shown = 0;
    float lowest = 0.0f;
    float highest = 0.0f;
    std::vector<SampleRect> rects;
    for (const std::string& id : ids) {
      const KeptPath* const path = mDocument.PathsNow().set.Find(id);
      if (path == nullptr || path->points.size() < 2) {
        continue;
      }
      const auto it = mDocument.PathsNow().results.find(id);
      const auto built =
        BuildKeptPath(*path, ground, it != mDocument.PathsNow().results.end() ? it->second.get() : nullptr, false);
      if (!built) {
        mDocument.Heights().EndStroke(field->data);
        return "Preview: " + built.error();
      }
      const KeptPathPlan& plan = *built;
      const SampleRect rect{plan.x0, plan.z0, plan.x1, plan.z1};
      mDocument.Heights().BeforeWrite(field->data, rect);
      const int w = plan.x1 - plan.x0 + 1;
      for (int z = plan.z0; z <= plan.z1; ++z) {
        for (int x = plan.x0; x <= plan.x1; ++x) {
          field->data[static_cast<std::size_t>(z) * field->width + x] =
            plan.words[static_cast<std::size_t>(z - plan.z0) * w + (x - plan.x0)];
        }
      }
      rects.push_back(rect);
      lowest = std::min(lowest, plan.lowest);
      highest = std::max(highest, plan.highest);
      ++shown;
    }
    const std::size_t before = mDocument.Heights().UndoCount();
    mDocument.Heights().EndStroke(field->data);
    if (mDocument.Heights().UndoCount() == before) {
      return shown == 0 ? "No path with two points or more to preview." : "The preview changes nothing.";
    }
    mDocument.EditEnded(EdDocument::EditKind::Heights);
    mDocument.SetModified(true);
    RefreshHeights(rects);
    mPathPreviewShown = true;
    mPathPreviewDepth = mDocument.UndoOrder().size();
    if (mPathEdit != nullptr) {
      mPathEdit->previewShown = true;
    }
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Preview of %d path%s: %zu samples, height change %+.1f .. %+.1f",
      shown,
      shown == 1 ? "" : "s",
      mDocument.Heights().NewestChangedSamples(),
      static_cast<double>(lowest),
      static_cast<double>(highest)
    );
    return text;
  }

  void EdMapScene::SwapPathItems(
    const KeptPathResult* const result,
    const KeptPathResult* const next,
    bool& propsChanged,
    bool& decalsChanged
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    // The old ones: found by blueprint (texture) and place.
    if (result != nullptr && !result->props.empty() && mMap->mProps != nullptr) {
      auto& entries = mMap->mProps->mEntries;
      for (const KeptPathResult::Placed& item : result->props) {
        for (std::size_t i = entries.size(); i-- > 0;) {
          if (
            entries[i].mBlueprintPath.c_str() == item.what &&
            std::hypot(entries[i].mTransform.pos_.x - item.x, entries[i].mTransform.pos_.z - item.z) < 0.05f
          ) {
            if (i < mProps.size()) {
              delete mProps[i];
              mProps.erase(mProps.begin() + static_cast<std::ptrdiff_t>(i));
            }
            mDocument.DeletePropAt(i);
            propsChanged = true;
            break;
          }
        }
      }
    }
    if (result != nullptr && !result->decals.empty() && mDocument.Decals() != nullptr) {
      EdDocument::DecalSnapshot decals = mDocument.DecalsNow();
      const std::size_t was = decals.size();
      for (const KeptPathResult::Placed& item : result->decals) {
        for (std::size_t i = decals.size(); i-- > 0;) {
          if (
            decals[i].names[0] == item.what &&
            std::hypot(decals[i].position[0] - item.x, decals[i].position[2] - item.z) < 0.05f
          ) {
            decals.erase(decals.begin() + static_cast<std::ptrdiff_t>(i));
            break;
          }
        }
      }
      if (decals.size() != was) {
        mDocument.RestoreDecals(decals);
        decalsChanged = true;
      }
    }
    if (next == nullptr) {
      return;
    }
    if (!next->props.empty() && mMap->mProps != nullptr) {
      for (const KeptPathResult::Placed& item : next->props) {
        moho::CWldPropEntry entry;
        entry.mBlueprintPath.assign(item.what.c_str());
        entry.mTransform.pos_ = Wm3::Vec3f{item.x, item.y, item.z};
        entry.mTransform.orient_ = Wm3::Quatf(std::cos(item.heading * 0.5f), 0.0f, std::sin(item.heading * 0.5f), 0.0f);
        PropRecord record = PropRecordFor(item.what, entry.mTransform);
        record.values[12] = record.values[13] = record.values[14] = item.scale;
        entry.mTransform = record.loaded;
        mDocument.AddProp(entry, record);
        mProps.push_back(MakePropInstance(entry));
        propsChanged = true;
      }
    }
    if (!next->decals.empty()) {
      if (moho::IDecalManager* const manager = mDocument.Decals(); manager != nullptr) {
        for (const KeptPathResult::Placed& item : next->decals) {
          const DecalFootprint footprint = DecalAround(item.x, item.z, item.scale, item.scale, item.heading);
          DecalState state;
          state.type = DecalTypeForTexture(item.what);
          state.names[0] = item.what;
          state.scale[0] = footprint.sizeX;
          state.scale[1] = std::max(footprint.sizeX, footprint.sizeZ);
          state.scale[2] = footprint.sizeZ;
          state.position[0] = footprint.x;
          state.position[1] = item.y;
          state.position[2] = footprint.z;
          state.orientation[1] = item.heading;
          state.cutoff = 1000.0f;
          if (AddDecal(*manager, state) != nullptr) {
            decalsChanged = true;
          }
        }
      }
    }
  }

  std::string EdMapScene::ApplyKeptPaths(
    const std::vector<std::string>& ids,
    const std::function<void(std::vector<SampleRect>&)>& beforeHook,
    const std::function<void(std::vector<SampleRect>&)>& afterHook,
    std::shared_ptr<const PadResult>* const skeletonPads
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting || mPaintingMask || mObjectStroke) {
      return "No map, or a stroke is under way.";
    }
    (void)RevertPathPreview();
    KeptPathGround ground;
    ground.words = reinterpret_cast<const std::uint16_t*>(field->data);
    ground.width = field->width;
    ground.height = field->height;
    ground.water = mDocument.WaterNow().elevation;
    ground.images = PathImages();
    EdDocument::PathsState pathsBefore = mDocument.PathsNow();
    EdDocument::DecalSnapshot decalsBefore = mDocument.DecalsNow();
    std::uint16_t parts = 0;
    // Heights: one stroke over every path, each built on the ground the ones before it left.
    mDocument.Heights().BeginStroke();
    std::vector<SampleRect> rects;
    if (beforeHook) {
      beforeHook(rects);
    }
    std::vector<std::pair<std::string, KeptPathPlan>> plans;
    std::string error;
    for (const std::string& id : ids) {
      const KeptPath* const path = mDocument.PathsNow().set.Find(id);
      if (path == nullptr || path->points.size() < 2) {
        continue;
      }
      const auto it = mDocument.PathsNow().results.find(id);
      auto built =
        BuildKeptPath(*path, ground, it != mDocument.PathsNow().results.end() ? it->second.get() : nullptr, true);
      if (!built) {
        error = built.error();
        break;
      }
      KeptPathPlan& plan = *built;
      const SampleRect rect{plan.x0, plan.z0, plan.x1, plan.z1};
      mDocument.Heights().BeforeWrite(field->data, rect);
      const int w = plan.x1 - plan.x0 + 1;
      for (int z = plan.z0; z <= plan.z1; ++z) {
        for (int x = plan.x0; x <= plan.x1; ++x) {
          field->data[static_cast<std::size_t>(z) * field->width + x] =
            plan.words[static_cast<std::size_t>(z - plan.z0) * w + (x - plan.x0)];
        }
      }
      rects.push_back(rect);
      plans.emplace_back(id, std::move(plan));
    }
    if (afterHook) {
      afterHook(rects);
    }
    mDocument.Heights().EndStroke(field->data);
    parts |= mDocument.Heights().LastStrokeKept() ? 1 : 0;
    if (!error.empty() && plans.empty()) {
      if ((parts & 1) != 0) {
        mDocument.EditEnded(EdDocument::EditKind::Heights);
        (void)Undo();
      }
      return "Apply: " + error;
    }
    if (!rects.empty()) {
      RefreshHeights(rects);
    }
    // Strata: one mask stroke for every path that paints (or painted before).
    std::map<std::string, std::map<int, std::vector<float>>> maskDeltas;
    std::size_t texels = 0;
    {
      bool any = false;
      for (const auto& [id, plan] : plans) {
        const auto it = mDocument.PathsNow().results.find(id);
        any = any || !plan.masks.empty() ||
          (it != mDocument.PathsNow().results.end() && it->second != nullptr && !it->second->maskDelta.empty());
      }
      if (any) {
        LoadMasks();
        EdDocument::MaskGrid& masks = mDocument.Masks();
        if (!masks.texels.empty()) {
          const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
          mDocument.MaskUndo().BeginStroke();
          mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
          const float mapSize = static_cast<float>(std::max(mDocument.Facts().sizeX, mDocument.Facts().sizeZ));
          const std::uint8_t remapped = RemappedStrata(TerrainShader());
          for (const auto& [id, plan] : plans) {
            const auto it = mDocument.PathsNow().results.find(id);
            const std::map<int, std::vector<float>>* old =
              it != mDocument.PathsNow().results.end() && it->second != nullptr ? &it->second->maskDelta : nullptr;
            std::size_t changed = 0;
            maskDeltas[id] = ApplyKeptPathMasks(
              masks.texels.data(), masks.width, masks.height, mapSize, remapped, plan.masks, old, changed
            );
            texels += changed;
          }
          mDocument.MaskUndo().EndStroke(masks.texels.data());
          if (mDocument.MaskUndo().LastStrokeKept()) {
            parts |= 2;
            UploadMasks({whole}, 0xFFu);
            UpdateCoverage();
          }
        }
      }
    }
    // Props and decals along the paths: the earlier ones off, the new ones on.
    bool propsChanged = false;
    bool decalsChanged = false;
    BeginObjectStroke();
    EdDocument::PathsState pathsAfter = mDocument.PathsNow();
    std::size_t placedProps = 0;
    std::size_t placedDecals = 0;
    for (auto& [id, plan] : plans) {
      const KeptPath* const path = pathsAfter.set.Find(id);
      auto result = std::make_shared<KeptPathResult>();
      result->x0 = plan.x0;
      result->z0 = plan.z0;
      result->x1 = plan.x1;
      result->z1 = plan.z1;
      result->heightDelta = std::move(plan.delta);
      result->maskDelta = std::move(maskDeltas[id]);
      if (path != nullptr) {
        if (path->props.on && !path->props.what.empty()) {
          for (const KeptPathItem& item : KeptPathScatterPlan(*path, path->props)) {
            result->props.push_back(
              {path->props.what, item.x, GroundHeightAt(item.x, item.z), item.z, item.heading, item.scale}
            );
          }
        }
        if (path->decals.on && !path->decals.what.empty()) {
          for (const KeptPathItem& item : KeptPathScatterPlan(*path, path->decals)) {
            result->decals.push_back(
              {path->decals.what,
               item.x,
               GroundHeightAt(item.x, item.z),
               item.z,
               item.heading,
               path->decals.size * item.scale}
            );
          }
        }
      }
      const auto old = pathsAfter.results.find(id);
      SwapPathItems(
        old != pathsAfter.results.end() ? old->second.get() : nullptr, result.get(), propsChanged, decalsChanged
      );
      placedProps += result->props.size();
      placedDecals += result->decals.size();
      pathsAfter.results[id] = std::move(result);
    }
    mObjectsChanged = propsChanged;
    if (EndObjectStroke(false)) {
      parts |= 128;
    }
    if (decalsChanged) {
      mDocument.DecalsEdited(std::move(decalsBefore), false);
      parts |= 512;
    }
    if (skeletonPads != nullptr) {
      pathsAfter.skeletonPads = *skeletonPads;
    }
    mDocument.EditPaths() = std::move(pathsAfter);
    mDocument.PathsEdited(std::move(pathsBefore), false);
    parts |= 1024;
    mDocument.BuildEdited(parts);
    char text[260];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Applied %zu path%s: %zu height samples, %zu mask texels, %zu props, %zu decals. One undo step.%s%s",
      plans.size(),
      plans.size() == 1 ? "" : "s",
      mDocument.Heights().LastStrokeKept() ? mDocument.Heights().NewestChangedSamples() : 0u,
      texels,
      placedProps,
      placedDecals,
      error.empty() ? "" : " Stopped: ",
      error.c_str()
    );
    gpg::Logf("editor: paths: %s", text);
    return text;
  }

  std::string EdMapScene::UnapplyKeptPath(
    const std::string& id
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mPainting || mPaintingMask || mObjectStroke) {
      return "No map, or a stroke is under way.";
    }
    (void)RevertPathPreview();
    const auto it = mDocument.PathsNow().results.find(id);
    if (it == mDocument.PathsNow().results.end() || it->second == nullptr) {
      return "This path has no result on the map to take off.";
    }
    const std::shared_ptr<const KeptPathResult> result = it->second;
    EdDocument::PathsState pathsBefore = mDocument.PathsNow();
    EdDocument::DecalSnapshot decalsBefore = mDocument.DecalsNow();
    std::uint16_t parts = 0;
    if (!result->heightDelta.empty()) {
      const SampleRect rect{result->x0, result->z0, result->x1, result->z1};
      mDocument.Heights().BeginStroke();
      mDocument.Heights().BeforeWrite(field->data, rect);
      const int w = result->x1 - result->x0 + 1;
      for (int z = result->z0; z <= result->z1; ++z) {
        for (int x = result->x0; x <= result->x1; ++x) {
          std::uint16_t& word = field->data[static_cast<std::size_t>(z) * field->width + x];
          word = static_cast<std::uint16_t>(std::clamp(
            static_cast<int>(word) -
              result->heightDelta[static_cast<std::size_t>(z - result->z0) * w + (x - result->x0)],
            0,
            65535
          ));
        }
      }
      mDocument.Heights().EndStroke(field->data);
      parts |= mDocument.Heights().LastStrokeKept() ? 1 : 0;
      RefreshHeights({rect});
    }
    if (!result->maskDelta.empty()) {
      LoadMasks();
      EdDocument::MaskGrid& masks = mDocument.Masks();
      if (!masks.texels.empty()) {
        const SampleRect whole{0, 0, masks.width - 1, masks.height - 1};
        mDocument.MaskUndo().BeginStroke();
        mDocument.MaskUndo().BeforeWrite(masks.texels.data(), whole);
        (void)RemoveKeptPathMasks(
          masks.texels.data(), masks.width, masks.height, RemappedStrata(TerrainShader()), result->maskDelta
        );
        mDocument.MaskUndo().EndStroke(masks.texels.data());
        if (mDocument.MaskUndo().LastStrokeKept()) {
          parts |= 2;
          UploadMasks({whole}, 0xFFu);
          UpdateCoverage();
        }
      }
    }
    bool propsChanged = false;
    bool decalsChanged = false;
    BeginObjectStroke();
    SwapPathItems(result.get(), nullptr, propsChanged, decalsChanged);
    mObjectsChanged = propsChanged;
    if (EndObjectStroke(false)) {
      parts |= 128;
    }
    if (decalsChanged) {
      mDocument.DecalsEdited(std::move(decalsBefore), false);
      parts |= 512;
    }
    mDocument.EditPaths().results.erase(id);
    mDocument.PathsEdited(std::move(pathsBefore), false);
    parts |= 1024;
    mDocument.BuildEdited(parts);
    gpg::Logf("editor: paths: %s's result taken off the map", id.c_str());
    return "The path's result is off the map. One undo step.";
  }

  std::string EdMapScene::BakeKeptPath(
    const std::string& id
  )
  {
    const auto it = mDocument.PathsNow().results.find(id);
    if (it == mDocument.PathsNow().results.end()) {
      return "This path has no result to bake.";
    }
    EdDocument::PathsState before = mDocument.PathsNow();
    mDocument.EditPaths().results.erase(id);
    mDocument.PathsEdited(std::move(before));
    return "Baked: the ground keeps the result, the next Apply adds to it.";
  }

  bool EdMapScene::PathMouseDown(
    HWND window,
    const float x,
    const float z,
    const bool shift,
    const bool ctrl
  )
  {
    if (mPathEdit == nullptr) {
      return false;
    }
    (void)RevertPathPreview();
    EdDocument::PathsState& state = mDocument.EditPaths();
    KeptPath* path = state.set.Find(mPathEdit->current);
    const float reach = std::clamp(mDistance * 0.015f, 2.0f, 40.0f);
    const auto snap = [this](const float v) {
      return mPathEdit->snap > 0.0f ? std::round(v / mPathEdit->snap) * mPathEdit->snap : v;
    };
    const auto ground = [this](const float gx, const float gz) {
      return GroundHeightAt(gx, gz);
    };
    // A point of the current path: select it (Ctrl adds) and start a drag.
    if (path != nullptr) {
      if (const int hit = PickPoint(*path, x, z, reach); hit >= 0) {
        auto& sel = mPathEdit->selected;
        if (ctrl) {
          const auto found = std::find(sel.begin(), sel.end(), hit);
          if (found != sel.end()) {
            sel.erase(found);
          } else {
            sel.push_back(hit);
          }
        } else if (std::find(sel.begin(), sel.end(), hit) == sel.end()) {
          sel = {hit};
        }
        mPathDragBefore = std::make_unique<EdDocument::PathsState>(mDocument.PathsNow());
        mPathDragging = true;
        mPathDragMoved = false;
        mPathDragX = x;
        mPathDragZ = z;
        ::SetCapture(window);
        mDocument.PathsTouched();
        return true;
      }
      // Shift on the curve: a point inserted there.
      if (shift) {
        if (const int seg = PickSegment(*path, x, z, reach); seg >= 0) {
          EdDocument::PathsState before = mDocument.PathsNow();
          InsertKeptPathPoint(*path, seg, snap(x), snap(z));
          mPathEdit->selected = {seg + 1};
          mDocument.PathsEdited(std::move(before));
          return true;
        }
      }
    }
    // Another path's point: that path becomes the current one.
    for (KeptPath& other : state.set.paths) {
      if (&other != path) {
        if (const int hit = PickPoint(other, x, z, reach); hit >= 0) {
          mPathEdit->current = other.id;
          mPathEdit->selected = {hit};
          mDocument.PathsTouched();
          return true;
        }
      }
    }
    // Empty ground: a point added to the current path (a new path when there is none).
    EdDocument::PathsState before = mDocument.PathsNow();
    if (path == nullptr) {
      const auto mode = static_cast<KeptPathMode>(std::clamp(mPathEdit->newMode, 0, kKeptPathModeCount - 1));
      KeptPath fresh = NewKeptPath(mode, mPathEdit->newBezier, state.set.TakeId());
      state.set.paths.push_back(std::move(fresh));
      path = &state.set.paths.back();
      mPathEdit->current = path->id;
    }
    AddKeptPathPoint(*path, snap(x), snap(z), ground);
    mPathEdit->selected = {static_cast<int>(path->points.size()) - 1};
    mDocument.PathsEdited(std::move(before));
    return true;
  }

  void EdMapScene::PathMouseMove(
    const float x,
    const float z
  )
  {
    if (!mPathDragging || mPathEdit == nullptr) {
      return;
    }
    KeptPath* const path = mDocument.EditPaths().set.Find(mPathEdit->current);
    if (path == nullptr) {
      return;
    }
    const float dx = x - mPathDragX;
    const float dz = z - mPathDragZ;
    if (std::abs(dx) < 1e-4f && std::abs(dz) < 1e-4f) {
      return;
    }
    mPathDragX = x;
    mPathDragZ = z;
    mPathDragMoved = true;
    for (const int i : mPathEdit->selected) {
      if (i >= 0 && static_cast<std::size_t>(i) < path->points.size()) {
        path->points[static_cast<std::size_t>(i)].x += dx;
        path->points[static_cast<std::size_t>(i)].z += dz;
      }
    }
    mDocument.PathsTouched();
  }

  bool EdMapScene::PathMouseUp()
  {
    mPathDragging = false;
    if (mPathDragBefore == nullptr) {
      return true;
    }
    if (mPathDragMoved && mPathEdit != nullptr) {
      if (
        KeptPath* const path = mDocument.EditPaths().set.Find(mPathEdit->current);
        path != nullptr && mPathEdit->snap > 0.0f
      ) {
        for (const int i : mPathEdit->selected) {
          if (i >= 0 && static_cast<std::size_t>(i) < path->points.size()) {
            KeptPathPoint& p = path->points[static_cast<std::size_t>(i)];
            p.x = std::round(p.x / mPathEdit->snap) * mPathEdit->snap;
            p.z = std::round(p.z / mPathEdit->snap) * mPathEdit->snap;
          }
        }
      }
      mDocument.PathsEdited(std::move(*mPathDragBefore));
    }
    mPathDragBefore.reset();
    return true;
  }

  bool EdMapScene::PathKey(
    const WPARAM key
  )
  {
    if (mPathEdit == nullptr) {
      return false;
    }
    KeptPath* const path = mDocument.EditPaths().set.Find(mPathEdit->current);
    if (key == VK_DELETE && path != nullptr && !mPathEdit->selected.empty()) {
      EdDocument::PathsState before = mDocument.PathsNow();
      std::vector<int> sel = mPathEdit->selected;
      std::ranges::sort(sel, std::ranges::greater{});
      for (const int i : sel) {
        if (i >= 0 && static_cast<std::size_t>(i) < path->points.size()) {
          path->points.erase(path->points.begin() + i);
        }
      }
      mPathEdit->selected.clear();
      if (path->points.empty()) {
        const std::string id = path->id;
        auto& list = mDocument.EditPaths().set.paths;
        list.erase(
          std::remove_if(
            list.begin(),
            list.end(),
            [&id](const KeptPath& p) {
          return p.id == id;
        }
          ),
          list.end()
        );
        mPathEdit->current.clear();
      }
      mDocument.PathsEdited(std::move(before));
      return true;
    }
    if (key == VK_ESCAPE) {
      if (!mPathEdit->selected.empty()) {
        mPathEdit->selected.clear();
      } else {
        mPathEdit->current.clear();
      }
      mDocument.PathsTouched();
      return true;
    }
    return false;
  }

  void EdMapScene::TickPaths()
  {
    // (Each frame, beside the paths: the units a height change left off the ground.)
    ReseatUnitsNow();
    if (mPathEdit == nullptr || mMap == nullptr) {
      return;
    }
    const PathEditState::Ask ask = std::exchange(mPathEdit->ask, PathEditState::Ask::None);
    std::vector<std::string> ids = std::move(mPathEdit->askIds);
    mPathEdit->askIds.clear();
    if (ids.empty() && !mPathEdit->current.empty()) {
      ids.push_back(mPathEdit->current);
    }
    switch (ask) {
    case PathEditState::Ask::None:
      break;
    case PathEditState::Ask::Preview:
      mPathEdit->status = PreviewKeptPath(ids);
      mPathPreviewRevision = mDocument.PathsRevision();
      break;
    case PathEditState::Ask::RevertPreview:
      mPathEdit->status =
        RevertPathPreview() ? "The preview is off." : "No preview to take off (other edits came after it).";
      break;
    case PathEditState::Ask::Apply:
    case PathEditState::Ask::ApplyMany:
      mPathEdit->status = ApplyKeptPaths(ids);
      break;
    case PathEditState::Ask::Unapply:
      mPathEdit->status = ids.empty() ? "No path chosen." : UnapplyKeptPath(ids.front());
      break;
    case PathEditState::Ask::Bake:
      mPathEdit->status = ids.empty() ? "No path chosen." : BakeKeptPath(ids.front());
      break;
    case PathEditState::Ask::SkeletonGenerate:
      mPathEdit->status = GenerateSkeleton(mPathEdit->skeleton);
      break;
    case PathEditState::Ask::SkeletonApply:
      mPathEdit->status = ApplySkeleton(mPathEdit->skeleton);
      break;
    case PathEditState::Ask::SkeletonClear:
      mPathEdit->status = ClearSkeleton();
      break;
    }
    // A preview that other edits came after is theirs now.
    if (mPathPreviewShown && mDocument.UndoOrder().size() != mPathPreviewDepth) {
      mPathPreviewShown = false;
      mPathEdit->previewShown = false;
    }
    // Live preview: the current path previewed again after a change (not while dragging).
    if (
      mPathEdit->livePreview && !mPathDragging && !mPathEdit->current.empty() &&
      mDocument.PathsRevision() != mPathPreviewRevision && !mPainting && !mPaintingMask && !mObjectStroke
    ) {
      mPathPreviewRevision = mDocument.PathsRevision();
      mPathEdit->status = PreviewKeptPath({mPathEdit->current});
      // The preview's own stroke bumps nothing in the paths, so it doesn't run again until they change.
    }
  }

  void EdMapScene::DrawKeptPaths(
    moho::CD3DPrimBatcher& batcher,
    const moho::CHeightField& field
  )
  {
    const EdDocument::PathsState& state = mDocument.PathsNow();
    if (state.set.paths.empty()) {
      return;
    }
    constexpr std::uint32_t kCurve = 0xF04AD2FFu;
    constexpr std::uint32_t kCurrent = 0xFF7CF0FFu;
    constexpr std::uint32_t kEdge = 0x9060B0E0u;
    constexpr std::uint32_t kReach = 0x605080B0u;
    constexpr std::uint32_t kPoint = 0xF0FFFFFFu;
    constexpr std::uint32_t kSelected = 0xFFFFE040u;
    constexpr std::uint32_t kApplied = 0xF060FF60u;
    constexpr float kLift = 0.6f;
    const auto ground = [&field](const float x, const float z) {
      return FieldHeight(field, x, z) + kLift;
    };
    for (const KeptPath& path : state.set.paths) {
      const bool current = mPathEdit != nullptr && path.id == mPathEdit->current;
      const KeptPathSamples S = SampleKeptPath(path, 2.0f);
      const std::uint32_t colour = current ? kCurrent : kCurve;
      for (std::size_t k = 1; k < S.Count(); ++k) {
        batcher.DrawLine(
          At(S.x[k - 1], ground(S.x[k - 1], S.z[k - 1]), S.z[k - 1], colour),
          At(S.x[k], ground(S.x[k], S.z[k]), S.z[k], colour)
        );
      }
      if (current && S.Count() > 1) {
        // The half width and the reach on both sides.
        for (const int side : {-1, 1}) {
          for (int ring = 0; ring < 2; ++ring) {
            float px = 0.0f;
            float pz = 0.0f;
            for (std::size_t k = 0; k < S.Count(); ++k) {
              const std::size_t a = k == 0 ? 0 : k - 1;
              const std::size_t b = k == 0 ? 1 : k;
              float dx = S.x[b] - S.x[a];
              float dz = S.z[b] - S.z[a];
              const float dl = std::hypot(dx, dz);
              if (dl < 1e-4f) {
                continue;
              }
              dx /= dl;
              dz /= dl;
              const float off = static_cast<float>(side) * (ring == 0 ? S.w[k] : S.w[k] + S.f[k]);
              const float x = S.x[k] - dz * off;
              const float z = S.z[k] + dx * off;
              if (k > 0) {
                batcher.DrawLine(
                  At(px, ground(px, pz), pz, ring == 0 ? kEdge : kReach),
                  At(x, ground(x, z), z, ring == 0 ? kEdge : kReach)
                );
              }
              px = x;
              pz = z;
            }
          }
        }
      }
      const bool applied = state.results.contains(path.id);
      for (std::size_t i = 0; i < path.points.size(); ++i) {
        const KeptPathPoint& p = path.points[i];
        const bool selected = current && mPathEdit != nullptr &&
          std::find(mPathEdit->selected.begin(), mPathEdit->selected.end(), static_cast<int>(i)) !=
            mPathEdit->selected.end();
        const std::uint32_t c = selected ? kSelected : (applied ? kApplied : kPoint);
        const float y = ground(p.x, p.z);
        batcher.DrawLine(At(p.x, y, p.z, c), At(p.x, y + (p.abs ? 8.0f : 5.0f), p.z, c));
        const float r = selected ? 2.0f : 1.2f;
        for (int s = 0; s < 12; ++s) {
          const float a0 = 2.0f * kPathPi * static_cast<float>(s) / 12.0f;
          const float a1 = 2.0f * kPathPi * static_cast<float>(s + 1) / 12.0f;
          batcher.DrawLine(
            At(p.x + std::cos(a0) * r, y, p.z + std::sin(a0) * r, c),
            At(p.x + std::cos(a1) * r, y, p.z + std::sin(a1) * r, c)
          );
        }
      }
    }
  }

  std::string EdMapScene::GenerateSkeleton(
    const SkeletonSettings& settings
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return "No map.";
    }
    const std::vector<SkeletonStart> starts = SkeletonStarts(PadMarkers());
    if (starts.size() < 2) {
      return "The skeleton needs at least two start positions (ARMY_1, ARMY_2, ...).";
    }
    // The skeleton paths' results come off first (each its own undo step, as in Studio).
    std::vector<std::string> applied;
    for (const KeptPath& p : mDocument.PathsNow().set.paths) {
      if (p.skeleton && mDocument.PathsNow().results.contains(p.id)) {
        applied.push_back(p.id);
      }
    }
    for (const std::string& id : applied) {
      (void)UnapplyKeptPath(id);
    }
    // The base heights the lanes are pinned to: the ground with the pads on it (worked out on a copy).
    const int width = field->width;
    const int height = field->height;
    const std::uint16_t* const words = reinterpret_cast<const std::uint16_t*>(field->data);
    std::vector<std::uint16_t> copy(words, words + static_cast<std::size_t>(width) * height);
    const auto groundOf = [&copy, width, height](const float x, const float z) {
      const int ix = std::clamp(static_cast<int>(std::lround(x)), 0, width - 1);
      const int iz = std::clamp(static_cast<int>(std::lround(z)), 0, height - 1);
      return static_cast<float>(copy[static_cast<std::size_t>(iz) * width + ix]) / 128.0f;
    };
    const PadSettings& padSettings = mTools->PadSettingsNow();
    if (const auto& old = mDocument.PathsNow().skeletonPads; old != nullptr && !old->Empty()) {
      (void)RemovePads(copy.data(), width, height, 1.0f / 128.0f, *old);
    }
    const std::vector<Pad> pads = SkeletonPads(starts, settings, padSettings, groundOf);
    if (!pads.empty()) {
      PadResult unused;
      (void)ApplyPads(copy.data(), width, height, 1.0f / 128.0f, pads, padSettings, PadResult{}, unused);
    }
    EdDocument::PathsState before = mDocument.PathsNow();
    EdDocument::PathsState& state = mDocument.EditPaths();
    auto& list = state.set.paths;
    list.erase(
      std::remove_if(
        list.begin(),
        list.end(),
        [](const KeptPath& p) {
      return p.skeleton;
    }
      ),
      list.end()
    );
    std::vector<KeptPath> made =
      SkeletonPaths(starts, settings, padSettings, pads, groundOf, mDocument.WaterNow().elevation, state.set);
    const std::size_t count = made.size();
    for (KeptPath& p : made) {
      list.push_back(std::move(p));
    }
    if (mPathEdit != nullptr) {
      mPathEdit->current = count > 0 ? list[list.size() - count].id : std::string();
      mPathEdit->selected.clear();
    }
    mDocument.PathsEdited(std::move(before));
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Skeleton: %zu paths and %zu pads (%s, %s); edit them in the Paths panel, then Apply all.",
      count,
      pads.size(),
      SkeletonStyleName(settings.style),
      SkeletonTopologyName(settings.topology)
    );
    gpg::Logf("editor: %s", text);
    return text;
  }

  std::string EdMapScene::ApplySkeleton(
    const SkeletonSettings& settings
  )
  {
    moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return "No map.";
    }
    std::vector<std::string> ids;
    for (const KeptPath& p : mDocument.PathsNow().set.paths) {
      if (p.skeleton) {
        ids.push_back(p.id);
      }
    }
    if (ids.empty()) {
      return "There is no skeleton: Generate first.";
    }
    const int width = field->width;
    const int height = field->height;
    std::uint16_t* const words = reinterpret_cast<std::uint16_t*>(field->data);
    const SampleRect whole{0, 0, width - 1, height - 1};
    const std::vector<SkeletonStart> starts = SkeletonStarts(PadMarkers());
    const PadSettings& padSettings = mTools->PadSettingsNow();
    std::shared_ptr<const PadResult> padsNow = mDocument.PathsNow().skeletonPads;
    std::string padNote;
    // Pads first (the earlier skeleton pads replaced), in the paths' stroke.
    const auto pads = [&](std::vector<SampleRect>& rects) {
      const auto groundOf = [this](const float x, const float z) {
        return GroundHeightAt(x, z);
      };
      const std::vector<Pad> list = SkeletonPads(starts, settings, padSettings, groundOf);
      if (list.empty() && (padsNow == nullptr || padsNow->Empty())) {
        return;
      }
      mDocument.Heights().BeforeWrite(field->data, whole);
      PadResult result;
      if (list.empty()) {
        (void)RemovePads(words, width, height, 1.0f / 128.0f, *padsNow);
        padsNow = nullptr;
      } else if (
        const auto applied = ApplyPads(
          words, width, height, 1.0f / 128.0f, list, padSettings, padsNow != nullptr ? *padsNow : PadResult{}, result
        )
      ) {
        padsNow = std::make_shared<const PadResult>(std::move(result));
      } else {
        padNote = " Pads: " + applied.error() + ".";
      }
      rects.push_back(whole);
    };
    // Smooth: the pathable slope limit over the lanes' corridors.
    const auto smooth = [&](std::vector<SampleRect>& rects) {
      if (!settings.smooth) {
        return;
      }
      auto H = std::make_shared<field::Grid>(width, height, 1.0f, 0.0f, 0.0f);
      for (std::size_t k = 0; k < H->v.size(); ++k) {
        H->v[k] = static_cast<float>(words[k]) / 128.0f;
      }
      auto mask = std::make_shared<field::Grid>(width, height, 1.0f, 0.0f, 0.0f);
      bool any = false;
      for (const std::string& id : ids) {
        const KeptPath* const p = mDocument.PathsNow().set.Find(id);
        if (p == nullptr || p->points.size() < 2 || KeptPathOffsetMode(p->mode) || p->mode == KeptPathMode::River) {
          continue;
        }
        const KeptPathSamples S = SampleKeptPath(*p, 1.0f);
        std::vector<double> pts;
        for (std::size_t k = 0; k < S.Count(); ++k) {
          pts.insert(pts.end(), {S.x[k], S.z[k], 0.0, S.w[k], S.f[k], 0.0, 0.0, S.s[k]});
        }
        field::OpArgs args;
        args.in["like"] = H;
        args.p.arr["pts"] = std::move(pts);
        args.p.str["kind"] = "reach";
        args.p.num["soft"] = 4.0;
        field::Grid mk;
        if (field::RunOp("path_mask", args, mk)) {
          for (std::size_t k = 0; k < mask->v.size(); ++k) {
            mask->v[k] = std::max(mask->v[k], mk.v[k]);
          }
          any = true;
        }
      }
      if (!any) {
        return;
      }
      const SlopeLimitSettings& slope = mTools->SlopeSettingsNow();
      field::OpArgs args;
      args.in["a"] = H;
      args.in["mask"] = mask;
      args.p.num["limit"] = slope.limit;
      args.p.num["margin"] = slope.margin;
      args.p.str["mode"] = "both";
      args.p.num["balance"] = 0.5;
      field::Grid out;
      const auto ran = field::RunOp("slope_limit", args, out);
      if (!ran || out.v.size() != H->v.size()) {
        padNote += " Smoothing: " + (ran ? std::string() : ran.error()) + ".";
        return;
      }
      mDocument.Heights().BeforeWrite(field->data, whole);
      for (std::size_t k = 0; k < out.v.size(); ++k) {
        words[k] = static_cast<std::uint16_t>(std::clamp(std::lround(out.v[k] * 128.0f), 0L, 65535L));
      }
      rects.push_back(whole);
    };
    std::string text = ApplyKeptPaths(ids, pads, smooth, &padsNow) + padNote;
    gpg::Logf("editor: skeleton applied: %s", text.c_str());
    return "Skeleton: " + text;
  }

  std::string EdMapScene::ClearSkeleton()
  {
    std::vector<std::string> applied;
    for (const KeptPath& p : mDocument.PathsNow().set.paths) {
      if (p.skeleton && mDocument.PathsNow().results.contains(p.id)) {
        applied.push_back(p.id);
      }
    }
    for (const std::string& id : applied) {
      (void)UnapplyKeptPath(id);
    }
    EdDocument::PathsState before = mDocument.PathsNow();
    auto& list = mDocument.EditPaths().set.paths;
    const std::size_t was = list.size();
    list.erase(
      std::remove_if(
        list.begin(),
        list.end(),
        [](const KeptPath& p) {
      return p.skeleton;
    }
      ),
      list.end()
    );
    if (list.size() == was) {
      return "There is no skeleton.";
    }
    if (mPathEdit != nullptr && mDocument.PathsNow().set.Find(mPathEdit->current) == nullptr) {
      mPathEdit->current.clear();
      mPathEdit->selected.clear();
    }
    mDocument.PathsEdited(std::move(before));
    return "The skeleton paths are gone (their results taken off).";
  }

  void EdMapScene::TestSkeleton(
    const std::string& spec
  )
  {
    SkeletonSettings settings;
    const std::size_t comma = spec.find(',');
    const std::string style = spec.substr(0, comma);
    const std::string topology = comma == std::string::npos ? std::string("ring") : spec.substr(comma + 1);
    for (int s = 0; s < 4; ++s) {
      if (style == SkeletonStyleId(static_cast<SkeletonStyle>(s))) {
        settings.style = static_cast<SkeletonStyle>(s);
      }
    }
    settings.topology = topology == "hub" ? SkeletonTopology::Hub
      : topology == "both"                ? SkeletonTopology::Both
                                          : SkeletonTopology::Ring;
    const std::uint64_t start = HeightsHash();
    gpg::Logf("editor: /skeletontest: %s", GenerateSkeleton(settings).c_str());
    gpg::Logf("editor: /skeletontest: %s", ApplySkeleton(settings).c_str());
    gpg::Logf("editor: /skeletontest: the heights %s", HeightsHash() != start ? "changed" : "did not change");
    (void)Undo();
    gpg::Logf(
      "editor: /skeletontest: undo %s the heights before", HeightsHash() == start ? "restores" : "does not restore"
    );
    (void)Undo();
  }

  void EdMapScene::TestKeptPath(
    const std::string& spec
  )
  {
    // mode,x0,z0,x1,z1[,...]
    std::vector<std::string> parts;
    for (std::size_t at = 0; at <= spec.size();) {
      const std::size_t comma = std::min(spec.find(',', at), spec.size());
      parts.push_back(spec.substr(at, comma - at));
      at = comma + 1;
    }
    KeptPathMode mode = KeptPathMode::Carve;
    if (parts.empty() || !KeptPathModeFromId(parts[0], mode)) {
      gpg::Warnf("editor: /keptpathtest: the mode must be carve, raise, level, ramp, road or river");
      return;
    }
    const std::uint64_t start = HeightsHash();
    EdDocument::PathsState before = mDocument.PathsNow();
    KeptPath path = NewKeptPath(mode, false, mDocument.EditPaths().set.TakeId());
    const auto ground = [this](const float x, const float z) {
      return GroundHeightAt(x, z);
    };
    for (std::size_t i = 1; i + 1 < parts.size(); i += 2) {
      AddKeptPathPoint(
        path,
        static_cast<float>(std::atof(parts[i].c_str())),
        static_cast<float>(std::atof(parts[i + 1].c_str())),
        ground
      );
    }
    path.strata[0].layer = 1;
    const std::string id = path.id;
    mDocument.EditPaths().set.paths.push_back(std::move(path));
    mDocument.PathsEdited(std::move(before));
    gpg::Logf("editor: /keptpathtest: %s", ApplyKeptPaths({id}).c_str());
    const std::uint64_t applied = HeightsHash();
    gpg::Logf("editor: /keptpathtest: re-apply: %s", ApplyKeptPaths({id}).c_str());
    gpg::Logf(
      "editor: /keptpathtest: re-apply %s the same heights", HeightsHash() == applied ? "gives" : "does not give"
    );
    gpg::Logf("editor: /keptpathtest: %s", UnapplyKeptPath(id).c_str());
    gpg::Logf(
      "editor: /keptpathtest: unapply %s the heights before", HeightsHash() == start ? "restores" : "does not restore"
    );
    (void)Undo();
    gpg::Logf(
      "editor: /keptpathtest: undo of the unapply %s the applied heights",
      HeightsHash() == applied ? "restores" : "does not restore"
    );
    (void)Undo();
    (void)Undo();
    (void)Undo();
    gpg::Logf(
      "editor: /keptpathtest: undo of everything %s the heights before",
      HeightsHash() == start ? "restores" : "does not restore"
    );
  }
} // namespace faf::editor
