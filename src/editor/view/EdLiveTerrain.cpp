#include "editor/view/EdLiveTerrain.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <utility>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/utils/Logging.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/math/MathReflection.h"
#include "moho/path/PathTables.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimEditorHook.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace faf::editor
{
  namespace
  {
    /** One rectangle's samples for the sim (row by row, its own width). */
    struct Patch
    {
      gpg::Rect2i rect{};
      int width = 0;
      std::vector<std::uint16_t> samples;
    };

    std::mutex gMutex;
    std::vector<Patch> gQueue;
    bool gNoReseat = false;

    /** On the sim's thread, at a beat's start: the queued heights into the sim's height field. */
    void ApplyQueued(moho::Sim& sim)
    {
      std::vector<Patch> patches;
      {
        const std::lock_guard<std::mutex> lock(gMutex);
        if (gQueue.empty()) {
          return;
        }
        patches.swap(gQueue);
      }
      if (sim.mMapData == nullptr || sim.mMapData->mHeightField.get() == nullptr) {
        return;
      }
      moho::CHeightField* const field = sim.mMapData->mHeightField.get();
      // The sim's own height at the first rectangle's middle, before and after (the proof it took them).
      const float cx = static_cast<float>(patches.front().rect.x0 + patches.front().rect.x1) * 0.5f;
      const float cz = static_cast<float>(patches.front().rect.z0 + patches.front().rect.z1) * 0.5f;
      const float before = field->GetElevation(cx, cz);
      std::size_t samples = 0;
      for (const Patch& patch : patches) {
        field->SetElevationRectRaw(patch.rect, patch.samples.data(), patch.width);
        samples += patch.samples.size();
      }
      // The changed area as one rectangle: its path clusters worked out again from the new heights, and the land and
      // seabed units on it put back on the ground, as `Sim::FlattenMapRect` (0x0074B120) does after its write.
      gpg::Rect2i area = patches.front().rect;
      for (const Patch& patch : patches) {
        area.x0 = std::min(area.x0, patch.rect.x0);
        area.z0 = std::min(area.z0, patch.rect.z0);
        area.x1 = std::max(area.x1, patch.rect.x1);
        area.z1 = std::max(area.z1, patch.rect.z1);
      }
      if (sim.mPathTables != nullptr) {
        // A footprint's slope check reaches a few cells past the cell it stands on.
        constexpr int kPad = 4;
        sim.mPathTables->DirtyClusters(gpg::Rect2i{std::max(0, area.x0 - kPad), std::max(0, area.z0 - kPad),
                                                   std::min(field->width - 1, area.x1 + kPad), std::min(field->height - 1, area.z1 + kPad)});
      }
      int reseated = 0;
      if (sim.mOGrid != nullptr && !gNoReseat) {
        const Wm3::Vector3f centre{static_cast<float>(area.x0 + area.x1) * 0.5f, 0.0f, static_cast<float>(area.z0 + area.z1) * 0.5f};
        const Wm3::Vector3f extents{static_cast<float>(area.x1 - area.x0), 100.0f, static_cast<float>(area.z1 - area.z0)};
        const moho::VAxes3 axes{Wm3::Quaternionf(0.0f, 0.0f, 0.0f, 0.0f)};
        const Wm3::Box3f box{centre, &axes.vX, &extents.x};
        gpg::core::FastVectorN<moho::CollisionResult, 10> hits{};
        sim.mOGrid->CollectEntitiesInBox(hits, moho::ENTITYTYPE_Unit, box);
        for (const moho::CollisionResult& hit : hits) {
          moho::Unit* const unit = hit.sourceEntity->IsUnit();
          if (unit == nullptr || unit->IsDead() || unit->DestroyQueued() ||
              (unit->mVarDat.mLayerMask != moho::LAYER_Land && unit->mVarDat.mLayerMask != moho::LAYER_Seabed)) {
            continue;
          }
          if (unit->UnitMotion != nullptr) {
            unit->UnitMotion->mProcessSurfaceCollision = true; // its motion puts it on the ground next tick
          } else {
            unit->Warp(unit->GetTransform()); // a structure: at once
          }
          ++reseated;
        }
      }
      gpg::Logf("editor: %zu height rectangles (%zu samples) into the play's sim; its height at %.0f,%.0f %.2f -> %.2f; %d units re-seated, "
                "path clusters in %d,%d..%d,%d redone",
                patches.size(), samples, static_cast<double>(cx), static_cast<double>(cz), static_cast<double>(before),
                static_cast<double>(field->GetElevation(cx, cz)), reseated, area.x0, area.z0, area.x1, area.z1);
    }
  } // namespace

  void LiveHeights(moho::CWldMap& sessionMap, const moho::CHeightField& edited, const std::vector<HeightRect>& rects)
  {
    if (sessionMap.mTerrainRes == nullptr || rects.empty()) {
      return;
    }
    moho::CHeightField* const shown = sessionMap.mTerrainRes->GetHeightField();
    if (shown == nullptr || shown->width != edited.width || shown->height != edited.height) {
      gpg::Warnf("editor: the play's map isn't this map's size: height edits stay in the editor");
      return;
    }
    // The rendered terrain: copied in at once, the normals redrawn one sample wider.
    std::vector<gpg::Rect2i> changed;
    std::vector<Patch> patches;
    for (const HeightRect& r : rects) {
      const gpg::Rect2i rect{r.x0, r.z0, r.x1, r.z1};
      shown->SetElevationRectRaw(rect, edited.data + r.x0 + static_cast<std::ptrdiff_t>(r.z0) * edited.width, edited.width);
      changed.push_back(gpg::Rect2i{std::max(0, r.x0 - 1), std::max(0, r.z0 - 1), std::min(edited.width - 1, r.x1 + 1), std::min(edited.height - 1, r.z1 + 1)});
      // The sim's copy: the rectangle's samples (inclusive of its far edges), applied at its next beat.
      Patch patch;
      patch.rect = rect;
      patch.width = r.x1 - r.x0 + 1;
      for (int z = r.z0; z <= r.z1; ++z) {
        const std::uint16_t* const row = edited.data + static_cast<std::ptrdiff_t>(z) * edited.width + r.x0;
        patch.samples.insert(patch.samples.end(), row, row + patch.width);
      }
      patches.push_back(std::move(patch));
    }
    sessionMap.mTerrainRes->NotifyMapChanges(changed.data(), changed.size());
    const float cx = static_cast<float>(rects.front().x0 + rects.front().x1) * 0.5f;
    const float cz = static_cast<float>(rects.front().z0 + rects.front().z1) * 0.5f;
    gpg::Debugf("editor: the play's drawn terrain at %.0f,%.0f is now %.2f", static_cast<double>(cx), static_cast<double>(cz),
                static_cast<double>(shown->GetElevation(cx, cz)));
    {
      const std::lock_guard<std::mutex> lock(gMutex);
      for (Patch& patch : patches) {
        gQueue.push_back(std::move(patch));
      }
    }
    moho::gSimBeforeBeat = &ApplyQueued;
  }

  void SetLiveHeightsNoReseat(const bool off) noexcept
  {
    gNoReseat = off;
  }

  void DropLiveHeights()
  {
    if (moho::gSimBeforeBeat == nullptr) {
      return;
    }
    moho::gSimBeforeBeat = nullptr;
    const std::lock_guard<std::mutex> lock(gMutex);
    gQueue.clear();
  }
} // namespace faf::editor
