#include "editor/view/EdLiveTerrain.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <utility>

#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimEditorHook.h"

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
      gpg::Logf("editor: %zu height rectangles (%zu samples) into the play's sim; its height at %.0f,%.0f %.2f -> %.2f", patches.size(), samples,
                static_cast<double>(cx), static_cast<double>(cz), static_cast<double>(before), static_cast<double>(field->GetElevation(cx, cz)));
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
