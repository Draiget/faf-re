// The detail pass in the view (FAF Studio's detail.lua): its classes scattered through the terrain graph's scatter
// (Poisson points, slope window, density mask, symmetry), one undo step for the whole pass; its plan; and Measure,
// which reads the classes off the open map.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "editor/tools/EdMaskBrush.h"
#include "editor/tools/EdScatter.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace faf::editor
{
  namespace
  {
    std::shared_ptr<field::Grid> HeightsGrid(
      const moho::CHeightField& field
    )
    {
      auto g = std::make_shared<field::Grid>(field.width, field.height, 1.0f, 0.0f, 0.0f);
      for (std::size_t k = 0; k < g->v.size(); ++k) {
        g->v[k] = static_cast<float>(field.data[k]) / 128.0f;
      }
      return g;
    }
  } // namespace

  std::string EdMapScene::DetailEnvironmentGuess() const
  {
    std::vector<std::string> textures;
    for (const EdTools::LayerSlot& slot : LayerSlots()) {
      textures.push_back(slot.albedo);
    }
    return GuessDetailEnvironment(textures);
  }

  std::string EdMapScene::PlanDetailPass(
    const DetailRun& run
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr) {
      return "No map.";
    }
    const std::vector<std::string>& blueprints = mTools->PropBlueprints();
    const std::vector<DetailClass> classes =
      DetailClasses(run.environment, [&blueprints](const std::string& group, const std::string& name) {
      return FindEnvironmentProp(blueprints, group, name);
    }, gameFileExists);
    if (classes.empty()) {
      return blueprints.empty() ? "The game's prop list isn't loaded yet."
                                : "No props or decals of this environment exist in the game data.";
    }
    const double area = static_cast<double>(field->width - 1) * static_cast<double>(field->height - 1);
    std::string text;
    for (const DetailClass& c : classes) {
      if (!run.only.empty() && std::find(run.only.begin(), run.only.end(), c.id) == run.only.end()) {
        continue;
      }
      char line[200];
      (void)std::snprintf(
        line,
        sizeof(line),
        "%s: %d %s (%zu kinds), slope %.0f-%.0f deg\n",
        c.label.c_str(),
        DetailCount(c, area, run.density),
        c.decals ? "decals" : "props",
        c.entries.size(),
        static_cast<double>(c.slopeMin),
        static_cast<double>(c.slopeMax)
      );
      text += line;
    }
    return text;
  }

  std::string EdMapScene::RunDetailPass(
    const DetailRun& run
  )
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr || mTools == nullptr || mPainting || mPaintingMask || mObjectStroke) {
      return "No map, or a stroke is under way.";
    }
    const std::vector<std::string>& blueprints = mTools->PropBlueprints();
    const std::vector<DetailClass> classes =
      DetailClasses(run.environment, [&blueprints](const std::string& group, const std::string& name) {
      return FindEnvironmentProp(blueprints, group, name);
    }, gameFileExists);
    if (classes.empty()) {
      return "No props or decals of this environment exist in the game data.";
    }
    const double area = static_cast<double>(field->width - 1) * static_cast<double>(field->height - 1);
    MaskGenContext context;
    context.heights = HeightsGrid(*field);
    const WaterState water = mDocument.WaterNow();
    context.water = water.enabled ? water.elevation : -1.0e6f;
    std::uint16_t parts = 0;
    EdDocument::DecalSnapshot decalsBefore = mDocument.DecalsNow();
    BeginObjectStroke();
    int placedProps = 0;
    int placedDecals = 0;
    std::string text;
    int index = 0;
    for (const DetailClass& c : classes) {
      ++index;
      if (!run.only.empty() && std::find(run.only.begin(), run.only.end(), c.id) == run.only.end()) {
        continue;
      }
      TerrainBuildWrites::Scatter s;
      if (const auto made = DetailDensity(context, c, 700 + index * 31 + run.seed, s.density); !made) {
        text += c.label + ": " + made.error() + ". ";
        continue;
      }
      for (const std::string& entry : c.entries) {
        s.entries.emplace_back(entry, 1);
      }
      s.count = DetailCount(c, area, run.density);
      s.minDist = c.minDist;
      s.fill = 1.0f;
      s.slopeMin = c.slopeMin;
      s.slopeMax = c.slopeMax;
      s.scaleMin = c.scaleMin;
      s.scaleMax = c.scaleMax;
      s.margin = 2.0f;
      s.underWater = run.underWater;
      s.seed = static_cast<std::uint32_t>(run.seed * 100 + index);
      s.decals = c.decals;
      s.decalSize = c.decalSize;
      std::string note;
      const int placed = c.decals ? ScatterDecalsFromGraph(s, note) : ScatterFromGraph(s, note);
      (c.decals ? placedDecals : placedProps) += placed;
      char line[160];
      (void)std::snprintf(line, sizeof(line), "%s %d. ", c.id.c_str(), placed);
      text += line;
      if (!note.empty()) {
        text += note + ". ";
      }
    }
    if (EndObjectStroke(false)) {
      parts |= 128;
    }
    if (!(mDocument.DecalsNow() == decalsBefore)) {
      mDocument.DecalsEdited(std::move(decalsBefore), false);
      parts |= 512;
    }
    if (parts != 0) {
      mDocument.BuildEdited(parts);
    }
    char head[160];
    (void)std::snprintf(
      head,
      sizeof(head),
      "Detail pass (%s, density %.2f): %d props and %d decals placed%s. ",
      run.environment.c_str(),
      static_cast<double>(run.density),
      placedProps,
      placedDecals,
      parts != 0 ? ", one undo step" : ""
    );
    gpg::Logf("editor: %s%s", head, text.c_str());
    return head + text;
  }

  std::string EdMapScene::MeasureDetailPass()
  {
    const moho::CHeightField* const field = mMap != nullptr ? mMap->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return "No map.";
    }
    std::vector<DetailThing> things;
    if (mMap->mProps != nullptr) {
      for (const auto& entry : mMap->mProps->mEntries) {
        things.push_back({entry.mBlueprintPath.c_str(), false, entry.mTransform.pos_.x, entry.mTransform.pos_.z, 0.0f});
      }
    }
    for (const DecalState& d : mDocument.DecalsNow()) {
      things.push_back({d.names[0], true, d.position[0], d.position[2], std::max(d.scale[0], d.scale[2])});
    }
    const double area = static_cast<double>(field->width - 1) * static_cast<double>(field->height - 1);
    const auto slope = [field](const float x, const float z) {
      const auto h = [field](const float sx, const float sz) {
        const int ix = std::clamp(static_cast<int>(std::lround(sx)), 0, field->width - 1);
        const int iz = std::clamp(static_cast<int>(std::lround(sz)), 0, field->height - 1);
        return static_cast<float>(field->data[static_cast<std::size_t>(iz) * field->width + ix]) / 128.0f;
      };
      return SlopeDegrees(h(x - 1.0f, z), h(x + 1.0f, z), h(x, z - 1.0f), h(x, z + 1.0f));
    };
    std::string text;
    int total = 0;
    for (const DetailMeasure& m : MeasureDetail(things, area, slope)) {
      char line[200];
      (void)std::snprintf(
        line,
        sizeof(line),
        "%s: %d (%.2f per 1000), mean slope %.1f deg%s\n",
        m.label.c_str(),
        m.count,
        static_cast<double>(m.per1000),
        static_cast<double>(m.meanSlope),
        m.meanSize > 0.0f ? (", mean size " + std::to_string(static_cast<int>(m.meanSize))).c_str() : ""
      );
      text += line;
      total += m.count;
    }
    char head[160];
    (void)std::snprintf(
      head, sizeof(head), "This map: %zu props and decals, %d of them in the detail classes.\n", things.size(), total
    );
    return head + text;
  }
} // namespace faf::editor
