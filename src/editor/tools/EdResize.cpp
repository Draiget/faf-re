#include "editor/tools/EdResize.h"

#include "editor/doc/EdSaveFile.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMarkers.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <regex>
#include <set>

namespace faf::editor
{
  ResizeGeometry MakeResizeGeometry(
    const ResizeOptions& o
  )
  {
    ResizeGeometry g;
    g.mode = o.mode;
    g.oldWidth = static_cast<float>(o.oldWidth);
    g.oldDepth = static_cast<float>(o.oldDepth);
    g.width = static_cast<float>(o.newWidth);
    g.depth = static_cast<float>(o.newDepth);
    if (o.mode == ResizeMode::Scale) {
      g.fx = g.width / std::max(1.0f, g.oldWidth);
      g.fz = g.depth / std::max(1.0f, g.oldDepth);
      return g;
    }
    const int anchor = std::clamp(o.anchor, 0, 8);
    const float ax = static_cast<float>(anchor % 3) * 0.5f; // 0 left, 0.5 middle, 1 right
    const float az = static_cast<float>(anchor / 3) * 0.5f; // 0 top
    g.ox = std::round((g.width - g.oldWidth) * ax);
    g.oz = std::round((g.depth - g.oldDepth) * az);
    return g;
  }

  bool ResizePoint(
    const ResizeGeometry& g,
    const float x,
    const float z,
    float& nx,
    float& nz
  )
  {
    nx = x * g.fx + g.ox;
    nz = z * g.fz + g.oz;
    return nx >= 0.0f && nz >= 0.0f && nx <= g.width && nz <= g.depth;
  }

  HeightImage ResizeImage(
    const HeightImage& image,
    const ResizeGeometry& g,
    const int width,
    const int height,
    const bool padEdge,
    const std::uint16_t pad
  )
  {
    HeightImage out;
    out.width = width;
    out.height = height;
    out.words.assign(static_cast<std::size_t>(std::max(width, 0)) * static_cast<std::size_t>(std::max(height, 0)), pad);
    if (image.width < 2 || image.height < 2 || width < 2 || height < 2) {
      return out;
    }
    const auto at = [&](const int x, const int y) {
      return static_cast<double>(image.words[static_cast<std::size_t>(y) * image.width + x]);
    };
    for (int j = 0; j < height; ++j) {
      for (int i = 0; i < width; ++i) {
        // The new sample's world position, back to the old map's, to its sample.
        const double wx = static_cast<double>(i) / (width - 1) * g.width;
        const double wz = static_cast<double>(j) / (height - 1) * g.depth;
        const double ox = (wx - g.ox) / g.fx;
        const double oz = (wz - g.oz) / g.fz;
        double sx = ox / g.oldWidth * (image.width - 1);
        double sy = oz / g.oldDepth * (image.height - 1);
        const bool outside = sx < -1e-6 || sy < -1e-6 || sx > image.width - 1 + 1e-6 || sy > image.height - 1 + 1e-6;
        if (outside && !padEdge) {
          continue; // (the pad)
        }
        sx = std::clamp(sx, 0.0, static_cast<double>(image.width - 1));
        sy = std::clamp(sy, 0.0, static_cast<double>(image.height - 1));
        const int x0 = std::min(static_cast<int>(sx), image.width - 2);
        const int y0 = std::min(static_cast<int>(sy), image.height - 2);
        const double tx = sx - x0;
        const double ty = sy - y0;
        const double top = at(x0, y0) * (1.0 - tx) + at(x0 + 1, y0) * tx;
        const double bottom = at(x0, y0 + 1) * (1.0 - tx) + at(x0 + 1, y0 + 1) * tx;
        out.words[static_cast<std::size_t>(j) * width + i] =
          static_cast<std::uint16_t>(std::clamp(std::lround(top * (1.0 - ty) + bottom * ty), 0L, 65535L));
      }
    }
    return out;
  }

  std::string ResizeReport::Text() const
  {
    char text[400];
    std::snprintf(
      text,
      sizeof(text),
      "markers %d kept, %d dropped; areas %d kept, %d dropped; units %d kept, %d dropped; chains dropped %d; props %d "
      "kept, %d dropped; decals %d kept, %d dropped",
      markersKept,
      markersDropped,
      areasKept,
      areasDropped,
      unitsKept,
      unitsDropped,
      chainsDropped,
      propsKept,
      propsDropped,
      decalsKept,
      decalsDropped
    );
    return text;
  }

  namespace
  {
    /** The group with its units moved, those outside dropped (its members' order kept). */
    void ResizeGroup(
      UnitGroup& group,
      const ResizeGeometry& g,
      ResizeReport& report
    )
    {
      std::vector<int> unitIndex(group.units.size(), -1);
      std::vector<SaveUnit> kept;
      for (std::size_t u = 0; u < group.units.size(); ++u) {
        SaveUnit unit = group.units[u];
        float nx = 0.0f;
        float nz = 0.0f;
        if (ResizePoint(g, unit.position[0], unit.position[2], nx, nz)) {
          unit.position[0] = nx;
          unit.position[2] = nz;
          unitIndex[u] = static_cast<int>(kept.size());
          kept.push_back(unit);
          ++report.unitsKept;
        } else {
          ++report.unitsDropped;
        }
      }
      for (UnitGroup& child : group.groups) {
        ResizeGroup(child, g, report);
      }
      std::vector<UnitGroup::Member> order;
      for (const UnitGroup::Member& m : group.order) {
        if (m.unit >= 0) {
          if (static_cast<std::size_t>(m.unit) < unitIndex.size() && unitIndex[static_cast<std::size_t>(m.unit)] >= 0) {
            order.push_back({-1, unitIndex[static_cast<std::size_t>(m.unit)]});
          }
        } else {
          order.push_back(m);
        }
      }
      group.units = std::move(kept);
      group.order = std::move(order);
    }
  } // namespace

  std::string ResizeSaveText(
    const std::string& saveText,
    const ResizeGeometry& g,
    ResizeReport& report,
    std::string& error
  )
  {
    SaveFile save;
    if (!save.Parse(saveText, error)) {
      return {};
    }
    // Markers.
    std::set<std::string> dropped;
    std::vector<SaveEntry>& markers = save.Markers();
    for (auto it = markers.begin(); it != markers.end();) {
      float x = 0.0f, y = 0.0f, z = 0.0f;
      float nx = 0.0f, nz = 0.0f;
      if (MarkerPosition(*it, x, y, z) && !ResizePoint(g, x, z, nx, nz)) {
        dropped.insert(it->name);
        it = markers.erase(it);
        ++report.markersDropped;
        continue;
      }
      if (MarkerPosition(*it, x, y, z)) {
        (void)ResizePoint(g, x, z, nx, nz);
        it->Set("position", Vector3Value(nx, y, nz));
      }
      ++report.markersKept;
      ++it;
    }
    // Chains lose the dropped markers; an empty one goes.
    std::vector<MarkerChain>& chains = save.Chains();
    for (auto it = chains.begin(); it != chains.end();) {
      it->markers.erase(
        std::remove_if(
          it->markers.begin(),
          it->markers.end(),
          [&](const std::string& name) {
        return dropped.count(name) != 0;
      }
        ),
        it->markers.end()
      );
      if (it->markers.empty()) {
        it = chains.erase(it);
        ++report.chainsDropped;
      } else {
        ++it;
      }
    }
    // Areas moved and clipped.
    std::vector<SaveEntry>& areas = save.Areas();
    for (auto it = areas.begin(); it != areas.end();) {
      const std::vector<double> r = ValueNumbers(it->Get("rectangle"));
      if (r.size() >= 4) {
        double x0 = r[0] * g.fx + g.ox;
        double z0 = r[1] * g.fz + g.oz;
        double x1 = r[2] * g.fx + g.ox;
        double z1 = r[3] * g.fz + g.oz;
        x0 = std::clamp(x0, 0.0, static_cast<double>(g.width));
        x1 = std::clamp(x1, 0.0, static_cast<double>(g.width));
        z0 = std::clamp(z0, 0.0, static_cast<double>(g.depth));
        z1 = std::clamp(z1, 0.0, static_cast<double>(g.depth));
        if (x1 - x0 < 1.0 || z1 - z0 < 1.0) {
          it = areas.erase(it);
          ++report.areasDropped;
          continue;
        }
        it->Set("rectangle", RectangleValue(x0, z0, x1, z1));
      }
      ++report.areasKept;
      ++it;
    }
    // Every army's units.
    for (SaveEntry& army : save.Armies()) {
      const std::string units = army.Get("Units");
      if (units.empty()) {
        continue;
      }
      UnitGroup root;
      std::string why;
      if (!ParseUnitGroup(units, root, why)) {
        continue; // (left as it was: the editor can't read it)
      }
      ResizeGroup(root, g, report);
      army.Set("Units", FormatUnitGroup(root, 12));
    }
    return save.Text();
  }

  std::string WithScenarioSize(
    const std::string& scenario,
    const int width,
    const int depth
  )
  {
    const std::regex size(R"((\bsize\s*=\s*\{)\s*[0-9.]+\s*,\s*[0-9.]+\s*(\}))");
    std::smatch m;
    if (!std::regex_search(scenario, m, size)) {
      return scenario;
    }
    // (spliced by hand: "$1" before the digits would read as a later group)
    return m.prefix().str() + m[1].str() + std::to_string(width) + ", " + std::to_string(depth) + m[2].str() +
      m.suffix().str();
  }
} // namespace faf::editor
