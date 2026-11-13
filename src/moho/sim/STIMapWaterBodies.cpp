// Engine addition, not in the binary: a map's water bodies (.plans/water-levels/PLAN.md).
#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"

namespace moho
{
  namespace
  {
    constexpr float kHeightWordScale = 0.0078125f;
    /// A body's Deep and Abyss below its level when neither the body nor the sea gives them.
    constexpr float kDefaultDeepBelow = 2.5f;
    constexpr float kDefaultAbyssBelow = 15.0f;

    /// A number field of `table`, or `fallback` when it is missing or not a number.
    [[nodiscard]] float NumberField(
      const LuaPlus::LuaObject& table,
      const char* const name,
      const float fallback,
      bool* const present = nullptr
    )
    {
      const LuaPlus::LuaObject value = table[name];
      const bool isNumber = value.IsNumber();
      if (present != nullptr) {
        *present = isNumber;
      }
      return isNumber ? static_cast<float>(value.GetNumber()) : fallback;
    }

    /// `{ a, b, ... }` with `count` numbers, into `out`; false when it is not that.
    [[nodiscard]] bool NumberList(
      const LuaPlus::LuaObject& list,
      float* const out,
      const std::int32_t count
    )
    {
      if (!list.IsTable()) {
        return false;
      }
      for (std::int32_t index = 0; index < count; ++index) {
        const LuaPlus::LuaObject value = list[index + 1];
        if (!value.IsNumber()) {
          return false;
        }
        out[index] = static_cast<float>(value.GetNumber());
      }
      return true;
    }

    /**
     * `River = { Points = { { x, z, Level = , HalfWidth = , Fall = , Below = }, ... }, Steps = , Margin = ,
     * FlowScale = }` into `out`; false with `why` set when it is not that. The values are checked by
     * `ValidateRiver` when the river is built.
     */
    [[nodiscard]] bool ReadRiver(
      const LuaPlus::LuaObject& river,
      SRiverDesc& out,
      std::string& why
    )
    {
      if (!river.IsTable()) {
        why = "River is not a table";
        return false;
      }
      const LuaPlus::LuaObject points = river["Points"];
      if (!points.IsTable()) {
        why = "River.Points is not a list of points";
        return false;
      }
      const std::int32_t count = points.GetCount();
      for (std::int32_t index = 1; index <= count; ++index) {
        const LuaPlus::LuaObject entry = points[index];
        float xz[2] = {0.0f, 0.0f};
        if (!NumberList(entry, xz, 2)) {
          why = "River.Points[" + std::to_string(index) + "] is not { x, z, Level = , HalfWidth = }";
          return false;
        }
        SRiverPoint point;
        point.x = xz[0];
        point.z = xz[1];
        bool present = false;
        point.level = NumberField(entry, "Level", 0.0f, &present);
        if (!present) {
          why = "River.Points[" + std::to_string(index) + "] has no Level";
          return false;
        }
        point.halfWidth = NumberField(entry, "HalfWidth", 0.0f, &present);
        if (!present) {
          why = "River.Points[" + std::to_string(index) + "] has no HalfWidth";
          return false;
        }
        const LuaPlus::LuaObject fall = entry["Fall"];
        point.fall = fall.IsBoolean() && fall.GetBoolean();
        point.below = NumberField(entry, "Below", point.level, &present);
        if (point.fall && !present) {
          why = "River.Points[" + std::to_string(index) + "] is a Fall without Below";
          return false;
        }
        out.points.push_back(point);
      }
      out.steps = static_cast<std::int32_t>(NumberField(river, "Steps", static_cast<float>(kRiverDefaultSteps)));
      out.margin = NumberField(river, "Margin", kRiverDefaultMargin);
      out.flowScale = NumberField(river, "FlowScale", 1.0f);
      return true;
    }
  } // namespace

  void STIMap::InstallWaterBodies(
    const LuaPlus::LuaObject& scenarioInfo
  )
  {
    mWaterBodies.reset();
    if (!scenarioInfo.IsTable()) {
      return;
    }
    const LuaPlus::LuaObject list = scenarioInfo["WaterBodies"];
    if (!list.IsTable()) {
      return;
    }
    if (!FAF_IsSimFixActive(EFafSimFix::WaterBodies)) {
      gpg::Logf("Water bodies: the map describes some, but this game has them off (sim_FixWaterBodies); sea only");
      return;
    }

    // Shading depths default to the sea's distances below its level, or without a sea to the
    // original maps' usual ones (Seton's Clutch: 17.5, 15, 2.5).
    const bool seaShading =
      mWaterEnabled != 0u && mWaterElevation > mWaterElevationDeep && mWaterElevation > mWaterElevationAbyss;
    const float deepBelow = seaShading ? mWaterElevation - mWaterElevationDeep : kDefaultDeepBelow;
    const float abyssBelow = seaShading ? mWaterElevation - mWaterElevationAbyss : kDefaultAbyssBelow;

    std::vector<SWaterBodyDesc> descs;
    std::vector<std::string> log;
    const std::int32_t count = list.GetCount();
    for (std::int32_t index = 1; index <= count; ++index) {
      const LuaPlus::LuaObject entry = list[index];
      if (!entry.IsTable()) {
        log.push_back("water body " + std::to_string(index) + " skipped: not a table");
        continue;
      }

      SWaterBodyDesc desc;
      const LuaPlus::LuaObject dry = entry["Dry"];
      desc.dry = dry.IsBoolean() && dry.GetBoolean();

      // A river: the surface runs along a centreline and falls block movement. With the switch off the
      // body is a flat lake at its Elevation (below), if it has one.
      const LuaPlus::LuaObject riverObject = entry["River"];
      if (!riverObject.IsNil() && FAF_IsSimFixActive(EFafSimFix::WaterRivers)) {
        std::string why;
        if (!ReadRiver(riverObject, desc.river, why)) {
          log.push_back("water body " + std::to_string(index) + " skipped: " + why);
          continue;
        }
        desc.isRiver = true;
        desc.hasSeed = false;
        float highest = -1.0e30f;
        for (const SRiverPoint& point : desc.river.points) {
          highest = point.level > highest ? point.level : highest;
        }
        desc.elevation = highest;
        desc.deep = NumberField(entry, "Deep", highest - deepBelow);
        desc.abyss = NumberField(entry, "Abyss", highest - abyssBelow);
        if (desc.deep >= highest || desc.abyss >= highest) {
          log.push_back(
            "water body " + std::to_string(index) +
            ": Deep and Abyss must be below the river's highest level; using 2.5 and 15 below it"
          );
          desc.deep = highest - kDefaultDeepBelow;
          desc.abyss = highest - kDefaultAbyssBelow;
        }
        descs.push_back(desc);
        continue;
      }

      bool hasElevation = false;
      desc.elevation = NumberField(entry, "Elevation", 0.0f, &hasElevation);
      bool hasFillTo = false;
      desc.fillTo = NumberField(entry, "FillTo", desc.elevation, &hasFillTo);
      if (desc.dry ? !hasFillTo : !hasElevation) {
        log.push_back(
          "water body " + std::to_string(index) +
          (desc.dry ? " skipped: a dry body needs FillTo"
                    : (riverObject.IsNil() ? " skipped: no Elevation"
                                           : " skipped: a River needs sim_FixRivers, or an Elevation for a flat lake"))
        );
        continue;
      }
      desc.deep = NumberField(entry, "Deep", desc.elevation - deepBelow);
      desc.abyss = NumberField(entry, "Abyss", desc.elevation - abyssBelow);
      // Shading only (drawing divides by Elevation - Abyss): keep both below the level.
      if (!desc.dry && (desc.deep >= desc.elevation || desc.abyss >= desc.elevation)) {
        log.push_back(
          "water body " + std::to_string(index) + ": Deep and Abyss must be below Elevation; using 2.5 and 15 below it"
        );
        desc.deep = desc.elevation - kDefaultDeepBelow;
        desc.abyss = desc.elevation - kDefaultAbyssBelow;
      }

      // Outline: { {x, z}, {x, z}, ... }, the control points of a closed spline.
      const LuaPlus::LuaObject outline = entry["Outline"];
      if (!outline.IsNil()) {
        bool valid = outline.IsTable();
        const std::int32_t pointCount = valid ? outline.GetCount() : 0;
        for (std::int32_t point = 1; valid && point <= pointCount; ++point) {
          float xz[2] = {0.0f, 0.0f};
          valid = NumberList(outline[point], xz, 2);
          desc.outline.push_back(xz[0]);
          desc.outline.push_back(xz[1]);
        }
        if (!valid || pointCount < 3) {
          log.push_back("water body " + std::to_string(index) + " skipped: Outline is not 3 or more { x, z } points");
          continue;
        }
      }

      LuaPlus::LuaObject seedObject = entry["Seed"];
      float seed[2] = {0.0f, 0.0f};
      if (seedObject.IsNil() && desc.outline.empty() && riverObject.IsTable()) {
        // A river as a flat lake (sim_FixRivers off) starts at its first point.
        const LuaPlus::LuaObject riverPoints = riverObject["Points"];
        if (riverPoints.IsTable()) {
          seedObject = riverPoints[1];
        }
      }
      if (seedObject.IsNil() && !desc.outline.empty()) {
        desc.hasSeed = false;
      } else if (!NumberList(seedObject, seed, 2)) {
        log.push_back("water body " + std::to_string(index) + " skipped: Seed is not { x, z }");
        continue;
      }
      desc.seedX = seed[0];
      desc.seedZ = seed[1];

      const LuaPlus::LuaObject bounds = entry["Bounds"];
      if (!bounds.IsNil()) {
        float rect[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        if (!NumberList(bounds, rect, 4)) {
          log.push_back("water body " + std::to_string(index) + " skipped: Bounds is not { x0, z0, x1, z1 }");
          continue;
        }
        desc.hasBounds = true;
        desc.x0 = static_cast<std::int32_t>(rect[0]);
        desc.z0 = static_cast<std::int32_t>(rect[1]);
        desc.x1 = static_cast<std::int32_t>(rect[2]);
        desc.z1 = static_cast<std::int32_t>(rect[3]);
      }
      descs.push_back(desc);
    }

    const CHeightField* const field = mHeightField.get();
    if (field != nullptr && !descs.empty()) {
      mWaterBodies = CWaterBodies::Build(field->data, field->width, field->height, kHeightWordScale, descs, &log);
    }

    for (const std::string& line : log) {
      gpg::Warnf("Water bodies: %s", line.c_str());
    }
    if (!mWaterBodies) {
      gpg::Logf("Water bodies: none filled; sea only");
      return;
    }
    for (std::size_t number = 1; number <= mWaterBodies->BodyCount(); ++number) {
      const SWaterBody& body = mWaterBodies->Body(static_cast<std::uint8_t>(number));
      if (const CWaterRiver* const river = mWaterBodies->River(static_cast<std::uint8_t>(number)); river != nullptr) {
        gpg::Logf(
          "Water bodies: %zu river at %g to %g, %zu falls (%u fall cells), %u cells in [%d, %d] x [%d, %d]",
          number,
          static_cast<double>(body.levelMax),
          static_cast<double>(body.levelMin),
          river->Falls().size(),
          river->FallCellCount(),
          body.cellCount,
          body.x0,
          body.x1,
          body.z0,
          body.z1
        );
        continue;
      }
      gpg::Logf(
        "Water bodies: %zu at %g, %u cells in [%d, %d] x [%d, %d]",
        number,
        static_cast<double>(body.elevation),
        body.cellCount,
        body.x0,
        body.x1,
        body.z0,
        body.z1
      );
    }
  }
} // namespace moho
