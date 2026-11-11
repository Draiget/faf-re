#include "editor/doc/EdWaterBodies.h"

#include <cmath>

#include "editor/doc/EdLuaText.h"

namespace faf::editor
{
  namespace
  {
    /** `{ a, b, ... }` with exactly `count` numbers. */
    bool Numbers(
      const LuaText& value,
      const std::size_t count,
      double* const out
    )
    {
      if (!value.isTable || !value.fields.empty() || value.items.size() != count) {
        return false;
      }
      for (std::size_t i = 0; i < count; ++i) {
        if (!value.items[i].IsNumber()) {
          return false;
        }
        out[i] = value.items[i].Number();
      }
      return true;
    }

    /** One body; its `unreadable` says why when a field isn't what the editor writes. */
    WaterBody ReadBody(
      const std::string& text,
      const LuaText& value
    )
    {
      WaterBody body;
      body.hasElevation = false;
      body.hasSeed = false;
      const auto fail = [&](const std::string& why) {
        WaterBody kept;
        kept.raw = text.substr(value.start, value.end - value.start);
        kept.unreadable = why;
        return kept;
      };
      if (!value.isTable) {
        return fail("not a table");
      }
      if (!value.items.empty()) {
        return fail("it has items without names");
      }
      for (const auto& [key, field] : value.fields) {
        double numbers[4] = {0.0, 0.0, 0.0, 0.0};
        if (key == "Elevation" || key == "FillTo" || key == "Deep" || key == "Abyss") {
          if (!field.IsNumber()) {
            return fail(key + " is not a number");
          }
          const float number = static_cast<float>(field.Number());
          if (key == "Elevation") {
            body.hasElevation = true;
            body.elevation = number;
          } else if (key == "FillTo") {
            body.hasFillTo = true;
            body.fillTo = number;
          } else if (key == "Deep") {
            body.hasDeep = true;
            body.deep = number;
          } else {
            body.hasAbyss = true;
            body.abyss = number;
          }
        } else if (key == "Dry") {
          if (field.atom != "true" && field.atom != "false") {
            return fail("Dry is not true or false");
          }
          body.dry = field.IsTrue();
        } else if (key == "Seed") {
          if (!Numbers(field, 2, numbers)) {
            return fail("Seed is not { x, z }");
          }
          body.hasSeed = true;
          body.seedX = static_cast<float>(numbers[0]);
          body.seedZ = static_cast<float>(numbers[1]);
        } else if (key == "Outline") {
          if (!field.isTable || !field.fields.empty()) {
            return fail("Outline is not a list of { x, z } points");
          }
          for (const LuaText& point : field.items) {
            if (!Numbers(point, 2, numbers)) {
              return fail("Outline is not a list of { x, z } points");
            }
            body.outline.emplace_back(static_cast<float>(numbers[0]), static_cast<float>(numbers[1]));
          }
        } else if (key == "Bounds") {
          if (!Numbers(field, 4, numbers)) {
            return fail("Bounds is not { x0, z0, x1, z1 }");
          }
          body.hasBounds = true;
          body.x0 = static_cast<int>(static_cast<float>(numbers[0]));
          body.z0 = static_cast<int>(static_cast<float>(numbers[1]));
          body.x1 = static_cast<int>(static_cast<float>(numbers[2]));
          body.z1 = static_cast<int>(static_cast<float>(numbers[3]));
        } else {
          return fail("the editor doesn't know " + key);
        }
      }
      return body;
    }

    /** The indentation of the line `at` is on. */
    std::string LineIndent(
      const std::string& text,
      const std::size_t at
    )
    {
      const std::size_t lineStart = text.rfind('\n', at == 0 ? 0 : at - 1);
      const std::size_t from = lineStart == std::string::npos ? 0 : lineStart + 1;
      std::size_t end = from;
      while (end < text.size() && (text[end] == ' ' || text[end] == '\t')) {
        ++end;
      }
      return text.substr(from, end - from);
    }

    std::string TableText(
      const std::vector<WaterBody>& bodies,
      const std::string& indent
    )
    {
      std::string out = "{\n";
      for (const WaterBody& body : bodies) {
        out += indent + "    " + WaterBodyText(body) + ",\n";
      }
      return out + indent + "}";
    }
  } // namespace

  WaterBodiesRead ReadWaterBodies(
    const std::string& scenario
  )
  {
    WaterBodiesRead read;
    LuaText info;
    if (!ReadLuaAssignment(scenario, "ScenarioInfo", info, read.error)) {
      return read;
    }
    if (!info.isTable) {
      read.error = "ScenarioInfo is not a table";
      return read;
    }
    const LuaText* const list = info.Field("WaterBodies");
    if (list == nullptr) {
      return read;
    }
    read.present = true;
    if (!list->isTable) {
      read.error = "WaterBodies is not a table";
      return read;
    }
    for (const LuaText& item : list->items) {
      read.bodies.push_back(ReadBody(scenario, item));
    }
    return read;
  }

  std::string WaterBodyText(
    const WaterBody& body
  )
  {
    if (!body.raw.empty()) {
      return body.raw;
    }
    std::vector<std::string> parts;
    if (body.hasElevation) {
      parts.push_back("Elevation = " + LuaNumber(body.elevation));
    }
    if (body.dry) {
      parts.emplace_back("Dry = true");
    }
    if (body.hasFillTo) {
      parts.push_back("FillTo = " + LuaNumber(body.fillTo));
    }
    if (body.hasDeep) {
      parts.push_back("Deep = " + LuaNumber(body.deep));
    }
    if (body.hasAbyss) {
      parts.push_back("Abyss = " + LuaNumber(body.abyss));
    }
    if (body.hasSeed) {
      parts.push_back("Seed = { " + LuaNumber(body.seedX) + ", " + LuaNumber(body.seedZ) + " }");
    }
    if (!body.outline.empty()) {
      std::string points;
      for (const auto& [x, z] : body.outline) {
        points += (points.empty() ? "" : ", ") + std::string("{ ") + LuaNumber(x) + ", " + LuaNumber(z) + " }";
      }
      parts.push_back("Outline = { " + points + " }");
    }
    if (body.hasBounds) {
      parts.push_back(
        "Bounds = { " + std::to_string(body.x0) + ", " + std::to_string(body.z0) + ", " + std::to_string(body.x1) +
        ", " + std::to_string(body.z1) + " }"
      );
    }
    std::string out = "{ ";
    for (std::size_t i = 0; i < parts.size(); ++i) {
      out += (i == 0 ? "" : ", ") + parts[i];
    }
    return out + (parts.empty() ? "}" : " }");
  }

  std::string WithWaterBodies(
    const std::string& scenario,
    const std::vector<WaterBody>& bodies
  )
  {
    LuaText info;
    std::string error;
    if (!ReadLuaAssignment(scenario, "ScenarioInfo", info, error) || !info.isTable) {
      return scenario;
    }
    std::string out = scenario;
    if (const LuaText* const list = info.Field("WaterBodies"); list != nullptr) {
      const std::size_t key = out.rfind("WaterBodies", list->start);
      if (key == std::string::npos) {
        return scenario;
      }
      if (!bodies.empty()) {
        out.replace(list->start, list->end - list->start, TableText(bodies, LineIndent(out, key)));
        return out;
      }
      // Out with its comma, and its line when nothing else is on it.
      std::size_t from = key;
      std::size_t to = list->end;
      while (to < out.size() && (out[to] == ' ' || out[to] == '\t')) {
        ++to;
      }
      if (to < out.size() && (out[to] == ',' || out[to] == ';')) {
        ++to;
      }
      std::size_t lineEnd = to;
      while (lineEnd < out.size() && (out[lineEnd] == ' ' || out[lineEnd] == '\t' || out[lineEnd] == '\r')) {
        ++lineEnd;
      }
      const std::size_t indent = LineIndent(out, key).size();
      const std::size_t lineStart = key - indent;
      if ((lineStart == 0 || out[lineStart - 1] == '\n') && (lineEnd >= out.size() || out[lineEnd] == '\n')) {
        from = lineStart;
        to = lineEnd < out.size() ? lineEnd + 1 : lineEnd;
      }
      out.erase(from, to - from);
      return out;
    }
    if (bodies.empty()) {
      return scenario;
    }
    // At the top of ScenarioInfo, on its own lines.
    const std::size_t lineEnd = out.find('\n', info.start);
    const std::size_t at = lineEnd == std::string::npos ? info.start + 1 : lineEnd + 1;
    const std::string block = "    WaterBodies = " + TableText(bodies, "    ") + ",\n";
    out.insert(at, lineEnd == std::string::npos ? "\n" + block : block);
    return out;
  }

  std::vector<moho::SWaterBodyDesc> WaterBodyDescs(
    const std::vector<WaterBody>& bodies,
    const float deepBelow,
    const float abyssBelow,
    std::vector<std::string>& log,
    std::vector<std::size_t>* const bodyOf
  )
  {
    // As STIMap::InstallWaterBodies reads them (src/moho/sim/STIMapWaterBodies.cpp); its lines, its defaults.
    constexpr float kDefaultDeepBelow = 2.5f;
    constexpr float kDefaultAbyssBelow = 15.0f;
    std::vector<moho::SWaterBodyDesc> descs;
    for (std::size_t i = 0; i < bodies.size(); ++i) {
      const WaterBody& body = bodies[i];
      const std::string name = "water body " + std::to_string(i + 1);
      if (!body.raw.empty()) {
        log.push_back(name + " not previewed: the editor can't read it (" + body.unreadable + ")");
        continue;
      }
      moho::SWaterBodyDesc desc;
      desc.dry = body.dry;
      desc.elevation = body.hasElevation ? body.elevation : 0.0f;
      desc.fillTo = body.hasFillTo ? body.fillTo : desc.elevation;
      if (desc.dry ? !body.hasFillTo : !body.hasElevation) {
        log.push_back(name + (desc.dry ? " skipped: a dry body needs FillTo" : " skipped: no Elevation"));
        continue;
      }
      desc.deep = body.hasDeep ? body.deep : desc.elevation - deepBelow;
      desc.abyss = body.hasAbyss ? body.abyss : desc.elevation - abyssBelow;
      if (!desc.dry && (desc.deep >= desc.elevation || desc.abyss >= desc.elevation)) {
        log.push_back(name + ": Deep and Abyss must be below Elevation; using 2.5 and 15 below it");
        desc.deep = desc.elevation - kDefaultDeepBelow;
        desc.abyss = desc.elevation - kDefaultAbyssBelow;
      }
      if (!body.outline.empty() && body.outline.size() < 3) {
        log.push_back(name + " skipped: Outline is not 3 or more { x, z } points");
        continue;
      }
      for (const auto& [x, z] : body.outline) {
        desc.outline.push_back(x);
        desc.outline.push_back(z);
      }
      if (!body.hasSeed && body.outline.empty()) {
        log.push_back(name + " skipped: Seed is not { x, z }");
        continue;
      }
      desc.hasSeed = body.hasSeed;
      desc.seedX = body.hasSeed ? body.seedX : 0.0f;
      desc.seedZ = body.hasSeed ? body.seedZ : 0.0f;
      desc.hasBounds = body.hasBounds;
      desc.x0 = body.x0;
      desc.z0 = body.z0;
      desc.x1 = body.x1;
      desc.z1 = body.z1;
      descs.push_back(std::move(desc));
      if (bodyOf != nullptr) {
        bodyOf->push_back(i);
      }
    }
    return descs;
  }
} // namespace faf::editor
