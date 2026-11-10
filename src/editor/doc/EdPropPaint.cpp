#include "editor/doc/EdPropPaint.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  std::string PaintSetToProppaintset(const std::vector<PropPaintEntry>& entries)
  {
    std::string out = "{\n    \"PaintProps\": [";
    for (std::size_t i = 0; i < entries.size(); ++i) {
      const PropPaintEntry& entry = entries[i];
      out += i == 0 ? "\n" : ",\n";
      out += "        {\n";
      out += "            \"Blueprint\": " + JsonQuoted(entry.blueprint) + ",\n";
      out += "            \"ScaleMin\": " + JsonNumber(entry.scaleMin) + ",\n";
      out += "            \"ScaleMax\": " + JsonNumber(entry.scaleMax) + ",\n";
      out += "            \"RotationMin\": " + std::to_string(entry.rotationMin) + ",\n";
      out += "            \"RotationMax\": " + std::to_string(entry.rotationMax) + ",\n";
      out += "            \"Chance\": " + std::to_string(entry.chance) + "\n";
      out += "        }";
    }
    return out + (entries.empty() ? "]\n}" : "\n    ]\n}");
  }

  bool PaintSetFromProppaintset(const std::string& text, std::vector<PropPaintEntry>& entries, std::string& error)
  {
    std::string array;
    if (!JsonValue(text, "PaintProps", array) || array.empty() || array.front() != '[') {
      error = "not a prop paint set (no PaintProps list)";
      return false;
    }
    std::vector<PropPaintEntry> read;
    for (const std::string& object : JsonObjects(array)) {
      PropPaintEntry entry;
      if (!JsonValue(object, "Blueprint", entry.blueprint) || entry.blueprint.empty()) {
        continue;
      }
      (void)JsonFloat(object, "ScaleMin", entry.scaleMin);
      (void)JsonFloat(object, "ScaleMax", entry.scaleMax);
      std::string number;
      if (JsonValue(object, "RotationMin", number)) {
        entry.rotationMin = std::atoi(number.c_str());
      }
      if (JsonValue(object, "RotationMax", number)) {
        entry.rotationMax = std::atoi(number.c_str());
      }
      if (JsonValue(object, "Chance", number)) {
        entry.chance = std::max(0, std::atoi(number.c_str()));
      }
      read.push_back(std::move(entry));
    }
    entries = std::move(read);
    return true;
  }

  int PickPaintEntry(const std::vector<PropPaintEntry>& entries, const float roll)
  {
    int total = 0;
    for (const PropPaintEntry& entry : entries) {
      total += std::max(0, entry.chance);
    }
    if (total <= 0) {
      return -1;
    }
    const int at = std::clamp(static_cast<int>(std::floor(roll * static_cast<float>(total))), 0, total - 1);
    int sum = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
      sum += std::max(0, entries[i].chance);
      if (at < sum) {
        return static_cast<int>(i);
      }
    }
    return static_cast<int>(entries.size()) - 1;
  }
} // namespace faf::editor
