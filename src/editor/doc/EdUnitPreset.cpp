#include "editor/doc/EdUnitPreset.h"

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kRadToDeg = 180.0f / kPi;
    constexpr float kDegToRad = kPi / 180.0f;
  } // namespace

  std::string UnitsToScunits(const std::vector<SaveUnit>& units)
  {
    float centre[3] = {0.0f, 0.0f, 0.0f};
    std::string out = "{\n    \"Units\": [";
    for (std::size_t i = 0; i < units.size(); ++i) {
      const SaveUnit& unit = units[i];
      float pos[3];
      GameToFafme(unit.position, pos);
      for (int a = 0; a < 3; ++a) {
        centre[a] += pos[a];
      }
      // UnitInstance.RotationFromScmapRotation.
      const float degrees[3] = {unit.orientation[0] * kRadToDeg, -unit.orientation[1] * kRadToDeg, unit.orientation[2] * kRadToDeg};
      float rot[4];
      UnityEulerToQuaternion(degrees, rot);
      out += i == 0 ? "\n" : ",\n";
      out += "        {\n";
      out += "            \"ID\": " + JsonQuoted(unit.type) + ",\n";
      out += "            \"pos\": " + JsonVectorText(pos, 3, "            ") + ",\n";
      out += "            \"rot\": " + JsonVectorText(rot, 4, "            ") + ",\n";
      out += "            \"orders\": " + JsonQuoted(unit.orders) + ",\n";
      out += "            \"platoon\": " + JsonQuoted(unit.platoon) + "\n";
      out += "        }";
    }
    if (!units.empty()) {
      for (float& axis : centre) {
        axis /= static_cast<float>(units.size());
      }
    }
    out += units.empty() ? "],\n" : "\n    ],\n";
    out += "    \"Center\": " + JsonVectorText(centre, 3, "    ") + "\n";
    return out + "}";
  }

  bool UnitsFromScunits(const std::string& text, std::vector<SaveUnit>& units, float (&centre)[3], std::string& error)
  {
    std::string array;
    if (!JsonValue(text, "Units", array) || array.empty() || array.front() != '[') {
      error = "not a units file (no Units list)";
      return false;
    }
    for (const std::string& object : JsonObjects(array)) {
      SaveUnit unit;
      if (!JsonValue(object, "ID", unit.type) || unit.type.empty()) {
        continue;
      }
      (void)JsonValue(object, "orders", unit.orders);
      (void)JsonValue(object, "platoon", unit.platoon);
      float pos[3] = {0.0f, 0.0f, 0.0f};
      float rot[4] = {0.0f, 0.0f, 0.0f, 1.0f};
      JsonVector(object, "pos", pos, 3);
      JsonVector(object, "rot", rot, 4);
      FafmeToGame(pos, unit.position);
      // UnitInstance.ScmapRotationFromRotation.
      float degrees[3];
      UnityQuaternionToEuler(rot, degrees);
      unit.orientation[0] = degrees[0] * kDegToRad;
      unit.orientation[1] = -degrees[1] * kDegToRad;
      unit.orientation[2] = degrees[2] * kDegToRad;
      units.push_back(std::move(unit));
    }
    float fafme[3] = {0.0f, 0.0f, 0.0f};
    JsonVector(text, "Center", fafme, 3);
    FafmeToGame(fafme, centre);
    return true;
  }

  bool FitUnitsOnMap(std::vector<SaveUnit>& units, const float (&centre)[3], const float width, const float height)
  {
    bool off = false;
    for (const SaveUnit& unit : units) {
      off = off || unit.position[0] < 0.0f || unit.position[2] < 0.0f || unit.position[0] > width || unit.position[2] > height;
    }
    if (!off) {
      return false;
    }
    const float dx = width * 0.5f - centre[0];
    const float dz = height * 0.5f - centre[2];
    for (SaveUnit& unit : units) {
      unit.position[0] += dx;
      unit.position[2] += dz;
    }
    return true;
  }
} // namespace faf::editor
