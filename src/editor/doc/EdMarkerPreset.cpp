#include "editor/doc/EdMarkerPreset.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

#include "editor/doc/EdJson.h"
#include "editor/tools/EdMarkers.h"

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kRadToDeg = 180.0f / kPi;
    constexpr float kDegToRad = kPi / 180.0f;

    // FAForeverMapEditor's SaveLua.Marker.MarkerTypes in its order (the number JsonUtility writes), as our `type`
    // strings: its MarkerTypeToString puts a space before each capital. Null: a type the editor doesn't place.
    const char* const kFafmeTypes[] = {
      nullptr, // None
      "Mass",
      "Hydrocarbon",
      "Blank Marker",
      "Camera Info",
      "Combat Zone",
      "Defensive Point",
      "Naval Defensive Point",
      "Protected Experimental Construction",
      "Expansion Area",
      "Large Expansion Area",
      "Naval Area",
      "Rally Point",
      "Naval Rally Point",
      "Land Path Node",
      "Air Path Node",
      "Water Path Node",
      "Amphibious Path Node",
      nullptr, // AutoPathNode: FAFME's own, saved as land or water nodes
      "Naval Link",
      "Transport Marker",
      "Island",
      nullptr, // WeatherGenerator
      nullptr, // WeatherDefinition
      nullptr, // Effect
      nullptr, // NavalExclude
      nullptr, // Objective
    };
    constexpr int kFafmeTypeCount = static_cast<int>(sizeof(kFafmeTypes) / sizeof(kFafmeTypes[0]));

    int FafmeTypeOf(const std::string& type)
    {
      for (int i = 0; i < kFafmeTypeCount; ++i) {
        if (kFafmeTypes[i] != nullptr && type == kFafmeTypes[i]) {
          return i;
        }
      }
      return 0;
    }

    // MarkerObject.ScmapRotToMarkerRot: the save's orientation (radians) to the marker's rotation. A camera's is its
    // pitch from straight down and its heading; every other marker's is the orientation as Euler angles.
    void OrientationToRotation(const std::vector<double>& orientation, const bool camera, float (&quaternion)[4])
    {
      const float x = orientation.size() > 0 ? static_cast<float>(orientation[0]) : 0.0f;
      const float y = orientation.size() > 1 ? static_cast<float>(orientation[1]) : 0.0f;
      const float z = orientation.size() > 2 ? static_cast<float>(orientation[2]) : 0.0f;
      float degrees[3] = {x * kRadToDeg, y * kRadToDeg, z * kRadToDeg};
      if (camera) {
        degrees[0] = y * kRadToDeg;
        degrees[1] = -x * kRadToDeg;
        degrees[2] = 0.0f;
        while (degrees[0] < -180.0f) {
          degrees[0] += 360.0f;
        }
        while (degrees[0] >= 360.0f) {
          degrees[0] -= 360.0f;
        }
        degrees[0] = 90.0f - std::clamp(degrees[0], 0.0f, 180.0f);
      }
      UnityEulerToQuaternion(degrees, quaternion);
    }

    // MarkerObject.MarkerRotToScmapRot, the way back.
    void RotationToOrientation(const float (&quaternion)[4], const bool camera, double (&orientation)[3])
    {
      float euler[3];
      UnityQuaternionToEuler(quaternion, euler);
      euler[2] = 0.0f;
      if (camera) {
        while (euler[0] < 0.0f) {
          euler[0] += 360.0f;
        }
        euler[0] = 90.0f - euler[0];
        const float heading = -euler[1] * kDegToRad;
        const float pitch = euler[0] * kDegToRad;
        orientation[0] = std::round(heading * 1000000.0f) / 1000000.0;
        orientation[1] = std::round(pitch * 1000000.0f) / 1000000.0;
        orientation[2] = 0.0;
        return;
      }
      orientation[0] = euler[0] * kDegToRad;
      orientation[1] = euler[1] * kDegToRad;
      orientation[2] = 0.0;
    }

    std::vector<int> JsonInts(const std::string& array)
    {
      std::vector<int> numbers;
      const char* at = array.c_str();
      while (*at != '\0') {
        if ((*at >= '0' && *at <= '9') || *at == '-') {
          char* end = nullptr;
          numbers.push_back(static_cast<int>(std::strtol(at, &end, 10)));
          at = end;
        } else {
          ++at;
        }
      }
      return numbers;
    }
  } // namespace

  std::string MarkersToFafmapmarkers(const std::vector<SaveEntry>& markers, const std::vector<std::string>& names, const int mapWidth,
                                     const int mapHeight)
  {
    std::vector<const SaveEntry*> chosen;
    for (const SaveEntry& marker : markers) {
      if (names.empty() || std::find(names.begin(), names.end(), marker.name) != names.end()) {
        chosen.push_back(&marker);
      }
    }
    std::string out = "{\n    \"Markers\": [";
    for (std::size_t i = 0; i < chosen.size(); ++i) {
      const SaveEntry& marker = *chosen[i];
      const std::string type = MarkerTypeOf(marker);
      float x = 0.0f, y = 0.0f, z = 0.0f;
      (void)MarkerPosition(marker, x, y, z);
      const float game[3] = {x, y, z};
      float pos[3];
      GameToFafme(game, pos);
      float rot[4];
      OrientationToRotation(ValueNumbers(marker.Get("orientation")), type == "Camera Info", rot);
      std::string connected;
      for (const std::string& link : MarkerLinks(marker)) {
        const auto at = std::find_if(chosen.begin(), chosen.end(), [&](const SaveEntry* other) { return other->name == link; });
        if (at != chosen.end()) {
          connected += (connected.empty() ? "" : ",") + std::string("\n                ") + std::to_string(at - chosen.begin());
        }
      }
      out += i == 0 ? "\n" : ",\n";
      out += "        {\n";
      out += "            \"MarkerType\": " + std::to_string(FafmeTypeOf(type)) + ",\n";
      out += "            \"Pos\": " + JsonVectorText(pos, 3, "            ") + ",\n";
      out += "            \"Rot\": " + JsonVectorText(rot, 4, "            ") + ",\n";
      out += "            \"Connected\": [" + (connected.empty() ? std::string() : connected + "\n            ") + "]\n";
      out += "        }";
    }
    out += chosen.empty() ? "],\n" : "\n    ],\n";
    out += "    \"MapWidth\": " + std::to_string(mapWidth) + ",\n";
    out += "    \"MapHeight\": " + std::to_string(mapHeight) + "\n";
    return out + "}";
  }

  bool MarkersFromFafmapmarkers(const std::string& text, std::vector<SaveEntry>& markers, MarkerImport& result, std::string& error,
                                const std::vector<std::string>& reserved)
  {
    std::string array;
    if (!JsonValue(text, "Markers", array) || array.empty() || array.front() != '[') {
      error = "not a marker file (no Markers list)";
      return false;
    }
    // Each file marker's new name, or empty when it was left out.
    std::vector<std::string> made;
    std::vector<std::vector<int>> connected;
    // Names in use: the markers' and the reserved ones.
    std::vector<SaveEntry> taken = markers;
    for (const std::string& name : reserved) {
      taken.push_back({name, {}});
    }
    for (const std::string& object : JsonObjects(array)) {
      std::string number;
      const int index = JsonValue(object, "MarkerType", number) ? std::atoi(number.c_str()) : 0;
      const char* const typeName = index >= 0 && index < kFafmeTypeCount ? kFafmeTypes[index] : nullptr;
      const MarkerType* const type = typeName != nullptr ? FindMarkerType(typeName) : nullptr;
      std::string links;
      (void)JsonValue(object, "Connected", links);
      connected.push_back(JsonInts(links));
      if (type == nullptr) {
        made.emplace_back();
        ++result.skipped;
        continue;
      }
      float pos[3] = {0.0f, 0.0f, 0.0f};
      float rot[4] = {0.0f, 0.0f, 0.0f, 1.0f};
      JsonVector(object, "Pos", pos, 3);
      JsonVector(object, "Rot", rot, 4);
      float game[3];
      FafmeToGame(pos, game);
      SaveEntry marker = NewMarker(*type, NextMarkerName(taken, *type), game[0], game[1], game[2]);
      taken.push_back({marker.name, {}});
      double orientation[3];
      RotationToOrientation(rot, std::string(typeName) == "Camera Info", orientation);
      marker.Set("orientation", Vector3Value(orientation[0], orientation[1], orientation[2]));
      made.push_back(marker.name);
      result.names.push_back(marker.name);
      markers.push_back(std::move(marker));
    }
    for (std::size_t i = 0; i < made.size(); ++i) {
      for (const int other : connected[i]) {
        if (!made[i].empty() && other >= 0 && static_cast<std::size_t>(other) < made.size() && !made[other].empty() &&
            !MarkersLinked(markers, made[i], made[other]) && SetMarkerLink(markers, made[i], made[other], true)) {
          ++result.links;
        }
      }
    }
    return true;
  }
} // namespace faf::editor
