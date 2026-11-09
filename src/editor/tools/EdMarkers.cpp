#include "editor/tools/EdMarkers.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    const char* const kProps = "/env/common/props/markers/";

    std::string Prop(const char* const file)
    {
      return std::string(kProps) + file;
    }

    std::string Float(const double value)
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "FLOAT( %.6f )", value);
      return text;
    }

    std::vector<std::pair<std::string, std::string>> Hint()
    {
      return {{"hint", "BOOLEAN( true )"}};
    }

    std::vector<std::pair<std::string, std::string>> PathNode(const char* const graph)
    {
      return {{"hint", "BOOLEAN( true )"}, {"graph", StringValue(graph)}, {"adjacentTo", StringValue("")}};
    }
  } // namespace

  const std::vector<MarkerType>& MarkerTypes()
  {
    static const std::vector<MarkerType> types = {
      {"Mass", "Resources", "Mass ", "ff808080", "M_Mass_prop.bp",
       {{"size", Float(1.0)}, {"resource", "BOOLEAN( true )"}, {"amount", Float(100.0)}, {"editorIcon", StringValue("/textures/editor/marker_mass.bmp")}}},
      {"Hydrocarbon", "Resources", "Hydrocarbon ", "ff008000", "M_Hydrocarbon_prop.bp",
       {{"size", Float(3.0)}, {"resource", "BOOLEAN( true )"}, {"amount", Float(100.0)}}},
      {"Blank Marker", "Starts", "ARMY_", "ff800080", "M_Blank_prop.bp", {}},
      {"Rally Point", "AI", "Rally Point ", "FF808000", "M_Defensive_prop.bp", Hint()},
      {"Naval Rally Point", "AI", "Naval Rally Point ", "ff00FFFF", "M_Defensive_prop.bp", Hint()},
      {"Expansion Area", "AI", "Expansion Area ", "ff008080", "M_Expansion_prop.bp", Hint()},
      {"Large Expansion Area", "AI", "Large Expansion Area ", "ffff0080", "M_Expansion_prop.bp", Hint()},
      {"Naval Area", "AI", "Naval Area ", "ff0000FF", "M_Expansion_prop.bp", Hint()},
      {"Defensive Point", "AI", "Defensive Point ", "ff008000", "M_Defensive_prop.bp", Hint()},
      {"Naval Defensive Point", "AI", "Naval Defensive Point ", "ff0080FF", "M_Defensive_prop.bp", Hint()},
      {"Combat Zone", "AI", "Combat Zone ", "ff800000", "M_CombatZone_prop.bp", Hint()},
      {"Protected Experimental Construction", "AI", "Protected Experimental Construction ", "ff0000AA", "M_Expansion_prop.bp", Hint()},
      {"Transport Marker", "AI", "Transport Marker ", "ff80A088", "M_Blank_prop.bp", {}},
      {"Naval Link", "AI", "Naval Link ", "ffff0000", "M_Blank_prop.bp", {}},
      {"Land Path Node", "Path nodes", "LandPN", "ff00ff00", "M_Path_prop.bp", PathNode("DefaultLand")},
      {"Water Path Node", "Path nodes", "WaterPN", "ff0000ff", "M_Path_prop.bp", PathNode("DefaultWater2")},
      {"Amphibious Path Node", "Path nodes", "AmphPN", "ff00ffff", "M_Path_prop.bp", PathNode("DefaultAmphibious")},
      {"Air Path Node", "Path nodes", "AirPN", "ffffffff", "M_Path_prop.bp", PathNode("DefaultAir")},
      {"Camera Info", "Other", "Camera Info ", "ff808000", "M_Camera_prop.bp",
       {{"zoom", Float(30.0)}, {"canSetCamera", "BOOLEAN( true )"}, {"canSyncCamera", "BOOLEAN( true )"}}},
      {"Island", "Other", "Island ", "ff808080", "M_Blank_prop.bp", Hint()},
    };
    return types;
  }

  const MarkerType* FindMarkerType(const std::string& type)
  {
    for (const MarkerType& entry : MarkerTypes()) {
      if (type == entry.type) {
        return &entry;
      }
    }
    return nullptr;
  }

  std::string NextMarkerName(const std::vector<SaveEntry>& markers, const MarkerType& type)
  {
    std::set<std::string> used;
    for (const SaveEntry& marker : markers) {
      used.insert(marker.name);
    }
    const bool start = std::string(type.type) == "Blank Marker";
    for (int number = start ? 1 : 0;; ++number) {
      char name[96];
      if (start) {
        (void)std::snprintf(name, sizeof(name), "%s%d", type.prefix, number);
      } else {
        (void)std::snprintf(name, sizeof(name), "%s%02d", type.prefix, number);
      }
      if (used.count(name) == 0) {
        return name;
      }
    }
  }

  SaveEntry NewMarker(const MarkerType& type, const std::string& name, const float x, const float y, const float z)
  {
    SaveEntry marker;
    marker.name = name;
    for (const auto& [key, value] : type.extra) {
      marker.properties.emplace_back(key, value);
    }
    marker.properties.emplace_back("color", StringValue(type.color));
    marker.properties.emplace_back("type", StringValue(type.type));
    marker.properties.emplace_back("prop", StringValue(Prop(type.prop)));
    marker.properties.emplace_back("orientation", Vector3Value(0.0, 0.0, 0.0));
    marker.properties.emplace_back("position", Vector3Value(x, y, z));
    return marker;
  }

  bool MarkerPosition(const SaveEntry& marker, float& x, float& y, float& z)
  {
    const std::vector<double> numbers = ValueNumbers(marker.Get("position"));
    if (numbers.size() < 3) {
      return false;
    }
    x = static_cast<float>(numbers[0]);
    y = static_cast<float>(numbers[1]);
    z = static_cast<float>(numbers[2]);
    return true;
  }

  std::uint32_t MarkerColor(const SaveEntry& marker)
  {
    const std::string hex = ValueString(marker.Get("color"));
    if (hex.empty()) {
      return 0xFF808080u;
    }
    return static_cast<std::uint32_t>(std::strtoul(hex.c_str(), nullptr, 16)) | 0xFF000000u;
  }

  std::string MarkerTypeOf(const SaveEntry& marker)
  {
    return ValueString(marker.Get("type"));
  }

  std::vector<std::string> MarkerLinks(const SaveEntry& marker)
  {
    std::vector<std::string> links;
    std::istringstream words(ValueString(marker.Get("adjacentTo")));
    for (std::string word; words >> word;) {
      links.push_back(word);
    }
    return links;
  }

  namespace
  {
    SaveEntry* Find(std::vector<SaveEntry>& markers, const std::string& name)
    {
      for (SaveEntry& marker : markers) {
        if (marker.name == name) {
          return &marker;
        }
      }
      return nullptr;
    }

    void WriteLinks(SaveEntry& marker, const std::vector<std::string>& links)
    {
      std::string joined;
      for (const std::string& link : links) {
        joined += (joined.empty() ? "" : " ") + link;
      }
      marker.Set("adjacentTo", StringValue(joined));
    }
  } // namespace

  bool IsPathNode(const SaveEntry& marker)
  {
    return !ValueString(marker.Get("graph")).empty();
  }

  bool MarkersLinked(const std::vector<SaveEntry>& markers, const std::string& a, const std::string& b)
  {
    for (const SaveEntry& marker : markers) {
      if (marker.name != a && marker.name != b) {
        continue;
      }
      const std::vector<std::string> links = MarkerLinks(marker);
      if (std::find(links.begin(), links.end(), marker.name == a ? b : a) != links.end()) {
        return true;
      }
    }
    return false;
  }

  bool SetMarkerLink(std::vector<SaveEntry>& markers, const std::string& a, const std::string& b, const bool linked)
  {
    SaveEntry* const first = Find(markers, a);
    SaveEntry* const second = Find(markers, b);
    if (first == nullptr || second == nullptr || first == second || !IsPathNode(*first) ||
        ValueString(first->Get("graph")) != ValueString(second->Get("graph"))) {
      return false;
    }
    bool changed = false;
    for (auto [from, to] : {std::pair{first, b}, std::pair{second, a}}) {
      std::vector<std::string> links = MarkerLinks(*from);
      const auto at = std::find(links.begin(), links.end(), to);
      if (linked && at == links.end()) {
        links.push_back(to);
      } else if (!linked && at != links.end()) {
        links.erase(std::remove(links.begin(), links.end(), to), links.end());
      } else {
        continue;
      }
      WriteLinks(*from, links);
      changed = true;
    }
    return changed;
  }

  int RemoveLinksTo(std::vector<SaveEntry>& markers, const std::string& name)
  {
    int changed = 0;
    for (SaveEntry& marker : markers) {
      std::vector<std::string> links = MarkerLinks(marker);
      const std::size_t count = links.size();
      links.erase(std::remove(links.begin(), links.end(), name), links.end());
      if (links.size() != count) {
        WriteLinks(marker, links);
        ++changed;
      }
    }
    return changed;
  }

  MarkerGroup MarkerGroupOf(const SaveEntry& marker)
  {
    const std::string type = MarkerTypeOf(marker);
    if (type == "Blank Marker") {
      return MarkerGroup::Starts;
    }
    if (type == "Mass" || type == "Hydrocarbon") {
      return MarkerGroup::Resources;
    }
    if (IsPathNode(marker)) {
      return MarkerGroup::PathNodes;
    }
    // The palette's own group for the types it knows (rally points, expansions, naval links...).
    if (const MarkerType* const known = FindMarkerType(type); known != nullptr && std::string(known->group) == "AI") {
      return MarkerGroup::Ai;
    }
    return MarkerGroup::Other;
  }

  const char* MarkerGroupName(const MarkerGroup group)
  {
    switch (group) {
    case MarkerGroup::Starts:
      return "Start positions";
    case MarkerGroup::Resources:
      return "Resources";
    case MarkerGroup::Ai:
      return "AI markers";
    case MarkerGroup::PathNodes:
      return "Path nodes";
    case MarkerGroup::Other:
      break;
    }
    return "Other";
  }

  int MarkerNear(const std::vector<SaveEntry>& markers, const std::string& type, const float x, const float z, const float reach)
  {
    int best = -1;
    float bestDistance = reach;
    for (std::size_t i = 0; i < markers.size(); ++i) {
      float mx = 0.0f, my = 0.0f, mz = 0.0f;
      if (MarkerTypeOf(markers[i]) != type || !MarkerPosition(markers[i], mx, my, mz)) {
        continue;
      }
      const float d = std::hypot(mx - x, mz - z);
      if (d <= bestDistance) {
        bestDistance = d;
        best = static_cast<int>(i);
      }
    }
    return best;
  }
} // namespace faf::editor
