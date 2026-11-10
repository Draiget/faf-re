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

  const char* MarkerTypeUse(const std::string& type)
  {
    // From FAF's Lua: who reads each type and what for (the readers are named for the curious).
    struct Use
    {
      const char* type;
      const char* use;
    };
    static constexpr Use kUses[] = {
      {"Mass", "The game makes a mass deposit here at the start (when 'resource' is on), and AIs pick extractor spots from them "
               "(ScenarioUtilities CreateResources, GridDeposits)."},
      {"Hydrocarbon", "The game makes a hydrocarbon deposit here at the start (when 'resource' is on), and AIs pick power "
                      "generator spots from them."},
      {"Blank Marker", "No game code reads the type. A marker named ARMY_n is that army's start position whatever its type, and "
                       "scripts find markers by name."},
      {"Rally Point", "AI factories send their new units to the nearest one. FAF's skirmish AIs make their own at the start and "
                      "drop the map's; campaign AIs use the map's (FactoryBuilderManager, base-ai)."},
      {"Naval Rally Point", "AI naval factories send their new ships to the nearest one; the map's are used (not made again)."},
      {"Expansion Area", "AIs send engineers to build expansion bases here and raid or guard them. FAF's skirmish AIs make their "
                         "own from groups of 2-3 mass points and drop the map's; campaign AIs use the map's."},
      {"Large Expansion Area", "Like Expansion Area, for large AI expansion bases; skirmish AIs make theirs from groups of more "
                               "than 3 mass points and drop the map's."},
      {"Naval Area", "AIs build naval bases here. FAF's skirmish AIs make their own from water near starts and expansions and "
                     "drop the map's; campaign AIs use the map's."},
      {"Defensive Point", "AI engineers build defences at the nearest one that has none yet."},
      {"Naval Defensive Point", "AI engineers build naval defences at the nearest one that has none yet."},
      {"Combat Zone", "Read only by AIGetSortedScoutingLocations (AI scouting targets), which nothing in FAF calls: in today's "
                      "game it changes nothing. AI mods may still read it."},
      {"Protected Experimental Construction", "AI engineers build experimentals at the nearest one (where they stand when the "
                                              "map has none)."},
      {"Transport Marker", "An AI transport drop-off spot, used only on a map without any Land Path Node."},
      {"Naval Link", "No game code reads it (only the in-game debug marker list shows it)."},
      {"Land Path Node", "Older AI code builds its pathing graph from the path nodes and their 'adjacentTo' links (threat-avoiding "
                         "routes, path checks, transport drops); most AI movement now uses the navigation mesh. The lobby shows "
                         "\"AI markers: yes\" when nodes are linked."},
      {"Water Path Node", "The naval layer of the older AI pathing graph (see Land Path Node)."},
      {"Amphibious Path Node", "The amphibious layer of the older AI pathing graph; made from land and water nodes when a map "
                               "has none."},
      {"Air Path Node", "The air layer of the older AI pathing graph."},
      {"Camera Info", "No code checks the type: campaign camera moves take a marker and read its position, orientation and "
                      "'zoom'."},
      {"Island", "Any Island marker makes AIs treat the map as an island map: they pick other build plans."},
    };
    for (const Use& use : kUses) {
      if (type == use.type) {
        return use.use;
      }
    }
    return "";
  }

  const char* MarkerFieldUse(const std::string& key)
  {
    struct Use
    {
      const char* key;
      const char* use;
    };
    static constexpr Use kUses[] = {
      {"hint", "Editor display only: no game code reads it."},
      {"prop", "Editor display only: the marker's model in editors (a resource's prop is the game's own)."},
      {"editorIcon", "Editor display only: no game code reads it."},
      {"color", "Only the colour of the AI debug overlays; it changes nothing in a game."},
      {"resource", "When on, the game makes the deposit (mass or hydrocarbon) here at the start."},
      {"size", "The deposit's size, given to the game's CreateResourceDeposit."},
      {"amount", "Not read by the game."},
      {"adjacentTo", "The path nodes this one links to (names, space-separated): the AI pathing graph's edges."},
      {"graph", "The path node's graph name (default: its type's): nodes of one graph link."},
      {"zoom", "The camera's zoom for a campaign camera move to this marker."},
      {"canSetCamera", "Not read by FAF's Lua."},
      {"canSyncCamera", "Not read by FAF's Lua."},
    };
    for (const Use& use : kUses) {
      if (key == use.key) {
        return use.use;
      }
    }
    return "";
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
  std::vector<SaveEntry> AirNodeGrid(const std::vector<SaveEntry>& existing, const int count, const float x0, const float z0,
                                     const float x1, const float z1, const std::function<float(float, float)>& height)
  {
    std::vector<SaveEntry> grid;
    const MarkerType* const type = FindMarkerType("Air Path Node");
    if (type == nullptr || count < 2 || x1 <= x0 || z1 <= z0) {
      return grid;
    }
    std::vector<SaveEntry> taken = existing;
    const float stepX = (x1 - x0) / static_cast<float>(count);
    const float stepZ = (z1 - z0) / static_cast<float>(count);
    for (int row = 0; row < count; ++row) {
      for (int column = 0; column < count; ++column) {
        // Each node on the half unit, as the game's saves place markers.
        const float x = std::floor(x0 + stepX * (static_cast<float>(column) + 0.5f)) + 0.5f;
        const float z = std::floor(z0 + stepZ * (static_cast<float>(row) + 0.5f)) + 0.5f;
        SaveEntry node = NewMarker(*type, NextMarkerName(taken, *type), x, height(x, z), z);
        taken.push_back({node.name, {}});
        grid.push_back(std::move(node));
      }
    }
    // Each to its 8 neighbours (each pair once; SetMarkerLink writes both ends).
    for (int row = 0; row < count; ++row) {
      for (int column = 0; column < count; ++column) {
        const std::string& name = grid[static_cast<std::size_t>(row * count + column)].name;
        for (const auto& [dr, dc] : {std::pair{0, 1}, std::pair{1, -1}, std::pair{1, 0}, std::pair{1, 1}}) {
          const int r = row + dr;
          const int c = column + dc;
          if (r < count && c >= 0 && c < count) {
            const std::string other = grid[static_cast<std::size_t>(r * count + c)].name;
            (void)SetMarkerLink(grid, name, other, true);
          }
        }
      }
    }
    return grid;
  }
} // namespace faf::editor
