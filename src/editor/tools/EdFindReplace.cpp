#include "editor/tools/EdFindReplace.h"

#include <algorithm>
#include <cmath>
#include <map>

namespace faf::editor
{
  std::vector<FindTypeCount> CountFindTypes(
    const std::vector<FindObject>& objects
  )
  {
    std::map<std::pair<int, std::string>, std::pair<int, int>> counts; // count, group
    for (const FindObject& object : objects) {
      auto& [count, group] = counts[{static_cast<int>(object.kind), object.type}];
      ++count;
      group = object.group;
    }
    std::vector<FindTypeCount> types;
    types.reserve(counts.size());
    for (const auto& [key, value] : counts) {
      types.push_back({static_cast<FindKind>(key.first), key.second, value.first, value.second});
    }
    std::stable_sort(types.begin(), types.end(), [](const FindTypeCount& a, const FindTypeCount& b) {
      if (a.kind != b.kind) {
        return a.kind < b.kind;
      }
      return a.count > b.count; // equal counts stay in name order (the map's)
    });
    return types;
  }

  std::vector<int> FindMatches(
    const std::vector<FindObject>& objects,
    const FindKind kind,
    const std::string& type,
    const FindScope scope
  )
  {
    std::vector<int> matches;
    for (std::size_t i = 0; i < objects.size(); ++i) {
      const FindObject& object = objects[i];
      if (object.kind != kind || object.type != type) {
        continue;
      }
      if ((scope == FindScope::Selection && !object.selected) || (scope == FindScope::FirstPart && !object.firstPart)) {
        continue;
      }
      matches.push_back(static_cast<int>(i));
    }
    return matches;
  }

  bool InFirstPart(
    const int width,
    const int height,
    const Symmetry symmetry,
    const int turns,
    const float x,
    const float z
  )
  {
    float cx[kMaxSymmetryCopies];
    float cz[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(width, height, x, z, symmetry, turns, cx, cz);
    constexpr float kSame = 1e-3f; // an image this close is the point itself (on a mirror line)
    for (int c = 1; c < copies; ++c) {
      if (cx[c] < x - kSame || (std::abs(cx[c] - x) <= kSame && cz[c] < z - kSame)) {
        return false;
      }
    }
    return true;
  }

  const char* FindKindName(
    const FindKind kind
  ) noexcept
  {
    switch (kind) {
    case FindKind::Marker:
      return "marker";
    case FindKind::Unit:
      return "unit";
    case FindKind::Prop:
      return "prop";
    case FindKind::Decal:
      return "decal";
    default:
      return "";
    }
  }

  std::string FindTypeLabel(
    const FindKind kind,
    const std::string& type
  )
  {
    if (kind != FindKind::Prop && kind != FindKind::Decal) {
      return type;
    }
    const std::size_t slash = type.find_last_of("/\\");
    std::string name = slash == std::string::npos ? type : type.substr(slash + 1);
    if (const std::size_t dot = name.find_last_of('.'); dot != std::string::npos && dot > 0) {
      name.resize(dot);
    }
    if (kind == FindKind::Prop && name.size() > 5 && name.compare(name.size() - 5, 5, "_prop") == 0) {
      name.resize(name.size() - 5);
    }
    return name;
  }
} // namespace faf::editor
