#include "editor/tools/EdSelectModes.h"

#include <set>

namespace faf::editor
{
  const char* SelectModeName(
    const SelectMode mode
  )
  {
    switch (mode) {
    case SelectMode::All:
      return "all";
    case SelectMode::None:
      return "none";
    case SelectMode::Invert:
      return "invert";
    default:
      return "same type";
    }
  }

  std::vector<std::size_t> SelectByMode(
    const std::vector<std::string>& keys,
    const std::vector<bool>& selectable,
    const std::vector<std::size_t>& selected,
    const SelectMode mode
  )
  {
    const auto canPick = [&](const std::size_t i) {
      return i < selectable.size() ? selectable[i] : true;
    };
    std::vector<std::size_t> out;
    if (mode == SelectMode::None) {
      return out;
    }
    const std::set<std::size_t> now(selected.begin(), selected.end());
    std::set<std::string> types;
    for (const std::size_t i : selected) {
      if (i < keys.size()) {
        types.insert(keys[i]);
      }
    }
    for (std::size_t i = 0; i < keys.size(); ++i) {
      if (!canPick(i)) {
        continue;
      }
      const bool take = mode == SelectMode::All ? true
        : mode == SelectMode::Invert            ? now.count(i) == 0
                                                : types.count(keys[i]) != 0;
      if (take) {
        out.push_back(i);
      }
    }
    return out;
  }
} // namespace faf::editor
