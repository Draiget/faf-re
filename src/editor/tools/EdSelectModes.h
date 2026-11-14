#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace faf::editor
{
  /** Select › All, None, Invert, Same type (design §5 Select): over the kind the active tool selects. */
  enum class SelectMode
  {
    All,
    None,
    Invert,
    Same,
  };
  [[nodiscard]] const char* SelectModeName(SelectMode mode);

  /**
   * The items selected after a Select command, by index, in index order. `keys` is each item's type (a prop's
   * blueprint, a marker's type, a decal's texture, a unit's blueprint id); `selectable` is false for an item the view
   * hides (it is never picked); `selected` the selection now. Same type picks every selectable item whose key one of
   * the selected items has (nothing when nothing is selected).
   */
  [[nodiscard]] std::vector<std::size_t> SelectByMode(
    const std::vector<std::string>& keys,
    const std::vector<bool>& selectable,
    const std::vector<std::size_t>& selected,
    SelectMode mode
  );
} // namespace faf::editor
