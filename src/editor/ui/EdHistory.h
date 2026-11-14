#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /** A row of the History panel: a step (or the map as opened), where it sits, and whether it is done now. */
  struct EdHistoryRow
  {
    std::string label;
    int position = 0; // 0: as opened; n: after the n-th step
    bool done = true; // false: undone, Redo brings it back
  };

  /**
   * The History panel's rows, oldest first: the map as opened, each done step (`undo`, oldest first: the document's
   * undo order), then the undone ones (`redo` as the document keeps it, the next one to redo last) in the order
   * Redo would bring them back. Numbered so that equal names stay apart ("props 2").
   */
  [[nodiscard]] std::vector<EdHistoryRow>
  HistoryRows(const std::vector<std::string>& undo, const std::vector<std::string>& redo);

  /** How to reach `target` from `current`: negative, that many Undos; positive, that many Redos. */
  [[nodiscard]] int StepsTo(int current, int target);
} // namespace faf::editor
