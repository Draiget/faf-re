#include "editor/ui/EdHistory.h"

#include <map>

namespace faf::editor
{
  std::vector<EdHistoryRow> HistoryRows(
    const std::vector<std::string>& undo,
    const std::vector<std::string>& redo
  )
  {
    std::vector<EdHistoryRow> rows;
    rows.push_back({"Opened", 0, true});
    std::map<std::string, int> seen;
    const auto label = [&seen](const std::string& name) {
      const int n = ++seen[name];
      return n == 1 ? name : name + " " + std::to_string(n);
    };
    int position = 0;
    for (const std::string& name : undo) {
      rows.push_back({label(name), ++position, true});
    }
    // The redo stack's last is the next Redo: from there backwards.
    for (auto it = redo.rbegin(); it != redo.rend(); ++it) {
      rows.push_back({label(*it), ++position, false});
    }
    return rows;
  }

  int StepsTo(
    const int current,
    const int target
  )
  {
    return target - current;
  }
} // namespace faf::editor
