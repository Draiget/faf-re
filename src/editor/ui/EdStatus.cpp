#include "editor/ui/EdStatus.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <utility>

namespace faf::editor
{
  namespace
  {
    struct StatusState
    {
      std::string text;
      double time = -1.0;
    };

    StatusState& State()
    {
      static StatusState state;
      return state;
    }
  } // namespace

  void PostStatusMessageAt(
    std::string text,
    const double time
  )
  {
    State().text = std::move(text);
    State().time = time;
  }

  void PostStatusMessage(
    std::string text
  )
  {
    PostStatusMessageAt(std::move(text), StatusClock());
  }

  double StatusClock()
  {
    static const auto start = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  }

  const std::string& StatusMessage()
  {
    return State().text;
  }

  double StatusMessageTime()
  {
    return State().time;
  }

  std::string AgoText(
    const double seconds
  )
  {
    if (seconds < 5.0) {
      return "now";
    }
    if (seconds < 60.0) {
      return std::to_string(static_cast<int>(seconds)) + " s ago";
    }
    if (seconds < 3600.0) {
      return std::to_string(static_cast<int>(seconds / 60.0)) + " min ago";
    }
    return std::to_string(static_cast<int>(seconds / 3600.0)) + " h ago";
  }

  std::string SelectionCountText(
    std::string_view selectionText
  )
  {
    if (selectionText.empty() || std::isdigit(static_cast<unsigned char>(selectionText.front())) == 0) {
      return {};
    }
    return std::string(selectionText.substr(0, selectionText.find(':')));
  }

  std::vector<std::size_t> FitStatusItems(
    const std::vector<float>& widths,
    const std::vector<int>& priorities,
    const float width,
    const float gap
  )
  {
    std::vector<std::size_t> kept;
    for (std::size_t i = 0; i < widths.size(); ++i) {
      kept.push_back(i);
    }
    const auto total = [&] {
      float sum = 0.0f;
      for (const std::size_t i : kept) {
        sum += widths[i];
      }
      return sum + gap * static_cast<float>(kept.empty() ? 0 : kept.size() - 1);
    };
    while (total() > width) {
      // The highest priority number, the last of them.
      std::size_t drop = kept.size();
      for (std::size_t k = 0; k < kept.size(); ++k) {
        const int p = k < kept.size() && kept[k] < priorities.size() ? priorities[kept[k]] : 0;
        if (p > 0 && (drop == kept.size() || p >= priorities[kept[drop]])) {
          drop = k;
        }
      }
      if (drop == kept.size()) {
        break; // only the ones that always stay
      }
      kept.erase(kept.begin() + static_cast<std::ptrdiff_t>(drop));
    }
    return kept;
  }
} // namespace faf::editor
