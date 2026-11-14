#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /**
   * The status bar's last message (design §3: "Saved", the autosave's time, a workspace's keys written): anything
   * posts one; the bar shows it with how long ago, until the next.
   */
  void PostStatusMessage(std::string text);
  [[nodiscard]] const std::string& StatusMessage();
  /** Seconds since the first call: the clock the messages are timed by. */
  [[nodiscard]] double StatusClock();
  /** When it was posted, by StatusClock; negative when there is none. */
  [[nodiscard]] double StatusMessageTime();
  /** Posts with a time given (tests). */
  void PostStatusMessageAt(std::string text, double time);

  /** How long ago, short: "now" under 5 s, "12 s ago", "3 min ago", "2 h ago". */
  [[nodiscard]] std::string AgoText(double seconds);

  /** The count from the scene's selection text ("3 markers: a, ..." gives "3 markers"); empty when nothing is. */
  [[nodiscard]] std::string SelectionCountText(std::string_view selectionText);

  /**
   * Which of the bar's items fit in `width`: all when they do; else the ones with the highest `priority` number go
   * first (the last of them first), until the rest with `gap` between them fit. Priority 0 always stays. Returns the
   * kept items' indices in their order.
   */
  [[nodiscard]] std::vector<std::size_t>
  FitStatusItems(const std::vector<float>& widths, const std::vector<int>& priorities, float width, float gap);
} // namespace faf::editor
