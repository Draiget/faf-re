#pragma once

namespace faf::editor
{
  /** Whether the panels' help shows in full (View > Full help text), or as one line with the rest on hover. */
  bool& FullHelpText();

  /**
   * A panel's help: a small "?" and the text's first sentence on one dimmed line, cut to the panel's width, with the
   * whole text in a tooltip when hovered; the whole text wrapped when FullHelpText is on.
   */
  void HelpNote(const char* text);
} // namespace faf::editor
