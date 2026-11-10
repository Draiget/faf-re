#pragma once

struct ImFont;

namespace faf::editor
{
  /** Fonts the panels use besides the default (Segoe UI): headings, and codes to read out. Null when missing. */
  inline ImFont* gBoldFont = nullptr;
  inline ImFont* gMonoFont = nullptr;
} // namespace faf::editor
