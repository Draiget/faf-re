#pragma once

#include <string>

namespace moho
{
  /**
   * Inlined block from FUN_00848050.
   *
   * Keeps the vendored wxURL headers out of translation units that include
   * reconstructed wx runtime types while preserving OpenURL's parse,
   * protocol-allow-list, and shell-launch sequence.
   */
  void OpenAllowedUrlByWx(const std::wstring& url);
} // namespace moho
