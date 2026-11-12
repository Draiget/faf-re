#pragma once

#include <string>

namespace moho
{
  /**
   * Inlined block from FUN_00848050 (OpenURL).
   *
   * Opens `url` with the desktop's handler when its scheme is one of DISK_GetAllowedProtocols.
   * The retail binary parsed the URL with its window library's URL class; the scheme is what it read, up to the first
   * ':'.
   */
  void OpenAllowedUrl(const std::wstring& url);
} // namespace moho
