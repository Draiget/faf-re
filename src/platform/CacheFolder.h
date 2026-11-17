#pragma once

// Engine addition (macOS client, issue #269): the folder the engine's caches go under. Windows and
// Linux keep them below the local application data folder, as Forged Alliance always has
// (SHGetFolderPathW(CSIDL_LOCAL_APPDATA); Linux's is $XDG_DATA_HOME, platform/posix/Win32Shim.cpp).
// macOS keeps caches in ~/Library/Caches, apart from the user data in ~/Library/Application Support,
// so the system and backup tools can tell them apart.

#include "PlatformDefines.h"

#include <cstdlib>
#include <filesystem>
#include <system_error>

#include <Windows.h>
#include <ShlObj.h>

namespace platform
{
  /// The cache root (the caches add their own subfolders); empty when the system names none.
  [[nodiscard]] inline std::filesystem::path CacheFolder()
  {
#if FAFRE_PLATFORM_MACOS // ~/Library/Caches
    const char* const home = std::getenv("HOME");
    if (home == nullptr || home[0] != '/') {
      return {};
    }
    std::filesystem::path folder = std::filesystem::path(home) / "Library" / "Caches";
    std::error_code created;
    std::filesystem::create_directories(folder, created);
    return folder;
#else
    wchar_t localAppData[MAX_PATH]{};
    if (FAILED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
      return {};
    }
    return std::filesystem::path(localAppData);
#endif
  }
} // namespace platform
