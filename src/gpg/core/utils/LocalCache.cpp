#include "gpg/core/utils/LocalCache.h"

#include <Windows.h>
#include <ShlObj.h>

#include <cstdlib>
#include <filesystem>
#include <system_error>

#include "gpg/core/utils/Logging.h"

namespace gpg
{
  const std::string& LocalCacheDirectory()
  {
    static const std::string directory = [] {
      // As StartupHelpers' paths: the shell folder (the XDG one on Linux, platform/posix), then
      // std::filesystem, so the headless Linux build keeps the same caches.
      std::filesystem::path folder;
      if (const char* const configured = std::getenv("FAF_SHADER_CACHE_DIR"); configured != nullptr && configured[0] != '\0') {
        folder = configured;
      } else {
        wchar_t localAppData[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
          folder = std::filesystem::path(localAppData) / "FAForever" / "ShaderCache";
        }
      }
      if (folder.empty()) {
        return std::string();
      }
      // The caches open their files through narrow names. A folder the system code page can't hold
      // has none, and asking for one throws: those players go without the caches.
      std::string path;
      try {
        path = folder.string();
      } catch (const std::system_error& conversion) {
        gpg::Warnf("the cache directory's name doesn't fit the system code page (%s); nothing is cached", conversion.what());
        return std::string();
      }
      std::error_code error;
      std::filesystem::create_directories(folder, error);
      if (error) {
        gpg::Warnf("cannot create the cache directory %s (%s); nothing is cached", path.c_str(), error.message().c_str());
        return std::string();
      }
      if (path.back() != '\\' && path.back() != '/') {
        path += static_cast<char>(std::filesystem::path::preferred_separator);
      }
      return path;
    }();
    return directory;
  }

  std::uint64_t ExecutableIdentity()
  {
    static const std::uint64_t identity = [] {
      std::uint64_t hash = 0xCBF29CE484222325ULL; // FNV-1a, 64-bit
      const auto add = [&hash](const void* const data, const std::size_t bytes) {
        for (std::size_t index = 0U; index < bytes; ++index) {
          hash ^= static_cast<const unsigned char*>(data)[index];
          hash *= 0x100000001B3ULL;
        }
      };
      wchar_t path[MAX_PATH]{};
      WIN32_FILE_ATTRIBUTE_DATA data{};
      const DWORD length = ::GetModuleFileNameW(nullptr, path, MAX_PATH);
      if (length != 0U && length < MAX_PATH && ::GetFileAttributesExW(path, GetFileExInfoStandard, &data)) {
        add(&data.nFileSizeHigh, sizeof(data.nFileSizeHigh));
        add(&data.nFileSizeLow, sizeof(data.nFileSizeLow));
        add(&data.ftLastWriteTime, sizeof(data.ftLastWriteTime));
      }
      return hash;
    }();
    return identity;
  }
} // namespace gpg
