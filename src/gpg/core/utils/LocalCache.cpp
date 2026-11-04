#include "gpg/core/utils/LocalCache.h"

#include <Windows.h>
#include <ShlObj.h>

#include <cstdlib>

#include "gpg/core/utils/Logging.h"

namespace gpg
{
  const std::string& LocalCacheDirectory()
  {
    static const std::string directory = [] {
      std::string path;
      if (const char* const configured = std::getenv("FAF_SHADER_CACHE_DIR"); configured != nullptr && configured[0] != '\0') {
        path = configured;
      } else {
        char localAppData[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) {
          path = std::string(localAppData) + "\\FAForever\\ShaderCache";
        }
      }
      if (path.empty()) {
        return std::string();
      }
      if (path.back() != '\\' && path.back() != '/') {
        path += '\\';
      }
      const int result = ::SHCreateDirectoryExA(nullptr, path.c_str(), nullptr);
      if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS) {
        gpg::Warnf("cannot create the cache directory %s (error %d); nothing is cached", path.c_str(), result);
        return std::string();
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
