// Engine addition, not in the shipped binary: see EmbeddedFiles.h (issue #315).

#include "EmbeddedFiles.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include <windows.h>

#include <zstd.h>
#endif

#include "gpg/core/utils/Logging.h"

namespace gpg
{
#if !defined(_WIN32)
  // Linux (the dedicated server and headless): an executable there carries no resources, so nothing
  // is embedded and the loose files are used, as the header says for an exe without the resource.
  std::wstring EmbeddedDxcDirectory()
  {
    return {};
  }
#else
  namespace
  {
    /** A resource of type RCDATA in the executable, or an empty view. */
    [[nodiscard]] std::string_view FindEmbedded(const wchar_t* const name)
    {
      HMODULE const module = ::GetModuleHandleW(nullptr);
      HRSRC const found = ::FindResourceW(module, name, MAKEINTRESOURCEW(10)); // RT_RCDATA
      if (found == nullptr) {
        return {};
      }
      HGLOBAL const loaded = ::LoadResource(module, found);
      const void* const bytes = loaded != nullptr ? ::LockResource(loaded) : nullptr;
      return bytes != nullptr ? std::string_view(static_cast<const char*>(bytes), ::SizeofResource(module, found)) : std::string_view{};
    }

    [[nodiscard]] std::uint64_t Fnv1a64(const std::string_view bytes) noexcept
    {
      std::uint64_t hash = 0xCBF29CE484222325ULL;
      for (const char byte : bytes) {
        hash = (hash ^ static_cast<std::uint8_t>(byte)) * 0x100000001B3ULL;
      }
      return hash;
    }

    /** %LOCALAPPDATA%\FAForever\faf-re\<name>-<hash of bytes>\, created; empty on failure. */
    [[nodiscard]] std::wstring CopyFolder(const wchar_t* const name, const std::string_view bytes)
    {
      wchar_t localAppData[MAX_PATH]{};
      const DWORD length = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
      if (length == 0U || length >= MAX_PATH) {
        return {};
      }
      std::wstring folder = std::wstring(localAppData) + L"\\FAForever";
      ::CreateDirectoryW(folder.c_str(), nullptr);
      folder += L"\\faf-re";
      ::CreateDirectoryW(folder.c_str(), nullptr);
      wchar_t leaf[64]{};
      std::swprintf(leaf, 64, L"\\%ls-%016llx", name, static_cast<unsigned long long>(Fnv1a64(bytes)));
      folder += leaf;
      if (!::CreateDirectoryW(folder.c_str(), nullptr) && ::GetLastError() != ERROR_ALREADY_EXISTS) {
        return {};
      }
      return folder + L'\\';
    }

    [[nodiscard]] bool FileExists(const std::wstring& path)
    {
      const DWORD attributes = ::GetFileAttributesW(path.c_str());
      return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U;
    }

    /**
     * Writes `bytes` to `path` through a file of this process's own, so a game starting at the
     * same time never sees half a file. A copy another game wrote first is kept.
     */
    [[nodiscard]] bool WriteFileOnce(const std::wstring& path, const std::string_view bytes)
    {
      if (FileExists(path)) {
        return true;
      }
      const std::wstring temporary = path + L"." + std::to_wstring(::GetCurrentProcessId()) + L".tmp";
      HANDLE const file = ::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return false;
      }
      DWORD written = 0U;
      const bool ok = ::WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
      ::CloseHandle(file);
      if (ok && ::MoveFileExW(temporary.c_str(), path.c_str(), 0U)) {
        return true;
      }
      ::DeleteFileW(temporary.c_str());
      return FileExists(path); // another game wrote it first
    }

    [[nodiscard]] bool Decompress(const std::string_view packed, std::vector<char>& outBytes)
    {
      ZSTD_DStream* const stream = ZSTD_createDStream();
      if (stream == nullptr) {
        return false;
      }
      ZSTD_inBuffer input{packed.data(), packed.size(), 0U};
      std::vector<char> chunk(ZSTD_DStreamOutSize());
      bool ok = true;
      while (ok && input.pos < input.size) {
        ZSTD_outBuffer output{chunk.data(), chunk.size(), 0U};
        const std::size_t result = ZSTD_decompressStream(stream, &output, &input);
        ok = ZSTD_isError(result) == 0U;
        outBytes.insert(outBytes.end(), chunk.data(), chunk.data() + output.pos);
      }
      ZSTD_freeDStream(stream);
      return ok;
    }

    /** Each regular file of a tar archive: its name and bytes. */
    template <typename Visit> [[nodiscard]] bool ForEachTarFile(const std::vector<char>& tar, Visit&& visit)
    {
      constexpr std::size_t kBlock = 512U;
      for (std::size_t at = 0U; at + kBlock <= tar.size();) {
        const char* const header = tar.data() + at;
        if (header[0] == '\0') {
          return true; // the end blocks
        }
        const std::string name(header, strnlen(header, 100U));
        const std::size_t size = std::strtoull(std::string(header + 124, 12U).c_str(), nullptr, 8);
        const char type = header[156];
        at += kBlock;
        if (at + size > tar.size()) {
          return false;
        }
        if ((type == '0' || type == '\0') && !visit(name, std::string_view(tar.data() + at, size))) {
          return false;
        }
        at += (size + kBlock - 1U) / kBlock * kBlock;
      }
      return true;
    }
  } // namespace

  namespace
  {
    /**
     * The files of the zstd-compressed tar `resource`, unpacked once into their folder (see
     * CopyFolder); the folder with a trailing backslash, or empty. A marker written last tells a
     * complete folder from one a crashed game left half done.
     */
    [[nodiscard]] std::wstring UnpackOnce(const wchar_t* const resource, const wchar_t* const name)
    {
      const std::string_view packed = FindEmbedded(resource);
      if (packed.empty()) {
        return {};
      }
      const std::wstring folder = CopyFolder(name, packed);
      if (folder.empty()) {
        gpg::Warnf("embedded files: no folder for %ls under %%LOCALAPPDATA%%\\FAForever\\faf-re", name);
        return {};
      }
      const std::wstring marker = folder + L".unpacked";
      if (FileExists(marker)) {
        return folder;
      }
      std::vector<char> tar;
      const bool ok = Decompress(packed, tar) && ForEachTarFile(tar, [&folder](const std::string& path, const std::string_view bytes) {
        std::wstring target = folder;
        for (const char c : path) {
          if (c == '/') {
            ::CreateDirectoryW(target.c_str(), nullptr);
            target += L'\\';
          } else {
            target += static_cast<wchar_t>(static_cast<unsigned char>(c));
          }
        }
        return WriteFileOnce(target, bytes);
      }) && WriteFileOnce(marker, {});
      if (!ok) {
        gpg::Warnf("embedded files: could not unpack %ls into %%LOCALAPPDATA%%\\FAForever\\faf-re", name);
        return {};
      }
      gpg::Logf("embedded files: unpacked %ls (%zu bytes)", name, tar.size());
      return folder;
    }
  } // namespace

  std::wstring EmbeddedDxcDirectory()
  {
    static const std::wstring directory = UnpackOnce(L"FAF_DXC", L"dxc");
    return directory;
  }
#endif
} // namespace gpg
