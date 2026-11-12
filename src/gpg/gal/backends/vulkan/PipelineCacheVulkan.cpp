// Engine addition, not in the shipped binary (see PipelineCacheVulkan.h).

#include "gpg/gal/backends/vulkan/PipelineCacheVulkan.h"

#include <Windows.h> // GetCommandLineW (the POSIX shim provides it too)

#include <atomic>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/PipelineDiskCache.h"

namespace gpg::gal::vulkan
{
  namespace
  {
    constexpr const char* kFileName = "pipelines-vulkan.bin";

    // As the Direct3D 12 cache: each save numbers its snapshot, and a write older than the one on disk is dropped.
    std::mutex gWriteMutex;
    std::uint64_t gWrittenSnapshot = 0U; // under gWriteMutex
    std::atomic<std::uint64_t> gNextSnapshot{0U};

    [[nodiscard]] bool StartupFlagDisables()
    {
      const wchar_t* const commandLine = ::GetCommandLineW();
      return commandLine != nullptr && std::wcsstr(commandLine, L"/nopipelinecache") != nullptr;
    }

    [[nodiscard]] std::vector<std::uint8_t> ReadFileBytes(
      const std::string& path
    )
    {
      std::vector<std::uint8_t> bytes;
      std::error_code error;
      const std::uintmax_t size = std::filesystem::file_size(path, error);
      if (error || size == 0U || size > (512ULL << 20U)) {
        return bytes;
      }
      std::ifstream file(path, std::ios::binary);
      bytes.resize(static_cast<std::size_t>(size));
      if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        bytes.clear();
      }
      return bytes;
    }

    /** Writes through a temporary file renamed over the old one, so a crash mid-write leaves the old file. */
    void WriteFileBytes(
      const std::string& path,
      const std::vector<std::uint8_t>& bytes,
      const std::uint64_t snapshot
    ) noexcept
    {
      try {
        const std::lock_guard<std::mutex> lock(gWriteMutex);
        if (snapshot <= gWrittenSnapshot) {
          return; // a newer cache is on disk already
        }
        gWrittenSnapshot = snapshot;
        // Unique across game processes writing the same folder: the thread and the time.
        const auto unique = std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
          static_cast<std::size_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        const std::string temporary = path + "." + std::to_string(unique) + ".tmp";
        bool ok = false;
        {
          std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
          ok = file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())) &&
            file.flush();
        }
        std::error_code error;
        if (ok) {
          std::filesystem::rename(temporary, path, error);
        }
        if (!ok || error) {
          std::filesystem::remove(temporary, error);
        }
      } catch (...) {
        // Out of memory or a file system error: this save is skipped, the next one tries again.
      }
    }

    /** Temporary files a process left when it ended mid-write, untouched for ten minutes (another may be writing). */
    void RemoveStaleTemporaries(
      const std::string& path
    )
    {
      const std::filesystem::path file(path);
      const std::string prefix = file.filename().string() + ".";
      std::error_code error;
      const auto now = std::filesystem::file_time_type::clock::now();
      for (std::filesystem::directory_iterator entry(file.parent_path(), error), end; !error && entry != end;
           entry.increment(error)) {
        const std::string name = entry->path().filename().string();
        if (
          name.size() <= prefix.size() + 4U || name.compare(0U, prefix.size(), prefix) != 0 ||
          name.compare(name.size() - 4U, 4U, ".tmp") != 0
        ) {
          continue;
        }
        std::error_code timeError;
        const auto written = std::filesystem::last_write_time(entry->path(), timeError);
        if (!timeError && now - written > std::chrono::minutes(10)) {
          std::filesystem::remove(entry->path(), timeError);
        }
      }
    }
  } // namespace

  std::vector<std::uint8_t> PipelineCacheFile::Open(
    const VkPhysicalDeviceProperties& properties,
    const std::string& directory
  )
  {
    mPath.clear();
    mSavedSize = 0U;
    mLastSize = 0U;
    if (!gPipelineDiskCache || StartupFlagDisables()) {
      gPipelineDiskCache = false;
      gpg::Logf("Vulkan: pipeline cache off");
      return {};
    }
    if (directory.empty()) {
      return {};
    }
    mPath = directory + kFileName;
    RemoveStaleTemporaries(mPath);
    std::vector<std::uint8_t> bytes = ReadFileBytes(mPath);
    if (bytes.empty()) {
      gpg::Logf("Vulkan: pipeline cache %s (new)", mPath.c_str());
      return bytes;
    }
    // VkPipelineCacheHeaderVersionOne: some drivers trust the data they are handed, so a file from another device or
    // driver is dropped here.
    VkPipelineCacheHeaderVersionOne header{};
    bool usable = bytes.size() >= sizeof(header);
    if (usable) {
      std::memcpy(&header, bytes.data(), sizeof(header));
      usable = header.headerSize >= sizeof(header) && header.headerSize <= bytes.size() &&
        header.headerVersion == VK_PIPELINE_CACHE_HEADER_VERSION_ONE && header.vendorID == properties.vendorID &&
        header.deviceID == properties.deviceID &&
        std::memcmp(header.pipelineCacheUUID, properties.pipelineCacheUUID, VK_UUID_SIZE) == 0;
    }
    if (!usable) {
      gpg::Logf("Vulkan: pipeline cache %s is from another device or driver; starting empty", mPath.c_str());
      bytes.clear();
      return bytes;
    }
    mSavedSize = bytes.size();
    mLastSize = bytes.size();
    gpg::Logf("Vulkan: pipeline cache %s (%zu KB)", mPath.c_str(), bytes.size() / 1024U);
    return bytes;
  }

  void PipelineCacheFile::OnFrame(
    const VkDevice device,
    const VkPipelineCache cache
  )
  {
    if (mPath.empty() || cache == VK_NULL_HANDLE || !gPipelineDiskCache) {
      return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - mLastCheck < kCheckEvery) {
      return;
    }
    mLastCheck = now;
    std::size_t size = 0U;
    if (Vk().vkGetPipelineCacheData(device, cache, &size, nullptr) != VK_SUCCESS) {
      return;
    }
    if (size != mLastSize) {
      mLastSize = size;
      mLastGrowth = now;
      return;
    }
    if (size != mSavedSize && now - mLastGrowth >= kQuietSeconds) {
      Save(device, cache, true);
    }
  }

  void PipelineCacheFile::Close(
    const VkDevice device,
    const VkPipelineCache cache
  ) noexcept
  {
    if (mPath.empty() || cache == VK_NULL_HANDLE || !gPipelineDiskCache) {
      return;
    }
    std::size_t size = 0U;
    if (Vk().vkGetPipelineCacheData(device, cache, &size, nullptr) == VK_SUCCESS && size != mSavedSize) {
      Save(device, cache, false); // the process may exit right after; write before returning
    }
  }

  void PipelineCacheFile::Save(
    const VkDevice device,
    const VkPipelineCache cache,
    const bool inBackground
  ) noexcept
  {
    try {
      // Pipeline workers add to the cache meanwhile: VK_INCOMPLETE means it grew between the size and the copy.
      for (int attempt = 0; attempt < 3; ++attempt) {
        std::size_t size = 0U;
        if (Vk().vkGetPipelineCacheData(device, cache, &size, nullptr) != VK_SUCCESS || size == 0U) {
          return;
        }
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(size);
        const VkResult result = Vk().vkGetPipelineCacheData(device, cache, &size, bytes->data());
        if (result == VK_INCOMPLETE) {
          continue;
        }
        if (result != VK_SUCCESS) {
          return;
        }
        bytes->resize(size);
        mSavedSize = size;
        mLastSize = size;
        const std::uint64_t snapshot = ++gNextSnapshot;
        if (inBackground) {
          std::thread([path = mPath, bytes, snapshot] {
            WriteFileBytes(path, *bytes, snapshot);
          }).detach();
        } else {
          WriteFileBytes(mPath, *bytes, snapshot);
        }
        return;
      }
    } catch (...) {
      // Out of memory or no thread for the write: skipped; the next quiet frame or the close saves again.
    }
  }
} // namespace gpg::gal::vulkan
