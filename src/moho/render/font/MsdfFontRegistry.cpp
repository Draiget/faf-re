#include "moho/render/font/MsdfFontRegistry.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gpg/core/algorithms/SHA256.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "platform/Platform.h"

namespace moho
{
  namespace
  {
    constexpr int kCookThreads = 2;
    // Part of the cache key: raise it when the cook's output changes for the same font and options.
    constexpr std::uint32_t kCookVersion = 1u;

    struct FontFile
    {
      std::string mPath;
      std::vector<std::uint8_t> mBytes;
      std::shared_ptr<const SMsdfFontAtlas> mAtlas;
      bool mQueued = false;
    };

    struct Registry
    {
      std::mutex mMutex;
      std::condition_variable mWake;
      std::vector<std::unique_ptr<FontFile>> mFiles;
      std::size_t mNamedFiles = 0u; // files whose names are in mByName
      std::map<std::string, FontFile*> mByName;
      std::deque<FontFile*> mQueue;
      std::thread mThread;
      bool mStop = false;
    };

    [[nodiscard]] Registry& GetRegistry()
    {
      static Registry registry;
      return registry;
    }

    [[nodiscard]] std::string LowerName(const char* const name)
    {
      std::string text(name != nullptr ? name : "");
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    [[nodiscard]] SMsdfCookOptions MakeCookOptions()
    {
      SMsdfCookOptions options;
      options.mThreads = kCookThreads;
      options.mCodepoints = MSDF_DefaultCodepoints();
      return options;
    }

    /** The cache file of one font: a hash of its bytes, the cook version and the settings. */
    [[nodiscard]] std::filesystem::path MakeCachePath(const FontFile& file, const SMsdfCookOptions& options)
    {
      gpg::SHA256 hash;
      hash.Update(file.mBytes.data(), file.mBytes.size());
      hash.Update(&kCookVersion, sizeof(kCookVersion));
      hash.Update(&options.mAtlasWidth, sizeof(options.mAtlasWidth));
      hash.Update(&options.mHeightStep, sizeof(options.mHeightStep));
      hash.Update(&options.mMaxAtlasHeight, sizeof(options.mMaxAtlasHeight));
      hash.Update(&options.mEmPixels, sizeof(options.mEmPixels));
      hash.Update(&options.mDistanceRange, sizeof(options.mDistanceRange));
      hash.Update(&options.mMiterLimit, sizeof(options.mMiterLimit));
      hash.Update(&options.mGlyphSpacing, sizeof(options.mGlyphSpacing));
      hash.Update(options.mCodepoints.data(), options.mCodepoints.size() * sizeof(options.mCodepoints[0]));
      const gpg::SHA256::Digest digest = hash.Snapshot();

      char name[2 * 16 + 1] = {};
      for (std::size_t i = 0; i < 16u; ++i) {
        std::snprintf(name + i * 2u, 3u, "%02x", digest[i]);
      }
      const std::filesystem::path cacheDir(USER_GetAppCacheDir().c_str());
      return cacheDir.parent_path() / "fontcache" / (std::string(name) + ".msdf");
    }

    [[nodiscard]] bool ReadCache(const std::filesystem::path& path, SMsdfFontAtlas& atlas)
    {
      std::ifstream in(path, std::ios::binary);
      if (!in) {
        return false;
      }
      const std::vector<char> bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
      return MSDF_LoadAtlas(bytes.data(), bytes.size(), atlas);
    }

    /** Through a temporary and a rename: games started together on one machine share this folder. */
    void WriteCache(const std::filesystem::path& path, const SMsdfFontAtlas& atlas)
    {
      const std::vector<std::uint8_t> packed = MSDF_SaveAtlas(atlas);
      if (packed.empty()) {
        return;
      }
      std::error_code error;
      std::filesystem::create_directories(path.parent_path(), error);
      std::filesystem::path temporary = path;
      temporary += "." + std::to_string(::GetCurrentProcessId()) + ".tmp";
      {
        std::ofstream out(temporary, std::ios::binary);
        out.write(reinterpret_cast<const char*>(packed.data()), static_cast<std::streamsize>(packed.size()));
        if (!out) {
          gpg::Warnf("MSDF: can't write %s", temporary.string().c_str());
          return;
        }
      }
      std::filesystem::rename(temporary, path, error);
      if (error) {
        std::filesystem::remove(temporary, error);
      }
    }

    [[nodiscard]] std::shared_ptr<const SMsdfFontAtlas> LoadOrCook(const FontFile& file)
    {
      const SMsdfCookOptions options = MakeCookOptions();
      const std::filesystem::path cachePath = MakeCachePath(file, options);
      auto atlas = std::make_shared<SMsdfFontAtlas>();
      if (ReadCache(cachePath, *atlas)) {
        gpg::Logf("MSDF: %s from the cache, %zu glyphs", file.mPath.c_str(), atlas->mGlyphs.size());
        return atlas;
      }

      const auto start = std::chrono::steady_clock::now();
      std::string error;
      if (!MSDF_CookFont(file.mBytes.data(), file.mBytes.size(), options, *atlas, error)) {
        gpg::Warnf("MSDF: can't cook %s: %s", file.mPath.c_str(), error.c_str());
        return nullptr;
      }
      const auto elapsed = std::chrono::steady_clock::now() - start;
      gpg::Logf(
        "MSDF: cooked %s, %zu glyphs, %u missing, %dx%d, %lld ms", file.mPath.c_str(), atlas->mGlyphs.size(), atlas->mMissing,
        atlas->mWidth, atlas->mHeight, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count())
      );
      WriteCache(cachePath, *atlas);
      return atlas;
    }

    /** Reads the names of files registered since the last call, in the order they came. */
    void ReadNewFontNames(Registry& registry)
    {
      for (; registry.mNamedFiles < registry.mFiles.size(); ++registry.mNamedFiles) {
        FontFile* const file = registry.mFiles[registry.mNamedFiles].get();
        for (const std::string& name : MSDF_ReadFontNames(file->mBytes.data(), file->mBytes.size())) {
          // The first file to answer to a name keeps it.
          registry.mByName.emplace(name, file);
        }
      }
    }

    void WorkerMain()
    {
      ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
      Registry& registry = GetRegistry();
      std::unique_lock<std::mutex> lock(registry.mMutex);
      for (;;) {
        registry.mWake.wait(lock, [&registry]() { return registry.mStop || !registry.mQueue.empty(); });
        if (registry.mStop) {
          return;
        }
        FontFile* const file = registry.mQueue.front();
        registry.mQueue.pop_front();
        lock.unlock();
        // A registered file's bytes don't change, so reading them needs no lock.
        std::shared_ptr<const SMsdfFontAtlas> atlas = LoadOrCook(*file);
        lock.lock();
        file->mAtlas = std::move(atlas);
      }
    }
  } // namespace

  void MSDF_RegisterFontFile(const char* const path, const void* const fontBytes, const std::size_t byteCount)
  {
    auto file = std::make_unique<FontFile>();
    file->mPath = path != nullptr ? path : "";
    const auto* const bytes = static_cast<const std::uint8_t*>(fontBytes);
    file->mBytes.assign(bytes, bytes + byteCount);

    Registry& registry = GetRegistry();
    const std::lock_guard<std::mutex> lock(registry.mMutex);
    registry.mFiles.push_back(std::move(file));
  }

  std::shared_ptr<const SMsdfFontAtlas> MSDF_FindAtlas(const char* const faceName)
  {
    Registry& registry = GetRegistry();
    const std::lock_guard<std::mutex> lock(registry.mMutex);
    ReadNewFontNames(registry);
    const auto known = registry.mByName.find(LowerName(faceName));
    if (known == registry.mByName.end()) {
      return nullptr;
    }
    FontFile* const file = known->second;
    if (!file->mQueued && !registry.mStop) {
      file->mQueued = true;
      registry.mQueue.push_back(file);
      if (!registry.mThread.joinable()) {
        registry.mThread = std::thread(WorkerMain);
        std::atexit(MSDF_ShutdownFontRegistry);
      }
      registry.mWake.notify_one();
    }
    return file->mAtlas;
  }

  void MSDF_ShutdownFontRegistry()
  {
    Registry& registry = GetRegistry();
    {
      const std::lock_guard<std::mutex> lock(registry.mMutex);
      registry.mStop = true;
    }
    registry.mWake.notify_one();
    if (registry.mThread.joinable()) {
      registry.mThread.join();
    }
  }
} // namespace moho
