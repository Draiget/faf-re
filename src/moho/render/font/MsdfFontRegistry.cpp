#include "moho/render/font/MsdfFontRegistry.h"

#include <algorithm>
#include <atomic>
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
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/font/MsdfFontCheck.h"
#include "moho/render/font/MsdfFontGpuCook.h"
#include "platform/Platform.h"

namespace moho
{
  bool ren_ModFonts = true;

  TConVar<bool> gTConVar_ren_ModFonts(
    "ren_ModFonts",
    "Let mods load their own fonts (1, the default). 0 refuses them, and their text draws in the default font.",
    &ren_ModFonts
  );

  namespace
  {
    constexpr int kCookThreads = 2;
    constexpr std::size_t kMaxModFontsPerSession = 16u;
    constexpr std::uintmax_t kMaxFontCacheBytes = 512u * 1024u * 1024u;
    // Starts that ended while a mod's font was cooking, before the font is taken for the cause and refused.
    constexpr int kMaxUnfinishedCooks = 2;
    // Part of the cache key: raise it when the cook's output changes for the same font and options.
    constexpr std::uint32_t kCookVersion = 2u;

    std::atomic<bool> gCancelCooks{false};

    struct FontFile
    {
      std::string mPath;
      std::vector<std::uint8_t> mBytes;
      std::shared_ptr<const SMsdfFontAtlas> mAtlas;
      bool mQueued = false;
      bool mFromMod = false;
    };

    struct Registry
    {
      std::mutex mMutex;
      std::condition_variable mWake;
      std::vector<std::unique_ptr<FontFile>> mFiles;
      std::size_t mNamedFiles = 0u; // files whose names are in mByName
      std::size_t mModFonts = 0u;
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
      if (!options.mStrikeSizes.empty()) {
        hash.Update(options.mStrikeSizes.data(), options.mStrikeSizes.size() * sizeof(options.mStrikeSizes[0]));
      }
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

    [[nodiscard]] std::uintmax_t FontCacheBytes(const std::filesystem::path& folder)
    {
      std::uintmax_t total = 0u;
      std::error_code error;
      for (const auto& entry : std::filesystem::directory_iterator(folder, error)) {
        std::error_code sizeError;
        const std::uintmax_t size = entry.file_size(sizeError);
        total += sizeError ? 0u : size;
      }
      return total;
    }

    /** A refused font is remembered beside the atlas it would have had, so it doesn't run again on each start. */
    void RememberRefusal(const std::filesystem::path& path, const std::string& reason)
    {
      std::error_code error;
      std::filesystem::create_directories(path.parent_path(), error);
      std::ofstream out(path, std::ios::binary);
      out << reason;
    }

    [[nodiscard]] std::filesystem::path RefusalPath(std::filesystem::path cachePath)
    {
      cachePath.replace_extension(".refused");
      return cachePath;
    }

    [[nodiscard]] std::filesystem::path CookingPath(std::filesystem::path cachePath)
    {
      cachePath.replace_extension(".cooking");
      return cachePath;
    }

    [[nodiscard]] bool IsProcessRunning(const unsigned long processId)
    {
      const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
      if (process == nullptr) {
        return false;
      }
      DWORD exitCode = 0;
      const bool running = ::GetExitCodeProcess(process, &exitCode) != FALSE && exitCode == STILL_ACTIVE;
      ::CloseHandle(process);
      return running;
    }

    /**
     * A mod's font cooks in this process, so a font that crashes FreeType would close the game on every start
     * with that mod. A marker beside the cache file lives while it cooks: one left by a process that is gone
     * counts as a start that ended there, and after `kMaxUnfinishedCooks` the font is refused. Another game
     * cooking the same font at the moment doesn't count. False when the font is to be refused.
     */
    [[nodiscard]] bool MarkCooking(const std::filesystem::path& markerPath)
    {
      unsigned long processId = 0u;
      int unfinished = 0;
      {
        std::ifstream in(markerPath);
        in >> processId >> unfinished;
      }
      const unsigned long self = ::GetCurrentProcessId();
      if (processId != 0u && processId != self && !IsProcessRunning(processId)) {
        ++unfinished;
      }
      if (unfinished >= kMaxUnfinishedCooks) {
        return false;
      }
      std::error_code error;
      std::filesystem::create_directories(markerPath.parent_path(), error);
      std::ofstream out(markerPath);
      out << self << ' ' << unfinished;
      return true;
    }

    void ClearCooking(const std::filesystem::path& markerPath)
    {
      std::error_code error;
      std::filesystem::remove(markerPath, error);
    }

    /**
     * Game fonts and mod fonts take the same steps; a mod's font has its own options, with limits on work,
     * memory and time, its cache file checked against them, and its refusals remembered.
     */
    [[nodiscard]] std::shared_ptr<const SMsdfFontAtlas> LoadOrCook(const FontFile& file)
    {
      SMsdfCookOptions options = file.mFromMod ? MSDF_MakeModCookOptions(kCookThreads) : MSDF_MakeCookOptions(kCookThreads);
      options.mCancel = &gCancelCooks;
      const char* const kind = file.mFromMod ? "mod font " : "";
      const char* const path = file.mPath.c_str();
      const std::filesystem::path cachePath = MakeCachePath(file, options);
      auto atlas = std::make_shared<SMsdfFontAtlas>();
      const bool useGpu = MSDF_IsGpuCookAvailable();
      const bool compare = useGpu && ren_GpuFontCookCompare;
      std::string error;
      if (!compare && ReadCache(cachePath, *atlas) && (!file.mFromMod || MSDF_CheckCookedAtlas(*atlas, options, error))) {
        gpg::Logf("MSDF: %s%s from the cache, %zu glyphs", kind, path, atlas->mGlyphs.size());
        return atlas;
      }

      const std::filesystem::path markerPath = CookingPath(cachePath);
      if (file.mFromMod) {
        if (FontCacheBytes(cachePath.parent_path()) > kMaxFontCacheBytes) {
          gpg::Warnf("MSDF: mod font %s not cooked: the font cache is full", path);
          return nullptr;
        }
        if (!MarkCooking(markerPath)) {
          error = "the game closed while cooking it, more than once";
          gpg::Warnf("MSDF: mod font %s refused: %s", path, error.c_str());
          RememberRefusal(RefusalPath(cachePath), error);
          ClearCooking(markerPath);
          return nullptr;
        }
      }
      const auto finishWithout = [&](const MsdfCookPlan& plan) -> std::shared_ptr<const SMsdfFontAtlas> {
        ClearCooking(markerPath);
        if (plan.TimedOut()) {
          gpg::Warnf("MSDF: %s%s not cooked this time: %s", kind, path, error.c_str());
        } else if (file.mFromMod) {
          gpg::Warnf("MSDF: mod font %s refused: %s", path, error.c_str());
          RememberRefusal(RefusalPath(cachePath), error);
        } else {
          gpg::Warnf("MSDF: can't cook %s: %s", path, error.c_str());
        }
        return nullptr;
      };

      const auto start = std::chrono::steady_clock::now();
      MsdfCookPlan plan;
      if (!plan.Prepare(file.mBytes.data(), file.mBytes.size(), options, error)) {
        return finishWithout(plan);
      }
      bool cookedOnGpu = false;
      if (useGpu) {
        cookedOnGpu = MSDF_CookOnGpu(plan, error);
        if (!cookedOnGpu) {
          gpg::Warnf("MSDF: %s%s cooks on the CPU instead of the GPU: %s", kind, path, error.c_str());
        }
      }
      if (!cookedOnGpu && !plan.GenerateOnCpu(error)) {
        return finishWithout(plan);
      }
      plan.Finish(*atlas);
      const auto elapsed = std::chrono::steady_clock::now() - start;
      if (compare && cookedOnGpu) {
        SMsdfFontAtlas onCpu;
        const auto cpuStart = std::chrono::steady_clock::now();
        if (MSDF_CookFont(file.mBytes.data(), file.mBytes.size(), options, onCpu, error)) {
          const auto cpuElapsed = std::chrono::steady_clock::now() - cpuStart;
          MSDF_LogAtlasComparison(
            path, *atlas, onCpu, std::chrono::duration<double, std::milli>(elapsed).count(),
            std::chrono::duration<double, std::milli>(cpuElapsed).count()
          );
        }
      }
      ClearCooking(markerPath);
      gpg::Logf(
        "MSDF: cooked %s%s on the %s, %zu glyphs, %u missing, %dx%d, %lld ms", kind, path, cookedOnGpu ? "GPU" : "CPU", atlas->mGlyphs.size(),
        atlas->mMissing, atlas->mWidth, atlas->mHeight,
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count())
      );
      WriteCache(cachePath, *atlas);
      return atlas;
    }

    void WorkerMain();

    /** Reads the names of files registered since the last call, in the order they came. */
    void ReadNewFontNames(Registry& registry)
    {
      for (; registry.mNamedFiles < registry.mFiles.size(); ++registry.mNamedFiles) {
        FontFile* const file = registry.mFiles[registry.mNamedFiles].get();
        if (file->mFromMod) {
          continue; // a mod's font answers to its private name alone, and FreeType never sees it here
        }
        for (const std::string& name : MSDF_ReadFontNames(file->mBytes.data(), file->mBytes.size())) {
          // The first file to answer to a name keeps it.
          registry.mByName.emplace(name, file);
        }
      }
    }

    /** With the registry's lock held. */
    void EnqueueLocked(Registry& registry, FontFile* const file)
    {
      if (file->mQueued || registry.mStop) {
        return;
      }
      file->mQueued = true;
      registry.mQueue.push_back(file);
      if (!registry.mThread.joinable()) {
        registry.mThread = std::thread(WorkerMain);
        std::atexit(MSDF_ShutdownFontRegistry);
      }
      registry.mWake.notify_one();
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

  std::string MSDF_RegisterModFont(const char* const path, const void* const fontBytes, const std::size_t byteCount)
  {
    const char* const shownPath = path != nullptr ? path : "";
    if (!ren_ModFonts) {
      gpg::Warnf("MSDF: mod font %s refused: ren_ModFonts is off", shownPath);
      return {};
    }
    std::string reason;
    if (!MSDF_CheckFontStructure(fontBytes, byteCount, reason)) {
      gpg::Warnf("MSDF: mod font %s refused: %s", shownPath, reason.c_str());
      return {};
    }

    gpg::SHA256 hash;
    hash.Update(fontBytes, byteCount);
    const gpg::SHA256::Digest digest = hash.Snapshot();
    std::string family = "mod:";
    for (std::size_t i = 0; i < 16u; ++i) {
      char pair[3] = {};
      std::snprintf(pair, sizeof(pair), "%02x", digest[i]);
      family += pair;
    }

    auto file = std::make_unique<FontFile>();
    file->mPath = shownPath;
    const auto* const bytes = static_cast<const std::uint8_t*>(fontBytes);
    file->mBytes.assign(bytes, bytes + byteCount);
    file->mFromMod = true;

    // A font refused on an earlier start or a moment ago answers nil, not a name that never draws.
    std::error_code error;
    if (std::filesystem::exists(RefusalPath(MakeCachePath(*file, MSDF_MakeModCookOptions(kCookThreads))), error)) {
      gpg::Warnf("MSDF: mod font %s stays refused", shownPath);
      return {};
    }

    Registry& registry = GetRegistry();
    const std::lock_guard<std::mutex> lock(registry.mMutex);
    if (registry.mByName.count(family) != 0u) {
      return family;
    }
    if (registry.mModFonts >= kMaxModFontsPerSession) {
      gpg::Warnf("MSDF: mod font %s refused: over the limit of %zu fonts", shownPath, kMaxModFontsPerSession);
      return {};
    }
    ++registry.mModFonts;
    FontFile* const added = file.get();
    registry.mByName.emplace(family, added);
    registry.mFiles.push_back(std::move(file));
    // Cooking starts now, so text is ready sooner than if the first draw had to ask.
    EnqueueLocked(registry, added);
    return family;
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
    if (file->mFromMod && !ren_ModFonts) {
      return nullptr;
    }
    EnqueueLocked(registry, file);
    return file->mAtlas;
  }

  void MSDF_ShutdownFontRegistry()
  {
    gCancelCooks.store(true, std::memory_order_relaxed);
    MSDF_CancelGpuCook();
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
