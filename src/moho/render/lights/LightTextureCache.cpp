#include "moho/render/lights/LightTextureCache.h"

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace moho::lights
{
  namespace
  {
    constexpr std::size_t kTextureCacheMax = 512;
    std::unordered_map<std::string, TexEntry> gTextures;
    int gLogBudget = 400;
    // What the textures read on this thread since the last TrimTextureCache (once a frame) cost (the synchronous path).
    double gFrameLoadMs = 0.0;
    int gFrameLoads = 0;
    int gHitchLogBudget = 100;
    // What the worker finished since the last TrimTextureCache.
    double gFrameWorkerMs = 0.0;
    int gFrameWorkerLoads = 0;
    int gWorkerLogBudget = 100;

    // FAF_LIGHT_TEXTURES_SYNC=1 reads the textures on the render thread again (A/B tests, bisecting).
    [[nodiscard]] bool WorkerWanted()
    {
      static const bool wanted = [] {
        std::size_t length = 0U;
        char value[8] = {};
        return !(
          ::getenv_s(&length, value, sizeof(value), "FAF_LIGHT_TEXTURES_SYNC") == 0 && length != 0U && value[0] == '1'
        );
      }();
      return wanted;
    }

    // Reads and summarises the file behind a virtual path. Thread safe: the file system lookups are the ones the effect
    // compiles run on their worker threads, the decode is a pure function.
    TexEntry ReadTexture(
      const std::string& path,
      std::size_t& fileSize,
      bool& decoded
    )
    {
      TexEntry entry;
      // The engine's own two steps (CD3DEffect::InitEffectFromFile does the same): the virtual path is resolved to the
      // file or archive entry first, the resolved name is what DISK_MemoryMapFile maps.
      gpg::MemBuffer<const char> file;
      if (
        FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
        waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr
      ) {
        fa::string resolved{};
        (void)waitHandleSet->mHandle->FindFile(&resolved, path.c_str(), nullptr);
        if (!resolved.empty()) {
          file = DISK_MemoryMapFile(resolved.c_str());
        }
      }
      fileSize = file.Size();
      decoded = false;
      if (fileSize > 0 && fileSize <= (8u << 20)) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(file.GetPtr(0U, 0U));
        decoded = bytes != nullptr && DecodeDds(bytes, fileSize, 256, entry.image);
        entry.ok = decoded;
        if (entry.ok) {
          entry.colour = Summarise(entry.image);
          entry.ok = entry.colour.valid;
        }
      }
      return entry;
    }

    void LogTexture(
      const std::string& path,
      const TexEntry& entry,
      const std::size_t fileSize,
      const bool decoded
    )
    {
      if (gLogBudget <= 0) {
        return;
      }
      --gLogBudget;
      if (entry.ok) {
        gpg::Logf(
          "DynLights: texture %s %ux%u hue=(%.2f %.2f %.2f) brightness=%.3f peak=%.2f alpha=%.2f",
          path.c_str(),
          entry.image.width,
          entry.image.height,
          entry.colour.hue[0],
          entry.colour.hue[1],
          entry.colour.hue[2],
          entry.colour.brightness,
          entry.colour.peak,
          entry.colour.alpha
        );
      } else {
        gpg::Logf(
          "DynLights: texture %s could not be read (file %u bytes, decoded %d)",
          path.c_str(),
          static_cast<unsigned>(fileSize),
          decoded ? 1 : 0
        );
      }
    }

    // The textures of the first sight of a unit or an effect are read and decoded here, one at a time, off the render
    // thread (a file read and a DXT decode were up to 14 ms of a frame). The render thread asks (FindTexture), uses its
    // neutral answer while the texture is pending, and takes the finished ones into the cache once a frame
    // (TrimTextureCache), where no feed holds a pointer into it.
    struct Finished
    {
      std::string path;
      TexEntry entry;
      std::size_t fileSize = 0U;
      bool decoded = false;
      double milliseconds = 0.0;
    };

    struct Worker
    {
      std::mutex mutex;
      std::condition_variable wake;
      std::deque<std::string> queue;
      std::vector<Finished> done;
      bool stop = false;
      std::thread thread;

      ~Worker()
      {
        {
          const std::lock_guard<std::mutex> lock(mutex);
          stop = true;
        }
        wake.notify_all();
        if (thread.joinable()) {
          thread.join();
        }
      }

      void Run()
      {
        for (;;) {
          std::string path;
          {
            std::unique_lock<std::mutex> lock(mutex);
            wake.wait(lock, [this] {
              return stop || !queue.empty();
            });
            if (stop) {
              return;
            }
            path = std::move(queue.front());
            queue.pop_front();
          }
          const auto started = std::chrono::steady_clock::now();
          Finished finished;
          try {
            finished.entry = ReadTexture(path, finished.fileSize, finished.decoded);
          } catch (...) {
            finished.entry = TexEntry{};
          }
          finished.milliseconds =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
          finished.path = std::move(path);
          const std::lock_guard<std::mutex> lock(mutex);
          done.push_back(std::move(finished));
        }
      }
    };

    Worker gWorker;
    std::unordered_set<std::string> gPending; // render thread only: asked for, not taken into the cache yet

    void Request(
      const std::string& path
    )
    {
      FILE_EnsureWaitHandleSet(); // the lazy part of the lookup stays on the render thread
      if (!gPending.insert(path).second) {
        return;
      }
      {
        const std::lock_guard<std::mutex> lock(gWorker.mutex);
        gWorker.queue.push_back(path);
        if (!gWorker.thread.joinable()) {
          gWorker.thread = std::thread([] {
            gWorker.Run();
          });
        }
      }
      gWorker.wake.notify_one();
    }
  } // namespace

  TextureState FindTexture(
    const std::string& path,
    const TexEntry*& out
  )
  {
    out = nullptr;
    if (path.empty()) {
      return TextureState::Failed;
    }
    const auto found = gTextures.find(path);
    if (found != gTextures.end()) {
      if (!found->second.ok) {
        return TextureState::Failed;
      }
      out = &found->second;
      return TextureState::Ready;
    }
    if (WorkerWanted()) {
      Request(path);
      return TextureState::Pending;
    }
    // Never cleared here: the callers hold the pointers of earlier calls (an albedo while the specular map loads);
    // TrimTextureCache does it between frames.
    const auto loadStart = std::chrono::steady_clock::now();
    FILE_EnsureWaitHandleSet();
    std::size_t fileSize = 0U;
    bool decoded = false;
    TexEntry entry = ReadTexture(path, fileSize, decoded);
    LogTexture(path, entry, fileSize, decoded);
    gFrameLoadMs += std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - loadStart).count();
    ++gFrameLoads;
    const auto inserted = gTextures.emplace(path, std::move(entry));
    if (!inserted.first->second.ok) {
      return TextureState::Failed;
    }
    out = &inserted.first->second;
    return TextureState::Ready;
  }

  const TexEntry* LoadTexture(
    const std::string& path
  )
  {
    const TexEntry* texture = nullptr;
    (void)FindTexture(path, texture);
    return texture;
  }

  bool TextureBudgetLeft()
  {
    constexpr double kBudgetMs = 2.0;
    return gFrameLoadMs < kBudgetMs;
  }

  void NoteTextureWork(
    const double milliseconds
  )
  {
    gFrameLoadMs += milliseconds;
  }

  void TrimTextureCache()
  {
    if (gFrameLoads != 0 && gFrameLoadMs >= 1.0 && gHitchLogBudget > 0) {
      --gHitchLogBudget;
      gpg::Logf("DynLights: %d textures read this frame in %.2f ms", gFrameLoads, gFrameLoadMs);
    }
    gFrameLoadMs = 0.0;
    gFrameLoads = 0;
    if (gTextures.size() >= kTextureCacheMax) {
      gTextures.clear();
    }
    // The finished reads join the cache here, after a clear and before any feed asks this frame.
    if (!gPending.empty()) {
      std::vector<Finished> finished;
      {
        const std::lock_guard<std::mutex> lock(gWorker.mutex);
        finished.swap(gWorker.done);
      }
      for (Finished& item : finished) {
        gPending.erase(item.path);
        gFrameWorkerMs += item.milliseconds;
        ++gFrameWorkerLoads;
        LogTexture(item.path, item.entry, item.fileSize, item.decoded);
        gTextures.emplace(std::move(item.path), std::move(item.entry));
      }
    }
    if (gFrameWorkerLoads != 0) {
      if (gWorkerLogBudget > 0 && gFrameWorkerMs >= 1.0) {
        --gWorkerLogBudget;
        gpg::Logf("DynLights: %d textures read on the worker in %.2f ms", gFrameWorkerLoads, gFrameWorkerMs);
      }
      gFrameWorkerMs = 0.0;
      gFrameWorkerLoads = 0;
    }
  }
} // namespace moho::lights
