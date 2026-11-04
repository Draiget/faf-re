#include "remote/UnderlayPaths.h"

#include <atomic>
#include <mutex>

// Engine addition, server mode: see UnderlayPaths.h.

namespace faf::remote
{
  namespace
  {
    // The sim thread writes, the frame builder reads (in loopback on another thread).
    std::mutex gLock;
    std::unordered_map<std::uint32_t, std::string> gPaths;
    std::atomic<std::uint64_t> gVersion{0}; // counts the changes, written under the lock
  } // namespace

  void SetUnderlayPath(const std::uint32_t entityId, const std::string& path)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    gVersion.fetch_add(1u, std::memory_order_release);
    if (path.empty()) {
      gPaths.erase(entityId);
    } else {
      gPaths[entityId] = path;
    }
  }

  void CopyUnderlayPath(const std::uint32_t fromEntityId, const std::uint32_t toEntityId)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    gVersion.fetch_add(1u, std::memory_order_release);
    if (const auto it = gPaths.find(fromEntityId); it != gPaths.end()) {
      gPaths[toEntityId] = it->second;
    } else {
      gPaths.erase(toEntityId);
    }
  }

  void ForgetUnderlayPath(const std::uint32_t entityId)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    gVersion.fetch_add(1u, std::memory_order_release);
    gPaths.erase(entityId);
  }

  void CUnderlayPathReader::Refresh()
  {
    if (gVersion.load(std::memory_order_acquire) == mVersion) {
      return;
    }
    const std::lock_guard<std::mutex> lock(gLock);
    mVersion = gVersion.load(std::memory_order_relaxed);
    mPaths = gPaths;
  }
} // namespace faf::remote
