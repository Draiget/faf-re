#include "remote/UnderlayPaths.h"

#include <mutex>
#include <unordered_map>

// Engine addition, server mode: see UnderlayPaths.h.

namespace faf::remote
{
  namespace
  {
    // The sim thread writes, the frame builder reads (in loopback on another thread).
    std::mutex gLock;
    std::unordered_map<std::uint32_t, std::string> gPaths;
  } // namespace

  void SetUnderlayPath(const std::uint32_t entityId, const std::string& path)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    if (path.empty()) {
      gPaths.erase(entityId);
    } else {
      gPaths[entityId] = path;
    }
  }

  void CopyUnderlayPath(const std::uint32_t fromEntityId, const std::uint32_t toEntityId)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    if (const auto it = gPaths.find(fromEntityId); it != gPaths.end()) {
      gPaths[toEntityId] = it->second;
    } else {
      gPaths.erase(toEntityId);
    }
  }

  void ForgetUnderlayPath(const std::uint32_t entityId)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    gPaths.erase(entityId);
  }

  std::string UnderlayPath(const std::uint32_t entityId)
  {
    const std::lock_guard<std::mutex> lock(gLock);
    const auto it = gPaths.find(entityId);
    return it != gPaths.end() ? it->second : std::string();
  }
} // namespace faf::remote
