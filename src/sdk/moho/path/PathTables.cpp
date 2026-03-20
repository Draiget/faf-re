#include "PathTables.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "legacy/containers/Vector.h"
#include "moho/path/ClusterMap.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
  struct PathQueueImplView
  {
    std::uint8_t pad_00[0x1C];
    msvc8::vector<moho::ClusterMap*> mClusters; // +0x1C
  };

  static_assert(offsetof(PathQueueImplView, mClusters) == 0x1C, "PathQueueImpl::mClusters offset must be 0x1C");

  bool gGenPathWarmupPending = true;

  [[nodiscard]] bool IsGenPathEnabled()
  {
#ifdef _WIN32
    const char* const commandLine = ::GetCommandLineA();
    return commandLine && std::strstr(commandLine, "/genpath");
#else
    return false;
#endif
  }

  template <typename Fn>
  void ForEachClusterMap(PathQueueImplView* impl, Fn&& fn)
  {
    if (!impl) {
      return;
    }

    for (auto it = impl->mClusters.begin(); it != impl->mClusters.end(); ++it) {
      moho::ClusterMap* const cluster = *it;
      if (!cluster) {
        continue;
      }
      fn(cluster);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076BC10 (FUN_0076BC10)
   */
  void PathTables::UpdateBackground(int* budget)
  {
    if (!budget || !mQueue) {
      return;
    }

    auto* const impl = reinterpret_cast<PathQueueImplView*>(mQueue);

    // /genpath one-shot pass forces "unlimited" budget through every cluster once.
    if (IsGenPathEnabled() && gGenPathWarmupPending) {
      ForEachClusterMap(impl, [&](moho::ClusterMap* cluster) {
        *budget = INT_MAX;
        cluster->BackgroundWork(*budget);
      });
      gGenPathWarmupPending = false;
    }

    ForEachClusterMap(impl, [&](moho::ClusterMap* cluster) {
      cluster->BackgroundWork(*budget);
    });
  }

  /**
   * Address: 0x0076BBD0 (FUN_0076BBD0, Moho::PathQueue::DirtyClusters)
   */
  void PathTables::DirtyClusters(const gpg::Rect2i& dirtyRect)
  {
    if (!mQueue) {
      return;
    }

    auto* const impl = reinterpret_cast<PathQueueImplView*>(mQueue);
    for (auto it = impl->mClusters.begin(); it != impl->mClusters.end(); ++it) {
      moho::ClusterMap* const cluster = *it;
      if (!cluster) {
        continue;
      }

      cluster->DirtyRect(dirtyRect);
    }
  }
} // namespace moho
