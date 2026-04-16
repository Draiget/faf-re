#include "moho/resource/CResourceWatcher.h"

#include "moho/resource/ResourceManager.h"

namespace moho
{
  /**
   * Address: 0x007DD660 (FUN_007DD660, ??0CResourceWatcher@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes inline watched-resource storage and seeds the fallback
   * inline-capacity slot used by the small-vector reset lane.
   */
  CResourceWatcher::CResourceWatcher() noexcept
    : mWatcherFlags(0)
    , mWatchedBegin(mWatchedInline)
    , mWatchedEnd(mWatchedInline)
    , mWatchedStorageEnd(mWatchedInline + sizeof(mWatchedInline))
    , mWatchedStorageOrigin(mWatchedInline)
    , mWatchedInline{}
  {
    // Legacy small-vector reset path reads `*(origin)` as fallback storage end.
    auto** const inlineSlots = reinterpret_cast<void**>(mWatchedInline);
    inlineSlots[0] = mWatchedStorageEnd;
  }

  /**
   * Address: 0x007DA8D0 (FUN_007DA8D0, ??1CResourceWatcher@Moho@@QAE@@Z)
   *
   * What it does:
   * Flushes pending watched-resource nodes through the manager lane and then
   * resets watcher storage to inline mode.
   */
  CResourceWatcher::~CResourceWatcher()
  {
    if (mWatchedBegin != mWatchedEnd) {
      ResourceManager* const manager = RES_GetResourceManager();
      if (manager != nullptr) {
        manager->ManageWatchedResources(this);
      }
    }

    if (mWatchedBegin != mWatchedStorageOrigin) {
      ::operator delete[](mWatchedBegin);
      mWatchedBegin = mWatchedStorageOrigin;
      mWatchedStorageEnd = *reinterpret_cast<void**>(mWatchedStorageOrigin);
    }

    mWatchedEnd = mWatchedBegin;
  }
} // namespace moho
