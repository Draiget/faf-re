#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"

namespace moho
{
  class ResourceManager;

  /**
   * VFTABLE: 0x00E3F468
   * COL: 0x00E97FD0
   *
   * Runtime watcher base used by mesh/skydome resource reload lanes.
   */
  class CResourceWatcher
  {
  public:
    /**
     * Address: 0x007DD660 (FUN_007DD660, ??0CResourceWatcher@Moho@@QAE@@Z)
     * Also inlined in mesh/skydome constructor lanes (`0x007DD5E0`,
     * `0x007DD680`, `0x008149E0`).
     *
     * What it does:
     * Initializes watched-resource small-vector storage to inline mode.
     */
    CResourceWatcher() noexcept;

    /**
     * Address: 0x00A82547 (_purecall slot in base vtable)
     *
     * What it does:
     * Implemented by concrete watchers to reload when one watched path changes.
     */
    virtual void OnResourceChanged(gpg::StrArg resourcePath) = 0;

    /**
     * Address: 0x007DA8D0 (FUN_007DA8D0, ??1CResourceWatcher@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases pending watcher nodes through the resource-manager lane, then
     * resets watched-node storage to inline mode.
     */
    ~CResourceWatcher();

  public:
    friend class ResourceManager;

    std::uint32_t mWatcherFlags;      // +0x04
    void* mWatchedBegin;              // +0x08
    void* mWatchedEnd;                // +0x0C
    void* mWatchedStorageEnd;         // +0x10
    void* mWatchedStorageOrigin;      // +0x14
    std::uint8_t mWatchedInline[0x08]; // +0x18
  };

  static_assert(offsetof(CResourceWatcher, mWatcherFlags) == 0x04, "CResourceWatcher::mWatcherFlags offset must be 0x04");
  static_assert(offsetof(CResourceWatcher, mWatchedBegin) == 0x08, "CResourceWatcher::mWatchedBegin offset must be 0x08");
  static_assert(offsetof(CResourceWatcher, mWatchedEnd) == 0x0C, "CResourceWatcher::mWatchedEnd offset must be 0x0C");
  static_assert(offsetof(CResourceWatcher, mWatchedStorageEnd) == 0x10, "CResourceWatcher::mWatchedStorageEnd offset must be 0x10");
  static_assert(
    offsetof(CResourceWatcher, mWatchedStorageOrigin) == 0x14,
    "CResourceWatcher::mWatchedStorageOrigin offset must be 0x14"
  );
  static_assert(offsetof(CResourceWatcher, mWatchedInline) == 0x18, "CResourceWatcher::mWatchedInline offset must be 0x18");
  static_assert(sizeof(CResourceWatcher) == 0x20, "CResourceWatcher size must be 0x20");
} // namespace moho
