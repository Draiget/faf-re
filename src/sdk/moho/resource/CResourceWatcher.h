#pragma once

#include <cstddef>

#include "boost/noncopyable.hpp"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"

namespace moho
{
  struct ResourceWatch;

  /**
   * VFTABLE: 0x00E3F468
   * COL: 0x00E97FD0
   *
   * Something that wants to hear when a resource it loaded changes on disk
   * (`Mesh`, `SkyDome`). Passing one to `RES_GetResource` registers a
   * `ResourceWatch`; the manager calls `OnResourceChanged` when the file
   * changes.
   */
  class CResourceWatcher : private boost::noncopyable
  {
  public:
    /**
     * Address: 0x007DD660 (FUN_007DD660, ??0CResourceWatcher@Moho@@QAE@@Z)
     * Also inlined in the `Mesh` and `SkyDome` constructors (0x007DD5E0,
     * 0x007DD680, 0x008149E0).
     *
     * What it does:
     * Stores the vftable and arms `mWatches`' inline storage; +0x04 is the
     * padding in front of the 8-aligned vector and is never written.
     */
    CResourceWatcher() = default;

    /**
     * Address: 0x00A82547 (FUN_00A82547, _purecall slot in base vtable)
     *
     * What it does:
     * Called by `ResourceManager::OnDiskWatchEvent` with the watched path.
     */
    virtual void OnResourceChanged(gpg::StrArg resourcePath) = 0;

    /**
     * Address: 0x007DA8D0 (FUN_007DA8D0, ??1CResourceWatcher@Moho@@QAE@@Z)
     *
     * What it does:
     * Hands any remaining watches to `ResourceManager::DetachWatcher`, then
     * the vector's own destructor frees its heap block.
     */
    ~CResourceWatcher();

    gpg::fastvector_n<ResourceWatch*, 2> mWatches; // +0x08
  };

  static_assert(offsetof(CResourceWatcher, mWatches) == 0x08, "CResourceWatcher::mWatches offset must be 0x08");
  static_assert(sizeof(CResourceWatcher) == 0x20, "CResourceWatcher size must be 0x20");
} // namespace moho
