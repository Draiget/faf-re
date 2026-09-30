#include "moho/resource/CResourceWatcher.h"

#include "moho/resource/ResourceManager.h"

namespace moho
{
  /**
   * Address: 0x007DA8D0 (FUN_007DA8D0, ??1CResourceWatcher@Moho@@QAE@@Z)
   *
   * What it does:
   * Hands any remaining watches to the resource manager, which frees them
   * and resets the vector to its inline storage.
   */
  CResourceWatcher::~CResourceWatcher()
  {
    if (!mWatches.empty()) {
      RES_GetResourceManager()->DetachWatcher(this);
    }
  }
} // namespace moho
