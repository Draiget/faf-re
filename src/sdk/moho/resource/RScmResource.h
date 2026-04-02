#pragma once

#include "boost/shared_ptr.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CAniSkel;

  class RScmResource
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00538DB0 (FUN_00538DB0,
     * ?GetSkeleton@RScmResource@Moho@@QAE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     */
    [[nodiscard]] boost::shared_ptr<const CAniSkel> GetSkeleton();
  };

  /**
   * Address: 0x00BC91A0 (FUN_00BC91A0)
   *
   * What it does:
   * Resolves `RScmResource` RTTI and registers the `"models"` prefetch lane.
   */
  void register_RScmResourceModelPrefetchType();
} // namespace moho
