#pragma once

#include "boost/shared_ptr.h"

namespace moho
{
  class CAniSkel;

  class RScmResource
  {
  public:
    /**
     * Address: 0x00538DB0 (FUN_00538DB0,
     * ?GetSkeleton@RScmResource@Moho@@QAE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     */
    [[nodiscard]] boost::shared_ptr<const CAniSkel> GetSkeleton();
  };
} // namespace moho
