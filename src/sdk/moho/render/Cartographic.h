#pragma once

#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"

namespace moho
{
  class Cartographic
  {
  public:
    /**
     * Address: 0x007D1E50 (FUN_007D1E50, ?GetEffect@Cartographic@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
     *
     * What it does:
     * Resolves the cartographic shader from the active D3D device resources
     * and returns the backing GAL effect handle.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::Effect> GetEffect();
  };
} // namespace moho
