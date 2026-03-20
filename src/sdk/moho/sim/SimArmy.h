#pragma once

#include "IArmy.h"

namespace moho
{
  class SimArmy : public IArmy
  {
  public:
    /**
     * Address: 0x006FDAD0 (FUN_006FDAD0, Moho::SimArmy::~SimArmy)
     *
     * What it does:
     * Restores the SimArmy vtable and tears down the +0x08 IArmy subobject.
     * Calls helper Address: 0x006FDB00 (FUN_006FDB00), which then calls Address: 0x006FD570.
     */
    ~SimArmy() override;
  };
} // namespace moho
