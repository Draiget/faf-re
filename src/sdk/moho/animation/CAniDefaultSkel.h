#pragma once

#include "moho/animation/CAniSkel.h"

namespace moho
{
  class CAniDefaultSkel : public CAniSkel
  {
  public:
    /**
     * Address: 0x0054A390 (FUN_0054A390, Moho::CAniDefaultSkel::CAniDefaultSkel)
     * Mangled: ??0CAniDefaultSkel@Moho@@IAE@XZ
     *
     * What it does:
     * Initializes the process-default skeleton with one `Root` bone and one
     * matching bone-name index entry, then rebuilds bounds.
     */
    CAniDefaultSkel();

    /**
     * Address: 0x0054AD50 (FUN_0054AD50, scalar deleting destructor thunk)
     * Mangled: ??_GCAniDefaultSkel@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Runs base skeleton teardown and conditionally deletes `this`.
     */
    ~CAniDefaultSkel() override;
  };

  static_assert(sizeof(CAniDefaultSkel) == 0x2C, "CAniDefaultSkel size must be 0x2C");
} // namespace moho
