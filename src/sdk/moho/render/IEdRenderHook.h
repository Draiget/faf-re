#pragma once

#include <cstddef>

namespace moho
{
  /**
   * VFTABLE: 0x00E3CAF8
   * COL:     0x00E96668
   */
  class IEdRenderHook
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * What it does:
     * Abstract editor-render callback lane 0.
     */
    virtual void Hook0() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * What it does:
     * Abstract editor-render callback lane 1.
     */
    virtual void Hook1() = 0;
  };

  static_assert(sizeof(IEdRenderHook) == 0x04, "IEdRenderHook size must be 0x04");
} // namespace moho
