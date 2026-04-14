#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Base interface lane for decal grouping owners.
   *
   * Binary evidence:
   * - constructor lane at 0x00877240
   * - base-vtable reset lane at 0x00877230
   */
  class IDecalGroup
  {
  public:
    /**
     * Address: 0x00877240 (FUN_00877240, ??0IDecalGroup@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one decal-group base object with the `IDecalGroup` vtable.
     */
    IDecalGroup();

    virtual ~IDecalGroup() = default;
  };

  static_assert(sizeof(IDecalGroup) == 0x04, "IDecalGroup size must be 0x04");
} // namespace moho
