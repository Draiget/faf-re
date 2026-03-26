#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1D930
   * COL:  0x00E74338
   */
  class ReconBlipTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005BE630 (FUN_005BE630, Moho::ReconBlipTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk for ReconBlipTypeInfo.
     */
    ~ReconBlipTypeInfo() override;

    /**
     * Address: 0x005BE620 (FUN_005BE620, Moho::ReconBlipTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type label for ReconBlip.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005BE5F0 (FUN_005BE5F0, Moho::ReconBlipTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets ReconBlip size metadata, registers Entity as reflected base,
     * and finalizes the reflected type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005C9010 (FUN_005C9010)
     *
     * What it does:
     * Adds Entity base metadata to the ReconBlip type.
     */
    static void AddBase_Entity(gpg::RType* typeInfo);
  };

  static_assert(sizeof(ReconBlipTypeInfo) == 0x64, "ReconBlipTypeInfo size must be 0x64");
} // namespace moho
