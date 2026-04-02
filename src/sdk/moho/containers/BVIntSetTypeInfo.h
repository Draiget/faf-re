#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00DFFF24
   * COL: 0x00E5C564
   */
  class BVIntSetTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00401460 (FUN_00401460, Moho::BVIntSetTypeInfo::BVIntSetTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the BVIntSet reflection descriptor.
     */
    BVIntSetTypeInfo();

    /**
     * Address: 0x004014F0 (FUN_004014F0, deleting dtor lane)
     * Slot: 2
     */
    ~BVIntSetTypeInfo() override;

    /**
     * Address: 0x004014E0 (FUN_004014E0, Moho::BVIntSetTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004014C0 (FUN_004014C0, Moho::BVIntSetTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected BVIntSet size metadata and finalizes the descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(BVIntSetTypeInfo) == 0x64, "BVIntSetTypeInfo size must be 0x64");
} // namespace moho
