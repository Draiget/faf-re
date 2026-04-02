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
     * Address: 0x005BE590 (FUN_005BE590, Moho::ReconBlipTypeInfo::ReconBlipTypeInfo)
     *
     * What it does:
     * Preregisters `ReconBlip` RTTI into the reflection lookup table.
     */
    ReconBlipTypeInfo();

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

  /**
   * Address: 0x00BCDC50 (FUN_00BCDC50, register_ReconBlipTypeInfo)
   *
   * What it does:
   * Constructs the recovered `ReconBlipTypeInfo` helper and installs
   * process-exit cleanup.
   */
  void register_ReconBlipTypeInfo();

  /**
   * Address: 0x005BE380 (FUN_005BE380, sub_5BE380)
   *
   * What it does:
   * Constructs/preregisters RTTI for `SPerArmyReconInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SPerArmyReconInfoTypeInfo();

  /**
   * Address: 0x00BF77E0 (FUN_00BF77E0, sub_BF77E0)
   *
   * What it does:
   * Tears down startup-owned `SPerArmyReconInfo` RTTI storage.
   */
  void cleanup_SPerArmyReconInfoTypeInfo();

  /**
   * Address: 0x00BCDBB0 (FUN_00BCDBB0, sub_BCDBB0)
   *
   * What it does:
   * Registers `SPerArmyReconInfo` RTTI and installs process-exit cleanup.
   */
  int register_SPerArmyReconInfoTypeInfo();

  /**
   * Address: 0x005CA510 (FUN_005CA510, sub_5CA510)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `msvc8::vector<SPerArmyReconInfo>`.
   */
  [[nodiscard]] gpg::RType* preregister_RVectorType_SPerArmyReconInfo();

  /**
   * Address: 0x00BF7D20 (FUN_00BF7D20, sub_BF7D20)
   *
   * What it does:
   * Tears down startup-owned `vector<SPerArmyReconInfo>` reflection storage.
   */
  void cleanup_RVectorType_SPerArmyReconInfo();

  /**
   * Address: 0x00BCDF00 (FUN_00BCDF00, sub_BCDF00)
   *
   * What it does:
   * Registers `vector<SPerArmyReconInfo>` reflection metadata and installs
   * process-exit cleanup.
   */
  int register_RVectorType_SPerArmyReconInfo();
} // namespace moho
