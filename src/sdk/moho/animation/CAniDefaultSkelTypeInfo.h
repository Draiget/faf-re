#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0054A9C0 (FUN_0054A9C0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAniDefaultSkelTypeInfo() override;

    /**
     * Address: 0x0054A9B0 (FUN_0054A9B0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0054A990 (FUN_0054A990)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAniDefaultSkel` and registers
     * `CAniSkel` as base metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(CAniDefaultSkelTypeInfo) == 0x64, "CAniDefaultSkelTypeInfo size must be 0x64");

  /**
   * Address: 0x0054A930 (FUN_0054A930, preregister_CAniDefaultSkelTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `CAniDefaultSkel`.
   */
  [[nodiscard]] gpg::RType* preregister_CAniDefaultSkelTypeInfo();

  /**
   * Address: 0x00BF44E0 (FUN_00BF44E0, cleanup_CAniDefaultSkelTypeInfo)
   *
   * What it does:
   * Releases startup-owned `CAniDefaultSkelTypeInfo` field/base metadata storage.
   */
  void cleanup_CAniDefaultSkelTypeInfo();

  /**
   * Address: 0x00BC98B0 (FUN_00BC98B0, register_CAniDefaultSkelTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `CAniDefaultSkel` RTTI and installs process-exit cleanup.
   */
  int register_CAniDefaultSkelTypeInfoAtexit();
} // namespace moho
