#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniSkelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00549FF0 (FUN_00549FF0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAniSkelTypeInfo() override;

    /**
     * Address: 0x00549FE0 (FUN_00549FE0)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00549FC0 (FUN_00549FC0)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAniSkel` (`sizeof = 0x2C`).
     */
    void Init() override;
  };

  static_assert(sizeof(CAniSkelTypeInfo) == 0x64, "CAniSkelTypeInfo size must be 0x64");

  /**
   * Address: 0x00549F60 (FUN_00549F60, preregister_CAniSkelTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `CAniSkel`.
   */
  [[nodiscard]] gpg::RType* preregister_CAniSkelTypeInfo();

  /**
   * Address: 0x00BF4480 (FUN_00BF4480, cleanup_CAniSkelTypeInfo)
   *
   * What it does:
   * Releases startup-owned `CAniSkelTypeInfo` field/base metadata storage.
   */
  void cleanup_CAniSkelTypeInfo();

  /**
   * Address: 0x00BC9890 (FUN_00BC9890, register_CAniSkelTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `CAniSkel` RTTI and installs process-exit cleanup.
   */
  int register_CAniSkelTypeInfoAtexit();
} // namespace moho
