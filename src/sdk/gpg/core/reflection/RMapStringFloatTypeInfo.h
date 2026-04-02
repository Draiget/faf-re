#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  /**
   * Reflection descriptor for `std::map<std::string,float>`.
   *
   * VFTABLE: `gpg::RMapType<std::string,float>`
   * COL: from startup lane around `FUN_006B16B0`.
   */
  class RMapStringFloatTypeInfo final : public gpg::RType
  {
  public:
    /**
     * What it does:
     * Returns the reflected type label for `std::map<std::string,float>`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * What it does:
     * Initializes reflected size/version metadata and finalizes field/base
     * index data for this map type descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(RMapStringFloatTypeInfo) == 0x64, "RMapStringFloatTypeInfo size must be 0x64");

  /**
   * Address: 0x006B16B0 (FUN_006B16B0, register_MapStringFloat_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `std::map<std::string,float>`.
   */
  [[nodiscard]] gpg::RType* register_MapStringFloat_Type_00();

  /**
   * Address: 0x00BFDBE0 (FUN_00BFDBE0, cleanup_MapStringFloat_Type)
   *
   * What it does:
   * Tears down startup-owned `std::map<std::string,float>` RTTI storage.
   */
  void cleanup_MapStringFloat_Type();

  /**
   * Address: 0x00BD6BC0 (FUN_00BD6BC0, register_MapStringFloat_Type_AtExit)
   *
   * What it does:
   * Registers `std::map<std::string,float>` RTTI and installs process-exit
   * cleanup.
   */
  int register_MapStringFloat_Type_AtExit();
} // namespace gpg
