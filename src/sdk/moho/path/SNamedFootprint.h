#pragma once
#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/sim/SFootprint.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  struct SNamedFootprint : public SFootprint
  {
    msvc8::string mName; // +0x10
    std::int32_t mIndex; // +0x2C
  };

  static_assert(offsetof(SNamedFootprint, mName) == 0x10, "SNamedFootprint::mName offset must be 0x10");
  static_assert(offsetof(SNamedFootprint, mIndex) == 0x2C, "SNamedFootprint::mIndex offset must be 0x2C");
  static_assert(sizeof(SNamedFootprint) == 0x30, "SNamedFootprint size must be 0x30");

  /**
   * Address: 0x00513CF0 (FUN_00513CF0, preregister_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `SNamedFootprint`.
   */
  [[nodiscard]] gpg::RType* preregister_SNamedFootprintTypeInfo();

  /**
   * Address: 0x00BF2820 (FUN_00BF2820, cleanup_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SNamedFootprintTypeInfo` storage at process exit.
   */
  void cleanup_SNamedFootprintTypeInfo();

  /**
   * Address: 0x00BC8360 (FUN_00BC8360, register_SNamedFootprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SNamedFootprint` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintTypeInfoStartup();

  /**
   * Address: 0x005149D0 (FUN_005149D0, preregister_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `std::list<SNamedFootprint>`.
   */
  [[nodiscard]] gpg::RType* preregister_SNamedFootprintListTypeInfo();

  /**
   * Address: 0x00BF2910 (FUN_00BF2910, cleanup_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `std::list<SNamedFootprint>` RTTI storage at process exit.
   */
  void cleanup_SNamedFootprintListTypeInfo();

  /**
   * Address: 0x00BC83A0 (FUN_00BC83A0, register_SNamedFootprintListTypeInfoStartup)
   *
   * What it does:
   * Preregisters `std::list<SNamedFootprint>` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintListTypeInfoStartup();
} // namespace moho
