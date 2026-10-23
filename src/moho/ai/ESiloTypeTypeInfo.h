#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiSiloBuild.h"

namespace moho
{
  class ESiloTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0050A300 (FUN_0050A300, scalar deleting destructor)
     */
    ~ESiloTypeTypeInfo() override;

    /**
     * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(ESiloTypeTypeInfo) == 0x78, "ESiloTypeTypeInfo size must be 0x78");


  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `ESiloType`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloTypeTypeInfo();

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   *
   * What it does:
   * Runs `ESiloType` typeinfo preregistration.
   */
  void register_ESiloTypeTypeInfo();
} // namespace moho
