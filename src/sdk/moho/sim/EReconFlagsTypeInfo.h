#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EReconFlags : std::int32_t;

  class EReconFlagsTypeInfo final : public gpg::REnumType
  {
  public:
    /** Address: 0x00564490 (FUN_00564490, sub_564490) */
    EReconFlagsTypeInfo();
    /** Address: 0x00564520 (deleting thunk) */
    ~EReconFlagsTypeInfo() override;
    /** Address: 0x00564510 (GetName) */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x005644F0 (Init) */
    void Init() override;

  private:
    /** Address: 0x00564550 (FUN_00564550, AddEnums) */
    static void AddEnums(gpg::REnumType* enumType);
  };

  static_assert(sizeof(EReconFlagsTypeInfo) == 0x78, "EReconFlagsTypeInfo size must be 0x78");

  void register_EReconFlagsTypeInfoStartup();
} // namespace moho
