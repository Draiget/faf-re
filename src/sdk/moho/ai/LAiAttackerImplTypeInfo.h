#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class LAiAttackerImpl;

  /**
   * VFTABLE: 0x00E1EA94
   * COL: 0x00E7599C
   */
  class LAiAttackerImplTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D6040 (FUN_005D6040, Moho::LAiAttackerImplTypeInfo::LAiAttackerImplTypeInfo)
     *
     * What it does:
     * Preregisters `LAiAttackerImpl` RTTI into the reflection lookup table.
     */
    LAiAttackerImplTypeInfo();

    /**
     * Address: 0x005D60F0 (FUN_005D60F0, scalar deleting thunk)
     */
    ~LAiAttackerImplTypeInfo() override;

    /**
     * Address: 0x005D60E0 (FUN_005D60E0, Moho::LAiAttackerImplTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005D60A0 (FUN_005D60A0, Moho::LAiAttackerImplTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x005DEA30 (FUN_005DEA30, Moho::LAiAttackerImplTypeInfo::AddBase_CTask)
     */
    static void __stdcall AddBase_CTask(gpg::RType* typeInfo);

    /**
     * Address: 0x005DD850 (FUN_005DD850, Moho::LAiAttackerImplTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `LAiAttackerImpl` and returns a reflection reference to
     * the constructed object.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005DD8E0 (FUN_005DD8E0, Moho::LAiAttackerImplTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `LAiAttackerImpl` in caller-provided storage and returns
     * a reflection reference to it.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005DD8C0 (FUN_005DD8C0, Moho::LAiAttackerImplTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005DD950 (FUN_005DD950, Moho::LAiAttackerImplTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(LAiAttackerImplTypeInfo) == 0x64, "LAiAttackerImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCE830 (FUN_00BCE830, register_LAiAttackerImplTypeInfo)
   *
   * What it does:
   * Constructs the recovered `LAiAttackerImpl` type-info helper and installs
   * process-exit cleanup.
   */
  void register_LAiAttackerImplTypeInfo();
} // namespace moho
