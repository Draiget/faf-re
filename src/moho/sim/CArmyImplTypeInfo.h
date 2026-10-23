#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CArmyImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006FE3D0 (FUN_006FE3D0, Moho::CArmyImplTypeInfo::CArmyImplTypeInfo)
     *
     * What it does:
     * Initializes RTTI base lanes and preregisters `CArmyImpl` type metadata.
     */
    CArmyImplTypeInfo();

    /**
     * Address: 0x006FE480 (FUN_006FE480, Moho::CArmyImplTypeInfo::dtr)
     * Slot: 2
     */
    ~CArmyImplTypeInfo() override;

    /**
     * Address: 0x006FE470 (FUN_006FE470, Moho::CArmyImplTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `CArmyImpl`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006FE430 (FUN_006FE430, Moho::CArmyImplTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CArmyImpl`
     * (`sizeof = 0x288`) and registers `SimArmy` as a base type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00701D00 (FUN_00701D00, sub_701D00)
     *
     * What it does:
     * Assigns reflected construction/destruction callback lanes for `CArmyImpl`.
     */
    static CArmyImplTypeInfo* AssignFactoryCallbacks(CArmyImplTypeInfo* typeInfo);

    /**
     * Address: 0x007034D0 (FUN_007034D0, sub_7034D0)
     *
     * What it does:
     * Allocates and constructs a reflected `CArmyImpl` object reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00703570 (FUN_00703570, sub_703570)
     *
     * What it does:
     * Placement-constructs a reflected `CArmyImpl` object reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00703550 (FUN_00703550, sub_703550)
     *
     * What it does:
     * Invokes deleting-dtor callback path for reflected `CArmyImpl` storage.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x007035E0 (FUN_007035E0, sub_7035E0)
     *
     * What it does:
     * Invokes non-deleting destructor callback path for reflected `CArmyImpl` storage.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00703F40 (FUN_00703F40, Moho::CArmyImplTypeInfo::AddBase_SimArmy)
     *
     * What it does:
     * Registers `SimArmy` as reflection base for `CArmyImpl`.
     */
    static void AddBase_SimArmy(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CArmyImplTypeInfo) == 0x64, "CArmyImplTypeInfo size must be 0x64");
} // namespace moho
