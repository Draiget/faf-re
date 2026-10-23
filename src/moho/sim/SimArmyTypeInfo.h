#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SimArmyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006FD970 (FUN_006FD970, Moho::SimArmyTypeInfo::SimArmyTypeInfo)
     *
     * What it does:
     * Initializes RTTI preregistration state for SimArmy metadata.
     */
    SimArmyTypeInfo();

    /**
     * Address: 0x006FDA00 (FUN_006FDA00, Moho::SimArmyTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for SimArmyTypeInfo.
     */
    ~SimArmyTypeInfo() override;

    /**
     * Address: 0x006FD9F0 (FUN_006FD9F0, Moho::SimArmyTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for SimArmy.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006FD9D0 (FUN_006FD9D0, Moho::SimArmyTypeInfo::Init)
     *
     * What it does:
     * Sets SimArmy size metadata, registers IArmy base subobject mapping,
     * and finalizes reflection type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00703E40 (FUN_00703E40, Moho::SimArmyTypeInfo::AddBase_IArmy)
     *
     * What it does:
     * Registers IArmy as a reflected base at subobject offset +0x08.
     */
    static void AddBase_IArmy(gpg::RType* typeInfo);

    /**
     * Address: 0x006FDAA0 (FUN_006FDAA0)
     *
     * What it does:
     * Wrapper lane that forwards one base-registration dispatch to
     * `AddBase_IArmy`.
     */
    [[maybe_unused]] static void AddBase_IArmyAdapter(gpg::RType* typeInfo);
  };

  static_assert(sizeof(SimArmyTypeInfo) == 0x64, "SimArmyTypeInfo size must be 0x64");
} // namespace moho
