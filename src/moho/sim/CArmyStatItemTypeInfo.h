#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CArmyStatItemTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0070B610 (FUN_0070B610, sub_70B610)
     *
     * What it does:
     * Initializes RTTI base lanes and preregisters `CArmyStatItem` type metadata.
     */
    CArmyStatItemTypeInfo();

    /**
     * Address: 0x0070B6C0 (FUN_0070B6C0, Moho::CArmyStatItemTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CArmyStatItemTypeInfo.
     */
    ~CArmyStatItemTypeInfo() override;

    /**
     * Address: 0x0070B6B0 (FUN_0070B6B0, Moho::CArmyStatItemTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CArmyStatItem.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0070B670 (FUN_0070B670, Moho::CArmyStatItemTypeInfo::Init)
     *
     * What it does:
     * Sets CArmyStatItem size metadata, binds object lifecycle callbacks,
     * adds StatItem as reflection base, and finalizes type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0070EE90 (FUN_0070EE90)
     *
     * What it does:
     * Installs CArmyStatItem allocation/construct/delete/destruct callback
     * slots on one reflected type descriptor.
     */
    static gpg::RType* AssignLifecycleCallbacks(gpg::RType* typeInfo);

    /**
     * Address: 0x007111C0 (FUN_007111C0)
     *
     * What it does:
     * Allocates and default-constructs a CArmyStatItem ("Root") and returns
     * it as a reflected object reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00711260 (FUN_00711260)
     *
     * What it does:
     * Placement-constructs a CArmyStatItem ("Root") in caller-provided
     * storage and returns it as a reflected object reference.
     */
    static gpg::RRef CtrRef(void* objectPtr);

    /**
     * Address: 0x00711240 (FUN_00711240)
     *
     * What it does:
     * Invokes deleting destructor path for CArmyStatItem.
     */
    static void Delete(void* objectPtr);

    /**
     * Address: 0x007112E0 (FUN_007112E0)
     *
     * What it does:
     * Invokes non-deleting destructor path for CArmyStatItem.
     */
    static void Destruct(void* objectPtr);

    /**
     * Address: 0x00712500 (FUN_00712500)
     *
     * What it does:
     * Registers StatItem as reflection base for CArmyStatItem.
     */
    static void AddBase_StatItem(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CArmyStatItemTypeInfo) == 0x64, "CArmyStatItemTypeInfo size must be 0x64");
} // namespace moho
