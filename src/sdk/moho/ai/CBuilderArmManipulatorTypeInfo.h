#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CBuilderArmManipulator;

  /**
   * Type-info owner for `CBuilderArmManipulator`.
   */
  class CBuilderArmManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00635A40 (FUN_00635A40, scalar deleting thunk)
     */
    ~CBuilderArmManipulatorTypeInfo() override;

    /**
     * Address: 0x00635A30 (FUN_00635A30, Moho::CBuilderArmManipulatorTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type-name literal for `CBuilderArmManipulator`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006359F0 (FUN_006359F0, Moho::CBuilderArmManipulatorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/callback lanes, registers reflected
     * `IAniManipulator` base, and finalizes type-info initialization.
     */
    void Init() override;

    /**
     * Address: 0x00637010 (FUN_00637010, Moho::CBuilderArmManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CBuilderArmManipulator` and returns a typed reflection
     * reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006370B0 (FUN_006370B0, Moho::CBuilderArmManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CBuilderArmManipulator` in caller storage and
     * returns a typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

  private:
    /**
     * Address: 0x00636F30 (FUN_00636F30, callback shard)
     *
     * What it does:
     * Assigns all lifecycle callback slots (`NewRef`, `CtrRef`, `Delete`,
     * `Destruct`) on one type descriptor.
     */
    static void AssignAllLifecycleCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo);

    /**
     * Address: 0x00636FF0 (FUN_00636FF0, callback shard)
     *
     * What it does:
     * Assigns constructor-lane callback slots (`NewRef`, `CtrRef`) on one type
     * descriptor.
     */
    static void AssignCtorCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo);

    /**
     * Address: 0x00637000 (FUN_00637000, callback shard)
     *
     * What it does:
     * Assigns destructor-lane callback slots (`Delete`, `Destruct`) on one
     * type descriptor.
     */
    static void AssignDtorCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo);

    static void Delete(void* objectStorage);
    static void Destruct(void* objectStorage);
    static void AddBase_IAniManipulator(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BD2590 (FUN_00BD2590, register_CBuilderArmManipulatorTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CBuilderArmManipulatorTypeInfo` storage and
   * installs process-exit cleanup.
   */
  int register_CBuilderArmManipulatorTypeInfo();

  static_assert(sizeof(CBuilderArmManipulatorTypeInfo) == 0x64, "CBuilderArmManipulatorTypeInfo size must be 0x64");
} // namespace moho
