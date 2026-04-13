#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B4EC
   * COL:  0x00E70B30
   */
  class CAiFormationInstanceTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059BD80 (FUN_0059BD80, ctor/preregister lane)
     *
     * What it does:
     * Initializes RTTI base lanes and preregisters `CAiFormationInstance`
     * reflection ownership.
     */
    CAiFormationInstanceTypeInfo();

    /**
     * Address: 0x0059BE30 (FUN_0059BE30, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiFormationInstanceTypeInfo() override;

    /**
     * Address: 0x0059BE20 (FUN_0059BE20, ?GetName@CAiFormationInstanceTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0059BDE0 (FUN_0059BDE0, ?Init@CAiFormationInstanceTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;

    /**
     * Address: 0x0059D0F0 (FUN_0059D0F0, ??2CAiFormationInstance@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Allocates and default-constructs one `CAiFormationInstance`, then returns
     * it as a typed reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0059D1A0 (FUN_0059D1A0)
     *
     * What it does:
     * Placement-constructs one `CAiFormationInstance` in caller-provided
     * storage and returns it as a typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0059D180 (FUN_0059D180)
     *
     * What it does:
     * Invokes slot-0 deleting lane (`deleteFlags=1`) when storage is non-null.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0059D220 (FUN_0059D220)
     *
     * What it does:
     * Invokes slot-0 non-deleting lane (`deleteFlags=0`) for in-place teardown.
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CAiFormationInstanceTypeInfo) == 0x64, "CAiFormationInstanceTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC130 (FUN_00BCC130, register_CAiFormationInstanceTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiFormationInstanceTypeInfo` storage and installs
   * process-exit cleanup.
   */
  void register_CAiFormationInstanceTypeInfo();
} // namespace moho
