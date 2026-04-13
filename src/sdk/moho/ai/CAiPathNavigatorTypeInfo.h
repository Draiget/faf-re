#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiPathNavigator;

  /**
   * VFTABLE: 0x00E1C6B4
   * COL:  0x00E72488
   */
  class CAiPathNavigatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005AFA70 (FUN_005AFA70, ??0CAiPathNavigatorTypeInfo@Moho@@QAE@XZ)
     *
     * What it does:
     * Preregisters `CAiPathNavigator` RTTI for this type-info helper.
     */
    CAiPathNavigatorTypeInfo();

    /**
     * Address: 0x005AFB30 (FUN_005AFB30, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiPathNavigatorTypeInfo() override;

    /**
     * Address: 0x005AFB20 (FUN_005AFB20, ?GetName@CAiPathNavigatorTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AFAD0 (FUN_005AFAD0, ?Init@CAiPathNavigatorTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;

    /**
     * Address: 0x005B0930 (FUN_005B0930, Moho::CAiPathNavigatorTypeInfo::AddBase_Listener_NavPath)
     */
    static void __stdcall AddBase_Listener_NavPath(gpg::RType* typeInfo);

    /**
     * Address: 0x005B0740 (FUN_005B0740, Moho::CAiPathNavigatorTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CAiPathNavigator` and returns a reflection reference to
     * the constructed object.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x005B07E0 (FUN_005B07E0, Moho::CAiPathNavigatorTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CAiPathNavigator` in caller-provided storage and returns
     * a reflection reference to it.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x005B07C0 (FUN_005B07C0, Moho::CAiPathNavigatorTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x005B0850 (FUN_005B0850, Moho::CAiPathNavigatorTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CAiPathNavigatorTypeInfo) == 0x64, "CAiPathNavigatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCD020 (FUN_00BCD020, register_CAiPathNavigatorTypeInfo)
   *
   * What it does:
   * Constructs the recovered `CAiPathNavigatorTypeInfo` startup owner and
   * installs process-exit cleanup.
   */
  void register_CAiPathNavigatorTypeInfo();
} // namespace moho
