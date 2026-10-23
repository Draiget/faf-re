#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "Wm3Sphere3.h"

namespace moho
{
  /**
   * Owns reflected metadata for `CColPrimitive<Wm3::Sphere3<float>>`.
   */
  class DColPrimSphereTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004FE6D0 (FUN_004FE6D0, Moho::DColPrimSphereTypeInfo::dtr)
     * Slot: 2
     */
    ~DColPrimSphereTypeInfo() override;

    /**
     * Address: 0x004FE6C0 (FUN_004FE6C0, Moho::DColPrimSphereTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `DColPrimSphere`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004FE6A0 (FUN_004FE6A0, Moho::DColPrimSphereTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CColPrimitive<Wm3::Sphere3<float>>`
     * (`sizeof = 0x20`) and adds the `CColPrimitiveBase` base lane.
     */
    void Init() override;

    /**
     * Address: 0x00500390 (FUN_00500390, Moho::DColPrimSphereTypeInfo::AddBase_CColPrimitiveBase)
     *
     * What it does:
     * Registers `CColPrimitiveBase` as this type's reflected base at offset 0.
     */
    static void AddBase_CColPrimitiveBase(gpg::RType* typeInfo);
  };

  static_assert(sizeof(DColPrimSphereTypeInfo) == 0x64, "DColPrimSphereTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC7550 (FUN_00BC7550, register_DColPrimSphereTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimSphereTypeInfo` instance.
   */
  void register_DColPrimSphereTypeInfo();

  template <class T>
  [[nodiscard]] const T& Invalid();

  /**
   * Address: 0x00473050 (FUN_00473050, Moho::Invalid<Wm3::Sphere3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid Sphere3f (center/radius set to NaN).
   */
  template <>
  [[nodiscard]] const Wm3::Sphere3f& Invalid<Wm3::Sphere3f>();
} // namespace moho
