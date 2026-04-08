#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SFootprint;

  /**
   * Owns reflected metadata for `SFootprint`.
   */
  class SFootprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050C410 (FUN_0050C410, Moho::SFootprintTypeInfo::SFootprintTypeInfo)
     *
     * What it does:
     * Preregisters the `SFootprint` RTTI descriptor with the reflection map.
     */
    SFootprintTypeInfo();

    /**
     * Address: 0x0050C4A0 (FUN_0050C4A0, Moho::SFootprintTypeInfo::dtr)
     *
     * What it does:
     * Releases the `SFootprint` reflection descriptor lanes.
     */
    ~SFootprintTypeInfo() override;

    /**
     * Address: 0x0050C490 (FUN_0050C490, Moho::SFootprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SFootprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050C470 (FUN_0050C470, Moho::SFootprintTypeInfo::Init)
     *
     * What it does:
     * Sets reflected width, registers field metadata, and finalizes the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0050C540 (FUN_0050C540, Moho::SFootprintTypeInfo::AddFields)
     *
     * What it does:
     * Registers reflected lanes for all `SFootprint` members in binary order.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC7E40 (FUN_00BC7E40, register_SFootprintTypeInfo)
   *
   * What it does:
   * Installs the static `SFootprintTypeInfo` instance and its shutdown hook.
   */
  void register_SFootprintTypeInfo();

  /**
   * Address: 0x00BC7E60 (FUN_00BC7E60, register_SFootprintSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `SFootprint` and registers shutdown
   * unlink/destruction.
   */
  void register_SFootprintSerializer();

  static_assert(sizeof(SFootprintTypeInfo) == 0x64, "SFootprintTypeInfo size must be 0x64");
} // namespace moho
