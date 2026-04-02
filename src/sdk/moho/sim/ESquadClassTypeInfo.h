#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/ESquadClass.h"

namespace moho
{
  /**
   * Owns reflected metadata for the `ESquadClass` enum.
   */
  class ESquadClassTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00723BA0 (FUN_00723BA0, Moho::ESquadClassTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the enum descriptor.
     */
    ~ESquadClassTypeInfo() override;

    /**
     * Address: 0x00723B90 (FUN_00723B90, Moho::ESquadClassTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected enum label.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00723B70 (FUN_00723B70, Moho::ESquadClassTypeInfo::Init)
     *
     * What it does:
     * Writes enum-size metadata, installs enum values, then finalizes the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00723BD0 (FUN_00723BD0, Moho::ESquadClassTypeInfo::AddEnums)
     *
     * What it does:
     * Registers `SQUADCLASS_` lexical tokens and mapped integer values.
     */
    void AddEnums();
  };

  static_assert(sizeof(ESquadClassTypeInfo) == 0x78, "ESquadClassTypeInfo size must be 0x78");
} // namespace moho

