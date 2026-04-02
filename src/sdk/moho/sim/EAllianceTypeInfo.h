#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Owns the reflected enum descriptor for `EAlliance`.
   */
  enum EAlliance : std::int32_t
  {
    ALLIANCE_Neutral = 0,
    ALLIANCE_Ally = 1,
    ALLIANCE_Enemy = 2,
  };

  static_assert(sizeof(EAlliance) == 0x04, "EAlliance size must be 0x04");

  /**
   * Owns reflected metadata for the `EAlliance` enum.
   */
  class EAllianceTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00509DF0 (FUN_00509DF0, Moho::EAllianceTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the `EAlliance` enum descriptor.
     */
    ~EAllianceTypeInfo() override;

    /**
     * Address: 0x00509DE0 (FUN_00509DE0, Moho::EAllianceTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EAlliance`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00509DC0 (FUN_00509DC0, Moho::EAllianceTypeInfo::Init)
     *
     * What it does:
     * Writes the enum width, installs values, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00509E20 (FUN_00509E20, Moho::EAllianceTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `ALLIANCE_` enum names and values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAllianceTypeInfo) == 0x78, "EAllianceTypeInfo size must be 0x78");
} // namespace moho
