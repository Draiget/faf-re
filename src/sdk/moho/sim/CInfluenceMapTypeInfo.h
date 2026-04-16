#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CInfluenceMapTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00717490 (FUN_00717490, sub_717490)
     *
     * What it does:
     * Preregisters CInfluenceMap RTTI with the reflection system.
     */
    CInfluenceMapTypeInfo();

    /**
     * Address: 0x00717520 (FUN_00717520, Moho::CInfluenceMapTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting destructor thunk for CInfluenceMapTypeInfo.
     */
    ~CInfluenceMapTypeInfo() override;

    /**
     * Address: 0x00717510 (FUN_00717510, Moho::CInfluenceMapTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for CInfluenceMap.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007174F0 (FUN_007174F0, Moho::CInfluenceMapTypeInfo::Init)
     *
     * What it does:
     * Sets CInfluenceMap size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(CInfluenceMapTypeInfo) == 0x64, "CInfluenceMapTypeInfo size must be 0x64");

  /**
   * Owns reflected metadata for the `EThreatType` enum.
   */
  class EThreatTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x007154D0 (FUN_007154D0, Moho::EThreatTypeTypeInfo::EThreatTypeTypeInfo)
     *
     * What it does:
     * Preregisters `EThreatType` enum metadata with the reflection runtime.
     */
    EThreatTypeTypeInfo();

    /**
     * Address: 0x00715580 (FUN_00715580, j_??1REnumType@gpg@@QAE@@Z_48)
     *
     * What it does:
     * Scalar deleting-destructor thunk lane for `EThreatTypeTypeInfo`.
     */
    ~EThreatTypeTypeInfo() override;

    /**
     * Address: 0x00715550 (FUN_00715550, Moho::EThreatTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EThreatType`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00715530 (FUN_00715530, Moho::EThreatTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum size metadata, registers enum entries, and finalizes.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00715590 (FUN_00715590, Moho::EThreatTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `THREATTYPE_` enum names and numeric values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EThreatTypeTypeInfo) == 0x78, "EThreatTypeTypeInfo size must be 0x78");

  /**
   * What it does:
   * Forces EThreatType type-info startup materialization.
   */
  void register_EThreatTypeTypeInfo();
} // namespace moho
