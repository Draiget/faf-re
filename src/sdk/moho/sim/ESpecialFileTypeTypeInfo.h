#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SpecialFileType.h"

namespace moho
{
  /**
   * Owns reflected metadata for `ESpecialFileType`.
   */
  class ESpecialFileTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x008CA250 (FUN_008CA250, Moho::ESpecialFileTypeTypeInfo::dtr)
     *
     * What it does:
     * Releases one `ESpecialFileType` enum descriptor instance.
     */
    ~ESpecialFileTypeTypeInfo() override;

    /**
     * Address: 0x008CA240 (FUN_008CA240, Moho::ESpecialFileTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected enum type label `"ESpecialFileType"`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x008CA220 (FUN_008CA220, Moho::ESpecialFileTypeTypeInfo::Init)
     *
     * What it does:
     * Sets enum width, runs base reflection initialization, registers enum
     * names/values, and finishes type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x008CA280 (FUN_008CA280, Moho::ESpecialFileTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `SFT_` enum lexical/value mapping.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(ESpecialFileTypeTypeInfo) == 0x78, "ESpecialFileTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x008CA1C0 (FUN_008CA1C0, preregister_ESpecialFileTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the process-global `ESpecialFileTypeTypeInfo`
   * descriptor for `typeid(ESpecialFileType)`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESpecialFileTypeTypeInfo();

  /**
   * Address: 0x00BE8C00 (FUN_00BE8C00, register_ESpecialFileTypeTypeInfo)
   *
   * What it does:
   * Runs preregistration and installs process-exit cleanup for
   * `ESpecialFileTypeTypeInfo`.
   */
  int register_ESpecialFileTypeTypeInfo();
} // namespace moho
