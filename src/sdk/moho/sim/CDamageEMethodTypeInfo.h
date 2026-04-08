#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/CDamage.h"

namespace moho
{
  /**
   * Owns reflected metadata for `CDamageMethod`.
   */
  class CDamageEMethodTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00738440 (FUN_00738440, Moho::CDamageEMethodTypeInfo::dtr)
     *
     * What it does:
     * Releases one `CDamageMethod` enum descriptor instance.
     */
    ~CDamageEMethodTypeInfo() override;

    /**
     * Address: 0x00738430 (FUN_00738430, Moho::CDamageEMethodTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected enum type label `"CDamage::EMethod"`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00738410 (FUN_00738410, Moho::CDamageEMethodTypeInfo::Init)
     *
     * What it does:
     * Sets enum width, runs base reflection initialization, registers enum
     * names/values, and finishes type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00738470 (FUN_00738470, Moho::CDamageEMethodTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `CDamage::` method enum lexical/value mapping.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(CDamageEMethodTypeInfo) == 0x78, "CDamageEMethodTypeInfo size must be 0x78");

  /**
   * Address: 0x007383B0 (FUN_007383B0, preregister_CDamageEMethodTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the process-global `CDamageEMethodTypeInfo`
   * descriptor for `typeid(CDamageMethod)`.
   */
  [[nodiscard]] gpg::REnumType* preregister_CDamageEMethodTypeInfo();

  /**
   * Address: 0x00BDB710 (FUN_00BDB710, register_CDamageEMethodTypeInfo)
   *
   * What it does:
   * Runs preregistration and installs process-exit cleanup for
   * `CDamageEMethodTypeInfo`.
   */
  int register_CDamageEMethodTypeInfo();
} // namespace moho
