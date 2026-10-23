#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SNamedFootprint;

  /**
   * Owns reflected metadata for `SNamedFootprint`: `SFootprint` as its base at
   * offset 0, then `Name` and `Index`.
   */
  class SNamedFootprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * What it does:
     * Preregisters this descriptor for `typeid(SNamedFootprint)`; inlined into
     * `preregister_SNamedFootprintTypeInfo` 0x00513CF0.
     */
    SNamedFootprintTypeInfo();

    /**
     * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
     * Address: 0x00513E00 (the non-deleting body out of line: the field and base vectors freed and the
     * `RObject` vptr restored; not an IDA function, no references in the PE)
     *
     * What it does:
     * Releases the reflected field and base vector storage.
     */
    ~SNamedFootprintTypeInfo() override;

    /**
     * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SNamedFootprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size, installs the base and fields, and finalizes the
     * type.
     */
    void Init() override;

    /**
     * Address: 0x00514680 (FUN_00514680)
     *
     * What it does:
     * Registers `SFootprint` as this type's reflected base at offset 0, looking
     * its type up once into `SFootprint::sType` (0x010C6D94).
     */
    static void AddBase_SFootprint(gpg::RType* typeInfo);

  private:
    /**
     * Address: 0x00513E40 (the out-of-line copy, not an IDA function and with no references in the PE:
     * `Init` 0x00513D50 inlines it)
     *
     * What it does:
     * The `SFootprint` base, then `Name` (`msvc8::string` at +0x10) and
     * `Index` (`int` at +0x2C).
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  static_assert(sizeof(SNamedFootprintTypeInfo) == 0x64, "SNamedFootprintTypeInfo size must be 0x64");

  /**
   * Address: 0x00513CF0 (FUN_00513CF0, preregister_SNamedFootprintTypeInfo)
   * Address: 0x00BF2820 (FUN_00BF2820, atexit destructor of the SNamedFootprintTypeInfo object)
   *
   * What it does:
   * Constructs the `SNamedFootprintTypeInfo` static at 0x010AA9A8, which
   * preregisters it, and returns it.
   */
  [[nodiscard]] gpg::RType* preregister_SNamedFootprintTypeInfo();

  /**
   * Address: 0x00BC8360 (FUN_00BC8360, register_SNamedFootprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SNamedFootprint` RTTI.
   */
  void register_SNamedFootprintTypeInfoStartup();

  /**
   * Address: 0x005149D0 (FUN_005149D0, preregister_SNamedFootprintListTypeInfo)
   * Address: 0x00BF2910 (FUN_00BF2910, atexit destructor of the list type object)
   *
   * What it does:
   * Constructs the `gpg::RListType<SNamedFootprint>` static at 0x011047E8,
   * which preregisters it for `typeid(msvc8::list<SNamedFootprint>)`, and
   * returns it.
   */
  [[nodiscard]] gpg::RType* preregister_SNamedFootprintListTypeInfo();

  /**
   * Address: 0x00BC83A0 (FUN_00BC83A0, register_SNamedFootprintListTypeInfoStartup)
   *
   * What it does:
   * Preregisters `msvc8::list<SNamedFootprint>` RTTI.
   */
  void register_SNamedFootprintListTypeInfoStartup();
} // namespace moho
