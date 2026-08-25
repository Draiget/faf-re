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

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESquadClass,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESquadClass@Moho@@H@gpg'`):
   * `FUN_00BDAB80` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0072A4A0`. A third writer for the same global's storage address,
   * `FUN_0072A9F0` (demangled `gpg::SerSaveLoadHelper<Moho::ESquadClass>`),
   * is itself zero-xref/unreachable -- same sibling-writer pattern already
   * documented for `EAlliance`/`ELayer`/`EVisibilityMode` on the template
   * itself (see `Reflection.h`). There is no real `SerSaveLoadHelper<
   * ESquadClass>` instance in this binary; only the `PrimitiveSerHelper`
   * instantiation is ever constructed.
   *
   * The real ctor's tail pushes plain, unmangled `FUN_00C00440` as its
   * `atexit` target (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) -- modeled by the template's own real
   * destructor, no explicit `atexit` call needed.
   */
  using ESquadClassPrimitiveSerializer = gpg::PrimitiveSerHelper<ESquadClass, int>;
} // namespace moho

