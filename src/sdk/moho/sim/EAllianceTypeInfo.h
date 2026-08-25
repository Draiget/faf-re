#pragma once

#include <cstddef>
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
    // Sentinel "no alliance filter" value used by build-placement / target
    // scanners (e.g. CAiBrain::CanBuildStructureAt) to disable the alliance gate.
    ALLIANCE_None = 3,
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

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAlliance,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAlliance@Moho@@H@gpg'`):
   * `FUN_00BC7A30` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at 0x0050A600 (compiler/linker artifact, no source line -- see the
   * class-level Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h).
   *
   * The previous raw-struct recovery of this instantiation also modeled a
   * "secondary" startup thunk at 0x0050A960 as if it were a duplicate
   * emission of this same ctor. It is not: per `vtable_writers`, 0x0050A960
   * is the (itself dead, zero-xref) ctor of the unrelated template
   * instantiation `gpg::SerSaveLoadHelper<Moho::EAlliance>`
   * (`class_name='?$SerSaveLoadHelper@W4EAlliance@Moho@@@gpg'`), a distinct
   * ~50-instantiation template family (see `ArchiveSerialization.cpp` and
   * friends) that has not been canonicalized and is out of scope here.
   */
  using EAlliancePrimitiveSerializer = gpg::PrimitiveSerHelper<EAlliance, int>;

  /**
   * Address: 0x00BC7A10 (FUN_00BC7A10, register_EAllianceTypeInfo)
   *
   * What it does:
   * Runs `EAlliance` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EAllianceTypeInfo();
} // namespace moho
