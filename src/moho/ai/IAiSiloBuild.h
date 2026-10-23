#pragma once

#include <cstdint>

namespace gpg
{
  class RType;
}

namespace moho
{
  struct SEconValue;
  class Unit;

  enum ESiloType : std::int32_t
  {
    SILOTYPE_Tactical = 0,
    SILOTYPE_Nuke = 1,
  };

  class IAiSiloBuild
  {
  public:
    /**
     * Address: 0x005CE850 (FUN_005CE850, ??0IAiSiloBuild@Moho@@QAE@XZ)
     * Address: 0x005CF660 (FUN_005CF660)
     *
     * VFTable SLOT: construction lane
     *
     * What it does:
     * Initializes one silo-build interface base object; the second constructor
     * lane is an equivalent alias.
     */
    IAiSiloBuild();

    /**
     * Address: 0x005CE860 (FUN_005CE860, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiSiloBuild();

    /**
     * Address: 0x005CEE40 (FUN_005CEE40)
     *
     * VFTable SLOT: 1
     */
    virtual void SiloUpdateProjectileBlueprint() = 0;

    /**
     * Address: 0x005CEF00 (FUN_005CEF00, ?SiloIsBusy@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 2
     */
    [[nodiscard]]
    virtual bool SiloIsBusy(ESiloType type) const = 0;

    /**
     * Address: 0x005CEF20 (FUN_005CEF20, ?SiloIsFull@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    virtual bool SiloIsFull(ESiloType type) const = 0;

    /**
     * Address: 0x005CEF50 (FUN_005CEF50, ?SiloGetBuildCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    virtual std::int32_t SiloGetBuildCount(ESiloType type) const = 0;

    /**
     * Address: 0x005CEF80 (FUN_005CEF80, ?SiloGetStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 5
     */
    [[nodiscard]]
    virtual std::int32_t SiloGetStorageCount(ESiloType type) const = 0;

    /**
     * Address: 0x005CEF90 (FUN_005CEF90, ?SiloGetMaxStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 6
     */
    [[nodiscard]]
    virtual std::int32_t SiloGetMaxStorageCount(ESiloType type) const = 0;

    /**
     * Address: 0x005CEFA0 (FUN_005CEFA0, ?SiloAdjustStorageCount@CAiSiloBuildImpl@Moho@@UAEXW4ESiloType@2@H@Z)
     *
     * VFTable SLOT: 7
     */
    virtual void SiloAdjustStorageCount(ESiloType type, std::int32_t delta) = 0;

    /**
     * Address: 0x005CEFC0 (FUN_005CEFC0, ?SiloAddBuild@CAiSiloBuildImpl@Moho@@UAE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    virtual bool SiloAddBuild(ESiloType type) = 0;

    /**
     * Address: 0x005CF1E0 (FUN_005CF1E0, ?SiloTick@CAiSiloBuildImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    virtual void SiloTick() = 0;

    /**
     * Address: 0x005CF030 (FUN_005CF030, ?SiloAssistWithResource@CAiSiloBuildImpl@Moho@@UAEXABUSEconValue@2@@Z)
     *
     * VFTable SLOT: 10
     */
    virtual void SiloAssistWithResource(const SEconValue& value) = 0;

    /**
     * Address: 0x005CF130 (FUN_005CF130, ?SiloStopBuild@CAiSiloBuildImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 11
     */
    virtual void SiloStopBuild() = 0;

  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(IAiSiloBuild) == 0x04, "IAiSiloBuild size must be 0x04");

  /**
   * Address: 0x005CF980 (FUN_005CF980, ?AI_CreateSiloBuilder@Moho@@YAPAVIAiSiloBuild@1@PAVUnit@1@@Z)
   *
   * What it does:
   * Allocates one `CAiSiloBuildImpl` bound to `unit` and returns it as
   * `IAiSiloBuild`.
   */
  [[nodiscard]] IAiSiloBuild* AI_CreateSiloBuilder(Unit* unit);
} // namespace moho
