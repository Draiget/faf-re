#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/IAiSiloBuild.h"
#include "moho/misc/CEconomyEvent.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class Unit;
  class UnitWeapon;

  enum ESiloBuildStage : std::int32_t
  {
    SBS_Idle = 0,
    SBS_Prepare = 1,
    SBS_Active = 2,
    SBS_Finish = 3,
  };

  struct SSiloBuildInfo
  {
    UnitWeapon* mWeapon;           // +0x00
    std::int32_t mAmmo;            // +0x04
    std::int32_t mMaxStorageCount; // +0x08
  };

  struct SSiloTypeListNode
  {
    SSiloTypeListNode* mNext; // +0x00
    SSiloTypeListNode* mPrev; // +0x04
    ESiloType mValue;         // +0x08
  };

  struct SSiloTypeList
  {
    void* mProxyOrUnused;     // +0x00
    SSiloTypeListNode* mHead; // +0x04
    std::int32_t mSize;       // +0x08
  };

  /**
   * VFTABLE: 0x00E1DDD4
   * COL:  0x00E7498C
   */
  class CAiSiloBuildImpl : public IAiSiloBuild
  {
  public:
    /**
     * Address: 0x005CED30 (FUN_005CED30, ??0CAiSiloBuildImpl@Moho@@QAE@PAVUnit@1@@Z)
     *
     * Moho::Unit *
     *
     * What it does:
     * Initializes silo slots/queue state and refreshes linked weapon info.
     */
    explicit CAiSiloBuildImpl(Unit* unit);

    /**
     * Address: 0x005CF640 (FUN_005CF640, scalar deleting thunk)
     * Address: 0x005CEDF0 (FUN_005CEDF0, core dtor)
     *
     * VFTable SLOT: 0
     */
    ~CAiSiloBuildImpl() override;

    /**
     * Address: 0x005CEE40 (FUN_005CEE40, ?SiloUpdateProjectileBlueprint@CAiSiloBuildImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 1
     */
    void SiloUpdateProjectileBlueprint() override;

    /**
     * Address: 0x005CEF00 (FUN_005CEF00, ?SiloIsBusy@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 2
     */
    [[nodiscard]]
    bool SiloIsBusy(ESiloType type) const override;

    /**
     * Address: 0x005CEF20 (FUN_005CEF20, ?SiloIsFull@CAiSiloBuildImpl@Moho@@UBE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    bool SiloIsFull(ESiloType type) const override;

    /**
     * Address: 0x005CEF50 (FUN_005CEF50, ?SiloGetBuildCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    std::int32_t SiloGetBuildCount(ESiloType type) const override;

    /**
     * Address: 0x005CEF80 (FUN_005CEF80, ?SiloGetStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 5
     */
    [[nodiscard]]
    std::int32_t SiloGetStorageCount(ESiloType type) const override;

    /**
     * Address: 0x005CEF90 (FUN_005CEF90, ?SiloGetMaxStorageCount@CAiSiloBuildImpl@Moho@@UBEHW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 6
     */
    [[nodiscard]]
    std::int32_t SiloGetMaxStorageCount(ESiloType type) const override;

    /**
     * Address: 0x005CEFA0 (FUN_005CEFA0, ?SiloAdjustStorageCount@CAiSiloBuildImpl@Moho@@UAEXW4ESiloType@2@H@Z)
     *
     * VFTable SLOT: 7
     */
    void SiloAdjustStorageCount(ESiloType type, std::int32_t delta) override;

    /**
     * Address: 0x005CEFC0 (FUN_005CEFC0, ?SiloAddBuild@CAiSiloBuildImpl@Moho@@UAE_NW4ESiloType@2@@Z)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    bool SiloAddBuild(ESiloType type) override;

    /**
     * Address: 0x005CF1E0 (FUN_005CF1E0, ?SiloTick@CAiSiloBuildImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void SiloTick() override;

    /**
     * Address: 0x005CF030 (FUN_005CF030, ?SiloAssistWithResource@CAiSiloBuildImpl@Moho@@UAEXABUSEconValue@2@@Z)
     *
     * VFTable SLOT: 10
     */
    void SiloAssistWithResource(const SEconValue& value) override;

    /**
     * Address: 0x005CF130 (FUN_005CF130, ?SiloStopBuild@CAiSiloBuildImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 11
     */
    void SiloStopBuild() override;

  public:
    static gpg::RType* sType;

    Unit* mUnit;                  // +0x04
    SSiloBuildInfo mSiloInfo[2];  // +0x08
    SSiloTypeList mSiloTypes;     // +0x20
    CEconRequest* mRequest;       // +0x2C
    ESiloBuildStage mState;       // +0x30
    SEconValue mSegmentCost;      // +0x34
    SEconValue mSegmentSpent;     // +0x3C
    float mSegments;              // +0x44
    std::int32_t mCurSegments;    // +0x48
  };

  static_assert(sizeof(SSiloBuildInfo) == 0x0C, "SSiloBuildInfo size must be 0x0C");
  static_assert(sizeof(SSiloTypeListNode) == 0x0C, "SSiloTypeListNode size must be 0x0C");
  static_assert(sizeof(SSiloTypeList) == 0x0C, "SSiloTypeList size must be 0x0C");
  static_assert(offsetof(CAiSiloBuildImpl, mUnit) == 0x04, "CAiSiloBuildImpl::mUnit offset must be 0x04");
  static_assert(offsetof(CAiSiloBuildImpl, mSiloInfo) == 0x08, "CAiSiloBuildImpl::mSiloInfo offset must be 0x08");
  static_assert(offsetof(CAiSiloBuildImpl, mSiloTypes) == 0x20, "CAiSiloBuildImpl::mSiloTypes offset must be 0x20");
  static_assert(offsetof(CAiSiloBuildImpl, mRequest) == 0x2C, "CAiSiloBuildImpl::mRequest offset must be 0x2C");
  static_assert(offsetof(CAiSiloBuildImpl, mState) == 0x30, "CAiSiloBuildImpl::mState offset must be 0x30");
  static_assert(offsetof(CAiSiloBuildImpl, mSegmentCost) == 0x34, "CAiSiloBuildImpl::mSegmentCost offset must be 0x34");
  static_assert(offsetof(CAiSiloBuildImpl, mSegmentSpent) == 0x3C, "CAiSiloBuildImpl::mSegmentSpent offset must be 0x3C");
  static_assert(offsetof(CAiSiloBuildImpl, mSegments) == 0x44, "CAiSiloBuildImpl::mSegments offset must be 0x44");
  static_assert(offsetof(CAiSiloBuildImpl, mCurSegments) == 0x48, "CAiSiloBuildImpl::mCurSegments offset must be 0x48");
  static_assert(sizeof(CAiSiloBuildImpl) == 0x4C, "CAiSiloBuildImpl size must be 0x4C");
} // namespace moho
