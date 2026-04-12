#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/Entity.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
  class WriteArchive;
  class RType;
} // namespace gpg

namespace moho
{
  class CAniPose;
  class CArmyImpl;
  struct RMeshBlueprint;
  class RScmResource;
  class Sim;
  class Unit;
  enum EReconFlags : std::int32_t;

  /**
   * Per-army recon state block owned by `ReconBlip::mReconDat`.
   *
   * Address family:
   * - 0x005BE6E0 (`ReconBlip` ctor init payload passed to `sub_5C5460`)
   * - 0x005C1B90 (`CAiReconDBImpl::RefreshBlip`)
   * - 0x005C1CF0 (`CAiReconDBImpl::UpdateBlip`)
   * - 0x005C21F0 (`CAiReconDBImpl::DeleteBlip`)
   */
  struct SPerArmyReconInfo
  {
    std::uint8_t mNeedsFlush;                   // +0x00
    std::uint8_t pad_01_03[0x03];               // +0x01
    std::uint32_t mReconFlags;                  // +0x04
    union
    {
      std::int32_t mMeshTypeClassId;            // +0x08
      RMeshBlueprint* mStiMesh;                 // +0x08
    };
    boost::SharedPtrRaw<RScmResource> mMesh;    // +0x0C
    boost::SharedPtrRaw<CAniPose> mPriorPose;   // +0x14
    boost::SharedPtrRaw<CAniPose> mPose;        // +0x1C
    float mHealth;                              // +0x24
    float mMaxHealth;                           // +0x28
    float mFractionComplete;                    // +0x2C
    std::uint8_t mMaybeDead;                    // +0x30
    std::uint8_t pad_31_33[0x03];               // +0x31

    /**
     * Address: 0x005C4F50 (FUN_005C4F50, Moho::SPerArmyReconInfo::~SPerArmyReconInfo)
     *
     * What it does:
     * Releases shared recon snapshot lanes (`mPose`, `mPriorPose`, `mMesh`)
     * in binary destructor order.
     */
    ~SPerArmyReconInfo();

    /**
     * Address: 0x005C8DE0 (FUN_005C8DE0, Moho::SPerArmyReconInfo::MemberDeserialize)
     *
     * What it does:
     * Deserializes one per-army recon snapshot lane.
     */
    void MemberDeserialize(gpg::ReadArchive* archive, int version);

    /**
     * Address: 0x005C8ED0 (FUN_005C8ED0, Moho::SPerArmyReconInfo::MemberSerialize)
     *
     * What it does:
     * Serializes one per-army recon snapshot lane.
     */
    void MemberSerialize(gpg::WriteArchive* archive, int version);

    static gpg::RType* sType;
  };

  static_assert(sizeof(SPerArmyReconInfo) == 0x34, "SPerArmyReconInfo size must be 0x34");
  static_assert(offsetof(SPerArmyReconInfo, mNeedsFlush) == 0x00, "SPerArmyReconInfo::mNeedsFlush offset must be 0x00");
  static_assert(offsetof(SPerArmyReconInfo, mReconFlags) == 0x04, "SPerArmyReconInfo::mReconFlags offset must be 0x04");
  static_assert(
    offsetof(SPerArmyReconInfo, mMeshTypeClassId) == 0x08, "SPerArmyReconInfo::mMeshTypeClassId offset must be 0x08"
  );
  static_assert(offsetof(SPerArmyReconInfo, mStiMesh) == 0x08, "SPerArmyReconInfo::mStiMesh offset must be 0x08");
  static_assert(offsetof(SPerArmyReconInfo, mMesh) == 0x0C, "SPerArmyReconInfo::mMesh offset must be 0x0C");
  static_assert(offsetof(SPerArmyReconInfo, mPriorPose) == 0x14, "SPerArmyReconInfo::mPriorPose offset must be 0x14");
  static_assert(offsetof(SPerArmyReconInfo, mPose) == 0x1C, "SPerArmyReconInfo::mPose offset must be 0x1C");
  static_assert(offsetof(SPerArmyReconInfo, mHealth) == 0x24, "SPerArmyReconInfo::mHealth offset must be 0x24");
  static_assert(offsetof(SPerArmyReconInfo, mMaxHealth) == 0x28, "SPerArmyReconInfo::mMaxHealth offset must be 0x28");
  static_assert(
    offsetof(SPerArmyReconInfo, mFractionComplete) == 0x2C,
    "SPerArmyReconInfo::mFractionComplete offset must be 0x2C"
  );
  static_assert(offsetof(SPerArmyReconInfo, mMaybeDead) == 0x30, "SPerArmyReconInfo::mMaybeDead offset must be 0x30");

  /**
   * Constant unit data slice stored on a `ReconBlip` for `CreateInterface` dispatch.
   *
   * Binary layout is identical to `SSTIUnitConstantData` and `SCreateUnitConstantData`;
   * named separately here to tie the ownership to the recon blip copy path.
   *
   * Evidence:
   * - `ReconBlip::CreateInterface` (0x005BEE90): copies mBuildStateTag, mStatsRoot, mFake
   *   into a `SCreateUnitParams::mConstDat` packet and pushes to `SSyncData::mNewUnits`.
   */
  struct SReconBlipUnitConstData
  {
    std::uint8_t mBuildStateTag = 0;                    // +0x00
    std::uint8_t mPad01[3] = {};                        // +0x01
    boost::shared_ptr<Stats<StatItem>> mStatsRoot{};    // +0x04
    std::uint8_t mFake = 0;                             // +0x0C
    std::uint8_t mPad0D[3] = {};                        // +0x0D
  };

  static_assert(sizeof(SReconBlipUnitConstData) == 0x10, "SReconBlipUnitConstData size must be 0x10");
  static_assert(
    offsetof(SReconBlipUnitConstData, mStatsRoot) == 0x04,
    "SReconBlipUnitConstData::mStatsRoot offset must be 0x04"
  );
  static_assert(
    offsetof(SReconBlipUnitConstData, mFake) == 0x0C, "SReconBlipUnitConstData::mFake offset must be 0x0C"
  );

  /**
   * Opaque `SSTIUnitVariableData` payload for ReconBlip.
   */
  struct SReconBlipUnitVarData
  {
    std::uint8_t mPad00_09[0x0A];      // +0x00
    std::uint8_t mHasLinkedSource;     // +0x0A
    std::uint8_t mPad0B_43[0x39];      // +0x0B
    msvc8::string mCustomName;          // +0x44
    std::uint8_t mPad60_207[0x1A8];    // +0x60
    std::uint8_t mBlueprintState0;     // +0x208
    std::uint8_t mBlueprintState1;     // +0x209
    std::uint8_t mPad20A_227[0x1E];    // +0x20A
  };

  static_assert(sizeof(SReconBlipUnitVarData) == 0x228, "SReconBlipUnitVarData size must be 0x228");
  static_assert(
    offsetof(SReconBlipUnitVarData, mHasLinkedSource) == 0x0A,
    "SReconBlipUnitVarData::mHasLinkedSource offset must be 0x0A"
  );
  static_assert(
    offsetof(SReconBlipUnitVarData, mCustomName) == 0x44,
    "SReconBlipUnitVarData::mCustomName offset must be 0x44"
  );
  static_assert(
    offsetof(SReconBlipUnitVarData, mBlueprintState0) == 0x208,
    "SReconBlipUnitVarData::mBlueprintState0 offset must be 0x208"
  );
  static_assert(
    offsetof(SReconBlipUnitVarData, mBlueprintState1) == 0x209,
    "SReconBlipUnitVarData::mBlueprintState1 offset must be 0x209"
  );

  /**
   * VFTABLE: 0x00E1D824
   * COL:  0x00E743E8
   */
  class ReconBlip : public Entity
  {
  public:
    [[nodiscard]] static gpg::RType* StaticGetClass();

    static gpg::RType* sType;
    static gpg::RType* sPointerType;

    /**
     * Address: 0x005C6470 (FUN_005C6470, Moho::ReconBlip::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for `ReconBlip*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x005BED70 (FUN_005BED70, Moho::ReconBlip::ReconBlip)
     *
     * Sim *
     *
     * IDA signature:
     * Moho::ReconBlip *__stdcall Moho::ReconBlip::ReconBlip(Moho::ReconBlip *this, Moho::Sim *sim);
     *
     * What it does:
     * Constructs serializer-load baseline state for `ReconBlip`.
     */
    explicit ReconBlip(Sim* sim);

    /**
     * Address: 0x005BE6E0 (FUN_005BE6E0)
     *
     * Unit *,Sim *,bool
     *
     * IDA signature:
     * Moho::ReconBlip *__userpurge Moho::ReconBlip::ReconBlip@<eax>(
     *   Moho::Unit *unit@<ebx>, Moho::ReconBlip *this, Moho::Sim *sim, char fake);
     *
     * What it does:
     * Constructs a recon blip from `unit`, allocates a 0x3xx-family entity id,
     * initializes per-army recon state storage, and performs an initial refresh.
     */
    ReconBlip(Unit* sourceUnit, Sim* sim, bool fake);

    /**
     * Address: 0x005BFBE0 (FUN_005BFBE0, Moho::ReconBlip::MemberConstruct)
     *
     * gpg::ReadArchive &,int,gpg::RRef const &,gpg::SerConstructResult &
     *
     * What it does:
     * Reads serializer construct args (`Sim*`), allocates one `ReconBlip`, and
     * returns it as an unowned construct result.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x005BEE90 (FUN_005BEE90)
     * Mangled: ?CreateInterface@ReconBlip@Moho@@MAEXPAUSSyncData@2@@Z
     *
     * What it does:
     * Copies constant-data from this blip (mUnitConstDat) into a
     * `SCreateUnitParams` packet and appends it to `syncData->mNewUnits`,
     * then marks `mInterfaceCreated = 1`.
     */
    void CreateInterface(SSyncData* syncData) override;

    /**
     * Address: 0x005BDE90 (FUN_005BDE90)
     *
     * What it does:
     * Runtime identity virtual for entity recon blips.
     */
    ReconBlip* IsReconBlip() override;

    /**
     * Address: 0x005BEE80 (FUN_005BEE80)
     *
     * What it does:
     * Returns the source unit blueprint pointer stored on this blip.
     */
    [[nodiscard]] const RUnitBlueprint* GetBlueprint() const;

    /**
     * Address: 0x00579670 (FUN_00579670, Moho::ReconBlip::GetCreator)
     *
     * What it does:
     * Returns the linked source-unit pointer from `mCreator` or null when this
     * blip is detached.
     */
    [[nodiscard]] Unit* GetCreator() const noexcept;

    /**
     * Address: 0x005BDF00 (FUN_005BDF00, Moho::ReconBlip::GetFlags)
     *
     * What it does:
     * Returns one army-local recon bitmask by direct army-index lane lookup.
     */
    [[nodiscard]] EReconFlags GetFlags(std::int32_t armyIndex) const;

    /**
     * Address: 0x005BDF10 (FUN_005BDF10, Moho::ReconBlip::GetFlags)
     *
     * What it does:
     * Returns one army-local recon bitmask by owning army object.
     */
    [[nodiscard]] EReconFlags GetFlags(CArmyImpl* army) const;

    /**
     * Address: 0x005BDF30 (FUN_005BDF30, Moho::ReconBlip::IsKnownFake)
     *
     * What it does:
     * Returns whether this blip is marked `RECON_KnownFake` for the queried
     * army lane.
     */
    [[nodiscard]] bool IsKnownFake(CArmyImpl* army) const;

    /**
     * Address: 0x005BDF50 (FUN_005BDF50, Moho::ReconBlip::IsOnRadar)
     *
     * What it does:
     * Returns whether this blip is currently radar-visible for the queried army
     * lane.
     */
    [[nodiscard]] bool IsOnRadar(CArmyImpl* army) const;

    /**
     * Address: 0x005BDF70 (FUN_005BDF70, Moho::ReconBlip::IsOnSonar)
     *
     * What it does:
     * Returns whether this blip is currently sonar-visible for the queried army
     * lane.
     */
    [[nodiscard]] bool IsOnSonar(CArmyImpl* army) const;

    /**
     * Address: 0x005BDF90 (FUN_005BDF90, Moho::ReconBlip::IsOnOmni)
     *
     * What it does:
     * Returns whether this blip is currently omni-visible for the queried army
     * lane.
     */
    [[nodiscard]] bool IsOnOmni(CArmyImpl* army) const;

    /**
     * Address: 0x005BDFB0 (FUN_005BDFB0, Moho::ReconBlip::IsSeenEver)
     *
     * What it does:
     * Returns whether this blip has ever been seen (`RECON_LOSEver`) by the
     * queried army lane.
     */
    [[nodiscard]] bool IsSeenEver(CArmyImpl* army) const;

    /**
     * Address: 0x005BDFD0 (FUN_005BDFD0, Moho::ReconBlip::IsSeenNow)
     *
     * What it does:
     * Returns whether this blip is currently seen (`RECON_LOSNow`) by the
     * queried army lane.
     */
    [[nodiscard]] bool IsSeenNow(CArmyImpl* army) const;

    /**
     * Address: 0x005BDFF0 (FUN_005BDFF0, Moho::ReconBlip::IsMaybeDead)
     *
     * What it does:
     * Returns whether this blip is marked `RECON_MaybeDead` for the queried
     * army lane.
     */
    [[nodiscard]] bool IsMaybeDead(CArmyImpl* army) const;

    /**
     * Address: 0x005BF5F0 (FUN_005BF5F0, Moho::ReconBlip::GetTargetPoint)
     *
     * What it does:
     * Resolves one blip target point: source-unit target point plus jam offset
     * when linked, otherwise root-bone position with blueprint collision-y
     * offset lift.
     */
    [[nodiscard]] Wm3::Vec3f GetTargetPoint(std::int32_t targetPoint);

    /**
     * Address: 0x005BF4F0 (FUN_005BF4F0, Moho::ReconBlip::PickTargetPointAboveWater)
     *
     * What it does:
     * Selects one above-water target-point lane by delegating to source unit
     * when linked, otherwise by comparing blip elevation against water level.
     */
    bool PickTargetPointAboveWater(std::int32_t& outTargetPoint) const;

    /**
     * Address: 0x005BF570 (FUN_005BF570, Moho::ReconBlip::PickTargetPointBelowWater)
     *
     * What it does:
     * Selects one below-water target-point lane by delegating to source unit
     * when linked, otherwise by comparing blip elevation against water level.
     */
    bool PickTargetPointBelowWater(std::int32_t& outTargetPoint) const;

    /**
     * Address: 0x005BF810 (FUN_005BF810)
     *
     * What it does:
     * Refreshes cached transform/visual words from the linked source unit.
     */
    void Refresh();

    /**
     * Address: 0x005BF6F0 (FUN_005BF6F0)
     *
     * What it does:
     * Destroys this blip once no army still tracks it and source retention rules
     * are no longer satisfied.
     */
    void DestroyIfUnused();

    [[nodiscard]] Unit* GetSourceUnit() const noexcept;
    [[nodiscard]] bool IsFake() const noexcept;
    [[nodiscard]] SPerArmyReconInfo* GetPerArmyReconInfo(std::int32_t armyIndex) noexcept;
    [[nodiscard]] const SPerArmyReconInfo* GetPerArmyReconInfo(std::int32_t armyIndex) const noexcept;

  public:
    WeakPtr<Unit> mCreator;                   // +0x270
    std::uint8_t mDeleteWhenStale;            // +0x278
    std::uint8_t mPad279[0x03];               // +0x279
    Wm3::Vec3f mJamOffset;                    // +0x27C
    SReconBlipUnitConstData mUnitConstDat;    // +0x288
    SReconBlipUnitVarData mUnitVarDat;        // +0x298
    msvc8::vector<SPerArmyReconInfo> mReconDat; // +0x4C0
  };

  static_assert(offsetof(ReconBlip, mCreator) == 0x270, "ReconBlip::mCreator offset must be 0x270");
  static_assert(offsetof(ReconBlip, mDeleteWhenStale) == 0x278, "ReconBlip::mDeleteWhenStale offset must be 0x278");
  static_assert(offsetof(ReconBlip, mJamOffset) == 0x27C, "ReconBlip::mJamOffset offset must be 0x27C");
  static_assert(offsetof(ReconBlip, mUnitConstDat) == 0x288, "ReconBlip::mUnitConstDat offset must be 0x288");
  static_assert(offsetof(ReconBlip, mUnitVarDat) == 0x298, "ReconBlip::mUnitVarDat offset must be 0x298");
  static_assert(offsetof(ReconBlip, mReconDat) == 0x4C0, "ReconBlip::mReconDat offset must be 0x4C0");
  static_assert(sizeof(ReconBlip) == 0x4D0, "ReconBlip size must be 0x4D0");
} // namespace moho
