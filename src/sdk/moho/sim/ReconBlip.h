#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class ReadArchive;
  struct RRef;
  class SerConstructResult;
  class WriteArchive;
  class RType;
} // namespace gpg

namespace moho
{
  class CAniPose;
  class RMeshBlueprint;
  class RScmResource;
  class Sim;
  class Unit;

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
   * `SSTIUnitConstantData` subobject slice used by ReconBlip.
   *
   * `mFake` lives at +0x0C in this 0x10-byte block.
   */
  struct SReconBlipUnitConstData
  {
    std::uint8_t mOpaque00_0B[0x0C];
    std::uint8_t mFake;           // +0x0C
    std::uint8_t mPad0D_0F[0x03]; // +0x0D
  };

  static_assert(sizeof(SReconBlipUnitConstData) == 0x10, "SReconBlipUnitConstData size must be 0x10");
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
