#pragma once

#include <cstddef>
#include <cstdint>

#include "../../boost/shared_ptr.h"
#include "../../legacy/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CIntelGrid;

  /**
   * Address context:
   * - 0x00700080 (FUN_00700080, CArmyImpl slot helper)
   * - 0x007000A0 (FUN_007000A0)
   * - 0x00550B20 (FUN_00550B20, IArmyTypeInfo::Init)
   * - 0x006FD9D0 (FUN_006FD9D0, SimArmyTypeInfo::Init)
   *
   * What it does:
   * Constant/identity payload for army sync state (the first 0x80 bytes of the IArmy subobject).
   */
  struct SSTIArmyConstantData
  {
    static gpg::RType* sType;

    /**
     * Address: 0x006FD330 (FUN_006FD330, Moho::SSTIArmyConstantData::SSTIArmyConstantData)
     *
     * What it does:
     * Initializes fixed army identity lanes, zeroes civilian state, and clears
     * all tracked intel-grid shared-pointer lanes.
     */
    SSTIArmyConstantData();

    /**
     * Address: 0x00742FA0 (FUN_00742FA0, Moho::SSTIArmyConstantData::SSTIArmyConstantData copy-ctor)
     *
     * What it does:
     * Clones fixed identity/string lanes and all eight tracked shared
     * `CIntelGrid` pointer lanes from one source payload.
     */
    SSTIArmyConstantData(const SSTIArmyConstantData& other);

    /**
     * Address: 0x006FD570 (FUN_006FD570, Moho::SSTIArmyConstantData::~SSTIArmyConstantData)
     *
     * What it does:
     * Releases shared intel-grid lanes and tears down owned name strings in
     * reverse member order.
     */
    ~SSTIArmyConstantData();

    /**
     * Address: 0x005510C0 (FUN_005510C0, Moho::SSTIArmyConstantData::MemberSerialize)
     *
     * What it does:
     * Serializes fixed army identity lanes and all eight tracked shared
     * `CIntelGrid` pointer lanes to a write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00550FC0 (FUN_00550FC0, Moho::SSTIArmyConstantData::MemberDeserialize)
     *
     * What it does:
     * Reads `mArmyIndex` (uint), `mArmyName`, `mPlayerName`, `mIsCivilian`,
     * then eight tracked-shared `CIntelGrid` pointers from a read archive in
     * field-declaration order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    std::int32_t mArmyIndex;                          // +0x00
    msvc8::string mArmyName;                          // +0x04
    msvc8::string mPlayerName;                        // +0x20
    std::uint8_t mIsCivilian;                         // +0x3C
    std::uint8_t mPad3D[3];                           // +0x3D
    boost::shared_ptr<CIntelGrid> mExploredReconGrid; // +0x40
    boost::shared_ptr<CIntelGrid> mFogReconGrid;      // +0x48
    boost::shared_ptr<CIntelGrid> mWaterReconGrid;    // +0x50
    boost::shared_ptr<CIntelGrid> mRadarReconGrid;    // +0x58
    boost::shared_ptr<CIntelGrid> mSonarReconGrid;    // +0x60
    boost::shared_ptr<CIntelGrid> mOmniReconGrid;     // +0x68
    boost::shared_ptr<CIntelGrid> mRciReconGrid;      // +0x70
    boost::shared_ptr<CIntelGrid> mSciReconGrid;      // +0x78
  };

  /**
   * Address: 0x007000A0 (FUN_007000A0)
   *
   * What it does:
   * Assigns one `SSTIArmyConstantData` payload from `source` into
   * `destination` and returns the destination pointer. `UserArmy`'s
   * constructor uses this to stamp the sim-supplied constant data over its
   * payload base.
   */
  SSTIArmyConstantData* AssignArmyConstantData(const SSTIArmyConstantData& source, SSTIArmyConstantData* destination);

  static_assert(sizeof(boost::shared_ptr<CIntelGrid>) == 0x08, "shared_ptr<CIntelGrid> size must be 0x08");
  static_assert(
    offsetof(SSTIArmyConstantData, mArmyName) == 0x04, "SSTIArmyConstantData::mArmyName offset must be 0x04"
  );
  static_assert(
    offsetof(SSTIArmyConstantData, mPlayerName) == 0x20, "SSTIArmyConstantData::mPlayerName offset must be 0x20"
  );
  static_assert(
    offsetof(SSTIArmyConstantData, mIsCivilian) == 0x3C, "SSTIArmyConstantData::mIsCivilian offset must be 0x3C"
  );
  static_assert(
    offsetof(SSTIArmyConstantData, mExploredReconGrid) == 0x40,
    "SSTIArmyConstantData::mExploredReconGrid offset must be 0x40"
  );
  static_assert(
    offsetof(SSTIArmyConstantData, mSciReconGrid) == 0x78, "SSTIArmyConstantData::mSciReconGrid offset must be 0x78"
  );
  static_assert(sizeof(SSTIArmyConstantData) == 0x80, "SSTIArmyConstantData size must be 0x80");

  /**
   * VFTABLE: 0x00E17534
   */
  class SSTIArmyConstantDataSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9AB0 (FUN_00BC9AB0, dynamic initializer for the global
     * `SSTIArmyConstantDataSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SSTIArmyConstantDataSerializer();

    /**
     * Address: 0x00BF47E0 (FUN_00BF47E0, ??1SSTIArmyConstantDataSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SSTIArmyConstantDataSerializer();

    /**
     * Address: 0x005507F0 (FUN_005507F0, Moho::SSTIArmyConstantDataSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade forwarding to
     * `SSTIArmyConstantData::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550810 (FUN_00550810, Moho::SSTIArmyConstantDataSerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade forwarding to
     * `SSTIArmyConstantData::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550CF0 (FUN_00550CF0, shared Init() body -- also serves
     * the dead SerSaveLoadHelper<SSTIArmyConstantData> duplicate's vtable
     * slot 0, confirmed via incoming_xrefs from both vtables)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSTIArmyConstantData` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SSTIArmyConstantDataSerializer, mLoadCallback) == 0x0C,
    "SSTIArmyConstantDataSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIArmyConstantDataSerializer, mSaveCallback) == 0x10,
    "SSTIArmyConstantDataSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SSTIArmyConstantDataSerializer) == 0x14, "SSTIArmyConstantDataSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E17E5C
   *
   * Reflection serializer for `EntId` (`std::int32_t`). Adjacent to
   * `SSTIArmyConstantDataSerializer` in the binary's registration cluster
   * (0x00BC9AB0/0x00BC9F80 sit in the same address range), suggesting the
   * original 2007 translation unit housed both together.
   */
  class EntIdSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9F80 (FUN_00BC9F80, dynamic initializer for the global
     * `EntIdSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    EntIdSerializer();

    /**
     * Address: 0x00BF4DB0 (FUN_00BF4DB0, ??1EntIdSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~EntIdSerializer();

    /**
     * Address: 0x00557EF0 (FUN_00557EF0, Moho::EntIdSerializer::Deserialize)
     *
     * What it does:
     * Reads the raw `EntId` value directly through the archive.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00557F10 (FUN_00557F10, Moho::EntIdSerializer::Serialize)
     *
     * What it does:
     * Writes the raw `EntId` value directly through the archive.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005589E0 (FUN_005589E0, shared Init() body -- also serves
     * the dead SerSaveLoadHelper<EntId> duplicate's vtable slot 0, confirmed
     * via incoming_xrefs from both vtables)
     *
     * What it does:
     * Binds load/save serializer callbacks into `EntId` RTTI. `EntId` is a
     * `std::int32_t` alias (not a class), so unlike `SSTIArmyConstantData`
     * it cannot host its own `static RType* sType` member; the cached type
     * pointer lives as a translation-unit-local static instead (matches the
     * real ctor's `Moho__EntId__sType` target, a plain data symbol rather
     * than a class static member).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(EntIdSerializer, mLoadCallback) == 0x0C, "EntIdSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(EntIdSerializer, mSaveCallback) == 0x10, "EntIdSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(EntIdSerializer) == 0x14, "EntIdSerializer size must be 0x14");
} // namespace moho
