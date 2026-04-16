#pragma once

#include <cstddef>
#include <cstdint>

#include "../../boost/shared_ptr.h"
#include "../../legacy/containers/String.h"

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
} // namespace moho
