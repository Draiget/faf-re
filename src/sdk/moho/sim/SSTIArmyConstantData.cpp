#include "SSTIArmyConstantData.h"

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/sim/CIntelGrid.h"

namespace moho
{
  /**
   * Address: 0x006FD570 (FUN_006FD570, Moho::SSTIArmyConstantData::~SSTIArmyConstantData)
   *
   * What it does:
   * Runs reverse-order member teardown for intel-grid shared pointers and army
   * identity strings.
   */
  SSTIArmyConstantData::~SSTIArmyConstantData() = default;

  /**
   * Address: 0x005510C0 (FUN_005510C0, Moho::SSTIArmyConstantData::MemberSerialize)
   *
   * What it does:
   * Serializes fixed army identity lanes and all eight tracked shared
   * `CIntelGrid` pointer lanes to a write archive.
   */
  void SSTIArmyConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->WriteUInt(static_cast<std::uint32_t>(mArmyIndex));
    archive->WriteString(const_cast<msvc8::string*>(&mArmyName));
    archive->WriteString(const_cast<msvc8::string*>(&mPlayerName));
    archive->WriteBool(mIsCivilian != 0u);

    const auto writeSharedGridPointer = [archive, &ownerRef](const boost::shared_ptr<CIntelGrid>& gridPointer) {
      gpg::RRef gridRef{};
      (void)gpg::RRef_CIntelGrid(&gridRef, const_cast<CIntelGrid*>(gridPointer.get()));
      gpg::WriteRawPointer(archive, gridRef, gpg::TrackedPointerState::Shared, ownerRef);
    };

    writeSharedGridPointer(mExploredReconGrid);
    writeSharedGridPointer(mFogReconGrid);
    writeSharedGridPointer(mWaterReconGrid);
    writeSharedGridPointer(mRadarReconGrid);
    writeSharedGridPointer(mSonarReconGrid);
    writeSharedGridPointer(mOmniReconGrid);
    writeSharedGridPointer(mRciReconGrid);
    writeSharedGridPointer(mSciReconGrid);
  }
} // namespace moho
