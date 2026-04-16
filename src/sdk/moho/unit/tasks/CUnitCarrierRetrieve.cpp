#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEntitySetTemplateUnit));
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006085A0 (FUN_006085A0, Moho::CUnitCarrierRetrieve::MemberDeserialize)
   *
   * What it does:
   * Deserializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), this, ownerRef);
    archive->ReadBool(&mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Read(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00608630 (FUN_00608630, Moho::CUnitCarrierRetrieve::MemberSerialize)
   *
   * What it does:
   * Serializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), this, ownerRef);
    archive->WriteBool(mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00607E80 (FUN_00607E80)
   *
   * What it does:
   * Preserves one deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneA(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00608030 (FUN_00608030)
   *
   * What it does:
   * Alternate deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneB(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }
} // namespace moho

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitCarrierRetrieveSerializer{};

  /**
   * Address: 0x006063F0 (FUN_006063F0)
   *
   * What it does:
   * Unlinks `CUnitCarrierRetrieveSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierRetrieveSerializer);
  }

  /**
   * Address: 0x00606420 (FUN_00606420)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCarrierRetrieveSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierRetrieveSerializer);
  }
} // namespace
