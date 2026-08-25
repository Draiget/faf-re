#include "moho/ai/CAiNavigatorLandSerializer.h"

#include <cstdint>

#include "moho/ai/CAiNavigatorLand.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x005A7E60 (FUN_005A7E60, j_Moho::CAiNavigatorLand::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiNavigatorLand::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorLandMemberSerializeThunk(
    const moho::CAiNavigatorLand* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorLand::MemberSerialize(navigator, archive);
  }

  /**
   * Address: 0x005A8790 (FUN_005A8790, j_Moho::CAiNavigatorLand::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiNavigatorLand::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorLandMemberSerializeThunkSecondary(
    const moho::CAiNavigatorLand* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorLand::MemberSerialize(navigator, archive);
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorLandType()
  {
    gpg::RType* type = CAiNavigatorLand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorLand));
      CAiNavigatorLand::sType = type;
    }
    return type;
  }

  // Address: 0x010AEC14 -- process-global `CAiNavigatorLandSerializer`
  // singleton. Constructing it runs CAiNavigatorLandSerializer::
  // CAiNavigatorLandSerializer() (0x00BCC7E0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiNavigatorLandSerializer,
  // 0x00BF6EB0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiNavigatorLandSerializer gCAiNavigatorLandSerializer;
} // namespace

/**
 * Address: 0x005A47D0 (FUN_005A47D0, Moho::CAiNavigatorLandSerializer::Deserialize)
 */
void CAiNavigatorLandSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  CAiNavigatorLand::MemberDeserialize(
    reinterpret_cast<CAiNavigatorLand*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x005A47E0 (FUN_005A47E0, Moho::CAiNavigatorLandSerializer::Serialize)
 */
void CAiNavigatorLandSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const navigator = reinterpret_cast<const CAiNavigatorLand*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    CAiNavigatorLand::MemberSerialize(navigator, archive);
    return;
  }

  CAiNavigatorLandMemberSerializeThunk(navigator, archive);
}

/**
 * Address: 0x00BCC7E0 (FUN_00BCC7E0, dynamic initializer for the global
 * `CAiNavigatorLandSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiNavigatorLandSerializer::CAiNavigatorLandSerializer()
  : mLoadCallback(&CAiNavigatorLandSerializer::Deserialize)
  , mSaveCallback(&CAiNavigatorLandSerializer::Serialize)
{}

/**
 * Address: 0x00BF6EB0 (FUN_00BF6EB0, Moho::CAiNavigatorLandSerializer::~CAiNavigatorLandSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiNavigatorLandSerializer::~CAiNavigatorLandSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005A7430 (FUN_005A7430)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorLandSerializer::Init()
{
  gpg::RType* const type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
