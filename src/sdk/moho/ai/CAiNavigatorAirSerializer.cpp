#include "moho/ai/CAiNavigatorAirSerializer.h"

#include <cstdint>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x005A7F30 (FUN_005A7F30, j_Moho::CAiNavigatorAir::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiNavigatorAir::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiNavigatorAirMemberDeserializeThunk(
    moho::CAiNavigatorAir* const navigator, gpg::ReadArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorAir::MemberDeserialize(navigator, archive);
  }

  /**
   * Address: 0x005A7F40 (FUN_005A7F40, j_Moho::CAiNavigatorAir::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiNavigatorAir::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorAirMemberSerializeThunk(
    const moho::CAiNavigatorAir* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorAir::MemberSerialize(navigator, archive);
  }

  /**
   * Address: 0x005A8950 (FUN_005A8950, j_Moho::CAiNavigatorAir::MemberDeserialize_0)
   * Address: 0x0084B3E0 (FUN_0084B3E0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiNavigatorAir::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiNavigatorAirMemberDeserializeThunkSecondary(
    moho::CAiNavigatorAir* const navigator, gpg::ReadArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorAir::MemberDeserialize(navigator, archive);
  }

  /**
   * Address: 0x005A8960 (FUN_005A8960, j_Moho::CAiNavigatorAir::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiNavigatorAir::MemberSerialize`.
   */
  [[maybe_unused]] void CAiNavigatorAirMemberSerializeThunkSecondary(
    const moho::CAiNavigatorAir* const navigator, gpg::WriteArchive* const archive
  )
  {
    if (!navigator) {
      return;
    }

    moho::CAiNavigatorAir::MemberSerialize(navigator, archive);
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }

  // Address: 0x010AEC28 -- process-global `CAiNavigatorAirSerializer`
  // singleton. Constructing it runs CAiNavigatorAirSerializer::
  // CAiNavigatorAirSerializer() (0x00BCC880), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiNavigatorAirSerializer,
  // 0x00BF6F70) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiNavigatorAirSerializer gCAiNavigatorAirSerializer;
} // namespace

/**
 * Address: 0x005A56D0 (FUN_005A56D0, Moho::CAiNavigatorAirSerializer::Deserialize)
 */
void CAiNavigatorAirSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const navigator = reinterpret_cast<CAiNavigatorAir*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    CAiNavigatorAir::MemberDeserialize(navigator, archive);
    return;
  }

  CAiNavigatorAirMemberDeserializeThunk(navigator, archive);
}

/**
 * Address: 0x005A56E0 (FUN_005A56E0, Moho::CAiNavigatorAirSerializer::Serialize)
 */
void CAiNavigatorAirSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const navigator = reinterpret_cast<const CAiNavigatorAir*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    CAiNavigatorAir::MemberSerialize(navigator, archive);
    return;
  }

  CAiNavigatorAirMemberSerializeThunk(navigator, archive);
}

/**
 * Address: 0x00BCC880 (FUN_00BCC880, dynamic initializer for the global
 * `CAiNavigatorAirSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiNavigatorAirSerializer::CAiNavigatorAirSerializer()
  : mLoadCallback(&CAiNavigatorAirSerializer::Deserialize)
  , mSaveCallback(&CAiNavigatorAirSerializer::Serialize)
{}

/**
 * Address: 0x00BF6F70 (FUN_00BF6F70, Moho::CAiNavigatorAirSerializer::~CAiNavigatorAirSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiNavigatorAirSerializer::~CAiNavigatorAirSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005A7550 (FUN_005A7550)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorAirSerializer::Init()
{
  gpg::RType* const type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
