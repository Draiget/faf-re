#include "moho/ai/CAiBuilderImplSerializer.h"

#include <cstdint>

#include "moho/ai/CAiBuilderImpl.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x005A1CF0 (FUN_005A1CF0, j_Moho::CAiBuilderImpl::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiBuilderImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiBuilderImplMemberSerializeThunk(
    const moho::CAiBuilderImpl* const builder, gpg::WriteArchive* const archive
  )
  {
    if (!builder) {
      return;
    }

    builder->MemberSerialize(archive);
  }

  /**
   * Address: 0x005A21F0 (FUN_005A21F0, j_Moho::CAiBuilderImpl::MemberSerialize_0)
   * Address: 0x00635370 (FUN_00635370)
   * Address: 0x004E7070 (FUN_004E7070)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiBuilderImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiBuilderImplMemberSerializeThunkSecondary(
    const moho::CAiBuilderImpl* const builder, gpg::WriteArchive* const archive
  )
  {
    if (!builder) {
      return;
    }

    builder->MemberSerialize(archive);
  }

  [[nodiscard]] gpg::RType* CachedCAiBuilderImplType()
  {
    gpg::RType* type = CAiBuilderImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBuilderImpl));
      CAiBuilderImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010AE5CC -- process-global `CAiBuilderImplSerializer`
  // singleton. Constructing it runs CAiBuilderImplSerializer::
  // CAiBuilderImplSerializer() (0x00BCC320), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiBuilderImplSerializer,
  // 0x00BF6AF0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiBuilderImplSerializer gCAiBuilderImplSerializer;
} // namespace

/**
 * Address: 0x0059FE20 (FUN_0059FE20, Moho::CAiBuilderImplSerializer::Deserialize)
 */
void CAiBuilderImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const builder = reinterpret_cast<CAiBuilderImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!builder) {
    return;
  }

  builder->MemberDeserialize(archive);
}

/**
 * Address: 0x0059FE30 (FUN_0059FE30, Moho::CAiBuilderImplSerializer::Serialize)
 */
void CAiBuilderImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const builder = reinterpret_cast<const CAiBuilderImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!builder) {
    return;
  }

  if (ownerRef != nullptr) {
    builder->MemberSerialize(archive);
    return;
  }

  CAiBuilderImplMemberSerializeThunk(builder, archive);
}

/**
 * Address: 0x00BCC320 (FUN_00BCC320, dynamic initializer for the global
 * `CAiBuilderImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiBuilderImplSerializer::CAiBuilderImplSerializer()
  : mLoadCallback(&CAiBuilderImplSerializer::Deserialize)
  , mSaveCallback(&CAiBuilderImplSerializer::Serialize)
{}

/**
 * Address: 0x00BF6AF0 (FUN_00BF6AF0, Moho::CAiBuilderImplSerializer::~CAiBuilderImplSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiBuilderImplSerializer::~CAiBuilderImplSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005A06D0 (FUN_005A06D0)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiBuilderImplSerializer::Init()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
