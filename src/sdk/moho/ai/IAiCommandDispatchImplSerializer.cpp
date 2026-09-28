#include "moho/ai/IAiCommandDispatchImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/misc/Stats.h"

using namespace moho;

namespace
{
  // Address: 0x010AE324 -- process-global `IAiCommandDispatchImplSerializer`
  // singleton. Constructing it runs IAiCommandDispatchImplSerializer::
  // IAiCommandDispatchImplSerializer() (0x00BCBF00), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~IAiCommandDispatchImplSerializer, 0x00BF66F0) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  IAiCommandDispatchImplSerializer gIAiCommandDispatchImplSerializer;

  /**
   * Address: 0x00599A40 (FUN_00599A40, j_Moho::IAiCommandDispatchImpl::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `IAiCommandDispatchImpl::MemberSerialize`.
   */
  [[maybe_unused]] void IAiCommandDispatchImplMemberSerializeThunk(
    const moho::IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive) {
      return;
    }

    moho::IAiCommandDispatchImpl::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00599C70 (FUN_00599C70, j_Moho::IAiCommandDispatchImpl::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `IAiCommandDispatchImpl::MemberSerialize`.
   */
  [[maybe_unused]] void IAiCommandDispatchImplMemberSerializeThunkSecondary(
    const moho::IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive) {
      return;
    }

    moho::IAiCommandDispatchImpl::MemberSerialize(object, archive);
  }

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

} // namespace

/**
 * Address: 0x005993C0 (FUN_005993C0, Moho::IAiCommandDispatchImplSerializer::Deserialize)
 */
void IAiCommandDispatchImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiCommandDispatchImpl::MemberDeserialize(
    archive,
    reinterpret_cast<IAiCommandDispatchImpl*>(static_cast<std::uintptr_t>(objectPtr))
  );
}

/**
 * Address: 0x005993D0 (FUN_005993D0, Moho::IAiCommandDispatchImplSerializer::Serialize)
 */
void IAiCommandDispatchImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const object = reinterpret_cast<const IAiCommandDispatchImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    IAiCommandDispatchImpl::MemberSerialize(object, archive);
    return;
  }

  IAiCommandDispatchImplMemberSerializeThunk(object, archive);
}

/**
 * Address: 0x00BCBF00 (FUN_00BCBF00, dynamic initializer for the global
 * `IAiCommandDispatchImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
IAiCommandDispatchImplSerializer::IAiCommandDispatchImplSerializer()
  : mLoadCallback(&IAiCommandDispatchImplSerializer::Deserialize)
  , mSaveCallback(&IAiCommandDispatchImplSerializer::Serialize)
{}

/**
 * Address: 0x00BF66F0 (FUN_00BF66F0, ??1IAiCommandDispatchImplSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
IAiCommandDispatchImplSerializer::~IAiCommandDispatchImplSerializer() = default;

/**
 * Address: 0x005996D0 (FUN_005996D0)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplSerializer::Init()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
