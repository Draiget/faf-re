#include "moho/ai/CAiTransportImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x005EC3F0 (FUN_005EC3F0, j_Moho::CAiTransportImpl::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiTransportImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiTransportImplMemberSerializeThunk(
    moho::CAiTransportImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!object || !archive) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x005EDCC0 (FUN_005EDCC0, j_Moho::CAiTransportImpl::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiTransportImpl::MemberSerialize`.
   */
  [[maybe_unused]] void CAiTransportImplMemberSerializeThunkSecondary(
    moho::CAiTransportImpl* const object, gpg::WriteArchive* const archive
  )
  {
    if (!object || !archive) {
      return;
    }

    object->MemberSerialize(archive);
  }

  [[nodiscard]] gpg::RType* CachedCAiTransportImplType()
  {
    gpg::RType* type = CAiTransportImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTransportImpl));
      CAiTransportImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010B07D8 -- process-global `CAiTransportImplSerializer`
  // singleton. Constructing it runs CAiTransportImplSerializer::
  // CAiTransportImplSerializer() (0x00BCEF50), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; the compiler registers its destructor with
  // `atexit`.
  CAiTransportImplSerializer gCAiTransportImplSerializer;

} // namespace

/**
 * Address: 0x005E8590 (FUN_005E8590, Moho::CAiTransportImplSerializer::Deserialize)
 */
void CAiTransportImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
{
  auto* const object = reinterpret_cast<CAiTransportImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberDeserialize(archive);
}

/**
 * Address: 0x005E85A0 (FUN_005E85A0, Moho::CAiTransportImplSerializer::Serialize)
 */
void CAiTransportImplSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const object = reinterpret_cast<CAiTransportImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  if (ownerRef != nullptr) {
    object->MemberSerialize(archive);
    return;
  }

  CAiTransportImplMemberSerializeThunk(object, archive);
}

/**
 * Address: 0x00BCEF50 (FUN_00BCEF50, dynamic initializer for the global
 * `CAiTransportImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices into
 * `sNewHelpers`) and binds the load/save callback fields; the compiler
 * registers the destructor with `atexit`.
 */
CAiTransportImplSerializer::CAiTransportImplSerializer()
  : mLoadCallback(&CAiTransportImplSerializer::Deserialize)
  , mSaveCallback(&CAiTransportImplSerializer::Serialize)
{}

/**
 * Address: 0x00BF8C70 (FUN_00BF8C70, dynamic atexit destructor for `gCAiTransportImplSerializer`)
 *
 * What it does:
 * Unlinks this helper node from the serializer-helper list (the
 * `TDatListItem` base destructor). The compiler registers it with
 * `atexit` from the global's dynamic initializer (0x00BCEF50).
 * `FUN_005E85E0` and `FUN_005E8610` are
 * unreferenced out-of-line copies of the same body.
 */
CAiTransportImplSerializer::~CAiTransportImplSerializer() = default;

/**
 * Address: 0x005E9C30 (FUN_005E9C30)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiTransportImplSerializer::Init()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEF50 caller lane (`IAiTransport.cpp`'s reflection bootstrap
 * sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiTransportImplSerializer` singleton from an explicit registration
 * sequence. `gCAiTransportImplSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
 * sequence does not need editing.
 */
void moho::register_CAiTransportImplSerializer()
{
}
