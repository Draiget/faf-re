#include "moho/ai/CAiNavigatorImplSerializer.h"

#include <cstdint>

#include "moho/ai/CAiNavigatorImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    gpg::RType* type = CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorImpl));
      CAiNavigatorImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010AE79C -- process-global `CAiNavigatorImplSerializer`
  // singleton. Constructing it runs CAiNavigatorImplSerializer::
  // CAiNavigatorImplSerializer() (0x00BCC720), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiNavigatorImplSerializer,
  // 0x00BF6DA0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiNavigatorImplSerializer gCAiNavigatorImplSerializer;
} // namespace

/**
 * Address: 0x005A39F0 (FUN_005A39F0, Moho::CAiNavigatorImplSerializer::Deserialize)
 */
void CAiNavigatorImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  CAiNavigatorImpl::MemberDeserialize(
    reinterpret_cast<CAiNavigatorImpl*>(static_cast<std::uintptr_t>(objectPtr)),
    archive,
    version
  );
}

/**
 * Address: 0x005A3A10 (FUN_005A3A10, Moho::CAiNavigatorImplSerializer::Serialize)
 */
void CAiNavigatorImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  CAiNavigatorImpl::MemberSerialize(
    reinterpret_cast<const CAiNavigatorImpl*>(static_cast<std::uintptr_t>(objectPtr)),
    archive,
    version
  );
}

/**
 * Address: 0x00BCC720 (FUN_00BCC720, dynamic initializer for the global
 * `CAiNavigatorImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiNavigatorImplSerializer::CAiNavigatorImplSerializer()
  : mLoadCallback(&CAiNavigatorImplSerializer::Deserialize)
  , mSaveCallback(&CAiNavigatorImplSerializer::Serialize)
{}

/**
 * Address: 0x00BF6DA0 (FUN_00BF6DA0, Moho::CAiNavigatorImplSerializer::~CAiNavigatorImplSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiNavigatorImplSerializer::~CAiNavigatorImplSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005A72A0 (FUN_005A72A0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorImplSerializer::Init()
{
  gpg::RType* const type = CachedCAiNavigatorImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
