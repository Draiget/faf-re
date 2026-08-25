#include "moho/ai/CAiFormationDBImplSerializer.h"

#include <cstdint>

#include "moho/ai/CAiFormationDBImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiFormationDBImplType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(CAiFormationDBImpl));
    }
    return sCachedType;
  }

  // Address: 0x010AE4E0 -- process-global `CAiFormationDBImplSerializer`
  // singleton. Constructing it runs CAiFormationDBImplSerializer::
  // CAiFormationDBImplSerializer() (0x00BCC1D0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiFormationDBImplSerializer,
  // 0x00BF6890) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiFormationDBImplSerializer gCAiFormationDBImplSerializer;
} // namespace

/**
 * Address: 0x0059C670 (FUN_0059C670, Moho::CAiFormationDBImplSerializer::Deserialize)
 */
void CAiFormationDBImplSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const formationDb = reinterpret_cast<CAiFormationDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  formationDb->MemberDeserialize(archive);
}

/**
 * Address: 0x0059C680 (FUN_0059C680, Moho::CAiFormationDBImplSerializer::Serialize)
 */
void CAiFormationDBImplSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const formationDb = reinterpret_cast<const CAiFormationDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  formationDb->MemberSerialize(archive);
}

/**
 * Address: 0x00BCC1D0 (FUN_00BCC1D0, dynamic initializer for the global
 * `CAiFormationDBImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiFormationDBImplSerializer::CAiFormationDBImplSerializer()
  : mLoadCallback(&CAiFormationDBImplSerializer::Deserialize)
  , mSaveCallback(&CAiFormationDBImplSerializer::Serialize)
{}

/**
 * Address: 0x00BF6890 (FUN_00BF6890, Moho::CAiFormationDBImplSerializer::~CAiFormationDBImplSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiFormationDBImplSerializer::~CAiFormationDBImplSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x0059CBA0 (FUN_0059CBA0)
 *
 * What it does:
 * Lazily resolves CAiFormationDBImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationDBImplSerializer::Init()
{
  gpg::RType* const type = CachedCAiFormationDBImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
