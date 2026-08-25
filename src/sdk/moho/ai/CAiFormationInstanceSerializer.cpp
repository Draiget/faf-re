#include "moho/ai/CAiFormationInstanceSerializer.h"

#include <cstdint>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiFormationInstanceType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(CAiFormationInstance));
    }
    return sCachedType;
  }

  // Address: 0x010AE424 -- process-global `CAiFormationInstanceSerializer`
  // singleton. Constructing it runs CAiFormationInstanceSerializer::
  // CAiFormationInstanceSerializer() (0x00BCC150), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor
  // (~CAiFormationInstanceSerializer, 0x00BF67A0) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  moho::CAiFormationInstanceSerializer gCAiFormationInstanceSerializer;
} // namespace

/**
 * Address: 0x0059BEE0 (FUN_0059BEE0, Moho::CAiFormationInstanceSerializer::Deserialize)
 */
void CAiFormationInstanceSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const formation = reinterpret_cast<CAiFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  if (!formation) {
    return;
  }

  formation->MemberDeserialize(archive);
}

/**
 * Address: 0x0059BEF0 (FUN_0059BEF0, Moho::CAiFormationInstanceSerializer::Serialize)
 */
void CAiFormationInstanceSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const formation = reinterpret_cast<const CAiFormationInstance*>(static_cast<std::uintptr_t>(objectPtr));
  if (!formation) {
    return;
  }

  formation->MemberSerialize(archive);
}

/**
 * Address: 0x00BCC150 (FUN_00BCC150, dynamic initializer for the global
 * `CAiFormationInstanceSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiFormationInstanceSerializer::CAiFormationInstanceSerializer()
  : mLoadCallback(&CAiFormationInstanceSerializer::Deserialize)
  , mSaveCallback(&CAiFormationInstanceSerializer::Serialize)
{}

/**
 * Address: 0x00BF67A0 (FUN_00BF67A0, Moho::CAiFormationInstanceSerializer::~CAiFormationInstanceSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiFormationInstanceSerializer::~CAiFormationInstanceSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x0059C820 (FUN_0059C820)
 *
 * What it does:
 * Lazily resolves CAiFormationInstance RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationInstanceSerializer::Init()
{
  gpg::RType* const type = CachedCAiFormationInstanceType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
