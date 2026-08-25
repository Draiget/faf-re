#include "moho/ai/CAiBrainSerializer.h"

#include <cstdint>

#include "moho/ai/CAiBrain.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }

  // Address: 0x010AD79C -- process-global `CAiBrainSerializer` singleton.
  // Constructing it runs CAiBrainSerializer::CAiBrainSerializer()
  // (0x00BCB430), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiBrainSerializer,
  // 0x00BF62F0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiBrainSerializer gCAiBrainSerializer;
} // namespace

/**
 * Address: 0x00579D90 (FUN_00579D90, Moho::CAiBrainSerializer::Deserialize)
 */
void CAiBrainSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const brain = reinterpret_cast<CAiBrain*>(static_cast<std::uintptr_t>(objectPtr));
  brain->MemberDeserialize(archive);
}

/**
 * Address: 0x00579DA0 (FUN_00579DA0, Moho::CAiBrainSerializer::Serialize)
 */
void CAiBrainSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const brain = reinterpret_cast<const CAiBrain*>(static_cast<std::uintptr_t>(objectPtr));
  brain->MemberSerialize(archive);
}

/**
 * Address: 0x00BCB430 (FUN_00BCB430, dynamic initializer for the global
 * `CAiBrainSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiBrainSerializer::CAiBrainSerializer()
  : mLoadCallback(&CAiBrainSerializer::Deserialize)
  , mSaveCallback(&CAiBrainSerializer::Serialize)
{}

/**
 * Address: 0x00BF62F0 (FUN_00BF62F0, Moho::CAiBrainSerializer::~CAiBrainSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiBrainSerializer::~CAiBrainSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x0057E460 (FUN_0057E460)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiBrainSerializer::Init()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
