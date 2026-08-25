#include "moho/ai/CAiPathFinderSerializer.h"

#include <cstdint>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    gpg::RType* type = CAiPathFinder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathFinder));
      CAiPathFinder::sType = type;
    }
    return type;
  }

  // Address: 0x010AED04 -- process-global `CAiPathFinderSerializer`
  // singleton. Constructing it runs CAiPathFinderSerializer::
  // CAiPathFinderSerializer() (0x00BCCD70), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiPathFinderSerializer,
  // 0x00BF7240) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiPathFinderSerializer gCAiPathFinderSerializer;
} // namespace

/**
 * Address: 0x005AAC30 (FUN_005AAC30, Moho::CAiPathFinderSerializer::Deserialize)
 */
void CAiPathFinderSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberDeserialize(archive, version);
}

/**
 * Address: 0x005AAC40 (FUN_005AAC40, Moho::CAiPathFinderSerializer::Serialize)
 */
void CAiPathFinderSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberSerialize(archive, version);
}

/**
 * Address: 0x00BCCD70 (FUN_00BCCD70, dynamic initializer for the global
 * `CAiPathFinderSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiPathFinderSerializer::CAiPathFinderSerializer()
  : mLoadCallback(&CAiPathFinderSerializer::Deserialize)
  , mSaveCallback(&CAiPathFinderSerializer::Serialize)
{}

/**
 * Address: 0x00BF7240 (FUN_00BF7240, Moho::CAiPathFinderSerializer::~CAiPathFinderSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiPathFinderSerializer::~CAiPathFinderSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005AB210 (FUN_005AB210)
 *
 * What it does:
 * Lazily resolves CAiPathFinder RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathFinderSerializer::Init()
{
  gpg::RType* const type = CachedCAiPathFinderType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
