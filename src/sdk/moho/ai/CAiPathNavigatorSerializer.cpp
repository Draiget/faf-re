#include "moho/ai/CAiPathNavigatorSerializer.h"

#include <cstdint>

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    gpg::RType* type = CAiPathNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathNavigator));
      CAiPathNavigator::sType = type;
    }
    return type;
  }

  // Address: 0x010AEF44 -- process-global `CAiPathNavigatorSerializer`
  // singleton. Constructing it runs CAiPathNavigatorSerializer::
  // CAiPathNavigatorSerializer() (0x00BCD040), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiPathNavigatorSerializer,
  // 0x00BF73C0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiPathNavigatorSerializer gCAiPathNavigatorSerializer;
} // namespace

/**
 * Address: 0x005AFBE0 (FUN_005AFBE0, Moho::CAiPathNavigatorSerializer::Deserialize)
 */
void CAiPathNavigatorSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const)
{
  auto* const navigator = reinterpret_cast<CAiPathNavigator*>(static_cast<std::uintptr_t>(objectPtr));
  navigator->MemberDeserialize(archive, version);
}

/**
 * Address: 0x005AFC00 (FUN_005AFC00, Moho::CAiPathNavigatorSerializer::Serialize)
 */
void CAiPathNavigatorSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const)
{
  auto* const navigator = reinterpret_cast<CAiPathNavigator*>(static_cast<std::uintptr_t>(objectPtr));
  navigator->MemberSerialize(archive, version);
}

/**
 * Address: 0x00BCD040 (FUN_00BCD040, dynamic initializer for the global
 * `CAiPathNavigatorSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiPathNavigatorSerializer::CAiPathNavigatorSerializer()
  : mLoadCallback(&CAiPathNavigatorSerializer::Deserialize)
  , mSaveCallback(&CAiPathNavigatorSerializer::Serialize)
{}

/**
 * Address: 0x00BF73C0 (FUN_00BF73C0, Moho::CAiPathNavigatorSerializer::~CAiPathNavigatorSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiPathNavigatorSerializer::~CAiPathNavigatorSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005B0130 (FUN_005B0130)
 *
 * What it does:
 * Lazily resolves CAiPathNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathNavigatorSerializer::Init()
{
  gpg::RType* type = CachedCAiPathNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
