#include "moho/ai/IAiNavigatorSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  // Address: 0x010AE788 -- process-global `IAiNavigatorSerializer` singleton.
  // Constructing it runs IAiNavigatorSerializer::IAiNavigatorSerializer()
  // (0x00BCC6C0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~IAiNavigatorSerializer,
  // 0x00BF6D60) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  IAiNavigatorSerializer gIAiNavigatorSerializer;

  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    gpg::RType* type = IAiNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiNavigator));
      IAiNavigator::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A32D0 (FUN_005A32D0, Moho::IAiNavigatorSerializer::Deserialize)
 */
void IAiNavigatorSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiNavigator::MemberDeserialize(reinterpret_cast<IAiNavigator*>(static_cast<std::uintptr_t>(objectPtr)), archive);
}

/**
 * Address: 0x005A32E0 (FUN_005A32E0, Moho::IAiNavigatorSerializer::Serialize)
 */
void IAiNavigatorSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  IAiNavigator::MemberSerialize(
    reinterpret_cast<const IAiNavigator*>(static_cast<std::uintptr_t>(objectPtr)),
    archive
  );
}

/**
 * Address: 0x00BCC6C0 (FUN_00BCC6C0, dynamic initializer for the global
 * `IAiNavigatorSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
IAiNavigatorSerializer::IAiNavigatorSerializer()
  : mLoadCallback(&IAiNavigatorSerializer::Deserialize)
  , mSaveCallback(&IAiNavigatorSerializer::Serialize)
{}

/**
 * Address: 0x00BF6D60 (FUN_00BF6D60, ??1IAiNavigatorSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
IAiNavigatorSerializer::~IAiNavigatorSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005A71A0 (FUN_005A71A0)
 *
 * What it does:
 * Lazily resolves IAiNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiNavigatorSerializer::Init()
{
  gpg::RType* const type = CachedIAiNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
