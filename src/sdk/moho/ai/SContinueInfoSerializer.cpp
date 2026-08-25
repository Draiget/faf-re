#include "moho/ai/SContinueInfoSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  // Address: 0x010AEF74 -- process-global `SContinueInfoSerializer`
  // singleton. Constructing it runs SContinueInfoSerializer::
  // SContinueInfoSerializer() (0x00BCD2F0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SContinueInfoSerializer,
  // 0x00BF74B0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  SContinueInfoSerializer gSContinueInfoSerializer;

  [[nodiscard]] gpg::RType* CachedSContinueInfoType()
  {
    gpg::RType* type = SContinueInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SContinueInfo));
      SContinueInfo::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005B2290 (FUN_005B2290, Moho::SContinueInfoSerializer::Deserialize)
 */
void SContinueInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const continuationInfo = reinterpret_cast<SContinueInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !continuationInfo) {
    return;
  }

  continuationInfo->MemberDeserialize(archive);
}

/**
 * Address: 0x005B22A0 (FUN_005B22A0, Moho::SContinueInfoSerializer::Serialize)
 */
void SContinueInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const continuationInfo = reinterpret_cast<SContinueInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !continuationInfo) {
    return;
  }

  continuationInfo->MemberSerialize(archive);
}

/**
 * Address: 0x00BCD2F0 (FUN_00BCD2F0, dynamic initializer for the global
 * `SContinueInfoSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
SContinueInfoSerializer::SContinueInfoSerializer()
  : mLoadCallback(&SContinueInfoSerializer::Deserialize)
  , mSaveCallback(&SContinueInfoSerializer::Serialize)
{}

/**
 * Address: 0x00BF74B0 (FUN_00BF74B0, ??1SContinueInfoSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
SContinueInfoSerializer::~SContinueInfoSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005B4820 (FUN_005B4820)
 */
void SContinueInfoSerializer::Init()
{
  gpg::RType* const type = CachedSContinueInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}
