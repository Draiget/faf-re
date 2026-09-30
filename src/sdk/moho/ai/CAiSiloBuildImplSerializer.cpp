#include "moho/ai/CAiSiloBuildImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSSiloBuildInfoType()
  {
    gpg::RType* type = SSiloBuildInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SSiloBuildInfo));
      SSiloBuildInfo::sType = type;
    }
    return type;
  }

  // Address: 0x010AFD8C -- process-global `SSiloBuildInfoSerializer`
  // singleton. Constructing it runs SSiloBuildInfoSerializer::
  // SSiloBuildInfoSerializer() (0x00BCE0B0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SSiloBuildInfoSerializer,
  // 0x00BF7EA0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  SSiloBuildInfoSerializer gSSiloBuildInfoSerializer;

} // namespace

/**
 * Address: 0x005CEC70 (FUN_005CEC70, Moho::SSiloBuildInfoSerializer::Deserialize)
 */
void SSiloBuildInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<SSiloBuildInfo*>(static_cast<std::uintptr_t>(objectPtr));
  SSiloBuildInfo::MemberDeserialize(archive, info);
}

/**
 * Address: 0x005CEC80 (FUN_005CEC80, Moho::SSiloBuildInfoSerializer::Serialize)
 */
void SSiloBuildInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<const SSiloBuildInfo*>(static_cast<std::uintptr_t>(objectPtr));
  SSiloBuildInfo::MemberSerialize(info, archive);
}

/**
 * Address: 0x00BCE0B0 (FUN_00BCE0B0, dynamic initializer for the global
 * `SSiloBuildInfoSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
SSiloBuildInfoSerializer::SSiloBuildInfoSerializer()
  : mLoadCallback(&SSiloBuildInfoSerializer::Deserialize)
  , mSaveCallback(&SSiloBuildInfoSerializer::Serialize)
{}

/**
 * Address: 0x00BF7EA0 (FUN_00BF7EA0, ??1SSiloBuildInfoSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
SSiloBuildInfoSerializer::~SSiloBuildInfoSerializer() = default;

/**
 * Address: 0x005CFB60 (FUN_005CFB60)
 *
 * What it does:
 * Lazily resolves `SSiloBuildInfo` RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void SSiloBuildInfoSerializer::Init()
{
  gpg::RType* const type = CachedSSiloBuildInfoType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE0B0 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `SSiloBuildInfoSerializer` singleton from an explicit registration
 * sequence. `gSSiloBuildInfoSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_SSiloBuildInfoSerializer()
{
  return 0;
}

/**
 * Address: 0x00BCE150 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiSiloBuildImplSerializer` singleton from an explicit registration
 * sequence. `gCAiSiloBuildImplSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_CAiSiloBuildImplSerializer()
{
  return 0;
}
