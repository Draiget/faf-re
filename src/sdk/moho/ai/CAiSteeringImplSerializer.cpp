#include "moho/ai/CAiSteeringImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiSteeringImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiSteeringImplType()
  {
    gpg::RType* type = CAiSteeringImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSteeringImpl));
      CAiSteeringImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010AFDD0 -- process-global `CAiSteeringImplSerializer`
  // singleton. Constructing it runs CAiSteeringImplSerializer::
  // CAiSteeringImplSerializer() (0x00BCE4A0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers and explicitly registers this
  // translation unit's unlink callback via `atexit` (this class has no
  // user-declared destructor).
  CAiSteeringImplSerializer gCAiSteeringImplSerializer;

  /**
   * Address: 0x00BF8190 (FUN_00BF8190)
   *
   * What it does:
   * Unlinks the global `CAiSteeringImplSerializer` helper node from the
   * intrusive serializer chain and restores it to a self-linked node.
   * Registered by the real dynamic initializer (0x00BCE4A0) as the global's
   * `atexit` teardown.
   */
  void CleanupCAiSteeringImplSerializer()
  {
    gCAiSteeringImplSerializer.ResetLinks();
  }
} // namespace

/**
 * Address: 0x005D3B70 (FUN_005D3B70, Moho::CAiSteeringImplSerializer::Deserialize)
 */
void CAiSteeringImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const object = reinterpret_cast<CAiSteeringImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberDeserialize(archive);
}

/**
 * Address: 0x005D3B80 (FUN_005D3B80, Moho::CAiSteeringImplSerializer::Serialize)
 */
void CAiSteeringImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const object = reinterpret_cast<const CAiSteeringImpl*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !object) {
    return;
  }

  object->MemberSerialize(archive);
}

/**
 * Address: 0x00BCE4A0 (FUN_00BCE4A0, dynamic initializer for the global
 * `CAiSteeringImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the load/save callback fields, and explicitly
 * registers `atexit` cleanup.
 */
CAiSteeringImplSerializer::CAiSteeringImplSerializer()
  : mSerLoadFunc(&CAiSteeringImplSerializer::Deserialize)
  , mSerSaveFunc(&CAiSteeringImplSerializer::Serialize)
{
  (void)std::atexit(&CleanupCAiSteeringImplSerializer);
}

/**
 * Address: 0x005D3EB0 (FUN_005D3EB0)
 *
 * What it does:
 * Lazily resolves CAiSteeringImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiSteeringImplSerializer::Init()
{
  gpg::RType* const type = CachedCAiSteeringImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}
