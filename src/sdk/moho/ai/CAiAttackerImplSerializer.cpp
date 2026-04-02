#include "moho/ai/CAiAttackerImplSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"

using namespace moho;

namespace
{
  alignas(CAiAttackerImplSerializer) unsigned char gCAiAttackerImplSerializerStorage[sizeof(CAiAttackerImplSerializer)];
  bool gCAiAttackerImplSerializerConstructed = false;

  [[nodiscard]] CAiAttackerImplSerializer* AcquireCAiAttackerImplSerializer()
  {
    if (!gCAiAttackerImplSerializerConstructed) {
      new (gCAiAttackerImplSerializerStorage) CAiAttackerImplSerializer();
      gCAiAttackerImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiAttackerImplSerializer*>(gCAiAttackerImplSerializerStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
    }
    return cached;
  }

  /**
   * Address: 0x00BF8430 (FUN_00BF8430, cleanup thunk)
   *
   * What it does:
   * Tears down recovered static `CAiAttackerImplSerializer` storage.
   */
  void cleanup_CAiAttackerImplSerializer()
  {
    if (!gCAiAttackerImplSerializerConstructed) {
      return;
    }

    CAiAttackerImplSerializer* const serializer = AcquireCAiAttackerImplSerializer();
    if (serializer->mHelperNext && serializer->mHelperPrev) {
      serializer->mHelperNext->mPrev = serializer->mHelperPrev;
      serializer->mHelperPrev->mNext = serializer->mHelperNext;
    }

    serializer->~CAiAttackerImplSerializer();
    gCAiAttackerImplSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005D8430 (FUN_005D8430, Moho::CAiAttackerImplSerializer::Deserialize)
 *
 * What it does:
 * Load-callback lane used by recovered `CAiAttackerImpl` serializer
 * registration.
 */
void CAiAttackerImplSerializer::Deserialize(gpg::ReadArchive* const, const int, const int, gpg::RRef* const)
{}

/**
 * Address: 0x005D8440 (FUN_005D8440, Moho::CAiAttackerImplSerializer::Serialize)
 *
 * What it does:
 * Save-callback lane used by recovered `CAiAttackerImpl` serializer
 * registration.
 */
void CAiAttackerImplSerializer::Serialize(gpg::WriteArchive* const, const int, const int, gpg::RRef* const)
{}

/**
 * Address: 0x005DC0D0 (FUN_005DC0D0)
 *
 * What it does:
 * Lazily resolves `CAiAttackerImpl` RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiAttackerImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiAttackerImplType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  if (!type) {
    return;
  }

  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE8D0 (FUN_00BCE8D0, register_CAiAttackerImplSerializer)
 *
 * What it does:
 * Registers `CAiAttackerImpl` serializer callbacks and installs process-exit
 * cleanup.
 */
void moho::register_CAiAttackerImplSerializer()
{
  CAiAttackerImplSerializer* const serializer = AcquireCAiAttackerImplSerializer();
  serializer->mHelperNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mHelperPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mLoadCallback = &CAiAttackerImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiAttackerImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiAttackerImplSerializer);
}
