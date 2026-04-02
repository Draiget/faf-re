#include "moho/ai/CAiAttackerImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"

using namespace moho;

namespace
{
  alignas(CAiAttackerImplConstruct) unsigned char gCAiAttackerImplConstructStorage[sizeof(CAiAttackerImplConstruct)];
  bool gCAiAttackerImplConstructConstructed = false;

  [[nodiscard]] CAiAttackerImplConstruct* AcquireCAiAttackerImplConstruct()
  {
    if (!gCAiAttackerImplConstructConstructed) {
      new (gCAiAttackerImplConstructStorage) CAiAttackerImplConstruct();
      gCAiAttackerImplConstructConstructed = true;
    }

    return reinterpret_cast<CAiAttackerImplConstruct*>(gCAiAttackerImplConstructStorage);
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
   * Address: 0x00BF8400 (FUN_00BF8400, sub_BF8400)
   *
   * What it does:
   * Tears down recovered static `CAiAttackerImplConstruct` storage.
   */
  void cleanup_CAiAttackerImplConstruct()
  {
    if (!gCAiAttackerImplConstructConstructed) {
      return;
    }

    CAiAttackerImplConstruct* const construct = AcquireCAiAttackerImplConstruct();
    if (construct->mHelperNext && construct->mHelperPrev) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    construct->~CAiAttackerImplConstruct();
    gCAiAttackerImplConstructConstructed = false;
  }
} // namespace

/**
 * Address: 0x005D8390 (FUN_005D8390)
 *
 * What it does:
 * Construct-callback lane used by recovered `CAiAttackerImpl` reflection
 * helper registration.
 */
void CAiAttackerImplConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const)
{}

/**
 * Address: 0x005DEB50 (FUN_005DEB50)
 *
 * What it does:
 * Delete-callback lane used by recovered `CAiAttackerImpl` reflection helper
 * registration.
 */
void CAiAttackerImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiAttackerImpl*>(object);
}

/**
 * Address: 0x005DC050 (FUN_005DC050)
 *
 * What it does:
 * Lazily resolves `CAiAttackerImpl` RTTI and installs construct/delete
 * callbacks from this helper object into the type descriptor.
 */
void CAiAttackerImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiAttackerImplType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
  GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
  if (!type) {
    return;
  }

  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCE890 (FUN_00BCE890, register_CAiAttackerImplConstruct)
 *
 * What it does:
 * Registers `CAiAttackerImpl` construct/delete callbacks and installs
 * process-exit cleanup.
 */
int moho::register_CAiAttackerImplConstruct()
{
  CAiAttackerImplConstruct* const construct = AcquireCAiAttackerImplConstruct();
  construct->mHelperNext = reinterpret_cast<gpg::SerHelperBase*>(construct);
  construct->mHelperPrev = reinterpret_cast<gpg::SerHelperBase*>(construct);
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiAttackerImplConstruct::Construct);
  construct->mDeleteCallback = &CAiAttackerImplConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&cleanup_CAiAttackerImplConstruct);
}
