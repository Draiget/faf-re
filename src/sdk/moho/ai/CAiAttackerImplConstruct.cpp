#include "moho/ai/CAiAttackerImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

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

  [[nodiscard]] gpg::RRef MakeCAiAttackerImplRef(CAiAttackerImpl* const object)
  {
    gpg::RRef ref{};
    gpg::RRef_CAiAttackerImpl(&ref, object);
    return ref;
  }

  /**
   * Address: 0x005D83A0 (FUN_005D83A0)
   *
   * What it does:
   * Allocates one `CAiAttackerImpl`, wraps it in a typed reflected reference,
   * and publishes that payload through `SerConstructResult::SetUnowned`.
   */
  void ConstructCAiAttackerImplForResult(gpg::SerConstructResult* const result)
  {
    CAiAttackerImpl* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiAttackerImpl), std::nothrow);
    if (storage) {
      object = new (storage) CAiAttackerImpl();
    }

    result->SetUnowned(MakeCAiAttackerImplRef(object), 0u);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkCAiAttackerImplConstructHelperNode()
  {
    if (!gCAiAttackerImplConstructConstructed) {
      return nullptr;
    }

    CAiAttackerImplConstruct* const construct = AcquireCAiAttackerImplConstruct();
    if (construct->mHelperNext && construct->mHelperPrev) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&construct->mHelperNext);
    construct->mHelperNext = self;
    construct->mHelperPrev = self;
    return self;
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
    (void)UnlinkCAiAttackerImplConstructHelperNode();
    construct->~CAiAttackerImplConstruct();
    gCAiAttackerImplConstructConstructed = false;
  }

  /**
   * Address: 0x005D8330 (FUN_005D8330)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks recovered
   * `CAiAttackerImplConstruct` helper links and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiAttackerImplConstructStartupThunkA()
  {
    return UnlinkCAiAttackerImplConstructHelperNode();
  }

  /**
   * Address: 0x005D8360 (FUN_005D8360)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same
   * `CAiAttackerImplConstruct` helper unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiAttackerImplConstructStartupThunkB()
  {
    return UnlinkCAiAttackerImplConstructHelperNode();
  }
} // namespace

/**
 * Address: 0x005D8390 (FUN_005D8390)
 *
 * What it does:
 * Construct-callback lane used by recovered `CAiAttackerImpl` reflection
 * helper registration. Forwards into the canonical helper body recovered at
 * `0x005D83A0`.
 */
void CAiAttackerImplConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  ConstructCAiAttackerImplForResult(result);
}

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
