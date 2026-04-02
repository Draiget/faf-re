#include "moho/ai/CAiBuilderImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBuilderImpl.h"

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
  alignas(CAiBuilderImplConstruct) unsigned char gCAiBuilderImplConstructStorage[sizeof(CAiBuilderImplConstruct)] = {};
  bool gCAiBuilderImplConstructConstructed = false;

  [[nodiscard]] gpg::SerHelperBase* HelperNode(CAiBuilderImplConstruct& construct) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&construct.mHelperNext);
  }

  [[nodiscard]] CAiBuilderImplConstruct* AcquireCAiBuilderImplConstruct()
  {
    if (!gCAiBuilderImplConstructConstructed) {
      new (gCAiBuilderImplConstructStorage) CAiBuilderImplConstruct();
      gCAiBuilderImplConstructConstructed = true;
    }

    return reinterpret_cast<CAiBuilderImplConstruct*>(gCAiBuilderImplConstructStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAiBuilderImplType()
  {
    gpg::RType* type = CAiBuilderImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBuilderImpl));
      CAiBuilderImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAiBuilderImplRef(CAiBuilderImpl* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCAiBuilderImplType();
    return ref;
  }

  /**
   * Address: 0x0059FD90 (FUN_0059FD90, construct helper)
   *
   * What it does:
   * Allocates one `CAiBuilderImpl` and stores an unowned reference into
   * serialization construct result output.
   */
  void ConstructAiBuilderImplForResult(gpg::SerConstructResult* const result)
  {
    CAiBuilderImpl* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiBuilderImpl), std::nothrow);
    if (storage) {
      object = new (storage) CAiBuilderImpl();
    }

    if (!result) {
      delete object;
      return;
    }
    result->SetUnowned(MakeCAiBuilderImplRef(object), 0u);
  }

  /**
   * Address: 0x00BF6AC0 (FUN_00BF6AC0, cleanup_CAiBuilderImplConstruct)
   *
   * What it does:
   * Unlinks recovered CAiBuilderImpl construct helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiBuilderImplConstruct()
  {
    if (!gCAiBuilderImplConstructConstructed) {
      return nullptr;
    }

    CAiBuilderImplConstruct* const construct = AcquireCAiBuilderImplConstruct();
    gpg::SerHelperBase* const self = HelperNode(*construct);
    if (construct->mHelperNext != nullptr && construct->mHelperPrev != nullptr) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    construct->mHelperNext = self;
    construct->mHelperPrev = self;
    return self;
  }

  void cleanup_CAiBuilderImplConstruct_atexit()
  {
    (void)cleanup_CAiBuilderImplConstruct();
  }
} // namespace

/**
 * Address: 0x0059FD80 (FUN_0059FD80, construct callback)
 */
void CAiBuilderImplConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }

  ConstructAiBuilderImplForResult(result);
}

/**
 * Address: 0x005A1C80 (FUN_005A1C80, delete callback)
 */
void CAiBuilderImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiBuilderImpl*>(object);
}

/**
 * Address: 0x005A0650 (FUN_005A0650)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiBuilderImplConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCC2E0 (FUN_00BCC2E0)
 *
 * What it does:
 * Initializes the global CAiBuilderImpl construct helper callbacks and
 * installs process-exit cleanup.
 */
int moho::register_CAiBuilderImplConstruct()
{
  CAiBuilderImplConstruct* const construct = AcquireCAiBuilderImplConstruct();
  gpg::SerHelperBase* const self = HelperNode(*construct);
  construct->mHelperNext = self;
  construct->mHelperPrev = self;
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiBuilderImplConstruct::Construct);
  construct->mDeleteCallback = &CAiBuilderImplConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&cleanup_CAiBuilderImplConstruct_atexit);
}

namespace
{
  struct CAiBuilderImplConstructBootstrap
  {
    CAiBuilderImplConstructBootstrap()
    {
      (void)moho::register_CAiBuilderImplConstruct();
    }
  };

  [[maybe_unused]] CAiBuilderImplConstructBootstrap gCAiBuilderImplConstructBootstrap;
} // namespace
