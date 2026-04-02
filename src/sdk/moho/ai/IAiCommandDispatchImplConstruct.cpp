#include "moho/ai/IAiCommandDispatchImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatchImpl.h"

using namespace moho;

namespace
{
  alignas(IAiCommandDispatchImplConstruct)
  unsigned char gIAiCommandDispatchImplConstructStorage[sizeof(IAiCommandDispatchImplConstruct)] = {};
  bool gIAiCommandDispatchImplConstructConstructed = false;

  [[nodiscard]] IAiCommandDispatchImplConstruct* AcquireIAiCommandDispatchImplConstruct()
  {
    if (!gIAiCommandDispatchImplConstructConstructed) {
      new (gIAiCommandDispatchImplConstructStorage) IAiCommandDispatchImplConstruct();
      gIAiCommandDispatchImplConstructConstructed = true;
    }

    return reinterpret_cast<IAiCommandDispatchImplConstruct*>(gIAiCommandDispatchImplConstructStorage);
  }

  template <typename TConstruct>
  [[nodiscard]] gpg::SerHelperBase* ConstructSelfNode(TConstruct& construct) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&construct.mHelperNext);
  }

  template <typename TConstruct>
  void InitializeConstructNode(TConstruct& construct) noexcept
  {
    gpg::SerHelperBase* const self = ConstructSelfNode(construct);
    construct.mHelperNext = self;
    construct.mHelperPrev = self;
  }

  template <typename TConstruct>
  [[nodiscard]] gpg::SerHelperBase* UnlinkConstructNode(TConstruct& construct) noexcept
  {
    if (construct.mHelperNext != nullptr && construct.mHelperPrev != nullptr) {
      construct.mHelperNext->mPrev = construct.mHelperPrev;
      construct.mHelperPrev->mNext = construct.mHelperNext;
    }

    gpg::SerHelperBase* const self = ConstructSelfNode(construct);
    construct.mHelperPrev = self;
    construct.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF66C0 (FUN_00BF66C0, cleanup_IAiCommandDispatchImplConstruct)
   *
   * What it does:
   * Unlinks recovered construct helper node from intrusive serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_IAiCommandDispatchImplConstruct()
  {
    if (!gIAiCommandDispatchImplConstructConstructed) {
      return nullptr;
    }

    return UnlinkConstructNode(*AcquireIAiCommandDispatchImplConstruct());
  }

  void cleanup_IAiCommandDispatchImplConstruct_atexit()
  {
    (void)cleanup_IAiCommandDispatchImplConstruct();
  }
} // namespace

/**
 * Address: 0x00599320 (FUN_00599320, Moho::IAiCommandDispatchImplConstruct::Construct)
 */
void IAiCommandDispatchImplConstruct::Construct(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::SerConstructResult* const result
)
{
  IAiCommandDispatchImpl::MemberConstruct(archive, objectPtr, version, result);
}

/**
 * Address: 0x005999D0 (FUN_005999D0, Moho::IAiCommandDispatchImplConstruct::Deconstruct)
 */
void IAiCommandDispatchImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<IAiCommandDispatchImpl*>(object);
}

/**
 * Address: 0x00599650 (FUN_00599650)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs construct/delete
 * callbacks from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x00BCBEC0 (FUN_00BCBEC0, register_IAiCommandDispatchImplConstruct)
 *
 * What it does:
 * Initializes recovered construct helper storage/callback lanes and installs
 * process-exit unlink cleanup.
 */
void moho::register_IAiCommandDispatchImplConstruct()
{
  IAiCommandDispatchImplConstruct* const construct = AcquireIAiCommandDispatchImplConstruct();
  InitializeConstructNode(*construct);
  construct->mConstructFunc = reinterpret_cast<gpg::RType::construct_func_t>(&IAiCommandDispatchImplConstruct::Construct);
  construct->mDeleteFunc = &IAiCommandDispatchImplConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  (void)std::atexit(&cleanup_IAiCommandDispatchImplConstruct_atexit);
}

namespace
{
  struct IAiCommandDispatchImplConstructBootstrap
  {
    IAiCommandDispatchImplConstructBootstrap()
    {
      moho::register_IAiCommandDispatchImplConstruct();
    }
  };

  [[maybe_unused]] IAiCommandDispatchImplConstructBootstrap gIAiCommandDispatchImplConstructBootstrap;
} // namespace
