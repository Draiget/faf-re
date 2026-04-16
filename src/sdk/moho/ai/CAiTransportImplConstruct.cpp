#include "moho/ai/CAiTransportImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(CAiTransportImplConstruct) unsigned char gCAiTransportImplConstructStorage[sizeof(CAiTransportImplConstruct)];
  bool gCAiTransportImplConstructConstructed = false;

  [[nodiscard]] CAiTransportImplConstruct* AcquireCAiTransportImplConstruct()
  {
    if (!gCAiTransportImplConstructConstructed) {
      new (gCAiTransportImplConstructStorage) CAiTransportImplConstruct();
      gCAiTransportImplConstructConstructed = true;
    }

    return reinterpret_cast<CAiTransportImplConstruct*>(gCAiTransportImplConstructStorage);
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
  void UnlinkConstructNode(TConstruct& construct) noexcept
  {
    if (construct.mHelperNext != nullptr && construct.mHelperPrev != nullptr) {
      construct.mHelperNext->mPrev = construct.mHelperPrev;
      construct.mHelperPrev->mNext = construct.mHelperNext;
    }

    InitializeConstructNode(construct);
  }

  /**
   * Address: 0x005E8490 (FUN_005E8490)
   *
   * What it does:
   * Splices this construct helper node out of its intrusive lane when linked,
   * then resets helper links to self and returns the self node pointer.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCAiTransportImplConstructHelperNodeVariantA(
    CAiTransportImplConstruct& construct
  ) noexcept
  {
    UnlinkConstructNode(construct);
    return ConstructSelfNode(construct);
  }

  /**
   * Address: 0x005E84C0 (FUN_005E84C0)
   *
   * What it does:
   * Secondary helper-node unlink/reset variant that preserves the same
   * intrusive unlink semantics and returns the helper self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCAiTransportImplConstructHelperNodeVariantB(
    CAiTransportImplConstruct& construct
  ) noexcept
  {
    return UnlinkCAiTransportImplConstructHelperNodeVariantA(construct);
  }

  [[nodiscard]] gpg::RType* CachedCAiTransportImplType()
  {
    gpg::RType* type = CAiTransportImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTransportImpl));
      CAiTransportImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005E9B80 (FUN_005E9B80)
   *
   * What it does:
   * Initializes callback lanes for global `CAiTransportImplConstruct` helper
   * storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] CAiTransportImplConstruct* InitializeCAiTransportImplConstructStartupThunk()
  {
    CAiTransportImplConstruct* const construct = AcquireCAiTransportImplConstruct();
    InitializeConstructNode(*construct);
    construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiTransportImplConstruct::Construct);
    construct->mDeleteCallback = &CAiTransportImplConstruct::Deconstruct;
    return construct;
  }

  void cleanup_CAiTransportImplConstruct()
  {
    if (!gCAiTransportImplConstructConstructed) {
      return;
    }

    CAiTransportImplConstruct* const construct = AcquireCAiTransportImplConstruct();
    (void)UnlinkCAiTransportImplConstructHelperNodeVariantA(*construct);
    construct->~CAiTransportImplConstruct();
    gCAiTransportImplConstructConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E84F0 (FUN_005E84F0, Moho::CAiTransportImplConstruct::Construct)
 *
 * What it does:
 * Forwards construct callback flow into `CAiTransportImpl::MemberConstruct`.
 */
void CAiTransportImplConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result)
{
  if (!result) {
    return;
  }

  CAiTransportImpl::MemberConstruct(result);
}

/**
 * Address: 0x005EC380 (FUN_005EC380, Moho::CAiTransportImplConstruct::Deconstruct)
 *
 * What it does:
 * Deletes one constructed `CAiTransportImpl` object.
 */
void CAiTransportImplConstruct::Deconstruct(void* const objectPtr)
{
  delete static_cast<CAiTransportImpl*>(objectPtr);
}

/**
 * Address: 0x00BCEF10 (FUN_00BCEF10, register_CAiTransportImplConstruct)
 *
 * What it does:
 * Registers construct/delete callbacks for `CAiTransportImpl` and installs
 * process-exit cleanup.
 */
void moho::register_CAiTransportImplConstruct()
{
  CAiTransportImplConstruct* const construct = AcquireCAiTransportImplConstruct();
  InitializeConstructNode(*construct);
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiTransportImplConstruct::Construct);
  construct->mDeleteCallback = &CAiTransportImplConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  (void)std::atexit(&cleanup_CAiTransportImplConstruct);
}

/**
 * Address: 0x005E9BB0 (FUN_005E9BB0)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiTransportImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
