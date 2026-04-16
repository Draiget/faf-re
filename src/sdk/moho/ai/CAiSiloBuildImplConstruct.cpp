#include "moho/ai/CAiSiloBuildImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  alignas(CAiSiloBuildImplConstruct) unsigned char gCAiSiloBuildImplConstructStorage[sizeof(CAiSiloBuildImplConstruct)];
  bool gCAiSiloBuildImplConstructConstructed = false;

  [[nodiscard]] CAiSiloBuildImplConstruct* AcquireCAiSiloBuildImplConstruct()
  {
    if (!gCAiSiloBuildImplConstructConstructed) {
      new (gCAiSiloBuildImplConstructStorage) CAiSiloBuildImplConstruct();
      gCAiSiloBuildImplConstructConstructed = true;
    }

    return reinterpret_cast<CAiSiloBuildImplConstruct*>(gCAiSiloBuildImplConstructStorage);
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
    construct.mHelperNext->mPrev = construct.mHelperPrev;
    construct.mHelperPrev->mNext = construct.mHelperNext;
    gpg::SerHelperBase* const self = ConstructSelfNode(construct);
    construct.mHelperPrev = self;
    construct.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedCAiSiloBuildImplType()
  {
    gpg::RType* type = CAiSiloBuildImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSiloBuildImpl));
      CAiSiloBuildImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005CF7E0 (FUN_005CF7E0, CAiSiloBuildImplConstruct cleanup helper variant)
   *
   * What it does:
   * Unlinks `CAiSiloBuildImplConstruct` from the intrusive helper list,
   * resets self-links, and returns the helper node.
   */
  [[maybe_unused, nodiscard]] gpg::SerHelperBase* cleanup_CAiSiloBuildImplConstruct_primary()
  {
    CAiSiloBuildImplConstruct* const construct =
      reinterpret_cast<CAiSiloBuildImplConstruct*>(gCAiSiloBuildImplConstructStorage);
    return UnlinkConstructNode(*construct);
  }

  /**
   * Address: 0x005CF810 (FUN_005CF810, CAiSiloBuildImplConstruct cleanup helper variant)
   *
   * What it does:
   * Secondary cleanup variant that unlinks
   * `CAiSiloBuildImplConstruct` from the intrusive helper list, resets
   * self-links, and returns the helper node.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiSiloBuildImplConstruct_secondary()
  {
    CAiSiloBuildImplConstruct* const construct =
      reinterpret_cast<CAiSiloBuildImplConstruct*>(gCAiSiloBuildImplConstructStorage);
    return UnlinkConstructNode(*construct);
  }

  /**
   * Address: 0x00BF7F30 (FUN_00BF7F30, cleanup_CAiSiloBuildImplConstruct)
   *
   * What it does:
   * Startup teardown hook that performs the construct helper unlink/reset and
   * returns the helper node.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiSiloBuildImplConstruct()
  {
    return cleanup_CAiSiloBuildImplConstruct_secondary();
  }

  void cleanup_CAiSiloBuildImplConstruct_atexit()
  {
    (void)cleanup_CAiSiloBuildImplConstruct();
  }
} // namespace

/**
 * Address: 0x005CF840 (FUN_005CF840, Moho::CAiSiloBuildImplConstruct::Construct)
 */
void CAiSiloBuildImplConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result)
{
  if (!result) {
    return;
  }

  CAiSiloBuildImpl::MemberConstruct(result);
}

/**
 * Address: 0x005D0870 (FUN_005D0870, Moho::CAiSiloBuildImplConstruct::Deconstruct)
 */
void CAiSiloBuildImplConstruct::Deconstruct(void* const objectPtr)
{
  delete static_cast<CAiSiloBuildImpl*>(objectPtr);
}

/**
 * Address: 0x00BCE110 (FUN_00BCE110, register_CAiSiloBuildImplConstruct)
 *
 * What it does:
 * Registers construct/delete callbacks for `CAiSiloBuildImpl` and installs
 * process-exit cleanup.
 */
int moho::register_CAiSiloBuildImplConstruct()
{
  CAiSiloBuildImplConstruct* const construct = AcquireCAiSiloBuildImplConstruct();
  InitializeConstructNode(*construct);
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiSiloBuildImplConstruct::Construct);
  construct->mDeleteCallback = &CAiSiloBuildImplConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&cleanup_CAiSiloBuildImplConstruct_atexit);
}

/**
 * Address: 0x005CFEB0 (FUN_005CFEB0)
 *
 * void ()
 *
 * IDA signature:
 * int __thiscall sub_5CFEB0(_DWORD *this);
 *
 * What it does:
 * Lazily resolves CAiSiloBuildImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiSiloBuildImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiSiloBuildImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
