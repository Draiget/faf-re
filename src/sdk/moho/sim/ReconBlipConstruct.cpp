#include "moho/sim/ReconBlipConstruct.h"

#include <cstdlib>

#include "moho/sim/ReconBlip.h"

namespace
{
  moho::ReconBlipConstruct gReconBlipConstruct;

  [[nodiscard]] gpg::SerHelperBase* ConstructNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gReconBlipConstruct.mHelperNext);
  }

  void ResetReconBlipConstructLinksImpl() noexcept
  {
    gReconBlipConstruct.mHelperNext->mPrev = gReconBlipConstruct.mHelperPrev;
    gReconBlipConstruct.mHelperPrev->mNext = gReconBlipConstruct.mHelperNext;

    gpg::SerHelperBase* const self = ConstructNode();
    gReconBlipConstruct.mHelperPrev = self;
    gReconBlipConstruct.mHelperNext = self;
  }

  /**
   * Address: 0x005BFB60 (FUN_005BFB60)
   *
   * What it does:
   * Unlinks ReconBlip construct helper node from the global helper list and
   * rewires it as a self-linked singleton.
   */
  [[nodiscard]] gpg::SerHelperBase* ResetReconBlipConstructLinksPrimary()
  {
    ResetReconBlipConstructLinksImpl();
    return ConstructNode();
  }

  /**
   * Address: 0x005BFB90 (FUN_005BFB90)
   *
   * What it does:
   * Duplicate entry that performs the same construct-helper unlink/self-link
   * operation as 0x005BFB60.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* ResetReconBlipConstructLinksSecondary()
  {
    return ResetReconBlipConstructLinksPrimary();
  }

  /**
   * Address: 0x00BF7900 (FUN_00BF7900, cleanup_ReconBlipConstruct)
   *
   * What it does:
   * Process-exit cleanup that unlinks ReconBlip construct helper node.
   */
  void cleanup_ReconBlipConstruct()
  {
    (void)ResetReconBlipConstructLinksPrimary();
  }

  struct ReconBlipConstructBootstrap
  {
    ReconBlipConstructBootstrap()
    {
      moho::register_ReconBlipConstruct();
    }
  };

  [[maybe_unused]] ReconBlipConstructBootstrap gReconBlipConstructBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005BFBC0 (FUN_005BFBC0, Moho::ReconBlipConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow into `ReconBlip::MemberConstruct`.
   */
  void ReconBlipConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int version, gpg::SerConstructResult* const result
  )
  {
    if (!archive || !result) {
      return;
    }

    const gpg::RRef ownerRef{};
    ReconBlip::MemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void ReconBlipConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x005C9070 (FUN_005C9070, Moho::ReconBlipConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed object through its deleting-destructor vtable
   * entry when the pointer is non-null.
   */
  void ReconBlipConstruct::DeleteConstructedObject(void* const objectPtr)
  {
    if (!objectPtr) {
      return;
    }
    delete static_cast<ReconBlip*>(objectPtr);
  }

  /**
   * Address: 0x00BCDCA0 (FUN_00BCDCA0, register_ReconBlipConstruct)
   *
   * What it does:
   * Initializes ReconBlip construct helper callback lanes, binds them into
   * reflected RTTI, and installs process-exit cleanup.
   */
  void register_ReconBlipConstruct()
  {
    gpg::SerHelperBase* const self = ConstructNode();
    gReconBlipConstruct.mHelperNext = self;
    gReconBlipConstruct.mHelperPrev = self;
    gReconBlipConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ReconBlipConstruct::Construct);
    gReconBlipConstruct.mDeleteCallback = &ReconBlipConstruct::DeleteConstructedObject;
    gReconBlipConstruct.RegisterConstructFunction();
    (void)std::atexit(&cleanup_ReconBlipConstruct);
  }
} // namespace moho
