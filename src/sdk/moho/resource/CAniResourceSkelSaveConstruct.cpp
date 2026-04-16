#include "moho/resource/CAniResourceSkelSaveConstruct.h"

#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  moho::CAniResourceSkelSaveConstruct gCAniResourceSkelSaveConstruct{};

  [[nodiscard]] gpg::SerHelperBase* ResetCAniResourceSkelSaveConstructHelperLinks() noexcept
  {
    gCAniResourceSkelSaveConstruct.mHelperNext->mPrev = gCAniResourceSkelSaveConstruct.mHelperPrev;
    gCAniResourceSkelSaveConstruct.mHelperPrev->mNext = gCAniResourceSkelSaveConstruct.mHelperNext;
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gCAniResourceSkelSaveConstruct.mHelperNext);
    gCAniResourceSkelSaveConstruct.mHelperPrev = self;
    gCAniResourceSkelSaveConstruct.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00538710 (FUN_00538710)
   *
   * What it does:
   * Unlinks `CAniResourceSkelSaveConstruct` helper node from the intrusive
   * helper list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCAniResourceSkelSaveConstructHelperNodePrimary() noexcept
  {
    return ResetCAniResourceSkelSaveConstructHelperLinks();
  }

  /**
   * Address: 0x00538740 (FUN_00538740)
   *
   * What it does:
   * Secondary entrypoint for `CAniResourceSkelSaveConstruct` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCAniResourceSkelSaveConstructHelperNodeSecondary() noexcept
  {
    return ResetCAniResourceSkelSaveConstructHelperLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00539500 (FUN_00539500, gpg::SerSaveConstructHelper_CAniResourceSkel::Init)
   *
   * What it does:
   * Resolves `CAniResourceSkel` RTTI and installs save-construct-args callback.
   */
  void CAniResourceSkelSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCAniResourceSkelType();
    resource_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }
} // namespace moho
