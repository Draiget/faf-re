#include "moho/resource/CAniResourceSkelSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/WriteArchive.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetShared(unsigned int flags);
  };
} // namespace gpg

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

  void CleanupCAniResourceSkelSaveConstructAtexit()
  {
    (void)CleanupCAniResourceSkelSaveConstructHelperNodePrimary();
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

  /**
   * Address: 0x00538770 (FUN_00538770, sub_538770)
   *
   * IDA signature:
   * void callcnv_F3 sub_538770(int a1@<edi>, int a2@<esi>, gpg::SerSaveConstructArgsResult *a3);
   *
   * What it does:
   * Maps the resource's model-path (`CAniResourceSkel::mName`) through the
   * mounted virtual file system, writes the resulting mounted path into the
   * write archive, then marks the save-construct result ownership lane shared.
   */
  static void WriteAniResourceSkelSaveConstructArgs(
    gpg::WriteArchive* const archive,
    const CAniResourceSkel* const resource,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    msvc8::string mountedPath{};
    (void)FILE_ToMountedPath(&mountedPath, resource->mName.c_str());
    archive->WriteString(&mountedPath);
    result->SetShared(1u);
  }

  /**
   * Address: 0x005386F0 (FUN_005386F0, Moho::CAniResourceSkelSaveConstruct::Construct)
   *
   * IDA signature:
   * void __cdecl sub_5386F0(int a1, int a2, int a3, int a4, gpg::SerSaveConstructArgsResult *a5);
   *
   * What it does:
   * Save-construct-args callback entry: forwards `(archive, resource, result)`
   * to the mounted-path writer helper.
   */
  void CAniResourceSkelSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    CAniResourceSkel* const resource,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    WriteAniResourceSkelSaveConstructArgs(archive, resource, result);
  }

  /**
   * Address: 0x00BC9080 (FUN_00BC9080, register_CAniResourceSkelSaveConstruct)
   *
   * What it does:
   * Initializes the global save-construct helper node, installs `&Construct`
   * as the save-construct-args callback, binds it into `CAniResourceSkel`
   * RTTI, and schedules helper-node teardown at process exit.
   */
  void register_CAniResourceSkelSaveConstruct()
  {
    gpg::SerHelperBase* const self =
      reinterpret_cast<gpg::SerHelperBase*>(&gCAniResourceSkelSaveConstruct.mHelperNext);
    gCAniResourceSkelSaveConstruct.mHelperNext = self;
    gCAniResourceSkelSaveConstruct.mHelperPrev = self;
    gCAniResourceSkelSaveConstruct.mSerSaveConstructArgsFunc =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CAniResourceSkelSaveConstruct::Construct);
    // Binds the callback into CAniResourceSkel RTTI. The binary splits this into a
    // separate helper (SerSaveConstructHelper::Init, 0x00539500) invoked from the
    // reflection path; invoking it here keeps the callback installed and matches the
    // sibling SaveConstruct-helper registration idiom (LuaState/Projectile/etc.).
    gCAniResourceSkelSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupCAniResourceSkelSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct CAniResourceSkelSaveConstructBootstrap
  {
    CAniResourceSkelSaveConstructBootstrap()
    {
      moho::register_CAniResourceSkelSaveConstruct();
    }
  };

  CAniResourceSkelSaveConstructBootstrap gCAniResourceSkelSaveConstructBootstrap;
} // namespace
