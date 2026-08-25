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
  // Address: 0x010ABBC8 -- process-global `CAniResourceSkelSaveConstruct`
  // singleton (constructed by FUN_00BC9080, self-registering via `__xc_a`;
  // see CAniResourceSkelSaveConstruct.h for the real-ctor/atexit-target/
  // dead-duplicate evidence).
  moho::CAniResourceSkelSaveConstruct gCAniResourceSkelSaveConstruct;
} // namespace

namespace moho
{
  /**
   * Address: 0x00539500 (FUN_00539500, gpg::SerSaveConstructHelper_CAniResourceSkel::Init)
   *
   * What it does:
   * Resolves `CAniResourceSkel` RTTI and installs save-construct-args callback.
   */
  void CAniResourceSkelSaveConstruct::Init()
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
   * Address: 0x00BC9080 (FUN_00BC9080, dynamic initializer for the global
   * `CAniResourceSkelSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  CAniResourceSkelSaveConstruct::CAniResourceSkelSaveConstruct()
    : mSerSaveConstructArgsFunc(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CAniResourceSkelSaveConstruct::Construct)
      )
  {}

  CAniResourceSkelSaveConstruct::~CAniResourceSkelSaveConstruct()
  {
    ResetLinks();
  }
} // namespace moho
