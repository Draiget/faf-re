#include "moho/resource/CAniResourceSkel.h"

#include "moho/resource/SScmFile.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/resource/RScmResource.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace moho
{
  gpg::RType* CAniResourceSkel::sType = nullptr;

  /**
   * Address: 0x00538480 (FUN_00538480,
   * ??0CAniResourceSkel@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
   *
   * IDA signature:
   * Moho::CAniResourceSkel *__thiscall CAniResourceSkel(
   *   Moho::CAniResourceSkel *this, std::string *name, boost::shared_ptr<SScmFile> *file);
   *
   * What it does:
   * Delegates to the `CAniSkel` base ctor to parse the SCM skeleton, then
   * installs the derived vtable (implicit) and copies the resource name into
   * `mName`. The binary empty-initializes the SSO string and assigns the full
   * source name (`assign(name, 0, npos)`).
   */
  CAniResourceSkel::CAniResourceSkel(const msvc8::string& name, const boost::shared_ptr<const SScmFile>& file)
    : CAniSkel(file)
  {
    mName.assign(name, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x00538500 (FUN_00538500, Moho::CAniResourceSkel::dtr thunk/body)
   */
  CAniResourceSkel::~CAniResourceSkel()
  {
    mName.tidy(true, 0u);
  }
} // namespace moho

namespace moho
{
  void CAniResourceSkel::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    msvc8::string path;
    archive.ReadString(&path);
    boost::shared_ptr<const CAniSkel> skeleton;
    if (const boost::shared_ptr<RScmResource> model = GetModel(path.c_str(), nullptr)) {
      skeleton = model->GetSkeleton();
    }
    result.SetShared(skeleton, 1u);
  }

  /**
   * Address: 0x00538770 (FUN_00538770)
   */
  void CAniResourceSkel::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    msvc8::string mountedPath;
    (void)FILE_ToMountedPath(&mountedPath, mName.c_str());
    archive.WriteString(&mountedPath);
    result.SetShared(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CAniResourceSkel>`, vtable 0x00E16340.
   *
   * Address: 0x00BC9080 (FUN_00BC9080 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3B80 (FUN_00BF3B80 -- the global's destructor.)
   * Address: 0x00539500 (FUN_00539500 -- `Init`.)
   * Address: 0x005386F0 (FUN_005386F0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct CAniResourceSkelSaveConstruct : gpg::SerSaveConstructHelper<CAniResourceSkel>
  {};

  /**
   * `gpg::SerConstructHelper<CAniResourceSkel>`, vtable 0x00E16350.
   *
   * Address: 0x00BC90B0 (FUN_00BC90B0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3BB0 (FUN_00BF3BB0 -- the global's destructor.)
   * Address: 0x00539580 (FUN_00539580 -- `Init`.)
   * Address: 0x005388C0 (FUN_005388C0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00539B80 (FUN_00539B80 -- `Delete`.)
   */
  struct CAniResourceSkelConstruct : gpg::SerConstructHelper<CAniResourceSkel>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ABBC8 -- process-global `CAniResourceSkelSaveConstruct` singleton.
  moho::CAniResourceSkelSaveConstruct gCAniResourceSkelSaveConstruct;

  // Address: 0x010ABBB4 -- process-global `CAniResourceSkelConstruct` singleton.
  moho::CAniResourceSkelConstruct gCAniResourceSkelConstruct;
} // namespace
