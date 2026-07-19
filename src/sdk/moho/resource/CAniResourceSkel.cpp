#include "moho/resource/CAniResourceSkel.h"

#include "moho/resource/SScmFile.h"

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
