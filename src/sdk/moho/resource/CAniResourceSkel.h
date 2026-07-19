#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/animation/CAniSkel.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  struct SScmFile;

  class CAniResourceSkel : public CAniSkel
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00538480 (FUN_00538480,
     * ??0CAniResourceSkel@Moho@@QAE@VStrArg@gpg@@ABV?$shared_ptr@$$CBUSScmFile@Moho@@@boost@@@Z)
     *
     * IDA signature:
     * Moho::CAniResourceSkel *__thiscall CAniResourceSkel(
     *   Moho::CAniResourceSkel *this, std::string *name, boost::shared_ptr<SScmFile> *file);
     *
     * What it does:
     * Constructs the `CAniSkel` base from the SCM file (parses the skeleton),
     * installs the `CAniResourceSkel` vtable, and copies the resource name into
     * `mName`.
     */
    CAniResourceSkel(const msvc8::string& name, const boost::shared_ptr<const SScmFile>& file);

    /**
     * Address: 0x00538500 (FUN_00538500, Moho::CAniResourceSkel::dtr thunk/body)
     * Slot: 0
     */
    ~CAniResourceSkel() override;

  public:
    msvc8::string mName; // +0x2C
  };

  static_assert(offsetof(CAniResourceSkel, mName) == 0x2C, "CAniResourceSkel::mName offset must be 0x2C");
  static_assert(sizeof(CAniResourceSkel) == 0x48, "CAniResourceSkel size must be 0x48");
} // namespace moho
