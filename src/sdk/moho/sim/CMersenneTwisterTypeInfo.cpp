#include "moho/sim/CMersenneTwisterTypeInfo.h"

#include <typeinfo>

#include "moho/sim/CMersenneTwister.h"

namespace moho
{
  /**
   * Address: 0x0040EC70 (FUN_0040EC70, Moho::CMersenneTwisterTypeInfo::CMersenneTwisterTypeInfo)
   */
  CMersenneTwisterTypeInfo::CMersenneTwisterTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CMersenneTwister), this);
  }

  /**
   * Address: 0x0040ED00 (FUN_0040ED00, deleting dtor lane)
   */
  CMersenneTwisterTypeInfo::~CMersenneTwisterTypeInfo() = default;

  /**
   * Address: 0x0040ECF0 (FUN_0040ECF0, Moho::CMersenneTwisterTypeInfo::GetName)
   */
  const char* CMersenneTwisterTypeInfo::GetName() const
  {
    return "CMersenneTwister";
  }

  /**
   * Address: 0x0040ECD0 (FUN_0040ECD0, Moho::CMersenneTwisterTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CMersenneTwisterTypeInfo::Init(gpg::RType *this);
   */
  void CMersenneTwisterTypeInfo::Init()
  {
    size_ = sizeof(CMersenneTwister);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
