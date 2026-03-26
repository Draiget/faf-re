#include "moho/unit/CUnitMotionTypeInfo.h"

#include <typeinfo>

#include "moho/unit/CUnitMotion.h"

namespace moho
{
  gpg::RType* CUnitMotion::sType = nullptr;

  gpg::RType* CUnitMotion::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitMotion));
    }
    return sType;
  }

  /**
   * Address: 0x006B7830 (FUN_006B7830, gpg::RType::~RType thunk owner)
   */
  CUnitMotionTypeInfo::~CUnitMotionTypeInfo() = default;

  /**
   * Address: 0x006B7820 (FUN_006B7820, Moho::CUnitMotionTypeInfo::GetName)
   */
  const char* CUnitMotionTypeInfo::GetName() const
  {
    return "CUnitMotion";
  }

  /**
   * Address: 0x006B7800 (FUN_006B7800, Moho::CUnitMotionTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_6B7800(_DWORD *this);
   */
  void CUnitMotionTypeInfo::Init()
  {
    size_ = sizeof(CUnitMotion);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
