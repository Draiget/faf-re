#include "moho/resource/CAniResourceSkelTypeInfo.h"

#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00538610 (FUN_00538610, Moho::CAniResourceSkelTypeInfo::dtr)
   */
  CAniResourceSkelTypeInfo::~CAniResourceSkelTypeInfo() = default;

  /**
   * Address: 0x00538600 (FUN_00538600, Moho::CAniResourceSkelTypeInfo::GetName)
   */
  const char* CAniResourceSkelTypeInfo::GetName() const
  {
    return "CAniResourceSkel";
  }

  /**
   * Address: 0x005385E0 (FUN_005385E0, Moho::CAniResourceSkelTypeInfo::Init)
   *
   * What it does:
   * Initializes reflection metadata for `CAniResourceSkel` and registers
   * `CAniSkel` as the single base type.
   */
  void CAniResourceSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniResourceSkel);
    gpg::RType::Init();
    resource_reflection::AddBase(this, resource_reflection::ResolveCAniSkelType());
    Finish();
  }
} // namespace moho
