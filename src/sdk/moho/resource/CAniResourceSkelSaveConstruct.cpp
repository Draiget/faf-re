#include "moho/resource/CAniResourceSkelSaveConstruct.h"

#include "moho/resource/ResourceReflectionHelpers.h"

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
