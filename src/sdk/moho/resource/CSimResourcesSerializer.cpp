#include "moho/resource/CSimResourcesSerializer.h"

#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
   */
  void CSimResourcesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCSimResourcesType();
    resource_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }
} // namespace moho
