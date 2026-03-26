#include "moho/resource/RD3DTextureResourceTypeInfo.h"

#include "moho/resource/RD3DTextureResource.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x0043D660 (FUN_0043D660, Moho::RD3DTextureResourceTypeInfo::dtr)
   */
  RD3DTextureResourceTypeInfo::~RD3DTextureResourceTypeInfo() = default;

  /**
   * Address: 0x0043D650 (FUN_0043D650, Moho::RD3DTextureResourceTypeInfo::GetName)
   */
  const char* RD3DTextureResourceTypeInfo::GetName() const
  {
    return "RD3DTextureResource";
  }

  /**
   * Address: 0x0043D630 (FUN_0043D630, Moho::RD3DTextureResourceTypeInfo::Init)
   */
  void RD3DTextureResourceTypeInfo::Init()
  {
    size_ = sizeof(RD3DTextureResource);
    gpg::RType::Init();
    AddBase_ID3DTextureSheet(this);
    Finish();
  }

  /**
   * Address: 0x004454B0 (FUN_004454B0, Moho::RD3DTextureResourceTypeInfo::AddBase_ID3DTextureSheet)
   */
  void RD3DTextureResourceTypeInfo::AddBase_ID3DTextureSheet(gpg::RType* const typeInfo)
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveID3DTextureSheetType());
  }
} // namespace moho
