#include "moho/resource/ResourceReflectionHelpers.h"

#include <typeinfo>

#include "gpg/core/streams/MemBufferStream.h"
#include "moho/animation/CAniSkel.h"
#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ISimResources.h"

namespace moho::resource_reflection
{
  namespace
  {
    [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cachedType, const std::type_info& typeInfo)
    {
      if (cachedType == nullptr) {
        cachedType = gpg::LookupRType(typeInfo);
      }
      return cachedType;
    }
  } // namespace

  gpg::RType* ResolveCAniSkelType()
  {
    return ResolveCachedType(moho::CAniSkel::sType, typeid(moho::CAniSkel));
  }

  gpg::RType* ResolveCAniResourceSkelType()
  {
    return ResolveCachedType(moho::CAniResourceSkel::sType, typeid(moho::CAniResourceSkel));
  }

  gpg::RType* ResolveCParticleTextureType()
  {
    return ResolveCachedType(moho::CParticleTexture::sType, typeid(moho::CParticleTexture));
  }

  gpg::RType* ResolveCSimResourcesType()
  {
    return ResolveCachedType(moho::CSimResources::sType, typeid(moho::CSimResources));
  }

  gpg::RType* ResolveISimResourcesType()
  {
    return ResolveCachedType(moho::ISimResources::sType, typeid(moho::ISimResources));
  }

  gpg::RType* ResolveIResourcesType()
  {
    return ResolveCachedType(moho::IResources::sType, typeid(moho::IResources));
  }

  // ResolveRD3DTextureResourceType and ResolveID3DTextureSheetType are defined in
  // moho/render/d3d/RD3DTextureResourceTypeInfo.cpp (render device, client side).

  gpg::RType* ResolveMemBufferConstType()
  {
    return ResolveCachedType(gpg::MemBuffer<const char>::sType, typeid(gpg::MemBuffer<const char>));
  }

  void AddBase(gpg::RType* const ownerType, gpg::RType* const baseType)
  {
    if (ownerType == nullptr || baseType == nullptr) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    ownerType->AddBase(baseField);
  }

  void RegisterSerializeCallbacks(
    gpg::RType* const typeInfo, const gpg::RType::load_func_t loadCallback, const gpg::RType::save_func_t saveCallback
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr);
    typeInfo->serLoadFunc_ = loadCallback;
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr);
    typeInfo->serSaveFunc_ = saveCallback;
  }

} // namespace moho::resource_reflection
