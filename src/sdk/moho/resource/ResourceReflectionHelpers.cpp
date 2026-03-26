#include "moho/resource/ResourceReflectionHelpers.h"

#include <typeinfo>

#include "moho/animation/CAniSkel.h"
#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ISimResources.h"
#include "moho/resource/RD3DTextureResource.h"
#include "moho/render/ID3DTextureSheet.h"

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

  gpg::RType* ResolveRD3DTextureResourceType()
  {
    return ResolveCachedType(moho::RD3DTextureResource::sType, typeid(moho::RD3DTextureResource));
  }

  gpg::RType* ResolveID3DTextureSheetType()
  {
    return ResolveCachedType(moho::ID3DTextureSheet::sType, typeid(moho::ID3DTextureSheet));
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
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    ownerType->AddBase(baseField);
  }

  void RegisterConstructCallbacks(
    gpg::RType* const typeInfo,
    const gpg::RType::construct_func_t constructCallback,
    const gpg::RType::delete_func_t deleteCallback
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = constructCallback;
    typeInfo->deleteFunc_ = deleteCallback;
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

  void RegisterSaveConstructArgsCallback(
    gpg::RType* const typeInfo, const gpg::RType::save_construct_args_func_t saveConstructArgsCallback
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = saveConstructArgsCallback;
  }
} // namespace moho::resource_reflection
