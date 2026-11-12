#include "gpg/core/reflection/Reflection.h"
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
  } // namespace

  gpg::RType* ResolveCAniSkelType()
  {
    return gpg::CachedLookup(moho::CAniSkel::sType, typeid(moho::CAniSkel));
  }

  gpg::RType* ResolveCParticleTextureType()
  {
    return gpg::CachedLookup(moho::CParticleTexture::sType, typeid(moho::CParticleTexture));
  }

  gpg::RType* ResolveCSimResourcesType()
  {
    return gpg::CachedLookup(moho::CSimResources::sType, typeid(moho::CSimResources));
  }

  gpg::RType* ResolveISimResourcesType()
  {
    return gpg::CachedLookup(moho::ISimResources::sType, typeid(moho::ISimResources));
  }

  gpg::RType* ResolveIResourcesType()
  {
    return gpg::CachedLookup(moho::IResources::sType, typeid(moho::IResources));
  }

  // ResolveRD3DTextureResourceType and ResolveID3DTextureSheetType are defined in
  // moho/render/d3d/RD3DTextureResourceTypeInfo.cpp (render device, client side).

  void AddBase(
    gpg::RType* const ownerType,
    gpg::RType* const baseType
  )
  {
    if (ownerType == nullptr || baseType == nullptr) {
      return;
    }

    gpg::AddReflectedBaseType(ownerType, baseType);
  }

} // namespace moho::resource_reflection
