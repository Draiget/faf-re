#include "moho/resource/CParticleTextureReflection.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveCParticleTextureType()
  {
    return moho::resource_reflection::ResolveCParticleTextureType();
  }
} // namespace

/**
 * Address: 0x00490A60 (FUN_00490A60, gpg::RRef_CParticleTexture)
 *
 * What it does:
 * Builds one typed reflection reference for a `CParticleTexture*` lane,
 * resolving derived runtime type + base adjustment when needed.
 */
gpg::RRef* gpg::RRef_CParticleTexture(gpg::RRef* const outRef, moho::CParticleTexture* const value)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RType* const staticType = ResolveCParticleTextureType();
  outRef->mType = staticType;
  outRef->mObj = value;
  if (value == nullptr || staticType == nullptr) {
    return outRef;
  }

  const std::type_info& dynamicTypeInfo = typeid(*value);
  if (dynamicTypeInfo == typeid(moho::CParticleTexture)) {
    return outRef;
  }

  gpg::RType* const dynamicType = gpg::LookupRType(dynamicTypeInfo);
  if (dynamicType == nullptr) {
    return outRef;
  }

  std::int32_t baseOffset = 0;
  const bool isDerived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
  GPG_ASSERT(isDerived);
  if (!isDerived) {
    return outRef;
  }

  outRef->mType = dynamicType;
  outRef->mObj = reinterpret_cast<std::uint8_t*>(value) - static_cast<std::ptrdiff_t>(baseOffset);
  return outRef;
}

/**
 * Address: 0x0048FFD0 (FUN_0048FFD0, sub_48FFD0)
 *
 * What it does:
 * Wrapper that forwards to `RRef_CParticleTexture` and returns the output
 * lane pointer.
 */
gpg::RRef* gpg::AssignCParticleTextureRef(gpg::RRef* const outRef, moho::CParticleTexture* const value)
{
  return gpg::RRef_CParticleTexture(outRef, value);
}
