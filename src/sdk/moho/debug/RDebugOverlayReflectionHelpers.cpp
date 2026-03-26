#include "moho/debug/RDebugOverlayReflectionHelpers.h"

#include "moho/render/RDebugOverlay.h"
#include "moho/script/CScriptObject.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedRDebugOverlayType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RDebugOverlay));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedRTypeType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(gpg::RType));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedRObjectType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(gpg::RObject));
    }
    return sType;
  }
} // namespace

namespace moho::debug_reflection
{
  gpg::RType* ResolveCachedType(gpg::RType*& cachedType, const std::type_info& typeInfo)
  {
    if (cachedType == nullptr) {
      cachedType = gpg::LookupRType(typeInfo);
    }
    return cachedType;
  }

  gpg::RRef MakeRef(void* object, gpg::RType* const typeInfo)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = typeInfo;
    return out;
  }

  void AddBase(gpg::RType* const owner, gpg::RType* const baseType)
  {
    if (owner == nullptr || baseType == nullptr) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    owner->AddBase(baseField);
  }

  void AddBaseRDebugOverlay(gpg::RType* const owner)
  {
    AddBase(owner, CachedRDebugOverlayType());
  }

  void AddBaseRType(gpg::RType* const owner)
  {
    AddBase(owner, CachedRTypeType());
  }

  void AddBaseRObject(gpg::RType* const owner)
  {
    AddBase(owner, CachedRObjectType());
  }

  void AddBaseCScriptObject(gpg::RType* const owner)
  {
    AddBase(owner, moho::CScriptObject::StaticGetClass());
  }
} // namespace moho::debug_reflection
