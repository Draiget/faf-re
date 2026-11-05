#include "gpg/core/reflection/Reflection.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

#include "moho/render/RDebugOverlay.h"
#include "moho/script/CScriptObject.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedRDebugOverlayType()
  {
    static gpg::RType* sType = nullptr;
    return moho::debug_reflection::ResolveCachedType(sType, typeid(moho::RDebugOverlay));
  }

  [[nodiscard]] gpg::RType* CachedRTypeType()
  {
    static gpg::RType* sType = nullptr;
    return moho::debug_reflection::ResolveCachedType(sType, typeid(gpg::RType));
  }

  [[nodiscard]] gpg::RType* CachedRObjectType()
  {
    static gpg::RType* sType = nullptr;
    return moho::debug_reflection::ResolveCachedType(sType, typeid(gpg::RObject));
  }
} // namespace

namespace moho::debug_reflection
{

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

    gpg::AddReflectedBaseType(owner, baseType);
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

  /**
   * Address: 0x0086D7E0 (FUN_0086D7E0, gpg::RType::AddBase_CScriptObject)
   *
   * What it does:
   * Registers `moho::CScriptObject` as a reflected base of `owner`, naming the
   * base field after the base type.
   */
  void AddBaseCScriptObject(gpg::RType* const owner)
  {
    AddBase(owner, moho::CScriptObject::StaticGetClass());
  }
} // namespace moho::debug_reflection
