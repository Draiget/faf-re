#pragma once

#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho::debug_reflection
{
  [[nodiscard]]
  gpg::RType* ResolveCachedType(gpg::RType*& cachedType, const std::type_info& typeInfo);

  [[nodiscard]]
  gpg::RRef MakeRef(void* object, gpg::RType* typeInfo);

  void AddBase(gpg::RType* owner, gpg::RType* baseType);
  void AddBaseRDebugOverlay(gpg::RType* owner);
  void AddBaseRType(gpg::RType* owner);
  void AddBaseRObject(gpg::RType* owner);
  void AddBaseCScriptObject(gpg::RType* owner);

  template <typename TObject>
  [[nodiscard]]
  gpg::RType* ResolveObjectType(gpg::RType*& cachedType)
  {
    return cachedType ? cachedType : ResolveCachedType(cachedType, typeid(TObject));
  }

  template <typename TObject>
  [[nodiscard]]
  gpg::RRef NewRef(gpg::RType*& cachedType)
  {
    TObject* const object = new (std::nothrow) TObject();
    return MakeRef(object, ResolveObjectType<TObject>(cachedType));
  }

  template <typename TObject>
  [[nodiscard]]
  gpg::RRef CtrRef(void* objectStorage, gpg::RType*& cachedType)
  {
    auto* const object = static_cast<TObject*>(objectStorage);
    if (object != nullptr) {
      new (object) TObject();
    }
    return MakeRef(object, ResolveObjectType<TObject>(cachedType));
  }

  template <typename TObject>
  void Delete(void* objectStorage)
  {
    delete static_cast<TObject*>(objectStorage);
  }

  template <typename TObject>
  void Destruct(void* objectStorage)
  {
    auto* const object = static_cast<TObject*>(objectStorage);
    if (object != nullptr) {
      object->~TObject();
    }
  }
} // namespace moho::debug_reflection
