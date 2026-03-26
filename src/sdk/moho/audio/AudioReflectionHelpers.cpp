#include "moho/audio/AudioReflectionHelpers.h"

#include <typeinfo>

#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/ISoundManager.h"
#include "moho/script/CScriptEvent.h"

namespace
{
  gpg::RType*& CachedISoundManagerType()
  {
    static gpg::RType* sType = nullptr;
    return sType;
  }

  gpg::RType*& CachedCSimSoundManagerType()
  {
    static gpg::RType* sType = nullptr;
    return sType;
  }

  gpg::RType*& CachedCScriptEventType()
  {
    static gpg::RType* sType = nullptr;
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cachedType, const std::type_info& typeInfo)
  {
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeInfo);
    }
    return cachedType;
  }
} // namespace

namespace moho::audio_reflection
{
  gpg::RType* ResolveISoundManagerType()
  {
    return ResolveCachedType(CachedISoundManagerType(), typeid(moho::ISoundManager));
  }

  gpg::RType* ResolveCSimSoundManagerType()
  {
    return ResolveCachedType(CachedCSimSoundManagerType(), typeid(moho::CSimSoundManager));
  }

  gpg::RType* ResolveCScriptEventType()
  {
    return ResolveCachedType(CachedCScriptEventType(), typeid(moho::CScriptEvent));
  }

  void AddBase(gpg::RType* const ownerType, gpg::RType* const baseType)
  {
    if (!ownerType || !baseType) {
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
} // namespace moho::audio_reflection

