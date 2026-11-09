#include "gpg/core/reflection/Reflection.h"
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

} // namespace

namespace moho::audio_reflection
{
  gpg::RType* ResolveISoundManagerType()
  {
    return gpg::CachedLookup(CachedISoundManagerType(), typeid(moho::ISoundManager));
  }

  gpg::RType* ResolveCSimSoundManagerType()
  {
    return gpg::CachedLookup(CachedCSimSoundManagerType(), typeid(moho::CSimSoundManager));
  }

  gpg::RType* ResolveCScriptEventType()
  {
    return gpg::CachedLookup(CachedCScriptEventType(), typeid(moho::CScriptEvent));
  }

  void AddBase(gpg::RType* const ownerType, gpg::RType* const baseType)
  {
    if (!ownerType || !baseType) {
      return;
    }

    gpg::AddReflectedBaseType(ownerType, baseType);
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

} // namespace moho::audio_reflection

