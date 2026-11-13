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

  gpg::RType* ResolveCScriptEventType()
  {
    return gpg::CachedLookup(CachedCScriptEventType(), typeid(moho::CScriptEvent));
  }

  void AddBase(
    gpg::RType* const ownerType,
    gpg::RType* const baseType
  )
  {
    if (!ownerType || !baseType) {
      return;
    }

    gpg::AddReflectedBaseType(ownerType, baseType);
  }

} // namespace moho::audio_reflection
