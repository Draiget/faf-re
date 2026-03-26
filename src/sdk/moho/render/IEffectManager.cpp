#include "moho/render/IEffectManager.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* IEffectManager::sType = nullptr;

  gpg::RType* IEffectManager::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IEffectManager));
    }
    return sType;
  }

  /**
   * Address: 0x0066B1F0 (FUN_0066B1F0, Moho::IEffectManager::dtr)
   */
  IEffectManager::~IEffectManager() = default;
} // namespace moho
