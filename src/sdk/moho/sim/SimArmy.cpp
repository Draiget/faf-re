#include "SimArmy.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* IArmy::sType = nullptr;
  gpg::RType* SimArmy::sType = nullptr;

  gpg::RType* IArmy::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IArmy));
    }
    return sType;
  }

  gpg::RType* SimArmy::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SimArmy));
    }
    return sType;
  }

  IArmy::~IArmy() = default;

  /**
   * Address: 0x006FDAD0 (FUN_006FDAD0, Moho::SimArmy::~SimArmy)
   */
  SimArmy::~SimArmy() = default;
} // namespace moho
