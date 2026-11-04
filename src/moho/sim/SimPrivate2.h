#pragma once

// Private to moho/sim: helpers the pieces of the former Sim.cpp share.

#include "moho/sim/SimPrivate.h"

namespace
{

  std::uint32_t FloatBits(const float value)
  {
    return std::bit_cast<std::uint32_t>(value);
  }

  void ReadEntityVelocity(Entity* entity, Wm3::Vec3f* outVelocity)
  {
    if (!entity || !outVelocity) {
      return;
    }

    *outVelocity = entity->GetVelocity();
  }

  void* GetSimVarStorage(CSimConVarInstanceBase* instance)
  {
    if (!instance) {
      return nullptr;
    }

    return instance->GetValueStorage();
  }

  bool ReadSimConVarBool(Sim* sim, CSimConVarBase* conVar, const bool defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const uint8_t*>(valuePtr) != 0;
  }

  int ReadSimConVarInt(Sim* sim, CSimConVarBase* conVar, const int defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const int*>(valuePtr);
  }

  // `CUnitIterAllArmies` (0x006B6AA0 ctor, 0x005C87A0 step): the unit-family
  // range of `EntityDB::mAllUnits`, every army.
  template <typename Fn>
  void ForEachAllArmyUnit(Sim* const sim, Fn&& fn)
  {
    for (CUnitIterAllArmies iter(sim); iter.mItr != iter.mEnd; iter.Next()) {
      if (Unit* const unit = iter.mCur; unit != nullptr) {
        fn(unit);
      }
    }
  }

  void RunQueuedDestroy(void* queuedObject)
  {
    if (!queuedObject) {
      return;
    }

    Entity* entity = static_cast<Entity*>(queuedObject);
    entity->OnDestroy();
  }
}

