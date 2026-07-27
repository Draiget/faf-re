#pragma once

/**
 * Shared read access to sim console variables.
 *
 * The engine reaches a con-var's value in three hops - resolve the registered
 * console command by name, narrow it to a variable, then ask the `Sim` for that
 * variable's per-simulation instance - because the same variable object carries
 * a distinct value per running simulation. Every recovered call site does the
 * same walk, so it lives here rather than being open-coded per translation unit.
 */

#include <string>

#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/Sim.h"

namespace moho
{
  /**
   * Resolves one registered console command by name and narrows it to a
   * variable. Returns null when the name is unknown or names a command that is
   * not a variable.
   */
  [[nodiscard]] inline CSimConVarBase* FindSimConVarByName(const char* const name)
  {
    if (name == nullptr || *name == '\0') {
      return nullptr;
    }

    CSimConCommand* const command = FindRegisteredSimConCommand(name);
    return dynamic_cast<CSimConVarBase*>(command);
  }

  /**
   * Reads one con-var's value for `sim` into `outValue`, leaving it untouched
   * and returning false if any hop in the walk comes up empty.
   */
  template <typename TValue>
  [[nodiscard]] bool ReadSimConVarValue(Sim* const sim, const char* const name, TValue& outValue)
  {
    if (sim == nullptr) {
      return false;
    }

    CSimConVarBase* const conVar = FindSimConVarByName(name);
    if (conVar == nullptr) {
      return false;
    }

    CSimConVarInstanceBase* const instance = sim->GetSimVar(conVar);
    if (instance == nullptr) {
      return false;
    }

    const void* const valueStorage = instance->GetValueStorage();
    if (valueStorage == nullptr) {
      return false;
    }

    outValue = *static_cast<const TValue*>(valueStorage);
    return true;
  }
} // namespace moho
