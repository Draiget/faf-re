#pragma once

// Private to moho/unit/core: helpers the pieces of the former UnitLuaFunctions.cpp share.

#include "moho/unit/core/UnitPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  constexpr const char* kUnitGetCommandQueueInvalidUnitError = "UnitScript:GetCommandQueue Passed in an invalid unit";
  constexpr const char* kUnitGetCommandQueueInvalidQueueError = "UnitScript:GetCommandQueue invalid UnitCommandQueue";
  constexpr const char* kUnitLuaClassName = "Unit";
  constexpr const char* kGlobalLuaClassName = "<global>";

  // `IsSpeedThroughBusyCommandType` (0x00552C10, func_UnitStateIsBusy) lives
  // in moho/command/SSTICommandVariableData.cpp next to the command type it
  // classifies; the formation code calls it too.

  [[maybe_unused]] [[nodiscard]] gpg::RRef MakeUnitStateRef(EUnitState* const unitState)
  {
    gpg::RRef enumRef{};
    if (unitState == nullptr) {
      return enumRef;
    }

    static gpg::RType* sUnitStateType = nullptr;
    if (sUnitStateType == nullptr) {
      sUnitStateType = gpg::LookupRType(typeid(EUnitState));
    }

    enumRef.mObj = unitState;
    enumRef.mType = sUnitStateType;
    return enumRef;
  }

  [[nodiscard]] gpg::RRef MakeRuleUnitToggleCapsRef(ERuleBPUnitToggleCaps* const toggleCap)
  {
    gpg::RRef enumRef{};
    if (toggleCap == nullptr) {
      return enumRef;
    }

    static gpg::RType* sToggleCapType = nullptr;
    if (sToggleCapType == nullptr) {
      sToggleCapType = gpg::LookupRType(typeid(ERuleBPUnitToggleCaps));
    }

    enumRef.mObj = toggleCap;
    enumRef.mType = sToggleCapType;
    return enumRef;
  }

  [[maybe_unused]] [[nodiscard]] gpg::RRef MakeRuleUnitCommandCapsRef(ERuleBPUnitCommandCaps* const commandCap)
  {
    gpg::RRef enumRef{};
    if (commandCap == nullptr) {
      return enumRef;
    }

    static gpg::RType* sCommandCapType = nullptr;
    if (sCommandCapType == nullptr) {
      sCommandCapType = gpg::LookupRType(typeid(ERuleBPUnitCommandCaps));
    }

    enumRef.mObj = commandCap;
    enumRef.mType = sCommandCapType;
    return enumRef;
  }

  [[maybe_unused]] [[nodiscard]] int ScriptBitIndexFromToggleCapValue(int toggleCapValue) noexcept
  {
    int bitIndex = 0;
    if (toggleCapValue == 1) {
      return bitIndex;
    }

    do {
      toggleCapValue >>= 1;
      ++bitIndex;
    } while (toggleCapValue != 1);
    return bitIndex;
  }

  /**
   * Address: 0x00593970 (FUN_00593970, func_GetUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `Unit*` without throwing Lua conversion errors.
   */
  [[nodiscard]] Unit* GetUnitOptional(const LuaPlus::LuaObject& unitObject)
  {
    CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(unitObject);
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = scriptObject->GetDerivedObjectRef();
    const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<Unit>());
    return static_cast<Unit*>(unitRef.mObj);
  }
}

