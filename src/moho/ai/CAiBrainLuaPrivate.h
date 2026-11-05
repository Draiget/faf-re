#pragma once

// Private to moho/ai: helpers the pieces of the former CAiBrainLuaFunctions.cpp share.

#include "moho/ai/CAiBrainPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaInitForm.h"

namespace
{
  constexpr const char* kAiBrainLuaClassName = "CAiBrain";
  constexpr const char* kLuaExpectedArgRangeWarning = "%s\n  expected between %d and %d args, but got %d";

  // a deleted overlay (0x10 pad bytes then `void** mUnitSlotsStart/End`
  // at +0x10/+0x14) and a deleted overlay (`mLuaObj` at +0x20, a squad
  // pointer pair at +0x40/+0x44, `mUniqueName` at +0xAC) used to stand here,
  // together with a `CountSquadUnits`/`CountPlatoonUnits` pair that walked
  // them. Every one of those offsets names a field `CSquad`/`CPlatoon` already
  // has:
  //
  //   +0x10/+0x14  `CSquad::mUnits.mVec`'s `start_`/`end_` -- `mUnits` is a
  //                `EntitySetTemplate<Unit>` at +0x08 whose `gpg::fastvector_n<
  //                Entity*, 4> mVec` sits at +0x08 inside it.
  //   +0x20        `CScriptObject::mLuaObj`, inherited.
  //   +0x40/+0x44  `CPlatoon::mSquadList`'s `start_`/`end_`
  //                (`gpg::fastvector_n<CSquad*, 8>`).
  //   +0xA8        `CPlatoon::mUniqueName` -- and the view said 0xAC, which was
  //                wrong and is the reason it is gone. See
  //                `cfunc_CAiBrainGetPlatoonsListL` below for the asm.
  //
  // The two counting helpers are `CPlatoon::CountUnits()`
  // (0x00725840), the same loop with the same per-squad `end_ - start_`.

  [[nodiscard]] gpg::RRef MakeEconResourceRef(moho::EEconResource* const resource)
  {
    gpg::RRef enumRef{};
    if (resource == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEconResourceType = nullptr;
    if (sEconResourceType == nullptr) {
      sEconResourceType = gpg::LookupRType(typeid(moho::EEconResource));
    }

    enumRef.mObj = resource;
    enumRef.mType = sEconResourceType;
    return enumRef;
  }

  [[nodiscard]] float& SelectResourceLane(moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[maybe_unused]] [[nodiscard]] const float& SelectResourceLane(const moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[maybe_unused]] [[nodiscard]] std::uint64_t SelectResourceLane(
    const moho::SEconStoragePair& value, const moho::EEconResource resource
  ) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[nodiscard]] moho::CArmyStats* ResolveArmyStats(moho::CAiBrain* const brain)
  {
    if (brain == nullptr || brain->mArmy == nullptr) {
      return nullptr;
    }

    return brain->mArmy->GetArmyStats();
  }
}

