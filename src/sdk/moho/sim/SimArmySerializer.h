#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class SimArmySerializer
  {
  public:
    /**
     * Address: 0x00701610 (FUN_00701610, gpg::SerSaveLoadHelper_SimArmy::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into SimArmy RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(SimArmySerializer, mHelperNext) == 0x04, "SimArmySerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SimArmySerializer, mHelperPrev) == 0x08, "SimArmySerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SimArmySerializer, mLoadCallback) == 0x0C, "SimArmySerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(SimArmySerializer, mSaveCallback) == 0x10, "SimArmySerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(SimArmySerializer) == 0x14, "SimArmySerializer size must be 0x14");
} // namespace moho
