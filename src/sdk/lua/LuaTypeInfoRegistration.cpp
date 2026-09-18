#include "lua/LuaObjectTypeInfo.h"
#include "lua/LuaStateTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "lua/LuaObject.h"
#include "lua/LuaTypeInfoStorage.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  lua::TypeInfoStorage<LuaPlus::LuaObjectTypeInfo> gLuaObjectTypeInfoStorage{};
  lua::TypeInfoStorage<LuaPlus::LuaStateTypeInfo> gLuaStateTypeInfoStorage{};

  [[nodiscard]] LuaPlus::LuaObjectTypeInfo& GetLuaObjectTypeInfo() noexcept
  {
    return lua::EnsureTypeInfo(gLuaObjectTypeInfoStorage);
  }

  [[nodiscard]] LuaPlus::LuaStateTypeInfo& GetLuaStateTypeInfo() noexcept
  {
    return lua::EnsureTypeInfo(gLuaStateTypeInfoStorage);
  }

  /**
   * Address: 0x00C098E0 (FUN_00C098E0, LuaPlus::LuaObjectTypeInfo::~LuaObjectTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `LuaObject` descriptor.
   */
  void cleanup_LuaObjectTypeInfo()
  {
    lua::DestroyTypeInfo(gLuaObjectTypeInfoStorage);
  }

  /**
   * Address: 0x00C09940 (FUN_00C09940, LuaPlus::LuaStateTypeInfo::~LuaStateTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `LuaState` descriptor.
   */
  void cleanup_LuaStateTypeInfo()
  {
    lua::DestroyTypeInfo(gLuaStateTypeInfoStorage);
  }

  /**
   * Address: 0x00BE9EF0 (FUN_00BE9EF0, register_LuaObjectTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `LuaObject` reflection descriptor and wires
   * teardown into CRT `atexit`.
   */
  void register_LuaObjectTypeInfo()
  {
    LuaPlus::LuaObjectTypeInfo& typeInfo = GetLuaObjectTypeInfo();
    gpg::PreRegisterRType(typeid(LuaPlus::LuaObject), &typeInfo);
    (void)std::atexit(&cleanup_LuaObjectTypeInfo);
  }

  /**
   * Address: 0x00BEA040 (FUN_00BEA040, register_LuaStateTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `LuaState` reflection descriptor and wires
   * teardown into CRT `atexit`.
   */
  void register_LuaStateTypeInfo()
  {
    LuaPlus::LuaStateTypeInfo& typeInfo = GetLuaStateTypeInfo();
    gpg::PreRegisterRType(typeid(LuaPlus::LuaState), &typeInfo);
    (void)std::atexit(&cleanup_LuaStateTypeInfo);
  }

  struct LuaTypeInfoRegistration
  {
    LuaTypeInfoRegistration()
    {
      register_LuaObjectTypeInfo();
      register_LuaStateTypeInfo();
    }
  };

  [[maybe_unused]] LuaTypeInfoRegistration gLuaTypeInfoRegistration;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_LuaObjectTypeInfo_da2f14, register_LuaObjectTypeInfo)
GPG_PREREGISTER_INIT(register_LuaStateTypeInfo_da2f14, register_LuaStateTypeInfo)
