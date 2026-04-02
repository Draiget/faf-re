#include "lua/LuaObjectTypeInfo.h"
#include "lua/LuaStateTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "lua/LuaObject.h"

#pragma init_seg(lib)

namespace
{
  template <class TTypeInfo>
  struct TypeInfoStorage
  {
    alignas(TTypeInfo) unsigned char bytes[sizeof(TTypeInfo)];
    bool constructed;
  };

  template <class TTypeInfo>
  [[nodiscard]] TTypeInfo& EnsureTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      new (storage.bytes) TTypeInfo();
      storage.constructed = true;
    }

    return *reinterpret_cast<TTypeInfo*>(storage.bytes);
  }

  template <class TTypeInfo>
  void DestroyTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    reinterpret_cast<TTypeInfo*>(storage.bytes)->~TTypeInfo();
    storage.constructed = false;
  }

  TypeInfoStorage<LuaPlus::LuaObjectTypeInfo> gLuaObjectTypeInfoStorage{};
  TypeInfoStorage<LuaPlus::LuaStateTypeInfo> gLuaStateTypeInfoStorage{};

  [[nodiscard]] LuaPlus::LuaObjectTypeInfo& GetLuaObjectTypeInfo() noexcept
  {
    return EnsureTypeInfo(gLuaObjectTypeInfoStorage);
  }

  [[nodiscard]] LuaPlus::LuaStateTypeInfo& GetLuaStateTypeInfo() noexcept
  {
    return EnsureTypeInfo(gLuaStateTypeInfoStorage);
  }

  /**
   * Address: 0x00C098E0 (FUN_00C098E0, LuaPlus::LuaObjectTypeInfo::~LuaObjectTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `LuaObject` descriptor.
   */
  void cleanup_LuaObjectTypeInfo()
  {
    DestroyTypeInfo(gLuaObjectTypeInfoStorage);
  }

  /**
   * Address: 0x00C09940 (FUN_00C09940, LuaPlus::LuaStateTypeInfo::~LuaStateTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `LuaState` descriptor.
   */
  void cleanup_LuaStateTypeInfo()
  {
    DestroyTypeInfo(gLuaStateTypeInfoStorage);
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
