#include "moho/net/CLobbyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/net/CLobby.h"

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

  TypeInfoStorage<moho::CLobbyTypeInfo> gCLobbyTypeInfoStorage{};

  [[nodiscard]] moho::CLobbyTypeInfo& GetCLobbyTypeInfo() noexcept
  {
    return EnsureTypeInfo(gCLobbyTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!moho::CScriptObject::sType) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }
    return moho::CScriptObject::sType;
  }

  /**
   * Address: 0x007CB630 (FUN_007CB630)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected `CLobby` base lane at
   * offset `+0x00`.
   */
  void AddCScriptObjectBaseToCLobbyType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00C039C0 (FUN_00C039C0, Moho::CLobbyTypeInfo::~CLobbyTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global CLobby type descriptor.
   */
  void cleanup_CLobbyTypeInfo()
  {
    DestroyTypeInfo(gCLobbyTypeInfoStorage);
  }

  /**
   * Address: 0x00BDFE30 (FUN_00BDFE30, register_CLobbyTypeInfo)
   *
   * What it does:
   * Constructs the global CLobby type descriptor and wires teardown into CRT
   * `atexit`.
   */
  void register_CLobbyTypeInfo()
  {
    (void)GetCLobbyTypeInfo();
    (void)std::atexit(&cleanup_CLobbyTypeInfo);
  }

  struct CLobbyTypeInfoRegistration
  {
    CLobbyTypeInfoRegistration()
    {
      register_CLobbyTypeInfo();
    }
  };

  [[maybe_unused]] CLobbyTypeInfoRegistration gCLobbyTypeInfoRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x007C0820 (FUN_007C0820, Moho::CLobbyTypeInfo::CLobbyTypeInfo)
   */
  CLobbyTypeInfo::CLobbyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CLobby), this);
  }

  /**
   * Address: 0x007C08C0 (FUN_007C08C0, Moho::CLobbyTypeInfo::dtr)
   */
  CLobbyTypeInfo::~CLobbyTypeInfo() = default;

  /**
   * Address: 0x007C08B0 (FUN_007C08B0, Moho::CLobbyTypeInfo::GetName)
   *
   * IDA signature:
   * const char *Moho::CLobbyTypeInfo::GetName();
   */
  const char* CLobbyTypeInfo::GetName() const
  {
    return "CLobby";
  }

  /**
   * Address: 0x007C0880 (FUN_007C0880, Moho::CLobbyTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CLobbyTypeInfo::Init(gpg::RType *this);
   */
  void CLobbyTypeInfo::Init()
  {
    size_ = sizeof(CLobby);
    AddCScriptObjectBaseToCLobbyType(this);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
