#include "lua/LuaRuntimeTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

/**
 * Address: 0x00923280 (FUN_00923280, TStringTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `TStringTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyTStringTypeInfoDeleting(
  TStringTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923300 (FUN_00923300, TableTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `TableTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyTableTypeInfoDeleting(
  TableTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009233D0 (FUN_009233D0, LClosureTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `LClosureTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyLClosureTypeInfoDeleting(
  LClosureTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923460 (FUN_00923460, UpValTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `UpValTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyUpValTypeInfoDeleting(
  UpValTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009234C0 (FUN_009234C0, ProtoTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `ProtoTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyProtoTypeInfoDeleting(
  ProtoTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923550 (FUN_00923550, lua_StateTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `lua_StateTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyLuaStateTypeInfoDeleting(
  lua_StateTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923600 (FUN_00923600, UdataTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `UdataTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyUdataTypeInfoDeleting(
  UdataTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009220B0 (FUN_009220B0, TableTypeInfo::TableTypeInfo)
 *
 * What it does:
 * Constructs the table runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Table)`.
 */
TableTypeInfo::TableTypeInfo()
{
  gpg::PreRegisterRType(typeid(Table), this);
}

/**
 * Address: 0x00921FD0 (FUN_00921FD0, TStringTypeInfo::TStringTypeInfo)
 *
 * What it does:
 * Constructs the TString runtime type descriptor and preregisters it with
 * reflection registry using `typeid(TString)`.
 */
TStringTypeInfo::TStringTypeInfo()
{
  gpg::PreRegisterRType(typeid(TString), this);
}

/**
 * Address: 0x00922020 (FUN_00922020, TStringTypeInfo::GetName)
 */
const char* TStringTypeInfo::GetName() const
{
  return "TStr";
}

/**
 * Address: 0x00922030 (FUN_00922030, TStringTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `TString`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void TStringTypeInfo::Init()
{
  size_ = 0x14;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922100 (FUN_00922100, TableTypeInfo::GetName)
 */
const char* TableTypeInfo::GetName() const
{
  return "Table";
}

/**
 * Address: 0x00922110 (FUN_00922110, TableTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Table`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void TableTypeInfo::Init()
{
  size_ = 0x24;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x009222D0 (FUN_009222D0, LClosureTypeInfo::LClosureTypeInfo)
 *
 * What it does:
 * Constructs the closure runtime type descriptor and preregisters it with
 * reflection registry using `typeid(LClosure)`.
 */
LClosureTypeInfo::LClosureTypeInfo()
{
  gpg::PreRegisterRType(typeid(LClosure), this);
}

/**
 * Address: 0x00922320 (FUN_00922320, LClosureTypeInfo::GetName)
 */
const char* LClosureTypeInfo::GetName() const
{
  return "LClosure";
}

/**
 * Address: 0x00922330 (FUN_00922330, LClosureTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `LClosure`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void LClosureTypeInfo::Init()
{
  size_ = 0x20;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x009223A0 (FUN_009223A0, UpValTypeInfo::UpValTypeInfo)
 *
 * What it does:
 * Constructs the upvalue runtime type descriptor and preregisters it with
 * reflection registry using `typeid(UpVal)`.
 */
UpValTypeInfo::UpValTypeInfo()
{
  gpg::PreRegisterRType(typeid(UpVal), this);
}

/**
 * Address: 0x009223F0 (FUN_009223F0, UpValTypeInfo::GetName)
 */
const char* UpValTypeInfo::GetName() const
{
  return "UpVal";
}

/**
 * Address: 0x00922400 (FUN_00922400, UpValTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `UpVal`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void UpValTypeInfo::Init()
{
  size_ = 0x14;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922470 (FUN_00922470, ProtoTypeInfo::ProtoTypeInfo)
 *
 * What it does:
 * Constructs the proto runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Proto)`.
 */
ProtoTypeInfo::ProtoTypeInfo()
{
  gpg::PreRegisterRType(typeid(Proto), this);
}

/**
 * Address: 0x009224C0 (FUN_009224C0, ProtoTypeInfo::GetName)
 */
const char* ProtoTypeInfo::GetName() const
{
  return "Proto";
}

/**
 * Address: 0x009224D0 (FUN_009224D0, ProtoTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Proto`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void ProtoTypeInfo::Init()
{
  size_ = 0x70;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922540 (FUN_00922540, lua_StateTypeInfo::lua_StateTypeInfo)
 *
 * What it does:
 * Constructs the C lua_State runtime type descriptor and preregisters it with
 * reflection registry using `typeid(lua_State)`.
 */
lua_StateTypeInfo::lua_StateTypeInfo()
{
  gpg::PreRegisterRType(typeid(lua_State), this);
}

/**
 * Address: 0x00922590 (FUN_00922590, lua_StateTypeInfo::GetName)
 */
const char* lua_StateTypeInfo::GetName() const
{
  return "lua_State";
}

/**
 * Address: 0x009225A0 (FUN_009225A0, lua_StateTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for C `lua_State`, initializes base RType
 * state, and finalizes field/base descriptors.
 */
void lua_StateTypeInfo::Init()
{
  size_ = 0x48;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922620 (FUN_00922620, UdataTypeInfo::UdataTypeInfo)
 *
 * What it does:
 * Constructs the Udata runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Udata)`.
 */
UdataTypeInfo::UdataTypeInfo()
{
  gpg::PreRegisterRType(typeid(Udata), this);
}

/**
 * Address: 0x00922670 (FUN_00922670, UdataTypeInfo::GetName)
 */
const char* UdataTypeInfo::GetName() const
{
  return "Udata";
}

/**
 * Address: 0x00922680 (FUN_00922680, UdataTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Udata`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void UdataTypeInfo::Init()
{
  size_ = 0x10;
  gpg::RType::Init();
  Finish();
}

// ---------------------------------------------------------------------------
// Startup registration
//
// Each descriptor registers its typeid from its constructor, so the descriptor
// only enters the reflection map if something constructs it. The binary does
// that from its CRT initializer table; these are the equivalent entries.
// ---------------------------------------------------------------------------

namespace
{
  alignas(TStringTypeInfo) unsigned char gStorage_TStringTypeInfo[sizeof(TStringTypeInfo)];
  bool gConstructed_TStringTypeInfo = false;
  alignas(TableTypeInfo) unsigned char gStorage_TableTypeInfo[sizeof(TableTypeInfo)];
  bool gConstructed_TableTypeInfo = false;
  alignas(LClosureTypeInfo) unsigned char gStorage_LClosureTypeInfo[sizeof(LClosureTypeInfo)];
  bool gConstructed_LClosureTypeInfo = false;
  alignas(UpValTypeInfo) unsigned char gStorage_UpValTypeInfo[sizeof(UpValTypeInfo)];
  bool gConstructed_UpValTypeInfo = false;
  alignas(ProtoTypeInfo) unsigned char gStorage_ProtoTypeInfo[sizeof(ProtoTypeInfo)];
  bool gConstructed_ProtoTypeInfo = false;
  alignas(lua_StateTypeInfo) unsigned char gStorage_lua_StateTypeInfo[sizeof(lua_StateTypeInfo)];
  bool gConstructed_lua_StateTypeInfo = false;
  alignas(UdataTypeInfo) unsigned char gStorage_UdataTypeInfo[sizeof(UdataTypeInfo)];
  bool gConstructed_UdataTypeInfo = false;

  void cleanup_TStringTypeInfo()
  {
    if (!gConstructed_TStringTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<TStringTypeInfo*>(gStorage_TStringTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_TableTypeInfo()
  {
    if (!gConstructed_TableTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<TableTypeInfo*>(gStorage_TableTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_LClosureTypeInfo()
  {
    if (!gConstructed_LClosureTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<LClosureTypeInfo*>(gStorage_LClosureTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_UpValTypeInfo()
  {
    if (!gConstructed_UpValTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<UpValTypeInfo*>(gStorage_UpValTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_ProtoTypeInfo()
  {
    if (!gConstructed_ProtoTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<ProtoTypeInfo*>(gStorage_ProtoTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_lua_StateTypeInfo()
  {
    if (!gConstructed_lua_StateTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<lua_StateTypeInfo*>(gStorage_lua_StateTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  void cleanup_UdataTypeInfo()
  {
    if (!gConstructed_UdataTypeInfo) {
      return;
    }
    auto& ti = *reinterpret_cast<UdataTypeInfo*>(gStorage_UdataTypeInfo);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct LuaRuntimeTypeInfoBootstrap
  {
    LuaRuntimeTypeInfoBootstrap()
    {
      register_TStringTypeInfoStartup();
      register_TableTypeInfoStartup();
      register_LClosureTypeInfoStartup();
      register_UpValTypeInfoStartup();
      register_ProtoTypeInfoStartup();
      register_lua_StateTypeInfoStartup();
      register_UdataTypeInfoStartup();
    }
  };

  LuaRuntimeTypeInfoBootstrap gLuaRuntimeTypeInfoBootstrap;
}

/** Address: 0x00BEA1A0 (register_TStringTypeInfo) */
void register_TStringTypeInfoStartup()
{
  if (!gConstructed_TStringTypeInfo) {
    new (gStorage_TStringTypeInfo) TStringTypeInfo();
    gConstructed_TStringTypeInfo = true;
    (void)std::atexit(&cleanup_TStringTypeInfo);
  }
}

/** Address: 0x00BEA2B0 (register_TableTypeInfo) */
void register_TableTypeInfoStartup()
{
  if (!gConstructed_TableTypeInfo) {
    new (gStorage_TableTypeInfo) TableTypeInfo();
    gConstructed_TableTypeInfo = true;
    (void)std::atexit(&cleanup_TableTypeInfo);
  }
}

/** Address: 0x00BEA3C0 (register_LClosureTypeInfo) */
void register_LClosureTypeInfoStartup()
{
  if (!gConstructed_LClosureTypeInfo) {
    new (gStorage_LClosureTypeInfo) LClosureTypeInfo();
    gConstructed_LClosureTypeInfo = true;
    (void)std::atexit(&cleanup_LClosureTypeInfo);
  }
}

/** Address: 0x00BEA4D0 (register_UpValTypeInfo) */
void register_UpValTypeInfoStartup()
{
  if (!gConstructed_UpValTypeInfo) {
    new (gStorage_UpValTypeInfo) UpValTypeInfo();
    gConstructed_UpValTypeInfo = true;
    (void)std::atexit(&cleanup_UpValTypeInfo);
  }
}

/** Address: 0x00BEA5E0 (register_ProtoTypeInfo) */
void register_ProtoTypeInfoStartup()
{
  if (!gConstructed_ProtoTypeInfo) {
    new (gStorage_ProtoTypeInfo) ProtoTypeInfo();
    gConstructed_ProtoTypeInfo = true;
    (void)std::atexit(&cleanup_ProtoTypeInfo);
  }
}

/** Address: 0x00BEA6F0 (register_lua_StateTypeInfo) */
void register_lua_StateTypeInfoStartup()
{
  if (!gConstructed_lua_StateTypeInfo) {
    new (gStorage_lua_StateTypeInfo) lua_StateTypeInfo();
    gConstructed_lua_StateTypeInfo = true;
    (void)std::atexit(&cleanup_lua_StateTypeInfo);
  }
}

/** Address: 0x00BEA800 (register_UdataTypeInfo) */
void register_UdataTypeInfoStartup()
{
  if (!gConstructed_UdataTypeInfo) {
    new (gStorage_UdataTypeInfo) UdataTypeInfo();
    gConstructed_UdataTypeInfo = true;
    (void)std::atexit(&cleanup_UdataTypeInfo);
  }
}

