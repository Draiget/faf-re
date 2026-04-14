#include "lua/LuaRuntimeTypeInfo.h"

#include <typeinfo>

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
