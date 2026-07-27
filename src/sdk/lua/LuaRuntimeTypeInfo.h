#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaRuntimeTypes.h"

class TStringTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x00921FD0 (FUN_00921FD0, TStringTypeInfo::TStringTypeInfo)
   *
   * What it does:
   * Constructs the TString runtime type descriptor and preregisters it with
   * reflection registry using `typeid(TString)`.
   */
  TStringTypeInfo();

  /**
   * Address: 0x00922020 (FUN_00922020, TStringTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x00922030 (FUN_00922030, TStringTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(TStringTypeInfo) == sizeof(gpg::RType), "TStringTypeInfo size must match gpg::RType");

class TableTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x009220B0 (FUN_009220B0, TableTypeInfo::TableTypeInfo)
   *
   * What it does:
   * Constructs the table runtime type descriptor and preregisters it with
   * reflection registry using `typeid(Table)`.
   */
  TableTypeInfo();

  /**
   * Address: 0x00922100 (FUN_00922100, TableTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x00922110 (FUN_00922110, TableTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(TableTypeInfo) == sizeof(gpg::RType), "TableTypeInfo size must match gpg::RType");

class LClosureTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x009222D0 (FUN_009222D0, LClosureTypeInfo::LClosureTypeInfo)
   *
   * What it does:
   * Constructs the closure runtime type descriptor and preregisters it with
   * reflection registry using `typeid(LClosure)`.
   */
  LClosureTypeInfo();

  /**
   * Address: 0x00922320 (FUN_00922320, LClosureTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x00922330 (FUN_00922330, LClosureTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(LClosureTypeInfo) == sizeof(gpg::RType), "LClosureTypeInfo size must match gpg::RType");

class UpValTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x009223A0 (FUN_009223A0, UpValTypeInfo::UpValTypeInfo)
   *
   * What it does:
   * Constructs the upvalue runtime type descriptor and preregisters it with
   * reflection registry using `typeid(UpVal)`.
   */
  UpValTypeInfo();

  /**
   * Address: 0x009223F0 (FUN_009223F0, UpValTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x00922400 (FUN_00922400, UpValTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(UpValTypeInfo) == sizeof(gpg::RType), "UpValTypeInfo size must match gpg::RType");

class ProtoTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x00922470 (FUN_00922470, ProtoTypeInfo::ProtoTypeInfo)
   *
   * What it does:
   * Constructs the proto runtime type descriptor and preregisters it with
   * reflection registry using `typeid(Proto)`.
   */
  ProtoTypeInfo();

  /**
   * Address: 0x009224C0 (FUN_009224C0, ProtoTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x009224D0 (FUN_009224D0, ProtoTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(ProtoTypeInfo) == sizeof(gpg::RType), "ProtoTypeInfo size must match gpg::RType");

class lua_StateTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x00922540 (FUN_00922540, lua_StateTypeInfo::lua_StateTypeInfo)
   *
   * What it does:
   * Constructs the C lua_State runtime type descriptor and preregisters it with
   * reflection registry using `typeid(lua_State)`.
   */
  lua_StateTypeInfo();

  /**
   * Address: 0x00922590 (FUN_00922590, lua_StateTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x009225A0 (FUN_009225A0, lua_StateTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(lua_StateTypeInfo) == sizeof(gpg::RType), "lua_StateTypeInfo size must match gpg::RType");

class UdataTypeInfo : public gpg::RType
{
public:
  /**
   * Address: 0x00922620 (FUN_00922620, UdataTypeInfo::UdataTypeInfo)
   *
   * What it does:
   * Constructs the Udata runtime type descriptor and preregisters it with
   * reflection registry using `typeid(Udata)`.
   */
  UdataTypeInfo();

  /**
   * Address: 0x00922670 (FUN_00922670, UdataTypeInfo::GetName)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x00922680 (FUN_00922680, UdataTypeInfo::Init)
   */
  void Init() override;
};
static_assert(sizeof(UdataTypeInfo) == sizeof(gpg::RType), "UdataTypeInfo size must match gpg::RType");

/**
 * Address: 0x00BEA1A0 (register_TStringTypeInfo)
 *
 * Constructs the process-lifetime `TStringTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_TStringTypeInfoStartup();

/**
 * Address: 0x00BEA2B0 (register_TableTypeInfo)
 *
 * Constructs the process-lifetime `TableTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_TableTypeInfoStartup();

/**
 * Address: 0x00BEA3C0 (register_LClosureTypeInfo)
 *
 * Constructs the process-lifetime `LClosureTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_LClosureTypeInfoStartup();

/**
 * Address: 0x00BEA4D0 (register_UpValTypeInfo)
 *
 * Constructs the process-lifetime `UpValTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_UpValTypeInfoStartup();

/**
 * Address: 0x00BEA5E0 (register_ProtoTypeInfo)
 *
 * Constructs the process-lifetime `ProtoTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_ProtoTypeInfoStartup();

/**
 * Address: 0x00BEA6F0 (register_lua_StateTypeInfo)
 *
 * Constructs the process-lifetime `lua_StateTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_lua_StateTypeInfoStartup();

/**
 * Address: 0x00BEA800 (register_UdataTypeInfo)
 *
 * Constructs the process-lifetime `UdataTypeInfo` singleton so its
 * constructor can pre-register its typeid, then arms teardown.
 */
void register_UdataTypeInfoStartup();

