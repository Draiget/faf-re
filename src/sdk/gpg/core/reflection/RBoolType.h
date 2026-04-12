#pragma once

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

/**
 * VFTABLE: `??_7RBoolType@@6B@`
 *
 * Global-namespace type-info base providing `GetLexical`/`SetLexical`
 * overrides for `bool` values. `boolTypeInfo` inherits from this class and
 * registers the bool type in the gpg pre-registration map.
 */
class RBoolType : public gpg::RType
{
public:
  /**
   * Address: 0x008DEF90 (FUN_008DEF90, ?GetLexical@RBoolType@@UBE...)
   *
   * What it does:
   * Returns "true" or "false" as an `msvc8::string` based on the bool value
   * referenced by `ref.mObj`.
   */
  [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

  /**
   * Address: 0x008DEEF0 (FUN_008DEEF0, ?SetLexical@RBoolType@@UBE_N...)
   *
   * What it does:
   * Parses lexical strings "0"/"false"/"no" as false and "1"/"true"/"yes"
   * as true (case-insensitive). Stores the result at `*ref.mObj`. Returns
   * `true` on success, `false` if the string is unrecognized.
   */
  bool SetLexical(const gpg::RRef& ref, const char* str) const override;

  /**
   * Address: 0x008DEFE0 (FUN_008DEFE0, scalar deleting thunk)
   */
  ~RBoolType() override;
};

/**
 * VFTABLE: `??_7boolTypeInfo@@6B@`
 *
 * Global-namespace concrete registration class for the `bool` scalar type.
 * Inherits `GetLexical`/`SetLexical` from `RBoolType` and registers `this`
 * under `bool RTTI Type Descriptor` in the gpg pre-registration map.
 */
class boolTypeInfo : public RBoolType
{
public:
  /**
   * Address: 0x008E02B0 (FUN_008E02B0, ??0boolTypeInfo@@QAE@@Z)
   *
   * What it does:
   * Calls `gpg::RType::RType()`, registers `this` under `typeid(bool)` in
   * the gpg pre-registration map, and sets `__vftable = &boolTypeInfo::vftable`.
   */
  boolTypeInfo();

  /**
   * Address: 0x008E0340 (FUN_008E0340, scalar deleting thunk)
   */
  ~boolTypeInfo() override;

  /**
   * Address: 0x008E0320 (FUN_008E0320)
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x008E0330 (FUN_008E0330)
   *
   * What it does:
   * Sets `mSize = 1` and calls `Finish()` to finalize the type descriptor.
   */
  void Init() override;
};

/**
 * Address: 0x00BE9920 (FUN_00BE9920, register_boolTypeInfo)
 */
void register_boolTypeInfoStartup();
