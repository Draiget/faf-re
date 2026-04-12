#pragma once

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

/**
 * VFTABLE: `??_7RStringType@@6B@`
 *
 * Reflection type-info base for `msvc8::string` (legacy `std::string`)
 * providing `GetLexical`/`SetLexical` overrides. `stringTypeInfo` inherits
 * and registers under `typeid(std::string)`.
 */
class RStringType : public gpg::RType
{
public:
  /**
   * Address: 0x008DF1C0 (FUN_008DF1C0)
   *
   * What it does:
   * Returns a copy of the string referenced by `ref.mObj`.
   */
  [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

  /**
   * Address: 0x008DF200 (FUN_008DF200)
   *
   * What it does:
   * Constructs/assigns the null-terminated `str` into the `msvc8::string` at
   * `*ref.mObj`. Always returns `true`.
   */
  bool SetLexical(const gpg::RRef& ref, const char* str) const override;

  /**
   * Address: 0x008DF230 (FUN_008DF230, scalar deleting thunk)
   */
  ~RStringType() override;
};

/**
 * VFTABLE: `??_7stringTypeInfo@@6B@`
 *
 * Concrete reflection registration for `std::string`/`msvc8::string`.
 */
class stringTypeInfo : public RStringType
{
public:
  /** Address: 0x008E0490 (FUN_008E0490) */
  stringTypeInfo();
  /** Address: 0x008E0520 (FUN_008E0520, deleting thunk) */
  ~stringTypeInfo() override;
  /** Address: 0x008E0500 (FUN_008E0500) */
  [[nodiscard]] const char* GetName() const override;
  /** Address: 0x008E0510 (FUN_008E0510) */
  void Init() override;
};

/** Address: 0x00BE9960 (FUN_00BE9960, register_stringTypeInfo) */
void register_stringTypeInfoStartup();
