#pragma once

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

/**
 * VFTABLE: `??_7RFloatType@@6B@`
 * COL: from data xrefs at 0x00D418A8 and 0x00D41B90 (shared with floatTypeInfo).
 *
 * Global-namespace type-info base providing `GetLexical`/`SetLexical`
 * overrides for `float` values. `floatTypeInfo` inherits from this class and
 * registers the float type in the gpg pre-registration map.
 *
 * Evidence:
 * - Both `??_7RFloatType@@6B@` and `??_7floatTypeInfo@@6B@` vtables reference
 *   `RFloatType::GetLexical` and `RFloatType::SetLexical` at the same slots,
 *   confirming that `floatTypeInfo` inherits and does not override them.
 */
class RFloatType : public gpg::RType
{
public:
  /**
   * Address: 0x008DF080 (FUN_008DF080)
   * Mangled: ?GetLexical@RFloatType@@UBE?AV?$basic_string@...
   *
   * What it does:
   * Formats the float value referenced by `ref.mObj` using `"%f"` and returns
   * it as an `msvc8::string`.  Pre-allocates 30 characters to guarantee
   * sprintf buffer capacity, then trims to the actual output length.
   */
  [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

  /**
   * Address: 0x008DF060 (FUN_008DF060)
   * Mangled: ?SetLexical@RFloatType@@UBE_NABV?$basic_string@...
   *
   * What it does:
   * Parses the lexical string `str` as a float via `atof` and stores the
   * result at `*ref.mObj`.  Returns `true` on success.
   */
  bool SetLexical(const gpg::RRef& ref, const char* str) const override;
};

/**
 * VFTABLE: `??_7floatTypeInfo@@6B@`
 *
 * Global-namespace concrete registration class for the `float` scalar type.
 * Inherits `GetLexical`/`SetLexical` from `RFloatType` and registers
 * `this` under `float RTTI Type Descriptor` in the gpg pre-registration map.
 */
class floatTypeInfo : public RFloatType
{
public:
  /**
   * Address: 0x008E03A0 (FUN_008E03A0)
   * Mangled: ??0floatTypeInfo@@QAE@@Z
   *
   * What it does:
   * Calls `gpg::RType::RType()`, registers `this` under `typeid(float)` in
   * the gpg pre-registration map, and sets `__vftable = &floatTypeInfo::vftable`.
   */
  floatTypeInfo();

  /**
   * Address: 0x008E0410 (FUN_008E0410)
   * Mangled: ?GetName@floatTypeInfo@@UBEPBDXZ
   *
   * What it does:
   * Returns the reflection type label `"float"`.
   */
  [[nodiscard]] const char* GetName() const override;

  /**
   * Address: 0x008E0420 (FUN_008E0420)
   * Mangled: ?Init@floatTypeInfo@@...
   *
   * What it does:
   * Sets `mSize = sizeof(float)` and calls `Finish()` to finalize the type
   * descriptor.
   */
  void Init() override;
};
