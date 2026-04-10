#include "gpg/core/reflection/RFloatType.h"

#include <cstdio>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

// ---------------------------------------------------------------------------
// RFloatType
// ---------------------------------------------------------------------------

/**
 * Address: 0x008DF080 (FUN_008DF080)
 * Mangled: ?GetLexical@RFloatType@@UBE?AV?$basic_string@...
 *
 * What it does:
 * Pre-allocates a 30-character buffer in the result string, formats the float
 * value at `ref.mObj` using `sprintf("%f", ...)` into the buffer, then trims
 * the string to the actual printed character count before returning.
 */
msvc8::string RFloatType::GetLexical(const gpg::RRef& ref) const
{
  const float value = *static_cast<const float*>(ref.mObj);

  msvc8::string result;
  result.resize(30, '\0');

  const int n = std::sprintf(result.raw_data_mut_unsafe(), "%f", value);

  result.resize(static_cast<std::size_t>(n));
  return result;
}

/**
 * Address: 0x008DF060 (FUN_008DF060)
 * Mangled: ?SetLexical@RFloatType@@UBE_NABV?$basic_string@...
 *
 * What it does:
 * Parses the null-terminated string `str` as a double via `atof`, stores the
 * result as a `float` at `*static_cast<float*>(ref.mObj)`, and returns `true`.
 */
bool RFloatType::SetLexical(const gpg::RRef& ref, const char* const str) const
{
  *static_cast<float*>(ref.mObj) = static_cast<float>(std::atof(str));
  return true;
}

// ---------------------------------------------------------------------------
// floatTypeInfo
// ---------------------------------------------------------------------------

/**
 * Address: 0x008E03A0 (FUN_008E03A0)
 * Mangled: ??0floatTypeInfo@@QAE@@Z
 *
 * What it does:
 * Initialises the `gpg::RType` base, then registers `this` instance under
 * `typeid(float)` in the gpg pre-registration map so that `LookupRType` can
 * resolve it later.
 */
floatTypeInfo::floatTypeInfo()
{
  gpg::PreRegisterRType(typeid(float), this);
}

/**
 * Address: 0x008E0410 (FUN_008E0410)
 * Mangled: ?GetName@floatTypeInfo@@UBEPBDXZ
 *
 * What it does:
 * Returns the reflection type label string `"float"`.
 */
const char* floatTypeInfo::GetName() const
{
  return "float";
}

/**
 * Address: 0x008E0420 (FUN_008E0420)
 *
 * What it does:
 * Sets the primitive size (`mSize = 4`) and calls `Finish()` to complete
 * descriptor initialisation.
 */
void floatTypeInfo::Init()
{
  size_ = static_cast<int>(sizeof(float));
  Finish();
}
