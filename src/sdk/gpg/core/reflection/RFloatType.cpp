#include "gpg/core/reflection/RFloatType.h"

#include <cstdio>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

#include <new>
#include "gpg/core/reflection/StaticInitPhase.h"

/**
 * Address: 0x00A83523 (FUN_00A83523, atof)
 *
 * What it does:
 * Parses the incoming null-terminated string using the recovered CRT `atof`
 * lane and returns the parsed value.
 */
extern "C" double __cdecl RuntimeAtofForward(const char* text)
{
  return std::atof(text != nullptr ? text : "0");
}

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
  *static_cast<float*>(ref.mObj) = static_cast<float>(RuntimeAtofForward(str));
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

namespace
{
  alignas(floatTypeInfo) unsigned char gStorage[sizeof(floatTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] floatTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) floatTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<floatTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) {
      return;
    }
    auto& ti = *reinterpret_cast<floatTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { register_floatTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/**
 * Address: 0x00BE9940 (register_floatTypeInfo)
 *
 * What it does:
 * Brings the `floatTypeInfo` singleton into existence so its constructor can
 * pre-register `typeid(float)`, then arms teardown. Without this the descriptor
 * is never constructed and every reflected `float` field resolves to a null
 * `RType`.
 */
void register_floatTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_floatTypeInfoStartup_f1479a, register_floatTypeInfoStartup)
