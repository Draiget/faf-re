#include "gpg/core/reflection/RStringType.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

namespace
{
  alignas(stringTypeInfo) unsigned char gStorage[sizeof(stringTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] stringTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) stringTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<stringTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<stringTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { register_stringTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x008DF1C0 (FUN_008DF1C0, RStringType::GetLexical)
 *
 * What it does:
 * Returns a copy of the string referenced by ref.mObj.
 */
msvc8::string RStringType::GetLexical(const gpg::RRef& ref) const
{
  const auto* const value = static_cast<const msvc8::string*>(ref.mObj);
  return *value;
}

/**
 * Address: 0x008DF200 (FUN_008DF200, RStringType::SetLexical)
 *
 * What it does:
 * Assigns null-terminated `str` into the msvc8::string at *ref.mObj.
 */
bool RStringType::SetLexical(const gpg::RRef& ref, const char* const str) const
{
  auto* const out = static_cast<msvc8::string*>(ref.mObj);
  *out = msvc8::string{str, std::strlen(str)};
  return true;
}

RStringType::~RStringType() = default;

/**
 * Address: 0x008E0490 (FUN_008E0490)
 */
stringTypeInfo::stringTypeInfo()
  : RStringType()
{
  gpg::PreRegisterRType(typeid(msvc8::string), this);
}

stringTypeInfo::~stringTypeInfo() = default;

/** Address: 0x008E0500 */
const char* stringTypeInfo::GetName() const { return "std::string"; }

/**
 * Address: 0x008E0510
 *
 * What it does:
 * Sets size = 28 (msvc8::string layout) and finalizes.
 */
void stringTypeInfo::Init()
{
  size_ = 28;
  Finish();
}

/** Address: 0x00BE9960 */
void register_stringTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
