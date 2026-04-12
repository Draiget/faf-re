#include "gpg/core/reflection/RBoolType.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

namespace
{
  alignas(boolTypeInfo) unsigned char gStorage[sizeof(boolTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] boolTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) boolTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<boolTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<boolTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { register_boolTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/**
 * Address: 0x008DEEF0 (FUN_008DEEF0, ?SetLexical@RBoolType@@UBE_N...)
 *
 * What it does:
 * Parses "0"/"false"/"no" as false and "1"/"true"/"yes" as true
 * (case-insensitive). Returns true on success.
 */
bool RBoolType::SetLexical(const gpg::RRef& ref, const char* const str) const
{
  auto* const out = static_cast<bool*>(ref.mObj);
  if (_stricmp(str, "0") == 0 || _stricmp(str, "false") == 0 || _stricmp(str, "no") == 0) {
    *out = false;
    return true;
  }
  if (_stricmp(str, "1") == 0 || _stricmp(str, "true") == 0 || _stricmp(str, "yes") == 0) {
    *out = true;
    return true;
  }
  return false;
}

/**
 * Address: 0x008DEF90 (FUN_008DEF90, ?GetLexical@RBoolType@@UBE...)
 *
 * What it does:
 * Returns "true" or "false" based on the bool value referenced by ref.mObj.
 */
msvc8::string RBoolType::GetLexical(const gpg::RRef& ref) const
{
  const auto* const value = static_cast<const bool*>(ref.mObj);
  return *value ? msvc8::string{"true"} : msvc8::string{"false"};
}

RBoolType::~RBoolType() = default;

/**
 * Address: 0x008E02B0 (FUN_008E02B0, ??0boolTypeInfo@@QAE@@Z)
 */
boolTypeInfo::boolTypeInfo()
  : RBoolType()
{
  gpg::PreRegisterRType(typeid(bool), this);
}

boolTypeInfo::~boolTypeInfo() = default;

/** Address: 0x008E0320 */
const char* boolTypeInfo::GetName() const { return "bool"; }

/**
 * Address: 0x008E0330
 *
 * What it does:
 * Sets size = 1 and finalizes.
 */
void boolTypeInfo::Init()
{
  size_ = sizeof(bool);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BE9920 (FUN_00BE9920, register_boolTypeInfo)
 */
void register_boolTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
