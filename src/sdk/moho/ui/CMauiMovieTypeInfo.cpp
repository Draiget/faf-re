#include "moho/ui/CMauiMovieTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiMovieTypeInfo) unsigned char gCMauiMovieTypeInfoStorage[sizeof(CMauiMovieTypeInfo)];
  bool gCMauiMovieTypeInfoConstructed = false;

  [[nodiscard]] CMauiMovieTypeInfo& AcquireCMauiMovieTypeInfo()
  {
    if (!gCMauiMovieTypeInfoConstructed) {
      new (gCMauiMovieTypeInfoStorage) CMauiMovieTypeInfo();
      gCMauiMovieTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiMovieTypeInfo*>(gCMauiMovieTypeInfoStorage);
  }

  void cleanup_CMauiMovieTypeInfo()
  {
    if (!gCMauiMovieTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiMovieTypeInfo*>(gCMauiMovieTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiMovieTypeInfoBootstrap
  {
    CMauiMovieTypeInfoBootstrap() { moho::register_CMauiMovieTypeInfoStartup(); }
  };
  CMauiMovieTypeInfoBootstrap gCMauiMovieTypeInfoBootstrap;

  /**
   * Address: 0x007A0140 (FUN_007A0140, Moho::CMauiMovieTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiMovie's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiMovie standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiMovie fails its upcast.
   */
  [[nodiscard]] gpg::RType* CachedCMauiControlType()
  {
    gpg::RType* baseType = moho::CMauiControl::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::CMauiControl));
      moho::CMauiControl::sType = baseType;
    }
    return baseType;
  }

  void AddCMauiControlBase(gpg::RType& typeInfo)
  {
    gpg::RType* const baseType = CachedCMauiControlType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x0079ECD0 (FUN_0079ECD0, Moho::CMauiMovieTypeInfo::CMauiMovieTypeInfo)
 */
CMauiMovieTypeInfo::CMauiMovieTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiMovie), this);
}

/**
 * Address: 0x0079ED70 (FUN_0079ED70, Moho::CMauiMovieTypeInfo::dtr)
 */
CMauiMovieTypeInfo::~CMauiMovieTypeInfo() = default;

/**
 * Address: 0x0079ED60 (FUN_0079ED60, Moho::CMauiMovieTypeInfo::GetName)
 */
const char* CMauiMovieTypeInfo::GetName() const
{
  return "CMauiMovie";
}

/**
 * Address: 0x0079ED30 (FUN_0079ED30, Moho::CMauiMovieTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiMovieTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 360 (0x168 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiMovieTypeInfo::Init()
{
  size_ = 0x168;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiMovieTypeInfoStartup()
{
  (void)AcquireCMauiMovieTypeInfo();
  (void)std::atexit(&cleanup_CMauiMovieTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiMovieTypeInfoStartup_79ecd0, moho::register_CMauiMovieTypeInfoStartup)
