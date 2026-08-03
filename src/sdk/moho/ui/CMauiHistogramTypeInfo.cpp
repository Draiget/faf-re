#include "moho/ui/CMauiHistogramTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiHistogramTypeInfo) unsigned char gCMauiHistogramTypeInfoStorage[sizeof(CMauiHistogramTypeInfo)];
  bool gCMauiHistogramTypeInfoConstructed = false;

  [[nodiscard]] CMauiHistogramTypeInfo& AcquireCMauiHistogramTypeInfo()
  {
    if (!gCMauiHistogramTypeInfoConstructed) {
      new (gCMauiHistogramTypeInfoStorage) CMauiHistogramTypeInfo();
      gCMauiHistogramTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiHistogramTypeInfo*>(gCMauiHistogramTypeInfoStorage);
  }

  void cleanup_CMauiHistogramTypeInfo()
  {
    if (!gCMauiHistogramTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiHistogramTypeInfo*>(gCMauiHistogramTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiHistogramTypeInfoBootstrap
  {
    CMauiHistogramTypeInfoBootstrap() { moho::register_CMauiHistogramTypeInfoStartup(); }
  };
  CMauiHistogramTypeInfoBootstrap gCMauiHistogramTypeInfoBootstrap;

  /**
   * Address: 0x00798950 (FUN_00798950, Moho::CMauiHistogramTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiHistogram's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiHistogram standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiHistogram fails its upcast.
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
 * Address: 0x00797650 (FUN_00797650, Moho::CMauiHistogramTypeInfo::CMauiHistogramTypeInfo)
 */
CMauiHistogramTypeInfo::CMauiHistogramTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiHistogram), this);
}

/**
 * Address: 0x007976F0 (FUN_007976F0, Moho::CMauiHistogramTypeInfo::dtr)
 */
CMauiHistogramTypeInfo::~CMauiHistogramTypeInfo() = default;

/**
 * Address: 0x007976E0 (FUN_007976E0, Moho::CMauiHistogramTypeInfo::GetName)
 */
const char* CMauiHistogramTypeInfo::GetName() const
{
  return "CMauiHistogram";
}

/**
 * Address: 0x007976B0 (FUN_007976B0, Moho::CMauiHistogramTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiHistogramTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 308 (0x134 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiHistogramTypeInfo::Init()
{
  size_ = 0x134;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiHistogramTypeInfoStartup()
{
  (void)AcquireCMauiHistogramTypeInfo();
  (void)std::atexit(&cleanup_CMauiHistogramTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiHistogramTypeInfoStartup_797650, moho::register_CMauiHistogramTypeInfoStartup)
