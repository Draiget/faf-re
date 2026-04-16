#include "moho/render/camera/CameraImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/render/camera/CameraImpl.h"
#include "moho/script/CScriptEvent.h"

using namespace moho;

namespace
{
  alignas(CameraImplTypeInfo) unsigned char gCameraImplTypeInfoStorage[sizeof(CameraImplTypeInfo)];
  bool gCameraImplTypeInfoConstructed = false;

  [[nodiscard]] gpg::RType* CachedCScriptEventType()
  {
    if (!CScriptEvent::sType) {
      CScriptEvent::sType = gpg::LookupRType(typeid(CScriptEvent));
    }
    return CScriptEvent::sType;
  }

  /**
   * Address: 0x007B0E30 (FUN_007B0E30)
   *
   * What it does:
   * Registers `CScriptEvent` as one reflected `CameraImpl` base lane at
   * offset `+0x0C`.
   */
  void AddCScriptEventBaseToCameraImplType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptEventType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 12;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] CameraImplTypeInfo& AcquireCameraImplTypeInfo()
  {
    if (!gCameraImplTypeInfoConstructed) {
      new (gCameraImplTypeInfoStorage) CameraImplTypeInfo();
      gCameraImplTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CameraImplTypeInfo*>(gCameraImplTypeInfoStorage);
  }

  void cleanup_CameraImplTypeInfo()
  {
    if (!gCameraImplTypeInfoConstructed) {
      return;
    }
    auto& ti = *reinterpret_cast<CameraImplTypeInfo*>(gCameraImplTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CameraImplTypeInfoBootstrap
  {
    CameraImplTypeInfoBootstrap() { moho::register_CameraImplTypeInfoStartup(); }
  };
  CameraImplTypeInfoBootstrap gCameraImplTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x007AAF30 (FUN_007AAF30, Moho::CameraImplTypeInfo::CameraImplTypeInfo)
 */
CameraImplTypeInfo::CameraImplTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CameraImpl), this);
}

/**
 * Address: 0x007AAFD0 (FUN_007AAFD0, scalar deleting thunk)
 */
CameraImplTypeInfo::~CameraImplTypeInfo() = default;

/**
 * Address: 0x007AAFC0 (FUN_007AAFC0, Moho::CameraImplTypeInfo::GetName)
 */
const char* CameraImplTypeInfo::GetName() const
{
  return "CameraImpl";
}

/**
 * Address: 0x007AAF90 (FUN_007AAF90, Moho::CameraImplTypeInfo::Init)
 */
void CameraImplTypeInfo::Init()
{
  size_ = 0x858;
  AddCScriptEventBaseToCameraImplType(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDF5C0 (FUN_00BDF5C0, register_CameraImplTypeInfo)
 */
void moho::register_CameraImplTypeInfoStartup()
{
  (void)AcquireCameraImplTypeInfo();
  (void)std::atexit(&cleanup_CameraImplTypeInfo);
}
