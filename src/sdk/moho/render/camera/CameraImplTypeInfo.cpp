#include "moho/render/camera/CameraImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/render/camera/CameraImpl.h"

using namespace moho;

namespace
{
  alignas(CameraImplTypeInfo) unsigned char gCameraImplTypeInfoStorage[sizeof(CameraImplTypeInfo)];
  bool gCameraImplTypeInfoConstructed = false;

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
    if (!gCameraImplTypeInfoConstructed) return;
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
 * Address: 0x007AAF30 (Moho::CameraImplTypeInfo::CameraImplTypeInfo)
 */
CameraImplTypeInfo::CameraImplTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CameraImpl), this);
}

/**
 * Address: 0x007AAFD0
 */
CameraImplTypeInfo::~CameraImplTypeInfo() = default;

/**
 * Address: 0x007AAFC0
 */
const char* CameraImplTypeInfo::GetName() const
{
  return "CameraImpl";
}

/**
 * Address: 0x007AAF90
 */
void CameraImplTypeInfo::Init()
{
  size_ = 0x858;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDF5C0
 */
void moho::register_CameraImplTypeInfoStartup()
{
  (void)AcquireCameraImplTypeInfo();
  (void)std::atexit(&cleanup_CameraImplTypeInfo);
}
