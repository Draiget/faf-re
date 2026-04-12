#include "moho/animation/CAniPoseTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniPose.h"

using namespace moho;

namespace
{
  alignas(CAniPoseTypeInfo) unsigned char gCAniPoseTypeInfoStorage[sizeof(CAniPoseTypeInfo)];
  bool gCAniPoseTypeInfoConstructed = false;

  [[nodiscard]] CAniPoseTypeInfo& AcquireCAniPoseTypeInfo()
  {
    if (!gCAniPoseTypeInfoConstructed) {
      new (gCAniPoseTypeInfoStorage) CAniPoseTypeInfo();
      gCAniPoseTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CAniPoseTypeInfo*>(gCAniPoseTypeInfoStorage);
  }

  [[nodiscard]] CAniPoseTypeInfo* PeekCAniPoseTypeInfo() noexcept
  {
    if (!gCAniPoseTypeInfoConstructed) {
      return nullptr;
    }
    return reinterpret_cast<CAniPoseTypeInfo*>(gCAniPoseTypeInfoStorage);
  }

  void cleanup_CAniPoseTypeInfoStartup()
  {
    CAniPoseTypeInfo* const typeInfo = PeekCAniPoseTypeInfo();
    if (!typeInfo) {
      return;
    }
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CAniPoseTypeInfoStartupBootstrap
  {
    CAniPoseTypeInfoStartupBootstrap()
    {
      moho::register_CAniPoseTypeInfoStartup();
    }
  };

  CAniPoseTypeInfoStartupBootstrap gCAniPoseTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x0054AD70 (FUN_0054AD70, ??0CAniPoseTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `CAniPose` RTTI for this type-info helper.
 */
CAniPoseTypeInfo::CAniPoseTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAniPose), this);
}

/**
 * Address: 0x0054AE30 (FUN_0054AE30, scalar deleting thunk)
 */
CAniPoseTypeInfo::~CAniPoseTypeInfo() = default;

/**
 * Address: 0x0054AE20 (FUN_0054AE20, ?GetName@CAniPoseTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAniPoseTypeInfo::GetName() const
{
  return "CAniPose";
}

/**
 * Address: 0x0054ADD0 (FUN_0054ADD0, ?Init@CAniPoseTypeInfo@Moho@@UAEXXZ)
 *
 * What it does:
 * Sets size = 0x90, installs ref-management function pointers, then finalizes.
 */
void CAniPoseTypeInfo::Init()
{
  size_ = sizeof(CAniPose);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BC9940 (FUN_00BC9940, register_CAniPoseTypeInfo)
 */
void moho::register_CAniPoseTypeInfoStartup()
{
  (void)AcquireCAniPoseTypeInfo();
  (void)std::atexit(&cleanup_CAniPoseTypeInfoStartup);
}
