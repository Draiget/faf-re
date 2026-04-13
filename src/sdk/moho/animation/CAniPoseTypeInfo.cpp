#include "moho/animation/CAniPoseTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"
#include "moho/animation/CAniPose.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAniPoseType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(CAniPose));
    }
    return sType;
  }

  [[nodiscard]] CAniPose* TryUpcastCAniPoseOrThrow(const gpg::RRef& sourceRef)
  {
    gpg::RType* const targetType = CachedCAniPoseType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, targetType);
    auto* const pose = static_cast<CAniPose*>(upcast.mObj);
    if (!pose) {
      const char* const sourceName = sourceRef.mType ? sourceRef.mType->GetName() : "null";
      const char* const targetName = targetType ? targetType->GetName() : "null";
      throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }

    return pose;
  }

  [[nodiscard]] gpg::RRef MakePoseRef(CAniPose* const pose)
  {
    gpg::RRef out{};
    gpg::RRef_CAniPose(&out, pose);
    return out;
  }

  void InitializeDefaultPoseStorage(CAniPose& pose)
  {
    pose.mSkeleton = boost::shared_ptr<const CAniSkel>{};
    pose.mScale = 1.0f;

    pose.mLocalTransform.orient_.w = 1.0f;
    pose.mLocalTransform.orient_.x = 0.0f;
    pose.mLocalTransform.orient_.y = 0.0f;
    pose.mLocalTransform.orient_.z = 0.0f;
    pose.mLocalTransform.pos_.x = 0.0f;
    pose.mLocalTransform.pos_.y = 0.0f;
    pose.mLocalTransform.pos_.z = 0.0f;

    pose.mBones.mBegin = &pose.mBones.mInlineStorage;
    pose.mBones.mEnd = &pose.mBones.mInlineStorage;
    pose.mBones.mCapacity = &pose.mBones.mInlineStorage + 1;
    pose.mBones.mOriginal = &pose.mBones.mInlineStorage;

    pose.mMaxOffset = 0.0f;
  }

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
  newRefFunc_ = &CAniPoseTypeInfo::NewRef;
  ctorRefFunc_ = &CAniPoseTypeInfo::CtrRef;
  cpyRefFunc_ = &CAniPoseTypeInfo::CpyRef;
  movRefFunc_ = &CAniPoseTypeInfo::MovRef;
  deleteFunc_ = &CAniPoseTypeInfo::Delete;
  dtrFunc_ = &CAniPoseTypeInfo::Destruct;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0054D8A0 (FUN_0054D8A0, Moho::CAniPoseTypeInfo::NewRef)
 *
 * What it does:
 * Allocates one default-initialized `CAniPose` and returns its typed
 * reflection reference.
 */
gpg::RRef CAniPoseTypeInfo::NewRef()
{
  auto* const pose = static_cast<CAniPose*>(::operator new(sizeof(CAniPose), std::nothrow));
  if (pose) {
    InitializeDefaultPoseStorage(*pose);
  }

  return MakePoseRef(pose);
}

/**
 * Address: 0x0054D940 (FUN_0054D940, Moho::CAniPoseTypeInfo::CpyRef)
 *
 * What it does:
 * Allocates one destination `CAniPose`, copy-constructs it from the source
 * reference, and returns the typed reflection reference.
 */
gpg::RRef CAniPoseTypeInfo::CpyRef(gpg::RRef* const sourceRef)
{
  auto* const pose = static_cast<CAniPose*>(::operator new(sizeof(CAniPose), std::nothrow));
  if (pose) {
    const CAniPose* const source = TryUpcastCAniPoseOrThrow(*sourceRef);
    new (pose) CAniPose(*source);
  }

  return MakePoseRef(pose);
}

/**
 * Address: 0x0054D9D0 (FUN_0054D9D0, Moho::CAniPoseTypeInfo::Delete)
 *
 * What it does:
 * Destroys and frees one heap-owned `CAniPose`.
 */
void CAniPoseTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<CAniPose*>(objectStorage);
}

/**
 * Address: 0x0054D9F0 (FUN_0054D9F0, Moho::CAniPoseTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-initializes one `CAniPose` in caller-provided storage and returns
 * its typed reflection reference.
 */
gpg::RRef CAniPoseTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const pose = static_cast<CAniPose*>(objectStorage);
  if (pose) {
    InitializeDefaultPoseStorage(*pose);
  }

  return MakePoseRef(pose);
}

/**
 * Address: 0x0054DA80 (FUN_0054DA80, Moho::CAniPoseTypeInfo::MovRef)
 *
 * What it does:
 * Placement-copy-constructs one `CAniPose` in caller-provided storage from the
 * source reflection reference.
 */
gpg::RRef CAniPoseTypeInfo::MovRef(void* const objectStorage, gpg::RRef* const sourceRef)
{
  auto* const pose = static_cast<CAniPose*>(objectStorage);
  if (pose) {
    const CAniPose* const source = TryUpcastCAniPoseOrThrow(*sourceRef);
    new (pose) CAniPose(*source);
  }

  return MakePoseRef(pose);
}

/**
 * Address: 0x0054DB00 (FUN_0054DB00, Moho::CAniPoseTypeInfo::Destruct)
 *
 * What it does:
 * Runs the `CAniPose` destructor in place without freeing storage.
 */
void CAniPoseTypeInfo::Destruct(void* const objectStorage)
{
  if (!objectStorage) {
    return;
  }

  static_cast<CAniPose*>(objectStorage)->~CAniPose();
}

/**
 * Address: 0x00BC9940 (FUN_00BC9940, register_CAniPoseTypeInfo)
 */
void moho::register_CAniPoseTypeInfoStartup()
{
  (void)AcquireCAniPoseTypeInfo();
  (void)std::atexit(&cleanup_CAniPoseTypeInfoStartup);
}
