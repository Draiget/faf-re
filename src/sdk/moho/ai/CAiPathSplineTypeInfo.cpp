#include "moho/ai/CAiPathSplineTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CAiPathSplineTypeInfo) unsigned char gCAiPathSplineTypeInfoStorage[sizeof(CAiPathSplineTypeInfo)] = {};
  bool gCAiPathSplineTypeInfoConstructed = false;

  [[nodiscard]] CAiPathSplineTypeInfo* AcquireCAiPathSplineTypeInfo()
  {
    if (!gCAiPathSplineTypeInfoConstructed) {
      new (gCAiPathSplineTypeInfoStorage) CAiPathSplineTypeInfo();
      gCAiPathSplineTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiPathSplineTypeInfo*>(gCAiPathSplineTypeInfoStorage);
  }

  /**
   * Address: 0x005B2340 (FUN_005B2340, preregister_CAiPathSplineTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI descriptor for `CAiPathSpline`.
   */
  [[nodiscard]] gpg::RType* preregister_CAiPathSplineTypeInfo()
  {
    CAiPathSplineTypeInfo* const typeInfo = AcquireCAiPathSplineTypeInfo();
    gpg::PreRegisterRType(typeid(CAiPathSpline), typeInfo);
    return typeInfo;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathSplineType()
  {
    if (!CAiPathSpline::sType) {
      CAiPathSpline::sType = gpg::LookupRType(typeid(CAiPathSpline));
    }
    return CAiPathSpline::sType;
  }

  template <typename T>
  [[nodiscard]] gpg::RRef MakeTypedRef(T* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x005B52A0 (FUN_005B52A0, Moho::CAiPathSpline::operator new)
   *
   * What it does:
   * Allocates and default-constructs one `CAiPathSpline`, then returns the
   * typed reflection reference used by RTTI new-ref lanes.
   */
  [[nodiscard]] gpg::RRef CreateAiPathSplineRefOwned()
  {
    CAiPathSpline* const spline = new (std::nothrow) CAiPathSpline();
    gpg::RRef out{};
    gpg::RRef_CAiPathSpline(&out, spline);
    return out;
  }

  /**
   * Address: 0x005B52F0 (FUN_005B52F0)
   *
   * What it does:
   * Destroys one heap-owned `CAiPathSpline` and frees its storage. Installed
   * as `deleteFunc_` by the lifecycle-callbacks helper. The compiler-generated
   * `delete` lowering chains through `~CAiPathSpline()` to release the inline
   * fastvector lanes before `operator delete`.
   */
  void DeleteAiPathSplineOwned(void* object)
  {
    delete static_cast<CAiPathSpline*>(object);
  }

  /**
   * Address: 0x005B5350 (FUN_005B5350)
   *
   * What it does:
   * Placement-constructs one `CAiPathSpline` over caller-provided storage and
   * wraps it in a typed `gpg::RRef` lane. Installed as `ctorRefFunc_` by the
   * lifecycle-callbacks helper.
   */
  [[nodiscard]] gpg::RRef ConstructAiPathSplineRefInPlace(void* objectStorage)
  {
    auto* const spline = static_cast<CAiPathSpline*>(objectStorage);
    if (spline) {
      new (spline) CAiPathSpline();
    }
    return MakeTypedRef(spline, CachedCAiPathSplineType());
  }

  /**
   * Address: 0x005B5390 (FUN_005B5390)
   *
   * What it does:
   * Runs the `CAiPathSpline` destructor in place over caller-provided storage
   * without freeing it. Installed as `dtrFunc_` by the lifecycle-callbacks
   * helper. The compiler-generated destructor body releases inline fastvector
   * lanes (matching the binary's manual cleanup of the embedded vectors).
   */
  void DestroyAiPathSplineInPlace(void* object)
  {
    auto* const spline = static_cast<CAiPathSpline*>(object);
    if (spline) {
      spline->~CAiPathSpline();
    }
  }

  /**
   * Address: 0x005B4890 (FUN_005B4890)
   *
   * What it does:
   * Assigns `CAiPathSpline` lifecycle callback lanes (`newRefFunc_`,
   * `deleteFunc_`, `ctorRefFunc_`, `dtrFunc_`) on one reflected type
   * descriptor and returns the same descriptor pointer.
   */
  [[nodiscard]] CAiPathSplineTypeInfo*
  ConfigureCAiPathSplineTypeInfoLifecycleCallbacks(CAiPathSplineTypeInfo* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return nullptr;
    }

    typeInfo->newRefFunc_ = &CreateAiPathSplineRefOwned;
    typeInfo->deleteFunc_ = &DeleteAiPathSplineOwned;
    typeInfo->ctorRefFunc_ = &ConstructAiPathSplineRefInPlace;
    typeInfo->dtrFunc_ = &DestroyAiPathSplineInPlace;
    return typeInfo;
  }

  /**
   * Address: 0x00BF74E0 (FUN_00BF74E0, cleanup_CAiPathSplineTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CAiPathSplineTypeInfo` reflection storage.
   */
  void cleanup_CAiPathSplineTypeInfo()
  {
    if (!gCAiPathSplineTypeInfoConstructed) {
      return;
    }

    AcquireCAiPathSplineTypeInfo()->~CAiPathSplineTypeInfo();
    gCAiPathSplineTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005B23F0 (FUN_005B23F0, scalar deleting thunk)
 */
CAiPathSplineTypeInfo::~CAiPathSplineTypeInfo() = default;

/**
 * Address: 0x005B23E0 (FUN_005B23E0, ?GetName@CAiPathSplineTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPathSplineTypeInfo::GetName() const
{
  return "CAiPathSpline";
}

/**
 * Address: 0x005B23A0 (FUN_005B23A0, ?Init@CAiPathSplineTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathSplineTypeInfo::Init()
{
  size_ = sizeof(CAiPathSpline);
  (void)ConfigureCAiPathSplineTypeInfoLifecycleCallbacks(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCD330 (FUN_00BCD330, register_CAiPathSplineTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `CAiPathSpline` and
 * installs process-exit cleanup.
 */
int moho::register_CAiPathSplineTypeInfo()
{
  (void)preregister_CAiPathSplineTypeInfo();
  return std::atexit(&cleanup_CAiPathSplineTypeInfo);
}

namespace
{
  struct CAiPathSplineTypeInfoBootstrap
  {
    CAiPathSplineTypeInfoBootstrap()
    {
      (void)moho::register_CAiPathSplineTypeInfo();
    }
  };

  [[maybe_unused]] CAiPathSplineTypeInfoBootstrap gCAiPathSplineTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiPathSplineTypeInfo_62956f, moho::register_CAiPathSplineTypeInfo)

GPG_PREREGISTER_INIT(preregister_CAiPathSplineTypeInfo_62956f, preregister_CAiPathSplineTypeInfo)
