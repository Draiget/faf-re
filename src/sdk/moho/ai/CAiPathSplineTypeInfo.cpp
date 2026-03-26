#include "moho/ai/CAiPathSplineTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
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

  [[nodiscard]] gpg::RRef CreateAiPathSplineRefOwned()
  {
    return MakeTypedRef(new CAiPathSpline(), CachedCAiPathSplineType());
  }

  void DeleteAiPathSplineOwned(void* object)
  {
    delete static_cast<CAiPathSpline*>(object);
  }

  [[nodiscard]] gpg::RRef ConstructAiPathSplineRefInPlace(void* objectStorage)
  {
    auto* const spline = static_cast<CAiPathSpline*>(objectStorage);
    if (spline) {
      new (spline) CAiPathSpline();
    }
    return MakeTypedRef(spline, CachedCAiPathSplineType());
  }

  void DestroyAiPathSplineInPlace(void* object)
  {
    auto* const spline = static_cast<CAiPathSpline*>(object);
    if (spline) {
      spline->~CAiPathSpline();
    }
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
  newRefFunc_ = &CreateAiPathSplineRefOwned;
  ctorRefFunc_ = &ConstructAiPathSplineRefInPlace;
  deleteFunc_ = &DeleteAiPathSplineOwned;
  dtrFunc_ = &DestroyAiPathSplineInPlace;
  gpg::RType::Init();
  Finish();
}
