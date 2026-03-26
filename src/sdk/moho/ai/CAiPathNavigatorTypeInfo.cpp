#include "moho/ai/CAiPathNavigatorTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    if (!CAiPathNavigator::sType) {
      CAiPathNavigator::sType = gpg::LookupRType(typeid(CAiPathNavigator));
    }
    return CAiPathNavigator::sType;
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

  [[nodiscard]] gpg::RRef CreateAiPathNavigatorRefOwned()
  {
    return MakeTypedRef(new CAiPathNavigator(nullptr), CachedCAiPathNavigatorType());
  }

  void DeleteAiPathNavigatorOwned(void* object)
  {
    delete static_cast<CAiPathNavigator*>(object);
  }

  [[nodiscard]] gpg::RRef ConstructAiPathNavigatorRefInPlace(void* objectStorage)
  {
    auto* const navigator = static_cast<CAiPathNavigator*>(objectStorage);
    if (navigator) {
      new (navigator) CAiPathNavigator(nullptr);
    }
    return MakeTypedRef(navigator, CachedCAiPathNavigatorType());
  }

  void DestroyAiPathNavigatorInPlace(void* object)
  {
    auto* const navigator = static_cast<CAiPathNavigator*>(object);
    if (navigator) {
      navigator->~CAiPathNavigator();
    }
  }
} // namespace

/**
 * Address: 0x005AFB30 (FUN_005AFB30, scalar deleting thunk)
 */
CAiPathNavigatorTypeInfo::~CAiPathNavigatorTypeInfo() = default;

/**
 * Address: 0x005AFB20 (FUN_005AFB20, ?GetName@CAiPathNavigatorTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPathNavigatorTypeInfo::GetName() const
{
  return "CAiPathNavigator";
}

/**
 * Address: 0x005AFAD0 (FUN_005AFAD0, ?Init@CAiPathNavigatorTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathNavigatorTypeInfo::Init()
{
  size_ = sizeof(CAiPathNavigator);
  newRefFunc_ = &CreateAiPathNavigatorRefOwned;
  ctorRefFunc_ = &ConstructAiPathNavigatorRefInPlace;
  deleteFunc_ = &DeleteAiPathNavigatorOwned;
  dtrFunc_ = &DestroyAiPathNavigatorInPlace;
  gpg::RType::Init();
  Finish();
}
