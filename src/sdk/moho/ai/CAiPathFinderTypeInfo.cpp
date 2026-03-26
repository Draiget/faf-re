#include "moho/ai/CAiPathFinderTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    if (!CAiPathFinder::sType) {
      CAiPathFinder::sType = gpg::LookupRType(typeid(CAiPathFinder));
    }
    return CAiPathFinder::sType;
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

  [[nodiscard]] gpg::RRef CreateAiPathFinderRefOwned()
  {
    return MakeTypedRef(new CAiPathFinder(), CachedCAiPathFinderType());
  }

  void DeleteAiPathFinderOwned(void* object)
  {
    delete static_cast<CAiPathFinder*>(object);
  }

  [[nodiscard]] gpg::RRef ConstructAiPathFinderRefInPlace(void* objectStorage)
  {
    auto* const pathFinder = static_cast<CAiPathFinder*>(objectStorage);
    if (pathFinder) {
      new (pathFinder) CAiPathFinder();
    }
    return MakeTypedRef(pathFinder, CachedCAiPathFinderType());
  }

  void DestroyAiPathFinderInPlace(void* object)
  {
    auto* const pathFinder = static_cast<CAiPathFinder*>(object);
    if (pathFinder) {
      pathFinder->~CAiPathFinder();
    }
  }

  void AddBaseByTypeInfo(gpg::RType* typeInfo, const std::type_info& baseTypeInfo, const std::int32_t baseOffset)
  {
    gpg::RType* baseType = nullptr;
    try {
      baseType = gpg::LookupRType(baseTypeInfo);
    } catch (...) {
      baseType = nullptr;
    }

    if (!baseType) {
      return;
    }

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = baseOffset;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }
} // namespace

/**
 * Address: 0x005AAB60 (FUN_005AAB60, scalar deleting thunk)
 */
CAiPathFinderTypeInfo::~CAiPathFinderTypeInfo() = default;

/**
 * Address: 0x005AAB50 (FUN_005AAB50, ?GetName@CAiPathFinderTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPathFinderTypeInfo::GetName() const
{
  return "CAiPathFinder";
}

/**
 * Address: 0x005AAB00 (FUN_005AAB00, ?Init@CAiPathFinderTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathFinderTypeInfo::Init()
{
  size_ = sizeof(CAiPathFinder);
  newRefFunc_ = &CreateAiPathFinderRefOwned;
  ctorRefFunc_ = &ConstructAiPathFinderRefInPlace;
  deleteFunc_ = &DeleteAiPathFinderOwned;
  dtrFunc_ = &DestroyAiPathFinderInPlace;

  gpg::RType::Init();

  AddBaseByTypeInfo(this, typeid(IPathTraveler), 0x00);
  AddBaseByTypeInfo(this, typeid(Broadcaster), 0x0C);

  Finish();
}
