#include "moho/ai/CAiReconDBImplTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiReconDB.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiReconDBImplType()
  {
    if (!CAiReconDBImpl::sType) {
      CAiReconDBImpl::sType = gpg::LookupRType(typeid(CAiReconDBImpl));
    }
    return CAiReconDBImpl::sType;
  }

  [[nodiscard]] gpg::RType* CachedIAiReconDBType()
  {
    if (!IAiReconDB::sType) {
      IAiReconDB::sType = gpg::LookupRType(typeid(IAiReconDB));
    }
    return IAiReconDB::sType;
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

  [[nodiscard]] gpg::RRef CreateAiReconDbRefOwned()
  {
    return MakeTypedRef(new CAiReconDBImpl(nullptr, false), CachedCAiReconDBImplType());
  }

  void DeleteAiReconDbOwned(void* object)
  {
    delete static_cast<CAiReconDBImpl*>(object);
  }

  [[nodiscard]] gpg::RRef ConstructAiReconDbRefInPlace(void* objectStorage)
  {
    auto* const recon = static_cast<CAiReconDBImpl*>(objectStorage);
    if (recon) {
      new (recon) CAiReconDBImpl(nullptr, false);
    }
    return MakeTypedRef(recon, CachedCAiReconDBImplType());
  }

  void DestroyAiReconDbInPlace(void* object)
  {
    auto* const recon = static_cast<CAiReconDBImpl*>(object);
    if (recon) {
      recon->~CAiReconDBImpl();
    }
  }

  void AddIAiReconDBBase(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedIAiReconDBType();
    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }
} // namespace

/**
 * Address: 0x005C2860 (FUN_005C2860, scalar deleting thunk)
 */
CAiReconDBImplTypeInfo::~CAiReconDBImplTypeInfo() = default;

/**
 * Address: 0x005C2850 (FUN_005C2850)
 */
const char* CAiReconDBImplTypeInfo::GetName() const
{
  return "CAiReconDBImpl";
}

/**
 * Address: 0x005C2810 (FUN_005C2810)
 */
void CAiReconDBImplTypeInfo::Init()
{
  size_ = sizeof(CAiReconDBImpl);
  newRefFunc_ = &CreateAiReconDbRefOwned;
  ctorRefFunc_ = &ConstructAiReconDbRefInPlace;
  deleteFunc_ = &DeleteAiReconDbOwned;
  dtrFunc_ = &DestroyAiReconDbInPlace;
  gpg::RType::Init();
  AddIAiReconDBBase(this);
  Finish();
}
