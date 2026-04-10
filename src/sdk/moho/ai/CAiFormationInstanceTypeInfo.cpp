#include "moho/ai/CAiFormationInstanceTypeInfo.h"

#include <cstdlib>
#include <initializer_list>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

namespace
{
  class CAiFormationInstanceTypeInfoConstructShim final : public CAiFormationInstance
  {
  public:
    SFormationLaneEntry* Func6(Unit*) override { return nullptr; }
    SCoordsVec2* GetFormationPosition(SCoordsVec2* dest, Unit*, SFormationLaneEntry*) override { return dest; }
    SOCellPos* GetAdjustedFormationPosition(SOCellPos* dest, Unit*, SFormationLaneEntry*) override { return dest; }
    SCoordsVec2* Func9(SCoordsVec2* dest, Unit*, SFormationLaneEntry*) override { return dest; }
    Wm3::Vec3f* Func10(Wm3::Vec3f* out, Unit*, SFormationLaneEntry*) override { return out; }
    float Func11(Unit*, SFormationLaneEntry*) override { return 0.0f; }
    std::int32_t Func12(Unit*, SFormationLaneEntry*) override { return 1; }
    float CalcFormationSpeed(Unit*, float* speedScaleOut, SFormationLaneEntry* laneEntry) override
    {
      if (speedScaleOut) {
        *speedScaleOut = 0.0f;
      }
      return laneEntry ? laneEntry->preferredSpeed : 0.0f;
    }
    Unit* Func14(Unit* unit, SFormationLaneEntry*) override { return unit; }
    void AddUnit(Unit*) override {}
    void RemoveUnit(Unit*) override {}
    bool Func17(Unit*, bool) const override { return false; }
    void Update() override {}
    Wm3::Vec3f* Func19(Wm3::Vec3f* out, Unit*) const override { return out; }
    bool Func21(Unit*) const override { return true; }
    SCoordsVec2* FindSlotFor(SCoordsVec2* dest, const SCoordsVec2* pos, Unit*) override
    {
      if (dest && pos) {
        *dest = *pos;
      }
      return dest;
    }
  };

  static_assert(
    sizeof(CAiFormationInstanceTypeInfoConstructShim) == sizeof(CAiFormationInstance),
    "CAiFormationInstanceTypeInfoConstructShim size must match CAiFormationInstance"
  );

  alignas(CAiFormationInstanceTypeInfo)
  unsigned char gCAiFormationInstanceTypeInfoStorage[sizeof(CAiFormationInstanceTypeInfo)] = {};
  bool gCAiFormationInstanceTypeInfoConstructed = false;

  [[nodiscard]] CAiFormationInstanceTypeInfo* AcquireCAiFormationInstanceTypeInfo()
  {
    if (!gCAiFormationInstanceTypeInfoConstructed) {
      new (gCAiFormationInstanceTypeInfoStorage) CAiFormationInstanceTypeInfo();
      gCAiFormationInstanceTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiFormationInstanceTypeInfo*>(gCAiFormationInstanceTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* CachedCAiFormationInstanceType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeid(CAiFormationInstance));
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RType* CachedCFormationInstanceType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = ResolveTypeByAnyName({"CFormationInstance", "Moho::CFormationInstance"});
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RRef MakeFormationInstanceRef(CAiFormationInstance* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedCAiFormationInstanceType();
    return out;
  }

  [[nodiscard]] gpg::RRef CreateFormationInstanceRefOwned()
  {
    auto* const object = new (std::nothrow) CAiFormationInstanceTypeInfoConstructShim();
    if (object) {
      object->mSim = nullptr;
    }

    return MakeFormationInstanceRef(object);
  }

  [[nodiscard]] gpg::RRef ConstructFormationInstanceRefInPlace(void* const objectStorage)
  {
    auto* const object = static_cast<CAiFormationInstanceTypeInfoConstructShim*>(objectStorage);
    if (object) {
      new (object) CAiFormationInstanceTypeInfoConstructShim();
      object->mSim = nullptr;
    }

    return MakeFormationInstanceRef(object);
  }

  void DeleteFormationInstanceOwned(void* const objectStorage)
  {
    auto* const object = static_cast<CAiFormationInstance*>(objectStorage);
    if (!object) {
      return;
    }

    object->operator_delete(1);
  }

  void DestroyFormationInstanceInPlace(void* const objectStorage)
  {
    auto* const object = static_cast<CAiFormationInstance*>(objectStorage);
    if (!object) {
      return;
    }

    object->operator_delete(0);
  }

  void AddCFormationInstanceBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCFormationInstanceType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BF6740 (FUN_00BF6740, cleanup_CAiFormationInstanceTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CAiFormationInstanceTypeInfo` storage, releasing
   * base/field vectors and restoring base RTTI vtable lanes.
   */
  void cleanup_CAiFormationInstanceTypeInfo()
  {
    if (!gCAiFormationInstanceTypeInfoConstructed) {
      return;
    }

    AcquireCAiFormationInstanceTypeInfo()->~CAiFormationInstanceTypeInfo();
    gCAiFormationInstanceTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x0059BD80 (FUN_0059BD80, ctor/preregister lane)
 *
 * What it does:
 * Initializes RTTI base lanes and preregisters `CAiFormationInstance`
 * reflection ownership.
 */
CAiFormationInstanceTypeInfo::CAiFormationInstanceTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiFormationInstance), this);
}

/**
 * Address: 0x0059BE30 (FUN_0059BE30, scalar deleting thunk)
 */
CAiFormationInstanceTypeInfo::~CAiFormationInstanceTypeInfo() = default;

/**
 * Address: 0x0059BE20 (FUN_0059BE20, ?GetName@CAiFormationInstanceTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiFormationInstanceTypeInfo::GetName() const
{
  return "CAiFormationInstance";
}

/**
 * Address: 0x0059BDE0 (FUN_0059BDE0, ?Init@CAiFormationInstanceTypeInfo@Moho@@UAEXXZ)
 */
void CAiFormationInstanceTypeInfo::Init()
{
  size_ = sizeof(CAiFormationInstance);
  newRefFunc_ = &CreateFormationInstanceRefOwned;
  ctorRefFunc_ = &ConstructFormationInstanceRefInPlace;
  deleteFunc_ = &DeleteFormationInstanceOwned;
  dtrFunc_ = &DestroyFormationInstanceInPlace;

  gpg::RType::Init();
  AddCFormationInstanceBase(this);
  Finish();
}

/**
 * Address: 0x00BCC130 (FUN_00BCC130, register_CAiFormationInstanceTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiFormationInstanceTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiFormationInstanceTypeInfo()
{
  (void)AcquireCAiFormationInstanceTypeInfo();
  (void)std::atexit(&cleanup_CAiFormationInstanceTypeInfo);
}

namespace
{
  struct CAiFormationInstanceTypeInfoBootstrap
  {
    CAiFormationInstanceTypeInfoBootstrap()
    {
      moho::register_CAiFormationInstanceTypeInfo();
    }
  };

  [[maybe_unused]] CAiFormationInstanceTypeInfoBootstrap gCAiFormationInstanceTypeInfoBootstrap;
} // namespace
