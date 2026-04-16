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
    gpg::RRef_CAiFormationInstance(&out, object);
    return out;
  }

  /**
   * Address: 0x0059DB00 (FUN_0059DB00)
   *
   * What it does:
   * Registers `CFormationInstance` as one reflected base lane for
   * `CAiFormationInstance` at offset `+0x00`.
   */
  void AddCFormationInstanceBaseToCAiFormationInstanceType(gpg::RType* const typeInfo)
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
  (void)InitializeAllocationCallbacks(this);

  gpg::RType::Init();
  AddCFormationInstanceBaseToCAiFormationInstanceType(this);
  Finish();
}

/**
 * Address: 0x0059C7D0 (FUN_0059C7D0)
 *
 * What it does:
 * Wires `newRef/ctorRef/delete/dtr` callback lanes for
 * `CAiFormationInstance` reflection ownership.
 */
gpg::RType* CAiFormationInstanceTypeInfo::InitializeAllocationCallbacks(gpg::RType* const typeInfo)
{
  typeInfo->newRefFunc_ = &CAiFormationInstanceTypeInfo::NewRef;
  typeInfo->ctorRefFunc_ = &CAiFormationInstanceTypeInfo::CtrRef;
  typeInfo->deleteFunc_ = &CAiFormationInstanceTypeInfo::Delete;
  typeInfo->dtrFunc_ = &CAiFormationInstanceTypeInfo::Destruct;
  return typeInfo;
}

/**
 * Address: 0x0059D0F0 (FUN_0059D0F0, ??2CAiFormationInstance@Moho@@QAE@@Z_0)
 */
gpg::RRef CAiFormationInstanceTypeInfo::NewRef()
{
  auto* const object = new (std::nothrow) CAiFormationInstanceTypeInfoConstructShim();
  if (object) {
    object->mSim = nullptr;
  }
  return MakeFormationInstanceRef(object);
}

/**
 * Address: 0x0059D1A0 (FUN_0059D1A0)
 */
gpg::RRef CAiFormationInstanceTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationInstanceTypeInfoConstructShim*>(objectStorage);
  if (object) {
    new (object) CAiFormationInstanceTypeInfoConstructShim();
    object->mSim = nullptr;
  }
  return MakeFormationInstanceRef(object);
}

/**
 * Address: 0x0059D180 (FUN_0059D180)
 */
void CAiFormationInstanceTypeInfo::Delete(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationInstance*>(objectStorage);
  if (!object) {
    return;
  }
  object->operator_delete(1);
}

/**
 * Address: 0x0059D220 (FUN_0059D220)
 */
void CAiFormationInstanceTypeInfo::Destruct(void* const objectStorage)
{
  static_cast<CAiFormationInstance*>(objectStorage)->operator_delete(0);
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
