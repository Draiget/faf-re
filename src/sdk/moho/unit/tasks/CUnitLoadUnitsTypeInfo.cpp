#include "moho/unit/tasks/CUnitLoadUnitsTypeInfo.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitLoadUnitsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitLoadUnits));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  struct CachedDerivedTypeEntry
  {
    const std::type_info* typeInfo;
    gpg::RType* rType;
  };

  // Mirrors the binary's small per-thread dynamic type cache used by RRef helpers.
  thread_local std::array<CachedDerivedTypeEntry, 3> gDerivedTypeCache{};

  [[nodiscard]] gpg::RType* LookupCachedDerivedType(const std::type_info& dynamicTypeInfo)
  {
    for (std::size_t index = 0; index < gDerivedTypeCache.size(); ++index) {
      const CachedDerivedTypeEntry& entry = gDerivedTypeCache[index];
      if (entry.typeInfo == nullptr || entry.rType == nullptr) {
        continue;
      }

      if (entry.typeInfo == &dynamicTypeInfo || (*entry.typeInfo == dynamicTypeInfo)) {
        gpg::RType* const cachedType = entry.rType;
        for (std::size_t shift = index; shift > 0; --shift) {
          gDerivedTypeCache[shift] = gDerivedTypeCache[shift - 1];
        }
        gDerivedTypeCache[0] = CachedDerivedTypeEntry{&dynamicTypeInfo, cachedType};
        return cachedType;
      }
    }

    gpg::RType* const resolvedType = gpg::LookupRType(dynamicTypeInfo);
    for (std::size_t shift = gDerivedTypeCache.size() - 1; shift > 0; --shift) {
      gDerivedTypeCache[shift] = gDerivedTypeCache[shift - 1];
    }
    gDerivedTypeCache[0] = CachedDerivedTypeEntry{&dynamicTypeInfo, resolvedType};
    return resolvedType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00624F40 (FUN_00624F40, scalar deleting destructor thunk)
   */
  CUnitLoadUnitsTypeInfo::~CUnitLoadUnitsTypeInfo() = default;

  /**
   * Address: 0x00624F30 (FUN_00624F30, Moho::CUnitLoadUnitsTypeInfo::GetName)
   */
  const char* CUnitLoadUnitsTypeInfo::GetName() const
  {
    return "CUnitLoadUnits";
  }

  /**
   * Address: 0x00624EF0 (FUN_00624EF0, Moho::CUnitLoadUnitsTypeInfo::Init)
   */
  void CUnitLoadUnitsTypeInfo::Init()
  {
    size_ = sizeof(CUnitLoadUnits);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitLoadUnitsTypeInfo::NewRef,
      &CUnitLoadUnitsTypeInfo::CtrRef,
      &CUnitLoadUnitsTypeInfo::Delete,
      &CUnitLoadUnitsTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00627F50 (FUN_00627F50, Moho::CUnitLoadUnitsTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitLoadUnitsTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCCommandTaskType();
    GPG_ASSERT(baseType != nullptr);

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00627C20 (FUN_00627C20, Moho::CUnitLoadUnitsTypeInfo::NewRef)
   */
  gpg::RRef CUnitLoadUnitsTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitLoadUnits();
    gpg::RRef out{};
    (void)gpg::RRef_CUnitLoadUnits(&out, task);
    return out;
  }

  /**
   * Address: 0x00627CC0 (FUN_00627CC0, Moho::CUnitLoadUnitsTypeInfo::CtrRef)
   */
  gpg::RRef CUnitLoadUnitsTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitLoadUnits*>(objectStorage);
    if (task) {
      new (task) CUnitLoadUnits();
    }

    gpg::RRef out{};
    (void)gpg::RRef_CUnitLoadUnits(&out, task);
    return out;
  }

  /**
   * Address: 0x00627CA0 (FUN_00627CA0, Moho::CUnitLoadUnitsTypeInfo::Delete)
   */
  void CUnitLoadUnitsTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitLoadUnits*>(objectStorage);
  }

  /**
   * Address: 0x00627D30 (FUN_00627D30, Moho::CUnitLoadUnitsTypeInfo::Destruct)
   */
  void CUnitLoadUnitsTypeInfo::Destruct(void* const objectStorage)
  {
    static_cast<CUnitLoadUnits*>(objectStorage)->~CUnitLoadUnits();
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00628C00 (FUN_00628C00, gpg::RRef_CUnitLoadUnits)
   */
  gpg::RRef* RRef_CUnitLoadUnits(gpg::RRef* const outRef, moho::CUnitLoadUnits* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RType* const staticType = CachedCUnitLoadUnitsType();
    outRef->mType = staticType;
    outRef->mObj = value;

    if (value == nullptr) {
      return outRef;
    }

    const std::type_info& dynamicTypeInfo = typeid(*value);
    if (dynamicTypeInfo == typeid(moho::CUnitLoadUnits)) {
      return outRef;
    }

    gpg::RType* const dynamicType = LookupCachedDerivedType(dynamicTypeInfo);
    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(isDerived);

    outRef->mType = dynamicType;
    outRef->mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(value) - baseOffset);
    return outRef;
  }

  /**
   * Address: 0x006282B0 (FUN_006282B0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitLoadUnits` and
   * copies object/type fields into the destination reference record.
   */
  [[maybe_unused]] gpg::RRef* AssignCUnitLoadUnitsRef(gpg::RRef* const outRef, moho::CUnitLoadUnits* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef tmp{};
    (void)RRef_CUnitLoadUnits(&tmp, value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }
} // namespace gpg
