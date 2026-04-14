#include "moho/unit/tasks/CUnitCarrierRetrieveTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

namespace
{
  using TypeInfo = moho::CUnitCarrierRetrieveTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitCarrierRetrieveRuntimeView final : moho::CCommandTask
  {
    bool mRetrievalComplete = false;              // +0x30
    std::uint8_t mPad31_37[0x07] = {0, 0, 0, 0, 0, 0, 0}; // +0x31
    moho::SEntitySetTemplateUnit mTrackedUnits{}; // +0x38

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitCarrierRetrieveRuntimeView) == sizeof(moho::CUnitCarrierRetrieve),
    "CUnitCarrierRetrieveRuntimeView size must match CUnitCarrierRetrieve"
  );
  static_assert(
    offsetof(CUnitCarrierRetrieveRuntimeView, mRetrievalComplete) == offsetof(moho::CUnitCarrierRetrieve, mRetrievalComplete),
    "CUnitCarrierRetrieveRuntimeView::mRetrievalComplete offset must match CUnitCarrierRetrieve"
  );
  static_assert(
    offsetof(CUnitCarrierRetrieveRuntimeView, mTrackedUnits) == offsetof(moho::CUnitCarrierRetrieve, mTrackedUnits),
    "CUnitCarrierRetrieveRuntimeView::mTrackedUnits offset must match CUnitCarrierRetrieve"
  );

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitCarrierRetrieveTypeInfo();
    gTypeInfoConstructed = false;
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

  [[nodiscard]] gpg::RType* CachedCUnitCarrierRetrieveType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCarrierRetrieve));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCarrierRetrieveRef(CUnitCarrierRetrieveRuntimeView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitCarrierRetrieve*>(object), CachedCUnitCarrierRetrieveType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00606240 (FUN_00606240)
   */
  CUnitCarrierRetrieveTypeInfo::CUnitCarrierRetrieveTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCarrierRetrieve), this);
  }

  /**
   * Address: 0x006062F0 (FUN_006062F0, scalar deleting thunk)
   */
  CUnitCarrierRetrieveTypeInfo::~CUnitCarrierRetrieveTypeInfo() = default;

  /**
   * Address: 0x006062E0 (FUN_006062E0)
   */
  const char* CUnitCarrierRetrieveTypeInfo::GetName() const
  {
    return "CUnitCarrierRetrieve";
  }

  /**
   * Address: 0x006062A0 (FUN_006062A0)
   */
  void CUnitCarrierRetrieveTypeInfo::Init()
  {
    size_ = sizeof(CUnitCarrierRetrieve);
    newRefFunc_ = &CUnitCarrierRetrieveTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitCarrierRetrieveTypeInfo::CtrRef;
    deleteFunc_ = &CUnitCarrierRetrieveTypeInfo::Delete;
    dtrFunc_ = &CUnitCarrierRetrieveTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00607E20 (FUN_00607E20, Moho::CUnitCarrierRetrieveTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitCarrierRetrieveTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCCommandTaskType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006079E0 (FUN_006079E0, Moho::CUnitCarrierRetrieveTypeInfo::NewRef)
   */
  gpg::RRef CUnitCarrierRetrieveTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitCarrierRetrieveRuntimeView();
    return MakeCUnitCarrierRetrieveRef(object);
  }

  /**
   * Address: 0x00607AA0 (FUN_00607AA0, Moho::CUnitCarrierRetrieveTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one carrier-retrieve task runtime lane in caller
   * storage and returns typed reflection reference.
   */
  gpg::RRef CUnitCarrierRetrieveTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitCarrierRetrieveRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitCarrierRetrieveRuntimeView();
    }
    return MakeCUnitCarrierRetrieveRef(object);
  }

  /**
   * Address: 0x00607A80 (FUN_00607A80, Moho::CUnitCarrierRetrieveTypeInfo::Delete)
   */
  void CUnitCarrierRetrieveTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCarrierRetrieveRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x00607B40 (FUN_00607B40, Moho::CUnitCarrierRetrieveTypeInfo::Destruct)
   */
  void CUnitCarrierRetrieveTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitCarrierRetrieveRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitCarrierRetrieveRuntimeView();
  }

  int register_CUnitCarrierRetrieveTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
