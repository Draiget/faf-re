#include "moho/unit/tasks/CUnitRefuelTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitRefuel.h"

namespace
{
  using TypeInfo = moho::CUnitRefuelTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitRefuelRuntimeView final : moho::CCommandTask
  {
    moho::WeakPtr<moho::Unit> mTargetUnit{}; // +0x30
    bool mHasTransportReservation = false;    // +0x38
    bool mIsCarrier = false;                  // +0x39
    std::uint8_t mPad3A[2] = {0, 0};          // +0x3A

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitRefuelRuntimeView) == sizeof(moho::CUnitRefuel),
    "CUnitRefuelRuntimeView size must match CUnitRefuel"
  );
  static_assert(
    offsetof(CUnitRefuelRuntimeView, mTargetUnit) == 0x30,
    "CUnitRefuelRuntimeView::mTargetUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitRefuelRuntimeView, mHasTransportReservation) == 0x38,
    "CUnitRefuelRuntimeView::mHasTransportReservation offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitRefuelRuntimeView, mIsCarrier) == 0x39,
    "CUnitRefuelRuntimeView::mIsCarrier offset must be 0x39"
  );

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
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

  [[nodiscard]] gpg::RType* CachedCUnitRefuelType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitRefuel));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitRefuelRef(moho::CUnitRefuel* const object)
  {
    return gpg::RRef{object, CachedCUnitRefuelType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00621270 (FUN_00621270, sub_621270)
   */
  CUnitRefuelTypeInfo::CUnitRefuelTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitRefuel), this);
  }

  /**
   * Address: 0x00621320 (FUN_00621320, Moho::CUnitRefuelTypeInfo::dtr)
   */
  CUnitRefuelTypeInfo::~CUnitRefuelTypeInfo() = default;

  /**
   * Address: 0x00621310 (FUN_00621310, Moho::CUnitRefuelTypeInfo::GetName)
   */
  const char* CUnitRefuelTypeInfo::GetName() const
  {
    return "CUnitRefuel";
  }

  /**
   * Address: 0x006212D0 (FUN_006212D0, Moho::CUnitRefuelTypeInfo::Init)
   */
  void CUnitRefuelTypeInfo::Init()
  {
    size_ = sizeof(CUnitRefuel);
    newRefFunc_ = &CUnitRefuelTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitRefuelTypeInfo::CtrRef;
    deleteFunc_ = &CUnitRefuelTypeInfo::Delete;
    dtrFunc_ = &CUnitRefuelTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00622400 (FUN_00622400, Moho::CUnitRefuelTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitRefuelTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x006222C0 (FUN_006222C0, Moho::CUnitRefuelTypeInfo::NewRef)
   */
  gpg::RRef CUnitRefuelTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitRefuelRuntimeView();
    return MakeCUnitRefuelRef(reinterpret_cast<CUnitRefuel*>(object));
  }

  /**
   * Address: 0x00622370 (FUN_00622370, Moho::CUnitRefuelTypeInfo::CtrRef)
   */
  gpg::RRef CUnitRefuelTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitRefuelRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitRefuelRuntimeView();
    }

    return MakeCUnitRefuelRef(reinterpret_cast<CUnitRefuel*>(object));
  }

  /**
   * Address: 0x00622350 (FUN_00622350, Moho::CUnitRefuelTypeInfo::Delete)
   */
  void CUnitRefuelTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitRefuelRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x006223F0 (FUN_006223F0, Moho::CUnitRefuelTypeInfo::Destruct)
   */
  void CUnitRefuelTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitRefuelRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitRefuelRuntimeView();
  }

  /**
   * Address: 0x00BFA360 (FUN_00BFA360)
   */
  void cleanup_CUnitRefuelTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitRefuelTypeInfo();
    gTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD1890 (FUN_00BD1890, sub_BD1890)
   */
  int register_CUnitRefuelTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitRefuelTypeInfo);
  }
} // namespace moho
