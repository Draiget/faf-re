#include "moho/unit/tasks/CUnitFerryTaskTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitFerryTask.h"

namespace
{
  using TypeInfo = moho::CUnitFerryTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  class CUnitFerryTaskReflectionView final : public moho::CCommandTask
  {
  public:
    moho::IAiCommandDispatchImpl* mDispatch; // +0x30
    std::int32_t mCommandIndex;              // +0x34
    bool mHasResolvedFerryTarget;            // +0x38
    std::uint8_t mPadding39[3];              // +0x39
    Wm3::Vector3f mPos;                      // +0x3C
    moho::WeakPtr<moho::Unit> mCommandUnit;  // +0x48
    moho::WeakPtr<moho::Unit> mFerryUnit;    // +0x50
    moho::WeakPtr<moho::Unit> mBeacon;       // +0x58

    CUnitFerryTaskReflectionView()
      : CCommandTask()
    {
      mDispatch = nullptr;
      mCommandIndex = 0;
      mHasResolvedFerryTarget = false;

      mCommandUnit.ownerLinkSlot = nullptr;
      mCommandUnit.nextInOwner = nullptr;
      mFerryUnit.ownerLinkSlot = nullptr;
      mFerryUnit.nextInOwner = nullptr;

      mPos.x = 0.0f;
      mPos.y = 0.0f;
      mPos.z = 0.0f;

      mBeacon.ownerLinkSlot = nullptr;
      mBeacon.nextInOwner = nullptr;
    }

    ~CUnitFerryTaskReflectionView() override
    {
      mBeacon.UnlinkFromOwnerChain();
      mFerryUnit.UnlinkFromOwnerChain();
      mCommandUnit.UnlinkFromOwnerChain();
    }

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitFerryTaskReflectionView) == sizeof(moho::CUnitFerryTask),
    "CUnitFerryTaskReflectionView size must match CUnitFerryTask"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mDispatch) == 0x30,
    "CUnitFerryTaskReflectionView::mDispatch offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mCommandIndex) == 0x34,
    "CUnitFerryTaskReflectionView::mCommandIndex offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mHasResolvedFerryTarget) == 0x38,
    "CUnitFerryTaskReflectionView::mHasResolvedFerryTarget offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mPos) == 0x3C,
    "CUnitFerryTaskReflectionView::mPos offset must be 0x3C"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mCommandUnit) == 0x48,
    "CUnitFerryTaskReflectionView::mCommandUnit offset must be 0x48"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mFerryUnit) == 0x50,
    "CUnitFerryTaskReflectionView::mFerryUnit offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitFerryTaskReflectionView, mBeacon) == 0x58,
    "CUnitFerryTaskReflectionView::mBeacon offset must be 0x58"
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

    AcquireTypeInfo().~CUnitFerryTaskTypeInfo();
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

  [[nodiscard]] gpg::RType* CachedCUnitFerryTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitFerryTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitFerryTaskRef(CUnitFerryTaskReflectionView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitFerryTask*>(object), CachedCUnitFerryTaskType()};
  }

  /**
   * Address: 0x0060FFB0 (FUN_0060FFB0)
   *
   * What it does:
   * Binds lifecycle callback lanes (`new/ctor/delete/destruct`) for one
   * `CUnitFerryTaskTypeInfo` descriptor.
   */
  [[maybe_unused]] gpg::RType* BindCUnitFerryTaskTypeLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
  {
    typeInfo->newRefFunc_ = &moho::CUnitFerryTaskTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &moho::CUnitFerryTaskTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &moho::CUnitFerryTaskTypeInfo::Delete;
    typeInfo->dtrFunc_ = &moho::CUnitFerryTaskTypeInfo::Destruct;
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060DB00 (FUN_0060DB00)
   */
  CUnitFerryTaskTypeInfo::CUnitFerryTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitFerryTask), this);
  }

  /**
   * Address: 0x0060DBB0 (FUN_0060DBB0, scalar deleting thunk)
   */
  CUnitFerryTaskTypeInfo::~CUnitFerryTaskTypeInfo() = default;

  /**
   * Address: 0x0060DBA0 (FUN_0060DBA0, Moho::CUnitFerryTaskTypeInfo::GetName)
   */
  const char* CUnitFerryTaskTypeInfo::GetName() const
  {
    return "CUnitFerryTask";
  }

  /**
   * Address: 0x0060DB60 (FUN_0060DB60, Moho::CUnitFerryTaskTypeInfo::Init)
   */
  void CUnitFerryTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitFerryTask);
    (void)BindCUnitFerryTaskTypeLifecycleCallbacks(this);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x006104B0 (FUN_006104B0, Moho::CUnitFerryTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitFerryTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x006101B0 (FUN_006101B0, Moho::CUnitFerryTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitFerryTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitFerryTaskReflectionView();
    return MakeCUnitFerryTaskRef(object);
  }

  /**
   * Address: 0x00610280 (FUN_00610280, Moho::CUnitFerryTaskTypeInfo::CtrRef)
   */
  gpg::RRef CUnitFerryTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitFerryTaskReflectionView*>(objectStorage);
    if (object) {
      new (object) CUnitFerryTaskReflectionView();
    }
    return MakeCUnitFerryTaskRef(object);
  }

  /**
   * Address: 0x00610260 (FUN_00610260, Moho::CUnitFerryTaskTypeInfo::Delete)
   */
  void CUnitFerryTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitFerryTaskReflectionView*>(objectStorage);
  }

  /**
   * Address: 0x00610330 (FUN_00610330, Moho::CUnitFerryTaskTypeInfo::Destruct)
   */
  void CUnitFerryTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitFerryTaskReflectionView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitFerryTaskReflectionView();
  }

  int register_CUnitFerryTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
