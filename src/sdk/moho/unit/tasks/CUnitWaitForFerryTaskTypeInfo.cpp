#include "moho/unit/tasks/CUnitWaitForFerryTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

namespace
{
  using TypeInfo = moho::CUnitWaitForFerryTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitWaitForFerryTaskRuntimeView final : moho::CCommandTask
  {
    std::uint32_t mUnknownWord0 = 0;  // +0x30
    std::uint32_t mUnknownWord1 = 0;  // +0x34
    std::uint32_t mUnknownWord2 = 0;  // +0x38
    std::uint32_t mUnknownWord3 = 0;  // +0x3C
    std::uint32_t mUnknownWord4 = 0;  // +0x40
    std::uint32_t mUnknownWord5 = 0;  // +0x44
    std::uint32_t mUnknownWord6 = 0;  // +0x48
    std::uint32_t mUnknownWord7 = 0;  // +0x4C
    std::uint32_t mUnknownWord8 = 0;  // +0x50
    std::uint32_t mUnknownWord9 = 0;  // +0x54
    std::uint32_t mUnknownWord10 = 0; // +0x58
    std::uint32_t mUnknownWord11 = 0; // +0x5C

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitWaitForFerryTaskRuntimeView) == sizeof(moho::CUnitWaitForFerryTask),
    "CUnitWaitForFerryTaskRuntimeView size must match CUnitWaitForFerryTask"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTaskRuntimeView, mUnknownWord0) == 0x30,
    "CUnitWaitForFerryTaskRuntimeView::mUnknownWord0 offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTaskRuntimeView, mUnknownWord11) == 0x5C,
    "CUnitWaitForFerryTaskRuntimeView::mUnknownWord11 offset must be 0x5C"
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

    AcquireTypeInfo().~CUnitWaitForFerryTaskTypeInfo();
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

  [[nodiscard]] gpg::RType* CachedCUnitWaitForFerryTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitWaitForFerryTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitWaitForFerryTaskRef(CUnitWaitForFerryTaskRuntimeView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitWaitForFerryTask*>(object), CachedCUnitWaitForFerryTaskType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060F830 (FUN_0060F830)
   */
  CUnitWaitForFerryTaskTypeInfo::CUnitWaitForFerryTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitWaitForFerryTask), this);
  }

  /**
   * Address: 0x0060F8E0 (FUN_0060F8E0, scalar deleting thunk)
   */
  CUnitWaitForFerryTaskTypeInfo::~CUnitWaitForFerryTaskTypeInfo() = default;

  /**
   * Address: 0x0060F8D0 (FUN_0060F8D0)
   */
  const char* CUnitWaitForFerryTaskTypeInfo::GetName() const
  {
    return "CUnitWaitForFerryTask";
  }

  /**
   * Address: 0x0060F890 (FUN_0060F890)
   */
  void CUnitWaitForFerryTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitWaitForFerryTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitWaitForFerryTaskTypeInfo::NewRef,
      &CUnitWaitForFerryTaskTypeInfo::CtrRef,
      &CUnitWaitForFerryTaskTypeInfo::Delete,
      &CUnitWaitForFerryTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00610530 (FUN_00610530, Moho::CUnitWaitForFerryTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitWaitForFerryTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00610340 (FUN_00610340, Moho::CUnitWaitForFerryTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitWaitForFerryTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitWaitForFerryTaskRuntimeView();
    return MakeCUnitWaitForFerryTaskRef(object);
  }

  /**
   * Address: 0x00610400 (FUN_00610400, Moho::CUnitWaitForFerryTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one wait-for-ferry task runtime lane in caller
   * storage and returns typed reflection reference.
   */
  gpg::RRef CUnitWaitForFerryTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitWaitForFerryTaskRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitWaitForFerryTaskRuntimeView();
    }
    return MakeCUnitWaitForFerryTaskRef(object);
  }

  /**
   * Address: 0x006103E0 (FUN_006103E0, Moho::CUnitWaitForFerryTaskTypeInfo::Delete)
   */
  void CUnitWaitForFerryTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitWaitForFerryTaskRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x006104A0 (FUN_006104A0, Moho::CUnitWaitForFerryTaskTypeInfo::Destruct)
   */
  void CUnitWaitForFerryTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitWaitForFerryTaskRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitWaitForFerryTaskRuntimeView();
  }

  int register_CUnitWaitForFerryTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho

