#include "moho/ai/IAiCommandDispatchImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

using namespace moho;

namespace
{
  alignas(IAiCommandDispatchImplTypeInfo)
  unsigned char gIAiCommandDispatchImplTypeInfoStorage[sizeof(IAiCommandDispatchImplTypeInfo)] = {};
  bool gIAiCommandDispatchImplTypeInfoConstructed = false;

  [[nodiscard]] IAiCommandDispatchImplTypeInfo* AcquireIAiCommandDispatchImplTypeInfo()
  {
    return reinterpret_cast<IAiCommandDispatchImplTypeInfo*>(gIAiCommandDispatchImplTypeInfoStorage);
  }

  /**
   * Address: 0x00599130 (FUN_00599130, constructor lane for IAiCommandDispatchImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `IAiCommandDispatchImplTypeInfo` storage and
   * preregisters RTTI for `IAiCommandDispatchImpl`.
   */
  [[nodiscard]] gpg::RType* construct_IAiCommandDispatchImplTypeInfo()
  {
    if (!gIAiCommandDispatchImplTypeInfoConstructed) {
      IAiCommandDispatchImplTypeInfo* const typeInfo =
        new (gIAiCommandDispatchImplTypeInfoStorage) IAiCommandDispatchImplTypeInfo();
      gpg::PreRegisterRType(typeid(IAiCommandDispatchImpl), typeInfo);
      gIAiCommandDispatchImplTypeInfoConstructed = true;
    }

    return AcquireIAiCommandDispatchImplTypeInfo();
  }

  /**
   * Address: 0x00BF6660 (FUN_00BF6660, cleanup_IAiCommandDispatchImplTypeInfo)
   *
   * What it does:
   * Tears down startup-owned IAiCommandDispatchImpl type-info storage by
   * running the `gpg::RType` destructor lane.
   */
  void cleanup_IAiCommandDispatchImplTypeInfoStorage()
  {
    if (!gIAiCommandDispatchImplTypeInfoConstructed) {
      return;
    }

    AcquireIAiCommandDispatchImplTypeInfo()->gpg::RType::~RType();
    gIAiCommandDispatchImplTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchType()
  {
    gpg::RType* type = IAiCommandDispatch::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatch));
      IAiCommandDispatch::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedQueueStatusListenerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Listener<EUnitCommandQueueStatus>));
    }
    return type;
  }

  void AddBaseIfPresent(gpg::RType* const typeInfo, gpg::RType* const baseType, const std::int32_t offset)
  {
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = offset;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x005991D0 (FUN_005991D0, scalar deleting thunk)
 */
IAiCommandDispatchImplTypeInfo::~IAiCommandDispatchImplTypeInfo() = default;

/**
 * Address: 0x005991C0 (FUN_005991C0, ?GetName@IAiCommandDispatchImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiCommandDispatchImplTypeInfo::GetName() const
{
  return "IAiCommandDispatchImpl";
}

/**
 * Address: 0x00599190 (FUN_00599190, ?Init@IAiCommandDispatchImplTypeInfo@Moho@@UAEXXZ)
 */
void IAiCommandDispatchImplTypeInfo::Init()
{
  size_ = sizeof(IAiCommandDispatchImpl);
  gpg::RType::Init();

  AddBaseIfPresent(this, CachedCCommandTaskType(), 0x00);
  AddBaseIfPresent(this, CachedIAiCommandDispatchType(), 0x30);
  AddBaseIfPresent(this, CachedQueueStatusListenerType(), 0x34);

  Finish();
}

/**
 * Address: 0x00BCBEA0 (FUN_00BCBEA0, register_IAiCommandDispatchImplTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI storage for
 * `IAiCommandDispatchImpl` and installs process-exit cleanup.
 */
int moho::register_IAiCommandDispatchImplTypeInfo()
{
  (void)construct_IAiCommandDispatchImplTypeInfo();
  return std::atexit(&cleanup_IAiCommandDispatchImplTypeInfoStorage);
}

namespace
{
  struct IAiCommandDispatchImplTypeInfoBootstrap
  {
    IAiCommandDispatchImplTypeInfoBootstrap()
    {
      (void)moho::register_IAiCommandDispatchImplTypeInfo();
    }
  };

  [[maybe_unused]] IAiCommandDispatchImplTypeInfoBootstrap gIAiCommandDispatchImplTypeInfoBootstrap;
} // namespace
