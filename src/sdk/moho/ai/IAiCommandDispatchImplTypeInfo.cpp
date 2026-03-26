#include "moho/ai/IAiCommandDispatchImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

using namespace moho;

namespace
{
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

