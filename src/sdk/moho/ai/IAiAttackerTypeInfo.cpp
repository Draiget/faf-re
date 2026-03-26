#include "moho/ai/IAiAttackerTypeInfo.h"

#include <typeinfo>

#include "moho/ai/IAiAttacker.h"

using namespace moho;

/**
 * Address: 0x005D5BA0 (FUN_005D5BA0, scalar deleting thunk)
 */
IAiAttackerTypeInfo::~IAiAttackerTypeInfo() = default;

/**
 * Address: 0x005D5B90 (FUN_005D5B90, ?GetName@IAiAttackerTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiAttackerTypeInfo::GetName() const
{
  return "IAiAttacker";
}

/**
 * Address: 0x005D5B70 (FUN_005D5B70, ?Init@IAiAttackerTypeInfo@Moho@@UAEXXZ)
 */
void IAiAttackerTypeInfo::Init()
{
  size_ = sizeof(IAiAttacker);
  gpg::RType::Init();

  gpg::RType* baseType = Broadcaster_EAiAttackerEvent::sType;
  if (!baseType) {
    baseType = gpg::LookupRType(typeid(Broadcaster_EAiAttackerEvent));
    Broadcaster_EAiAttackerEvent::sType = baseType;
  }

  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = offsetof(IAiAttacker, mListeners);
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
}
