#include "moho/ai/IAiAttackerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiAttacker.h"

using namespace moho;

namespace
{
  alignas(IAiAttackerTypeInfo) unsigned char gIAiAttackerTypeInfoStorage[sizeof(IAiAttackerTypeInfo)];
  bool gIAiAttackerTypeInfoConstructed = false;

  [[nodiscard]] IAiAttackerTypeInfo* AcquireIAiAttackerTypeInfo()
  {
    if (!gIAiAttackerTypeInfoConstructed) {
      new (gIAiAttackerTypeInfoStorage) IAiAttackerTypeInfo();
      gIAiAttackerTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiAttackerTypeInfo*>(gIAiAttackerTypeInfoStorage);
  }

  /**
   * Address: 0x005D5B10 (FUN_005D5B10)
   *
   * What it does:
   * Initializes the startup-owned `IAiAttackerTypeInfo` instance and
   * preregisters RTTI for `IAiAttacker`.
   */
  [[nodiscard]] gpg::RType* preregister_IAiAttackerTypeInfoStartup()
  {
    auto* const typeInfo = AcquireIAiAttackerTypeInfo();
    gpg::PreRegisterRType(typeid(IAiAttacker), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF8280 (FUN_00BF8280, sub_BF8280)
   *
   * What it does:
   * Tears down recovered static `IAiAttackerTypeInfo` storage.
   */
  void cleanup_IAiAttackerTypeInfo()
  {
    if (!gIAiAttackerTypeInfoConstructed) {
      return;
    }

    AcquireIAiAttackerTypeInfo()->~IAiAttackerTypeInfo();
    gIAiAttackerTypeInfoConstructed = false;
  }
} // namespace

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

/**
 * Address: 0x00BCE7B0 (FUN_00BCE7B0, sub_BCE7B0)
 *
 * What it does:
 * Registers `IAiAttacker` type-info object and installs process-exit cleanup.
 */
int moho::register_IAiAttackerTypeInfo()
{
  auto* const type = static_cast<IAiAttackerTypeInfo*>(preregister_IAiAttackerTypeInfoStartup());
  IAiAttacker::sType = type;
  return std::atexit(&cleanup_IAiAttackerTypeInfo);
}
