#include "moho/ai/IAiAttackerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiAttacker.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  AddBase_Broadcaster_EAiAttackerEvent(this);

  Finish();
}

/**
 * Address: 0x005DE870 (FUN_005DE870,
 *   Moho::IAiAttackerTypeInfo::AddBase_Broadcaster_EAiAttackerEvent)
 *
 * IDA signature:
 * void __stdcall Moho::IAiAttackerTypeInfo::AddBase_Broadcaster_EAiAttackerEvent(
 *     gpg::RType *a1);
 *
 * What it does:
 * Resolves and caches the `Broadcaster<EAiAttackerEvent>` reflected type,
 * then adds it as a base field of `typeInfo` at the subobject's offset.
 * Unlike the offset-0 AddBase helpers this base lives at +4 inside
 * `IAiAttacker`, which the emission spells as `a2.mOffset = 4`.
 */
void IAiAttackerTypeInfo::AddBase_Broadcaster_EAiAttackerEvent(gpg::RType* const typeInfo)
{
  gpg::RType* baseType = Broadcaster_EAiAttackerEvent::sType;
  if (!baseType) {
    baseType = gpg::LookupRType(typeid(Broadcaster_EAiAttackerEvent));
    Broadcaster_EAiAttackerEvent::sType = baseType;
  }

  if (typeInfo == nullptr || baseType == nullptr) {
    return;
  }

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = offsetof(IAiAttacker, mListeners);
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiAttackerTypeInfo_d7aa45, moho::register_IAiAttackerTypeInfo)

GPG_PREREGISTER_INIT(preregister_IAiAttackerTypeInfoStartup_d7aa45, preregister_IAiAttackerTypeInfoStartup)
