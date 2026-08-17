#include "moho/ai/IAiTransportTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"
#include "moho/unit/Broadcaster.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(IAiTransportTypeInfo) unsigned char gIAiTransportTypeInfoStorage[sizeof(IAiTransportTypeInfo)];
  bool gIAiTransportTypeInfoConstructed = false;

  [[nodiscard]] IAiTransportTypeInfo* AcquireIAiTransportTypeInfo()
  {
    if (!gIAiTransportTypeInfoConstructed) {
      new (gIAiTransportTypeInfoStorage) IAiTransportTypeInfo();
      gIAiTransportTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiTransportTypeInfo*>(gIAiTransportTypeInfoStorage);
  }

  void cleanup_IAiTransportTypeInfo()
  {
    if (!gIAiTransportTypeInfoConstructed) {
      return;
    }

    AcquireIAiTransportTypeInfo()->~IAiTransportTypeInfo();
    gIAiTransportTypeInfoConstructed = false;
  }

  /**
   * Address: 0x005EBC20 (FUN_005EBC20,
   *   ?AddBase_Broadcaster_EAiTransportEvent@IAiTransportTypeInfo@Moho@@SGXPAVRType@gpg@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::IAiTransportTypeInfo::AddBase_Broadcaster_EAiTransportEvent(
   *     gpg::RType* typeInfo);
   *
   * What it does:
   * Registers `Broadcaster<EAiTransportEvent>` as the base at offset 4 - the
   * listener-link subobject inside `IAiTransport`. The descriptor is cached on
   * the instantiation's own static, which is what the rest of the broadcaster
   * reflection paths read; a function-local cache leaves those reading null.
   */
  void AddBaseBroadcasterToIAiTransportTypeInfo(gpg::RType* const typeInfo)
  {
    using BroadcasterEvent = BroadcasterEventTag<EAiTransportEvent>;
    if (BroadcasterEvent::sType == nullptr) {
      BroadcasterEvent::sType = gpg::LookupRType(typeid(Broadcaster));
    }

    gpg::RType* const baseType = BroadcasterEvent::sType;
    if (baseType == nullptr) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 4;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x005E4740 (FUN_005E4740, ??0IAiTransportTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `IAiTransport` RTTI so lookup resolves to this type helper.
 */
IAiTransportTypeInfo::IAiTransportTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(IAiTransport), this);
}

/**
 * Address: 0x005E47D0 (FUN_005E47D0, scalar deleting thunk)
 */
IAiTransportTypeInfo::~IAiTransportTypeInfo() = default;

/**
 * Address: 0x005E47C0 (FUN_005E47C0, ?GetName@IAiTransportTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiTransportTypeInfo::GetName() const
{
  return "IAiTransport";
}

/**
 * Address: 0x005E47A0 (FUN_005E47A0, ?Init@IAiTransportTypeInfo@Moho@@UAEXXZ)
 */
void IAiTransportTypeInfo::Init()
{
  size_ = sizeof(IAiTransport);
  gpg::RType::Init();

  AddBaseBroadcasterToIAiTransportTypeInfo(this);

  Finish();
}

/**
 * Address: 0x00BCEE90 (FUN_00BCEE90, register_IAiTransportTypeInfo)
 *
 * What it does:
 * Registers `IAiTransport` type-info object and installs process-exit
 * cleanup.
 */
int moho::register_IAiTransportTypeInfo()
{
  (void)AcquireIAiTransportTypeInfo();
  return std::atexit(&cleanup_IAiTransportTypeInfo);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiTransportTypeInfo_a7ca8a, moho::register_IAiTransportTypeInfo)
