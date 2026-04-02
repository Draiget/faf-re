#include "moho/ai/IAiAttacker.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/ai/EAiAttackerEventTypeInfo.h"
#include "moho/ai/IAiAttackerSerializer.h"
#include "moho/ai/IAiAttackerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/Listener.h"
#include "moho/unit/core/UnitWeapon.h"

using namespace moho;

gpg::RType* Broadcaster_EAiAttackerEvent::sType = nullptr;
gpg::RType* IAiAttacker::sType = nullptr;

namespace moho
{
  class RBroadcasterRType_EAiAttackerEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Broadcaster<EAiAttackerEvent>";
    }

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      Finish();
    }
  };

  class RListenerRType_EAiAttackerEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Listener<EAiAttackerEvent>";
    }

    void Init() override
    {
      size_ = sizeof(Listener<EAiAttackerEvent>);
      Finish();
    }
  };
} // namespace moho

namespace gpg
{
  class RVectorType_UnitWeaponPtr final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_CAcquireTargetTaskPtr final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };
} // namespace gpg

namespace
{
  using BroadcasterAttackerType = moho::RBroadcasterRType_EAiAttackerEvent;
  using ListenerAttackerType = moho::RListenerRType_EAiAttackerEvent;
  using UnitWeaponPtrVectorType = gpg::RVectorType_UnitWeaponPtr;
  using CAcquireTargetTaskPtrVectorType = gpg::RVectorType_CAcquireTargetTaskPtr;

  using UnitWeaponPtrVector = msvc8::vector<moho::UnitWeapon*>;
  using CAcquireTargetTaskPtrVector = msvc8::vector<moho::CAcquireTargetTask*>;

  alignas(BroadcasterAttackerType) unsigned char gBroadcasterAttackerTypeStorage[sizeof(BroadcasterAttackerType)];
  bool gBroadcasterAttackerTypeConstructed = false;

  alignas(ListenerAttackerType) unsigned char gListenerAttackerTypeStorage[sizeof(ListenerAttackerType)];
  bool gListenerAttackerTypeConstructed = false;

  alignas(UnitWeaponPtrVectorType) unsigned char gUnitWeaponPtrVectorTypeStorage[sizeof(UnitWeaponPtrVectorType)];
  bool gUnitWeaponPtrVectorTypeConstructed = false;

  alignas(CAcquireTargetTaskPtrVectorType)
    unsigned char gCAcquireTargetTaskPtrVectorTypeStorage[sizeof(CAcquireTargetTaskPtrVectorType)];
  bool gCAcquireTargetTaskPtrVectorTypeConstructed = false;

  [[nodiscard]] BroadcasterAttackerType* AcquireBroadcasterAttackerType()
  {
    if (!gBroadcasterAttackerTypeConstructed) {
      new (gBroadcasterAttackerTypeStorage) BroadcasterAttackerType();
      gBroadcasterAttackerTypeConstructed = true;
    }

    return reinterpret_cast<BroadcasterAttackerType*>(gBroadcasterAttackerTypeStorage);
  }

  [[nodiscard]] ListenerAttackerType* AcquireListenerAttackerType()
  {
    if (!gListenerAttackerTypeConstructed) {
      new (gListenerAttackerTypeStorage) ListenerAttackerType();
      gListenerAttackerTypeConstructed = true;
    }

    return reinterpret_cast<ListenerAttackerType*>(gListenerAttackerTypeStorage);
  }

  [[nodiscard]] UnitWeaponPtrVectorType* AcquireUnitWeaponPtrVectorType()
  {
    if (!gUnitWeaponPtrVectorTypeConstructed) {
      new (gUnitWeaponPtrVectorTypeStorage) UnitWeaponPtrVectorType();
      gUnitWeaponPtrVectorTypeConstructed = true;
    }

    return reinterpret_cast<UnitWeaponPtrVectorType*>(gUnitWeaponPtrVectorTypeStorage);
  }

  [[nodiscard]] CAcquireTargetTaskPtrVectorType* AcquireCAcquireTargetTaskPtrVectorType()
  {
    if (!gCAcquireTargetTaskPtrVectorTypeConstructed) {
      new (gCAcquireTargetTaskPtrVectorTypeStorage) CAcquireTargetTaskPtrVectorType();
      gCAcquireTargetTaskPtrVectorTypeConstructed = true;
    }

    return reinterpret_cast<CAcquireTargetTaskPtrVectorType*>(gCAcquireTargetTaskPtrVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveUnitWeaponPtrType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::UnitWeapon*));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("UnitWeapon *");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveCAcquireTargetTaskPtrType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAcquireTargetTask*));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("CAcquireTargetTask *");
      }
    }
    return cached;
  }

  template <class TVector>
  [[nodiscard]] msvc8::string MakeVectorLexical(const gpg::RType* const ownerType, const gpg::RRef& ref, const TVector* vec)
  {
    const msvc8::string base = ownerType != nullptr ? ownerType->GetLexical(ref) : msvc8::string("vector");
    const int size = vec ? static_cast<int>(vec->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
  }

  void cleanup_RBroadcasterRType_EAiAttackerEvent()
  {
    if (!gBroadcasterAttackerTypeConstructed) {
      return;
    }

    AcquireBroadcasterAttackerType()->~BroadcasterAttackerType();
    gBroadcasterAttackerTypeConstructed = false;
  }

  void cleanup_RListenerRType_EAiAttackerEvent()
  {
    if (!gListenerAttackerTypeConstructed) {
      return;
    }

    AcquireListenerAttackerType()->~ListenerAttackerType();
    gListenerAttackerTypeConstructed = false;
  }

  void cleanup_RVectorType_UnitWeaponPtr()
  {
    if (!gUnitWeaponPtrVectorTypeConstructed) {
      return;
    }

    AcquireUnitWeaponPtrVectorType()->~UnitWeaponPtrVectorType();
    gUnitWeaponPtrVectorTypeConstructed = false;
  }

  void cleanup_RVectorType_CAcquireTargetTaskPtr()
  {
    if (!gCAcquireTargetTaskPtrVectorTypeConstructed) {
      return;
    }

    AcquireCAcquireTargetTaskPtrVectorType()->~CAcquireTargetTaskPtrVectorType();
    gCAcquireTargetTaskPtrVectorTypeConstructed = false;
  }
} // namespace

const char* gpg::RVectorType_UnitWeaponPtr::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveUnitWeaponPtrType();
    const char* const elementName = elementType ? elementType->GetName() : "UnitWeapon *";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "UnitWeapon *");
  }
  return sName.c_str();
}

msvc8::string gpg::RVectorType_UnitWeaponPtr::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const UnitWeaponPtrVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_UnitWeaponPtr::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_UnitWeaponPtr::Init()
{
  size_ = sizeof(UnitWeaponPtrVector);
  version_ = 1;
}

gpg::RRef gpg::RVectorType_UnitWeaponPtr::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<UnitWeaponPtrVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveUnitWeaponPtrType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_UnitWeaponPtr::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const UnitWeaponPtrVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_UnitWeaponPtr::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<UnitWeaponPtrVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), nullptr);
}

const char* gpg::RVectorType_CAcquireTargetTaskPtr::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveCAcquireTargetTaskPtrType();
    const char* const elementName = elementType ? elementType->GetName() : "CAcquireTargetTask *";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "CAcquireTargetTask *");
  }
  return sName.c_str();
}

msvc8::string gpg::RVectorType_CAcquireTargetTaskPtr::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const CAcquireTargetTaskPtrVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_CAcquireTargetTaskPtr::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_CAcquireTargetTaskPtr::Init()
{
  size_ = sizeof(CAcquireTargetTaskPtrVector);
  version_ = 1;
}

gpg::RRef gpg::RVectorType_CAcquireTargetTaskPtr::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<CAcquireTargetTaskPtrVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveCAcquireTargetTaskPtrType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_CAcquireTargetTaskPtr::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const CAcquireTargetTaskPtrVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_CAcquireTargetTaskPtr::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<CAcquireTargetTaskPtrVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), nullptr);
}

/**
 * Address: 0x005D5780 (FUN_005D5780)
 */
IAiAttacker::~IAiAttacker()
{
  Broadcaster* const link = static_cast<Broadcaster*>(&mListeners);
  link->mPrev->mNext = link->mNext;
  link->mNext->mPrev = link->mPrev;
  link->mNext = link;
  link->mPrev = link;
}

/**
 * Address: 0x00BCEAA0 (FUN_00BCEAA0, sub_BCEAA0)
 *
 * What it does:
 * Registers the broadcaster reflection lane for `EAiAttackerEvent` and
 * installs process-exit cleanup.
 */
int moho::register_RBroadcasterRType_EAiAttackerEvent()
{
  auto* const type = AcquireBroadcasterAttackerType();
  gpg::PreRegisterRType(typeid(moho::Broadcaster_EAiAttackerEvent), type);
  return std::atexit(&cleanup_RBroadcasterRType_EAiAttackerEvent);
}

/**
 * Address: 0x00BCEAC0 (FUN_00BCEAC0, register_RListenerRType_EAiAttackerEvent)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiAttackerEvent` and installs
 * process-exit cleanup.
 */
int moho::register_RListenerRType_EAiAttackerEvent()
{
  auto* const type = AcquireListenerAttackerType();
  gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiAttackerEvent>), type);
  return std::atexit(&cleanup_RListenerRType_EAiAttackerEvent);
}

/**
 * Address: 0x00BCEAE0 (FUN_00BCEAE0, sub_BCEAE0)
 *
 * What it does:
 * Registers `msvc8::vector<UnitWeapon*>` reflection metadata and installs
 * process-exit cleanup.
 */
int moho::register_RVectorType_UnitWeaponPtr()
{
  auto* const type = AcquireUnitWeaponPtrVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::UnitWeapon*>), type);
  return std::atexit(&cleanup_RVectorType_UnitWeaponPtr);
}

/**
 * Address: 0x00BCEB00 (FUN_00BCEB00, sub_BCEB00)
 *
 * What it does:
 * Registers `msvc8::vector<CAcquireTargetTask*>` reflection metadata and
 * installs process-exit cleanup.
 */
int moho::register_RVectorType_CAcquireTargetTaskPtr()
{
  auto* const type = AcquireCAcquireTargetTaskPtrVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::CAcquireTargetTask*>), type);
  return std::atexit(&cleanup_RVectorType_CAcquireTargetTaskPtr);
}

namespace
{
  struct IAiAttackerReflectionBootstrap
  {
    IAiAttackerReflectionBootstrap()
    {
      (void)moho::register_EAiAttackerEventTypeInfo();
      (void)moho::register_EAiAttackerEventPrimitiveSerializer();
      (void)moho::register_IAiAttackerTypeInfo();
      (void)moho::register_IAiAttackerSerializer();
      (void)moho::register_RBroadcasterRType_EAiAttackerEvent();
      (void)moho::register_RListenerRType_EAiAttackerEvent();
      (void)moho::register_RVectorType_UnitWeaponPtr();
      (void)moho::register_RVectorType_CAcquireTargetTaskPtr();
    }
  };

  [[maybe_unused]] IAiAttackerReflectionBootstrap gIAiAttackerReflectionBootstrap;
} // namespace
