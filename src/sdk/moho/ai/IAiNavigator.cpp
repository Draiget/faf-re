#include "moho/ai/IAiNavigator.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiNavigatorAir.h"
#include "moho/ai/CAiNavigatorLand.h"
#include "moho/misc/Listener.h"

using namespace moho;

namespace moho
{
  class RBroadcasterRType_EAiNavigatorEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      Finish();
    }
  };

  class RListenerRType_EAiNavigatorEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Listener<EAiNavigatorEvent>);
      Finish();
    }
  };
} // namespace moho

namespace
{
  using BroadcasterNavigatorType = moho::RBroadcasterRType_EAiNavigatorEvent;
  using ListenerNavigatorType = moho::RListenerRType_EAiNavigatorEvent;

  struct CachedTypeName
  {
    msvc8::string value;
    bool initialized = false;
  };

  alignas(BroadcasterNavigatorType) unsigned char gBroadcasterNavigatorTypeStorage[sizeof(BroadcasterNavigatorType)];
  bool gBroadcasterNavigatorTypeConstructed = false;

  alignas(ListenerNavigatorType) unsigned char gListenerNavigatorTypeStorage[sizeof(ListenerNavigatorType)];
  bool gListenerNavigatorTypeConstructed = false;

  [[nodiscard]] BroadcasterNavigatorType* AcquireBroadcasterNavigatorType()
  {
    if (!gBroadcasterNavigatorTypeConstructed) {
      new (gBroadcasterNavigatorTypeStorage) BroadcasterNavigatorType();
      gBroadcasterNavigatorTypeConstructed = true;
    }

    return reinterpret_cast<BroadcasterNavigatorType*>(gBroadcasterNavigatorTypeStorage);
  }

  [[nodiscard]] ListenerNavigatorType* AcquireListenerNavigatorType()
  {
    if (!gListenerNavigatorTypeConstructed) {
      new (gListenerNavigatorTypeStorage) ListenerNavigatorType();
      gListenerNavigatorTypeConstructed = true;
    }

    return reinterpret_cast<ListenerNavigatorType*>(gListenerNavigatorTypeStorage);
  }

  void cleanup_RBroadcasterRType_EAiNavigatorEvent()
  {
    if (!gBroadcasterNavigatorTypeConstructed) {
      return;
    }

    AcquireBroadcasterNavigatorType()->~BroadcasterNavigatorType();
    gBroadcasterNavigatorTypeConstructed = false;
  }

  void cleanup_RListenerRType_EAiNavigatorEvent()
  {
    if (!gListenerNavigatorTypeConstructed) {
      return;
    }

    AcquireListenerNavigatorType()->~ListenerNavigatorType();
    gListenerNavigatorTypeConstructed = false;
  }

  [[nodiscard]] gpg::RType* ResolveEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiNavigatorEvent));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("EAiNavigatorEvent");
      }
    }
    return cached;
  }

  [[nodiscard]] CachedTypeName& CachedBroadcasterEAiNavigatorEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedListenerEAiNavigatorEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  void cleanup_RBroadcasterRType_EAiNavigatorEvent_GetName()
  {
    CachedTypeName& cache = CachedBroadcasterEAiNavigatorEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RListenerRType_EAiNavigatorEvent_GetName()
  {
    CachedTypeName& cache = CachedListenerEAiNavigatorEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  [[nodiscard]] gpg::RType* CachedBroadcasterEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(BroadcasterEventTag<EAiNavigatorEvent>));
    }
    return cached;
  }
} // namespace

/**
 * Address: 0x005A7000 (FUN_005A7000, Moho::RBroadcasterRType_EAiNavigatorEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Broadcaster<EAiNavigatorEvent>`
 * using the currently registered enum reflection type name.
 */
const char* moho::RBroadcasterRType_EAiNavigatorEvent::GetName() const
{
  CachedTypeName& cache = CachedBroadcasterEAiNavigatorEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiNavigatorEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiNavigatorEvent";
    cache.value = gpg::STR_Printf("Broadcaster<%s>", eventTypeName ? eventTypeName : "EAiNavigatorEvent");
    (void)std::atexit(&cleanup_RBroadcasterRType_EAiNavigatorEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005A70C0 (FUN_005A70C0, Moho::RListenerRType_EAiNavigatorEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Listener<EAiNavigatorEvent>`
 * using the currently registered enum reflection type name.
 */
const char* moho::RListenerRType_EAiNavigatorEvent::GetName() const
{
  CachedTypeName& cache = CachedListenerEAiNavigatorEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiNavigatorEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiNavigatorEvent";
    cache.value = gpg::STR_Printf("Listener<%s>", eventTypeName ? eventTypeName : "EAiNavigatorEvent");
    (void)std::atexit(&cleanup_RListenerRType_EAiNavigatorEvent_GetName);
  }
  return cache.value.c_str();
}

std::size_t SNavPath::Count() const noexcept
{
  if (!start || !finish || finish < start) {
    return 0;
  }
  return static_cast<std::size_t>(finish - start);
}

std::int32_t SNavPath::CountInt() const noexcept
{
  return static_cast<std::int32_t>(Count());
}

std::size_t SNavPath::CapacityCount() const noexcept
{
  if (!start || !capacity || capacity < start) {
    return 0;
  }
  return static_cast<std::size_t>(capacity - start);
}

void SNavPath::ClearContent() noexcept
{
  if (start) {
    finish = start;
  }
}

void SNavPath::FreeStorage() noexcept
{
  if (start) {
    ::operator delete(start);
  }
  reserved0 = 0;
  start = nullptr;
  finish = nullptr;
  capacity = nullptr;
}

void SNavPath::EnsureCapacity(const std::size_t requiredCount)
{
  const std::size_t currentCapacity = CapacityCount();
  if (currentCapacity >= requiredCount) {
    return;
  }

  const std::size_t currentSize = Count();
  const std::size_t newCapacity = std::max(requiredCount, std::max<std::size_t>(4, currentCapacity * 2));
  auto* const storage = static_cast<SOCellPos*>(::operator new(sizeof(SOCellPos) * newCapacity));

  if (start && currentSize > 0) {
    std::memcpy(storage, start, sizeof(SOCellPos) * currentSize);
  }

  if (start) {
    ::operator delete(start);
  }

  start = storage;
  finish = storage + currentSize;
  capacity = storage + newCapacity;
}

void SNavPath::AssignCopy(const SNavPath& src)
{
  const std::size_t count = src.Count();
  if (count == 0) {
    ClearContent();
    return;
  }

  EnsureCapacity(count);
  std::memcpy(start, src.start, sizeof(SOCellPos) * count);
  finish = start + count;
}

void SNavPath::AppendCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::size_t appendCount = static_cast<std::size_t>(end - begin);
  const std::size_t currentCount = Count();
  EnsureCapacity(currentCount + appendCount);

  std::memcpy(start + currentCount, begin, sizeof(SOCellPos) * appendCount);
  finish = start + currentCount + appendCount;
}

void SNavPath::PrependCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::size_t prependCount = static_cast<std::size_t>(end - begin);
  const std::size_t currentCount = Count();
  EnsureCapacity(currentCount + prependCount);

  if (currentCount > 0) {
    std::memmove(start + prependCount, start, sizeof(SOCellPos) * currentCount);
  }
  std::memcpy(start, begin, sizeof(SOCellPos) * prependCount);
  finish = start + currentCount + prependCount;
}

void SNavPath::AppendCell(const SOCellPos& cell)
{
  AppendCells(&cell, &cell + 1);
}

void SNavPath::EraseFrontCell() noexcept
{
  const std::size_t count = Count();
  if (count == 0) {
    return;
  }

  if (count == 1) {
    finish = start;
    return;
  }

  std::memmove(start, start + 1, sizeof(SOCellPos) * (count - 1));
  --finish;
}

void SNavPath::EraseFrontCells(std::int32_t count) noexcept
{
  while (count > 0 && CountInt() > 0) {
    EraseFrontCell();
    --count;
  }
}

gpg::RType* IAiNavigator::sType = nullptr;

/**
 * Address: 0x005A5790 (FUN_005A5790, ?AI_CreatePathingNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiNavigatorLand` instance bound to `unit` and returns it as
 * the `IAiNavigator` interface pointer.
 */
IAiNavigator* moho::AI_CreatePathingNavigator(Unit* const unit)
{
  auto* const navigator = new (std::nothrow) CAiNavigatorLand(unit);
  return navigator;
}

/**
 * Address: 0x005A5800 (FUN_005A5800, ?AI_CreateAirNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiNavigatorAir` instance bound to `unit` and returns it as
 * the `IAiNavigator` interface pointer.
 */
IAiNavigator* moho::AI_CreateAirNavigator(Unit* const unit)
{
  auto* const navigator = new (std::nothrow) CAiNavigatorAir(unit);
  return navigator;
}

/**
 * Address: 0x005A2D30 (FUN_005A2D30, scalar deleting thunk)
 */
IAiNavigator::~IAiNavigator()
{
  mListenerNode.ListUnlink();
}

/**
 * Address: 0x005A7B60 (FUN_005A7B60, Moho::IAiNavigator::MemberDeserialize)
 *
 * What it does:
 * Loads IAiNavigator broadcaster listener payload through reflected
 * `Broadcaster<EAiNavigatorEvent>` metadata.
 */
void IAiNavigator::MemberDeserialize(IAiNavigator* const object, gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(
    CachedBroadcasterEAiNavigatorEventType(),
    object ? static_cast<void*>(&object->mListenerNode) : nullptr,
    ownerRef
  );
}

/**
 * Address: 0x005A7BB0 (FUN_005A7BB0, Moho::IAiNavigator::MemberSerialize)
 *
 * What it does:
 * Saves IAiNavigator broadcaster listener payload through reflected
 * `Broadcaster<EAiNavigatorEvent>` metadata.
 */
void IAiNavigator::MemberSerialize(const IAiNavigator* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(
    CachedBroadcasterEAiNavigatorEventType(),
    object ? static_cast<const void*>(&object->mListenerNode) : nullptr,
    ownerRef
  );
}

/**
 * Address: 0x00BCC9A0 (FUN_00BCC9A0)
 *
 * What it does:
 * Registers the broadcaster reflection lane for `EAiNavigatorEvent` and
 * installs process-exit cleanup.
 */
int moho::register_RBroadcasterRType_EAiNavigatorEvent()
{
  auto* const type = AcquireBroadcasterNavigatorType();
  gpg::PreRegisterRType(typeid(moho::BroadcasterEventTag<moho::EAiNavigatorEvent>), type);
  return std::atexit(&cleanup_RBroadcasterRType_EAiNavigatorEvent);
}

/**
 * Address: 0x00BCC9C0 (FUN_00BCC9C0)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiNavigatorEvent` and installs
 * process-exit cleanup.
 */
int moho::register_RListenerRType_EAiNavigatorEvent()
{
  auto* const type = AcquireListenerNavigatorType();
  gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiNavigatorEvent>), type);
  return std::atexit(&cleanup_RListenerRType_EAiNavigatorEvent);
}

namespace
{
  struct IAiNavigatorReflectionBootstrap
  {
    IAiNavigatorReflectionBootstrap()
    {
      (void)moho::register_RBroadcasterRType_EAiNavigatorEvent();
      (void)moho::register_RListenerRType_EAiNavigatorEvent();
    }
  };

  [[maybe_unused]] IAiNavigatorReflectionBootstrap gIAiNavigatorReflectionBootstrap;
} // namespace
