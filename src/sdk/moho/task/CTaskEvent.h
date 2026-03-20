#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class CTaskThread;

  struct STaskEventLinkage;

  template <>
  struct WeakPtrOwnerLinkOffset<CTaskThread>
  {
    static constexpr std::uintptr_t value = 0x08;
  };

  template <>
  struct WeakPtrOwnerLinkOffset<STaskEventLinkage>
  {
    static constexpr std::uintptr_t value = 0x08;
  };

  struct STaskEventLinkage : TDatListItem<STaskEventLinkage, void>
  {
    WeakPtr<STaskEventLinkage>* mOwnerWeakRefHead; // 0x08
    WeakPtr<CTaskThread> mThreadRef;               // 0x0C

    STaskEventLinkage()
      : mOwnerWeakRefHead(nullptr)
      , mThreadRef{nullptr, nullptr}
    {}

    /**
     * Address: 0x00406D30 (FUN_00406D30, ??1STaskEventLinkage@Moho@@QAE@XZ)
     *
     * What it does:
     * Unlinks the waiting-thread weak ref, clears all reverse weak refs owned
     * by this linkage, then unlinks from the event wait-list.
     */
    ~STaskEventLinkage();
  };

  static_assert(sizeof(STaskEventLinkage) == 0x14, "STaskEventLinkage size must be 0x14");
  static_assert(
    offsetof(STaskEventLinkage, mOwnerWeakRefHead) == 0x08, "STaskEventLinkage::mOwnerWeakRefHead offset must be 0x08"
  );
  static_assert(offsetof(STaskEventLinkage, mThreadRef) == 0x0C, "STaskEventLinkage::mThreadRef offset must be 0x0C");
  static_assert(WeakPtr<CTaskThread>::kOwnerLinkOffset == 0x08, "CTaskThread weak-owner slot offset must be 0x08");
  static_assert(
    WeakPtr<STaskEventLinkage>::kOwnerLinkOffset == 0x08, "STaskEventLinkage weak-owner slot offset must be 0x08"
  );

  class CTaskEvent
  {
  public:
    /**
     * Address: 0x00406C30 (scalar deleting thunk)
     * Address: 0x00406C70 (FUN_00406C70, ??1CTaskEvent@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0
     */
    virtual ~CTaskEvent();

    /**
     * Address: 0x00406E20 (FUN_00406E20, ?EventWait@CTaskEvent@Moho@@QAEPAUSTaskEventLinkage@2@PAVCTaskThread@2@@Z)
     *
     * What it does:
     * Stages the task thread if needed, allocates a wait-link node, binds it
     * to the thread weak-link chain, and appends it to this event wait-list.
     */
    STaskEventLinkage* EventWait(CTaskThread* thread);

    /**
     * Address: 0x00406D90 (FUN_00406D90, ?EventSetSignaled@CTaskEvent@Moho@@QAEX_N@Z)
     *
     * What it does:
     * Sets signaled state; when transitioning to signaled, releases all
     * waiting linkages and unstages their owner threads.
     */
    void EventSetSignaled(bool signaled);

    /**
     * Address: 0x00407020 (FUN_00407020, ?SerThreads@CTaskEvent@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
     *
     * What it does:
     * Rebuilds event wait-link intrusive list by reading owned link pointers
     * terminated by null.
     */
    void DeserializeWaitLinks(gpg::ReadArchive* archive);

    /**
     * Address: 0x00406FB0 (FUN_00406FB0, ?SerThreads@CTaskEvent@Moho@@ABEXAAVWriteArchive@gpg@@H@Z)
     *
     * What it does:
     * Writes event wait-link intrusive list as owned link pointers and appends
     * null terminator pointer.
     */
    void SerializeWaitLinks(gpg::WriteArchive* archive) const;

  public:
    bool mTriggered{false}; // 0x04
    // 0x05..0x07: layout alignment bytes (no direct task-path field accesses recovered).
    std::uint8_t mAlignmentPad05[3]{};
    TDatList<STaskEventLinkage, void> mWaitLinks; // 0x08
  };

  static_assert(sizeof(CTaskEvent) == 0x10, "CTaskEvent size must be 0x10");
  static_assert(offsetof(CTaskEvent, mTriggered) == 0x04, "CTaskEvent::mTriggered offset must be 0x04");
  static_assert(offsetof(CTaskEvent, mWaitLinks) == 0x08, "CTaskEvent::mWaitLinks offset must be 0x08");

  class CTaskEventSerializer
  {
  public:
    /**
     * Address: 0x00407620 (FUN_00407620, ?Init@CTaskEventSerializer@Moho@@UAEXXZ)
     * Slot: 0
     *
     * What it does:
     * Binds CTaskEvent load/save serializer callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CTaskEventTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00406B60 (FUN_00406B60, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CTaskEventTypeInfo() override;

    /**
     * Address: 0x00406B50 (FUN_00406B50, ?GetName@CTaskEventTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00406B30 (FUN_00406B30, ?Init@CTaskEventTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CTaskEventSerializer) == 0x14, "CTaskEventSerializer size must be 0x14");
  static_assert(sizeof(CTaskEventTypeInfo) == 0x64, "CTaskEventTypeInfo size must be 0x64");
} // namespace moho
