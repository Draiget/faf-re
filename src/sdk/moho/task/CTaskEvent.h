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

#ifndef MOHO_WEAKPTR_OWNER_LINK_OFFSET_CTASKTHREAD_DEFINED
#define MOHO_WEAKPTR_OWNER_LINK_OFFSET_CTASKTHREAD_DEFINED
  template <>
  struct WeakPtrOwnerLinkOffset<CTaskThread>
  {
    static constexpr std::uintptr_t value = 0x08;
  };
#endif

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

  /**
   * Wrapper namespace for free helpers operating on `WeakPtr<STaskEventLinkage>`
   * instances. Mirrors the binary's `Moho::WeakPtr_STaskEventLinkage::*` static
   * function lane.
   */
  struct WeakPtr_STaskEventLinkage
  {
    /**
     * Address: 0x010C6C74 (.data, Moho::WeakPtr_STaskEventLinkage::sType)
     *
     * What it does:
     * Caches reflected RTTI metadata for `WeakPtr<STaskEventLinkage>`.
     */
    static gpg::RType* sType;

    /**
     * Address: 0x004CC810 (FUN_004CC810)
     *
     * What it does:
     * Resolves/caches the reflected type metadata for
     * `WeakPtr<STaskEventLinkage>`.
     */
    static gpg::RType* ResolveType();

    /**
     * Address: 0x004CC7B0 (FUN_004CC7B0)
     *
     * What it does:
     * Loads one `WeakPtr<STaskEventLinkage>` lane through reflected type
     * metadata.
     */
    static void Read(gpg::ReadArchive* archive, void* object, const gpg::RRef& ownerRef);

    /**
     * Address: 0x004CC7E0 (FUN_004CC7E0)
     *
     * What it does:
     * Saves one `WeakPtr<STaskEventLinkage>` lane through reflected type
     * metadata.
     */
    static void Write(gpg::WriteArchive* archive, const void* object, const gpg::RRef& ownerRef);

    /**
     * Address: 0x004078B0 (FUN_004078B0, Moho::WeakPtr_STaskEventLinkage::SetObject)
     *
     * What it does:
     * Atomically rebinds an intrusive `WeakPtr<STaskEventLinkage>` slot to a
     * new linkage, unlinking from the prior owner's chain and inserting at
     * the new owner's chain head. No-op if the target object is unchanged.
     */
    static WeakPtr<STaskEventLinkage>* SetObject(WeakPtr<STaskEventLinkage>* slot, STaskEventLinkage* linkage) noexcept;
  };

  class STaskEventLinkageSerializer
  {
  public:
    /**
     * Address: 0x004069A0 (FUN_004069A0, Moho::STaskEventLinkageSerializer::Deserialize)
     * Alias:   0x00407900 (FUN_00407900, duplicate callback body)
     *
     * What it does:
     * Loads `STaskEventLinkage::mThreadRef` through reflected
     * `WeakPtr<CTaskThread>` serialization.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004069F0 (FUN_004069F0, Moho::STaskEventLinkageSerializer::Serialize)
     * Alias:   0x00407950 (FUN_00407950, duplicate callback body)
     *
     * What it does:
     * Saves `STaskEventLinkage::mThreadRef` through reflected
     * `WeakPtr<CTaskThread>` serialization.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00407240 (FUN_00407240, Moho::STaskEventLinkageSerializer::Init)
     * Slot: 0
     *
     * What it does:
     * Binds linkage serializer callbacks into RTTI for `STaskEventLinkage`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class STaskEventLinkageTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00406840 (FUN_00406840, Moho::STaskEventLinkageTypeInfo::STaskEventLinkageTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI descriptor for `STaskEventLinkage`.
     */
    STaskEventLinkageTypeInfo();

    /**
     * Address: 0x004068F0 (FUN_004068F0, Moho::STaskEventLinkageTypeInfo::dtr)
     * Slot: 2
     */
    ~STaskEventLinkageTypeInfo() override;

    /**
     * Address: 0x004068E0 (FUN_004068E0, Moho::STaskEventLinkageTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004068A0 (FUN_004068A0, Moho::STaskEventLinkageTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected size/callback lanes and finalizes the linkage RTTI type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x004077F0 (FUN_004077F0)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00407860 (FUN_00407860)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00407840 (FUN_00407840)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x004078A0 (FUN_004078A0)
     */
    static void Destruct(void* objectStorage);
  };

  template <class T>
  class RWeakPtrType;

  class CTaskEvent;

  template <>
  class RWeakPtrType<STaskEventLinkage> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00407EC0 (FUN_00407EC0, Moho::RWeakPtrType_STaskEventLinkage::dtr)
     * Slot: 2
     */
    ~RWeakPtrType() override;

    /**
     * Address: 0x004072B0 (FUN_004072B0, Moho::RWeakPtrType_STaskEventLinkage::GetName)
     * Slot: 3
     *
     * What it does:
     * Builds/caches lexical type name `WeakPtr<STaskEventLinkage>`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00407370 (FUN_00407370, Moho::RWeakPtrType_STaskEventLinkage::GetLexical)
     * Slot: 4
     *
     * What it does:
     * Returns `"NULL"` for empty weak pointers, otherwise wraps pointee lexical with brackets.
     */
    [[nodiscard]]
    msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00407500 (FUN_00407500, Moho::RWeakPtrType_STaskEventLinkage::IsIndexed)
     * Slot: 6
     */
    [[nodiscard]]
    const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00407510 (FUN_00407510, Moho::RWeakPtrType_STaskEventLinkage::IsPointer)
     * Slot: 7
     */
    [[nodiscard]]
    const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x00407350 (FUN_00407350, Moho::RWeakPtrType_STaskEventLinkage::Init)
     * Slot: 9
     *
     * What it does:
     * Sets weak-pointer size/version metadata and serializer callback lanes.
     */
    void Init() override;

    /**
     * Address: 0x00407550 (FUN_00407550, Moho::RWeakPtrType_STaskEventLinkage::SubscriptIndex)
     */
    [[nodiscard]]
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00407520 (FUN_00407520, Moho::RWeakPtrType_STaskEventLinkage::GetCount)
     */
    [[nodiscard]]
    size_t GetCount(void* obj) const override;
  };

  class CTaskEvent
  {
  public:
    /**
     * Address: 0x00406C10 (FUN_00406C10, ??0CTaskEvent@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes default trigger state and self-linked wait-list sentinel.
     */
    CTaskEvent();

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
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CTaskEventTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00406AD0 (FUN_00406AD0, Moho::CTaskEventTypeInfo::CTaskEventTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI descriptor for `CTaskEvent`.
     */
    CTaskEventTypeInfo();

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

  static_assert(sizeof(STaskEventLinkageSerializer) == 0x14, "STaskEventLinkageSerializer size must be 0x14");
  static_assert(sizeof(STaskEventLinkageTypeInfo) == 0x64, "STaskEventLinkageTypeInfo size must be 0x64");
  static_assert(sizeof(RWeakPtrType<STaskEventLinkage>) == 0x68, "RWeakPtrType<STaskEventLinkage> size must be 0x68");
  static_assert(sizeof(CTaskEventSerializer) == 0x14, "CTaskEventSerializer size must be 0x14");
  static_assert(sizeof(CTaskEventTypeInfo) == 0x64, "CTaskEventTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC2ED0 (FUN_00BC2ED0, register_STaskEventLinkageTypeInfo)
   *
   * What it does:
   * Materializes the startup `STaskEventLinkageTypeInfo` descriptor and
   * registers process-exit teardown.
   */
  void register_STaskEventLinkageTypeInfo();

  /**
   * Address: 0x00BC2EF0 (FUN_00BC2EF0, register_STaskEventLinkageSerializer)
   *
   * What it does:
   * Initializes startup serializer callbacks for `STaskEventLinkage` and
   * registers process-exit intrusive-link cleanup.
   */
  void register_STaskEventLinkageSerializer();

  /**
   * Address: 0x00BC2F30 (FUN_00BC2F30, register_CTaskEventTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskEventTypeInfo` descriptor and registers
   * process-exit teardown.
   */
  void register_CTaskEventTypeInfo();
} // namespace moho
