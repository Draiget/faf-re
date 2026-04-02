#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class CTaskThread;

  template <class T>
  class RWeakPtrType;

  struct WeakPtr_CTaskThread
  {
    /**
     * Address: 0x0040AD50 (FUN_0040AD50, Moho::WeakPtr_CTaskThread::Deserialize)
     *
     * What it does:
     * Loads one weak-pointer lane targeting `CTaskThread` and rebinds the
     * intrusive weak owner-link state.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0040AD80 (FUN_0040AD80, Moho::WeakPtr_CTaskThread::Serialize)
     *
     * What it does:
     * Saves one weak-pointer lane targeting `CTaskThread` as an unowned tracked
     * pointer record.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  /**
   * Address: 0x0040B200 (FUN_0040B200, sub_40B200)
   *
   * What it does:
   * Rebinds one `WeakPtr<CTaskThread>` node to the intrusive owner-link chain
   * of `thread` and returns the updated weak node.
   */
  [[nodiscard]] WeakPtr<CTaskThread>* RelinkWeakPtrCTaskThread(WeakPtr<CTaskThread>* weak, CTaskThread* thread);

  template <>
  class RWeakPtrType<CTaskThread> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0040BB50 (FUN_0040BB50, Moho::RWeakPtrType_CTaskThread::dtr)
     */
    ~RWeakPtrType() override;

    /**
     * Address: 0x0040BA70 (FUN_0040BA70, ??0RWeakPtrType_CTaskThread@Moho@@QAE@@Z)
     */
    RWeakPtrType();

    /**
     * Address: 0x0040A300 (FUN_0040A300, Moho::RWeakPtrType_CTaskThread::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0040A3C0 (FUN_0040A3C0, Moho::RWeakPtrType_CTaskThread::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0040A550 (FUN_0040A550, Moho::RWeakPtrType_CTaskThread::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0040A560 (FUN_0040A560, Moho::RWeakPtrType_CTaskThread::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x0040A3A0 (FUN_0040A3A0, Moho::RWeakPtrType_CTaskThread::Init)
     */
    void Init() override;

    /**
     * Address: 0x0040A5A0 (FUN_0040A5A0, Moho::RWeakPtrType_CTaskThread::SubscriptIndex)
     */
    [[nodiscard]] gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0040A570 (FUN_0040A570, Moho::RWeakPtrType_CTaskThread::GetCount)
     */
    [[nodiscard]] size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<CTaskThread>) == 0x68, "RWeakPtrType<CTaskThread> size must be 0x68");
} // namespace moho
