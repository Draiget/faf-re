#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Unit;

  struct WeakPtr_Unit
  {
    /**
     * Address: 0x006AF1E0 (FUN_006AF1E0, Moho::RWeakPtrType_Unit::SerLoad)
     *
     * What it does:
     * Deserializes one `WeakPtr<Unit>` payload from a tracked pointer lane.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006AF210 (FUN_006AF210, Moho::RWeakPtrType_Unit::SerSave)
     *
     * What it does:
     * Serializes one `WeakPtr<Unit>` payload as an unowned tracked pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  template <class T>
  class RWeakPtrType;

  template <>
  class RWeakPtrType<Unit> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006ADF90 (FUN_006ADF90, Moho::RWeakPtrType_Unit::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006AE050 (FUN_006AE050, Moho::RWeakPtrType_Unit::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006AE1E0 (FUN_006AE1E0, Moho::RWeakPtrType_Unit::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006AE1F0 (FUN_006AE1F0, Moho::RWeakPtrType_Unit::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x006AE030 (FUN_006AE030, Moho::RWeakPtrType_Unit::Init)
     */
    void Init() override;

    /**
     * Address: 0x006AE230 (FUN_006AE230, Moho::RWeakPtrType_Unit::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006AE200 (FUN_006AE200, Moho::RWeakPtrType_Unit::GetCount)
     */
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<Unit>) == 0x68, "RWeakPtrType<Unit> size must be 0x68");

  /**
   * Address: 0x006B1640 (FUN_006B1640, register_WeakPtr_Unit_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `WeakPtr<Unit>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_Unit_Type_00();

  /**
   * Address: 0x00BFDC40 (FUN_00BFDC40, cleanup_WeakPtr_Unit_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<Unit>` reflection storage.
   */
  void cleanup_WeakPtr_Unit_Type();

  /**
   * Address: 0x00BD6BA0 (FUN_00BD6BA0, register_WeakPtr_Unit_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<Unit>` reflection and installs process-exit teardown.
   */
  int register_WeakPtr_Unit_Type_AtExit();
} // namespace moho
