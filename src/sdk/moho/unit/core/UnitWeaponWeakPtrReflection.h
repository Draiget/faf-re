#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class UnitWeapon;

  struct WeakPtr_UnitWeapon
  {
    /**
     * Address: 0x00675220 (FUN_00675220, Moho::WeakPtr_UnitWeapon::Deserialize)
     *
     * What it does:
     * Deserializes one `WeakPtr<UnitWeapon>` payload from a tracked pointer lane.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00675250 (FUN_00675250, Moho::WeakPtr_UnitWeapon::Serialize)
     *
     * What it does:
     * Serializes one `WeakPtr<UnitWeapon>` payload as an unowned tracked pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  template <class T>
  class RWeakPtrType;

  template <>
  class RWeakPtrType<UnitWeapon> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00674BB0 (FUN_00674BB0, Moho::RWeakPtrType_UnitWeapon::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00674C70 (FUN_00674C70, Moho::RWeakPtrType_UnitWeapon::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00674E00 (FUN_00674E00, Moho::RWeakPtrType_UnitWeapon::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00674E10 (FUN_00674E10, Moho::RWeakPtrType_UnitWeapon::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x00674C50 (FUN_00674C50, Moho::RWeakPtrType_UnitWeapon::Init)
     */
    void Init() override;

    /**
     * Address: 0x00674E50 (FUN_00674E50, Moho::RWeakPtrType_UnitWeapon::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00674E20 (FUN_00674E20, Moho::RWeakPtrType_UnitWeapon::GetCount)
     */
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<UnitWeapon>) == 0x68, "RWeakPtrType<UnitWeapon> size must be 0x68");

  /**
   * Address: 0x00675AC0 (FUN_00675AC0, register_WeakPtr_UnitWeapon_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `WeakPtr<UnitWeapon>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_UnitWeapon_Type_00();

  /**
   * Address: 0x00BFC490 (FUN_00BFC490, cleanup_WeakPtr_UnitWeapon_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<UnitWeapon>` reflection storage.
   */
  void cleanup_WeakPtr_UnitWeapon_Type();

  /**
   * Address: 0x00BD4DF0 (FUN_00BD4DF0, register_WeakPtr_UnitWeapon_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<UnitWeapon>` reflection and installs process-exit teardown.
   */
  int register_WeakPtr_UnitWeapon_Type_AtExit();
} // namespace moho

