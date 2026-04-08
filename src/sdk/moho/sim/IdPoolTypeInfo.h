#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class IdPoolTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004037C0 (FUN_004037C0, Moho::IdPoolTypeInfo::IdPoolTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `IdPool`.
     */
    IdPoolTypeInfo();

    /**
     * Address: 0x00403870 (FUN_00403870, deleting dtor lane)
     * Slot: 2
     */
    ~IdPoolTypeInfo() override;

    /**
     * Address: 0x00403860 (FUN_00403860, Moho::IdPoolTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `IdPool`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00403820 (FUN_00403820, Moho::IdPoolTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected `IdPool` size metadata and binds lifecycle callbacks.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00403F40 (FUN_00403F40, Moho::IdPoolTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00404000 (FUN_00404000, Moho::IdPoolTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00403FC0 (FUN_00403FC0, Moho::IdPoolTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00404070 (FUN_00404070, Moho::IdPoolTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(IdPoolTypeInfo) == 0x64, "IdPoolTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC2D80 (FUN_00BC2D80, register_IdPoolTypeInfo)
   *
   * What it does:
   * Materializes startup `IdPoolTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_IdPoolTypeInfo();
} // namespace moho
