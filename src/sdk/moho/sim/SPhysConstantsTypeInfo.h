#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SPhysConstants;

  class SPhysConstantsTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00699AB0 (FUN_00699AB0, Moho::SPhysConstantsTypeInfo::SPhysConstantsTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `SPhysConstants`.
     */
    SPhysConstantsTypeInfo();

    /**
     * Address: 0x00699B60 (FUN_00699B60, Moho::SPhysConstantsTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Releases the reflected `SPhysConstantsTypeInfo` object.
     */
    ~SPhysConstantsTypeInfo() override;

    /**
     * Address: 0x00699B50 (FUN_00699B50, Moho::SPhysConstantsTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `SPhysConstants`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00699B10 (FUN_00699B10, Moho::SPhysConstantsTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected `SPhysConstants` size metadata and finalizes the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00699F60 (FUN_00699F60, Moho::SPhysConstantsTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and default-initializes a `SPhysConstants` reflection object.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00699FC0 (FUN_00699FC0, Moho::SPhysConstantsTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs a `SPhysConstants` reflection object in caller-provided storage.
     */
    static gpg::RRef CtrRef(void* objectPtr);

    /**
     * Address: 0x00699FB0 (FUN_00699FB0, Moho::SPhysConstantsTypeInfo::Delete)
     *
     * What it does:
     * Invokes deleting-dtor cleanup for `SPhysConstants`.
     */
    static void Delete(void* objectPtr);

    /**
     * Address: 0x0069A010 (FUN_0069A010, Moho::SPhysConstantsTypeInfo::Destruct)
     *
     * What it does:
     * Invokes the non-deleting destructor lane for `SPhysConstants`.
     */
    static void Destruct(void* objectPtr);
  };

  static_assert(sizeof(SPhysConstantsTypeInfo) == 0x64, "SPhysConstantsTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFD400 (FUN_00BFD400, cleanup_SPhysConstantsTypeInfo)
   *
   * What it does:
   * Releases `SPhysConstantsTypeInfo` storage and restores the base RTTI lane.
   */
  void cleanup_SPhysConstantsTypeInfo();

  /**
   * Address: 0x00BD6030 (FUN_00BD6030, register_SPhysConstantsTypeInfo)
   *
   * What it does:
   * Forces `SPhysConstantsTypeInfo` construction and schedules exit cleanup.
   */
  void register_SPhysConstantsTypeInfo();
} // namespace moho
