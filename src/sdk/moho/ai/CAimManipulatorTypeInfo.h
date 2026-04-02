#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAimManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0062FED0 (FUN_0062FED0, Moho::CAimManipulatorTypeInfo::CAimManipulatorTypeInfo)
     *
     * What it does:
     * Initializes RTTI base lanes and preregisters `CAimManipulator` type metadata.
     */
    CAimManipulatorTypeInfo();

    /**
     * Address: 0x0062FF80 (FUN_0062FF80, scalar deleting thunk)
     * Slot: 2
     */
    ~CAimManipulatorTypeInfo() override;

    /**
     * Address: 0x0062FF70 (FUN_0062FF70, Moho::CAimManipulatorTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0062FF30 (FUN_0062FF30, Moho::CAimManipulatorTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAimManipulator` (`sizeof = 0x110`)
     * and installs known callback lanes.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00632EA0 (FUN_00632EA0, Moho::CAimManipulatorTypeInfo::NewRef)
     *
     * What it does:
     * Creates a reflected owned-reference lane for `CAimManipulator`.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00632F40 (FUN_00632F40, Moho::CAimManipulatorTypeInfo::CtrRef)
     *
     * What it does:
     * Creates a reflected in-place reference lane for `CAimManipulator`.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00632F20 (FUN_00632F20, Moho::CAimManipulatorTypeInfo::Delete)
     *
     * What it does:
     * Deleting-dtor callback lane for reflected `CAimManipulator` storage.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00632FB0 (FUN_00632FB0, Moho::CAimManipulatorTypeInfo::Destruct)
     *
     * What it does:
     * Non-deleting destructor callback lane for reflected `CAimManipulator` storage.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00632FD0 (FUN_00632FD0, Moho::CAimManipulatorTypeInfo::AddBase_IAniManipulator)
     *
     * What it does:
     * Registers `IAniManipulator` as reflection base for `CAimManipulator`.
     */
    static void AddBase_IAniManipulator(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CAimManipulatorTypeInfo) == 0x64, "CAimManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD2270 (FUN_00BD2270, register_CAimManipulatorTypeInfo)
   *
   * What it does:
   * Registers `CAimManipulator` RTTI startup owner and installs process-exit
   * cleanup for its static storage.
   */
  void register_CAimManipulatorTypeInfo();
} // namespace moho
