#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00DFFF7C
   * COL: 0x00E5C700
   */
  class ThreadSafeCountedObjectTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00403470 (FUN_00403470, Moho::ThreadSafeCountedObjectTypeInfo::ThreadSafeCountedObjectTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `ThreadSafeCountedObject`.
     */
    ThreadSafeCountedObjectTypeInfo();

    /**
     * Address: 0x00403500 (FUN_00403500, Moho::ThreadSafeCountedObjectTypeInfo::dtr)
     * Slot: 2
     */
    ~ThreadSafeCountedObjectTypeInfo() override;

    /**
     * Address: 0x004034F0 (FUN_004034F0, Moho::ThreadSafeCountedObjectTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `ThreadSafeCountedObject`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004034D0 (FUN_004034D0, Moho::ThreadSafeCountedObjectTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected object size metadata and finalizes type registration.
     */
    void Init() override;
  };

  static_assert(
    sizeof(ThreadSafeCountedObjectTypeInfo) == 0x64, "ThreadSafeCountedObjectTypeInfo size must be 0x64"
  );

  /**
   * Address: 0x00BC2D60 (FUN_00BC2D60, register_ThreadSafeCountedObjectTypeInfo)
   *
   * What it does:
   * Materializes startup `ThreadSafeCountedObjectTypeInfo` storage and
   * registers process-exit teardown.
   */
  void register_ThreadSafeCountedObjectTypeInfo();
} // namespace moho
