#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: evidence from FUN_0054AD70
   */
  class CAniPoseTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0054AD70 (FUN_0054AD70, ??0CAniPoseTypeInfo@Moho@@QAE@XZ)
     *
     * What it does:
     * Preregisters `CAniPose` RTTI for this type-info helper.
     */
    CAniPoseTypeInfo();

    /**
     * Address: 0x0054AE30 (FUN_0054AE30, scalar deleting thunk)
     */
    ~CAniPoseTypeInfo() override;

    /**
     * Address: 0x0054AE20 (FUN_0054AE20, ?GetName@CAniPoseTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0054ADD0 (FUN_0054ADD0, ?Init@CAniPoseTypeInfo@Moho@@UAEXXZ)
     *
     * What it does:
     * Sets size = 0x90, installs ref-management function pointers in the same
     * order as the binary, then finalizes.
     */
    void Init() override;

    /**
     * Address: 0x0054D8A0 (FUN_0054D8A0, Moho::CAniPoseTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one default-initialized `CAniPose` and returns its typed
     * reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0054D940 (FUN_0054D940, Moho::CAniPoseTypeInfo::CpyRef)
     *
     * What it does:
     * Allocates one destination `CAniPose`, copy-constructs it from the source
     * reference, and returns the typed reflection reference.
     */
    static gpg::RRef CpyRef(gpg::RRef* sourceRef);

    /**
     * Address: 0x0054D9D0 (FUN_0054D9D0, Moho::CAniPoseTypeInfo::Delete)
     *
     * What it does:
     * Destroys and frees one heap-owned `CAniPose`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0054D9F0 (FUN_0054D9F0, Moho::CAniPoseTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-initializes one `CAniPose` in caller-provided storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0054DA80 (FUN_0054DA80, Moho::CAniPoseTypeInfo::MovRef)
     *
     * What it does:
     * Placement-copy-constructs one `CAniPose` in caller-provided storage from
     * the source reflection reference.
     */
    static gpg::RRef MovRef(void* objectStorage, gpg::RRef* sourceRef);

    /**
     * Address: 0x0054DB00 (FUN_0054DB00, Moho::CAniPoseTypeInfo::Destruct)
     *
     * What it does:
     * Runs the `CAniPose` destructor in place without freeing storage.
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CAniPoseTypeInfo) == 0x64, "CAniPoseTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC9940 (FUN_00BC9940, register_CAniPoseTypeInfo)
   *
   * What it does:
   * Ensures startup construction of `CAniPoseTypeInfo` and installs process-exit cleanup.
   */
  void register_CAniPoseTypeInfoStartup();
} // namespace moho
