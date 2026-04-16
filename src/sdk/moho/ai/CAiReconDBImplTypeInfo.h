#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DAE4
   * COL:  0x00E73CE8
   */
  class CAiReconDBImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005C27B0 (FUN_005C27B0, Moho::CAiReconDBImplTypeInfo::CAiReconDBImplTypeInfo)
     *
     * What it does:
     * Preregisters `CAiReconDBImpl` RTTI into the reflection lookup table.
     */
    CAiReconDBImplTypeInfo();

    /**
     * Address: 0x005C2860 (FUN_005C2860, scalar deleting thunk)
     *
     * What it does:
     * Destroys the type-info object and conditionally frees the allocation
     * through the scalar-delete thunk path.
     *
     * VFTable SLOT: 2
     */
    ~CAiReconDBImplTypeInfo() override;

    /**
     * Address: 0x005C2850 (FUN_005C2850)
     *
     * What it does:
     * Returns the reflection name string for `CAiReconDBImpl`.
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005C2810 (FUN_005C2810)
     *
     * What it does:
     * Registers `CAiReconDBImpl` reflection metadata (size, alloc/ctor/dtor
     * callbacks, base type chain).
     *
     * VFTable SLOT: 9
     */
    void Init() override;

  private:
    /**
     * Address: 0x005C4D30 (FUN_005C4D30)
     *
     * What it does:
     * Binds the reflection allocation/construction/destruction callback lanes
     * for `CAiReconDBImpl`.
     */
    void BindFactoryCallbacks() noexcept;
  };

  static_assert(sizeof(CAiReconDBImplTypeInfo) == 0x64, "CAiReconDBImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCDDA0 (FUN_00BCDDA0, register_CAiReconDBImplTypeInfo)
   *
   * What it does:
   * Constructs the recovered `CAiReconDBImplTypeInfo` helper and installs
   * process-exit cleanup.
   */
  void register_CAiReconDBImplTypeInfo();

  /**
   * Address: 0x005CA580 (FUN_005CA580, sub_5CA580)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `msvc8::vector<ReconBlip*>`.
   */
  [[nodiscard]] gpg::RType* preregister_RVectorType_ReconBlipPtr();

  /**
     * Address: 0x00BF7CC0 (FUN_00BF7CC0)
   *
   * What it does:
   * Tears down startup-owned `vector<ReconBlip*>` reflection storage.
   */
  void cleanup_RVectorType_ReconBlipPtr();

  /**
   * Address: 0x00BCDF60 (FUN_00BCDF60, sub_BCDF60)
   *
   * What it does:
   * Registers `vector<ReconBlip*>` reflection metadata and installs
   * process-exit cleanup.
   */
  int register_RVectorType_ReconBlipPtr();

  /**
   * Address: 0x005CA630 (FUN_005CA630, sub_5CA630)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for recon-blip map storage.
   */
  [[nodiscard]] gpg::RType* preregister_RMultiMapType_SReconKey_ReconBlipPtr();

  /**
     * Address: 0x00BF7C60 (FUN_00BF7C60)
   *
   * What it does:
   * Tears down startup-owned recon-blip map reflection storage.
   */
  void cleanup_RMultiMapType_SReconKey_ReconBlipPtr();

  /**
   * Address: 0x00BCDF80 (FUN_00BCDF80, sub_BCDF80)
   *
   * What it does:
   * Registers recon-blip map reflection metadata and installs process-exit
   * cleanup.
   */
  int register_RMultiMapType_SReconKey_ReconBlipPtr();
} // namespace moho
