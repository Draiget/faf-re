#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMotionConstruct final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD7240 (FUN_00BD7240, register_CUnitMotionConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CUnitMotionConstruct();

    /**
     * Address: 0x00BFE070 (FUN_00BFE070, cleanup_CUnitMotionConstruct)
     *
     * What it does:
     * Unlinks the `CUnitMotionConstruct` helper from the intrusive helper
     * list and rewires it as a self-linked singleton.
     */
    ~CUnitMotionConstruct();

    /**
     * Address: 0x006BA7F0 (FUN_006BA7F0, gpg::SerConstructHelper_CUnitMotion::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CUnitMotion RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  /**
   * Address: 0x006BAC40 (FUN_006BAC40, destroy_CUnitMotion)
   *
   * What it does:
   * Runs `CUnitMotion` teardown and frees the backing allocation when present.
   */
  void destroy_CUnitMotion(void* objectPtr);

  static_assert(
    offsetof(CUnitMotionConstruct, mConstructCallback) == 0x0C,
    "CUnitMotionConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitMotionConstruct, mDeleteCallback) == 0x10,
    "CUnitMotionConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitMotionConstruct) == 0x14, "CUnitMotionConstruct size must be 0x14");
} // namespace moho
