#pragma once

#include <cstddef>

#include "../../gpg/core/containers/FastVector.h"

namespace moho
{
  class Entity;

  /**
   * Address context:
   * - 0x0057DDD0 (FUN_0057DDD0, Moho::EntitySetTemplate_Entity::Add)
   * - 0x005E8960 (FUN_005E8960, Moho::EntitySetTemplate_Unit::Contains)
   * - 0x00700A00 (FUN_00700A00)
   * - 0x00700E20 (FUN_00700E20)
   * - 0x00700E70 (FUN_00700E70)
   *
   * What it does:
   * Per-category unit/entity set with intrusive links and sorted inline-vector storage.
   */
  struct SEntitySetTemplateUnit
  {
    void* mNext;                        // +0x00
    void* mPrev;                        // +0x04
    gpg::fastvector_n<Entity*, 4> mVec; // +0x08
  };

  static_assert(offsetof(SEntitySetTemplateUnit, mVec) == 0x08, "SEntitySetTemplateUnit::mVec offset must be 0x08");
  static_assert(sizeof(SEntitySetTemplateUnit) == 0x28, "SEntitySetTemplateUnit size must be 0x28");
} // namespace moho
