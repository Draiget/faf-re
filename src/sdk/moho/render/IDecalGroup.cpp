#include "moho/render/IDecalGroup.h"

namespace moho
{
  namespace
  {
    /**
     * Address: 0x00877230 (FUN_00877230, IDecalGroup base-vtable reset lane)
     *
     * What it does:
     * Represents the compiler-emitted base-vtable reset lane used by the public
     * `IDecalGroup` constructor.
     */
    void ResetIDecalGroupBaseVtable(IDecalGroup* const object)
    {
      // Recovered C++ constructor prologues already perform this vtable install.
      (void)object;
    }
  } // namespace

  /**
   * Address: 0x00877240 (FUN_00877240, ??0IDecalGroup@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes one decal-group base object with the `IDecalGroup` vtable.
   */
  IDecalGroup::IDecalGroup()
  {
    ResetIDecalGroupBaseVtable(this);
  }
} // namespace moho
