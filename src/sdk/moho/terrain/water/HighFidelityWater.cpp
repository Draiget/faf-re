#include "moho/terrain/water/HighFidelityWater.h"

namespace
{
  using PolymorphicDeleteFn = void(__thiscall*)(void* object, int deleteFlag);

  void DestroyPolymorphicSubobject(void*& subobject) noexcept
  {
    if (subobject == nullptr) {
      return;
    }

    auto* const vtable = *reinterpret_cast<void***>(subobject);
    auto* const deletingDestructor = reinterpret_cast<PolymorphicDeleteFn>(vtable[0]);
    deletingDestructor(subobject, 1);
    subobject = nullptr;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00810540 (FUN_00810540, Moho::HighFidelityWater::Func1)
   * Mangled: ?Func1@HighFidelityWater@Moho@@QAEXXZ
   *
   * What it does:
   * Clears the cached runtime state used by the high-fidelity water render
   * path, including both shared texture handles and the polymorphic helper
   * subobjects bound at the tail of the class.
   */
  void HighFidelityWater::ReleaseRenderState()
  {
    mFresnelMap.release();
    DestroyPolymorphicSubobject(mAuxiliarySurface0);
    DestroyPolymorphicSubobject(mAuxiliarySurface1);
    mWaterMap.release();
    mResources = nullptr;
  }

  /**
   * Address: 0x00810220 (??1HighFidelityWater@Moho@@QAE@@Z)
   * Mangled: ??1HighFidelityWater@Moho@@QAE@@Z
   *
   * What it does:
   * Releases the retained shared-owner lanes, destroys the two polymorphic
   * helper subobjects, and restores the WaterSurface base vtable on exit.
   */
  HighFidelityWater::~HighFidelityWater()
  {
    ReleaseRenderState();
  }
} // namespace moho
