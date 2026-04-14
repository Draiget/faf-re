#include "moho/terrain/water/WaveSystem.h"

namespace
{
  /**
   * Address: 0x0088AD00 (FUN_0088AD00, sub_88AD00)
   *
   * What it does:
   * Invokes scalar deleting destructor semantics for each non-null generator
   * pointer in one half-open range.
   */
  void DestroyWaveGeneratorRange(moho::WaveGenerator* const* const begin, moho::WaveGenerator* const* const end)
  {
    for (moho::WaveGenerator* const* it = begin; it != end; ++it) {
      delete *it;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00888CB0 (FUN_00888CB0, ??0WaveSystem@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes wave runtime lanes, spatial registration entry, and the
   * inline generator-cache storage window.
   */
  WaveSystem::WaveSystem()
    : mReserved04(0)
    , mSpatialMeshInstance()
    , mRuntimeBlock10{}
    , mWaveGenerators()
    , mGeneratorCache()
  {}

  /**
   * Address: 0x00888D50 (FUN_00888D50, ??1WaveSystem@Moho@@UAE@XZ)
   *
   * What it does:
   * Releases owned wave generators and restores generator cache storage to
   * inline state before member teardown.
   */
  WaveSystem::~WaveSystem()
  {
    ClearWaveGeneratorState();
  }

  /**
   * Address: 0x00889BA0 (FUN_00889BA0, sub_889BA0)
   *
   * What it does:
   * Deletes all owned wave-generator objects and resets both generator
   * storage lanes to empty runtime state.
   */
  void WaveSystem::ClearWaveGeneratorState()
  {
    DestroyWaveGeneratorRange(mWaveGenerators.begin(), mWaveGenerators.end());
    mWaveGenerators.clear();
    mGeneratorCache.ResetStorageToInline();
  }
} // namespace moho