#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "moho/mesh/Mesh.h"

namespace moho
{
  class WaveGenerator
  {
  public:
    virtual ~WaveGenerator() = default;
  };

  class WaveSystem
  {
  public:
    /**
     * Address: 0x00888CB0 (FUN_00888CB0, ??0WaveSystem@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes wave runtime lanes, spatial registration entry, and the
     * inline generator-cache storage window.
     */
    WaveSystem();

    /**
     * Address: 0x00888D50 (FUN_00888D50, ??1WaveSystem@Moho@@UAE@XZ)
     *
     * What it does:
     * Releases owned wave generators and restores generator cache storage to
     * inline state before member teardown.
     */
    virtual ~WaveSystem();

    /**
     * Address: 0x00889BA0 (FUN_00889BA0, sub_889BA0)
     *
     * What it does:
     * Deletes all owned wave-generator objects and resets both generator
     * storage lanes to empty runtime state.
     */
    void ClearWaveGeneratorState();

  public:
    std::uint32_t mReserved04;                            // +0x04
    SpatialDB_MeshInstance mSpatialMeshInstance;          // +0x08
    std::uint8_t mRuntimeBlock10[0x8C];                   // +0x10
    msvc8::vector<WaveGenerator*> mWaveGenerators;        // +0x9C
    gpg::fastvector_n<WaveGenerator*, 100> mGeneratorCache; // +0xA8
  };

  static_assert(offsetof(WaveSystem, mReserved04) == 0x04, "WaveSystem::mReserved04 offset must be 0x04");
  static_assert(
    offsetof(WaveSystem, mSpatialMeshInstance) == 0x08,
    "WaveSystem::mSpatialMeshInstance offset must be 0x08"
  );
  static_assert(
    offsetof(WaveSystem, mWaveGenerators) == 0x9C,
    "WaveSystem::mWaveGenerators offset must be 0x9C"
  );
  static_assert(
    offsetof(WaveSystem, mGeneratorCache) == 0xA8,
    "WaveSystem::mGeneratorCache offset must be 0xA8"
  );
  static_assert(sizeof(WaveSystem) == 0x248, "WaveSystem size must be 0x248");
} // namespace moho