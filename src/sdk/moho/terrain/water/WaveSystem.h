#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "moho/math/MathReflection.h"
#include "moho/mesh/Mesh.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace moho
{
  class CParticleTexture;

  class WaveGenerator
  {
  public:
    /**
     * Address: 0x00887BF0 (FUN_00887BF0, ??0WaveGenerator@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one wave generator, loads serialized lanes from reader, and
     * rebuilds texture/schedule/bounds runtime state.
     */
    WaveGenerator(SpatialDB_MeshInstance* spatialStorage, std::int32_t formatVersion, gpg::BinaryReader& reader);

    /**
     * Address: 0x00887D40 (FUN_00887D40, sub_887D40)
     *
     * What it does:
     * Initializes one wave generator directly from runtime parameter lanes,
     * then rebuilds texture handles, schedule timing, and spatial bounds.
     */
    WaveGenerator(
      SpatialDB_MeshInstance* spatialStorage,
      const msvc8::string& primaryTexturePath,
      const msvc8::string& rampTexturePath,
      const Wm3::Vec3f& position,
      float angle,
      const Wm3::Vec3f& direction,
      const Wm3::Vector2f& lifetimeRange,
      const Wm3::Vector2f& updateIntervalRange,
      const Wm3::Vector2f& sizeRange,
      float rampValueScale,
      const Wm3::Vector2f& framerateRange,
      float textureSelectionRange
    );

    /**
     * Address: 0x00887EC0 (FUN_00887EC0, sub_887EC0)
     *
     * What it does:
     * Releases texture references, resets texture paths, and clears spatial-db
     * registration state for this generator.
     */
    virtual ~WaveGenerator();

    /**
     * Address: 0x00888250 (FUN_00888250, ?Save@WaveGenerator@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Stores texture paths and wave-emission scalar lanes in binary stream
     * order used by terrain save/load.
     */
    void Save(gpg::BinaryWriter& writer) const;

    void Save(gpg::BinaryWriter* writer) const
    {
      if (writer != nullptr) {
        Save(*writer);
      }
    }

  private:
    friend struct WaveGeneratorLayoutVerifier;

    /**
     * Address: 0x00887FC0 (FUN_00887FC0, sub_887FC0)
     *
     * What it does:
     * Reads texture paths and wave-emission scalar payload from one binary
     * reader lane, then refreshes runtime-dependent state.
     */
    void LoadSerializedState(gpg::BinaryReader& reader, std::int32_t formatVersion);

    /**
     * Address: 0x00888B30 (FUN_00888B30, sub_888B30)
     *
     * What it does:
     * Rebuilds texture handles from stored path lanes, randomizes initial
     * emission schedule, and refreshes spatial bounds.
     */
    void RefreshTextureHandlesAndSchedule();

    /**
     * Address: 0x00888830 (FUN_00888830, sub_888830)
     *
     * What it does:
     * Recomputes spatial AABB/basis payload from wave-generator scalar lanes
     * and updates the attached spatial-db entry bounds.
     */
    void RebuildSpatialBounds();

  private:
    std::uint32_t mReserved04;             // +0x04
    SpatialDB_MeshInstance mSpatialEntry;  // +0x08
    Wm3::AxisAlignedBox3f mBounds;         // +0x10
    Wm3::Vec3f mBoundsCenter;              // +0x28
    VAxes3 mBoundsAxes;                    // +0x34
    Wm3::Vec3f mBoundsHalfExtents;         // +0x58
    std::uint32_t mReserved64;             // +0x64
    double mCurrentTime;                   // +0x68
    double mUpdateInterval;                // +0x70
    msvc8::string mPrimaryTexturePath;     // +0x78
    CParticleTexture* mPrimaryTexture;     // +0x94
    msvc8::string mRampTexturePath;        // +0x98
    CParticleTexture* mRampTexture;        // +0xB4
    Wm3::Vec3f mPosition;                  // +0xB8
    float mAngle;                          // +0xC4
    Wm3::Vec3f mDirection;                 // +0xC8
    float mMinLifetime;                    // +0xD4
    float mMaxLifetime;                    // +0xD8
    float mMinUpdateInterval;              // +0xDC
    float mMaxUpdateInterval;              // +0xE0
    float mBeginSize;                      // +0xE4
    float mEndSize;                        // +0xE8
    float mRampValueScale;                 // +0xEC
    float mMinFramerate;                   // +0xF0
    float mMaxFramerate;                   // +0xF4
    float mTextureSelectionRange;          // +0xF8
    std::uint8_t mTailPaddingFC[0x04];     // +0xFC
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

    /**
     * Address: 0x008899E0 (FUN_008899E0, ?Load@WaveSystem@Moho@@QAEXHHHAAVBinaryReader@gpg@@@Z)
     *
     * What it does:
     * Clears existing generators, resizes embedded spatial storage for current
     * map dimensions, then loads and appends serialized wave generators.
     */
    void Load(std::int32_t formatVersion, std::int32_t mapHeight, std::int32_t mapWidth, gpg::BinaryReader& reader);

    /**
     * Address: 0x00889AD0 (FUN_00889AD0, ?Save@WaveSystem@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Writes generator count and each wave-generator payload in save order.
     */
    void Save(gpg::BinaryWriter& writer) const;

    /**
     * Address: 0x00888E10 (FUN_00888E10, sub_888E10)
     *
     * What it does:
     * Allocates and appends one runtime wave generator from explicit parameter
     * lanes and returns the stored generator pointer.
     */
    WaveGenerator* CreateWaveGenerator(
      const msvc8::string& primaryTexturePath,
      const msvc8::string& rampTexturePath,
      const Wm3::Vec3f& position,
      float angle,
      const Wm3::Vec3f& direction,
      const Wm3::Vector2f& lifetimeRange,
      const Wm3::Vector2f& updateIntervalRange,
      const Wm3::Vector2f& sizeRange,
      float rampValueScale,
      const Wm3::Vector2f& framerateRange,
      float textureSelectionRange
    );

    /**
     * Address: 0x00888F20 (FUN_00888F20, sub_888F20)
     *
     * What it does:
     * Removes all cached references to `generator` from active wave-generator
     * storage and runs one deleting-destructor lane for that generator.
     */
    WaveGenerator* RemoveAndDeleteGenerator(WaveGenerator* generator);

  public:
    std::uint32_t mReserved04;                            // +0x04
    SpatialDB_MeshInstance mSpatialMeshInstance;          // +0x08
    std::uint8_t mRuntimeBlock10[0x8C];                   // +0x10
    // 12-byte gpg-style vector (no proxy lane); matches the binary triplet
    // initialized in WaveSystem ctor at 0x00888CB0 (mVec._Myfirst/_Mylast/_Myend).
    gpg::core::FastVector<WaveGenerator*> mWaveGenerators; // +0x9C
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

  struct WaveGeneratorLayoutVerifier
  {
    // Pending layout reconciliation: keep field-level annotations in class body.
  };
} // namespace moho
