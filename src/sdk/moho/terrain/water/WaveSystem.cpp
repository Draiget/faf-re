#include "moho/terrain/water/WaveSystem.h"

#include <algorithm>
#include <cmath>
#include <new>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/time/Timer.h"
#include "moho/math/MathReflection.h"
#include "moho/resource/CParticleTexture.h"

namespace
{
  constexpr std::int32_t kWaveSpatialRoutingMask = 0x800;
  constexpr float kWaveDefaultDissolveCutoff = 0.0f;
  constexpr float kWaveBoundsHalfHeight = 0.1f;
  constexpr float kPi = 3.1415925f;

  void ReleaseParticleTextureRef(moho::CParticleTexture*& texture) noexcept
  {
    if (texture == nullptr) {
      return;
    }

    static_cast<moho::CountedObject*>(texture)->ReleaseReferenceAtomic();
    texture = nullptr;
  }

  void AssignParticleTextureRef(moho::CParticleTexture*& slot, moho::CParticleTexture* const newTexture) noexcept
  {
    if (slot == newTexture) {
      return;
    }

    ReleaseParticleTextureRef(slot);
    slot = newTexture;
    if (slot != nullptr) {
      static_cast<moho::CountedObject*>(slot)->AddReferenceAtomic();
    }
  }

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
   * Address: 0x00887FC0 (FUN_00887FC0, sub_887FC0)
   *
   * What it does:
   * Reads texture paths and wave-emission scalar payload from one binary
   * reader lane, then refreshes runtime-dependent state.
   */
  void WaveGenerator::LoadSerializedState(gpg::BinaryReader& reader, const std::int32_t formatVersion)
  {
    reader.ReadString(&mPrimaryTexturePath);
    reader.ReadString(&mRampTexturePath);

    reader.ReadExact(mPosition.x);
    reader.ReadExact(mPosition.y);
    reader.ReadExact(mPosition.z);
    reader.ReadExact(mAngle);
    reader.ReadExact(mDirection.x);
    reader.ReadExact(mDirection.y);
    reader.ReadExact(mDirection.z);
    reader.ReadExact(mMinLifetime);
    reader.ReadExact(mMaxLifetime);
    reader.ReadExact(mMinUpdateInterval);
    reader.ReadExact(mMaxUpdateInterval);
    reader.ReadExact(mBeginSize);
    reader.ReadExact(mEndSize);

    if (formatVersion <= 51) {
      mRampValueScale = 1.0f;
      mMinFramerate = 1.0f;
      mMaxFramerate = 0.0f;
      mTextureSelectionRange = 1.0f;
    } else {
      reader.ReadExact(mRampValueScale);
      reader.ReadExact(mMinFramerate);
      reader.ReadExact(mMaxFramerate);
      reader.ReadExact(mTextureSelectionRange);
    }

    RefreshTextureHandlesAndSchedule();
  }

  /**
   * Address: 0x00888830 (FUN_00888830, sub_888830)
   *
   * What it does:
   * Recomputes spatial AABB/basis payload from wave-generator scalar lanes
   * and updates the attached spatial-db entry bounds.
   */
  void WaveGenerator::RebuildSpatialBounds()
  {
    const float sampledLifetime = static_cast<float>(MathGlobalRandomRange(mMinLifetime, mMaxLifetime));
    const float speedMagnitude = std::sqrt(
      (mDirection.x * mDirection.x) + (mDirection.y * mDirection.y) + (mDirection.z * mDirection.z)
    );
    const float dominantSize = std::max(mBeginSize, mEndSize);
    const float radius = (speedMagnitude * sampledLifetime) + (dominantSize * 0.5f);

    mBounds.Min.x = mPosition.x - radius;
    mBounds.Min.y = mPosition.y - kWaveBoundsHalfHeight;
    mBounds.Min.z = mPosition.z - radius;
    mBounds.Max.x = mPosition.x + radius;
    mBounds.Max.y = mPosition.y + kWaveBoundsHalfHeight;
    mBounds.Max.z = mPosition.z + radius;

    mBoundsCenter = mPosition;

    const float rotation = kPi - mAngle;
    const float c = std::cos(rotation);
    const float s = std::sin(rotation);
    mBoundsAxes.vX.x = c;
    mBoundsAxes.vX.y = 0.0f;
    mBoundsAxes.vX.z = s;
    mBoundsAxes.vY.x = 0.0f;
    mBoundsAxes.vY.y = 1.0f;
    mBoundsAxes.vY.z = 0.0f;
    mBoundsAxes.vZ.x = -s;
    mBoundsAxes.vZ.y = 0.0f;
    mBoundsAxes.vZ.z = c;

    mBoundsHalfExtents.x = radius;
    mBoundsHalfExtents.y = kWaveBoundsHalfHeight;
    mBoundsHalfExtents.z = radius;

    mSpatialEntry.UpdateBounds(mBounds);
  }

  /**
   * Address: 0x00888B30 (FUN_00888B30, sub_888B30)
   *
   * What it does:
   * Rebuilds texture handles from stored path lanes, randomizes initial
   * emission schedule, and refreshes spatial bounds.
   */
  void WaveGenerator::RefreshTextureHandlesAndSchedule()
  {
    CParticleTexture* const newPrimaryTexture = new (std::nothrow) CParticleTexture(mPrimaryTexturePath.c_str());
    AssignParticleTextureRef(mPrimaryTexture, newPrimaryTexture);

    CParticleTexture* const newRampTexture = new (std::nothrow) CParticleTexture(mRampTexturePath.c_str());
    AssignParticleTextureRef(mRampTexture, newRampTexture);

    const float nowSeconds = gpg::time::GetSystemTimer().ElapsedSeconds();
    const float randomInitialOffset = static_cast<float>(MathGlobalRandomRange(0.0f, mMaxUpdateInterval));
    mCurrentTime = static_cast<double>(nowSeconds - randomInitialOffset);
    mUpdateInterval = MathGlobalRandomRange(mMinUpdateInterval, mMaxUpdateInterval);

    RebuildSpatialBounds();
  }

  /**
   * Address: 0x00887BF0 (FUN_00887BF0, ??0WaveGenerator@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one wave generator, loads serialized lanes from reader, and
   * rebuilds texture/schedule/bounds runtime state.
   */
  WaveGenerator::WaveGenerator(
    SpatialDB_MeshInstance* const spatialStorage,
    const std::int32_t formatVersion,
    gpg::BinaryReader& reader
  )
    : mReserved04(0)
    , mSpatialEntry{nullptr, 0}
    , mBounds{}
    , mBoundsCenter{0.0f, 0.0f, 0.0f}
    , mBoundsAxes()
    , mBoundsHalfExtents{0.0f, 0.0f, 0.0f}
    , mReserved64(0)
    , mCurrentTime(0.0)
    , mUpdateInterval(0.0)
    , mPrimaryTexturePath()
    , mPrimaryTexture(nullptr)
    , mRampTexturePath()
    , mRampTexture(nullptr)
    , mPosition{0.0f, 0.0f, 0.0f}
    , mAngle(0.0f)
    , mDirection{0.0f, 0.0f, 0.0f}
    , mMinLifetime(0.0f)
    , mMaxLifetime(0.0f)
    , mMinUpdateInterval(0.0f)
    , mMaxUpdateInterval(0.0f)
    , mBeginSize(0.0f)
    , mEndSize(0.0f)
    , mRampValueScale(1.0f)
    , mMinFramerate(1.0f)
    , mMaxFramerate(1.0f)
    , mTextureSelectionRange(1.0f)
    , mTailPaddingFC{0, 0, 0, 0}
  {
    mSpatialEntry.Register(spatialStorage, this, kWaveSpatialRoutingMask);
    mSpatialEntry.UpdateDissolveCutoff(kWaveDefaultDissolveCutoff);
    LoadSerializedState(reader, formatVersion);
  }

  /**
   * Address: 0x00887D40 (FUN_00887D40, sub_887D40)
   *
   * What it does:
   * Initializes one wave generator directly from runtime parameter lanes,
   * then rebuilds texture handles, schedule timing, and spatial bounds.
   */
  WaveGenerator::WaveGenerator(
    SpatialDB_MeshInstance* const spatialStorage,
    const msvc8::string& primaryTexturePath,
    const msvc8::string& rampTexturePath,
    const Wm3::Vec3f& position,
    const float angle,
    const Wm3::Vec3f& direction,
    const Wm3::Vector2f& lifetimeRange,
    const Wm3::Vector2f& updateIntervalRange,
    const Wm3::Vector2f& sizeRange,
    const float rampValueScale,
    const Wm3::Vector2f& framerateRange,
    const float textureSelectionRange
  )
    : mReserved04(0)
    , mSpatialEntry{nullptr, 0}
    , mBounds{}
    , mBoundsCenter{0.0f, 0.0f, 0.0f}
    , mBoundsAxes()
    , mBoundsHalfExtents{0.0f, 0.0f, 0.0f}
    , mReserved64(0)
    , mCurrentTime(0.0)
    , mUpdateInterval(0.0)
    , mPrimaryTexturePath(primaryTexturePath)
    , mPrimaryTexture(nullptr)
    , mRampTexturePath(rampTexturePath)
    , mRampTexture(nullptr)
    , mPosition(position)
    , mAngle(angle)
    , mDirection(direction)
    , mMinLifetime(lifetimeRange.x)
    , mMaxLifetime(lifetimeRange.y)
    , mMinUpdateInterval(updateIntervalRange.x)
    , mMaxUpdateInterval(updateIntervalRange.y)
    , mBeginSize(sizeRange.x)
    , mEndSize(sizeRange.y)
    , mRampValueScale(rampValueScale)
    , mMinFramerate(framerateRange.x)
    , mMaxFramerate(framerateRange.y)
    , mTextureSelectionRange(textureSelectionRange)
    , mTailPaddingFC{0, 0, 0, 0}
  {
    mSpatialEntry.Register(spatialStorage, this, kWaveSpatialRoutingMask);
    mSpatialEntry.UpdateDissolveCutoff(kWaveDefaultDissolveCutoff);
    RefreshTextureHandlesAndSchedule();
  }

  /**
   * Address: 0x00887EC0 (FUN_00887EC0, sub_887EC0)
   *
   * What it does:
   * Releases texture references, resets texture paths, and clears spatial-db
   * registration state for this generator.
   */
  WaveGenerator::~WaveGenerator()
  {
    ReleaseParticleTextureRef(mRampTexture);
    mRampTexturePath.tidy(true, 0u);
    ReleaseParticleTextureRef(mPrimaryTexture);
    mPrimaryTexturePath.tidy(true, 0u);
  }

  /**
   * Address: 0x00888250 (FUN_00888250, ?Save@WaveGenerator@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
   *
   * What it does:
   * Stores texture paths and wave-emission scalar lanes in binary stream
   * order used by terrain save/load.
   */
  void WaveGenerator::Save(gpg::BinaryWriter& writer) const
  {
    writer.WriteString(mPrimaryTexturePath);
    writer.WriteString(mRampTexturePath);
    writer.Write(mPosition.x);
    writer.Write(mPosition.y);
    writer.Write(mPosition.z);
    writer.Write(mAngle);
    writer.Write(mDirection.x);
    writer.Write(mDirection.y);
    writer.Write(mDirection.z);
    writer.Write(mMinLifetime);
    writer.Write(mMaxLifetime);
    writer.Write(mMinUpdateInterval);
    writer.Write(mMaxUpdateInterval);
    writer.Write(mBeginSize);
    writer.Write(mEndSize);
    writer.Write(mRampValueScale);
    writer.Write(mMinFramerate);
    writer.Write(mMaxFramerate);
    writer.Write(mTextureSelectionRange);
  }

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
  {
    mSpatialMeshInstance.InitializeStorage();
  }

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
    mSpatialMeshInstance.DestroyStorage();
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

  /**
   * Address: 0x008899E0 (FUN_008899E0, ?Load@WaveSystem@Moho@@QAEXHHHAAVBinaryReader@gpg@@@Z)
   *
   * What it does:
   * Clears existing generators, resizes embedded spatial storage for current
   * map dimensions, then loads and appends serialized wave generators.
   */
  void WaveSystem::Load(
    const std::int32_t formatVersion,
    const std::int32_t mapHeight,
    const std::int32_t mapWidth,
    gpg::BinaryReader& reader
  )
  {
    ClearWaveGeneratorState();
    mSpatialMeshInstance.ResizeStorageForMap(mapWidth, mapHeight);

    std::int32_t generatorCount = 0;
    reader.ReadExact(generatorCount);
    if (generatorCount <= 0) {
      return;
    }

    for (std::int32_t index = 0; index < generatorCount; ++index) {
      WaveGenerator* const generator = new (std::nothrow) WaveGenerator(&mSpatialMeshInstance, formatVersion, reader);
      mWaveGenerators.push_back(generator);
    }
  }

  /**
   * Address: 0x00889AD0 (FUN_00889AD0, ?Save@WaveSystem@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
   *
   * What it does:
   * Writes generator count and each wave-generator payload in save order.
   */
  void WaveSystem::Save(gpg::BinaryWriter& writer) const
  {
    const std::int32_t generatorCount = static_cast<std::int32_t>(mWaveGenerators.size());
    writer.Write(generatorCount);

    for (WaveGenerator* const generator : mWaveGenerators) {
      generator->Save(writer);
    }
  }

  /**
   * Address: 0x00888E10 (FUN_00888E10, sub_888E10)
   *
   * What it does:
   * Allocates and appends one runtime wave generator from explicit parameter
   * lanes and returns the stored generator pointer.
   */
  WaveGenerator* WaveSystem::CreateWaveGenerator(
    const msvc8::string& primaryTexturePath,
    const msvc8::string& rampTexturePath,
    const Wm3::Vec3f& position,
    const float angle,
    const Wm3::Vec3f& direction,
    const Wm3::Vector2f& lifetimeRange,
    const Wm3::Vector2f& updateIntervalRange,
    const Wm3::Vector2f& sizeRange,
    const float rampValueScale,
    const Wm3::Vector2f& framerateRange,
    const float textureSelectionRange
  )
  {
    WaveGenerator* const generator = new (std::nothrow) WaveGenerator(
      &mSpatialMeshInstance,
      primaryTexturePath,
      rampTexturePath,
      position,
      angle,
      direction,
      lifetimeRange,
      updateIntervalRange,
      sizeRange,
      rampValueScale,
      framerateRange,
      textureSelectionRange
    );

    // Binary path appends even on allocation failure (stores nullptr).
    mWaveGenerators.push_back(generator);
    return generator;
  }
} // namespace moho
