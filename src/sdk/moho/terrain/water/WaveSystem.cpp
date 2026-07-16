#include "moho/terrain/water/WaveSystem.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <new>

#include <stdexcept>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/time/Timer.h"
#include "moho/math/MathReflection.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CRandomStream.h"

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

  /**
   * Address: 0x00887BB0 (FUN_00887BB0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `WaveGenerator`, forwarding through
   * non-deleting `WaveGenerator::~WaveGenerator` and optional storage release.
   */
  [[nodiscard]] moho::WaveGenerator* DestroyWaveGeneratorDeleting(
    moho::WaveGenerator* const generator,
    const unsigned char deleteFlag
  )
  {
    generator->~WaveGenerator();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(generator));
    }
    return generator;
  }

  /**
   * Address: 0x0088ACB0 (FUN_0088ACB0, sub_88ACB0)
   *
   * What it does:
   * Search-and-compact lane that walks a `WaveGenerator**` range and shifts
   * elements left to remove every occurrence of `target`. Records the new
   * compacted-end pointer through `outEnd`. The binary emits this body
   * out-of-line; wiring it through the named helper preserves the per-T
   * shape used by `WaveSystem::RemoveAndDeleteGenerator`.
   */
  [[nodiscard]] moho::WaveGenerator*** CompactWaveGeneratorPointerRangeWithoutTarget(
    moho::WaveGenerator*** const outEnd,
    moho::WaveGenerator** begin,
    moho::WaveGenerator** const end,
    moho::WaveGenerator* const target
  ) noexcept
  {
    moho::WaveGenerator** cursor = begin;
    while (cursor != end && *cursor != target) {
      ++cursor;
    }

    if (cursor == end) {
      *outEnd = cursor;
      return outEnd;
    }

    moho::WaveGenerator** write = cursor;
    for (moho::WaveGenerator** read = cursor + 1; read != end; ++read) {
      if (*read != target) {
        *write = *read;
        ++write;
      }
    }

    *outEnd = write;
    return outEnd;
  }

  /**
   * Address: 0x0088A7B0 (FUN_0088A7B0, sub_88A7B0)
   * Mangled: (out-of-line std::vector<Moho::WaveGenerator*>::_Insert_n grow lane)
   *
   * IDA signature:
   * void __userpurge sub_88A7B0(WaveGenerator **value@<eax>, VectorTriplet *vec, WaveGenerator **pos);
   *
   * What it does:
   * The reallocate/insert-one arm of `WaveSystem::mWaveGenerators`'s append
   * (the capacity-full path of the vector<WaveGenerator*>::push_back the engine
   * open-codes in WaveSystem::Load). It is the classic MSVC8 STL
   * `vector<T>::_Insert_n` shape specialised for a 4-byte pointer element and a
   * single inserted value:
   *   - Length guard: if the current size has reached 0x3FFFFFFF the growth
   *     would overflow the legacy 30-bit count field, so raise the standard
   *     "vector<T> too long" length-error (binary FUN_0088A9C0).
   *   - In-place-fit arm: when capacity already covers size+1, shift the live
   *     tail `[pos, end)` right by one slot and drop `value` at `pos`.
   *   - Grow arm: otherwise allocate a 1.5x-grown buffer (floored to size+1,
   *     capped at 0x3FFFFFFF), copy the head `[start, pos)`, place `value`,
   *     copy the tail `[pos, end)`, release the old storage, and rebind the
   *     `{start_, end_, capacity_}` triplet.
   *
   * The allocation forwards to `gpg::core::legacy::AllocateCheckedDwordLaneOrEmpty`
   * (binary FUN_00537F80 = the `newCap==0 ? operator new(0) : checked new(newCap*4)`
   * branch the binary inlines around FUN_0088AF50). The pointer element is
   * trivially relocatable, so the head/tail relocations are dword `memmove`s,
   * matching the binary's `memmove_s` lanes (FUN_0088AEE0 / FUN_0088AF20) and the
   * single-slot fill (FUN_0088A2E0).
   */
  moho::WaveGenerator** InsertWaveGeneratorWithGrow(
    gpg::core::FastVector<moho::WaveGenerator*>& vec,
    moho::WaveGenerator** const pos,
    moho::WaveGenerator* const value
  )
  {
    using Generator = moho::WaveGenerator*;

    Generator* const start = vec.start_;
    Generator* const end = vec.end_;
    Generator* const capacityEnd = vec.capacity_;

    constexpr std::size_t kMaxCount = 0x3FFFFFFFu;

    const std::size_t currentSize = static_cast<std::size_t>(end - start);
    const std::size_t currentCapacity = static_cast<std::size_t>(capacityEnd - start);

    // _Xlen guard: the legacy count field is 30-bit; refuse to grow past it.
    if (kMaxCount - currentSize < 1u) {
      throw std::length_error("vector<T> too long");
    }

    const std::size_t requiredSize = currentSize + 1u;

    if (currentCapacity >= requiredSize) {
      // In-place-fit arm: reserved capacity already covers the new element.
      const std::size_t tailCount = static_cast<std::size_t>(end - pos);
      if (tailCount == 0u) {
        // pos == end: the new slot is one past the live range.
        *end = value;
        vec.end_ = end + 1;
        return pos;
      }

      // Shift the live tail [pos, end) right by one slot, then drop value at pos.
      // (memmove is safe/overlap-correct and matches the binary's memmove_s lanes
      // for the 4-byte trivially-relocatable pointer element.)
      std::memmove(pos + 1, pos, tailCount * sizeof(Generator));
      vec.end_ = end + 1;
      *pos = value;
      return pos;
    }

    // Grow arm: 1.5x growth, floored to size+1, capped at 0x3FFFFFFF.
    std::size_t newCapacity = currentCapacity + (currentCapacity >> 1);
    if (kMaxCount - (currentCapacity >> 1) < currentCapacity) {
      // 1.5x would overflow the count field; fall back to the exact required size.
      newCapacity = requiredSize;
    }
    if (newCapacity < requiredSize) {
      newCapacity = requiredSize;
    }

    Generator* const newBuffer = static_cast<Generator*>(
      gpg::core::legacy::AllocateCheckedDwordLaneOrEmpty(static_cast<std::uint32_t>(newCapacity))
    );

    const std::size_t prefixCount = static_cast<std::size_t>(pos - start);
    if (prefixCount != 0u) {
      std::memmove(newBuffer, start, prefixCount * sizeof(Generator));
    }

    Generator* const insertSlot = newBuffer + prefixCount;
    *insertSlot = value;

    const std::size_t tailCount = static_cast<std::size_t>(end - pos);
    if (tailCount != 0u) {
      std::memmove(insertSlot + 1, pos, tailCount * sizeof(Generator));
    }

    if (start != nullptr) {
      ::operator delete(static_cast<void*>(start));
    }

    vec.start_ = newBuffer;
    vec.end_ = newBuffer + requiredSize;
    vec.capacity_ = newBuffer + newCapacity;
    return insertSlot;
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

      // Binary append shape (FUN_008899E0 @ 0x00889A72): fast in-place store when
      // storage is allocated and has spare capacity, otherwise route through the
      // grow lane by name. This is the vector<WaveGenerator*>::push_back the engine
      // open-codes as `insert(end(), 1, value)` on the capacity-full path.
      WaveGenerator** const first = mWaveGenerators.start_;
      WaveGenerator** const last = mWaveGenerators.end_;
      WaveGenerator** const capacityEnd = mWaveGenerators.capacity_;
      if (first != nullptr && static_cast<std::size_t>(last - first) < static_cast<std::size_t>(capacityEnd - first)) {
        *last = generator;
        mWaveGenerators.end_ = last + 1;
      } else {
        (void)InsertWaveGeneratorWithGrow(mWaveGenerators, last, generator);
      }
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

  /**
   * Address: 0x00888F20 (FUN_00888F20, sub_888F20)
   *
   * What it does:
   * Removes all cached references to `generator` from active wave-generator
   * storage and runs one deleting-destructor lane for that generator.
   */
  WaveGenerator* WaveSystem::RemoveAndDeleteGenerator(WaveGenerator* const generator)
  {
    WaveGenerator** const previousEnd = mWaveGenerators.end_;
    WaveGenerator** compactedEnd = previousEnd;

    // Inlined block from FUN_0088ACB0 (`sub_88ACB0`).
    (void)CompactWaveGeneratorPointerRangeWithoutTarget(
      &compactedEnd,
      mWaveGenerators.start_,
      previousEnd,
      generator
    );

    if (compactedEnd != previousEnd) {
      const std::ptrdiff_t trailingCount = static_cast<std::ptrdiff_t>(mWaveGenerators.end_ - previousEnd);
      WaveGenerator** updatedEnd = compactedEnd + trailingCount;
      if (trailingCount > 0) {
        std::memmove(
          compactedEnd,
          previousEnd,
          static_cast<std::size_t>(trailingCount) * sizeof(WaveGenerator*)
        );
      }
      mWaveGenerators.end_ = updatedEnd;
    }

    delete generator;
    return generator;
  }

  /**
   * Address: 0x00888560 (FUN_00888560, ?Update@WaveGenerator@Moho@@QAEXN@Z)
   *
   * IDA signature:
   * void __userpurge Moho::WaveGenerator::Update(WaveGenerator *this, double time);
   *
   * What it does:
   * When the randomized update interval has elapsed, emits one world particle:
   * seeds a `SWorldParticle` from the generator's texture handles and scalar
   * lanes, draws lifetime/framerate/texture-selection samples from the global
   * random stream (texture selection under `math_GlobalRandomMutex`), appends the
   * particle to `sWorldParticles`, then reschedules the next emission time.
   */
  void WaveGenerator::Update(double time)
  {
    if (time - mCurrentTime <= mUpdateInterval) {
      return;
    }

    SWorldParticle particle;
    particle.mTypeTag = "TRampAnimateFlat";
    (void)AssignCountedParticleTexturePtr(&particle.mTexture, mPrimaryTexture);
    (void)AssignCountedParticleTexturePtr(&particle.mRampTexture, mRampTexture);

    particle.mPos = mPosition;
    particle.mBlendMode = SWorldParticle::BlendMode::Mode0;
    particle.mLifetime = static_cast<float>(MathGlobalRandomRange(mMinLifetime, mMaxLifetime));
    particle.mBeginSize = mBeginSize;
    particle.mEndSize = mEndSize;
    particle.mAngle = mAngle;
    particle.mDir = mDirection;
    particle.mFramerate = static_cast<float>(MathGlobalRandomRange(mMinFramerate, mMaxFramerate));
    particle.mValue1 = static_cast<float>(1.0 / mRampValueScale);
    particle.mValue3 = static_cast<float>(1.0 / mTextureSelectionRange);

    // Random texture selection: scale the raw MT sample by the (integer-truncated)
    // texture-selection range in fixed point (high 32 bits of the 64-bit product),
    // then normalize by mValue3 (== 1 / mTextureSelectionRange). Only the raw draw
    // is taken under the global random mutex, matching the binary.
    const std::uint32_t textureSelectionScale =
      static_cast<std::uint32_t>(static_cast<std::int64_t>(mTextureSelectionRange));
    std::uint32_t randomSample = 0u;
    {
      boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
      randomSample = math_GlobalRandomStream.twister.NextUInt32();
    }
    const std::uint32_t scaledSelection = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(textureSelectionScale) * static_cast<std::uint64_t>(randomSample)) >> 32);
    particle.mTextureSelection =
      static_cast<float>(static_cast<double>(scaledSelection) * static_cast<double>(particle.mValue3));
    particle.mRampSelection = 0.0f;

    sWorldParticles.AddWorldParticle(particle, nullptr);

    mUpdateInterval = MathGlobalRandomRange(mMinUpdateInterval, mMaxUpdateInterval);
    mCurrentTime = time;
  }

  /**
   * Address: 0x00889900 (FUN_00889900, ?Update@WaveSystem@Moho@@QAEXABVGeomCamera3@2@MH@Z)
   *
   * IDA signature:
   * void __userpurge Moho::WaveSystem::Update(WaveSystem *this, const GeomCamera3 *cam,
   *   float elapsedSeconds, int tick);
   *
   * What it does:
   * Per-frame wave update: no-ops when there are no registered generators or the
   * frame-delta guard fails; every 5th tick rebuilds the in-view generator cache
   * from the spatial DB; then advances each cached generator's emission at the
   * current system time.
   */
  void WaveSystem::Update(const GeomCamera3& camera, const float elapsedSeconds, const std::int32_t tick)
  {
    if (mWaveGenerators.empty() || elapsedSeconds > 200.0f) {
      return;
    }

    const double now = gpg::time::GetSystemTimer().ElapsedSeconds();

    if (tick % 5 == 0) {
      mGeneratorCache.clear();
      mSpatialMeshInstance.CollectInView(
        const_cast<GeomCamera3*>(&camera),
        reinterpret_cast<gpg::fastvector<UserEntity*>&>(mGeneratorCache),
        static_cast<EEntityType>(ENTITYTYPE_Entity));
    }

    for (WaveGenerator** it = mGeneratorCache.begin(); it != mGeneratorCache.end(); ++it) {
      (*it)->Update(now);
    }
  }
} // namespace moho
