#include "moho/particles/ParticleRenderBuckets.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/ParticleRenderWorkItem.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/particles/SWorldTrail.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/SParticleBuffer.h"

namespace
{
  constexpr const char* kParticleCapExceededLog = "Particle cap exceeded, discarding excess.\n";
  constexpr std::int32_t kTrailVerticesPerSegment = 4;
  constexpr std::int32_t kTrailIndicesPerSegment = 6;
  constexpr std::int32_t kSharedTrailQuadCapacity = 0x4000;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;

  struct SParticleInstance
  {
    float posX = 0.0f;                 // +0x00
    float posY = 0.0f;                 // +0x04
    float posZ = 0.0f;                 // +0x08
    float angle = 0.0f;                // +0x0C
    float beginSize = 0.0f;            // +0x10
    float sizeDeltaPerFrame = 0.0f;    // +0x14
    float dirX = 0.0f;                 // +0x18
    float dirY = 0.0f;                 // +0x1C
    float dirZ = 0.0f;                 // +0x20
    float rotationCurve = 0.0f;        // +0x24
    float accelX = 0.0f;               // +0x28
    float accelY = 0.0f;               // +0x2C
    float accelZ = 0.0f;               // +0x30
    float interop = 0.0f;              // +0x34
    float lifetime = 0.0f;             // +0x38
    float framerate = 0.0f;            // +0x3C
    float value1 = 0.0f;               // +0x40
    float textureSelection = 0.0f;     // +0x44
    float rampSelection = 0.0f;        // +0x48
    float value3 = 0.0f;               // +0x4C
    float resistance = 0.0f;           // +0x50
    float inverseResistance = 0.0f;    // +0x54
    float inverseResistanceSq = 0.0f;  // +0x58
  };

  static_assert(sizeof(SParticleInstance) == 0x5C, "SParticleInstance size must be 0x5C");

  /**
   * Address: 0x00496710 (FUN_00496710, sub_496710)
   *
   * What it does:
   * Returns the max trail-segment capacity lane from one pooled trail-segment
   * render buffer.
   */
  [[nodiscard]] std::uint32_t GetTrailSegmentBufferMaxSegments(
    const moho::STrailSegmentBuffer& segmentBuffer
  ) noexcept
  {
    return segmentBuffer.maxSegments;
  }

  /**
   * Address: 0x004987C0 (FUN_004987C0, sub_4987C0)
   *
   * What it does:
   * Recreates one vertex-sheet slot from device resources with fixed stream
   * usage token `1`, releasing the replaced sheet when the pointer changes.
   */
  moho::ID3DVertexSheet* RecreateVertexSheetWithUsageTokenOne(
    moho::ID3DVertexSheet*& vertexSheet,
    moho::CD3DVertexFormat* const vertexFormat,
    const std::int32_t streamFrequencyToken
  )
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DDeviceResources* const resources = device->GetResources();
    moho::ID3DVertexSheet* const newSheet = resources->NewVertexSheet(1U, streamFrequencyToken, vertexFormat);

    moho::ID3DVertexSheet* const oldSheet = vertexSheet;
    if (newSheet != oldSheet && oldSheet != nullptr) {
      delete oldSheet;
    }

    vertexSheet = newSheet;
    return vertexSheet;
  }

  /**
   * Address: 0x00496750 (FUN_00496750, sub_496750)
   *
   * What it does:
   * Locks one trail-segment vertex-stream range from start vertex `0` and
   * stores the mapped pointer on the pooled segment buffer lane.
   */
  void* LockTrailSegmentVertexRangeFromStart(
    moho::STrailSegmentBuffer& segmentBuffer,
    const std::int32_t segmentCount
  )
  {
    moho::ID3DVertexStream* const vertexStream = segmentBuffer.vertexSheet->GetVertStream(0U);
    void* const mappedRange = vertexStream->Lock(0, 4 * segmentCount, false, true);
    segmentBuffer.mappedVertexData = mappedRange;
    return mappedRange;
  }

  /**
   * Address: 0x00496780 (FUN_00496780, sub_496780)
   *
   * What it does:
   * Locks one trail-segment vertex-stream subrange and stores the mapped
   * pointer on the pooled segment buffer lane.
   */
  void* LockTrailSegmentVertexRangeSubspan(
    moho::STrailSegmentBuffer& segmentBuffer,
    const std::int32_t startSegmentIndex,
    const std::int32_t segmentCount
  )
  {
    moho::ID3DVertexStream* const vertexStream = segmentBuffer.vertexSheet->GetVertStream(0U);
    void* const mappedRange = vertexStream->Lock(4 * startSegmentIndex, 4 * segmentCount, true, false);
    segmentBuffer.mappedVertexData = mappedRange;
    return mappedRange;
  }

  /**
   * Address: 0x004967E0 (FUN_004967E0, sub_4967E0)
   *
   * What it does:
   * Draws one trail segment batch from a pooled trail-segment vertex sheet by
   * binding shared quad indices and issuing one triangle-list draw call.
   */
  void DrawTrailSegmentBatch(
    const moho::STrailSegmentBuffer& segmentBuffer,
    const std::int32_t segmentCount,
    const std::int32_t startSegmentIndex
  )
  {
    if (segmentCount <= 0) {
      return;
    }

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DIndexSheet* const sharedTrailIndexSheet = moho::GetSharedTrailQuadIndexSheet();
    if (device == nullptr || sharedTrailIndexSheet == nullptr) {
      return;
    }

    moho::SD3DVertexRange vertexSheetView{};
    vertexSheetView.sheet = segmentBuffer.vertexSheet;
    // Binary (0x004967E0): +0x04 (BaseVertexIndex) = 4 * startSegment, +0x08 (MinIndex) = 0.
    vertexSheetView.startVertex = 0;
    vertexSheetView.baseVertex = kTrailVerticesPerSegment * startSegmentIndex;
    vertexSheetView.endVertex = (kTrailVerticesPerSegment * segmentCount) - 1;

    moho::SD3DIndexRange indexSheetView{};
    indexSheetView.sheet = sharedTrailIndexSheet;
    indexSheetView.startIndex = kTrailIndicesPerSegment * (kSharedTrailQuadCapacity - segmentCount);
    indexSheetView.indexCount = kTrailIndicesPerSegment * segmentCount;

    std::int32_t primitiveType = kTriangleListPrimitiveType;
    (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);
  }

  constexpr std::uint8_t kTrailSegmentPoolColorRed = 0U;
  constexpr std::uint8_t kTrailSegmentPoolColorBlack = 1U;


  [[nodiscard]] bool AppendInterval(
    moho::SParticleRenderWorkItem& workItem, const float beginFrame, const float lifeFrames
  )
  {
    // `msvc8::vector<SParticleRenderInterval>::push_back` (0x00496950, cited on Vector.h).
    const moho::SParticleRenderInterval intervalValue{beginFrame, lifeFrames};
    workItem.mIntervals.push_back(intervalValue);
    return true;
  }

  /**
   * What it does:
   * One vertex of a trail ribbon quad, 13 floats wide. Four of these are
   * emitted per `SWorldTrail`: the two ribbon ends, each duplicated for the two
   * sides of the ribbon, which the two sides distinguish by the sign of
   * `tangent` and by `texV`.
   */
  struct STrailVertex
  {
    Wm3::Vector3<float> position;   // +0x00  the ribbon end this vertex sits on
    Wm3::Vector3<float> tangent;    // +0x0C  that end's tangent, negated on one side
    float age = 0.0f;               // +0x18  that end's age in frames
    float lifetime = 0.0f;          // +0x1C  SWorldTrail::mLifetime
    float texU = 0.0f;              // +0x20  that end's texture coordinate
    float size = 0.0f;              // +0x24  SWorldTrail::mSize
    float reserved = 0.0f;          // +0x28  always zero
    float texV = 0.0f;              // +0x2C  1 on the negated side, 0 on the other
    float emitterAge = 0.0f;        // +0x30  SWorldTrail::mEmitterAge
  };

  static_assert(sizeof(STrailVertex) == 0x34, "STrailVertex size must be 0x34");

  /// Vertices emitted per trail segment: two ribbon ends, two sides each.
  inline constexpr std::size_t kTrailSegmentVertexCount = 4U;

  /**
   * What it does:
   * Expands one trail segment into its four ribbon vertices. The binary writes
   * the 52 floats one by one out of the record read as `float[20]`; every index
   * it uses is a named field, and the pattern is two ends x two sides:
   *
   *   vertex 0 : start end, negated tangent, texV 1
   *   vertex 1 : end end,   negated tangent, texV 1
   *   vertex 2 : end end,   plain tangent,   texV 0
   *   vertex 3 : start end, plain tangent,   texV 0
   *
   * so the shader offsets each vertex along `tangent x view` by `size` and
   * interpolates `texU` between the ends.
   */
  void PackTrailSegmentQuadVertices(STrailVertex* const outVertices, const moho::SWorldTrail& trail)
  {
    const auto emit = [&trail, outVertices](
      const std::size_t index,
      const Wm3::Vector3<float>& position,
      const Wm3::Vector3<float>& tangent,
      const float age,
      const float texU,
      const float texV
    ) noexcept {
      STrailVertex& vertex = outVertices[index];
      vertex.position = position;
      vertex.tangent = tangent;
      vertex.age = age;
      vertex.lifetime = trail.mLifetime;
      vertex.texU = texU;
      vertex.size = trail.mSize;
      vertex.reserved = 0.0f;
      vertex.texV = texV;
      vertex.emitterAge = trail.mEmitterAge;
    };

    const Wm3::Vector3<float> startTangent = trail.mStartTangent;
    const Wm3::Vector3<float> endTangent = trail.mEndTangent;
    const Wm3::Vector3<float> negatedStartTangent{-startTangent.x, -startTangent.y, -startTangent.z};
    const Wm3::Vector3<float> negatedEndTangent{-endTangent.x, -endTangent.y, -endTangent.z};

    emit(0U, trail.mStartPos, negatedStartTangent, trail.mStartAge, trail.mTexCoordStart, 1.0f);
    emit(1U, trail.mEndPos, negatedEndTangent, trail.mEndAge, trail.mTexCoordEnd, 1.0f);
    emit(2U, trail.mEndPos, endTangent, trail.mEndAge, trail.mTexCoordEnd, 0.0f);
    emit(3U, trail.mStartPos, startTangent, trail.mStartAge, trail.mTexCoordStart, 0.0f);
  }



  /**
   * Address: 0x00497C70 (FUN_00497C70, sub_497C70)
   *
   * What it does:
   * Writes one pointer-sized value to caller output storage.
   */
  const void** WritePointerToOutputSlot(
    const void** const outPointer,
    const void* const value
  ) noexcept
  {
    *outPointer = value;
    return outPointer;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00493480 (FUN_00493480, sub_493480)
   *
   * What it does:
   * Initializes one particle render bucket key/runtime lane from one world
   * particle payload and stores owner context.
   */
  SParticleRenderBucket* InitializeParticleRenderBucketFromWorldParticle(
    SParticleRenderBucket& bucket,
    const SWorldParticle& particle,
    CWorldParticles* const owner
  )
  {
    bucket.texture0.reset();
    bucket.texture1.reset();
    bucket.tag = msvc8::string{};
    bucket.blendMode = 0;
    bucket.zMode = 0;
    bucket.pendingParticles.clear();
    bucket.activeWorkItems.clear();
    bucket.owner = owner;

    bucket.dragEnabled = particle.mDragEnabled;

    CParticleTexture::TextureResourceHandle texture0{};
    if (particle.mTexture.tex != nullptr) {
      particle.mTexture.tex->GetTexture(texture0);
    }
    bucket.texture0 = texture0;

    CParticleTexture::TextureResourceHandle texture1{};
    if (particle.mRampTexture.tex != nullptr) {
      particle.mRampTexture.tex->GetTexture(texture1);
    }
    bucket.texture1 = texture1;

    bucket.tag.assign(particle.mTypeTag, 0U, msvc8::string::npos);
    bucket.blendMode = static_cast<std::int32_t>(particle.mBlendMode);
    bucket.zMode = static_cast<std::int32_t>(particle.mZMode);
    return &bucket;
  }

  /**
   * Address: 0x00494140 (FUN_00494140, sub_494140)
   *
   * What it does:
   * Initializes one trail render bucket key/runtime lane from one trail payload
   * and stores owner context.
   */
  STrailRenderBucket* InitializeTrailRenderBucketFromTrail(
    STrailRenderBucket& bucket,
    const SWorldTrail& trail,
    CWorldParticles* const owner
  )
  {
    bucket.texture0.reset();
    bucket.texture1.reset();
    bucket.tag = msvc8::string{};
    bucket.blendMode = 0;
    bucket.renderStartIndex = 0U;
    bucket.pendingTrails.clear();
    bucket.activeWorkItems.clear();
    bucket.owner = owner;

    CParticleTexture::TextureResourceHandle texture0{};
    if (trail.mTexture.tex != nullptr) {
      trail.mTexture.tex->GetTexture(texture0);
    }
    bucket.texture0 = texture0;

    CParticleTexture::TextureResourceHandle texture1{};
    if (trail.mRampTexture.tex != nullptr) {
      trail.mRampTexture.tex->GetTexture(texture1);
    }
    bucket.texture1 = texture1;

    bucket.tag.assign_owned(trail.mTypeTag != nullptr ? trail.mTypeTag : "");
    bucket.blendMode = trail.mBlendMode;
    return &bucket;
  }

  /**
   * Address: 0x00493210 (FUN_00493210, sub_493210)
   *
   * What it does:
   * Uploads a bounded batch of pending world particles into one particle
   * work-item instance stream for the current frame.
   */
  void UploadPendingParticlesIntoWorkItem(
    SParticleRenderWorkItem& workItem,
    const float frameDelta,
    msvc8::vector<SWorldParticle>& pendingParticles
  )
  {
    const std::size_t pendingCount = pendingParticles.size();
    if (pendingCount == 0U) {
      return;
    }

    const std::size_t intervalCount =
      workItem.mIntervals.size();

    std::size_t maxUploadCount = pendingCount;
    if (workItem.mIntervalCapacityHint > intervalCount) {
      maxUploadCount = std::min(maxUploadCount, static_cast<std::size_t>(workItem.mIntervalCapacityHint) - intervalCount);
    } else {
      maxUploadCount = 0U;
    }

    if (maxUploadCount == 0U) {
      return;
    }

    auto* const particleBuffer = static_cast<ParticleBuffer*>(workItem.mParticleBuffer);
    if (particleBuffer == nullptr) {
      pendingParticles.clear();
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervals.clear();
      return;
    }

    ParticleBuffer::Instanced* lockedInstances = nullptr;
    if (workItem.mRenderStartIndex != 0U) {
      lockedInstances = particleBuffer->Lock(static_cast<int>(workItem.mRenderStartIndex), static_cast<int>(maxUploadCount));
    } else {
      lockedInstances = particleBuffer->Lock(static_cast<int>(maxUploadCount));
    }

    if (lockedInstances == nullptr) {
      pendingParticles.clear();
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervals.clear();
      return;
    }

    for (std::size_t index = 0U; index < maxUploadCount; ++index) {
      SWorldParticle& particle = pendingParticles[index];
      particle.mInterop += frameDelta;
      (void)AppendInterval(workItem, particle.mInterop, particle.mLifetime);

      auto* const instance = reinterpret_cast<SParticleInstance*>(
        reinterpret_cast<std::uint8_t*>(lockedInstances) + (index * sizeof(ParticleBuffer::Instanced))
      );

      instance->posX = particle.mPos.x;
      instance->posY = particle.mPos.y;
      instance->posZ = particle.mPos.z;
      instance->angle = particle.mAngle;
      instance->beginSize = particle.mBeginSize;
      instance->sizeDeltaPerFrame = (particle.mEndSize - particle.mBeginSize) * (1.0f / particle.mLifetime);
      instance->dirX = particle.mDir.x;
      instance->dirY = particle.mDir.y;
      instance->dirZ = particle.mDir.z;
      instance->rotationCurve = particle.mRotationCurve;
      instance->accelX = particle.mAccel.x;
      instance->accelY = particle.mAccel.y;
      instance->accelZ = particle.mAccel.z;
      instance->interop = particle.mInterop;
      instance->lifetime = particle.mLifetime;
      instance->framerate = particle.mFramerate;
      instance->value1 = particle.mValue1;
      instance->textureSelection = particle.mTextureSelection;
      instance->rampSelection = particle.mRampSelection;
      instance->value3 = particle.mValue3;
      instance->resistance = particle.mResistance;
      instance->inverseResistance = 1.0f / particle.mResistance;
      instance->inverseResistanceSq = instance->inverseResistance * instance->inverseResistance;
    }

    workItem.mRenderStartIndex += static_cast<std::uint32_t>(maxUploadCount);
    // `erase(first, last)` (0x004956B0, cited on Vector.h): the uploaded prefix goes.
    (void)pendingParticles.erase(pendingParticles.begin(), pendingParticles.begin() + maxUploadCount);
    particleBuffer->UnlockInstanceBuffer();
  }

  /**
   * Address: 0x00493720 (FUN_00493720, sub_493720)
   *
   * What it does:
   * Returns active particle work-item buffers to the owner pool and destroys
   * the work-item objects.
   */
  void RecycleAndDestroyParticleBucketWorkItems(SParticleRenderBucket& bucket)
  {
    for (SParticleRenderWorkItem* const workItem : bucket.activeWorkItems) {
      if (workItem == nullptr) {
        continue;
      }
      bucket.owner->ReleaseParticleBuffer(static_cast<ParticleBuffer*>(workItem->mParticleBuffer));
      (void)DestroyParticleRenderWorkItem(workItem);
    }
    bucket.activeWorkItems.clear();
  }

  /**
   * Address: 0x00493620 (FUN_00493620, sub_493620)
   *
   * What it does:
   * Releases one particle render bucket runtime lane including key state,
   * pending payload lanes, and active work-item lanes.
   */
  void DestroyParticleRenderBucket(SParticleRenderBucket& bucket)
  {
    RecycleAndDestroyParticleBucketWorkItems(bucket);
    // The two vectors' `_Tidy` (0x004972E0 for the particles, cited on Vector.h).
    bucket.activeWorkItems.tidy();
    bucket.pendingParticles.tidy();

    bucket.tag.tidy(true, 0U);
    bucket.texture1.reset();
    bucket.texture0.reset();
  }

  /**
   * Address: 0x004943E0 (FUN_004943E0, sub_4943E0)
   *
   * What it does:
   * Returns active trail work-item segment buffers to the owner pool and
   * destroys the work-item objects.
   */
  void RecycleAndDestroyTrailBucketWorkItems(STrailRenderBucket& bucket)
  {
    for (SParticleRenderWorkItem* const workItem : bucket.activeWorkItems) {
      if (workItem == nullptr) {
        continue;
      }
      if (bucket.owner != nullptr && workItem->mParticleBuffer != nullptr) {
        auto* const segmentBuffer = static_cast<STrailSegmentBuffer*>(workItem->mParticleBuffer);
        bucket.owner->ReleaseTrailSegmentBuffer(segmentBuffer);
      }

      ResetParticleRenderWorkItemIntervals(*workItem);
      ::operator delete(workItem);
    }
    bucket.activeWorkItems.clear();
  }

  /**
   * Address: 0x004942E0 (FUN_004942E0, sub_4942E0)
   *
   * What it does:
   * Releases one trail render bucket runtime lane including key state,
   * pending trail payload lanes, and active work-item lanes.
   */
  void DestroyTrailRenderBucket(STrailRenderBucket& bucket)
  {
    RecycleAndDestroyTrailBucketWorkItems(bucket);
    // The two vectors' `_Tidy` (0x00497490 for the trails: each trail's
    // destructor releases its textures; cited on Vector.h).
    bucket.activeWorkItems.tidy();
    bucket.pendingTrails.tidy();

    bucket.tag.tidy(true, 0U);
    bucket.texture1.reset();
    bucket.texture0.reset();
  }

  /**
   * Address: 0x004937E0 (FUN_004937E0, sub_4937E0)
   *
   * What it does:
   * Advances active particle work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredParticleBucketWorkItems(SParticleRenderBucket& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.empty()) {
      return;
    }
    SParticleRenderWorkItem** writeIt = bucket.activeWorkItems.begin();
    for (SParticleRenderWorkItem** readIt = bucket.activeWorkItems.begin(); readIt != bucket.activeWorkItems.end(); ++readIt) {
      SParticleRenderWorkItem* const workItem = *readIt;
      if (workItem == nullptr) {
        continue;
      }

      if (AdvanceParticleRenderWorkItemCursorToFrame(*workItem, frameValue)) {
        bucket.owner->ReleaseParticleBuffer(static_cast<ParticleBuffer*>(workItem->mParticleBuffer));
        (void)DestroyParticleRenderWorkItem(workItem);
        continue;
      }

      *writeIt = workItem;
      ++writeIt;
    }

    // Pointer elements: dropping the tail is `erase(writeIt, end())`.
    (void)bucket.activeWorkItems.erase(writeIt, bucket.activeWorkItems.end());
  }

  /**
   * Address: 0x00493940 (FUN_00493940, sub_493940)
   *
   * What it does:
   * Ensures active work items exist for pending particle payload and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillParticleBucketWorkItems(SParticleRenderBucket& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = bucket.activeWorkItems.size();
    if (workItemCount != 0U) {
      SParticleRenderWorkItem* const tailWorkItem = bucket.activeWorkItems.back();
      if (tailWorkItem != nullptr) {
        UploadPendingParticlesIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingParticles);
      }
    }

    while (!bucket.pendingParticles.empty()) {
      ParticleBuffer* const pooledBuffer = bucket.owner->AcquireParticleBuffer();
      if (pooledBuffer == nullptr) {
        gpg::Logf(kParticleCapExceededLog);
        bucket.pendingParticles.clear();
        return false;
      }

      auto* const newWorkItem = static_cast<SParticleRenderWorkItem*>(::operator new(sizeof(SParticleRenderWorkItem)));
      (void)InitializeParticleRenderWorkItem(
        *newWorkItem,
        static_cast<std::uint32_t>(pooledBuffer->mMaxParticles),
        pooledBuffer
      );

      bucket.activeWorkItems.push_back(newWorkItem);

      UploadPendingParticlesIntoWorkItem(*newWorkItem, frameDelta, bucket.pendingParticles);
    }

    return true;
  }

  /**
   * Address: 0x00493C30 (FUN_00493C30, func_RenderParticle2)
   *
   * What it does:
   * Selects the particle technique, then renders active particle work items in
   * reverse order when the current bucket is allowed to draw.
   */
  bool RenderParticleBucket(SParticleRenderBucket& bucket, const float frameValue, const bool onlyTLight)
  {
    PruneExpiredParticleBucketWorkItems(bucket, frameValue);
    (void)EnsureAndFillParticleBucketWorkItems(bucket, frameValue);

    const std::size_t activeWorkItemCount = bucket.activeWorkItems.size();
    if (activeWorkItemCount == 0U) {
      return false;
    }

    if (onlyTLight && bucket.tag.compare(0U, bucket.tag.size(), "TLight", 6U) != 0) {
      return false;
    }

    bucket.SelectTechnique();

    for (std::size_t index = activeWorkItemCount; index > 0U; --index) {
      SParticleRenderWorkItem* const workItem = bucket.activeWorkItems[index - 1U];
      if (workItem == nullptr || workItem->mParticleBuffer == nullptr) {
        continue;
      }

      auto* const particleBuffer = static_cast<ParticleBuffer*>(workItem->mParticleBuffer);
      const std::uint32_t startIndex = workItem->mIntervalCursor;
      const std::uint32_t renderCount =
        (workItem->mRenderStartIndex > startIndex) ? (workItem->mRenderStartIndex - startIndex) : 0U;
      if (renderCount > 0) {
        particleBuffer->Render(static_cast<int>(renderCount), static_cast<int>(startIndex));
      }
    }

    return true;
  }

  /**
   * Address: 0x00493DA0 (FUN_00493DA0, sub_493DA0)
   *
   * What it does:
   * Uploads a bounded batch of pending trail payloads into one trail work-item
   * instance stream for the current frame.
   */
  bool UploadPendingTrailsIntoWorkItem(
    SParticleRenderWorkItem& workItem,
    const float frameDelta,
    msvc8::vector<SWorldTrail>& pendingTrails
  )
  {
    const std::size_t pendingCount = pendingTrails.size();
    if (pendingCount == 0U) {
      return false;
    }

    const std::size_t intervalCount =
      workItem.mIntervals.size();

    std::size_t maxUploadCount = pendingCount;
    if (workItem.mIntervalCapacityHint > intervalCount) {
      maxUploadCount = std::min(maxUploadCount, static_cast<std::size_t>(workItem.mIntervalCapacityHint) - intervalCount);
    } else {
      maxUploadCount = 0U;
    }

    if (maxUploadCount == 0U) {
      return pendingCount != 0U;
    }

    auto* const segmentBuffer = static_cast<STrailSegmentBuffer*>(workItem.mParticleBuffer);
    if (segmentBuffer == nullptr) {
      pendingTrails.clear();
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervals.clear();
      return false;
    }

    void* lockedVertices = nullptr;
    if (workItem.mRenderStartIndex != 0U) {
      lockedVertices = LockTrailSegmentVertexRangeSubspan(
        *segmentBuffer,
        static_cast<int>(workItem.mRenderStartIndex),
        static_cast<int>(maxUploadCount)
      );
    } else {
      lockedVertices = LockTrailSegmentVertexRangeFromStart(*segmentBuffer, static_cast<int>(maxUploadCount));
    }

    if (lockedVertices == nullptr) {
      pendingTrails.clear();
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervals.clear();
      return false;
    }

    auto* out = static_cast<STrailVertex*>(lockedVertices);
    SWorldTrail* const trailEnd = pendingTrails.begin() + maxUploadCount;

    for (SWorldTrail* trail = pendingTrails.begin(); trail != trailEnd; ++trail) {
      // The work-item interval opens at the older of the two ends and runs for
      // one frame past the segment's lifetime.
      const float beginFrame = std::max(trail->mStartAge, trail->mEndAge) + frameDelta;
      const float lifeFrames = trail->mLifetime + 1.0f;
      (void)AppendInterval(workItem, beginFrame, lifeFrames);

      // Age the segment by this frame before it is packed: both ribbon ends and
      // the emitter-age lane, but not the lifetime.
      const float frameStep = frameDelta + 1.0f;
      trail->mStartAge += frameStep;
      trail->mEndAge += frameStep;
      trail->mEmitterAge += frameStep;

      PackTrailSegmentQuadVertices(out, *trail);
      out += kTrailSegmentVertexCount;
    }

    workItem.mRenderStartIndex += static_cast<std::uint32_t>(maxUploadCount);
    // `erase(first, last)` (0x00495850, cited on Vector.h): the uploaded prefix goes.
    (void)pendingTrails.erase(pendingTrails.begin(), pendingTrails.begin() + maxUploadCount);

    if (segmentBuffer->mappedVertexData != nullptr) {
      if (moho::ID3DVertexStream* const vertexStream = segmentBuffer->vertexSheet->GetVertStream(0U); vertexStream != nullptr) {
        vertexStream->Unlock();
      }
      segmentBuffer->mappedVertexData = nullptr;
    }

    return true;
  }

  /**
   * Address: 0x00494480 (FUN_00494480, sub_494480)
   *
   * What it does:
   * Advances active trail work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredTrailBucketWorkItems(STrailRenderBucket& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.empty()) {
      return;
    }
    SParticleRenderWorkItem** writeIt = bucket.activeWorkItems.begin();
    for (SParticleRenderWorkItem** readIt = bucket.activeWorkItems.begin(); readIt != bucket.activeWorkItems.end(); ++readIt) {
      SParticleRenderWorkItem* const workItem = *readIt;
      if (workItem == nullptr) {
        continue;
      }

      if (AdvanceParticleRenderWorkItemCursorToFrame(*workItem, frameValue)) {
        if (bucket.owner != nullptr && workItem->mParticleBuffer != nullptr) {
          bucket.owner->ReleaseTrailSegmentBuffer(static_cast<STrailSegmentBuffer*>(workItem->mParticleBuffer));
        }

        (void)DestroyParticleRenderWorkItem(workItem);
        continue;
      }

      *writeIt = workItem;
      ++writeIt;
    }

    // Pointer elements: dropping the tail is `erase(writeIt, end())`.
    (void)bucket.activeWorkItems.erase(writeIt, bucket.activeWorkItems.end());
  }

  /**
   * Address: 0x004945C0 (FUN_004945C0, sub_4945C0)
   *
   * What it does:
   * Ensures active trail work items exist for pending trail payloads and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillTrailBucketWorkItems(STrailRenderBucket& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = bucket.activeWorkItems.size();
    if (workItemCount != 0U) {
      SParticleRenderWorkItem* const tailWorkItem = bucket.activeWorkItems.back();
      if (tailWorkItem != nullptr) {
        (void)UploadPendingTrailsIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingTrails);
      }
    }

    while (!bucket.pendingTrails.empty()) {
      STrailSegmentBuffer* const pooledBuffer = bucket.owner->AcquireTrailSegmentBuffer();
      if (pooledBuffer == nullptr) {
        gpg::Logf("Wow!  Ran out of segment buffers from the pool, discarding segments!\n");
        bucket.pendingTrails.clear();
        return false;
      }
      auto* const newWorkItem = static_cast<SParticleRenderWorkItem*>(::operator new(sizeof(SParticleRenderWorkItem)));
      (void)InitializeParticleRenderWorkItem(
        *newWorkItem,
        GetTrailSegmentBufferMaxSegments(*pooledBuffer),
        pooledBuffer
      );

      bucket.activeWorkItems.push_back(newWorkItem);

      (void)UploadPendingTrailsIntoWorkItem(*newWorkItem, frameDelta, bucket.pendingTrails);
    }

    return true;
  }

  /**
   * Address: 0x00494850 (FUN_00494850, func_RenderParticle)
   *
   * What it does:
   * Selects the trail technique, then renders active trail work items in order
   * when the current bucket is allowed to draw.
   */
  bool RenderTrailBucket(STrailRenderBucket& bucket, const float frameValue, const bool onlyTLight)
  {
    PruneExpiredTrailBucketWorkItems(bucket, frameValue);
    (void)EnsureAndFillTrailBucketWorkItems(bucket, frameValue);

    const std::size_t activeWorkItemCount = bucket.activeWorkItems.size();
    if (activeWorkItemCount == 0U || onlyTLight) {
      return false;
    }

    bucket.SelectTechnique();

    for (SParticleRenderWorkItem* const workItem : bucket.activeWorkItems) {
      if (workItem == nullptr || workItem->mParticleBuffer == nullptr) {
        continue;
      }

      const std::uint32_t startIndex = workItem->mIntervalCursor;
      const std::uint32_t segmentCount =
        (workItem->mRenderStartIndex > startIndex) ? (workItem->mRenderStartIndex - startIndex) : 0U;
      if (segmentCount == 0U) {
        continue;
      }

      DrawTrailSegmentBatch(
        *static_cast<STrailSegmentBuffer*>(workItem->mParticleBuffer),
        static_cast<std::int32_t>(segmentCount),
        static_cast<std::int32_t>(startIndex)
      );
    }

    return true;
  }
} // namespace moho
