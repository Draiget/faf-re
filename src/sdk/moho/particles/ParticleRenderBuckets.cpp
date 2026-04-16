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
#include "moho/particles/ParticleRenderWorkItemRuntime.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"
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

  struct ParticleInstanceRuntime
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

  static_assert(sizeof(ParticleInstanceRuntime) == 0x5C, "ParticleInstanceRuntime size must be 0x5C");

  template <typename TValue>
  [[nodiscard]] std::size_t VectorCount(const moho::RenderBucketVectorRuntime<TValue>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.end == nullptr || vector.end < vector.begin) {
      return 0U;
    }
    return static_cast<std::size_t>(vector.end - vector.begin);
  }

  template <typename TValue>
  [[nodiscard]] std::size_t VectorCapacity(const moho::RenderBucketVectorRuntime<TValue>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.capacityEnd == nullptr || vector.capacityEnd < vector.begin) {
      return 0U;
    }
    return static_cast<std::size_t>(vector.capacityEnd - vector.begin);
  }

  [[nodiscard]] moho::ParticleBufferPoolListRuntime* ResolveOwnerBufferPool(moho::CWorldParticles* const owner) noexcept
  {
    if (owner == nullptr) {
      return nullptr;
    }

    auto* const ownerView = reinterpret_cast<moho::CWorldParticlesParticlePoolRuntimeView*>(owner);
    return &ownerView->availableBuffers;
  }

  [[nodiscard]] moho::ParticleBuffer* PopFrontBufferFromOwnerPool(moho::CWorldParticles* const owner) noexcept
  {
    moho::ParticleBufferPoolListRuntime* const pool = ResolveOwnerBufferPool(owner);
    if (pool == nullptr || pool->head == nullptr || pool->size == 0U) {
      return nullptr;
    }

    moho::ParticleBufferPoolNodeRuntime* const first = pool->head->next;
    if (first == nullptr || first == pool->head) {
      return nullptr;
    }

    first->prev->next = first->next;
    first->next->prev = first->prev;

    moho::ParticleBuffer* const buffer = first->value;
    ::operator delete(first);
    --pool->size;
    return buffer;
  }

  void PushBackBufferToOwnerPool(moho::CWorldParticles* const owner, moho::ParticleBuffer* const buffer)
  {
    (void)moho::AppendParticleBufferToOwnerAvailablePool(owner, buffer);
  }

  /**
   * What it does:
   * Legacy intrusive-list node lane used by multiple world-particle pool helper
   * thunks.
   */
  struct LegacyPoolListNodeRuntime
  {
    LegacyPoolListNodeRuntime* next = nullptr; // +0x00
    LegacyPoolListNodeRuntime* prev = nullptr; // +0x04
  };

  static_assert(
    offsetof(LegacyPoolListNodeRuntime, next) == 0x00,
    "LegacyPoolListNodeRuntime::next offset must be 0x00"
  );
  static_assert(
    offsetof(LegacyPoolListNodeRuntime, prev) == 0x04,
    "LegacyPoolListNodeRuntime::prev offset must be 0x04"
  );
  static_assert(sizeof(LegacyPoolListNodeRuntime) == 0x08, "LegacyPoolListNodeRuntime size must be 0x08");

  /**
   * What it does:
   * Legacy list header lane (`proxy + head + size`) used by helper thunks at
   * `0x00495EA0..0x00495FF0`.
   */
  struct LegacyPoolListRuntime
  {
    std::uint32_t iteratorProxy = 0U;    // +0x00
    LegacyPoolListNodeRuntime* head = nullptr; // +0x04
    std::uint32_t size = 0U;             // +0x08
  };

  static_assert(
    offsetof(LegacyPoolListRuntime, head) == 0x04,
    "LegacyPoolListRuntime::head offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyPoolListRuntime, size) == 0x08,
    "LegacyPoolListRuntime::size offset must be 0x08"
  );
  static_assert(sizeof(LegacyPoolListRuntime) == 0x0C, "LegacyPoolListRuntime size must be 0x0C");

  /**
   * Address: 0x00495E30 (FUN_00495E30, sub_495E30)
   *
   * What it does:
   * Returns the `next` lane from one legacy intrusive-list node.
   */
  [[nodiscard]] LegacyPoolListNodeRuntime* GetLegacyPoolNodeNext(
    LegacyPoolListNodeRuntime* const node
  ) noexcept
  {
    return node->next;
  }

  /**
   * Address: 0x00495EA0 (FUN_00495EA0, sub_495EA0)
   *
   * What it does:
   * Writes the begin-node (`head->next`) from one legacy list header into
   * caller storage.
   */
  LegacyPoolListNodeRuntime** GetLegacyPoolListBeginNode(
    LegacyPoolListNodeRuntime** const outBeginNode,
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    *outBeginNode = list.head->next;
    return outBeginNode;
  }

  /**
   * Address: 0x00495EB0 (FUN_00495EB0, sub_495EB0)
   *
   * What it does:
   * Writes the head-sentinel node pointer from one legacy list header into
   * caller storage.
   */
  LegacyPoolListNodeRuntime** GetLegacyPoolListHeadNode(
    LegacyPoolListNodeRuntime** const outHeadNode,
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    *outHeadNode = list.head;
    return outHeadNode;
  }

  /**
   * Address: 0x00495EC0 (FUN_00495EC0, sub_495EC0)
   *
   * What it does:
   * Returns the node count from one legacy list header lane.
   */
  [[nodiscard]] std::uint32_t GetLegacyPoolListSize(
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    return list.size;
  }

  /**
   * Address: 0x00495F30 (FUN_00495F30, sub_495F30)
   *
   * What it does:
   * Clears one legacy intrusive list by unlinking the head sentinel and freeing
   * all non-sentinel nodes.
   */
  LegacyPoolListNodeRuntime* ClearLegacyPoolListNodes(
    LegacyPoolListRuntime& list
  ) noexcept
  {
    LegacyPoolListNodeRuntime* node = list.head->next;
    list.head->next = list.head;
    list.head->prev = list.head;
    list.size = 0U;

    while (node != list.head) {
      LegacyPoolListNodeRuntime* const next = node->next;
      ::operator delete(node);
      node = next;
    }

    return node;
  }

  /**
   * Address: 0x00495FD0 (FUN_00495FD0, sub_495FD0)
   *
   * What it does:
   * Duplicate begin-node accessor thunk for the same legacy list layout used by
   * sibling pool lanes.
   */
  LegacyPoolListNodeRuntime** GetLegacyPoolListBeginNodeDuplicate(
    LegacyPoolListNodeRuntime** const outBeginNode,
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    return GetLegacyPoolListBeginNode(outBeginNode, list);
  }

  /**
   * Address: 0x00495FE0 (FUN_00495FE0, sub_495FE0)
   *
   * What it does:
   * Duplicate head-sentinel accessor thunk for the same legacy list layout used
   * by sibling pool lanes.
   */
  LegacyPoolListNodeRuntime** GetLegacyPoolListHeadNodeDuplicate(
    LegacyPoolListNodeRuntime** const outHeadNode,
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    return GetLegacyPoolListHeadNode(outHeadNode, list);
  }

  /**
   * Address: 0x00495FF0 (FUN_00495FF0, sub_495FF0)
   *
   * What it does:
   * Duplicate list-size accessor thunk for the same legacy list layout used by
   * sibling pool lanes.
   */
  [[nodiscard]] std::uint32_t GetLegacyPoolListSizeDuplicate(
    const LegacyPoolListRuntime& list
  ) noexcept
  {
    return GetLegacyPoolListSize(list);
  }

  /**
   * What it does:
   * One forward-linked intrusive node lane used by legacy iterator/pop helper
   * thunks.
   */
  struct LegacyForwardNodeRuntime
  {
    LegacyForwardNodeRuntime* next = nullptr; // +0x00
  };

  static_assert(
    offsetof(LegacyForwardNodeRuntime, next) == 0x00,
    "LegacyForwardNodeRuntime::next offset must be 0x00"
  );
  static_assert(sizeof(LegacyForwardNodeRuntime) == 0x04, "LegacyForwardNodeRuntime size must be 0x04");

  using IntervalVectorRuntimeView = moho::RenderBucketVectorRuntime<moho::ParticleRenderIntervalRuntime>;
  using WorkItemPointerVectorRuntime = moho::RenderBucketVectorRuntime<moho::ParticleRenderWorkItemRuntime*>;

  moho::ParticleRenderIntervalRuntime* InsertIntervalValueAtAndGrowDuplicate(
    IntervalVectorRuntimeView& intervalVector,
    moho::ParticleRenderIntervalRuntime* insertPosition,
    const moho::ParticleRenderIntervalRuntime& value
  );

  [[nodiscard]] bool AppendWorkItemPointer(
    WorkItemPointerVectorRuntime& vector,
    moho::ParticleRenderWorkItemRuntime* workItem
  );

  /**
   * Address: 0x00496710 (FUN_00496710, sub_496710)
   *
   * What it does:
   * Returns the max trail-segment capacity lane from one pooled trail-segment
   * render buffer.
   */
  [[nodiscard]] std::uint32_t GetTrailSegmentBufferMaxSegments(
    const moho::TrailSegmentBufferRuntime& segmentBuffer
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
    moho::TrailSegmentBufferRuntime& segmentBuffer,
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
    moho::TrailSegmentBufferRuntime& segmentBuffer,
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
    const moho::TrailSegmentBufferRuntime& segmentBuffer,
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

    moho::CD3DVertexSheetViewRuntime vertexSheetView{};
    vertexSheetView.sheet = segmentBuffer.vertexSheet;
    vertexSheetView.startVertex = kTrailVerticesPerSegment * startSegmentIndex;
    vertexSheetView.baseVertex = 0;
    vertexSheetView.endVertex = (kTrailVerticesPerSegment * segmentCount) - 1;

    moho::CD3DIndexSheetViewRuntime indexSheetView{};
    indexSheetView.sheet = sharedTrailIndexSheet;
    indexSheetView.startIndex = kTrailIndicesPerSegment * (kSharedTrailQuadCapacity - segmentCount);
    indexSheetView.indexCount = kTrailIndicesPerSegment * segmentCount;

    std::int32_t primitiveType = kTriangleListPrimitiveType;
    (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);
  }

  /**
   * Address: 0x004968A0 (FUN_004968A0, sub_4968A0)
   *
   * What it does:
   * Advances one intrusive forward-list iterator slot to `node->next`.
   */
  LegacyForwardNodeRuntime** AdvanceLegacyForwardListIterator(
    LegacyForwardNodeRuntime** const inOutNodeSlot
  ) noexcept
  {
    *inOutNodeSlot = (*inOutNodeSlot)->next;
    return inOutNodeSlot;
  }

  /**
   * Address: 0x004968B0 (FUN_004968B0, sub_4968B0)
   *
   * What it does:
   * Pops the head node from one intrusive forward list and exports the removed
   * node to caller storage.
   */
  LegacyForwardNodeRuntime** PopLegacyForwardListHeadNode(
    LegacyForwardNodeRuntime** const outPoppedNode,
    LegacyForwardNodeRuntime** const inOutHeadSlot
  ) noexcept
  {
    LegacyForwardNodeRuntime* const popped = *inOutHeadSlot;
    *outPoppedNode = popped;
    *inOutHeadSlot = popped->next;
    return outPoppedNode;
  }

  /**
   * Address: 0x00496910 (FUN_00496910, sub_496910)
   *
   * What it does:
   * Writes one interval-vector begin pointer lane into caller storage.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalVectorBeginPointer(
    moho::ParticleRenderIntervalRuntime** const outBegin,
    const IntervalVectorRuntimeView& intervalVector
  ) noexcept
  {
    *outBegin = intervalVector.begin;
    return outBegin;
  }

  /**
   * Address: 0x00496920 (FUN_00496920, sub_496920)
   *
   * What it does:
   * Writes one interval-vector end pointer lane into caller storage.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalVectorEndPointer(
    moho::ParticleRenderIntervalRuntime** const outEnd,
    const IntervalVectorRuntimeView& intervalVector
  ) noexcept
  {
    *outEnd = intervalVector.end;
    return outEnd;
  }

  /**
   * Address: 0x0049AD70 (FUN_0049AD70, sub_49AD70)
   *
   * What it does:
   * Writes one `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotD(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049AD80 (FUN_0049AD80, sub_49AD80)
   *
   * What it does:
   * Returns the legacy max element-count lane for 8-byte vector storage.
   */
  [[nodiscard]] std::uint32_t GetLegacyVectorMaxElementCount_0x1FFFFFFF() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x0049AD90 (FUN_0049AD90, nullsub_594)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAJ() noexcept {}

  /**
   * Address: 0x0049AFF0 (FUN_0049AFF0, sub_49AFF0)
   *
   * What it does:
   * Throws the legacy vector-overflow error used by 8-byte vector grow paths.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateD()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0049E820 (FUN_0049E820, sub_49E820)
   *
   * What it does:
   * Copies one interval range (`[sourceBegin, sourceEnd)`) into destination
   * storage and returns the destination end pointer.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* CopyParticleIntervalRangeAndReturnEnd(
    moho::ParticleRenderIntervalRuntime* destination,
    const moho::ParticleRenderIntervalRuntime* sourceBegin,
    const moho::ParticleRenderIntervalRuntime* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        *destination = *sourceBegin;
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0049E850 (FUN_0049E850, sub_49E850)
   *
   * What it does:
   * Copies one interval source value across one destination range.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* CopyParticleIntervalValueAcrossRangeA(
    const moho::ParticleRenderIntervalRuntime& sourceValue,
    moho::ParticleRenderIntervalRuntime* destinationBegin,
    const moho::ParticleRenderIntervalRuntime* const destinationEnd
  ) noexcept
  {
    moho::ParticleRenderIntervalRuntime* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      *destinationBegin = sourceValue;
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049E870 (FUN_0049E870, sub_49E870)
   *
   * What it does:
   * Shifts one interval tail range right by one element using backward copy
   * order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* ShiftParticleIntervalRangeRightByOneAndReturnWriteCursorA(
    moho::ParticleRenderIntervalRuntime* sourceLast,
    moho::ParticleRenderIntervalRuntime* destinationEnd,
    const moho::ParticleRenderIntervalRuntime* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      *destinationEnd = *sourceLast;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049E890 (FUN_0049E890, sub_49E890)
   *
   * What it does:
   * Allocates one 8-byte interval array lane and throws `std::bad_alloc` on
   * legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateParticleIntervalArrayOrThrowA(const std::uint32_t elementCount)
  {
    constexpr std::size_t kIntervalSize = sizeof(moho::ParticleRenderIntervalRuntime);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kIntervalSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kIntervalSize);
  }

  /**
   * Address: 0x0049ADA0 (FUN_0049ADA0, sub_49ADA0)
   *
   * What it does:
   * Inserts one interval payload at the requested position in one interval
   * vector, growing storage when needed and returning the inserted lane.
   */
  moho::ParticleRenderIntervalRuntime* InsertIntervalValueAtAndGrow(
    IntervalVectorRuntimeView& intervalVector,
    moho::ParticleRenderIntervalRuntime* const insertPosition,
    const moho::ParticleRenderIntervalRuntime& value
  )
  {
    const std::size_t count = VectorCount(intervalVector);
    const std::size_t capacity = VectorCapacity(intervalVector);
    const std::size_t maxCount = GetLegacyVectorMaxElementCount_0x1FFFFFFF();

    if (count >= maxCount) {
      ThrowLegacyVectorTooLongDuplicateD();
    }

    std::size_t insertIndex = count;
    if (intervalVector.begin != nullptr &&
        intervalVector.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= intervalVector.begin &&
        insertPosition <= intervalVector.end) {
      insertIndex = static_cast<std::size_t>(insertPosition - intervalVector.begin);
    }

    if (count < capacity && intervalVector.begin != nullptr && intervalVector.end != nullptr) {
      moho::ParticleRenderIntervalRuntime* const destination = intervalVector.begin + insertIndex;
      if (destination != intervalVector.end) {
        (void)ShiftParticleIntervalRangeRightByOneAndReturnWriteCursorA(
          intervalVector.end - 1,
          intervalVector.end,
          destination
        );
      }
      (void)CopyParticleIntervalValueAcrossRangeA(value, destination, destination + 1);
      ++intervalVector.end;
      return destination;
    }

    const std::size_t grown = ((maxCount - (count >> 1U)) >= count) ? (count + (count >> 1U)) : 0U;
    std::size_t newCapacity = grown;
    if (newCapacity < count + 1U) {
      newCapacity = count + 1U;
    }

    auto* const newStorage = static_cast<moho::ParticleRenderIntervalRuntime*>(
      AllocateParticleIntervalArrayOrThrowA(static_cast<std::uint32_t>(newCapacity))
    );
    moho::ParticleRenderIntervalRuntime* const inserted = newStorage + insertIndex;

    if (insertIndex != 0U && intervalVector.begin != nullptr) {
      (void)CopyParticleIntervalRangeAndReturnEnd(
        newStorage,
        intervalVector.begin,
        intervalVector.begin + insertIndex
      );
    }

    *inserted = value;

    if ((count - insertIndex) != 0U && intervalVector.begin != nullptr) {
      (void)CopyParticleIntervalRangeAndReturnEnd(
        inserted + 1,
        intervalVector.begin + insertIndex,
        intervalVector.end
      );
    }

    if (intervalVector.begin != nullptr) {
      ::operator delete(intervalVector.begin);
    }

    intervalVector.begin = newStorage;
    intervalVector.end = newStorage + count + 1U;
    intervalVector.capacityEnd = newStorage + newCapacity;
    return inserted;
  }

  /**
   * Address: 0x00496950 (FUN_00496950, sub_496950)
   *
   * What it does:
   * Appends one particle-render interval into a legacy debug-vector lane,
   * growing the interval storage when required.
   */
  moho::ParticleRenderIntervalRuntime* AppendIntervalVectorValue(
    IntervalVectorRuntimeView& intervalVector,
    const moho::ParticleRenderIntervalRuntime& interval
  )
  {
    if (intervalVector.begin != nullptr &&
        intervalVector.end != nullptr &&
        intervalVector.capacityEnd != nullptr &&
        intervalVector.end < intervalVector.capacityEnd) {
      moho::ParticleRenderIntervalRuntime* const appended = intervalVector.end;
      *appended = interval;
      ++intervalVector.end;
      return appended;
    }

    return InsertIntervalValueAtAndGrow(intervalVector, intervalVector.end, interval);
  }

  /**
   * Address: 0x004969C0 (FUN_004969C0, sub_4969C0)
   *
   * What it does:
   * Clears one interval debug-vector lane by resetting `end` to `begin`.
   */
  void ClearIntervalVectorValues(IntervalVectorRuntimeView& intervalVector) noexcept
  {
    if (intervalVector.begin != intervalVector.end) {
      intervalVector.end = intervalVector.begin;
    }
  }

  /**
   * Address: 0x00496C20 (FUN_00496C20, sub_496C20)
   *
   * What it does:
   * Clears one work-item pointer debug-vector lane by resetting `end` to
   * `begin`.
   */
  void ClearWorkItemPointerVector(WorkItemPointerVectorRuntime& workItems) noexcept
  {
    if (workItems.begin != workItems.end) {
      workItems.end = workItems.begin;
    }
  }

  /**
   * Address: 0x0049DEA0 (FUN_0049DEA0, sub_49DEA0)
   *
   * What it does:
   * Copies one pointer range (`[sourceBegin, sourceEnd)`) into destination
   * storage and returns the destination end pointer.
   */
  [[nodiscard]] moho::ParticleRenderWorkItemRuntime** CopyWorkItemPointerRangeAndReturnEnd(
    moho::ParticleRenderWorkItemRuntime* const* const sourceBegin,
    moho::ParticleRenderWorkItemRuntime* const* const sourceEnd,
    moho::ParticleRenderWorkItemRuntime** const destinationBegin
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(moho::ParticleRenderWorkItemRuntime*);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin + count;
  }

  /**
   * Address: 0x0049DED0 (FUN_0049DED0, sub_49DED0)
   *
   * What it does:
   * Duplicate pointer-range copy helper used by the work-item vector assign
   * lane when copying the second segment into destination storage.
   */
  [[nodiscard]] moho::ParticleRenderWorkItemRuntime** CopyWorkItemPointerRangeAndReturnEndDuplicate(
    moho::ParticleRenderWorkItemRuntime* const* const sourceBegin,
    moho::ParticleRenderWorkItemRuntime* const* const sourceEnd,
    moho::ParticleRenderWorkItemRuntime** const destinationBegin
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(moho::ParticleRenderWorkItemRuntime*);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin + count;
  }

  /**
   * Address: 0x00496A30 (FUN_00496A30, sub_496A30)
   *
   * What it does:
   * Assigns one work-item pointer vector into another using legacy debug-vector
   * lanes (`proxy + begin/end/capacity`), reusing storage when possible.
   */
  WorkItemPointerVectorRuntime* AssignWorkItemPointerVector(
    const WorkItemPointerVectorRuntime& source,
    WorkItemPointerVectorRuntime& destination
  )
  {
    if (&source == &destination) {
      return &destination;
    }

    const std::size_t sourceCount = VectorCount(source);
    if (sourceCount == 0U) {
      ClearWorkItemPointerVector(destination);
      return &destination;
    }

    const std::size_t destinationCount = VectorCount(destination);
    const std::size_t destinationCapacity = VectorCapacity(destination);
    if (sourceCount > destinationCapacity) {
      if (destination.begin != nullptr) {
        ::operator delete(destination.begin);
      }
      destination.begin = nullptr;
      destination.end = nullptr;
      destination.capacityEnd = nullptr;

      if (sourceCount != 0U) {
        if (sourceCount > (std::numeric_limits<std::size_t>::max() / sizeof(moho::ParticleRenderWorkItemRuntime*))) {
          return &destination;
        }

        auto* const newStorage = static_cast<moho::ParticleRenderWorkItemRuntime**>(
          ::operator new(sourceCount * sizeof(moho::ParticleRenderWorkItemRuntime*))
        );
        destination.begin = newStorage;
        destination.end = newStorage;
        destination.capacityEnd = newStorage + sourceCount;
      }
    }

    if (sourceCount != 0U && destination.begin != nullptr && source.begin != nullptr && source.end != nullptr) {
      const std::size_t firstSegmentCount = std::min(destinationCount, sourceCount);
      auto* const splitSource = source.begin + firstSegmentCount;
      moho::ParticleRenderWorkItemRuntime** writeCursor = destination.begin;
      if (firstSegmentCount != 0U) {
        writeCursor = CopyWorkItemPointerRangeAndReturnEnd(source.begin, splitSource, destination.begin);
      }
      destination.end = CopyWorkItemPointerRangeAndReturnEndDuplicate(splitSource, source.end, writeCursor);
      return &destination;
    }

    destination.end = destination.begin + sourceCount;
    return &destination;
  }

  /**
   * Address: 0x00496B70 (FUN_00496B70, sub_496B70)
   *
   * What it does:
   * Writes one work-item pointer-vector begin lane into caller storage.
   */
  moho::ParticleRenderWorkItemRuntime*** GetWorkItemPointerVectorBegin(
    moho::ParticleRenderWorkItemRuntime*** const outBegin,
    const WorkItemPointerVectorRuntime& workItems
  ) noexcept
  {
    *outBegin = workItems.begin;
    return outBegin;
  }

  /**
   * Address: 0x00496B80 (FUN_00496B80, sub_496B80)
   *
   * What it does:
   * Writes one work-item pointer-vector end lane into caller storage.
   */
  moho::ParticleRenderWorkItemRuntime*** GetWorkItemPointerVectorEnd(
    moho::ParticleRenderWorkItemRuntime*** const outEnd,
    const WorkItemPointerVectorRuntime& workItems
  ) noexcept
  {
    *outEnd = workItems.end;
    return outEnd;
  }

  /**
   * Address: 0x00496BB0 (FUN_00496BB0, sub_496BB0)
   *
   * What it does:
   * Computes one pointer to a work-item pointer element by index from one
   * debug-vector begin lane.
   */
  [[nodiscard]] moho::ParticleRenderWorkItemRuntime** WorkItemPointerVectorElementAt(
    const WorkItemPointerVectorRuntime& workItems,
    const std::int32_t index
  ) noexcept
  {
    return workItems.begin + index;
  }

  /**
   * Address: 0x00496BD0 (FUN_00496BD0, sub_496BD0)
   *
   * What it does:
   * Appends one work-item pointer from caller slot into one pointer vector
   * lane, growing storage when required.
   */
  moho::ParticleRenderWorkItemRuntime* PushBackWorkItemPointerFromSlot(
    const moho::ParticleRenderWorkItemRuntime* const* const valueSlot,
    WorkItemPointerVectorRuntime& workItems
  )
  {
    auto* const value = const_cast<moho::ParticleRenderWorkItemRuntime*>(*valueSlot);
    if (AppendWorkItemPointer(workItems, value)) {
      return value;
    }
    return nullptr;
  }

  /**
   * Address: 0x00496C60 (FUN_00496C60, sub_496C60)
   *
   * What it does:
   * Returns one pointer value from caller pointer slot.
   */
  [[nodiscard]] void* ReadPointerSlotValueA(void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00496C80 (FUN_00496C80, sub_496C80)
   *
   * What it does:
   * Computes one interval pointer at index from one base-interval pointer slot.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalPointerAtIndex(
    moho::ParticleRenderIntervalRuntime** const outIntervalPointer,
    moho::ParticleRenderIntervalRuntime* const* const basePointerSlot,
    const std::int32_t index
  ) noexcept
  {
    *outIntervalPointer = (*basePointerSlot) + index;
    return outIntervalPointer;
  }

  /**
   * Address: 0x00496CA0 (FUN_00496CA0, sub_496CA0)
   *
   * What it does:
   * Returns one pointer value from caller pointer slot.
   */
  [[nodiscard]] void* ReadPointerSlotValueB(void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00496CE0 (FUN_00496CE0, sub_496CE0)
   *
   * What it does:
   * Returns one 32-bit legacy vector proxy token from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadLegacyVectorProxyToken(const std::uint32_t* const tokenSlot) noexcept
  {
    return *tokenSlot;
  }

  /**
   * Address: 0x00496D50 (FUN_00496D50, sub_496D50)
   *
   * What it does:
   * Duplicate begin-pointer accessor thunk for one interval debug-vector lane.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalVectorBeginPointerDuplicate(
    moho::ParticleRenderIntervalRuntime** const outBegin,
    const IntervalVectorRuntimeView& intervalVector
  ) noexcept
  {
    return GetIntervalVectorBeginPointer(outBegin, intervalVector);
  }

  /**
   * Address: 0x00496D60 (FUN_00496D60, sub_496D60)
   *
   * What it does:
   * Duplicate end-pointer accessor thunk for one interval debug-vector lane.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalVectorEndPointerDuplicate(
    moho::ParticleRenderIntervalRuntime** const outEnd,
    const IntervalVectorRuntimeView& intervalVector
  ) noexcept
  {
    return GetIntervalVectorEndPointer(outEnd, intervalVector);
  }

  /**
   * Address: 0x00496D90 (FUN_00496D90, sub_496D90)
   *
   * What it does:
   * Appends one interval payload from caller pointer into one interval
   * debug-vector lane, growing storage when needed.
   */
  moho::ParticleRenderIntervalRuntime* PushBackIntervalFromPointerSlot(
    const moho::ParticleRenderIntervalRuntime* const intervalSlotValue,
    IntervalVectorRuntimeView& intervalVector
  )
  {
    if (intervalVector.begin != nullptr &&
        intervalVector.end != nullptr &&
        intervalVector.capacityEnd != nullptr &&
        intervalVector.end < intervalVector.capacityEnd) {
      moho::ParticleRenderIntervalRuntime* const appended = intervalVector.end;
      *appended = *intervalSlotValue;
      ++intervalVector.end;
      return appended;
    }

    return InsertIntervalValueAtAndGrowDuplicate(intervalVector, intervalVector.end, *intervalSlotValue);
  }

  /**
   * Address: 0x00496E00 (FUN_00496E00, sub_496E00)
   *
   * What it does:
   * Duplicate clear thunk that resets one interval debug-vector `end` lane to
   * `begin`.
   */
  void ClearIntervalVectorValuesDuplicate(IntervalVectorRuntimeView& intervalVector) noexcept
  {
    ClearIntervalVectorValues(intervalVector);
  }

  using UInt32VectorRuntimeView = moho::RenderBucketVectorRuntime<std::uint32_t>;

  /**
   * Address: 0x0049DF00 (FUN_0049DF00, sub_49DF00)
   *
   * What it does:
   * Copies one `uint32_t` range (`[sourceBegin, sourceEnd)`) into destination
   * storage and returns the destination end pointer.
   */
  [[nodiscard]] std::uint32_t* CopyUInt32RangeAndReturnEnd(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin + count;
  }

  /**
   * Address: 0x0049DF30 (FUN_0049DF30, sub_49DF30)
   *
   * What it does:
   * Duplicate `uint32_t` range copy helper used by the second copy segment in
   * the legacy vector assignment lane.
   */
  [[nodiscard]] std::uint32_t* CopyUInt32RangeAndReturnEndDuplicate(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationBegin
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin + count;
  }

  /**
   * Address: 0x00496E70 (FUN_00496E70, sub_496E70)
   *
   * What it does:
   * Assigns one `uint32_t` debug-vector lane into another, clearing destination
   * when source is empty and reusing storage when capacity is sufficient.
   */
  UInt32VectorRuntimeView* AssignUInt32VectorValues(
    const UInt32VectorRuntimeView& source,
    UInt32VectorRuntimeView& destination
  )
  {
    if (&source == &destination) {
      return &destination;
    }

    const std::size_t sourceCount = VectorCount(source);
    if (sourceCount == 0U) {
      destination.end = destination.begin;
      return &destination;
    }

    const std::size_t destinationCount = VectorCount(destination);
    const std::size_t destinationCapacity = VectorCapacity(destination);
    if (sourceCount > destinationCount) {
      if (sourceCount <= destinationCapacity) {
        if (destination.begin != nullptr && source.begin != nullptr && source.end != nullptr) {
          const std::size_t firstSegmentCount = destinationCount;
          const std::uint32_t* const splitSource = source.begin + firstSegmentCount;
          std::uint32_t* writeCursor = destination.begin;
          if (firstSegmentCount != 0U) {
            writeCursor = CopyUInt32RangeAndReturnEnd(source.begin, splitSource, destination.begin);
          }
          destination.end = CopyUInt32RangeAndReturnEndDuplicate(splitSource, source.end, writeCursor);
          return &destination;
        }
        destination.end = destination.begin + sourceCount;
        return &destination;
      }

      if (destination.begin != nullptr) {
        ::operator delete(destination.begin);
      }
      destination.begin = nullptr;
      destination.end = nullptr;
      destination.capacityEnd = nullptr;

      auto* const newStorage = static_cast<std::uint32_t*>(::operator new(sourceCount * sizeof(std::uint32_t)));
      destination.begin = newStorage;
      destination.end = newStorage;
      destination.capacityEnd = newStorage + sourceCount;
      if (source.begin != nullptr && source.end != nullptr) {
        destination.end = CopyUInt32RangeAndReturnEndDuplicate(source.begin, source.end, destination.begin);
        return &destination;
      }
      destination.end = destination.begin + sourceCount;
      return &destination;
    }

    if (source.begin != nullptr && destination.begin != nullptr && source.end != nullptr) {
      destination.end = CopyUInt32RangeAndReturnEnd(source.begin, source.end, destination.begin);
      return &destination;
    }
    destination.end = destination.begin + sourceCount;
    return &destination;
  }

  /**
   * Address: 0x00496FB0 (FUN_00496FB0, sub_496FB0)
   *
   * What it does:
   * Writes the begin-pointer lane of one `uint32_t` debug-vector into caller
   * storage.
   */
  std::uint32_t** GetUInt32VectorBeginPointer(
    std::uint32_t** const outBegin,
    const UInt32VectorRuntimeView& values
  ) noexcept
  {
    *outBegin = values.begin;
    return outBegin;
  }

  /**
   * Address: 0x00496FC0 (FUN_00496FC0, sub_496FC0)
   *
   * What it does:
   * Writes the end-pointer lane of one `uint32_t` debug-vector into caller
   * storage.
   */
  std::uint32_t** GetUInt32VectorEndPointer(
    std::uint32_t** const outEnd,
    const UInt32VectorRuntimeView& values
  ) noexcept
  {
    *outEnd = values.end;
    return outEnd;
  }

  /**
   * Address: 0x0049B060 (FUN_0049B060, nullsub_595)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAK() noexcept {}

  /**
   * Address: 0x0049B0A0 (FUN_0049B0A0, sub_49B0A0)
   *
   * What it does:
   * Returns the legacy max element-count lane for 4-byte vector storage.
   */
  [[nodiscard]] std::uint32_t GetLegacyVectorMaxElementCount_0x3FFFFFFF() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049B710 (FUN_0049B710, nullsub_598)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAN() noexcept {}

  /**
   * Address: 0x0049B750 (FUN_0049B750, sub_49B750)
   *
   * What it does:
   * Returns one duplicate legacy max element-count lane for 4-byte vectors.
   */
  [[nodiscard]] std::uint32_t GetLegacyVectorMaxElementCount_0x3FFFFFFF_DuplicateA() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049B2C0 (FUN_0049B2C0, sub_49B2C0)
   *
   * What it does:
   * Throws the legacy vector-overflow error used by 4-byte vector grow paths.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateE()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0049B9C0 (FUN_0049B9C0, sub_49B9C0)
   *
   * What it does:
   * Throws one duplicate legacy vector-overflow error for 4-byte grow paths.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateG()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0049B330 (FUN_0049B330, nullsub_596)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAL() noexcept {}

  /**
   * Address: 0x0049BA30 (FUN_0049BA30, nullsub_599)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAO() noexcept {}

  /**
   * Address: 0x0049B370 (FUN_0049B370, sub_49B370)
   *
   * What it does:
   * Writes one duplicate `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotE(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049B380 (FUN_0049B380, sub_49B380)
   *
   * What it does:
   * Reads one duplicate `uint32_t` scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotD(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x0049B3C0 (FUN_0049B3C0, sub_49B3C0)
   *
   * What it does:
   * Writes one duplicate `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotF(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049B3D0 (FUN_0049B3D0, sub_49B3D0)
   *
   * What it does:
   * Reads one duplicate `uint32_t` scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotE(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x0049B3F0 (FUN_0049B3F0, sub_49B3F0)
   *
   * What it does:
   * Computes one `uint32_t` element pointer from base-pointer slot and index.
   */
  std::uint32_t** GetUInt32PointerAtIndex(
    std::uint32_t** const outValuePointer,
    std::uint32_t* const* const basePointerSlot,
    const std::int32_t index
  ) noexcept
  {
    *outValuePointer = (*basePointerSlot) + index;
    return outValuePointer;
  }

  /**
   * Address: 0x0049B420 (FUN_0049B420, sub_49B420)
   *
   * What it does:
   * Writes one duplicate `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotG(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049BA70 (FUN_0049BA70, sub_49BA70)
   *
   * What it does:
   * Writes one duplicate `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotH(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049BA80 (FUN_0049BA80, sub_49BA80)
   *
   * What it does:
   * Reads one duplicate `uint32_t` scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotF(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x0049BAC0 (FUN_0049BAC0, sub_49BAC0)
   *
   * What it does:
   * Writes one duplicate `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotI(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049BAD0 (FUN_0049BAD0, sub_49BAD0)
   *
   * What it does:
   * Reads one duplicate `uint32_t` scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotG(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * What it does:
   * Small two-dword lane used by scalar helper-thunk copies.
   */
  struct TwoUInt32Runtime
  {
    std::uint32_t first = 0U;  // +0x00
    std::uint32_t second = 0U; // +0x04
  };

  static_assert(offsetof(TwoUInt32Runtime, first) == 0x00, "TwoUInt32Runtime::first offset must be 0x00");
  static_assert(offsetof(TwoUInt32Runtime, second) == 0x04, "TwoUInt32Runtime::second offset must be 0x04");
  static_assert(sizeof(TwoUInt32Runtime) == 0x08, "TwoUInt32Runtime size must be 0x08");

  /**
   * Address: 0x0049BAF0 (FUN_0049BAF0, sub_49BAF0)
   *
   * What it does:
   * Computes one `uint32_t` element pointer from base-pointer slot and index.
   */
  std::uint32_t** GetUInt32PointerAtIndexDuplicateA(
    std::uint32_t** const outValuePointer,
    std::uint32_t* const* const basePointerSlot,
    const std::int32_t index
  ) noexcept
  {
    *outValuePointer = (*basePointerSlot) + index;
    return outValuePointer;
  }

  /**
   * Address: 0x0049BB20 (FUN_0049BB20, sub_49BB20)
   *
   * What it does:
   * Writes one duplicate scalar `uint32_t` into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotJ(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049BB30 (FUN_0049BB30, sub_49BB30)
   *
   * What it does:
   * Copies one two-dword lane from source storage into destination storage.
   */
  TwoUInt32Runtime* CopyTwoUInt32RuntimeA(
    TwoUInt32Runtime* const outValue,
    const TwoUInt32Runtime& source
  ) noexcept
  {
    outValue->first = source.first;
    outValue->second = source.second;
    return outValue;
  }

  /**
   * Address: 0x0049BB40 (FUN_0049BB40, sub_49BB40)
   *
   * What it does:
   * Duplicate two-dword copy thunk retained for binary parity.
   */
  TwoUInt32Runtime* CopyTwoUInt32RuntimeB(
    TwoUInt32Runtime* const outValue,
    const TwoUInt32Runtime& source
  ) noexcept
  {
    return CopyTwoUInt32RuntimeA(outValue, source);
  }

  /**
   * Address: 0x0049BB50 (FUN_0049BB50, sub_49BB50)
   *
   * What it does:
   * Writes one duplicate scalar `uint32_t` into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotK(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049BBC0 (FUN_0049BBC0, sub_49BBC0)
   *
   * What it does:
   * Returns one scalar value and clears the source slot to zero.
   */
  [[nodiscard]] std::uint32_t ReadAndClearUInt32SlotA(std::uint32_t& valueSlot) noexcept
  {
    const std::uint32_t value = valueSlot;
    valueSlot = 0U;
    return value;
  }

  /**
   * Address: 0x0049BBF0 (FUN_0049BBF0, sub_49BBF0)
   *
   * What it does:
   * Duplicate read-and-clear scalar thunk retained for binary parity.
   */
  [[nodiscard]] std::uint32_t ReadAndClearUInt32SlotB(std::uint32_t& valueSlot) noexcept
  {
    return ReadAndClearUInt32SlotA(valueSlot);
  }

  /**
   * Address: 0x0049B430 (FUN_0049B430, sub_49B430)
   *
   * What it does:
   * Returns one duplicate legacy max element-count lane for 8-byte vectors.
   */
  [[nodiscard]] std::uint32_t GetLegacyVectorMaxElementCount_0x1FFFFFFF_Duplicate() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x0049B440 (FUN_0049B440, nullsub_597)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAM() noexcept {}

  /**
   * Address: 0x0049B6A0 (FUN_0049B6A0, sub_49B6A0)
   *
   * What it does:
   * Throws one duplicate legacy vector-overflow error used by 8-byte vector
   * grow paths.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateF()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0049E9A0 (FUN_0049E9A0, nullsub_635)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAP() noexcept {}

  /**
   * Address: 0x0049E9B0 (FUN_0049E9B0, sub_49E9B0)
   *
   * What it does:
   * Copies one interval range (`[sourceBegin, sourceEnd)`) into destination
   * storage and returns the destination end pointer.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* CopyParticleIntervalRangeAndReturnEndDuplicateB(
    moho::ParticleRenderIntervalRuntime* destination,
    const moho::ParticleRenderIntervalRuntime* sourceBegin,
    const moho::ParticleRenderIntervalRuntime* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        *destination = *sourceBegin;
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0049E9E0 (FUN_0049E9E0, sub_49E9E0)
   *
   * What it does:
   * Copies one interval source value across one destination range.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* CopyParticleIntervalValueAcrossRangeB(
    const moho::ParticleRenderIntervalRuntime& sourceValue,
    moho::ParticleRenderIntervalRuntime* destinationBegin,
    const moho::ParticleRenderIntervalRuntime* const destinationEnd
  ) noexcept
  {
    moho::ParticleRenderIntervalRuntime* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      *destinationBegin = sourceValue;
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049EA00 (FUN_0049EA00, sub_49EA00)
   *
   * What it does:
   * Shifts one interval tail range right by one element using backward copy
   * order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::ParticleRenderIntervalRuntime* ShiftParticleIntervalRangeRightByOneAndReturnWriteCursorB(
    moho::ParticleRenderIntervalRuntime* sourceLast,
    moho::ParticleRenderIntervalRuntime* destinationEnd,
    const moho::ParticleRenderIntervalRuntime* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      *destinationEnd = *sourceLast;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049EA20 (FUN_0049EA20, sub_49EA20)
   *
   * What it does:
   * Allocates one duplicate 8-byte interval array lane and throws
   * `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateParticleIntervalArrayOrThrowB(const std::uint32_t elementCount)
  {
    constexpr std::size_t kIntervalSize = sizeof(moho::ParticleRenderIntervalRuntime);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kIntervalSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kIntervalSize);
  }

  /**
   * Address: 0x0049B450 (FUN_0049B450, sub_49B450)
   *
   * What it does:
   * Duplicate insert-and-grow helper for 8-byte interval-like vector lanes.
   */
  moho::ParticleRenderIntervalRuntime* InsertIntervalValueAtAndGrowDuplicate(
    IntervalVectorRuntimeView& intervalVector,
    moho::ParticleRenderIntervalRuntime* const insertPosition,
    const moho::ParticleRenderIntervalRuntime& value
  )
  {
    const std::size_t count = VectorCount(intervalVector);
    const std::size_t capacity = VectorCapacity(intervalVector);
    const std::size_t maxCount = GetLegacyVectorMaxElementCount_0x1FFFFFFF_Duplicate();

    if (count >= maxCount) {
      ThrowLegacyVectorTooLongDuplicateF();
    }

    std::size_t insertIndex = count;
    if (intervalVector.begin != nullptr &&
        intervalVector.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= intervalVector.begin &&
        insertPosition <= intervalVector.end) {
      insertIndex = static_cast<std::size_t>(insertPosition - intervalVector.begin);
    }

    if (count < capacity && intervalVector.begin != nullptr && intervalVector.end != nullptr) {
      moho::ParticleRenderIntervalRuntime* const destination = intervalVector.begin + insertIndex;
      if (destination != intervalVector.end) {
        (void)ShiftParticleIntervalRangeRightByOneAndReturnWriteCursorB(
          intervalVector.end - 1,
          intervalVector.end,
          destination
        );
      }
      (void)CopyParticleIntervalValueAcrossRangeB(value, destination, destination + 1);
      ++intervalVector.end;
      return destination;
    }

    const std::size_t grown = ((maxCount - (count >> 1U)) >= count) ? (count + (count >> 1U)) : 0U;
    std::size_t newCapacity = grown;
    if (newCapacity < count + 1U) {
      newCapacity = count + 1U;
    }

    auto* const newStorage = static_cast<moho::ParticleRenderIntervalRuntime*>(
      AllocateParticleIntervalArrayOrThrowB(static_cast<std::uint32_t>(newCapacity))
    );
    moho::ParticleRenderIntervalRuntime* const inserted = newStorage + insertIndex;

    if (insertIndex != 0U && intervalVector.begin != nullptr) {
      (void)CopyParticleIntervalRangeAndReturnEndDuplicateB(
        newStorage,
        intervalVector.begin,
        intervalVector.begin + insertIndex
      );
    }

    *inserted = value;

    if ((count - insertIndex) != 0U && intervalVector.begin != nullptr) {
      (void)CopyParticleIntervalRangeAndReturnEndDuplicateB(
        inserted + 1,
        intervalVector.begin + insertIndex,
        intervalVector.end
      );
    }

    if (intervalVector.begin != nullptr) {
      ::operator delete(intervalVector.begin);
    }

    intervalVector.begin = newStorage;
    intervalVector.end = newStorage + count + 1U;
    intervalVector.capacityEnd = newStorage + newCapacity;
    return inserted;
  }

  /**
   * Address: 0x0049E8E0 (FUN_0049E8E0, sub_49E8E0)
   *
   * What it does:
   * Copies one `uint32_t` range (`[sourceBegin, sourceEnd)`) into destination
   * storage with memmove semantics and returns the destination end pointer.
   */
  [[maybe_unused]] std::uint32_t* CopyUInt32RangeAndReturnEndA(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destination, sourceBegin, bytes);
    }
    return destination + count;
  }

  /**
   * Address: 0x0049E920 (FUN_0049E920, sub_49E920)
   *
   * What it does:
   * Copies one `uint32_t` range (`[sourceBegin, sourceEndExclusive)`) into the
   * tail-aligned destination ending at `destinationEnd`, returning the
   * beginning of copied destination range.
   */
  [[maybe_unused]] std::uint32_t* CopyUInt32RangeToTailAndReturnBeginA(
    const std::uint32_t* const sourceEndExclusive,
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    const std::size_t count = sourceEndExclusive > sourceBegin
      ? static_cast<std::size_t>(sourceEndExclusive - sourceBegin)
      : 0U;
    std::uint32_t* const destinationBegin = destinationEnd - static_cast<std::ptrdiff_t>(count);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049E950 (FUN_0049E950, sub_49E950)
   *
   * What it does:
   * Allocates one 4-byte scalar array lane and throws `std::bad_alloc` on
   * legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateUInt32ArrayOrThrowA(const std::uint32_t elementCount)
  {
    constexpr std::size_t kUInt32Size = sizeof(std::uint32_t);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kUInt32Size) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kUInt32Size);
  }

  /**
   * Address: 0x0049B0B0 (FUN_0049B0B0, sub_49B0B0)
   *
   * What it does:
   * Inserts one `uint32_t` payload at the requested position in one scalar
   * vector, growing storage when needed and returning the inserted lane.
   */
  std::uint32_t* InsertUInt32ValueAtAndGrow(
    UInt32VectorRuntimeView& values,
    std::uint32_t* const insertPosition,
    const std::uint32_t value
  )
  {
    const std::size_t count = VectorCount(values);
    const std::size_t capacity = VectorCapacity(values);
    const std::size_t maxCount = GetLegacyVectorMaxElementCount_0x3FFFFFFF();

    if (count >= maxCount) {
      ThrowLegacyVectorTooLongDuplicateE();
    }

    std::size_t insertIndex = count;
    if (values.begin != nullptr &&
        values.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= values.begin &&
        insertPosition <= values.end) {
      insertIndex = static_cast<std::size_t>(insertPosition - values.begin);
    }

    if (count < capacity && values.begin != nullptr && values.end != nullptr) {
      std::uint32_t* const destination = values.begin + insertIndex;
      if (destination != values.end) {
        (void)CopyUInt32RangeAndReturnEndA(values.end, values.end - 1, values.end);
        (void)CopyUInt32RangeToTailAndReturnBeginA(values.end - 1, values.end, destination);
      }
      *destination = value;
      ++values.end;
      return destination;
    }

    const std::size_t grown = ((maxCount - (count >> 1U)) >= count) ? (count + (count >> 1U)) : 0U;
    std::size_t newCapacity = grown;
    if (newCapacity < count + 1U) {
      newCapacity = count + 1U;
    }

    auto* const newStorage = static_cast<std::uint32_t*>(
      AllocateUInt32ArrayOrThrowA(static_cast<std::uint32_t>(newCapacity))
    );
    std::uint32_t* const inserted = newStorage + insertIndex;

    if (insertIndex != 0U && values.begin != nullptr) {
      (void)CopyUInt32RangeAndReturnEndA(newStorage, values.begin, values.begin + insertIndex);
    }

    *inserted = value;

    if ((count - insertIndex) != 0U && values.begin != nullptr) {
      (void)CopyUInt32RangeAndReturnEndA(inserted + 1, values.begin + insertIndex, values.end);
    }

    if (values.begin != nullptr) {
      ::operator delete(values.begin);
    }

    values.begin = newStorage;
    values.end = newStorage + count + 1U;
    values.capacityEnd = newStorage + newCapacity;
    return inserted;
  }

  /**
   * Address: 0x0049EA70 (FUN_0049EA70, sub_49EA70)
   *
   * What it does:
   * Duplicate `uint32_t` range copy helper with memmove semantics that returns
   * the destination end pointer.
   */
  [[maybe_unused]] std::uint32_t* CopyUInt32RangeAndReturnEndB(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destination, sourceBegin, bytes);
    }
    return destination + count;
  }

  /**
   * Address: 0x0049EAB0 (FUN_0049EAB0, sub_49EAB0)
   *
   * What it does:
   * Duplicate tail-aligned `uint32_t` range copy helper returning destination
   * range begin.
   */
  [[maybe_unused]] std::uint32_t* CopyUInt32RangeToTailAndReturnBeginB(
    const std::uint32_t* const sourceEndExclusive,
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    const std::size_t count = sourceEndExclusive > sourceBegin
      ? static_cast<std::size_t>(sourceEndExclusive - sourceBegin)
      : 0U;
    std::uint32_t* const destinationBegin = destinationEnd - static_cast<std::ptrdiff_t>(count);
    if (count != 0U) {
      const std::size_t bytes = count * sizeof(std::uint32_t);
      (void)std::memmove(destinationBegin, sourceBegin, bytes);
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049EAE0 (FUN_0049EAE0, sub_49EAE0)
   *
   * What it does:
   * Allocates one duplicate 4-byte scalar array lane and throws
   * `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateUInt32ArrayOrThrowB(const std::uint32_t elementCount)
  {
    constexpr std::size_t kUInt32Size = sizeof(std::uint32_t);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kUInt32Size) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kUInt32Size);
  }

  /**
   * Address: 0x0049EB70 (FUN_0049EB70, nullsub_636)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAQ() noexcept {}

  /**
   * Address: 0x0049EBD0 (FUN_0049EBD0, nullsub_637)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAR() noexcept {}

  /**
   * Address: 0x0049EBF0 (FUN_0049EBF0, nullsub_638)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAS() noexcept {}

  /**
   * Address: 0x0049B7B0 (FUN_0049B7B0, sub_49B7B0)
   *
   * What it does:
   * Duplicate insert-and-grow helper for 4-byte scalar vector lanes.
   */
  std::uint32_t* InsertUInt32ValueAtAndGrowDuplicate(
    UInt32VectorRuntimeView& values,
    std::uint32_t* const insertPosition,
    const std::uint32_t value
  )
  {
    const std::size_t count = VectorCount(values);
    const std::size_t capacity = VectorCapacity(values);
    const std::size_t maxCount = GetLegacyVectorMaxElementCount_0x3FFFFFFF_DuplicateA();

    if (count >= maxCount) {
      ThrowLegacyVectorTooLongDuplicateG();
    }

    std::size_t insertIndex = count;
    if (values.begin != nullptr &&
        values.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= values.begin &&
        insertPosition <= values.end) {
      insertIndex = static_cast<std::size_t>(insertPosition - values.begin);
    }

    if (count < capacity && values.begin != nullptr && values.end != nullptr) {
      std::uint32_t* const destination = values.begin + insertIndex;
      if (destination != values.end) {
        (void)CopyUInt32RangeAndReturnEndB(values.end, values.end - 1, values.end);
        (void)CopyUInt32RangeToTailAndReturnBeginB(values.end - 1, values.end, destination);
      }
      *destination = value;
      ++values.end;
      return destination;
    }

    const std::size_t grown = ((maxCount - (count >> 1U)) >= count) ? (count + (count >> 1U)) : 0U;
    std::size_t newCapacity = grown;
    if (newCapacity < count + 1U) {
      newCapacity = count + 1U;
    }

    auto* const newStorage = static_cast<std::uint32_t*>(
      AllocateUInt32ArrayOrThrowB(static_cast<std::uint32_t>(newCapacity))
    );
    std::uint32_t* const inserted = newStorage + insertIndex;

    if (insertIndex != 0U && values.begin != nullptr) {
      (void)CopyUInt32RangeAndReturnEndB(newStorage, values.begin, values.begin + insertIndex);
    }

    *inserted = value;

    if ((count - insertIndex) != 0U && values.begin != nullptr) {
      (void)CopyUInt32RangeAndReturnEndB(inserted + 1, values.begin + insertIndex, values.end);
    }

    if (values.begin != nullptr) {
      ::operator delete(values.begin);
    }

    values.begin = newStorage;
    values.end = newStorage + count + 1U;
    values.capacityEnd = newStorage + newCapacity;
    return inserted;
  }

  /**
   * Address: 0x00497000 (FUN_00497000, sub_497000)
   *
   * What it does:
   * Appends one `uint32_t` scalar from caller slot into one debug-vector lane,
   * growing storage when required.
   */
  std::uint32_t PushBackUInt32ValueFromSlot(
    const std::uint32_t* const valueSlot,
    UInt32VectorRuntimeView& values
  )
  {
    const std::uint32_t value = *valueSlot;
    (void)InsertUInt32ValueAtAndGrowDuplicate(values, values.end, value);
    return value;
  }

  /**
   * Address: 0x00497080 (FUN_00497080, sub_497080)
   *
   * What it does:
   * Returns one 32-bit scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUint32SlotValueA(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x004970A0 (FUN_004970A0, sub_4970A0)
   *
   * What it does:
   * Duplicate interval-pointer indexing thunk computed from one base-pointer
   * slot and one element index.
   */
  moho::ParticleRenderIntervalRuntime** GetIntervalPointerAtIndexDuplicate(
    moho::ParticleRenderIntervalRuntime** const outIntervalPointer,
    moho::ParticleRenderIntervalRuntime* const* const basePointerSlot,
    const std::int32_t index
  ) noexcept
  {
    return GetIntervalPointerAtIndex(outIntervalPointer, basePointerSlot, index);
  }

  /**
   * Address: 0x004970C0 (FUN_004970C0, sub_4970C0)
   *
   * What it does:
   * Returns one 32-bit scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUint32SlotValueB(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00497100 (FUN_00497100, sub_497100)
   *
   * What it does:
   * Returns one 32-bit scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadUint32SlotValueC(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  constexpr std::uint8_t kTrailSegmentPoolColorRed = 0U;
  constexpr std::uint8_t kTrailSegmentPoolColorBlack = 1U;
  constexpr std::uint32_t kLegacyListMaxSize = 0x3FFFFFFFU;

  [[nodiscard]] std::uint32_t IncrementLegacyListSizeChecked(
    moho::ParticleBufferPoolListRuntime& listRuntime
  )
  {
    if (listRuntime.size == kLegacyListMaxSize) {
      throw std::length_error("list<T> too long");
    }

    ++listRuntime.size;
    return listRuntime.size;
  }

  [[nodiscard]] bool IsTrailSegmentPoolSentinel(
    const moho::TrailSegmentPoolNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || node->isNil != 0U;
  }

  [[nodiscard]] bool IsTrailSegmentPoolNodeBlack(
    const moho::TrailSegmentPoolNodeRuntime* const node
  ) noexcept
  {
    return IsTrailSegmentPoolSentinel(node) || node->color == kTrailSegmentPoolColorBlack;
  }

  [[nodiscard]] std::uintptr_t TrailSegmentPointerKey(
    const moho::TrailSegmentBufferRuntime* const segmentBuffer
  ) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(segmentBuffer);
  }

  [[nodiscard]] bool IsTrailSegmentPointerLess(
    const moho::TrailSegmentBufferRuntime* const lhs,
    const moho::TrailSegmentBufferRuntime* const rhs
  ) noexcept
  {
    return TrailSegmentPointerKey(lhs) < TrailSegmentPointerKey(rhs);
  }

  /**
   * What it does:
   * One iterator/insert-result lane used by legacy trail-segment pool helpers.
   */
  struct TrailSegmentPoolInsertResultRuntime
  {
    moho::TrailSegmentPoolNodeRuntime* node = nullptr; // +0x00
    std::uint8_t inserted = 0U;                        // +0x04
    std::uint8_t padding05_07[0x03]{};                 // +0x05
  };

  static_assert(
    offsetof(TrailSegmentPoolInsertResultRuntime, node) == 0x00,
    "TrailSegmentPoolInsertResultRuntime::node offset must be 0x00"
  );
  static_assert(
    offsetof(TrailSegmentPoolInsertResultRuntime, inserted) == 0x04,
    "TrailSegmentPoolInsertResultRuntime::inserted offset must be 0x04"
  );
  static_assert(
    sizeof(TrailSegmentPoolInsertResultRuntime) == 0x08,
    "TrailSegmentPoolInsertResultRuntime size must be 0x08"
  );

  /**
   * Address: 0x00498080 (FUN_00498080, sub_498080)
   * Address: 0x0087CC40 (FUN_0087CC40)
   *
   * What it does:
   * Walks one trail-segment pool subtree to its left-most node and returns
   * that iterator position.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* TrailSegmentPoolMinimum(
    moho::TrailSegmentPoolNodeRuntime* node
  ) noexcept
  {
    while (!IsTrailSegmentPoolSentinel(node->left)) {
      node = node->left;
    }
    return node;
  }

  /**
   * Address: 0x00498060 (FUN_00498060, sub_498060)
   * Address: 0x0087CC20 (FUN_0087CC20)
   *
   * What it does:
   * Walks one trail-segment pool subtree to its right-most node and returns
   * that iterator position.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* TrailSegmentPoolMaximum(
    moho::TrailSegmentPoolNodeRuntime* node
  ) noexcept
  {
    while (!IsTrailSegmentPoolSentinel(node->right)) {
      node = node->right;
    }
    return node;
  }

  /**
   * Address: 0x0049AD20 (FUN_0049AD20, sub_49AD20)
   *
   * What it does:
   * Advances one trail-segment-pool iterator to its in-order successor.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* NextTrailSegmentPoolNode(
    moho::TrailSegmentPoolNodeRuntime* node,
    const moho::TrailSegmentPoolNodeRuntime* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr) {
      return nullptr;
    }

    if (!IsTrailSegmentPoolSentinel(node->right)) {
      return TrailSegmentPoolMinimum(node->right);
    }

    moho::TrailSegmentPoolNodeRuntime* parent = node->parent;
    while (!IsTrailSegmentPoolSentinel(parent) && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return parent;
  }

  /**
   * Address: 0x0049CDA0 (FUN_0049CDA0, sub_49CDA0)
   *
   * What it does:
   * Moves one trail-segment pool iterator to its in-order predecessor (or max
   * node when called with the head sentinel), updating the caller's iterator
   * slot in-place.
   */
  [[maybe_unused]] moho::TrailSegmentPoolNodeRuntime* MoveTrailSegmentPoolIteratorToPrevious(
    moho::TrailSegmentPoolNodeRuntime** const inOutNode
  ) noexcept
  {
    if (inOutNode == nullptr || *inOutNode == nullptr) {
      return nullptr;
    }

    moho::TrailSegmentPoolNodeRuntime* node = *inOutNode;
    if (IsTrailSegmentPoolSentinel(node)) {
      *inOutNode = node->right;
      return *inOutNode;
    }

    if (!IsTrailSegmentPoolSentinel(node->left)) {
      moho::TrailSegmentPoolNodeRuntime* rightMost = node->left;
      while (!IsTrailSegmentPoolSentinel(rightMost->right)) {
        rightMost = rightMost->right;
      }
      *inOutNode = rightMost;
      return rightMost;
    }

    moho::TrailSegmentPoolNodeRuntime* parent = node->parent;
    while (!IsTrailSegmentPoolSentinel(parent) && node == parent->left) {
      node = parent;
      parent = parent->parent;
    }

    *inOutNode = parent;
    return parent;
  }

  /**
   * Address: 0x00497E10 (FUN_00497E10, sub_497E10)
   *
   * What it does:
   * Recursively destroys one trail-segment-pool RB-tree subtree by visiting the
   * right branch first, then walking the left spine.
   */
  void DestroyTrailSegmentPoolSubtreeNodes(moho::TrailSegmentPoolNodeRuntime* node) noexcept
  {
    while (!IsTrailSegmentPoolSentinel(node)) {
      DestroyTrailSegmentPoolSubtreeNodes(node->right);
      moho::TrailSegmentPoolNodeRuntime* const next = node->left;
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x0049EC00 (FUN_0049EC00, sub_49EC00)
   *
   * What it does:
   * Allocates one trail-segment-pool node array lane (`0x14` bytes per
   * element) and throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateTrailSegmentPoolNodeArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kTrailSegmentPoolNodeSize = sizeof(moho::TrailSegmentPoolNodeRuntime);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kTrailSegmentPoolNodeSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kTrailSegmentPoolNodeSize);
  }

  /**
   * Address: 0x0049EC60 (FUN_0049EC60, nullsub_639)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAT() noexcept {}

  /**
   * Address: 0x0049EC80 (FUN_0049EC80, nullsub_640)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAU() noexcept {}

  /**
   * Address: 0x0049A7B0 (FUN_0049A7B0, sub_49A7B0)
   *
   * What it does:
   * Allocates one trail-segment-pool node and initializes link/key/color lanes
   * from caller-provided slots.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* AllocateTrailSegmentPoolNodeWithLinks(
    moho::TrailSegmentPoolNodeRuntime* const left,
    moho::TrailSegmentPoolNodeRuntime* const parent,
    moho::TrailSegmentPoolNodeRuntime* const right,
    moho::TrailSegmentBufferRuntime* const* const segmentBufferSlot
  )
  {
    auto* const node = static_cast<moho::TrailSegmentPoolNodeRuntime*>(AllocateTrailSegmentPoolNodeArrayOrThrow(1U));
    node->left = left;
    node->parent = parent;
    node->right = right;
    node->segmentBuffer = segmentBufferSlot != nullptr ? *segmentBufferSlot : nullptr;
    node->color = 0U;
    node->isNil = 0U;
    node->padding12 = 0U;
    return node;
  }

  moho::TrailSegmentPoolNodeRuntime** EraseTrailSegmentPoolNodeAndStoreSuccessor(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime** outSuccessor,
    moho::TrailSegmentPoolNodeRuntime* eraseTarget
  );

  /**
   * Address: 0x0049A6C0 (FUN_0049A6C0, sub_49A6C0)
   *
   * What it does:
   * Erases one trail-segment-pool node iterator range and writes the successor
   * iterator lane back to caller storage.
   */
  moho::TrailSegmentPoolNodeRuntime** EraseTrailSegmentPoolNodeRangeAndStoreIterator(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime** const outIterator,
    moho::TrailSegmentPoolNodeRuntime* eraseBegin,
    const moho::TrailSegmentPoolNodeRuntime* const eraseEnd
  ) noexcept
  {
    if (pool.head == nullptr) {
      *outIterator = nullptr;
      return outIterator;
    }

    if (eraseBegin == pool.head->left && eraseEnd == pool.head) {
      DestroyTrailSegmentPoolSubtreeNodes(pool.head->parent);
      pool.head->parent = pool.head;
      pool.size = 0U;
      pool.head->left = pool.head;
      pool.head->right = pool.head;
      *outIterator = pool.head->left;
      return outIterator;
    }

    while (eraseBegin != eraseEnd) {
      moho::TrailSegmentPoolNodeRuntime* const eraseTarget = eraseBegin;
      (void)EraseTrailSegmentPoolNodeAndStoreSuccessor(pool, &eraseBegin, eraseTarget);
    }

    *outIterator = eraseBegin;
    return outIterator;
  }

  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* TrailSegmentPoolLowerBound(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentBufferRuntime* const key
  ) noexcept
  {
    moho::TrailSegmentPoolNodeRuntime* result = pool.head;
    if (result == nullptr) {
      return nullptr;
    }

    moho::TrailSegmentPoolNodeRuntime* node = result->parent;
    while (!IsTrailSegmentPoolSentinel(node)) {
      if (!IsTrailSegmentPointerLess(node->segmentBuffer, key)) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return result;
  }

  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* TrailSegmentPoolFindEquivalentOrHead(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentBufferRuntime* const key
  ) noexcept
  {
    moho::TrailSegmentPoolNodeRuntime* const lowerBound = TrailSegmentPoolLowerBound(pool, key);
    if (lowerBound == nullptr || lowerBound == pool.head) {
      return pool.head;
    }
    return IsTrailSegmentPointerLess(key, lowerBound->segmentBuffer) ? pool.head : lowerBound;
  }

  /**
   * Address: 0x00498010 (FUN_00498010, sub_498010)
   *
   * What it does:
   * Performs one RB-tree left rotation in the trail-segment pool map lane.
   */
  void TrailSegmentPoolRotateLeft(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime* const pivot
  ) noexcept
  {
    if (IsTrailSegmentPoolSentinel(pivot) || IsTrailSegmentPoolSentinel(pivot->right)) {
      return;
    }

    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;
    moho::TrailSegmentPoolNodeRuntime* const right = pivot->right;

    pivot->right = right->left;
    if (!IsTrailSegmentPoolSentinel(right->left)) {
      right->left->parent = pivot;
    }

    right->parent = pivot->parent;
    if (IsTrailSegmentPoolSentinel(pivot->parent)) {
      head->parent = right;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = right;
    } else {
      pivot->parent->right = right;
    }

    right->left = pivot;
    pivot->parent = right;
  }

  /**
   * Address: 0x004980C0 (FUN_004980C0, sub_4980C0)
   *
   * What it does:
   * Performs one RB-tree right rotation in the trail-segment pool map lane.
   */
  void TrailSegmentPoolRotateRight(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime* const pivot
  ) noexcept
  {
    if (IsTrailSegmentPoolSentinel(pivot) || IsTrailSegmentPoolSentinel(pivot->left)) {
      return;
    }

    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;
    moho::TrailSegmentPoolNodeRuntime* const left = pivot->left;

    pivot->left = left->right;
    if (!IsTrailSegmentPoolSentinel(left->right)) {
      left->right->parent = pivot;
    }

    left->parent = pivot->parent;
    if (IsTrailSegmentPoolSentinel(pivot->parent)) {
      head->parent = left;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = left;
    } else {
      pivot->parent->left = left;
    }

    left->right = pivot;
    pivot->parent = left;
  }

  void TrailSegmentPoolInsertFixup(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime* node
  ) noexcept
  {
    while (!IsTrailSegmentPoolSentinel(node->parent) && node->parent->color == kTrailSegmentPoolColorRed) {
      moho::TrailSegmentPoolNodeRuntime* const parent = node->parent;
      moho::TrailSegmentPoolNodeRuntime* const grandparent = parent->parent;
      if (parent == grandparent->left) {
        moho::TrailSegmentPoolNodeRuntime* uncle = grandparent->right;
        if (!IsTrailSegmentPoolSentinel(uncle) && uncle->color == kTrailSegmentPoolColorRed) {
          parent->color = kTrailSegmentPoolColorBlack;
          uncle->color = kTrailSegmentPoolColorBlack;
          grandparent->color = kTrailSegmentPoolColorRed;
          node = grandparent;
        } else {
          if (node == parent->right) {
            node = parent;
            TrailSegmentPoolRotateLeft(pool, node);
          }
          node->parent->color = kTrailSegmentPoolColorBlack;
          node->parent->parent->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateRight(pool, node->parent->parent);
        }
      } else {
        moho::TrailSegmentPoolNodeRuntime* uncle = grandparent->left;
        if (!IsTrailSegmentPoolSentinel(uncle) && uncle->color == kTrailSegmentPoolColorRed) {
          parent->color = kTrailSegmentPoolColorBlack;
          uncle->color = kTrailSegmentPoolColorBlack;
          grandparent->color = kTrailSegmentPoolColorRed;
          node = grandparent;
        } else {
          if (node == parent->left) {
            node = parent;
            TrailSegmentPoolRotateRight(pool, node);
          }
          node->parent->color = kTrailSegmentPoolColorBlack;
          node->parent->parent->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateLeft(pool, node->parent->parent);
        }
      }
    }

    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;
    moho::TrailSegmentPoolNodeRuntime* const root = head != nullptr ? head->parent : nullptr;
    if (!IsTrailSegmentPoolSentinel(root)) {
      root->color = kTrailSegmentPoolColorBlack;
      root->parent = head;
    }
  }

  /**
   * Address: 0x00497E50 (FUN_00497E50, sub_497E50)
   *
   * What it does:
   * Inserts one trail-segment buffer key into the pool RB-tree and applies
   * insertion rebalancing while preserving head/begin/end sentinel lanes.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* InsertTrailSegmentPoolNode(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentBufferRuntime* const segmentBuffer
  )
  {
    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;
    if (head == nullptr) {
      return nullptr;
    }

    if (moho::TrailSegmentPoolNodeRuntime* const existing = TrailSegmentPoolFindEquivalentOrHead(pool, segmentBuffer);
        existing != head) {
      return existing;
    }

    moho::TrailSegmentBufferRuntime* segmentBufferSlot = segmentBuffer;
    auto* const inserted = AllocateTrailSegmentPoolNodeWithLinks(head, head, head, &segmentBufferSlot);
    inserted->color = kTrailSegmentPoolColorRed;

    moho::TrailSegmentPoolNodeRuntime* parent = head;
    moho::TrailSegmentPoolNodeRuntime* node = head->parent;
    bool insertAsLeftChild = true;
    while (!IsTrailSegmentPoolSentinel(node)) {
      parent = node;
      if (IsTrailSegmentPointerLess(segmentBuffer, node->segmentBuffer)) {
        node = node->left;
        insertAsLeftChild = true;
      } else {
        node = node->right;
        insertAsLeftChild = false;
      }
    }

    inserted->parent = parent;
    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
      inserted->parent = head;
    } else if (insertAsLeftChild) {
      parent->left = inserted;
      if (head->left == parent || IsTrailSegmentPointerLess(inserted->segmentBuffer, head->left->segmentBuffer)) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (head->right == parent || IsTrailSegmentPointerLess(head->right->segmentBuffer, inserted->segmentBuffer)) {
        head->right = inserted;
      }
    }

    ++pool.size;
    TrailSegmentPoolInsertFixup(pool, inserted);
    return inserted;
  }

  /**
   * Address: 0x00496000 (FUN_00496000, sub_496000)
   *
   * What it does:
   * Finds or inserts one trail-segment pool node by pointer key and records
   * whether insertion occurred.
   */
  TrailSegmentPoolInsertResultRuntime* FindOrInsertTrailSegmentPoolNodeByKey(
    moho::TrailSegmentPoolRuntime& pool,
    const moho::TrailSegmentBufferRuntime* const* const key,
    TrailSegmentPoolInsertResultRuntime* const outResult
  )
  {
    moho::TrailSegmentBufferRuntime* const keyBuffer = const_cast<moho::TrailSegmentBufferRuntime*>(*key);
    moho::TrailSegmentPoolNodeRuntime* const lowerBound = TrailSegmentPoolLowerBound(pool, keyBuffer);

    if (lowerBound != pool.head && !IsTrailSegmentPointerLess(keyBuffer, lowerBound->segmentBuffer)) {
      outResult->node = lowerBound;
      outResult->inserted = 0U;
      return outResult;
    }

    outResult->node = InsertTrailSegmentPoolNode(pool, keyBuffer);
    outResult->inserted = 1U;
    return outResult;
  }

  void TrailSegmentPoolEraseFixup(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime* node,
    moho::TrailSegmentPoolNodeRuntime* parent
  ) noexcept
  {
    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;

    while (node != head->parent && IsTrailSegmentPoolNodeBlack(node)) {
      if (node == parent->left) {
        moho::TrailSegmentPoolNodeRuntime* sibling = parent->right;

        if (!IsTrailSegmentPoolSentinel(sibling) && sibling->color == kTrailSegmentPoolColorRed) {
          sibling->color = kTrailSegmentPoolColorBlack;
          parent->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateLeft(pool, parent);
          sibling = parent->right;
        }

        if (IsTrailSegmentPoolSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailSegmentPoolNodeBlack(sibling->left) && IsTrailSegmentPoolNodeBlack(sibling->right)) {
          sibling->color = kTrailSegmentPoolColorRed;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailSegmentPoolNodeBlack(sibling->right)) {
          if (!IsTrailSegmentPoolSentinel(sibling->left)) {
            sibling->left->color = kTrailSegmentPoolColorBlack;
          }
          sibling->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateRight(pool, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = kTrailSegmentPoolColorBlack;
        if (!IsTrailSegmentPoolSentinel(sibling->right)) {
          sibling->right->color = kTrailSegmentPoolColorBlack;
        }
        TrailSegmentPoolRotateLeft(pool, parent);
      } else {
        moho::TrailSegmentPoolNodeRuntime* sibling = parent->left;

        if (!IsTrailSegmentPoolSentinel(sibling) && sibling->color == kTrailSegmentPoolColorRed) {
          sibling->color = kTrailSegmentPoolColorBlack;
          parent->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateRight(pool, parent);
          sibling = parent->left;
        }

        if (IsTrailSegmentPoolSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailSegmentPoolNodeBlack(sibling->right) && IsTrailSegmentPoolNodeBlack(sibling->left)) {
          sibling->color = kTrailSegmentPoolColorRed;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailSegmentPoolNodeBlack(sibling->left)) {
          if (!IsTrailSegmentPoolSentinel(sibling->right)) {
            sibling->right->color = kTrailSegmentPoolColorBlack;
          }
          sibling->color = kTrailSegmentPoolColorRed;
          TrailSegmentPoolRotateLeft(pool, sibling);
          sibling = parent->left;
        }

        sibling->color = parent->color;
        parent->color = kTrailSegmentPoolColorBlack;
        if (!IsTrailSegmentPoolSentinel(sibling->left)) {
          sibling->left->color = kTrailSegmentPoolColorBlack;
        }
        TrailSegmentPoolRotateRight(pool, parent);
      }

      break;
    }

    if (!IsTrailSegmentPoolSentinel(node)) {
      node->color = kTrailSegmentPoolColorBlack;
    }
  }

  void EraseTrailSegmentPoolNode(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime* const eraseTarget
  )
  {
    moho::TrailSegmentPoolNodeRuntime* const head = pool.head;
    if (IsTrailSegmentPoolSentinel(eraseTarget) || IsTrailSegmentPoolSentinel(head)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    moho::TrailSegmentPoolNodeRuntime* const next = NextTrailSegmentPoolNode(eraseTarget, head);
    moho::TrailSegmentPoolNodeRuntime* fixupNode = nullptr;
    moho::TrailSegmentPoolNodeRuntime* fixupParent = nullptr;

    if (IsTrailSegmentPoolSentinel(eraseTarget->left)) {
      fixupNode = eraseTarget->right;
      fixupParent = eraseTarget->parent;
      if (!IsTrailSegmentPoolSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsTrailSegmentPoolSentinel(fixupNode) ? fixupParent : TrailSegmentPoolMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsTrailSegmentPoolSentinel(fixupNode) ? fixupParent : TrailSegmentPoolMaximum(fixupNode);
      }
    } else if (IsTrailSegmentPoolSentinel(eraseTarget->right)) {
      fixupNode = eraseTarget->left;
      fixupParent = eraseTarget->parent;
      if (!IsTrailSegmentPoolSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsTrailSegmentPoolSentinel(fixupNode) ? fixupParent : TrailSegmentPoolMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsTrailSegmentPoolSentinel(fixupNode) ? fixupParent : TrailSegmentPoolMaximum(fixupNode);
      }
    } else {
      moho::TrailSegmentPoolNodeRuntime* const successor = next;
      fixupNode = successor->right;

      if (successor == eraseTarget->right) {
        fixupParent = successor;
      } else {
        fixupParent = successor->parent;
        if (!IsTrailSegmentPoolSentinel(fixupNode)) {
          fixupNode->parent = fixupParent;
        }
        fixupParent->left = fixupNode;

        successor->right = eraseTarget->right;
        successor->right->parent = successor;
      }

      if (head->parent == eraseTarget) {
        head->parent = successor;
      } else if (eraseTarget->parent->left == eraseTarget) {
        eraseTarget->parent->left = successor;
      } else {
        eraseTarget->parent->right = successor;
      }

      successor->parent = eraseTarget->parent;
      successor->left = eraseTarget->left;
      successor->left->parent = successor;
      std::swap(successor->color, eraseTarget->color);
    }

    if (eraseTarget->color == kTrailSegmentPoolColorBlack) {
      TrailSegmentPoolEraseFixup(pool, fixupNode, fixupParent);
    }

    ::operator delete(eraseTarget);
    if (pool.size != 0U) {
      --pool.size;
    }
  }

  /**
   * Address: 0x004960C0 (FUN_004960C0, sub_4960C0)
   *
   * What it does:
   * Erases one trail-segment pool node by iterator and stores the successor
   * iterator for caller traversal.
   */
  moho::TrailSegmentPoolNodeRuntime** EraseTrailSegmentPoolNodeAndStoreSuccessor(
    moho::TrailSegmentPoolRuntime& pool,
    moho::TrailSegmentPoolNodeRuntime** const outSuccessor,
    moho::TrailSegmentPoolNodeRuntime* const eraseTarget
  )
  {
    moho::TrailSegmentPoolNodeRuntime* const successor = NextTrailSegmentPoolNode(eraseTarget, pool.head);
    EraseTrailSegmentPoolNode(pool, eraseTarget);
    *outSuccessor = successor;
    return outSuccessor;
  }

  [[nodiscard]] bool AppendInterval(
    moho::ParticleRenderWorkItemRuntime& workItem, const float beginFrame, const float lifeFrames
  )
  {
    auto* const intervalVector = reinterpret_cast<IntervalVectorRuntimeView*>(&workItem.mReserved04);
    const moho::ParticleRenderIntervalRuntime intervalValue{beginFrame, lifeFrames};
    return AppendIntervalVectorValue(*intervalVector, intervalValue) != nullptr;
  }

  /**
   * What it does:
   * Packed vertex lane emitted by trail work-item upload paths.
   */
  struct TrailSegmentPackedVertexRuntime
  {
    float lane[13]{}; // 13 floats = 0x34 bytes, matching the recovered stream write width.
  };

  static_assert(sizeof(TrailSegmentPackedVertexRuntime) == 0x34, "TrailSegmentPackedVertexRuntime size must be 0x34");

  /**
   * What it does:
   * Packs one trail payload into four consecutive trail-segment vertices using
   * the recovered binary field shuffle.
   */
  void PackTrailSegmentQuadVertices(
    float* const outVertices,
    const float* const trailFloats
  )
  {
    const float* const trail = trailFloats;

    outVertices[0] = trail[0];
    outVertices[1] = trail[1];
    outVertices[2] = trail[2];
    outVertices[3] = -trail[6];
    outVertices[4] = -trail[7];
    outVertices[5] = -trail[8];
    outVertices[6] = trail[12];
    outVertices[7] = trail[14];
    outVertices[8] = trail[16];
    outVertices[9] = trail[19];
    outVertices[10] = 0.0f;
    outVertices[11] = 1.0f;
    outVertices[12] = trail[15];

    outVertices[13] = trail[3];
    outVertices[14] = trail[4];
    outVertices[15] = trail[5];
    outVertices[16] = -trail[9];
    outVertices[17] = -trail[10];
    outVertices[18] = -trail[11];
    outVertices[19] = trail[13];
    outVertices[20] = trail[14];
    outVertices[21] = trail[17];
    outVertices[22] = trail[19];
    outVertices[23] = 0.0f;
    outVertices[24] = 1.0f;
    outVertices[25] = trail[15];

    outVertices[26] = trail[3];
    outVertices[27] = trail[4];
    outVertices[28] = trail[5];
    outVertices[29] = trail[9];
    outVertices[30] = trail[10];
    outVertices[31] = trail[11];
    outVertices[32] = trail[13];
    outVertices[33] = trail[14];
    outVertices[34] = trail[17];
    outVertices[35] = trail[19];
    outVertices[36] = 0.0f;
    outVertices[37] = 0.0f;
    outVertices[38] = trail[15];

    outVertices[39] = trail[0];
    outVertices[40] = trail[1];
    outVertices[41] = trail[2];
    outVertices[42] = trail[6];
    outVertices[43] = trail[7];
    outVertices[44] = trail[8];
    outVertices[45] = trail[12];
    outVertices[46] = trail[14];
    outVertices[47] = trail[16];
    outVertices[48] = trail[19];
    outVertices[49] = 0.0f;
    outVertices[50] = 0.0f;
    outVertices[51] = trail[15];
  }

  /**
   * Address: 0x0049BC00 (FUN_0049BC00, ??0SWorldParticle@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Copies one world-particle payload lane with typed field assignment,
   * reference-counted texture retention, and string copy semantics.
   */
  void CopyWorldParticleForVectorMove(
    const moho::SWorldParticle& source, moho::SWorldParticle& destination
  ) noexcept
  {
    destination.mEnabled = source.mEnabled;
    destination.mResistance = source.mResistance;
    destination.mPos = source.mPos;
    destination.mDir = source.mDir;
    destination.mAccel = source.mAccel;
    destination.mInterop = source.mInterop;
    destination.mLifetime = source.mLifetime;
    destination.mFramerate = source.mFramerate;
    destination.mValue1 = source.mValue1;
    destination.mTextureSelection = source.mTextureSelection;
    destination.mValue3 = source.mValue3;
    destination.mRampSelection = source.mRampSelection;
    destination.mBeginSize = source.mBeginSize;
    destination.mEndSize = source.mEndSize;
    destination.mAngle = source.mAngle;
    destination.mRotationCurve = source.mRotationCurve;
    destination.mReserved54 = source.mReserved54;
    (void)moho::AssignCountedParticleTexturePtr(&destination.mTexture, source.mTexture.tex);
    (void)moho::AssignCountedParticleTexturePtr(&destination.mRampTexture, source.mRampTexture.tex);
    destination.mTypeTag.assign(source.mTypeTag, 0U, msvc8::string::npos);
    destination.mArmyIndex = source.mArmyIndex;
    destination.mBlendMode = source.mBlendMode;
    destination.mZMode = source.mZMode;
  }

  /**
   * Address: 0x0049BD30 (FUN_0049BD30, ??1SParticle@Moho@@QAE@@Z)
   *
   * What it does:
   * Releases one world-particle tail payload lane (`typeTag` + both counted
   * texture handles) during vector erase/reallocation paths.
   */
  void DestroyWorldParticleForVectorTail(moho::SWorldParticle& particle) noexcept
  {
    moho::ResetCountedParticleTexturePtr(particle.mTexture);
    moho::ResetCountedParticleTexturePtr(particle.mRampTexture);
    particle.mTypeTag.tidy(true, 0U);
  }

  void AssignTrailTextureLane(
    moho::CParticleTexture*& destination, moho::CParticleTexture* const source
  ) noexcept
  {
    if (destination != source) {
      if (destination != nullptr) {
        destination->ReleaseReferenceAtomic();
      }
      destination = source;
      if (source != nullptr) {
        source->AddReferenceAtomic();
      }
    }
  }

  /**
   * Address: 0x0049BDD0 (FUN_0049BDD0, sub_49BDD0)
   *
   * What it does:
   * Copies one trail-runtime payload lane, retaining both texture references.
   */
  void CopyTrailRuntimeViewForVectorMove(
    const moho::TrailRuntimeView& source, moho::TrailRuntimeView& destination
  ) noexcept
  {
    std::memcpy(destination.unknownPrefix, source.unknownPrefix, sizeof(destination.unknownPrefix));
    destination.sortScalar = source.sortScalar;
    std::memcpy(destination.unknown4C, source.unknown4C, sizeof(destination.unknown4C));
    AssignTrailTextureLane(destination.texture0, source.texture0);
    AssignTrailTextureLane(destination.texture1, source.texture1);
    destination.tag = source.tag;
    destination.uvScalar = source.uvScalar;
  }

  /**
   * Address: 0x0049BE90 (FUN_0049BE90, ??1STrail@Moho@@QAE@@Z)
   *
   * What it does:
   * Releases the two intrusive trail texture lanes and nulls them on one trail
   * runtime payload.
   */
  void DestroyTrailRuntimeViewForVectorTail(moho::TrailRuntimeView& trail) noexcept
  {
    AssignTrailTextureLane(trail.texture0, nullptr);
    AssignTrailTextureLane(trail.texture1, nullptr);
  }

  void DestroyWorldParticleRange(
    moho::SWorldParticle* begin,
    moho::SWorldParticle* end
  ) noexcept;

  void DestroyTrailRuntimeRange(
    moho::TrailRuntimeView* begin,
    moho::TrailRuntimeView* end
  ) noexcept;

  /**
   * Address: 0x00497200 (FUN_00497200, sub_497200)
   *
   * What it does:
   * Duplicate end-pointer accessor thunk for one world-particle debug-vector
   * lane.
   */
  moho::SWorldParticle** GetWorldParticleVectorEndPointerDuplicate(
    moho::SWorldParticle** const outEnd,
    const moho::RenderBucketVectorRuntime<moho::SWorldParticle>& pendingParticles
  ) noexcept
  {
    *outEnd = pendingParticles.end;
    return outEnd;
  }

  /**
   * Address: 0x0049E400 (FUN_0049E400, sub_49E400)
   *
   * What it does:
   * Copies one world-particle source value across one destination range.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyWorldParticleValueAcrossRange(
    const moho::SWorldParticle& sourceParticle,
    moho::SWorldParticle* destinationBegin,
    const moho::SWorldParticle* const destinationEnd
  ) noexcept
  {
    moho::SWorldParticle* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      CopyWorldParticleForVectorMove(sourceParticle, *destinationBegin);
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049E430 (FUN_0049E430, sub_49E430)
   *
   * What it does:
   * Shifts one world-particle tail range right by one element using backward
   * copy order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::SWorldParticle* ShiftWorldParticleRangeRightByOneAndReturnWriteCursor(
    moho::SWorldParticle* sourceLast,
    moho::SWorldParticle* destinationEnd,
    const moho::SWorldParticle* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      CopyWorldParticleForVectorMove(*sourceLast, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049E460 (FUN_0049E460, sub_49E460)
   *
   * What it does:
   * Allocates one world-particle array lane (`0x8C` bytes per element) and
   * throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateWorldParticleArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kWorldParticleSize = sizeof(moho::SWorldParticle);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kWorldParticleSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kWorldParticleSize);
  }

  /**
   * Address: 0x0049E4B0 (FUN_0049E4B0, sub_49E4B0)
   *
   * What it does:
   * Copies one trail-runtime range (`[sourceBegin, sourceEnd)`) into
   * destination storage and returns the destination end pointer.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyTrailRuntimeRangeAndReturnEnd(
    moho::TrailRuntimeView* destination,
    const moho::TrailRuntimeView* sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        CopyTrailRuntimeViewForVectorMove(*sourceBegin, *destination);
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0049E4E0 (FUN_0049E4E0, sub_49E4E0)
   *
   * What it does:
   * Copies one trail-runtime source value across one destination range.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyTrailRuntimeValueAcrossRange(
    const moho::TrailRuntimeView& sourceTrail,
    moho::TrailRuntimeView* destinationBegin,
    const moho::TrailRuntimeView* const destinationEnd
  ) noexcept
  {
    moho::TrailRuntimeView* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      CopyTrailRuntimeViewForVectorMove(sourceTrail, *destinationBegin);
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049E500 (FUN_0049E500, sub_49E500)
   *
   * What it does:
   * Shifts one trail-runtime tail range right by one element using backward
   * copy order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::TrailRuntimeView* ShiftTrailRuntimeRangeRightByOneAndReturnWriteCursor(
    moho::TrailRuntimeView* sourceLast,
    moho::TrailRuntimeView* destinationEnd,
    const moho::TrailRuntimeView* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      CopyTrailRuntimeViewForVectorMove(*sourceLast, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049E530 (FUN_0049E530, sub_49E530)
   *
   * What it does:
   * Allocates one trail-runtime array lane (`0x60` bytes per element) and
   * throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateTrailRuntimeArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kTrailRuntimeSize = sizeof(moho::TrailRuntimeView);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kTrailRuntimeSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kTrailRuntimeSize);
  }

  /**
   * Address: 0x00499250 (FUN_00499250, sub_499250)
   *
   * What it does:
   * Inserts one world-particle payload into a pending-particle debug-vector
   * lane, growing storage when required.
   */
  void InsertWorldParticleValueAtAndGrow(
    const moho::SWorldParticle& sourceParticle,
    moho::RenderBucketVectorRuntime<moho::SWorldParticle>& pendingParticles,
    moho::SWorldParticle* insertPosition
  )
  {
    constexpr std::size_t kWorldParticleMaxCount = 0x01D41D41U;

    alignas(moho::SWorldParticle) std::uint8_t temporaryStorage[sizeof(moho::SWorldParticle)]{};
    auto* const temporaryParticle = new (temporaryStorage) moho::SWorldParticle{};
    CopyWorldParticleForVectorMove(sourceParticle, *temporaryParticle);

    try {
      const std::size_t size = VectorCount(pendingParticles);
      const std::size_t capacity = VectorCapacity(pendingParticles);

      if (size >= kWorldParticleMaxCount) {
        throw std::length_error("vector<T> too long");
      }

      if (pendingParticles.begin == nullptr || pendingParticles.end == nullptr || insertPosition == nullptr
          || insertPosition < pendingParticles.begin || insertPosition > pendingParticles.end) {
        insertPosition = pendingParticles.end;
      }

      std::size_t insertIndex = size;
      if (pendingParticles.begin != nullptr && insertPosition != nullptr) {
        insertIndex = static_cast<std::size_t>(insertPosition - pendingParticles.begin);
      }
      if (insertIndex > size) {
        insertIndex = size;
      }

      if (capacity < (size + 1U)) {
        std::size_t newCapacity = 0U;
        if (kWorldParticleMaxCount - (capacity >> 1U) >= capacity) {
          newCapacity = capacity + (capacity >> 1U);
        }
        if (newCapacity < (size + 1U)) {
          newCapacity = size + 1U;
        }

        auto* const newStorage =
          static_cast<moho::SWorldParticle*>(AllocateWorldParticleArrayOrThrow(static_cast<std::uint32_t>(newCapacity)));
        std::size_t constructedCount = 0U;

        try {
          for (std::size_t index = 0U; index < insertIndex; ++index) {
            new (newStorage + index) moho::SWorldParticle{};
            CopyWorldParticleForVectorMove(pendingParticles.begin[index], newStorage[index]);
            ++constructedCount;
          }

          new (newStorage + insertIndex) moho::SWorldParticle{};
          CopyWorldParticleForVectorMove(*temporaryParticle, newStorage[insertIndex]);
          ++constructedCount;

          for (std::size_t index = insertIndex; index < size; ++index) {
            new (newStorage + index + 1U) moho::SWorldParticle{};
            CopyWorldParticleForVectorMove(pendingParticles.begin[index], newStorage[index + 1U]);
            ++constructedCount;
          }
        } catch (...) {
          DestroyWorldParticleRange(newStorage, newStorage + constructedCount);
          ::operator delete(newStorage);
          throw;
        }

        if (pendingParticles.begin != nullptr) {
          DestroyWorldParticleRange(pendingParticles.begin, pendingParticles.end);
          ::operator delete(pendingParticles.begin);
        }

        pendingParticles.begin = newStorage;
        pendingParticles.end = newStorage + size + 1U;
        pendingParticles.capacityEnd = newStorage + newCapacity;
      } else {
        moho::SWorldParticle* const oldEnd = pendingParticles.end;
        new (oldEnd) moho::SWorldParticle{};

        if (insertPosition == oldEnd) {
          CopyWorldParticleForVectorMove(*temporaryParticle, oldEnd[0]);
        } else {
          CopyWorldParticleForVectorMove(oldEnd[-1], oldEnd[0]);
          moho::SWorldParticle* const shiftedWriteCursor =
            ShiftWorldParticleRangeRightByOneAndReturnWriteCursor(oldEnd - 1, oldEnd, insertPosition);
          (void)CopyWorldParticleValueAcrossRange(*temporaryParticle, insertPosition, shiftedWriteCursor);
        }

        pendingParticles.end = oldEnd + 1;
      }

      DestroyWorldParticleForVectorTail(*temporaryParticle);
    } catch (...) {
      DestroyWorldParticleForVectorTail(*temporaryParticle);
      throw;
    }
  }

  /**
   * Address: 0x00497210 (FUN_00497210, sub_497210)
   *
   * What it does:
   * Forwards one world-particle insert path and exports the iterator position
   * that maps to the original insertion index.
   */
  moho::SWorldParticle** InsertOneWorldParticleAndExportIterator(
    moho::RenderBucketVectorRuntime<moho::SWorldParticle>& pendingParticles,
    moho::SWorldParticle** const outIterator,
    moho::SWorldParticle* const insertPosition,
    const moho::SWorldParticle* const sourceParticle
  )
  {
    std::size_t index = 0U;
    if (pendingParticles.begin != nullptr &&
        pendingParticles.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= pendingParticles.begin &&
        insertPosition <= pendingParticles.end &&
        pendingParticles.begin != pendingParticles.end) {
      index = static_cast<std::size_t>(insertPosition - pendingParticles.begin);
    }

    if (sourceParticle != nullptr) {
      InsertWorldParticleValueAtAndGrow(*sourceParticle, pendingParticles, insertPosition);
    }

    if (pendingParticles.begin == nullptr) {
      *outIterator = nullptr;
      return outIterator;
    }

    const std::size_t count = VectorCount(pendingParticles);
    if (index > count) {
      index = count;
    }
    *outIterator = pendingParticles.begin + index;
    return outIterator;
  }

  /**
   * Address: 0x004972C0 (FUN_004972C0, sub_4972C0)
   *
   * What it does:
   * Destroys one world-particle range used by vector erase/reallocation paths.
   */
  void DestroyWorldParticleRange(
    moho::SWorldParticle* const begin,
    moho::SWorldParticle* const end
  ) noexcept
  {
    for (moho::SWorldParticle* particle = begin; particle != end; ++particle) {
      DestroyWorldParticleForVectorTail(*particle);
    }
  }

  /**
   * Address: 0x004972E0 (FUN_004972E0, sub_4972E0)
   *
   * What it does:
   * Releases one world-particle debug-vector lane (destroy payload range +
   * free storage) and resets begin/end/capacity pointers.
   */
  void ResetWorldParticleVectorStorageDuplicate(
    moho::RenderBucketVectorRuntime<moho::SWorldParticle>& pendingParticles
  ) noexcept
  {
    if (pendingParticles.begin != nullptr) {
      DestroyWorldParticleRange(pendingParticles.begin, pendingParticles.end);
      ::operator delete(pendingParticles.begin);
    }
    pendingParticles.begin = nullptr;
    pendingParticles.end = nullptr;
    pendingParticles.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00495580 (FUN_00495580)
   *
   * What it does:
   * Thunk lane that forwards one world-particle vector storage cleanup request
   * into `FUN_004972E0`.
   */
  [[maybe_unused]] void ResetWorldParticleVectorStorageDuplicateThunk(
    moho::RenderBucketVectorRuntime<moho::SWorldParticle>& pendingParticles
  ) noexcept
  {
    ResetWorldParticleVectorStorageDuplicate(pendingParticles);
  }

  /**
   * Address: 0x00497330 (FUN_00497330, sub_497330)
   *
   * What it does:
   * Copy-constructs one world-particle range into uninitialized destination
   * storage and rolls back constructed elements on failure.
   */
  void CopyConstructWorldParticleRange(
    moho::SWorldParticle* const destination,
    const std::size_t count,
    const moho::SWorldParticle* const source
  )
  {
    if (destination == nullptr || source == nullptr || count == 0U) {
      return;
    }

    std::size_t constructedCount = 0U;
    try {
      for (; constructedCount < count; ++constructedCount) {
        new (destination + constructedCount) moho::SWorldParticle{};
        CopyWorldParticleForVectorMove(source[constructedCount], destination[constructedCount]);
      }
    } catch (...) {
      DestroyWorldParticleRange(destination, destination + constructedCount);
      throw;
    }
  }

  /**
   * Address: 0x00499630 (FUN_00499630, sub_499630)
   *
   * What it does:
   * Inserts one trail-runtime payload into a pending-trail debug-vector lane,
   * growing storage when required.
   */
  void InsertTrailValueAtAndGrow(
    const moho::TrailRuntimeView& sourceTrail,
    moho::RenderBucketVectorRuntime<moho::TrailRuntimeView>& pendingTrails,
    moho::TrailRuntimeView* insertPosition
  )
  {
    constexpr std::size_t kTrailMaxCount = 0x02AAAAAAU;

    alignas(moho::TrailRuntimeView) std::uint8_t temporaryStorage[sizeof(moho::TrailRuntimeView)]{};
    auto* const temporaryTrail = new (temporaryStorage) moho::TrailRuntimeView{};
    CopyTrailRuntimeViewForVectorMove(sourceTrail, *temporaryTrail);

    try {
      const std::size_t size = VectorCount(pendingTrails);
      const std::size_t capacity = VectorCapacity(pendingTrails);

      if (size >= kTrailMaxCount) {
        throw std::length_error("vector<T> too long");
      }

      if (pendingTrails.begin == nullptr || pendingTrails.end == nullptr || insertPosition == nullptr
          || insertPosition < pendingTrails.begin || insertPosition > pendingTrails.end) {
        insertPosition = pendingTrails.end;
      }

      std::size_t insertIndex = size;
      if (pendingTrails.begin != nullptr && insertPosition != nullptr) {
        insertIndex = static_cast<std::size_t>(insertPosition - pendingTrails.begin);
      }
      if (insertIndex > size) {
        insertIndex = size;
      }

      if (capacity < (size + 1U)) {
        std::size_t newCapacity = 0U;
        if (kTrailMaxCount - (capacity >> 1U) >= capacity) {
          newCapacity = capacity + (capacity >> 1U);
        }
        if (newCapacity < (size + 1U)) {
          newCapacity = size + 1U;
        }

        auto* const newStorage =
          static_cast<moho::TrailRuntimeView*>(AllocateTrailRuntimeArrayOrThrow(static_cast<std::uint32_t>(newCapacity)));
        std::size_t constructedCount = 0U;

        try {
          for (std::size_t index = 0U; index < insertIndex; ++index) {
            new (newStorage + index) moho::TrailRuntimeView{};
            ++constructedCount;
          }
          if (insertIndex != 0U && pendingTrails.begin != nullptr) {
            (void)CopyTrailRuntimeRangeAndReturnEnd(
              newStorage,
              pendingTrails.begin,
              pendingTrails.begin + insertIndex
            );
          }

          new (newStorage + insertIndex) moho::TrailRuntimeView{};
          CopyTrailRuntimeViewForVectorMove(*temporaryTrail, newStorage[insertIndex]);
          ++constructedCount;

          for (std::size_t index = insertIndex; index < size; ++index) {
            new (newStorage + index + 1U) moho::TrailRuntimeView{};
            ++constructedCount;
          }
          if ((size - insertIndex) != 0U && pendingTrails.begin != nullptr) {
            (void)CopyTrailRuntimeRangeAndReturnEnd(
              newStorage + insertIndex + 1U,
              pendingTrails.begin + insertIndex,
              pendingTrails.end
            );
          }
        } catch (...) {
          DestroyTrailRuntimeRange(newStorage, newStorage + constructedCount);
          ::operator delete(newStorage);
          throw;
        }

        if (pendingTrails.begin != nullptr) {
          DestroyTrailRuntimeRange(pendingTrails.begin, pendingTrails.end);
          ::operator delete(pendingTrails.begin);
        }

        pendingTrails.begin = newStorage;
        pendingTrails.end = newStorage + size + 1U;
        pendingTrails.capacityEnd = newStorage + newCapacity;
      } else {
        moho::TrailRuntimeView* const oldEnd = pendingTrails.end;
        new (oldEnd) moho::TrailRuntimeView{};

        if (insertPosition == oldEnd) {
          CopyTrailRuntimeViewForVectorMove(*temporaryTrail, oldEnd[0]);
        } else {
          CopyTrailRuntimeViewForVectorMove(oldEnd[-1], oldEnd[0]);
          moho::TrailRuntimeView* const shiftedWriteCursor =
            ShiftTrailRuntimeRangeRightByOneAndReturnWriteCursor(oldEnd - 1, oldEnd, insertPosition);
          (void)CopyTrailRuntimeValueAcrossRange(*temporaryTrail, insertPosition, shiftedWriteCursor);
        }

        pendingTrails.end = oldEnd + 1;
      }

      DestroyTrailRuntimeViewForVectorTail(*temporaryTrail);
    } catch (...) {
      DestroyTrailRuntimeViewForVectorTail(*temporaryTrail);
      throw;
    }
  }

  /**
   * Address: 0x004973A0 (FUN_004973A0, sub_4973A0)
   *
   * What it does:
   * Duplicate end-pointer accessor thunk for one trail debug-vector lane.
   */
  moho::TrailRuntimeView** GetTrailVectorEndPointerDuplicate(
    moho::TrailRuntimeView** const outEnd,
    const moho::RenderBucketVectorRuntime<moho::TrailRuntimeView>& pendingTrails
  ) noexcept
  {
    *outEnd = pendingTrails.end;
    return outEnd;
  }

  /**
   * Address: 0x004973B0 (FUN_004973B0, sub_4973B0)
   *
   * What it does:
   * Forwards one trail insert path and exports the iterator position that maps
   * to the original insertion index.
   */
  moho::TrailRuntimeView** InsertOneTrailAndExportIterator(
    moho::RenderBucketVectorRuntime<moho::TrailRuntimeView>& pendingTrails,
    moho::TrailRuntimeView** const outIterator,
    moho::TrailRuntimeView* const insertPosition,
    const moho::TrailRuntimeView* const sourceTrail
  )
  {
    std::size_t index = 0U;
    if (pendingTrails.begin != nullptr &&
        pendingTrails.end != nullptr &&
        insertPosition != nullptr &&
        insertPosition >= pendingTrails.begin &&
        insertPosition <= pendingTrails.end &&
        pendingTrails.begin != pendingTrails.end) {
      index = static_cast<std::size_t>(insertPosition - pendingTrails.begin);
    }

    if (sourceTrail != nullptr) {
      InsertTrailValueAtAndGrow(*sourceTrail, pendingTrails, insertPosition);
    }

    if (pendingTrails.begin == nullptr) {
      *outIterator = nullptr;
      return outIterator;
    }

    const std::size_t count = VectorCount(pendingTrails);
    if (index > count) {
      index = count;
    }
    *outIterator = pendingTrails.begin + index;
    return outIterator;
  }

  /**
   * Address: 0x00497470 (FUN_00497470, sub_497470)
   *
   * What it does:
   * Destroys one trail range used by vector erase/reallocation paths.
   */
  void DestroyTrailRuntimeRange(
    moho::TrailRuntimeView* const begin,
    moho::TrailRuntimeView* const end
  ) noexcept
  {
    for (moho::TrailRuntimeView* trail = begin; trail != end; ++trail) {
      DestroyTrailRuntimeViewForVectorTail(*trail);
    }
  }

  /**
   * Address: 0x00497490 (FUN_00497490, sub_497490)
   *
   * What it does:
   * Releases one trail debug-vector lane (destroy payload range + free storage)
   * and resets begin/end/capacity pointers.
   */
  void ResetTrailRuntimeVectorStorageDuplicate(
    moho::RenderBucketVectorRuntime<moho::TrailRuntimeView>& pendingTrails
  ) noexcept
  {
    if (pendingTrails.begin != nullptr) {
      DestroyTrailRuntimeRange(pendingTrails.begin, pendingTrails.end);
      ::operator delete(pendingTrails.begin);
    }
    pendingTrails.begin = nullptr;
    pendingTrails.end = nullptr;
    pendingTrails.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00495730 (FUN_00495730)
   *
   * What it does:
   * Thunk lane that forwards one trail-vector storage cleanup request into
   * `FUN_00497490`.
   */
  [[maybe_unused]] void ResetTrailRuntimeVectorStorageDuplicateThunk(
    moho::RenderBucketVectorRuntime<moho::TrailRuntimeView>& pendingTrails
  ) noexcept
  {
    ResetTrailRuntimeVectorStorageDuplicate(pendingTrails);
  }

  /**
   * Address: 0x004974E0 (FUN_004974E0, sub_4974E0)
   *
   * What it does:
   * Copy-constructs one repeated trail payload into `count` contiguous
   * destination slots and returns the resulting end pointer.
   */
  [[nodiscard]] moho::TrailRuntimeView* CopyConstructRepeatedTrailRuntimeAndReturnEnd(
    moho::TrailRuntimeView* const destination,
    const std::size_t count,
    const moho::TrailRuntimeView* const source
  )
  {
    if (destination == nullptr || source == nullptr || count == 0U) {
      return destination != nullptr ? destination + count : nullptr;
    }

    std::size_t constructedCount = 0U;
    try {
      for (; constructedCount < count; ++constructedCount) {
        new (destination + constructedCount) moho::TrailRuntimeView{};
        CopyTrailRuntimeViewForVectorMove(*source, destination[constructedCount]);
      }
    } catch (...) {
      DestroyTrailRuntimeRange(destination, destination + constructedCount);
      throw;
    }

    return destination + count;
  }

  /**
   * What it does:
   * One packed dword+byte lane used by legacy pointer/flag helper thunks.
   */
  struct DwordAndByteRuntime
  {
    std::uint32_t value = 0U;         // +0x00
    std::uint8_t flag = 0U;           // +0x04
    std::uint8_t padding05_07[0x03]{}; // +0x05
  };

  static_assert(
    offsetof(DwordAndByteRuntime, value) == 0x00,
    "DwordAndByteRuntime::value offset must be 0x00"
  );
  static_assert(
    offsetof(DwordAndByteRuntime, flag) == 0x04,
    "DwordAndByteRuntime::flag offset must be 0x04"
  );
  static_assert(sizeof(DwordAndByteRuntime) == 0x08, "DwordAndByteRuntime size must be 0x08");

  /**
   * Address: 0x004979F0 (FUN_004979F0, sub_4979F0)
   *
   * What it does:
   * Reads one 32-bit value from offset `+0x04` of caller storage.
   */
  [[nodiscard]] std::uint32_t ReadDwordAtOffset4(const std::uint32_t* const valueBase) noexcept
  {
    return valueBase[1];
  }

  /**
   * Address: 0x00497AA0 (FUN_00497AA0, sub_497AA0)
   *
   * What it does:
   * Writes one 32-bit scalar into caller output storage.
   */
  std::uint32_t* WriteDwordToOutputSlot(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x00497AE0 (FUN_00497AE0, sub_497AE0)
   *
   * What it does:
   * Reads one 32-bit scalar from caller storage.
   */
  [[nodiscard]] std::uint32_t ReadDwordFromSlot(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00497AF0 (FUN_00497AF0, sub_497AF0)
   *
   * What it does:
   * Packs one 32-bit scalar and one byte flag from caller slots into output
   * storage.
   */
  DwordAndByteRuntime* WriteDwordAndBytePair(
    DwordAndByteRuntime* const outPair,
    const std::uint32_t* const valueSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outPair->value = *valueSlot;
    outPair->flag = *flagSlot;
    return outPair;
  }

  /**
   * Address: 0x00497B30 (FUN_00497B30, sub_497B30)
   *
   * What it does:
   * Writes one 32-bit value from offset `+0x08` of caller storage into output
   * slot.
   */
  std::uint32_t* WriteDwordAtOffset8ToOutputSlot(
    std::uint32_t* const outValue,
    const std::uint32_t* const valueBase
  ) noexcept
  {
    *outValue = valueBase[2];
    return outValue;
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

  /**
   * Address: 0x00497C80 (FUN_00497C80, sub_497C80)
   *
   * What it does:
   * Reads one pointer-sized value from caller storage.
   */
  [[nodiscard]] const void* ReadPointerFromSlot(const void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00497CB0 (FUN_00497CB0, nullsub_556)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkA() noexcept {}

  /**
   * Address: 0x00497D40 (FUN_00497D40, nullsub_557)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkB(const std::uint32_t /*unused*/) noexcept {}

  /**
    * Alias of FUN_00498AA0 (non-canonical helper lane).
   *
   * What it does:
   * Shifts one `uint32_t` vector tail left from `source` into `destination`,
   * updates the vector end lane, and writes destination iterator to caller
   * storage.
   */
  std::uint32_t** ShiftUInt32VectorTailLeftAndStoreDestination(
    moho::RenderBucketVectorRuntime<std::uint32_t>& values,
    std::uint32_t** const outIterator,
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != source && values.end != nullptr && source != nullptr) {
      const auto remainingCount = values.end - source;
      std::uint32_t* const newEnd = destination + remainingCount;
      if (remainingCount > 0) {
        std::memmove(destination, source, static_cast<std::size_t>(remainingCount) * sizeof(std::uint32_t));
      }
      values.end = newEnd;
    }

    *outIterator = destination;
    return outIterator;
  }

  /**
   * Address: 0x0049B760 (FUN_0049B760, sub_49B760)
   *
   * What it does:
   * Duplicate tail-shift helper for one `uint32_t` vector erase lane,
   * exporting the post-shift iterator.
   */
  std::uint32_t** ShiftUInt32VectorTailLeftAndStoreDestinationDuplicate(
    moho::RenderBucketVectorRuntime<std::uint32_t>& values,
    std::uint32_t** const outIterator,
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != source && values.end != nullptr && source != nullptr) {
      const auto remainingCount = values.end - source;
      std::uint32_t* const newEnd = destination + remainingCount;
      if (remainingCount > 0) {
        std::memmove(destination, source, static_cast<std::size_t>(remainingCount) * sizeof(std::uint32_t));
      }
      values.end = newEnd;
    }

    *outIterator = destination;
    return outIterator;
  }

  /**
    * Alias of FUN_00498AF0 (non-canonical helper lane).
   *
   * What it does:
   * Initializes one `uint32_t` debug-vector storage lane with requested
   * capacity, keeping begin/end/capacity equal when requested capacity is
   * zero.
   */
  [[nodiscard]] bool InitializeUInt32VectorStorage(
    moho::RenderBucketVectorRuntime<std::uint32_t>& values,
    const std::uint32_t count
  )
  {
    if (count > kLegacyListMaxSize) {
      ThrowLegacyVectorTooLongDuplicateE();
    }

    if (count != 0U) {
      auto* const storage = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * count));
      values.begin = storage;
      values.end = storage;
      values.capacityEnd = storage + count;
    } else {
      auto* const emptyStorage = static_cast<std::uint32_t*>(::operator new(0));
      values.begin = emptyStorage;
      values.end = emptyStorage;
      values.capacityEnd = emptyStorage;
    }

    return true;
  }

  /**
    * Alias of FUN_00498B80 (non-canonical helper lane).
   *
   * What it does:
   * Fills one `uint32_t` range with scalar value from caller slot and returns
   * one-past-end destination pointer.
   */
  std::uint32_t* FillUInt32RangeFromValueSlot(
    const std::uint32_t* const valueSlot,
    std::uint32_t* const destination,
    const std::int32_t count
  ) noexcept
  {
    for (std::int32_t index = 0; index < count; ++index) {
      destination[index] = *valueSlot;
    }
    return destination + count;
  }

  /**
    * Alias of FUN_00498BE0 (non-canonical helper lane).
   *
   * What it does:
   * Writes one `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotA(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
    * Alias of FUN_00498BF0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `uint32_t` scalar from caller-provided storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotA(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
    * Alias of FUN_00498C30 (non-canonical helper lane).
   *
   * What it does:
   * Writes one `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotB(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
    * Alias of FUN_00498C40 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `uint32_t` scalar from caller-provided storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotB(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
    * Alias of FUN_00498C80 (non-canonical helper lane).
   *
   * What it does:
   * Writes one `uint32_t` scalar into caller-provided output storage.
   */
  std::uint32_t* WriteUInt32ToOutputSlotC(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
    * Alias of FUN_00498CA0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `uint32_t` scalar from caller-provided storage.
   */
  [[nodiscard]] std::uint32_t ReadUInt32FromSlotC(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  [[nodiscard]] bool AppendWorkItemPointer(
    moho::RenderBucketVectorRuntime<moho::ParticleRenderWorkItemRuntime*>& vector,
    moho::ParticleRenderWorkItemRuntime* const workItem
  )
  {
    const std::size_t count = VectorCount(vector);
    const std::size_t capacity = VectorCapacity(vector);

    if (count >= capacity) {
      std::size_t newCapacity = capacity != 0U ? capacity + (capacity / 2U) : 4U;
      if (newCapacity < count + 1U) {
        newCapacity = count + 1U;
      }
      if (newCapacity > (std::numeric_limits<std::size_t>::max() / sizeof(moho::ParticleRenderWorkItemRuntime*))) {
        return false;
      }

      auto* const newStorage = static_cast<moho::ParticleRenderWorkItemRuntime**>(
        ::operator new(newCapacity * sizeof(moho::ParticleRenderWorkItemRuntime*))
      );
      if (count != 0U && vector.begin != nullptr) {
        std::memcpy(newStorage, vector.begin, count * sizeof(moho::ParticleRenderWorkItemRuntime*));
      }
      if (vector.begin != nullptr) {
        ::operator delete(vector.begin);
      }

      vector.begin = newStorage;
      vector.end = newStorage + count;
      vector.capacityEnd = newStorage + newCapacity;
    }

    vector.end[count] = workItem;
    vector.end = vector.begin + count + 1U;
    return true;
  }

  void ReleaseBeamTextureHandlesInRange(
    moho::SWorldBeam* const begin,
    moho::SWorldBeam* const end
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return;
    }

    for (moho::SWorldBeam* beam = begin; beam != end; ++beam) {
      moho::ResetCountedParticleTexturePtr(beam->mTexture1);
      moho::ResetCountedParticleTexturePtr(beam->mTexture2);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00495590 (FUN_00495590, sub_495590)
   *
   * What it does:
   * Writes the begin-pointer lane of one world-particle render vector into
   * caller-provided iterator storage.
   */
  SWorldParticle** GetWorldParticleVectorBeginPointer(
    SWorldParticle** const outBeginPointer,
    const RenderBucketVectorRuntime<SWorldParticle>& pendingParticles
  ) noexcept
  {
    if (outBeginPointer != nullptr) {
      *outBeginPointer = pendingParticles.begin;
    }
    return outBeginPointer;
  }

  /**
   * Address: 0x004955A0 (FUN_004955A0, sub_4955A0)
   *
   * What it does:
   * Returns the active world-particle element count from one render vector
   * lane.
   */
  std::int32_t GetWorldParticleVectorCount(const RenderBucketVectorRuntime<SWorldParticle>& pendingParticles) noexcept
  {
    if (pendingParticles.begin == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(pendingParticles.end - pendingParticles.begin);
  }

  /**
   * Address: 0x00495740 (FUN_00495740, sub_495740)
   *
   * What it does:
   * Writes the begin-pointer lane of one trail render vector into
   * caller-provided iterator storage.
   */
  TrailRuntimeView** GetTrailVectorBeginPointer(
    TrailRuntimeView** const outBeginPointer,
    const RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails
  ) noexcept
  {
    if (outBeginPointer != nullptr) {
      *outBeginPointer = pendingTrails.begin;
    }
    return outBeginPointer;
  }

  /**
   * Address: 0x00495750 (FUN_00495750, sub_495750)
   *
   * What it does:
   * Returns the active trail element count from one render vector lane.
   */
  std::int32_t GetTrailVectorCount(const RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails) noexcept
  {
    if (pendingTrails.begin == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(pendingTrails.end - pendingTrails.begin);
  }

  /**
   * Address: 0x0049DE20 (FUN_0049DE20, sub_49DE20)
   *
   * What it does:
   * Copies one contiguous world-particle range into destination storage and
   * returns the destination end pointer.
   */
  [[nodiscard]] SWorldParticle* CopyWorldParticleRangeForErase(
    const SWorldParticle* readBegin,
    const SWorldParticle* const readEnd,
    SWorldParticle* writeBegin
  ) noexcept
  {
    for (const SWorldParticle* read = readBegin; read != readEnd; ++read, ++writeBegin) {
      CopyWorldParticleForVectorMove(*read, *writeBegin);
    }
    return writeBegin;
  }

  /**
   * Address: 0x004956B0 (FUN_004956B0, sub_4956B0)
   *
   * What it does:
   * Erases one world-particle range from a pending vector lane by shifting the
   * tail left with typed copy semantics and destroying trailing entries.
   */
  SWorldParticle** EraseWorldParticleVectorRange(
    RenderBucketVectorRuntime<SWorldParticle>& pendingParticles,
    SWorldParticle** const outBeginPointer,
    SWorldParticle* const eraseBegin,
    SWorldParticle* const eraseEnd
  ) noexcept
  {
    SWorldParticle* begin = eraseBegin;
    if (eraseBegin != eraseEnd) {
      SWorldParticle* const oldEnd = pendingParticles.end;
      SWorldParticle* const write = CopyWorldParticleRangeForErase(eraseEnd, oldEnd, eraseBegin);

      for (SWorldParticle* tail = write; tail != oldEnd; ++tail) {
        DestroyWorldParticleForVectorTail(*tail);
      }

      pendingParticles.end = write;
      begin = eraseBegin;
    }

    if (outBeginPointer != nullptr) {
      *outBeginPointer = begin;
    }
    return outBeginPointer;
  }

  /**
   * Address: 0x00495850 (FUN_00495850, sub_495850)
   *
   * What it does:
   * Erases one trail range from a pending vector lane by shifting the tail left
   * with typed copy semantics and destroying trailing entries.
   */
  TrailRuntimeView** EraseTrailVectorRange(
    RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails,
    TrailRuntimeView** const outBeginPointer,
    TrailRuntimeView* const eraseBegin,
    TrailRuntimeView* const eraseEnd
  ) noexcept
  {
    TrailRuntimeView* begin = eraseBegin;
    if (eraseBegin != eraseEnd) {
      TrailRuntimeView* const oldEnd = pendingTrails.end;
      TrailRuntimeView* write = eraseBegin;

      for (TrailRuntimeView* read = eraseEnd; read != oldEnd; ++read, ++write) {
        CopyTrailRuntimeViewForVectorMove(*read, *write);
      }

      for (TrailRuntimeView* tail = write; tail != oldEnd; ++tail) {
        DestroyTrailRuntimeViewForVectorTail(*tail);
      }

      pendingTrails.end = write;
      begin = eraseBegin;
    }

    if (outBeginPointer != nullptr) {
      *outBeginPointer = begin;
    }
    return outBeginPointer;
  }

  /**
   * Address: 0x00495930 (FUN_00495930, sub_495930)
   *
   * What it does:
   * Writes the begin-pointer lane of one beam vector into caller-provided
   * iterator storage.
   */
  SWorldBeam** GetBeamVectorBeginPointer(
    SWorldBeam** const outBeginPointer,
    const RenderBucketVectorRuntime<SWorldBeam>& beams
  ) noexcept
  {
    if (outBeginPointer != nullptr) {
      *outBeginPointer = beams.begin;
    }
    return outBeginPointer;
  }

  /**
   * Address: 0x00495940 (FUN_00495940, sub_495940)
   *
   * What it does:
   * Writes the end-pointer lane of one beam vector into caller-provided
   * iterator storage.
   */
  SWorldBeam** GetBeamVectorEndPointer(
    SWorldBeam** const outEndPointer,
    const RenderBucketVectorRuntime<SWorldBeam>& beams
  ) noexcept
  {
    if (outEndPointer != nullptr) {
      *outEndPointer = beams.end;
    }
    return outEndPointer;
  }

  /**
   * Address: 0x00495950 (FUN_00495950, sub_495950)
   *
   * What it does:
   * Returns the active beam element count from one beam vector lane.
   */
  std::int32_t GetBeamVectorCount(const RenderBucketVectorRuntime<SWorldBeam>& beams) noexcept
  {
    if (beams.begin == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(beams.end - beams.begin);
  }

  /**
   * Address: 0x004958F0 (FUN_004958F0, sub_4958F0)
   *
   * What it does:
   * Releases one beam-vector storage lane (including intrusive texture refs on
   * each beam payload) and clears begin/end/capacity pointers.
   */
  void ResetBeamVectorStorage(RenderBucketVectorRuntime<SWorldBeam>& beams) noexcept
  {
    if (beams.begin != nullptr) {
      ReleaseBeamTextureHandlesInRange(beams.begin, beams.end);
      ::operator delete(beams.begin);
    }

    beams.begin = nullptr;
    beams.end = nullptr;
    beams.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00492CA0 (FUN_00492CA0, sub_492CA0)
   *
   * What it does:
   * Appends one particle-buffer pointer into the owner available-buffer pool
   * list.
   */
  std::uint32_t AppendParticleBufferToOwnerAvailablePool(
    CWorldParticles* const owner,
    ParticleBuffer* const particleBuffer
  )
  {
    auto* const ownerView = reinterpret_cast<CWorldParticlesParticlePoolRuntimeView*>(owner);
    ParticleBufferPoolListRuntime* const pool = &ownerView->availableBuffers;
    ParticleBufferPoolNodeRuntime* const head = pool->head;

    auto* const node = static_cast<ParticleBufferPoolNodeRuntime*>(::operator new(sizeof(ParticleBufferPoolNodeRuntime)));
    node->next = head;
    node->prev = head->prev;
    node->value = particleBuffer;

    const std::uint32_t updatedSize = IncrementLegacyListSizeChecked(*pool);
    head->prev = node;
    node->prev->next = node;
    return updatedSize;
  }

  /**
   * Address: 0x00492CE0 (FUN_00492CE0, sub_492CE0)
   *
   * What it does:
   * Pops and returns one trail-segment buffer pointer from the owner pool.
   * Returns `nullptr` when the pool is empty.
   */
  TrailSegmentBufferRuntime* AcquireTrailSegmentBufferFromOwnerPool(CWorldParticles* const owner)
  {
    auto* const ownerView = reinterpret_cast<CWorldParticlesTrailSegmentPoolRuntimeView*>(owner);
    TrailSegmentPoolRuntime* const pool = &ownerView->trailSegmentPool;
    if (pool->size == 0U) {
      return nullptr;
    }

    TrailSegmentPoolNodeRuntime* const first = pool->head->left;
    TrailSegmentBufferRuntime* const segmentBuffer = first->segmentBuffer;
    TrailSegmentPoolNodeRuntime* successor = nullptr;
    (void)EraseTrailSegmentPoolNodeAndStoreSuccessor(*pool, &successor, first);
    (void)successor;
    return segmentBuffer;
  }

  /**
   * Address: 0x00492D10 (FUN_00492D10, sub_492D10)
   *
   * What it does:
   * Returns one trail-segment buffer pointer back into the owner pool.
   */
  void ReturnTrailSegmentBufferToOwnerPool(
    CWorldParticles* const owner,
    TrailSegmentBufferRuntime* const segmentBuffer
  )
  {
    auto* const ownerView = reinterpret_cast<CWorldParticlesTrailSegmentPoolRuntimeView*>(owner);
    TrailSegmentPoolRuntime* const pool = &ownerView->trailSegmentPool;
    const TrailSegmentBufferRuntime* key = segmentBuffer;
    TrailSegmentPoolInsertResultRuntime insertResult{};
    (void)FindOrInsertTrailSegmentPoolNodeByKey(*pool, &key, &insertResult);
  }

  /**
   * Address: 0x00493480 (FUN_00493480, sub_493480)
   *
   * What it does:
   * Initializes one particle render bucket key/runtime lane from one world
   * particle payload and stores owner context.
   */
  ParticleRenderBucketRuntime* InitializeParticleRenderBucketFromWorldParticle(
    ParticleRenderBucketRuntime& bucket,
    const SWorldParticle& particle,
    CWorldParticles* const owner
  )
  {
    bucket.texture0.reset();
    bucket.texture1.reset();
    bucket.tag = msvc8::string{};
    bucket.blendMode = 0;
    bucket.zMode = 0;
    bucket.pendingParticles = RenderBucketVectorRuntime<SWorldParticle>{};
    bucket.activeWorkItems = RenderBucketVectorRuntime<ParticleRenderWorkItemRuntime*>{};
    bucket.owner = owner;

    bucket.stateByte = particle.mEnabled;

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
  TrailRenderBucketRuntime* InitializeTrailRenderBucketFromTrail(
    TrailRenderBucketRuntime& bucket,
    const TrailRuntimeView& trail,
    CWorldParticles* const owner
  )
  {
    bucket.texture0.reset();
    bucket.texture1.reset();
    bucket.tag = msvc8::string{};
    bucket.uvScalar = 0.0f;
    bucket.renderStartIndex = 0U;
    bucket.pendingTrails = RenderBucketVectorRuntime<TrailRuntimeView>{};
    bucket.activeWorkItems = RenderBucketVectorRuntime<ParticleRenderWorkItemRuntime*>{};
    bucket.owner = owner;

    CParticleTexture::TextureResourceHandle texture0{};
    if (trail.texture0 != nullptr) {
      trail.texture0->GetTexture(texture0);
    }
    bucket.texture0 = texture0;

    CParticleTexture::TextureResourceHandle texture1{};
    if (trail.texture1 != nullptr) {
      trail.texture1->GetTexture(texture1);
    }
    bucket.texture1 = texture1;

    bucket.tag.assign_owned(trail.tag != nullptr ? trail.tag : "");
    bucket.uvScalar = trail.uvScalar;
    return &bucket;
  }

  /**
   * Address: 0x00493210 (FUN_00493210, sub_493210)
   *
   * What it does:
   * Uploads a bounded batch of pending world particles into one particle
   * work-item instance stream for the current frame.
   */
  bool UploadPendingParticlesIntoWorkItem(
    ParticleRenderWorkItemRuntime& workItem,
    const float frameDelta,
    RenderBucketVectorRuntime<SWorldParticle>& pendingParticles
  )
  {
    const std::size_t pendingCount = VectorCount(pendingParticles);
    if (pendingCount == 0U) {
      return false;
    }

    const std::size_t intervalCount =
      (workItem.mIntervalsBegin != nullptr && workItem.mIntervalsEnd != nullptr && workItem.mIntervalsEnd >= workItem.mIntervalsBegin)
      ? static_cast<std::size_t>(workItem.mIntervalsEnd - workItem.mIntervalsBegin)
      : 0U;

    std::size_t maxUploadCount = pendingCount;
    if (workItem.mIntervalCapacityHint > intervalCount) {
      maxUploadCount = std::min(maxUploadCount, static_cast<std::size_t>(workItem.mIntervalCapacityHint) - intervalCount);
    } else {
      maxUploadCount = 0U;
    }

    if (maxUploadCount == 0U) {
      return pendingCount != 0U;
    }

    auto* const particleBuffer = static_cast<ParticleBuffer*>(workItem.mParticleBuffer);
    if (particleBuffer == nullptr) {
      SWorldParticle* clearBegin = pendingParticles.begin;
      (void)EraseWorldParticleVectorRange(
        pendingParticles,
        &clearBegin,
        pendingParticles.begin,
        pendingParticles.end
      );
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervalsEnd = workItem.mIntervalsBegin;
      return false;
    }

    ParticleBuffer::Instanced* lockedInstances = nullptr;
    if (workItem.mRenderStartIndex != 0U) {
      lockedInstances = particleBuffer->Lock(static_cast<int>(workItem.mRenderStartIndex), static_cast<int>(maxUploadCount));
    } else {
      lockedInstances = particleBuffer->Lock(static_cast<int>(maxUploadCount));
    }

    if (lockedInstances == nullptr) {
      SWorldParticle* clearBegin = pendingParticles.begin;
      (void)EraseWorldParticleVectorRange(
        pendingParticles,
        &clearBegin,
        pendingParticles.begin,
        pendingParticles.end
      );
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervalsEnd = workItem.mIntervalsBegin;
      return false;
    }

    for (std::size_t index = 0U; index < maxUploadCount; ++index) {
      SWorldParticle& particle = pendingParticles.begin[index];
      particle.mInterop += frameDelta;
      (void)AppendInterval(workItem, particle.mInterop, particle.mLifetime);

      auto* const instance = reinterpret_cast<ParticleInstanceRuntime*>(
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
    SWorldParticle* eraseBegin = pendingParticles.begin;
    SWorldParticle* const eraseEnd = pendingParticles.begin + maxUploadCount;
    (void)EraseWorldParticleVectorRange(pendingParticles, &eraseBegin, eraseBegin, eraseEnd);
    return particleBuffer->UnlockInstanceBuffer() != 0;
  }

  /**
   * Address: 0x00493720 (FUN_00493720, sub_493720)
   *
   * What it does:
   * Returns active particle work-item buffers to the owner pool and destroys
   * the work-item objects.
   */
  void RecycleAndDestroyParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket)
  {
    if (bucket.activeWorkItems.begin != nullptr && bucket.activeWorkItems.end != nullptr) {
      for (ParticleRenderWorkItemRuntime** itemPtr = bucket.activeWorkItems.begin; itemPtr != bucket.activeWorkItems.end; ++itemPtr) {
        ParticleRenderWorkItemRuntime* const workItem = *itemPtr;
        if (workItem == nullptr) {
          continue;
        }

        PushBackBufferToOwnerPool(bucket.owner, static_cast<ParticleBuffer*>(workItem->mParticleBuffer));
        (void)DestroyParticleRenderWorkItem(workItem);
      }
    }

    bucket.activeWorkItems.end = bucket.activeWorkItems.begin;
  }

  /**
   * Address: 0x00493620 (FUN_00493620, sub_493620)
   *
   * What it does:
   * Releases one particle render bucket runtime lane including key state,
   * pending payload lanes, and active work-item lanes.
   */
  void DestroyParticleRenderBucket(ParticleRenderBucketRuntime& bucket)
  {
    RecycleAndDestroyParticleBucketWorkItems(bucket);

    if (bucket.activeWorkItems.begin != nullptr) {
      ::operator delete(bucket.activeWorkItems.begin);
    }
    bucket.activeWorkItems.begin = nullptr;
    bucket.activeWorkItems.end = nullptr;
    bucket.activeWorkItems.capacityEnd = nullptr;

    if (bucket.pendingParticles.begin != nullptr) {
      ::operator delete(bucket.pendingParticles.begin);
    }
    bucket.pendingParticles.begin = nullptr;
    bucket.pendingParticles.end = nullptr;
    bucket.pendingParticles.capacityEnd = nullptr;

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
  void RecycleAndDestroyTrailBucketWorkItems(TrailRenderBucketRuntime& bucket)
  {
    if (bucket.activeWorkItems.begin == nullptr || bucket.activeWorkItems.end == nullptr) {
      return;
    }

    for (ParticleRenderWorkItemRuntime** itemPtr = bucket.activeWorkItems.begin; itemPtr != bucket.activeWorkItems.end; ++itemPtr) {
      ParticleRenderWorkItemRuntime* const workItem = *itemPtr;
      if (workItem == nullptr) {
        continue;
      }

      if (bucket.owner != nullptr && workItem->mParticleBuffer != nullptr) {
        auto* const segmentBuffer = static_cast<TrailSegmentBufferRuntime*>(workItem->mParticleBuffer);
        ReturnTrailSegmentBufferToOwnerPool(bucket.owner, segmentBuffer);
      }

      ResetParticleRenderWorkItemIntervals(*workItem);
      ::operator delete(workItem);
    }

    bucket.activeWorkItems.end = bucket.activeWorkItems.begin;
  }

  /**
   * Address: 0x004942E0 (FUN_004942E0, sub_4942E0)
   *
   * What it does:
   * Releases one trail render bucket runtime lane including key state,
   * pending trail payload lanes, and active work-item lanes.
   */
  void DestroyTrailRenderBucket(TrailRenderBucketRuntime& bucket)
  {
    RecycleAndDestroyTrailBucketWorkItems(bucket);

    if (bucket.activeWorkItems.begin != nullptr) {
      ::operator delete(bucket.activeWorkItems.begin);
    }
    bucket.activeWorkItems.begin = nullptr;
    bucket.activeWorkItems.end = nullptr;
    bucket.activeWorkItems.capacityEnd = nullptr;

    if (bucket.pendingTrails.begin != nullptr) {
      for (TrailRuntimeView* trail = bucket.pendingTrails.begin; trail != bucket.pendingTrails.end; ++trail) {
        DestroyTrailRuntimeViewForVectorTail(*trail);
      }
      ::operator delete(bucket.pendingTrails.begin);
    }
    bucket.pendingTrails.begin = nullptr;
    bucket.pendingTrails.end = nullptr;
    bucket.pendingTrails.capacityEnd = nullptr;

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
  void PruneExpiredParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.begin == nullptr || bucket.activeWorkItems.end == nullptr) {
      return;
    }

    ParticleRenderWorkItemRuntime** writeIt = bucket.activeWorkItems.begin;
    for (ParticleRenderWorkItemRuntime** readIt = bucket.activeWorkItems.begin; readIt != bucket.activeWorkItems.end; ++readIt) {
      ParticleRenderWorkItemRuntime* const workItem = *readIt;
      if (workItem == nullptr) {
        continue;
      }

      if (AdvanceParticleRenderWorkItemCursorToFrame(*workItem, frameValue)) {
        PushBackBufferToOwnerPool(bucket.owner, static_cast<ParticleBuffer*>(workItem->mParticleBuffer));
        (void)DestroyParticleRenderWorkItem(workItem);
        continue;
      }

      *writeIt = workItem;
      ++writeIt;
    }

    bucket.activeWorkItems.end = writeIt;
  }

  /**
   * Address: 0x00493940 (FUN_00493940, sub_493940)
   *
   * What it does:
   * Ensures active work items exist for pending particle payload and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = VectorCount(bucket.activeWorkItems);
    if (workItemCount != 0U) {
      ParticleRenderWorkItemRuntime* const tailWorkItem = bucket.activeWorkItems.end[-1];
      if (tailWorkItem != nullptr) {
        (void)UploadPendingParticlesIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingParticles);
      }
    }

    while (VectorCount(bucket.pendingParticles) != 0U) {
      ParticleBuffer* const pooledBuffer = PopFrontBufferFromOwnerPool(bucket.owner);
      if (pooledBuffer == nullptr) {
        gpg::Logf(kParticleCapExceededLog);
        bucket.pendingParticles.end = bucket.pendingParticles.begin;
        return false;
      }

      auto* const newWorkItem = static_cast<ParticleRenderWorkItemRuntime*>(::operator new(sizeof(ParticleRenderWorkItemRuntime)));
      (void)InitializeParticleRenderWorkItem(
        *newWorkItem,
        static_cast<std::uint32_t>(pooledBuffer->mMaxParticles),
        pooledBuffer
      );

      if (!AppendWorkItemPointer(bucket.activeWorkItems, newWorkItem)) {
        PushBackBufferToOwnerPool(bucket.owner, pooledBuffer);
        (void)DestroyParticleRenderWorkItem(newWorkItem);
        bucket.pendingParticles.end = bucket.pendingParticles.begin;
        return false;
      }

      (void)UploadPendingParticlesIntoWorkItem(*newWorkItem, frameDelta, bucket.pendingParticles);
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
  bool RenderParticleBucket(ParticleRenderBucketRuntime& bucket, const float frameValue, const bool onlyTLight)
  {
    PruneExpiredParticleBucketWorkItems(bucket, frameValue);
    (void)EnsureAndFillParticleBucketWorkItems(bucket, frameValue);

    const std::size_t activeWorkItemCount = VectorCount(bucket.activeWorkItems);
    if (activeWorkItemCount == 0U) {
      return false;
    }

    if (onlyTLight && bucket.tag.compare(0U, bucket.tag.size(), "TLight", 6U) != 0) {
      return false;
    }

    ParticleTechniqueSelectionWithDragRuntime selection{};
    selection.dragEnabled = bucket.stateByte;
    selection.texture0 = bucket.texture0;
    selection.texture1 = bucket.texture1;
    selection.techniqueBaseName.assign(bucket.tag, 0U, msvc8::string::npos);
    selection.blendMode = bucket.blendMode;
    SelectParticleTechniqueWithDrag(selection);

    for (std::size_t index = activeWorkItemCount; index > 0U; --index) {
      ParticleRenderWorkItemRuntime* const workItem = bucket.activeWorkItems.begin[index - 1U];
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
    ParticleRenderWorkItemRuntime& workItem,
    const float frameDelta,
    RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails
  )
  {
    const std::size_t pendingCount = VectorCount(pendingTrails);
    if (pendingCount == 0U) {
      return false;
    }

    const std::size_t intervalCount =
      (workItem.mIntervalsBegin != nullptr && workItem.mIntervalsEnd != nullptr && workItem.mIntervalsEnd >= workItem.mIntervalsBegin)
        ? static_cast<std::size_t>(workItem.mIntervalsEnd - workItem.mIntervalsBegin)
        : 0U;

    std::size_t maxUploadCount = pendingCount;
    if (workItem.mIntervalCapacityHint > intervalCount) {
      maxUploadCount = std::min(maxUploadCount, static_cast<std::size_t>(workItem.mIntervalCapacityHint) - intervalCount);
    } else {
      maxUploadCount = 0U;
    }

    if (maxUploadCount == 0U) {
      return pendingCount != 0U;
    }

    auto* const segmentBuffer = static_cast<TrailSegmentBufferRuntime*>(workItem.mParticleBuffer);
    if (segmentBuffer == nullptr) {
      TrailRuntimeView* clearBegin = pendingTrails.begin;
      (void)EraseTrailVectorRange(pendingTrails, &clearBegin, pendingTrails.begin, pendingTrails.end);
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervalsEnd = workItem.mIntervalsBegin;
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
      TrailRuntimeView* clearBegin = pendingTrails.begin;
      (void)EraseTrailVectorRange(pendingTrails, &clearBegin, pendingTrails.begin, pendingTrails.end);
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervalsEnd = workItem.mIntervalsBegin;
      return false;
    }

    auto* const outVertices = static_cast<float*>(lockedVertices);
    TrailRuntimeView* currentTrail = pendingTrails.begin;
    TrailRuntimeView* const trailEnd = pendingTrails.begin + maxUploadCount;
    float* out = outVertices;

    while (currentTrail != trailEnd) {
      float* const trailFloats = reinterpret_cast<float*>(currentTrail);
      float* const trailState = trailFloats + 5;

      const float beginFrame = std::max(trailState[7], trailState[8]) + frameDelta;
      const float lifeFrames = trailState[9] + 1.0f;
      (void)AppendInterval(workItem, beginFrame, lifeFrames);

      trailState[7] = trailState[7] + frameDelta + 1.0f;
      trailState[8] = trailState[8] + frameDelta + 1.0f;
      trailState[10] = trailState[10] + frameDelta + 1.0f;

      PackTrailSegmentQuadVertices(out, trailFloats);
      out += 4U * 13U;
      ++currentTrail;
    }

    workItem.mRenderStartIndex += static_cast<std::uint32_t>(maxUploadCount);
    TrailRuntimeView* eraseBegin = pendingTrails.begin;
    TrailRuntimeView* const eraseEnd = pendingTrails.begin + maxUploadCount;
    (void)EraseTrailVectorRange(pendingTrails, &eraseBegin, eraseBegin, eraseEnd);

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
  void PruneExpiredTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.begin == nullptr || bucket.activeWorkItems.end == nullptr) {
      return;
    }

    ParticleRenderWorkItemRuntime** writeIt = bucket.activeWorkItems.begin;
    for (ParticleRenderWorkItemRuntime** readIt = bucket.activeWorkItems.begin; readIt != bucket.activeWorkItems.end; ++readIt) {
      ParticleRenderWorkItemRuntime* const workItem = *readIt;
      if (workItem == nullptr) {
        continue;
      }

      if (AdvanceParticleRenderWorkItemCursorToFrame(*workItem, frameValue)) {
        if (bucket.owner != nullptr && workItem->mParticleBuffer != nullptr) {
          ReturnTrailSegmentBufferToOwnerPool(bucket.owner, static_cast<TrailSegmentBufferRuntime*>(workItem->mParticleBuffer));
        }

        (void)DestroyParticleRenderWorkItem(workItem);
        continue;
      }

      *writeIt = workItem;
      ++writeIt;
    }

    bucket.activeWorkItems.end = writeIt;
  }

  /**
   * Address: 0x004945C0 (FUN_004945C0, sub_4945C0)
   *
   * What it does:
   * Ensures active trail work items exist for pending trail payloads and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = VectorCount(bucket.activeWorkItems);
    if (workItemCount != 0U) {
      ParticleRenderWorkItemRuntime* const tailWorkItem = bucket.activeWorkItems.end[-1];
      if (tailWorkItem != nullptr) {
        (void)UploadPendingTrailsIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingTrails);
      }
    }

    while (VectorCount(bucket.pendingTrails) != 0U) {
      TrailSegmentBufferRuntime* const pooledBuffer = AcquireTrailSegmentBufferFromOwnerPool(bucket.owner);
      if (pooledBuffer == nullptr) {
        gpg::Logf("Wow!  Ran out of segment buffers from the pool, discarding segments!\n");
        TrailRuntimeView* clearBegin = bucket.pendingTrails.begin;
        (void)EraseTrailVectorRange(bucket.pendingTrails, &clearBegin, bucket.pendingTrails.begin, bucket.pendingTrails.end);
        return false;
      }

      auto* const newWorkItem = static_cast<ParticleRenderWorkItemRuntime*>(::operator new(sizeof(ParticleRenderWorkItemRuntime)));
      (void)InitializeParticleRenderWorkItem(
        *newWorkItem,
        GetTrailSegmentBufferMaxSegments(*pooledBuffer),
        pooledBuffer
      );

      if (!AppendWorkItemPointer(bucket.activeWorkItems, newWorkItem)) {
        ReturnTrailSegmentBufferToOwnerPool(bucket.owner, pooledBuffer);
        (void)DestroyParticleRenderWorkItem(newWorkItem);
        TrailRuntimeView* clearBegin = bucket.pendingTrails.begin;
        (void)EraseTrailVectorRange(bucket.pendingTrails, &clearBegin, bucket.pendingTrails.begin, bucket.pendingTrails.end);
        return false;
      }

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
  bool RenderTrailBucket(TrailRenderBucketRuntime& bucket, const float frameValue, const bool onlyTLight)
  {
    PruneExpiredTrailBucketWorkItems(bucket, frameValue);
    (void)EnsureAndFillTrailBucketWorkItems(bucket, frameValue);

    const std::size_t activeWorkItemCount = VectorCount(bucket.activeWorkItems);
    if (activeWorkItemCount == 0U || onlyTLight) {
      return false;
    }

    ParticleTechniqueSelectionRuntime selection{};
    selection.texture0 = bucket.texture0;
    selection.texture1 = bucket.texture1;
    selection.techniqueBaseName.assign(bucket.tag, 0U, msvc8::string::npos);
    std::memcpy(&selection.blendMode, &bucket.uvScalar, sizeof(selection.blendMode));
    SelectParticleTechnique(selection);

    for (ParticleRenderWorkItemRuntime** itemPtr = bucket.activeWorkItems.begin; itemPtr != bucket.activeWorkItems.end; ++itemPtr) {
      ParticleRenderWorkItemRuntime* const workItem = *itemPtr;
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
        *static_cast<TrailSegmentBufferRuntime*>(workItem->mParticleBuffer),
        static_cast<std::int32_t>(segmentCount),
        static_cast<std::int32_t>(startIndex)
      );
    }

    return true;
  }
} // namespace moho
