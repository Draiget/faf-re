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
    // Binary (0x004967E0): +0x04 (BaseVertexIndex) = 4 * startSegment, +0x08 (MinIndex) = 0.
    vertexSheetView.startVertex = 0;
    vertexSheetView.baseVertex = kTrailVerticesPerSegment * startSegmentIndex;
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
   * Address: 0x0049AD90 (FUN_0049AD90, nullsub_594)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAJ() noexcept {}

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
   * Address: 0x0049B060 (FUN_0049B060, nullsub_595)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAK() noexcept {}

  /**
   * Address: 0x0049B710 (FUN_0049B710, nullsub_598)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAN() noexcept {}

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
   * Address: 0x0049B440 (FUN_0049B440, nullsub_597)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAM() noexcept {}

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



  [[nodiscard]] bool AppendInterval(
    moho::ParticleRenderWorkItemRuntime& workItem, const float beginFrame, const float lifeFrames
  )
  {
    // `msvc8::vector<ParticleRenderIntervalRuntime>::push_back` (0x00496950, cited on Vector.h).
    const moho::ParticleRenderIntervalRuntime intervalValue{beginFrame, lifeFrames};
    workItem.mIntervals.push_back(intervalValue);
    return true;
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
    if (pool->empty()) {
      return nullptr;
    }

    // The binary takes the leftmost node, keeps its buffer and erases it,
    // discarding the successor the erase hands back.
    const auto first = pool->begin();
    TrailSegmentBufferRuntime* const segmentBuffer = *first;
    (void)pool->erase(first);
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
    (void)pool->insert(segmentBuffer);
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
    bucket.pendingParticles.clear();
    bucket.activeWorkItems.clear();
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
    bucket.pendingTrails.clear();
    bucket.activeWorkItems.clear();
    bucket.owner = owner;

    CParticleTexture::TextureResourceHandle texture0{};
    if (trail.texture0.tex != nullptr) {
      trail.texture0.tex->GetTexture(texture0);
    }
    bucket.texture0 = texture0;

    CParticleTexture::TextureResourceHandle texture1{};
    if (trail.texture1.tex != nullptr) {
      trail.texture1.tex->GetTexture(texture1);
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
    msvc8::vector<SWorldParticle>& pendingParticles
  )
  {
    const std::size_t pendingCount = pendingParticles.size();
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

    auto* const particleBuffer = static_cast<ParticleBuffer*>(workItem.mParticleBuffer);
    if (particleBuffer == nullptr) {
      pendingParticles.clear();
      workItem.mIntervalCursor = 0U;
      workItem.mRenderStartIndex = 0U;
      workItem.mIntervals.clear();
      return false;
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
      return false;
    }

    for (std::size_t index = 0U; index < maxUploadCount; ++index) {
      SWorldParticle& particle = pendingParticles[index];
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
    // `erase(first, last)` (0x004956B0, cited on Vector.h): the uploaded prefix goes.
    (void)pendingParticles.erase(pendingParticles.begin(), pendingParticles.begin() + maxUploadCount);
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
    for (ParticleRenderWorkItemRuntime* const workItem : bucket.activeWorkItems) {
      if (workItem == nullptr) {
        continue;
      }
      PushBackBufferToOwnerPool(bucket.owner, static_cast<ParticleBuffer*>(workItem->mParticleBuffer));
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
  void DestroyParticleRenderBucket(ParticleRenderBucketRuntime& bucket)
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
  void RecycleAndDestroyTrailBucketWorkItems(TrailRenderBucketRuntime& bucket)
  {
    for (ParticleRenderWorkItemRuntime* const workItem : bucket.activeWorkItems) {
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
    bucket.activeWorkItems.clear();
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
  void PruneExpiredParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.empty()) {
      return;
    }
    ParticleRenderWorkItemRuntime** writeIt = bucket.activeWorkItems.begin();
    for (ParticleRenderWorkItemRuntime** readIt = bucket.activeWorkItems.begin(); readIt != bucket.activeWorkItems.end(); ++readIt) {
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
  bool EnsureAndFillParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = bucket.activeWorkItems.size();
    if (workItemCount != 0U) {
      ParticleRenderWorkItemRuntime* const tailWorkItem = bucket.activeWorkItems.back();
      if (tailWorkItem != nullptr) {
        (void)UploadPendingParticlesIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingParticles);
      }
    }

    while (!bucket.pendingParticles.empty()) {
      ParticleBuffer* const pooledBuffer = PopFrontBufferFromOwnerPool(bucket.owner);
      if (pooledBuffer == nullptr) {
        gpg::Logf(kParticleCapExceededLog);
        bucket.pendingParticles.clear();
        return false;
      }

      auto* const newWorkItem = static_cast<ParticleRenderWorkItemRuntime*>(::operator new(sizeof(ParticleRenderWorkItemRuntime)));
      (void)InitializeParticleRenderWorkItem(
        *newWorkItem,
        static_cast<std::uint32_t>(pooledBuffer->mMaxParticles),
        pooledBuffer
      );

      bucket.activeWorkItems.push_back(newWorkItem);

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

    const std::size_t activeWorkItemCount = bucket.activeWorkItems.size();
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
      ParticleRenderWorkItemRuntime* const workItem = bucket.activeWorkItems[index - 1U];
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
    msvc8::vector<TrailRuntimeView>& pendingTrails
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

    auto* const segmentBuffer = static_cast<TrailSegmentBufferRuntime*>(workItem.mParticleBuffer);
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

    auto* const outVertices = static_cast<float*>(lockedVertices);
    TrailRuntimeView* currentTrail = pendingTrails.begin();
    TrailRuntimeView* const trailEnd = pendingTrails.begin() + maxUploadCount;
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
  void PruneExpiredTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, const float frameValue)
  {
    if (bucket.activeWorkItems.empty()) {
      return;
    }
    ParticleRenderWorkItemRuntime** writeIt = bucket.activeWorkItems.begin();
    for (ParticleRenderWorkItemRuntime** readIt = bucket.activeWorkItems.begin(); readIt != bucket.activeWorkItems.end(); ++readIt) {
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
  bool EnsureAndFillTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, const float frameDelta)
  {
    const std::size_t workItemCount = bucket.activeWorkItems.size();
    if (workItemCount != 0U) {
      ParticleRenderWorkItemRuntime* const tailWorkItem = bucket.activeWorkItems.back();
      if (tailWorkItem != nullptr) {
        (void)UploadPendingTrailsIntoWorkItem(*tailWorkItem, frameDelta, bucket.pendingTrails);
      }
    }

    while (!bucket.pendingTrails.empty()) {
      TrailSegmentBufferRuntime* const pooledBuffer = AcquireTrailSegmentBufferFromOwnerPool(bucket.owner);
      if (pooledBuffer == nullptr) {
        gpg::Logf("Wow!  Ran out of segment buffers from the pool, discarding segments!\n");
        bucket.pendingTrails.clear();
        return false;
      }
      auto* const newWorkItem = static_cast<ParticleRenderWorkItemRuntime*>(::operator new(sizeof(ParticleRenderWorkItemRuntime)));
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
  bool RenderTrailBucket(TrailRenderBucketRuntime& bucket, const float frameValue, const bool onlyTLight)
  {
    PruneExpiredTrailBucketWorkItems(bucket, frameValue);
    (void)EnsureAndFillTrailBucketWorkItems(bucket, frameValue);

    const std::size_t activeWorkItemCount = bucket.activeWorkItems.size();
    if (activeWorkItemCount == 0U || onlyTLight) {
      return false;
    }

    ParticleTechniqueSelectionRuntime selection{};
    selection.texture0 = bucket.texture0;
    selection.texture1 = bucket.texture1;
    selection.techniqueBaseName.assign(bucket.tag, 0U, msvc8::string::npos);
    std::memcpy(&selection.blendMode, &bucket.uvScalar, sizeof(selection.blendMode));
    SelectParticleTechnique(selection);

    for (ParticleRenderWorkItemRuntime* const workItem : bucket.activeWorkItems) {
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
