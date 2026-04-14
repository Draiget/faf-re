#include "moho/particles/BeamRenderHelpers.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/d3d/CD3DVertexFormat.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/D3DSingletonCleanup.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/resource/CParticleTexture.h"

namespace moho
{
  extern bool ren_Beams;
}

namespace
{
  moho::TConVar<bool> gTConVar_ren_Beams("ren_Beams", "", &moho::ren_Beams);

  constexpr const char* kParticleRendererSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\ParticleRenderer.cpp";
  constexpr const char* kUnreachableAssertText = "Reached the supposably unreachable.";
  constexpr int kParticleSelectTechniqueAssertLine = 1359;
  constexpr int kParticleSelectTechniqueWithDragAssertLine = 1026;

  void CleanupTConVar_ren_Beams() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_ren_Beams);
  }

  template <typename TType>
  [[nodiscard]] bool IsSharedHandleLessForBucket(
    const boost::shared_ptr<TType>& lhs, const boost::shared_ptr<TType>& rhs
  ) noexcept
  {
    using SharedHandleRaw = boost::SharedPtrLayoutView<TType>;
    const auto* const lhsRaw = reinterpret_cast<const SharedHandleRaw*>(&lhs);
    const auto* const rhsRaw = reinterpret_cast<const SharedHandleRaw*>(&rhs);
    if (lhsRaw->px == rhsRaw->px) {
      return false;
    }
    return lhsRaw->pi < rhsRaw->pi;
  }

  template <typename TType>
  [[nodiscard]] bool AreSharedHandlesEquivalentForBucket(
    const boost::shared_ptr<TType>& lhs, const boost::shared_ptr<TType>& rhs
  ) noexcept
  {
    return lhs.get() == rhs.get();
  }

  [[nodiscard]] bool IsMsvc8StringLess(const msvc8::string& lhs, const msvc8::string& rhs) noexcept
  {
    const char* const lhsData = lhs.data();
    const char* const rhsData = rhs.data();
    return std::lexicographical_compare(
      lhsData,
      lhsData + lhs.size(),
      rhsData,
      rhsData + rhs.size()
    );
  }

  [[nodiscard]] Wm3::Vector3<float> LerpVector3(
    const Wm3::Vector3<float>& from, const Wm3::Vector3<float>& to, const float alpha
  ) noexcept
  {
    return Wm3::Vector3<float>{
      from.x + ((to.x - from.x) * alpha),
      from.y + ((to.y - from.y) * alpha),
      from.z + ((to.z - from.z) * alpha),
    };
  }

  [[nodiscard]] Wm3::Vector3<float> RotateVectorByOrientation(
    const Wm3::Vector3<float>& vector, const Wm3::Quaternion<float>& orientation
  ) noexcept
  {
    Wm3::Vector3<float> out{};
    Wm3::MultiplyQuaternionVector(&out, vector, orientation);
    return out;
  }

  [[nodiscard]] moho::BeamRenderVertexRuntime BuildBeamRenderVertex(
    const Wm3::Vector3<float>& worldPosition,
    const Wm3::Vector3<float>& axis,
    const float width,
    const moho::Vector4f& color,
    const float sideSign,
    const float repeatCoord,
    const float uShift,
    const float vShift
  ) noexcept
  {
    moho::BeamRenderVertexRuntime vertex{};
    vertex.worldPosition = worldPosition;
    vertex.axis = axis;
    vertex.width = width;
    vertex.color = color;
    vertex.sideSign = sideSign;
    vertex.repeatCoord = repeatCoord;
    vertex.uShift = uShift;
    vertex.vShift = vShift;
    return vertex;
  }

  /**
   * Address: 0x00495A20 (FUN_00495A20, func_register_ShaderVar_3)
   *
   * What it does:
   * Registers one particle shader-var lane and returns the same shader-var
   * storage pointer.
   */
  [[nodiscard]] moho::ShaderVar* RegisterParticleShaderVarSlotA(
    const char* const effectFileName,
    const char* const variableName,
    moho::ShaderVar* const shaderVar
  )
  {
    moho::RegisterShaderVar(variableName, shaderVar, effectFileName);
    return shaderVar;
  }

  /**
   * Address: 0x00495A50 (FUN_00495A50, func_register_ShaderVar_4)
   *
   * What it does:
   * Registers one particle shader-var lane and returns the same shader-var
   * storage pointer.
   */
  [[nodiscard]] moho::ShaderVar* RegisterParticleShaderVarSlotB(
    const char* const effectFileName,
    const char* const variableName,
    moho::ShaderVar* const shaderVar
  )
  {
    moho::RegisterShaderVar(variableName, shaderVar, effectFileName);
    return shaderVar;
  }

  using BeamBucketIteratorRuntime = moho::BeamTextureBucketMapRuntime::iterator;

  struct BeamBucketInsertPositionRuntime
  {
    BeamBucketIteratorRuntime iterator;
    bool inserted = false;
  };

  /**
   * Address: 0x00495A30 (FUN_00495A30, sub_495A30)
   *
   * What it does:
   * Returns the pointer value stored in one opaque pointer slot.
   */
  [[nodiscard]] void* ReadOpaquePointerSlotValue(void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00495A40 (FUN_00495A40, sub_495A40)
   *
   * What it does:
   * Converts one opaque pointer-slot presence check into the legacy
   * `0`/`-1` integer mask shape used by VC8 helper paths.
   */
  [[nodiscard]] int ComputeOpaquePointerSlotNullMask(void* const* const pointerSlot) noexcept
  {
    return ReadOpaquePointerSlotValue(pointerSlot) != nullptr ? 0 : -1;
  }

  /**
   * Address: 0x00495AC0 (FUN_00495AC0, sub_495AC0)
   *
   * What it does:
   * Writes the begin-iterator lane of one beam bucket map into caller-provided
   * iterator storage.
   */
  BeamBucketIteratorRuntime* GetBeamBucketMapBeginIterator(
    BeamBucketIteratorRuntime* const outIterator,
    moho::BeamTextureBucketMapRuntime& buckets
  ) noexcept
  {
    *outIterator = buckets.begin();
    return outIterator;
  }

  /**
   * Address: 0x00495AD0 (FUN_00495AD0, sub_495AD0)
   *
   * What it does:
   * Writes the end-iterator lane of one beam bucket map into caller-provided
   * iterator storage.
   */
  BeamBucketIteratorRuntime* GetBeamBucketMapEndIterator(
    BeamBucketIteratorRuntime* const outIterator,
    moho::BeamTextureBucketMapRuntime& buckets
  ) noexcept
  {
    *outIterator = buckets.end();
    return outIterator;
  }

  /**
   * Address: 0x00495AE0 (FUN_00495AE0, sub_495AE0)
   *
   * What it does:
   * Finds one beam bucket by key or inserts a new entry at lower-bound
   * position, returning both iterator and insertion flag.
   */
  BeamBucketInsertPositionRuntime* FindOrInsertBeamBucketEntryByKey(
    moho::BeamTextureBucketMapRuntime& buckets,
    const moho::BeamTextureBucketKeyRuntime& key,
    BeamBucketInsertPositionRuntime* const outPosition
  )
  {
    BeamBucketIteratorRuntime mapEnd = buckets.end();
    (void)GetBeamBucketMapEndIterator(&mapEnd, buckets);

    BeamBucketIteratorRuntime candidate = buckets.lower_bound(key);
    const bool keyPrecedesCandidate =
      (candidate == mapEnd) || buckets.key_comp()(key, candidate->first);

    if (keyPrecedesCandidate) {
      candidate = buckets.emplace_hint(candidate, key, msvc8::vector<moho::SWorldBeam>{});
      outPosition->inserted = true;
    } else {
      outPosition->inserted = false;
    }

    outPosition->iterator = candidate;
    return outPosition;
  }

  /**
   * Address: 0x00495C10 (FUN_00495C10)
   *
   * IDA signature:
   * _DWORD *__usercall sub_495C10@<eax>(_DWORD *a1@<eax>, int a2@<ecx>, _DWORD *a3@<ebx>)
   *
   * What it does:
   * Resolves the current beam-bucket lower-bound candidate and returns end when
   * the probe key still belongs before that candidate.
   */
  [[nodiscard]] BeamBucketIteratorRuntime FindBeamBucketEquivalentOrEnd(
    const moho::BeamTextureBucketKeyRuntime& key,
    moho::BeamTextureBucketMapRuntime& buckets
  ) noexcept
  {
    const BeamBucketIteratorRuntime candidate = buckets.lower_bound(key);
    if (candidate == buckets.end() || buckets.key_comp()(key, candidate->first)) {
      return buckets.end();
    }

    return candidate;
  }

  /**
   * Address: 0x00495CC0 (FUN_00495CC0)
   *
   * IDA signature:
   * char *__userpurge sub_495CC0@<eax>(char *a1@<edi>, char *a2, int a3)
   *
   * What it does:
   * Initializes one beam-texture bucket entry from a recovered key lane and
   * resets the entry's beam payload vector.
   */
  moho::BeamTextureBucketEntryRuntime* InitializeBeamTextureBucketEntry(
    moho::BeamTextureBucketEntryRuntime& entry,
    const moho::BeamTextureBucketKeyRuntime& key
  ) noexcept
  {
    entry.key = key;
    entry.allocatorProxy = 0U;
    entry.beams.clear();
    return &entry;
  }

  /**
   * Address: 0x00495D60 (FUN_00495D60)
   *
   * IDA signature:
   * int __thiscall sub_495D60(int *this)
   *
   * What it does:
   * Returns the active beam-render-vertex count from one packed 0x3C-stride
   * vector lane.
   */
  [[nodiscard]] std::int32_t GetBeamRenderVertexCount(
    const moho::BeamRenderVertexArrayRuntime& vertices
  ) noexcept
  {
    return static_cast<std::int32_t>(vertices.size());
  }

  /**
   * Address: 0x00495DA0 (FUN_00495DA0)
   *
   * IDA signature:
   * int __usercall sub_495DA0@<eax>(_DWORD *a1@<eax>, int a2@<ecx>)
   *
   * What it does:
   * Appends one packed beam-render vertex into the vertex lane, growing the
   * underlying storage when needed.
   */
  moho::BeamRenderVertexRuntime* AppendBeamRenderVertex(
    moho::BeamRenderVertexArrayRuntime& vertices,
    const moho::BeamRenderVertexRuntime& vertex
  )
  {
    vertices.push_back(vertex);
    return &vertices.back();
  }

  /**
   * What it does:
   * Legacy VC8 debug-vector lane (`proxy + begin/end/capacity`) used by
   * low-level helper thunks around beam/trail/particle vector operations.
   */
  template <typename TValue>
  struct LegacyDebugVectorRuntime
  {
    std::uint32_t iteratorProxy = 0U; // +0x00
    TValue* begin = nullptr;          // +0x04
    TValue* end = nullptr;            // +0x08
    TValue* capacityEnd = nullptr;    // +0x0C
  };

  static_assert(
    sizeof(LegacyDebugVectorRuntime<std::uint32_t>) == 0x10,
    "LegacyDebugVectorRuntime size must be 0x10"
  );

  template <typename TValue>
  [[nodiscard]] std::size_t LegacyVectorCount(const LegacyDebugVectorRuntime<TValue>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.end == nullptr || vector.end < vector.begin) {
      return 0U;
    }

    return static_cast<std::size_t>(vector.end - vector.begin);
  }

  template <typename TValue>
  [[nodiscard]] std::size_t LegacyVectorCapacity(const LegacyDebugVectorRuntime<TValue>& vector) noexcept
  {
    if (vector.begin == nullptr || vector.capacityEnd == nullptr || vector.capacityEnd < vector.begin) {
      return 0U;
    }

    return static_cast<std::size_t>(vector.capacityEnd - vector.begin);
  }

  /**
   * Address: 0x0049C1A0 (FUN_0049C1A0, sub_49C1A0)
   *
   * What it does:
   * Copies one counted particle-texture pointer lane while retaining the
   * source texture reference.
   */
  moho::CountedPtr_CParticleTexture* CopyCountedParticleTextureLaneRetain(
    moho::CountedPtr_CParticleTexture* const destination,
    const moho::CountedPtr_CParticleTexture* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    return moho::AssignCountedParticleTexturePtr(destination, source->tex);
  }

  /**
   * Address: 0x0049BF10 (FUN_0049BF10, sub_49BF10)
   *
   * What it does:
   * Copies one world-beam payload lane with typed field assignment, including
   * deep copy semantics for counted texture handles.
   */
  void CopyWorldBeamForVectorMove(const moho::SWorldBeam& source, moho::SWorldBeam& destination) noexcept
  {
    destination.mCurStart = source.mCurStart;
    destination.mLastStart = source.mLastStart;
    destination.mFromStart = source.mFromStart;
    destination.mCurEnd = source.mCurEnd;
    destination.mLastEnd = source.mLastEnd;
    destination.mLastInterpolation = source.mLastInterpolation;
    destination.mStart = source.mStart;
    destination.mEnd = source.mEnd;
    destination.mWidth = source.mWidth;
    destination.mStartColor = source.mStartColor;
    destination.mEndColor = source.mEndColor;
    (void)CopyCountedParticleTextureLaneRetain(&destination.mTexture1, &source.mTexture1);
    (void)CopyCountedParticleTextureLaneRetain(&destination.mTexture2, &source.mTexture2);
    destination.mUShift = source.mUShift;
    destination.mVShift = source.mVShift;
    destination.mRepeatRate = source.mRepeatRate;
    destination.mBlendMode = source.mBlendMode;
  }

  void DestroyWorldBeamForVectorTail(moho::SWorldBeam& beam) noexcept
  {
    moho::ResetCountedParticleTexturePtr(beam.mTexture1);
    moho::ResetCountedParticleTexturePtr(beam.mTexture2);
  }

  void DestroyWorldBeamRangeForVectorStorage(
    moho::SWorldBeam* const begin,
    moho::SWorldBeam* const end
  ) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return;
    }

    for (moho::SWorldBeam* beam = begin; beam != end; ++beam) {
      DestroyWorldBeamForVectorTail(*beam);
    }
  }

  /**
   * Address: 0x0049E5A0 (FUN_0049E5A0, sub_49E5A0)
   *
   * What it does:
   * Copies one world-beam range (`[sourceBegin, sourceEnd)`) into destination
   * storage and returns the destination end pointer.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyWorldBeamRangeAndReturnEnd(
    moho::SWorldBeam* destination,
    const moho::SWorldBeam* sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        CopyWorldBeamForVectorMove(*sourceBegin, *destination);
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0049E5D0 (FUN_0049E5D0, sub_49E5D0)
   *
   * What it does:
   * Copies one world-beam source value across one destination range.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyWorldBeamValueAcrossRange(
    const moho::SWorldBeam& sourceBeam,
    moho::SWorldBeam* destinationBegin,
    const moho::SWorldBeam* const destinationEnd
  ) noexcept
  {
    moho::SWorldBeam* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      CopyWorldBeamForVectorMove(sourceBeam, *destinationBegin);
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049E600 (FUN_0049E600, sub_49E600)
   *
   * What it does:
   * Shifts one world-beam tail range right by one element using backward copy
   * order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::SWorldBeam* ShiftWorldBeamRangeRightByOneAndReturnWriteCursor(
    moho::SWorldBeam* sourceLast,
    moho::SWorldBeam* destinationEnd,
    const moho::SWorldBeam* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      CopyWorldBeamForVectorMove(*sourceLast, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049E630 (FUN_0049E630, sub_49E630)
   *
   * What it does:
   * Allocates one world-beam array lane (`0xCC` bytes per element) and throws
   * `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateWorldBeamArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kWorldBeamSize = sizeof(moho::SWorldBeam);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kWorldBeamSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kWorldBeamSize);
  }

  /**
   * Address: 0x0049E690 (FUN_0049E690, nullsub_629)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAN() noexcept {}

  /**
   * Address: 0x0049E6A0 (FUN_0049E6A0, nullsub_630)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAO() noexcept {}

  /**
   * Address: 0x00497530 (FUN_00497530, sub_497530)
   *
   * What it does:
   * Copies one world-beam debug-vector lane into destination storage,
   * allocating a new payload block and deep-copying beam texture handles.
   */
  LegacyDebugVectorRuntime<moho::SWorldBeam>* CopyWorldBeamVectorStorage(
    const LegacyDebugVectorRuntime<moho::SWorldBeam>& source,
    LegacyDebugVectorRuntime<moho::SWorldBeam>& destination
  )
  {
    destination.begin = nullptr;
    destination.end = nullptr;
    destination.capacityEnd = nullptr;

    const std::size_t sourceCount = LegacyVectorCount(source);
    if (sourceCount == 0U) {
      return &destination;
    }

    if (sourceCount > 0x1414141U) {
      throw std::length_error("vector<T> too long");
    }

    auto* const newStorage =
      static_cast<moho::SWorldBeam*>(AllocateWorldBeamArrayOrThrow(static_cast<std::uint32_t>(sourceCount)));
    std::memset(newStorage, 0, sourceCount * sizeof(moho::SWorldBeam));

    destination.begin = newStorage;
    destination.end = newStorage;
    destination.capacityEnd = newStorage + sourceCount;

    if (source.begin != nullptr) {
      moho::SWorldBeam* write = destination.begin;
      for (const moho::SWorldBeam* read = source.begin; read != source.end; ++read, ++write) {
        CopyWorldBeamForVectorMove(*read, *write);
      }
      destination.end = destination.begin + sourceCount;
    }

    return &destination;
  }

  /**
   * Address: 0x00499A20 (FUN_00499A20, sub_499A20)
   *
   * What it does:
   * Inserts one world-beam payload into a beam debug-vector lane, growing
   * storage when required.
   */
  void InsertWorldBeamValueAtAndGrow(
    const moho::SWorldBeam& sourceBeam,
    LegacyDebugVectorRuntime<moho::SWorldBeam>& beams,
    moho::SWorldBeam* insertPosition
  )
  {
    constexpr std::size_t kWorldBeamMaxCount = 0x1414141U;

    const std::size_t size = LegacyVectorCount(beams);
    const std::size_t capacity = LegacyVectorCapacity(beams);

    if (size >= kWorldBeamMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    if (beams.begin == nullptr || beams.end == nullptr || insertPosition == nullptr || insertPosition < beams.begin
        || insertPosition > beams.end) {
      insertPosition = beams.end;
    }

    std::size_t insertionIndex = size;
    if (beams.begin != nullptr && insertPosition != nullptr) {
      insertionIndex = static_cast<std::size_t>(insertPosition - beams.begin);
    }
    if (insertionIndex > size) {
      insertionIndex = size;
    }

    alignas(moho::SWorldBeam) std::uint8_t temporaryStorage[sizeof(moho::SWorldBeam)]{};
    auto* const temporaryBeam = new (temporaryStorage) moho::SWorldBeam{};
    CopyWorldBeamForVectorMove(sourceBeam, *temporaryBeam);

    try {
      if (capacity < (size + 1U)) {
        std::size_t newCapacity = 0U;
        if (kWorldBeamMaxCount - (capacity >> 1U) >= capacity) {
          newCapacity = capacity + (capacity >> 1U);
        }
        if (newCapacity < size + 1U) {
          newCapacity = size + 1U;
        }

        if (newCapacity > kWorldBeamMaxCount) {
          throw std::length_error("vector<T> too long");
        }

        auto* const newStorage =
          static_cast<moho::SWorldBeam*>(AllocateWorldBeamArrayOrThrow(static_cast<std::uint32_t>(newCapacity)));
        std::size_t constructedCount = 0U;

        try {
          for (std::size_t index = 0U; index < insertionIndex; ++index) {
            new (newStorage + index) moho::SWorldBeam{};
            CopyWorldBeamForVectorMove(beams.begin[index], newStorage[index]);
            ++constructedCount;
          }

          new (newStorage + insertionIndex) moho::SWorldBeam{};
          CopyWorldBeamForVectorMove(*temporaryBeam, newStorage[insertionIndex]);
          ++constructedCount;

          for (std::size_t index = insertionIndex; index < size; ++index) {
            new (newStorage + index + 1U) moho::SWorldBeam{};
            CopyWorldBeamForVectorMove(beams.begin[index], newStorage[index + 1U]);
            ++constructedCount;
          }
        } catch (...) {
          DestroyWorldBeamRangeForVectorStorage(newStorage, newStorage + constructedCount);
          ::operator delete(newStorage);
          throw;
        }

        if (beams.begin != nullptr) {
          DestroyWorldBeamRangeForVectorStorage(beams.begin, beams.end);
          ::operator delete(beams.begin);
        }

        beams.begin = newStorage;
        beams.end = newStorage + size + 1U;
        beams.capacityEnd = newStorage + newCapacity;
      } else {
        moho::SWorldBeam* const oldEnd = beams.end;
        new (oldEnd) moho::SWorldBeam{};

        if (insertPosition == oldEnd) {
          CopyWorldBeamForVectorMove(*temporaryBeam, oldEnd[0]);
        } else {
          CopyWorldBeamForVectorMove(oldEnd[-1], oldEnd[0]);
          moho::SWorldBeam* const shiftedWriteCursor =
            ShiftWorldBeamRangeRightByOneAndReturnWriteCursor(oldEnd - 1, oldEnd, insertPosition);
          (void)CopyWorldBeamValueAcrossRange(*temporaryBeam, insertPosition, shiftedWriteCursor);
        }

        beams.end = oldEnd + 1;
      }

      DestroyWorldBeamForVectorTail(*temporaryBeam);
    } catch (...) {
      DestroyWorldBeamForVectorTail(*temporaryBeam);
      throw;
    }
  }

  /**
   * Address: 0x00497640 (FUN_00497640, sub_497640)
   *
   * What it does:
   * Wrapper thunk that forwards one world-beam insert request into the shared
   * insert-and-grow helper.
   */
  void InsertOneWorldBeamValueFromPointer(
    LegacyDebugVectorRuntime<moho::SWorldBeam>& beams,
    moho::SWorldBeam* const insertPosition,
    const moho::SWorldBeam* const sourceBeam
  )
  {
    if (sourceBeam == nullptr) {
      return;
    }

    InsertWorldBeamValueAtAndGrow(*sourceBeam, beams, insertPosition);
  }

  /**
   * Address: 0x004976F0 (FUN_004976F0, sub_4976F0)
   *
   * What it does:
   * Releases one world-beam debug-vector lane (destroy payload range + free
   * storage) and resets begin/end/capacity pointers.
   */
  void ResetWorldBeamVectorStorageDuplicate(
    LegacyDebugVectorRuntime<moho::SWorldBeam>& beams
  ) noexcept
  {
    if (beams.begin != nullptr) {
      DestroyWorldBeamRangeForVectorStorage(beams.begin, beams.end);
      ::operator delete(beams.begin);
    }

    beams.begin = nullptr;
    beams.end = nullptr;
    beams.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00497730 (FUN_00497730, sub_497730)
   *
   * What it does:
   * Copies one world-beam payload range from source into destination storage.
   */
  void CopyWorldBeamRange(
    moho::SWorldBeam* const destination,
    const std::size_t count,
    const moho::SWorldBeam* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr || count == 0U) {
      return;
    }

    for (std::size_t index = 0U; index < count; ++index) {
      CopyWorldBeamForVectorMove(source[index], destination[index]);
    }
  }

  /**
   * Address: 0x00497800 (FUN_00497800, sub_497800)
   *
   * What it does:
   * Recursively destroys one beam-bucket RB-tree subtree and all bucket-entry
   * payloads stored in node value lanes.
   */
  void DestroyBeamBucketTreeSubtree(
    const moho::BeamBucketMapStorageRuntime* const /*owner*/,
    moho::BeamBucketTreeNodeRuntime* node
  ) noexcept
  {
    while (node != nullptr && node->isNilSentinel == 0U) {
      DestroyBeamBucketTreeSubtree(nullptr, node->right);

      moho::BeamBucketTreeNodeRuntime* const next = node->left;
      moho::DestroyBeamTextureBucketEntry(
        reinterpret_cast<moho::BeamTextureBucketEntryRuntime*>(node->payload)
      );
      ::operator delete(node);

      node = next;
    }
  }

  /**
   * Address: 0x00497840 (FUN_00497840, sub_497840)
   *
   * What it does:
   * Inserts one beam-bucket key/value node at the caller hint and re-exports
   * the inserted iterator lane.
   */
  BeamBucketIteratorRuntime* InsertBeamBucketMapEntryAtHint(
    BeamBucketIteratorRuntime* const outIterator,
    moho::BeamTextureBucketMapRuntime& buckets,
    BeamBucketIteratorRuntime hint,
    const bool insertAsLeftChild,
    const moho::BeamTextureBucketKeyRuntime& key
  )
  {
    constexpr std::size_t kBeamBucketMapMaxCount = 0x071C71C6U;
    if (buckets.size() >= kBeamBucketMapMaxCount) {
      throw std::length_error("map/set<T> too long");
    }

    if (hint == buckets.end() && !buckets.empty()) {
      if (insertAsLeftChild) {
        hint = buckets.begin();
      } else {
        hint = buckets.end();
        --hint;
      }
    }

    *outIterator = buckets.emplace_hint(hint, key, msvc8::vector<moho::SWorldBeam>{});
    return outIterator;
  }

  /**
   * Address: 0x0049E720 (FUN_0049E720, sub_49E720)
   *
   * What it does:
   * Allocates one beam-render-vertex array lane (`0x3C` bytes per element) and
   * throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateBeamRenderVertexArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kBeamRenderVertexSize = sizeof(moho::BeamRenderVertexRuntime);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kBeamRenderVertexSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kBeamRenderVertexSize);
  }

  /**
   * Address: 0x00497B40 (FUN_00497B40, sub_497B40)
   *
   * What it does:
   * Grows one beam-render-vertex debug-vector lane for push-back and writes the
   * inserted slot pointer back to caller storage.
   */
  moho::BeamRenderVertexRuntime** GrowBeamRenderVertexVectorForPushBack(
    LegacyDebugVectorRuntime<moho::BeamRenderVertexRuntime>& vertices,
    moho::BeamRenderVertexRuntime** const outInsertPosition,
    moho::BeamRenderVertexRuntime* const appendPosition,
    const moho::BeamRenderVertexRuntime* const sourceVertex
  )
  {
    constexpr std::size_t kBeamRenderVertexMaxCount = 71582788U;

    const std::size_t size = LegacyVectorCount(vertices);
    const std::size_t capacity = LegacyVectorCapacity(vertices);

    std::size_t insertionIndex = size;
    if (
      vertices.begin != nullptr
      && appendPosition != nullptr
      && appendPosition >= vertices.begin
      && appendPosition <= vertices.end
    ) {
      insertionIndex = static_cast<std::size_t>(appendPosition - vertices.begin);
    }

    if (insertionIndex > size) {
      insertionIndex = size;
    }

    if (capacity <= size) {
      std::size_t newCapacity = capacity != 0U ? capacity + (capacity / 2U) : 1U;
      if (newCapacity < size + 1U) {
        newCapacity = size + 1U;
      }
      if (newCapacity > kBeamRenderVertexMaxCount) {
        throw std::length_error("vector<T> too long");
      }

      auto* const newStorage = static_cast<moho::BeamRenderVertexRuntime*>(
        AllocateBeamRenderVertexArrayOrThrow(static_cast<std::uint32_t>(newCapacity))
      );

      for (std::size_t index = 0U; index < size; ++index) {
        newStorage[index] = vertices.begin[index];
      }

      if (vertices.begin != nullptr) {
        ::operator delete(vertices.begin);
      }

      vertices.begin = newStorage;
      vertices.end = newStorage + size;
      vertices.capacityEnd = newStorage + newCapacity;
    }

    moho::BeamRenderVertexRuntime* insertSlot = nullptr;
    if (vertices.begin != nullptr) {
      insertSlot = vertices.begin + insertionIndex;
      if (sourceVertex != nullptr) {
        *insertSlot = *sourceVertex;
        vertices.end = insertSlot + 1;
      }
    }

    *outInsertPosition = insertSlot;
    return outInsertPosition;
  }

  /**
   * Address: 0x00497C20 (FUN_00497C20, sub_497C20)
   *
   * What it does:
   * Copies one beam-render vertex into `base[index]` and returns the destination
   * slot pointer.
   */
  [[nodiscard]] moho::BeamRenderVertexRuntime* CopyBeamRenderVertexAtIndex(
    moho::BeamRenderVertexRuntime* const base,
    const std::size_t index,
    const moho::BeamRenderVertexRuntime* const source
  ) noexcept
  {
    moho::BeamRenderVertexRuntime* slot = nullptr;
    if (base != nullptr) {
      slot = base + index;
      if (source != nullptr) {
        *slot = *source;
      }
    }
    return slot;
  }

  /**
   * Address: 0x00497CD0 (FUN_00497CD0, sub_497CD0)
   *
   * What it does:
   * Appends one value node to the tail of a legacy intrusive list and
   * increments the owning list size lane.
   */
  [[nodiscard]] std::uint32_t AppendLegacyIntrusiveListNodeTail(
    void* const* const valueSlot,
    std::uint32_t* const listSizeSlot,
    void* const listHeadNodeRaw
  );

  /**
   * Address: 0x00499DD0 (FUN_00499DD0, nullsub_582)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAA() noexcept {}

  /**
   * Address: 0x00499E40 (FUN_00499E40, sub_499E40)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent division helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x71C71C7() noexcept
  {
    return 0x071C71C7U;
  }

  /**
   * Address: 0x0049C1C0 (FUN_0049C1C0, sub_49C1C0)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent division helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x1D41D41() noexcept
  {
    return 0x01D41D41U;
  }

  /**
   * Address: 0x0049C1D0 (FUN_0049C1D0, sub_49C1D0)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent division helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x2AAAAAA() noexcept
  {
    return 0x02AAAAAAU;
  }

  /**
   * Address: 0x0049C1E0 (FUN_0049C1E0, sub_49C1E0)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent division helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x1414141() noexcept
  {
    return 0x01414141U;
  }

  /**
   * Address: 0x0049C1F0 (FUN_0049C1F0, sub_49C1F0)
   *
   * What it does:
   * Erases one validated beam-bucket iterator and exports the in-order
   * successor iterator to caller storage.
   */
  BeamBucketIteratorRuntime* EraseOneBeamBucketIteratorAndExportSuccessor(
    BeamBucketIteratorRuntime* const outIterator,
    moho::BeamTextureBucketMapRuntime& buckets,
    BeamBucketIteratorRuntime erasePosition
  )
  {
    if (erasePosition == buckets.end()) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    BeamBucketIteratorRuntime successor = erasePosition;
    ++successor;
    (void)buckets.erase(erasePosition);
    *outIterator = successor;
    return outIterator;
  }

  /**
   * Address: 0x00499E50 (FUN_00499E50, sub_499E50)
   *
   * What it does:
   * Erases one beam-bucket iterator range and writes the next iterator back to
   * caller storage.
   */
  BeamBucketIteratorRuntime* EraseBeamBucketIteratorRange(
    BeamBucketIteratorRuntime* const outIterator,
    moho::BeamTextureBucketMapRuntime& buckets,
    BeamBucketIteratorRuntime eraseBegin,
    const BeamBucketIteratorRuntime eraseEnd
  ) noexcept
  {
    if (eraseBegin == buckets.begin() && eraseEnd == buckets.end()) {
      buckets.clear();
      *outIterator = buckets.begin();
      return outIterator;
    }

    while (eraseBegin != eraseEnd) {
      (void)EraseOneBeamBucketIteratorAndExportSuccessor(&eraseBegin, buckets, eraseBegin);
    }

    *outIterator = eraseBegin;
    return outIterator;
  }

  /**
   * Address: 0x0049A0D0 (FUN_0049A0D0, nullsub_583)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  void NoOpHelperThunkStdcallA(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049A0E0 (FUN_0049A0E0, nullsub_584)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAB() noexcept {}

  /**
   * Address: 0x0049A110 (FUN_0049A110, nullsub_585)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAC() noexcept {}

  /**
   * Address: 0x0049A120 (FUN_0049A120, sub_49A120)
   *
   * What it does:
   * Writes one 32-bit scalar value into caller-provided slot and returns that
   * slot pointer.
   */
  std::uint32_t* WriteScalarDwordSlotG(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * What it does:
   * Compact two-dword lane used by adjacent slot-export helper thunks.
   */
  struct LegacyTwoDwordRuntime
  {
    std::uint32_t value0 = 0U; // +0x00
    std::uint32_t value1 = 0U; // +0x04
  };

  static_assert(
    offsetof(LegacyTwoDwordRuntime, value1) == 0x04,
    "LegacyTwoDwordRuntime::value1 offset must be 0x04"
  );
  static_assert(sizeof(LegacyTwoDwordRuntime) == 0x08, "LegacyTwoDwordRuntime size must be 0x08");

  /**
   * Address: 0x0049A1A0 (FUN_0049A1A0, sub_49A1A0)
   *
   * What it does:
   * Exports the second dword lane (`+0x04`) from one two-dword runtime block
   * into caller storage.
   */
  std::uint32_t* ExportLegacyTwoDwordValue1(
    std::uint32_t* const outValueSlot,
    const LegacyTwoDwordRuntime& source
  ) noexcept
  {
    *outValueSlot = source.value1;
    return outValueSlot;
  }

  /**
   * Address: 0x0049A150 (FUN_0049A150, sub_49A150)
   *
   * What it does:
   * Advances one beam-bucket RB-tree iterator slot to its in-order successor.
   */
  moho::BeamBucketTreeNodeRuntime* AdvanceBeamBucketTreeIterator(
    moho::BeamBucketTreeNodeRuntime** const inOutNodeSlot
  ) noexcept
  {
    moho::BeamBucketTreeNodeRuntime* result = *inOutNodeSlot;
    if (result == nullptr || result->isNilSentinel != 0U) {
      return result;
    }

    moho::BeamBucketTreeNodeRuntime* branch = result->right;
    if (branch != nullptr && branch->isNilSentinel == 0U) {
      result = branch->left;
      while (result != nullptr && result->isNilSentinel == 0U) {
        branch = result;
        result = result->left;
      }
      *inOutNodeSlot = branch;
      return result;
    }

    result = result->parent;
    while (result != nullptr && result->isNilSentinel == 0U) {
      if (*inOutNodeSlot != result->right) {
        break;
      }
      *inOutNodeSlot = result;
      result = result->parent;
    }

    *inOutNodeSlot = result;
    return result;
  }

  /**
   * Address: 0x0049A1B0 (FUN_0049A1B0, sub_49A1B0)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent division helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x4444444() noexcept
  {
    return 0x04444444U;
  }

  /**
   * Address: 0x0049A1C0 (FUN_0049A1C0, nullsub_586)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAD() noexcept {}

  /**
   * Address: 0x0049C0E0 (FUN_0049C0E0, sub_49C0E0)
   *
   * What it does:
   * Copies one packed beam-render vertex lane (`0x3C` bytes / 15 float words).
   */
  moho::BeamRenderVertexRuntime* CopyBeamRenderVertexLanePacked(
    moho::BeamRenderVertexRuntime* const destination,
    const moho::BeamRenderVertexRuntime* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x0049E6B0 (FUN_0049E6B0, sub_49E6B0)
   *
   * What it does:
   * Copies one beam-render-vertex range (`[sourceBegin, sourceEnd)`) into
   * destination storage and returns the destination end pointer.
   */
  [[maybe_unused]] moho::BeamRenderVertexRuntime* CopyBeamRenderVertexRangeAndReturnEnd(
    moho::BeamRenderVertexRuntime* destination,
    const moho::BeamRenderVertexRuntime* sourceBegin,
    const moho::BeamRenderVertexRuntime* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        (void)CopyBeamRenderVertexLanePacked(destination, sourceBegin);
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x0049E6E0 (FUN_0049E6E0, sub_49E6E0)
   *
   * What it does:
   * Copies one beam-render-vertex source value across one destination range.
   */
  [[maybe_unused]] moho::BeamRenderVertexRuntime* CopyBeamRenderVertexValueAcrossRange(
    const moho::BeamRenderVertexRuntime& sourceVertex,
    moho::BeamRenderVertexRuntime* destinationBegin,
    const moho::BeamRenderVertexRuntime* const destinationEnd
  ) noexcept
  {
    moho::BeamRenderVertexRuntime* result = destinationBegin;
    while (destinationBegin != destinationEnd) {
      (void)CopyBeamRenderVertexLanePacked(destinationBegin, &sourceVertex);
      result = destinationBegin;
      ++destinationBegin;
    }
    return result;
  }

  /**
   * Address: 0x0049E6F0 (FUN_0049E6F0, sub_49E6F0)
   *
   * What it does:
   * Shifts one beam-render-vertex tail range right by one element using
   * backward copy order and returns the write cursor after the shift.
   */
  [[maybe_unused]] moho::BeamRenderVertexRuntime* ShiftBeamRenderVertexRangeRightByOneAndReturnWriteCursor(
    moho::BeamRenderVertexRuntime* sourceLast,
    moho::BeamRenderVertexRuntime* destinationEnd,
    const moho::BeamRenderVertexRuntime* const stopAt
  ) noexcept
  {
    while (sourceLast != stopAt) {
      --sourceLast;
      --destinationEnd;
      (void)CopyBeamRenderVertexLanePacked(destinationEnd, sourceLast);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049E780 (FUN_0049E780, nullsub_631)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAP() noexcept {}

  /**
   * Address: 0x0049A1D0 (FUN_0049A1D0, sub_49A1D0)
   *
   * What it does:
   * Inserts one packed beam-render vertex into a legacy debug-vector lane,
   * growing storage when capacity is exhausted.
   */
  [[nodiscard]] moho::BeamRenderVertexRuntime* InsertBeamRenderVertexIntoLegacyVector(
    LegacyDebugVectorRuntime<moho::BeamRenderVertexRuntime>& vertices,
    moho::BeamRenderVertexRuntime* insertPosition,
    const moho::BeamRenderVertexRuntime* const sourceVertex
  )
  {
    constexpr std::size_t kBeamRenderVertexMaxCount = 71582788U;

    const std::size_t size = LegacyVectorCount(vertices);
    const std::size_t capacity = LegacyVectorCapacity(vertices);
    if (size >= kBeamRenderVertexMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    std::size_t insertIndex = size;
    if (
      vertices.begin != nullptr
      && insertPosition != nullptr
      && insertPosition >= vertices.begin
      && insertPosition <= vertices.end
    ) {
      insertIndex = static_cast<std::size_t>(insertPosition - vertices.begin);
    }
    if (insertIndex > size) {
      insertIndex = size;
    }

    if (size < capacity && vertices.begin != nullptr) {
      moho::BeamRenderVertexRuntime* const destination = vertices.begin + insertIndex;
      if (sourceVertex != nullptr) {
        if (destination != vertices.end && size != 0U) {
          moho::BeamRenderVertexRuntime* const shiftedWriteCursor =
            ShiftBeamRenderVertexRangeRightByOneAndReturnWriteCursor(vertices.end - 1, vertices.end, destination);
          (void)CopyBeamRenderVertexValueAcrossRange(*sourceVertex, destination, shiftedWriteCursor);
        } else {
          (void)CopyBeamRenderVertexValueAcrossRange(*sourceVertex, destination, destination + 1);
        }
        ++vertices.end;
      }
      return destination;
    }

    std::size_t newCapacity = capacity != 0U ? capacity + (capacity / 2U) : 1U;
    if (newCapacity < size + 1U) {
      newCapacity = size + 1U;
    }
    if (newCapacity > kBeamRenderVertexMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    auto* const newStorage = static_cast<moho::BeamRenderVertexRuntime*>(
      AllocateBeamRenderVertexArrayOrThrow(static_cast<std::uint32_t>(newCapacity))
    );

    moho::BeamRenderVertexRuntime* writeCursor = newStorage;
    if (vertices.begin != nullptr && insertIndex != 0U) {
      writeCursor = CopyBeamRenderVertexRangeAndReturnEnd(
        writeCursor,
        vertices.begin,
        vertices.begin + insertIndex
      );
    }

    const std::size_t insertedCount = sourceVertex != nullptr ? 1U : 0U;
    if (sourceVertex != nullptr) {
      (void)CopyBeamRenderVertexValueAcrossRange(*sourceVertex, writeCursor, writeCursor + 1);
      ++writeCursor;
    }

    if (vertices.begin != nullptr && insertIndex < size) {
      writeCursor = CopyBeamRenderVertexRangeAndReturnEnd(
        writeCursor,
        vertices.begin + insertIndex,
        vertices.begin + size
      );
    }

    if (vertices.begin != nullptr) {
      ::operator delete(vertices.begin);
    }

    vertices.begin = newStorage;
    vertices.end = newStorage + size + insertedCount;
    vertices.capacityEnd = newStorage + newCapacity;
    return newStorage + insertIndex;
  }

  /**
   * What it does:
   * Typed beam-bucket tree node overlay exposing `left/parent/right +
   * entry(color,nil)` lanes used by low-level helper thunks.
   */
  struct BeamBucketTreeEntryNodeRuntime
  {
    BeamBucketTreeEntryNodeRuntime* left = nullptr;   // +0x00
    BeamBucketTreeEntryNodeRuntime* parent = nullptr; // +0x04
    BeamBucketTreeEntryNodeRuntime* right = nullptr;  // +0x08
    moho::BeamTextureBucketEntryRuntime entry{};      // +0x0C
    std::uint8_t isBlack = 0U;                        // +0x34
    std::uint8_t isNilSentinel = 0U;                  // +0x35
    std::uint16_t padding36 = 0U;                     // +0x36
  };

  static_assert(
    offsetof(BeamBucketTreeEntryNodeRuntime, entry) == 0x0C,
    "BeamBucketTreeEntryNodeRuntime::entry offset must be 0x0C"
  );
  static_assert(
    offsetof(BeamBucketTreeEntryNodeRuntime, isBlack) == 0x34,
    "BeamBucketTreeEntryNodeRuntime::isBlack offset must be 0x34"
  );
  static_assert(
    offsetof(BeamBucketTreeEntryNodeRuntime, isNilSentinel) == 0x35,
    "BeamBucketTreeEntryNodeRuntime::isNilSentinel offset must be 0x35"
  );
  static_assert(sizeof(BeamBucketTreeEntryNodeRuntime) == 0x38, "BeamBucketTreeEntryNodeRuntime size must be 0x38");

  [[nodiscard]] BeamBucketTreeEntryNodeRuntime* AsBeamBucketEntryNode(
    moho::BeamBucketTreeNodeRuntime* const node
  ) noexcept
  {
    return reinterpret_cast<BeamBucketTreeEntryNodeRuntime*>(node);
  }

  [[nodiscard]] bool IsBeamBucketTreeSentinel(
    const BeamBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || node->isNilSentinel != 0U;
  }

  /**
   * Address: 0x0049C4B0 (FUN_0049C4B0, sub_49C4B0)
   *
   * What it does:
   * Returns the leftmost non-sentinel descendant for the provided beam-bucket
   * tree node.
   */
  [[nodiscard]] BeamBucketTreeEntryNodeRuntime* FindBeamBucketTreeLeftmostDescendant(
    BeamBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (IsBeamBucketTreeSentinel(node)) {
      return node;
    }

    BeamBucketTreeEntryNodeRuntime* result = node;
    BeamBucketTreeEntryNodeRuntime* cursor = node->left;
    while (!IsBeamBucketTreeSentinel(cursor)) {
      result = cursor;
      cursor = cursor->left;
    }

    return result;
  }

  /**
   * Address: 0x0049C550 (FUN_0049C550, sub_49C550)
   *
   * What it does:
   * Moves one beam-bucket tree iterator to its in-order predecessor (or max
   * node when called with the head sentinel).
   */
  [[nodiscard]] BeamBucketTreeEntryNodeRuntime* GetPreviousBeamBucketTreeNode(
    BeamBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    if (IsBeamBucketTreeSentinel(node)) {
      return node->right;
    }

    if (!IsBeamBucketTreeSentinel(node->left)) {
      BeamBucketTreeEntryNodeRuntime* rightMost = node->left;
      while (!IsBeamBucketTreeSentinel(rightMost->right)) {
        rightMost = rightMost->right;
      }
      return rightMost;
    }

    BeamBucketTreeEntryNodeRuntime* parent = node->parent;
    while (!IsBeamBucketTreeSentinel(parent) && node == parent->left) {
      node = parent;
      parent = parent->parent;
    }

    return parent;
  }

  /**
   * Address: 0x00499F40 (FUN_00499F40, sub_499F40)
   *
   * What it does:
   * Returns the lower-bound candidate node for one beam-bucket key probe.
   */
  [[nodiscard]] BeamBucketTreeEntryNodeRuntime* FindBeamBucketLowerBoundCandidateNode(
    moho::BeamBucketMapStorageRuntime& storage,
    const moho::BeamTextureBucketKeyRuntime& probeKey
  ) noexcept
  {
    auto* const head = AsBeamBucketEntryNode(storage.head);
    if (head == nullptr) {
      return nullptr;
    }

    BeamBucketTreeEntryNodeRuntime* result = head;
    BeamBucketTreeEntryNodeRuntime* node = head->parent;
    const moho::BeamTextureBucketKeyLess less{};

    while (!IsBeamBucketTreeSentinel(node)) {
      if (!less(node->entry.key, probeKey)) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return result;
  }

  /**
   * Address: 0x00499F90 (FUN_00499F90, sub_499F90)
   *
   * What it does:
   * Performs one left rotation around the provided beam-bucket tree pivot node.
   */
  BeamBucketTreeEntryNodeRuntime* RotateBeamBucketTreeLeft(
    BeamBucketTreeEntryNodeRuntime* const pivot,
    moho::BeamBucketMapStorageRuntime& storage
  ) noexcept
  {
    if (IsBeamBucketTreeSentinel(pivot)) {
      return pivot;
    }

    auto* const right = pivot->right;
    if (IsBeamBucketTreeSentinel(right)) {
      return right;
    }

    pivot->right = right->left;
    if (!IsBeamBucketTreeSentinel(right->left)) {
      right->left->parent = pivot;
    }

    right->parent = pivot->parent;

    auto* const head = AsBeamBucketEntryNode(storage.head);
    if (pivot == head->parent) {
      head->parent = right;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = right;
    } else {
      pivot->parent->right = right;
    }

    right->left = pivot;
    pivot->parent = right;
    return right;
  }

  /**
   * Address: 0x00499FE0 (FUN_00499FE0, sub_499FE0)
   *
   * What it does:
   * Performs one right rotation around the provided beam-bucket tree pivot
   * node.
   */
  BeamBucketTreeEntryNodeRuntime* RotateBeamBucketTreeRight(
    BeamBucketTreeEntryNodeRuntime* const pivot,
    moho::BeamBucketMapStorageRuntime& storage
  ) noexcept
  {
    if (IsBeamBucketTreeSentinel(pivot)) {
      return pivot;
    }

    auto* const left = pivot->left;
    if (IsBeamBucketTreeSentinel(left)) {
      return left;
    }

    pivot->left = left->right;
    if (!IsBeamBucketTreeSentinel(left->right)) {
      left->right->parent = pivot;
    }

    left->parent = pivot->parent;

    auto* const head = AsBeamBucketEntryNode(storage.head);
    if (pivot == head->parent) {
      head->parent = left;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = left;
    } else {
      pivot->parent->left = left;
    }

    left->right = pivot;
    pivot->parent = left;
    return left;
  }

  /**
   * Address: 0x0049A030 (FUN_0049A030, sub_49A030)
   *
   * What it does:
   * Allocates one beam-bucket tree node, binds caller-provided tree links,
   * default-constructs entry payload lanes, and marks the node as non-sentinel.
   */
  [[nodiscard]] BeamBucketTreeEntryNodeRuntime* AllocateBeamBucketTreeEntryNodeWithLinks(
    BeamBucketTreeEntryNodeRuntime* const left,
    BeamBucketTreeEntryNodeRuntime* const parent,
    BeamBucketTreeEntryNodeRuntime* const right
  )
  {
    auto* const node = AsBeamBucketEntryNode(moho::AllocateBeamBucketTreeNodes(1U));
    if (node == nullptr) {
      return nullptr;
    }

    node->left = left;
    node->parent = parent;
    node->right = right;
    ::new (static_cast<void*>(&node->entry)) moho::BeamTextureBucketEntryRuntime{};
    node->isBlack = 0U;
    node->isNilSentinel = 0U;
    node->padding36 = 0U;
    return node;
  }

  /**
   * Address: 0x0049CFD0 (FUN_0049CFD0, sub_49CFD0)
   *
   * What it does:
   * Copies one beam-bucket entry payload lane (key handles, blend mode, and
   * beam vector storage) into destination storage.
   */
  [[maybe_unused]] moho::BeamTextureBucketEntryRuntime* CopyBeamTextureBucketEntryPayload(
    moho::BeamTextureBucketEntryRuntime* const destination,
    const moho::BeamTextureBucketEntryRuntime* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }
    if (destination == source) {
      return destination;
    }

    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&destination->key.texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source->key.texture0)
    );
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&destination->key.texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source->key.texture1)
    );
    destination->key.blendMode = source->key.blendMode;
    destination->allocatorProxy = source->allocatorProxy;

    (void)CopyWorldBeamVectorStorage(
      *reinterpret_cast<const LegacyDebugVectorRuntime<moho::SWorldBeam>*>(&source->beams),
      *reinterpret_cast<LegacyDebugVectorRuntime<moho::SWorldBeam>*>(&destination->beams)
    );
    return destination;
  }

  /**
   * Address: 0x0049CF20 (FUN_0049CF20, sub_49CF20)
   *
   * What it does:
   * Initializes one beam-bucket tree node from caller-provided tree links and
   * copied entry payload, then marks the node as non-sentinel.
   */
  [[maybe_unused]] BeamBucketTreeEntryNodeRuntime* InitializeBeamBucketTreeEntryNodeWithEntryCopy(
    BeamBucketTreeEntryNodeRuntime* const outNode,
    BeamBucketTreeEntryNodeRuntime* const left,
    BeamBucketTreeEntryNodeRuntime* const parent,
    BeamBucketTreeEntryNodeRuntime* const right,
    const moho::BeamTextureBucketEntryRuntime* const entrySource
  )
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    outNode->left = left;
    outNode->parent = parent;
    outNode->right = right;
    ::new (static_cast<void*>(&outNode->entry)) moho::BeamTextureBucketEntryRuntime{};

    if (entrySource != nullptr) {
      (void)CopyBeamTextureBucketEntryPayload(&outNode->entry, entrySource);
    }

    outNode->isBlack = 0U;
    outNode->isNilSentinel = 0U;
    outNode->padding36 = 0U;
    return outNode;
  }

  /**
   * Address: 0x0049CF70 (FUN_0049CF70, nullsub_609)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAJ() noexcept {}

  /**
   * Address: 0x0049CF80 (FUN_0049CF80, nullsub_610)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAK() noexcept {}

  /**
   * Address: 0x0049CF90 (FUN_0049CF90, sub_49CF90)
   *
   * What it does:
   * Writes one `(dword pointer lane, byte flag lane)` pair from source slots
   * into caller output storage.
   */
  [[maybe_unused]] std::uint32_t* WritePointerBytePairFromSlotsA(
    std::uint32_t* const outStorage,
    const std::uint32_t* const pointerSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outStorage[0] = pointerSlot != nullptr ? *pointerSlot : 0U;
    *(reinterpret_cast<std::uint8_t*>(outStorage) + 4) = flagSlot != nullptr ? *flagSlot : 0U;
    return outStorage;
  }

  /**
   * Address: 0x0049CFA0 (FUN_0049CFA0, nullsub_611)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAL() noexcept {}

  /**
   * Address: 0x0049CFB0 (FUN_0049CFB0, nullsub_612)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAM() noexcept {}

  /**
   * Address: 0x0049CFC0 (FUN_0049CFC0, sub_49CFC0)
   *
   * What it does:
   * Duplicate `(dword pointer lane, byte flag lane)` writer retained for
   * adjacent helper parity.
   */
  [[maybe_unused]] std::uint32_t* WritePointerBytePairFromSlotsB(
    std::uint32_t* const outStorage,
    const std::uint32_t* const pointerSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outStorage[0] = pointerSlot != nullptr ? *pointerSlot : 0U;
    *(reinterpret_cast<std::uint8_t*>(outStorage) + 4) = flagSlot != nullptr ? *flagSlot : 0U;
    return outStorage;
  }

  /**
   * Address: 0x0049D030 (FUN_0049D030, sub_49D030)
   *
   * What it does:
   * Walks one beam-bucket subtree to its right-most node and returns that
   * iterator position.
   */
  [[maybe_unused]] BeamBucketTreeEntryNodeRuntime* GetBeamBucketTreeMaximum(
    BeamBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    while (!IsBeamBucketTreeSentinel(node->right)) {
      node = node->right;
    }
    return node;
  }

  /**
   * Address: 0x0049A470 (FUN_0049A470, sub_49A470)
   *
   * What it does:
   * Duplicate vector-overflow throw helper retained for callsite parity.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateC()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * What it does:
   * One legacy intrusive list node lane (`next/prev/value`) used by pooled
   * particle-buffer list helper thunks.
   */
  struct LegacyIntrusiveListNodeRuntime
  {
    LegacyIntrusiveListNodeRuntime* next = nullptr; // +0x00
    LegacyIntrusiveListNodeRuntime* prev = nullptr; // +0x04
    void* value = nullptr;                          // +0x08
  };

  static_assert(
    offsetof(LegacyIntrusiveListNodeRuntime, value) == 0x08,
    "LegacyIntrusiveListNodeRuntime::value offset must be 0x08"
  );
  static_assert(sizeof(LegacyIntrusiveListNodeRuntime) == 0x0C, "LegacyIntrusiveListNodeRuntime size must be 0x0C");

  [[nodiscard]] void* AllocateLegacyIntrusiveListNodeStorageArrayOrThrow(const std::uint32_t elementCount);

  /**
   * Address: 0x0049A4E0 (FUN_0049A4E0, nullsub_587)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAE() noexcept {}

  /**
   * Address: 0x0049A550 (FUN_0049A550, sub_49A550)
   *
   * What it does:
   * Writes one 32-bit scalar value into caller-provided slot and returns that
   * slot pointer.
   */
  std::uint32_t* WriteScalarDwordSlotH(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x0049A570 (FUN_0049A570, sub_49A570)
   *
   * What it does:
   * Allocates one legacy intrusive-list node and initializes `(next, prev,
   * value)` lanes from caller arguments.
   */
  [[nodiscard]] LegacyIntrusiveListNodeRuntime* AllocateLegacyIntrusiveListNode(
    LegacyIntrusiveListNodeRuntime* const next,
    LegacyIntrusiveListNodeRuntime* const prev,
    void* const* const valueSlot
  )
  {
    auto* const node = static_cast<LegacyIntrusiveListNodeRuntime*>(
      AllocateLegacyIntrusiveListNodeStorageArrayOrThrow(1U)
    );
    node->next = next;
    node->prev = prev;
    node->value = valueSlot != nullptr ? *valueSlot : nullptr;
    return node;
  }

  /**
   * Address: 0x0049A5B0 (FUN_0049A5B0, sub_49A5B0)
   *
   * What it does:
   * Increments one legacy list size lane with overflow guard.
   */
  [[nodiscard]] std::uint32_t IncrementLegacyListSizeCheckedDuplicateC(
    std::uint32_t* const listSizeSlot
  )
  {
    constexpr std::uint32_t kLegacyListMaxSize = 0x3FFFFFFFU;
    if (*listSizeSlot == kLegacyListMaxSize) {
      throw std::length_error("list<T> too long");
    }

    ++(*listSizeSlot);
    return *listSizeSlot;
  }

  /**
   * Address: 0x0049A650 (FUN_0049A650, nullsub_588)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  void NoOpHelperThunkStdcallB(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049A660 (FUN_0049A660, nullsub_589)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAF() noexcept {}

  /**
   * Address: 0x0049A670 (FUN_0049A670, sub_49A670)
   *
   * What it does:
   * Allocates storage for one legacy intrusive-list node lane.
   */
  [[nodiscard]] void* AllocateSingleLegacyListNodeStorage()
  {
    return AllocateLegacyIntrusiveListNodeStorageArrayOrThrow(1U);
  }

  /**
   * Address: 0x0049A690 (FUN_0049A690, nullsub_590)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAG() noexcept {}

  /**
   * Address: 0x0049A6B0 (FUN_0049A6B0, sub_49A6B0)
   *
   * What it does:
   * Returns the legacy maximum container element count constant (`0x3FFFFFFF`).
   */
  [[nodiscard]] std::uint32_t GetLegacyContainerMaxElementCount_0x3FFFFFFF() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049A7F0 (FUN_0049A7F0, nullsub_591)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  void NoOpHelperThunkStdcallC(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049A800 (FUN_0049A800, nullsub_592)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAH() noexcept {}

  /**
   * Address: 0x0049A810 (FUN_0049A810, nullsub_593)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkAI() noexcept {}

  /**
   * Address: 0x0049E790 (FUN_0049E790, sub_49E790)
   *
   * What it does:
   * Allocates one legacy intrusive-list node storage lane (`0x0C` bytes per
   * element) and throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateLegacyIntrusiveListNodeStorageArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::size_t kLegacyListNodeSize = sizeof(LegacyIntrusiveListNodeRuntime);
    constexpr std::uint32_t kLegacyUIntMax = std::numeric_limits<std::uint32_t>::max();

    if (elementCount != 0U && (kLegacyUIntMax / elementCount) < kLegacyListNodeSize) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * kLegacyListNodeSize);
  }

  /**
   * Address: 0x0049E7F0 (FUN_0049E7F0, nullsub_632)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAQ() noexcept {}

  /**
   * Address: 0x0049E800 (FUN_0049E800, nullsub_633)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAR() noexcept {}

  /**
   * Address: 0x0049E810 (FUN_0049E810, nullsub_634)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAS() noexcept {}

  [[nodiscard]] std::uint32_t AppendLegacyIntrusiveListNodeTail(
    void* const* const valueSlot,
    std::uint32_t* const listSizeSlot,
    void* const listHeadNodeRaw
  )
  {
    auto* const listHeadNode = static_cast<LegacyIntrusiveListNodeRuntime*>(listHeadNodeRaw);
    auto* const node = AllocateLegacyIntrusiveListNode(listHeadNode, listHeadNode->prev, valueSlot);
    const std::uint32_t newSize = IncrementLegacyListSizeCheckedDuplicateC(listSizeSlot);
    listHeadNode->prev = node;
    node->prev->next = node;
    return newSize;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleTexture0ShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      (void)RegisterParticleShaderVarSlotA("particle", "ParticleTexture0", &shaderVar);
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleTexture1ShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      (void)RegisterParticleShaderVarSlotB("particle", "ParticleTexture1", &shaderVar);
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleDragEnabledShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      moho::RegisterShaderVar("DragEnabled", &shaderVar, "particle");
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] const char* ResolveParticleTechniqueSuffix(
    const std::int32_t blendMode, const bool allowRefractSuffix, const int unreachableLine
  )
  {
    switch (blendMode) {
      case 0:
        return "_ALPHABLEND";
      case 1:
        return "_MODULATEINVERSE";
      case 2:
        return "_MODULATE2XINVERSE";
      case 3:
        return "_ADD";
      case 4:
        return "_PREMODALPHA";
      case 5:
        if (allowRefractSuffix) {
          return "_REFRACT";
        }
        break;
      default:
        break;
    }

    gpg::HandleAssertFailure(kUnreachableAssertText, unreachableLine, kParticleRendererSourcePath);
    return "_ALPHABLEND";
  }

  [[nodiscard]] std::string BuildBeamTechniqueName(const std::int32_t blendMode, const bool hasTwoTextures)
  {
    std::string techniqueName = hasTwoTextures ? "TBeam_TwoTexture" : "TBeam_OneTexture";
    techniqueName += ResolveParticleTechniqueSuffix(blendMode, false, 301);
    return techniqueName;
  }

  void BindBeamTextureShaderVar(moho::ShaderVar& shaderVar, const moho::TextureSheetHandle& textureSheet)
  {
    moho::ID3DTextureSheet::TextureHandle textureHandle{};
    if (textureSheet != nullptr) {
      textureSheet->GetTexture(textureHandle);
    }

    boost::weak_ptr<gpg::gal::TextureD3D9> weakTexture = textureHandle;
    shaderVar.GetTexture(weakTexture);
  }

  void BindBeamTextureShaderVar(
    moho::ShaderVar& shaderVar,
    const moho::CParticleTexture::TextureResourceHandle& textureResource
  )
  {
    boost::shared_ptr<gpg::gal::TextureD3D9> textureHandle{};
    if (textureResource != nullptr) {
      textureResource->GetTexture(textureHandle);
    }

    boost::weak_ptr<gpg::gal::TextureD3D9> weakTexture(textureHandle);
    shaderVar.GetTexture(weakTexture);
  }
} // namespace

namespace moho
{
  bool ren_Beams = true;

  bool BeamTextureBucketKeyLess::operator()(
    const BeamTextureBucketKeyRuntime& lhs, const BeamTextureBucketKeyRuntime& rhs
  ) const noexcept
  {
    if (lhs.blendMode != rhs.blendMode) {
      return lhs.blendMode < rhs.blendMode;
    }

    if (IsSharedHandleLessForBucket(lhs.texture0, rhs.texture0)) {
      return true;
    }
    return IsSharedHandleLessForBucket(lhs.texture1, rhs.texture1);
  }

  /**
   * Address: 0x00BC5530 (FUN_00BC5530, register_TConVar_ren_Beams)
   *
   * What it does:
   * Registers the beam-render enable convar and schedules process-exit teardown.
   */
  void register_TConVar_ren_Beams()
  {
    RegisterConCommand(gTConVar_ren_Beams);
    (void)std::atexit(&CleanupTConVar_ren_Beams);
  }

  /**
   * Address: 0x00491440 (FUN_00491440, func_NewVertexSheet)
   *
   * What it does:
   * Allocates one beam-particle vertex sheet from device resources and swaps it
   * into the caller slot, deleting the old sheet when replaced.
   */
  void RecreateBeamParticleVertexSheet(CD3DVertexSheet*& vertexSheet, CD3DVertexFormat* const vertexFormat)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexSheet* const newSheet = resources->NewVertexSheet(1U, 1000, vertexFormat);

    CD3DVertexSheet* const oldSheet = vertexSheet;
    if (newSheet != oldSheet && oldSheet != nullptr) {
      delete oldSheet;
    }

    vertexSheet = newSheet;
  }

  /**
   * Address: 0x0049EB80 (FUN_0049EB80, sub_49EB80)
   *
   * What it does:
   * Allocates one array lane of `BeamBucketTreeNodeRuntime` with overflow guard.
   */
  BeamBucketTreeNodeRuntime* AllocateBeamBucketTreeNodes(const std::uint32_t count)
  {
    if (count == 0 || std::numeric_limits<std::uint32_t>::max() / count < sizeof(BeamBucketTreeNodeRuntime)) {
      throw std::bad_alloc();
    }

    return static_cast<BeamBucketTreeNodeRuntime*>(::operator new(sizeof(BeamBucketTreeNodeRuntime) * count));
  }

  /**
   * Address: 0x0049C4D0 (FUN_0049C4D0, sub_49C4D0)
   *
   * What it does:
   * Allocates and clears one beam bucket tree node, initializing RB-tree flags
   * for non-sentinel usage.
   */
  BeamBucketTreeNodeRuntime* AllocateBeamBucketTreeNode()
  {
    BeamBucketTreeNodeRuntime* const node = AllocateBeamBucketTreeNodes(1U);
    if (node != nullptr) {
      node->left = nullptr;
      node->parent = nullptr;
      node->right = nullptr;
      node->isBlack = 1U;
      node->isNilSentinel = 0U;
    }
    return node;
  }

  /**
   * Address: 0x0049C510 (FUN_0049C510, nullsub_600)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBeamMapA(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049C520 (FUN_0049C520, sub_49C520)
   *
   * What it does:
   * Returns one fixed legacy map-size limit constant.
   */
  [[nodiscard]] std::uint32_t GetLegacyMapMaxElementCount_0x71C71C7() noexcept
  {
    return 0x071C71C7U;
  }

  /**
   * Address: 0x0049C530 (FUN_0049C530, sub_49C530)
   *
   * What it does:
   * Allocates one beam-bucket tree node lane via the shared array allocator.
   */
  [[nodiscard]] BeamBucketTreeNodeRuntime* AllocateSingleBeamBucketTreeNodeArray() { return AllocateBeamBucketTreeNodes(1U); }

  /**
   * Address: 0x0049C5B0 (FUN_0049C5B0, sub_49C5B0)
   *
   * What it does:
   * Returns one fixed legacy division magic constant.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x4444444_DuplicateA() noexcept
  {
    return 0x04444444U;
  }

  /**
   * Address: 0x0049C5F0 (FUN_0049C5F0, sub_49C5F0)
   *
   * What it does:
   * Returns one fixed legacy list-size cap constant.
   */
  [[nodiscard]] std::uint32_t GetLegacyListMaxElementCount_0x3FFFFFFF_BeamA() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049C600 (FUN_0049C600, nullsub_601)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBeamMapB(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004914B0 (FUN_004914B0, sub_4914B0)
   *
   * What it does:
   * Initializes one beam bucket map storage with a self-linked sentinel head.
   */
  BeamBucketMapStorageRuntime* InitializeBeamBucketMapStorage(BeamBucketMapStorageRuntime* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    storage->allocatorProxy = 0U;
    BeamBucketTreeNodeRuntime* const head = AllocateBeamBucketTreeNode();
    storage->head = head;
    if (head != nullptr) {
      head->isNilSentinel = 1U;
      head->parent = head;
      head->left = head;
      head->right = head;
    }
    storage->size = 0U;
    return storage;
  }

  /**
   * Address: 0x004921D0 (FUN_004921D0, sub_4921D0)
   *
   * What it does:
   * Initializes the two texture handle lanes used by one beam bucket key.
   */
  BeamTextureBucketKeyRuntime* InitializeBeamTextureBucketKeyHandles(BeamTextureBucketKeyRuntime* const key)
  {
    if (key == nullptr) {
      return nullptr;
    }

    key->texture0.reset();
    key->texture1.reset();
    return key;
  }

  /**
   * Address: 0x00492200 (FUN_00492200, sub_492200)
   *
   * What it does:
   * Releases one temporary beam bucket entry (vector storage + two retained
   * texture handles).
   */
  void DestroyBeamTextureBucketEntry(BeamTextureBucketEntryRuntime* const entry)
  {
    if (entry == nullptr) {
      return;
    }

    entry->beams = msvc8::vector<SWorldBeam>{};
    entry->allocatorProxy = 0U;
    entry->key.texture0.reset();
    entry->key.texture1.reset();
  }

  /**
   * Address: 0x004921A0 (FUN_004921A0, sub_4921A0)
   *
   * What it does:
   * Destroys all nodes in one beam texture bucket map and resets storage.
   */
  void DestroyBeamTextureBucketMap(BeamTextureBucketMapRuntime& buckets)
  {
    BeamTextureBucketMapRuntime emptyBuckets{};
    buckets.swap(emptyBuckets);
  }

  /**
   * Address: 0x00491540 (FUN_00491540, sub_491540)
   *
   * What it does:
   * Resolves beam textures into one bucket key and appends the beam payload
   * into the matching texture/blend bucket.
   */
  void AddBeamToTextureBuckets(BeamTextureBucketMapRuntime& buckets, const SWorldBeam& beam)
  {
    if (!ren_Beams) {
      return;
    }

    BeamTextureBucketKeyRuntime bucketKey{};
    (void)InitializeBeamTextureBucketKeyHandles(&bucketKey);

    CParticleTexture::TextureResourceHandle texture0{};
    if (beam.mTexture1.tex != nullptr) {
      beam.mTexture1.tex->GetTexture(texture0);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&bucketKey.texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&texture0)
    );

    CParticleTexture::TextureResourceHandle texture1{};
    if (beam.mTexture2.tex != nullptr) {
      beam.mTexture2.tex->GetTexture(texture1);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&bucketKey.texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&texture1)
    );
    bucketKey.blendMode = static_cast<std::int32_t>(beam.mBlendMode);

    BeamBucketInsertPositionRuntime insertPosition{};
    (void)FindOrInsertBeamBucketEntryByKey(buckets, bucketKey, &insertPosition);

    if (insertPosition.iterator != buckets.end()) {
      AppendBeamToVector(insertPosition.iterator->second, beam);
    }
  }

  /**
   * Address: 0x00495620 (FUN_00495620, std::vector_SWorldParticle::push_back)
   *
   * What it does:
   * Appends one world-particle payload into a world-particle vector lane.
   */
  void AppendWorldParticleToVector(msvc8::vector<SWorldParticle>& particles, const SWorldParticle& particle)
  {
    particles.push_back(particle);
  }

  /**
   * Address: 0x004957C0 (FUN_004957C0, std::vector_STrail::push_back)
   *
   * What it does:
   * Appends one world-trail payload into a trail vector lane.
   */
  void AppendTrailToVector(msvc8::vector<TrailRuntimeView>& trails, const TrailRuntimeView& trail)
  {
    trails.push_back(trail);
  }

  /**
   * Address: 0x00495990 (FUN_00495990, std::vector_Beam::push_back)
   *
   * What it does:
   * Appends one world-beam payload into a beam vector lane.
   */
  void AppendBeamToVector(msvc8::vector<SWorldBeam>& beams, const SWorldBeam& beam)
  {
    beams.push_back(beam);
  }

  /**
   * Address: 0x00494740 (FUN_00494740, func_ParticleSelectTechnique)
   *
   * What it does:
   * Binds particle textures and selects particle technique suffix by blend mode.
   */
  void SelectParticleTechnique(const ParticleTechniqueSelectionRuntime& selection)
  {
    BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), selection.texture0);
    BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), selection.texture1);

    std::string techniqueName(selection.techniqueBaseName.data(), selection.techniqueBaseName.size());
    techniqueName += ResolveParticleTechniqueSuffix(selection.blendMode, false, kParticleSelectTechniqueAssertLine);

    CD3DDevice* const device = D3D_GetDevice();
    if (device != nullptr) {
      device->SelectTechnique(techniqueName.c_str());
    }
  }

  /**
   * Address: 0x00493AE0 (FUN_00493AE0, func_ParticleSelectTechnique2)
   *
   * What it does:
   * Binds drag-enabled flag and particle textures, then selects particle
   * technique suffix (including refraction lane).
   */
  void SelectParticleTechniqueWithDrag(const ParticleTechniqueSelectionWithDragRuntime& selection)
  {
    const bool dragEnabled = selection.dragEnabled;
    ShaderVar& dragEnabledShaderVar = GetParticleDragEnabledShaderVar();
    if (dragEnabledShaderVar.Exists()) {
      dragEnabledShaderVar.mEffectVariable->SetPtr(&dragEnabled, 4U);
    }

    BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), selection.texture0);
    BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), selection.texture1);

    std::string techniqueName(selection.techniqueBaseName.data(), selection.techniqueBaseName.size());
    techniqueName += ResolveParticleTechniqueSuffix(selection.blendMode, true, kParticleSelectTechniqueWithDragAssertLine);

    CD3DDevice* const device = D3D_GetDevice();
    if (device != nullptr) {
      device->SelectTechnique(techniqueName.c_str());
    }
  }

  /**
   * Address: 0x00491760 (FUN_00491760, sub_491760)
   *
   * What it does:
   * Interpolates one beam segment and emits four packed render vertices that
   * form one billboarded beam quad.
   */
  void EmitInterpolatedBeamQuadVertices(
    const SWorldBeam& beam, const float frameAlpha, BeamRenderVertexArrayRuntime& outVertices
  )
  {
    const float interpolation = std::min(beam.mLastInterpolation * frameAlpha, 1.0f);

    const Wm3::Quaternion<float> startOrientation =
      Wm3::Quaternion<float>::Nlerp(beam.mLastStart.orient_, beam.mCurStart.orient_, interpolation);
    const Wm3::Vector3<float> startBasePosition = LerpVector3(beam.mLastStart.pos_, beam.mCurStart.pos_, interpolation);
    const Wm3::Vector3<float> startWorldPosition = Wm3::Vector3<float>::Add(
      startBasePosition, RotateVectorByOrientation(beam.mStart, startOrientation)
    );

    Wm3::Quaternion<float> endOrientation = startOrientation;
    Wm3::Vector3<float> endBasePosition = startBasePosition;
    if (beam.mFromStart) {
      endOrientation = Wm3::Quaternion<float>::Nlerp(beam.mLastEnd.orient_, beam.mCurEnd.orient_, interpolation);
      endBasePosition = LerpVector3(beam.mLastEnd.pos_, beam.mCurEnd.pos_, interpolation);
    }

    const Wm3::Vector3<float> endWorldPosition =
      Wm3::Vector3<float>::Add(endBasePosition, RotateVectorByOrientation(beam.mEnd, endOrientation));

    Wm3::Vector3<float> axis = Wm3::Vector3<float>::Sub(startWorldPosition, endWorldPosition);
    float repeatCoord = 1.0f;
    if (beam.mRepeatRate != 0.0f) {
      repeatCoord = Wm3::Vector3<float>::Length(axis) * beam.mRepeatRate;
    }
    Wm3::Vector3<float>::Normalize(axis);
    const Wm3::Vector3<float> oppositeAxis = Wm3::Vector3<float>::Scale(axis, -1.0f);

    outVertices.push_back(
      BuildBeamRenderVertex(startWorldPosition, axis, beam.mWidth, beam.mStartColor, 1.0f, 0.0f, beam.mUShift, beam.mVShift)
    );
    outVertices.push_back(
      BuildBeamRenderVertex(endWorldPosition, axis, beam.mWidth, beam.mEndColor, 1.0f, repeatCoord, beam.mUShift, beam.mVShift)
    );
    outVertices.push_back(
      BuildBeamRenderVertex(
        endWorldPosition,
        oppositeAxis,
        beam.mWidth,
        beam.mEndColor,
        0.0f,
        repeatCoord,
        beam.mUShift,
        beam.mVShift
      )
    );
    outVertices.push_back(
      BuildBeamRenderVertex(
        startWorldPosition,
        oppositeAxis,
        beam.mWidth,
        beam.mStartColor,
        0.0f,
        0.0f,
        beam.mUShift,
        beam.mVShift
      )
    );
  }

  /**
   * Address: 0x00491E40 (FUN_00491E40, func_DrawBeamParticle)
   *
   * What it does:
   * Renders the active beam buckets into the shared vertex/index sheets using
   * beam-technique selection and 1000-vertex batching.
   */
  [[nodiscard]] bool DrawBeamParticle(BeamBucketContainerRuntime& beams, const float frameAlpha, const bool disable)
  {
    if (!ren_Beams || disable) {
      return false;
    }

    if (beams.mVertexSheet == nullptr) {
      CD3DDevice* const device = D3D_GetDevice();
      if (device == nullptr) {
        return false;
      }

      ID3DDeviceResources* const resources = device->GetResources();
      if (resources == nullptr) {
        return false;
      }

      CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(13);
      if (vertexFormat == nullptr) {
        return false;
      }

      RecreateBeamParticleVertexSheet(beams.mVertexSheet, vertexFormat);
    }

    if (beams.mVertexSheet == nullptr) {
      return false;
    }

    ID3DIndexSheet* sharedIndexSheet = GetSharedTrailQuadIndexSheet();
    if (sharedIndexSheet == nullptr) {
      (void)RebuildSharedTrailQuadIndexSheet();
      sharedIndexSheet = GetSharedTrailQuadIndexSheet();
    }
    if (sharedIndexSheet == nullptr) {
      return false;
    }

    bool didDraw = false;
    BeamRenderVertexArrayRuntime vertices{};

    for (auto bucketIt = beams.mBuckets.begin(); bucketIt != beams.mBuckets.end(); ++bucketIt) {
      const BeamTextureBucketKeyRuntime& bucketKey = bucketIt->first;
      const msvc8::vector<SWorldBeam>& beamList = bucketIt->second;
      if (beamList.empty()) {
        continue;
      }

      vertices.clear();
      for (const SWorldBeam& beam : beamList) {
        EmitInterpolatedBeamQuadVertices(beam, frameAlpha, vertices);
      }

      const std::int32_t totalVertices = GetBeamRenderVertexCount(vertices);
      if (totalVertices <= 0) {
        continue;
      }

      BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), bucketKey.texture0);
      BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), bucketKey.texture1);

      CD3DDevice* const device = D3D_GetDevice();
      if (device == nullptr) {
        continue;
      }

      const std::string techniqueName = BuildBeamTechniqueName(
        bucketKey.blendMode,
        bucketKey.texture1.get() != nullptr
      );
      device->SelectTechnique(techniqueName.c_str());

      const BeamRenderVertexRuntime* const sourceVertices = vertices.empty() ? nullptr : &vertices[0];
      std::int32_t remainingVertices = totalVertices;
      std::int32_t vertexOffset = 0;

      while (remainingVertices > 0 && sourceVertices != nullptr) {
        const std::int32_t batchVertices = std::min<std::int32_t>(remainingVertices, 1000);
        const std::int32_t quadCount = batchVertices / 4;
        if (quadCount <= 0) {
          break;
        }

        ID3DVertexStream* const vertexStream = beams.mVertexSheet->GetVertStream(0U);
        if (vertexStream == nullptr) {
          break;
        }

        void* const mappedVertices = vertexStream->Lock(0, batchVertices, false, true);
        if (mappedVertices == nullptr) {
          break;
        }

        std::memcpy(
          mappedVertices,
          sourceVertices + vertexOffset,
          static_cast<std::size_t>(batchVertices) * sizeof(BeamRenderVertexRuntime)
        );
        vertexStream->Unlock();

        CD3DVertexSheetViewRuntime vertexSheetView{};
        vertexSheetView.sheet = beams.mVertexSheet;
        vertexSheetView.startVertex = 0;
        vertexSheetView.baseVertex = 0;
        vertexSheetView.endVertex = batchVertices - 1;

        CD3DIndexSheetViewRuntime indexSheetView{};
        indexSheetView.sheet = sharedIndexSheet;
        indexSheetView.startIndex = 0;
        indexSheetView.indexCount = 6 * quadCount;

        std::int32_t primitiveType = 4;
        (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);

        didDraw = true;
        vertexOffset += batchVertices;
        remainingVertices -= batchVertices;
      }
    }

    return didDraw;
  }

  /**
   * Address: 0x00492290 (FUN_00492290, sub_492290)
   *
   * What it does:
   * Strict-weak ordering comparator for world-particle bucket keys.
   */
  bool IsParticleBucketKeyRhsLessThanLhs(
    const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs
  ) noexcept
  {
    if (lhs.sortScalar != rhs.sortScalar) {
      return lhs.sortScalar > rhs.sortScalar;
    }

    if (lhs.stateByte != rhs.stateByte) {
      return rhs.stateByte < lhs.stateByte;
    }

    if (lhs.blendMode != rhs.blendMode) {
      return rhs.blendMode < lhs.blendMode;
    }

    if (lhs.zMode != rhs.zMode) {
      return rhs.zMode < lhs.zMode;
    }

    if (AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0)) {
      if (AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1)) {
        return IsMsvc8StringLess(rhs.tag, lhs.tag);
      }
      return IsSharedHandleLessForBucket(rhs.texture1, lhs.texture1);
    }

    return IsSharedHandleLessForBucket(rhs.texture0, lhs.texture0);
  }

  /**
   * Address: 0x00492310 (FUN_00492310, sub_492310)
   *
   * What it does:
   * Equality comparator for world-particle bucket keys.
   */
  bool AreParticleBucketKeysEquivalent(const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs) noexcept
  {
    return lhs.sortScalar == rhs.sortScalar &&
           lhs.stateByte == rhs.stateByte &&
           lhs.blendMode == rhs.blendMode &&
           lhs.zMode == rhs.zMode &&
           AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0) &&
           AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1) &&
           lhs.tag == rhs.tag;
  }

  /**
   * Address: 0x00494B90 (FUN_00494B90, sub_494B90)
   *
   * What it does:
   * Copies one world-particle bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  ParticleBucketKeyRuntime* CopyParticleBucketKey(
    ParticleBucketKeyRuntime* const destination,
    const ParticleBucketKeyRuntime* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->sortScalar = source->sortScalar;
    destination->stateByte = source->stateByte;

    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture1)
    );

    destination->tag = source->tag;
    destination->blendMode = source->blendMode;
    destination->zMode = source->zMode;
    return destination;
  }

  /**
   * Address: 0x00492390 (FUN_00492390, sub_492390)
   *
   * What it does:
   * Builds one trail bucket key from one `STrail` runtime payload.
   */
  TrailBucketKeyRuntime* InitializeTrailBucketKeyFromTrail(TrailBucketKeyRuntime* const key, const TrailRuntimeView& trail)
  {
    if (key == nullptr) {
      return nullptr;
    }

    key->texture0.reset();
    key->texture1.reset();
    key->tag = msvc8::string{};

    key->sortScalar = trail.sortScalar;

    CParticleTexture::TextureResourceHandle texture0{};
    if (trail.texture0 != nullptr) {
      trail.texture0->GetTexture(texture0);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&texture0)
    );

    CParticleTexture::TextureResourceHandle texture1{};
    if (trail.texture1 != nullptr) {
      trail.texture1->GetTexture(texture1);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&texture1)
    );

    key->tag.assign_owned(trail.tag != nullptr ? trail.tag : "");
    key->uvScalar = trail.uvScalar;
    return key;
  }

  /**
   * Address: 0x00492520 (FUN_00492520, sub_492520)
   *
   * What it does:
   * Strict-weak ordering comparator for trail bucket keys.
   */
  bool IsTrailBucketKeyRhsLessThanLhs(
    const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs
  ) noexcept
  {
    if (lhs.sortScalar != rhs.sortScalar) {
      return lhs.sortScalar > rhs.sortScalar;
    }

    if (lhs.uvScalar != rhs.uvScalar) {
      return rhs.uvScalar < lhs.uvScalar;
    }

    if (AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0)) {
      if (AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1)) {
        return IsMsvc8StringLess(rhs.tag, lhs.tag);
      }
      return IsSharedHandleLessForBucket(rhs.texture1, lhs.texture1);
    }

    return IsSharedHandleLessForBucket(rhs.texture0, lhs.texture0);
  }

  /**
   * Address: 0x00492590 (FUN_00492590, sub_492590)
   *
   * What it does:
   * Equality comparator for trail bucket keys.
   */
  bool AreTrailBucketKeysEquivalent(const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs) noexcept
  {
    return lhs.sortScalar == rhs.sortScalar &&
           lhs.uvScalar == rhs.uvScalar &&
           AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0) &&
           AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1) &&
           lhs.tag == rhs.tag;
  }

  /**
   * Address: 0x00494D90 (FUN_00494D90, sub_494D90)
   *
   * What it does:
   * Copies one world-trail bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  TrailBucketKeyRuntime* CopyTrailBucketKey(
    TrailBucketKeyRuntime* const destination,
    const TrailBucketKeyRuntime* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->sortScalar = source->sortScalar;
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture1)
    );
    destination->tag = source->tag;
    destination->uvScalar = source->uvScalar;
    return destination;
  }

  /**
   * Address: 0x00492EF0 (FUN_00492EF0, sub_492EF0)
   *
   * What it does:
   * Releases one world-particle bucket key resource lane.
   */
  void ResetParticleBucketKeyResources(ParticleBucketKeyRuntime& key)
  {
    key.tag.tidy(true, 0U);
    key.texture1.reset();
    key.texture0.reset();
  }

  /**
   * Address: 0x00492FC0 (FUN_00492FC0, sub_492FC0)
   *
   * What it does:
   * Releases one world-trail bucket key resource lane.
   */
  void ResetTrailBucketKeyResources(TrailBucketKeyRuntime& key)
  {
    key.tag.tidy(true, 0U);
    key.texture1.reset();
    key.texture0.reset();
  }
} // namespace moho

namespace
{
  struct BeamRenderHelpersStartupBootstrap
  {
    BeamRenderHelpersStartupBootstrap()
    {
      moho::register_TConVar_ren_Beams();
    }
  };

  [[maybe_unused]] BeamRenderHelpersStartupBootstrap gBeamRenderHelpersStartupBootstrap;
} // namespace

namespace moho
{
  namespace
  {
    /// Fetches the first stream of `sheet` through its typed virtual
    /// `GetVertStream(0)` slot, matching the binary's slot-8 dispatch.
    [[nodiscard]] ID3DVertexStream* FetchPrimaryVertexStream(CD3DVertexSheet* const sheet)
    {
      return sheet->GetVertStream(0u);
    }
  } // namespace

  /**
   * Address: 0x0043C3D0 (FUN_0043C3D0, sub_43C3D0)
   *
   * IDA signature:
   * int __usercall sub_43C3D0@<eax>(_DWORD *a1@<esi>);
   *
   * What it does:
   * Locks the first vertex stream of `context.sheet` for exclusive
   * write access over the full requested vertex count, stores the
   * returned map pointer into the context write cursor, and resets
   * the running quad count to zero.
   */
  void BeamDrawContextBeginMap(BeamDrawContextRuntime& context)
  {
    ID3DVertexStream* const stream = FetchPrimaryVertexStream(context.sheet);
    void* const mapped = stream->Lock(0, context.maxVertexCount, true, true);
    context.writeCursor = static_cast<float*>(mapped);
    context.quadCount = 0;
  }

  /**
   * Address: 0x0043C400 (FUN_0043C400, sub_43C400)
   *
   * IDA signature:
   * void __usercall sub_43C400(_DWORD *a1@<esi>);
   *
   * What it does:
   * If the context currently holds a live write cursor, unlocks the
   * first vertex stream of `context.sheet` and clears the cursor.
   */
  void BeamDrawContextEndMap(BeamDrawContextRuntime& context)
  {
    if (context.writeCursor != nullptr) {
      ID3DVertexStream* const stream = FetchPrimaryVertexStream(context.sheet);
      stream->Unlock();
      context.writeCursor = nullptr;
    }
  }

  /**
   * Address: 0x0043C390 (FUN_0043C390, sub_43C390)
   *
   * IDA signature:
   * void __usercall sub_43C390(_DWORD *a1@<esi>);
   *
   * What it does:
   * Ends any active map session, then releases the owning vertex
   * sheet through its deleting-destructor thunk (vtable slot 0 with
   * `deleteFlag = 1`, matching the binary) and nulls the sheet
   * pointer so the context is safe to reinitialize.
   */
  void BeamDrawContextTeardown(BeamDrawContextRuntime& context)
  {
    BeamDrawContextEndMap(context);
    if (context.sheet != nullptr) {
      delete context.sheet;
      context.sheet = nullptr;
    }
  }

  /**
   * Address: 0x0043C430 (FUN_0043C430, sub_43C430)
   *
   * IDA signature:
   * float *__userpurge sub_43C430@<eax>(
   *   float *a1@<eax>, int a2@<ecx>, float a3, float a4, float a5);
   *
   * What it does:
   * Builds four translated vertices from one unit-box corner pair
   * and writes them into the active write cursor in the order the
   * binary emits:
   *   v0 = ( boxCorners[0] + dx, boxCorners[4] + dy, boxCorners[2] + dz )
   *   v1 = ( boxCorners[3] + dx, boxCorners[4] + dy, boxCorners[2] + dz )
   *   v2 = ( boxCorners[3] + dx, boxCorners[1] + dy, boxCorners[5] + dz )
   *   v3 = ( boxCorners[0] + dx, boxCorners[1] + dy, boxCorners[5] + dz )
   * The cursor is then advanced by 48 bytes (four 3-float vertices)
   * and the running quad count is bumped.
   */
  float* BeamDrawContextWriteTranslatedQuad(
    BeamDrawContextRuntime& context,
    const float* const boxCorners,
    const float dx,
    const float dy,
    const float dz)
  {
    const float boxX0 = boxCorners[0];
    const float boxY0 = boxCorners[1];
    const float boxZ0 = boxCorners[2];
    const float boxX1 = boxCorners[3];
    const float boxY1 = boxCorners[4];
    const float boxZ1 = boxCorners[5];

    float* v0 = context.writeCursor;
    v0[0] = boxX0 + dx;
    v0[1] = boxY1 + dy;
    v0[2] = boxZ0 + dz;

    float* v1 = context.writeCursor + 3;
    v1[0] = boxX1 + dx;
    v1[1] = boxY1 + dy;
    v1[2] = boxZ0 + dz;

    float* v2 = context.writeCursor + 6;
    v2[0] = boxX1 + dx;
    v2[1] = boxY0 + dy;
    v2[2] = boxZ1 + dz;

    float* v3 = context.writeCursor + 9;
    v3[0] = boxX0 + dx;
    v3[1] = boxY0 + dy;
    v3[2] = boxZ1 + dz;

    context.writeCursor += 12;
    ++context.quadCount;
    return v3;
  }

  /**
   * Address: 0x0043C510 (FUN_0043C510, sub_43C510)
   *
   * IDA signature:
   * float *__usercall sub_43C510@<eax>(float *result@<eax>, int a2@<ecx>);
   *
   * What it does:
   * Copies four packed 3-float vertices (12 floats, 48 bytes) from
   * `packedQuad` into the active write cursor, advances the cursor
   * by 48 bytes, and bumps the running quad count.
   */
  const float* BeamDrawContextWritePackedQuad(
    BeamDrawContextRuntime& context,
    const float* const packedQuad)
  {
    for (std::size_t i = 0; i < 12; ++i) {
      context.writeCursor[i] = packedQuad[i];
    }
    context.writeCursor += 12;
    ++context.quadCount;
    return packedQuad;
  }

  namespace
  {
    [[nodiscard]] bool FlushBeamQuadDrawImpl(BeamDrawContextRuntime& context, const int quadCount)
    {
      if (context.writeCursor != nullptr) {
        ID3DVertexStream* const stream = FetchPrimaryVertexStream(context.sheet);
        stream->Unlock();
        context.writeCursor = nullptr;
      }

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = context.sheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = 0;
      vertexView.endVertex = (4 * quadCount) - 1;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = GetSharedTrailQuadIndexSheet();
      indexView.startIndex = 0;
      indexView.indexCount = 6 * quadCount;

      std::int32_t primitiveType = 4; // D3DPT_TRIANGLELIST
      CD3DDevice* const device = D3D_GetDevice();
      return device->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }
  } // namespace

  /**
   * Address: 0x0043C580 (FUN_0043C580, sub_43C580)
   *
   * IDA signature:
   * int __usercall sub_43C580@<eax>(_DWORD *a1@<eax>);
   *
   * What it does:
   * Ends any pending write session on the context (unlocking the
   * vertex stream when mapped) and submits one indexed triangle-list
   * draw covering `context.quadCount` quads through the shared
   * `sIndexSheet`.
   */
  bool BeamDrawContextFlushQuadDraw(BeamDrawContextRuntime& context)
  {
    return FlushBeamQuadDrawImpl(context, context.quadCount);
  }

  /**
   * Address: 0x0043C610 (FUN_0043C610, sub_43C610)
   *
   * IDA signature:
   * int __usercall sub_43C610@<eax>(int a1@<edi>, _DWORD *a2@<esi>);
   *
   * What it does:
   * Same as `BeamDrawContextFlushQuadDraw` but uses a caller-supplied
   * `quadCount` for the view bounds instead of the context's own
   * running count.
   */
  bool BeamDrawContextFlushQuadDrawWithCount(BeamDrawContextRuntime& context, const int quadCount)
  {
    return FlushBeamQuadDrawImpl(context, quadCount);
  }

  /**
   * Address: 0x0043C760 (FUN_0043C760, sub_43C760)
   *
   * IDA signature:
   * int (__thiscall ***__usercall sub_43C760@<eax>(int a1@<edi>))(_DWORD, int);
   *
   * What it does:
   * Fetches vertex format 3 from the device resources, ensures the
   * shared `sVertexStream` singleton is live (creating it via
   * `func_CreateSharedVertexStream` on first miss), then builds one
   * new vertex sheet from the `[nullptr, sVertexStream]` stream pair
   * and the fetched format through `ID3DDeviceResources::Func6`. The
   * new sheet replaces `context.sheet`; the previous sheet (when
   * different and non-null) is released through its deleting dtor.
   */
  CD3DVertexSheet* BeamDrawContextCreateVertexSheet(BeamDrawContextRuntime& context)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(3);

    if (SharedVertexStreamSlot() == nullptr) {
      func_CreateSharedVertexStream(vertexFormat);
    }

    CD3DVertexStream* streamArray[2]{nullptr, SharedVertexStreamSlot()};
    CD3DDevice* const device2 = D3D_GetDevice();
    ID3DDeviceResources* const resources2 = device2->GetResources();
    CD3DVertexSheet* const newSheet = resources2->Func6(
      1u,
      context.maxVertexCount,
      vertexFormat,
      streamArray);

    CD3DVertexSheet* const oldSheet = context.sheet;
    if (newSheet != oldSheet && oldSheet != nullptr) {
      delete oldSheet;
    }
    context.sheet = newSheet;
    return oldSheet;
  }

  /**
   * Address: 0x0043C360 (FUN_0043C360, sub_43C360)
   *
   * IDA signature:
   * void __usercall sub_43C360(int a1@<eax>, _DWORD *a2@<ecx>);
   *
   * What it does:
   * Lazy first-use initializer: when the context has no sheet, seeds
   * the quad-count / vertex-count / cursor lanes, builds the shared
   * vertex sheet, and primes the shared index sheet.
   */
  void BeamDrawContextInitialize(BeamDrawContextRuntime& context, const int quadCount)
  {
    if (context.sheet != nullptr) {
      return;
    }
    context.field_0x04 = quadCount;
    context.maxVertexCount = 4 * quadCount;
    context.writeCursor = nullptr;
    (void)BeamDrawContextCreateVertexSheet(context);
    func_InitSharedIndexSheet();
  }
} // namespace moho
