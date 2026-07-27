#include "moho/unit/CUnitCommandWeakPtrReflection.h"

#include <cstdlib>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using WeakPtrType = moho::RWeakPtrType<moho::CUnitCommand>;
  using WeakPtrVector = msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>;
  using WeakPtrVectorType = gpg::RVectorType<moho::WeakPtr<moho::CUnitCommand>>;

  alignas(WeakPtrType) unsigned char gWeakPtrTypeStorage[sizeof(WeakPtrType)];
  bool gWeakPtrTypeConstructed = false;

  alignas(WeakPtrVectorType) unsigned char gWeakPtrVectorTypeStorage[sizeof(WeakPtrVectorType)];
  bool gWeakPtrVectorTypeConstructed = false;

  msvc8::string gWeakPtrTypeName;
  msvc8::string gWeakPtrVectorTypeName;
  bool gWeakPtrTypeNameCleanupRegistered = false;
  bool gWeakPtrVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] WeakPtrType* AcquireWeakPtrType()
  {
    if (!gWeakPtrTypeConstructed) {
      new (gWeakPtrTypeStorage) WeakPtrType();
      gWeakPtrTypeConstructed = true;
    }
    return reinterpret_cast<WeakPtrType*>(gWeakPtrTypeStorage);
  }

  [[nodiscard]] WeakPtrVectorType* AcquireWeakPtrVectorType()
  {
    if (!gWeakPtrVectorTypeConstructed) {
      new (gWeakPtrVectorTypeStorage) WeakPtrVectorType();
      gWeakPtrVectorTypeConstructed = true;
    }
    return reinterpret_cast<WeakPtrVectorType*>(gWeakPtrVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    gpg::RType* cached = moho::CUnitCommand::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCommand));
      moho::CUnitCommand::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrCUnitCommandType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      if (!cached) {
        cached = moho::register_WeakPtr_CUnitCommand_Type_00();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrVectorCUnitCommandType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>));
      if (!cached) {
        cached = moho::register_WeakPtr_CUnitCommand_VectorType_00();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCommandRef(moho::CUnitCommand* command)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedCUnitCommandType();
    if (!command) {
      return out;
    }

    gpg::RType* dynamicType = CachedCUnitCommandType();
    try {
      dynamicType = gpg::LookupRType(typeid(*command));
    } catch (...) {
      dynamicType = CachedCUnitCommandType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && CachedCUnitCommandType() != nullptr &&
      dynamicType->IsDerivedFrom(CachedCUnitCommandType(), &baseOffset);

    out.mObj = isDerived
      ? reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(command) - static_cast<std::uintptr_t>(baseOffset))
      : static_cast<void*>(command);
    out.mType = dynamicType ? dynamicType : CachedCUnitCommandType();
    return out;
  }

  [[nodiscard]] gpg::RRef MakeWeakPtrCUnitCommandRef(moho::WeakPtr<moho::CUnitCommand>* value)
  {
    gpg::RRef out{};
    out.mObj = value;
    out.mType = CachedWeakPtrCUnitCommandType();
    return out;
  }

  /**
    * Alias of FUN_005F5100 (non-canonical helper lane).
   */
  [[nodiscard]] moho::CUnitCommand* ReadPointerCUnitCommand(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandType());
    if (upcast.mObj) {
      return static_cast<moho::CUnitCommand*>(upcast.mObj);
    }

    const char* const expected = CachedCUnitCommandType() ? CachedCUnitCommandType()->GetName() : "CUnitCommand";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "CUnitCommand",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  /**
   * Address: 0x00BFECA0 (FUN_00BFECA0, sub_BFECA0)
   */
  void cleanup_WeakPtrCUnitCommandTypeName()
  {
    gWeakPtrTypeName = msvc8::string{};
    gWeakPtrTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BFEC70 (FUN_00BFEC70, sub_BFEC70)
   */
  void cleanup_WeakPtrCUnitCommandVectorTypeName()
  {
    gWeakPtrVectorTypeName = msvc8::string{};
    gWeakPtrVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BFEDC0 (FUN_00BFEDC0, sub_BFEDC0)
   */
  void cleanup_WeakPtr_CUnitCommand_Type()
  {
    if (!gWeakPtrTypeConstructed) {
      return;
    }

    AcquireWeakPtrType()->~WeakPtrType();
    gWeakPtrTypeConstructed = false;
  }

  /**
   * Address: 0x00BFED60 (FUN_00BFED60, sub_BFED60)
   */
  void cleanup_WeakPtr_CUnitCommand_VectorType()
  {
    if (!gWeakPtrVectorTypeConstructed) {
      return;
    }

    AcquireWeakPtrVectorType()->~WeakPtrVectorType();
    gWeakPtrVectorTypeConstructed = false;
  }

  /**
   * Address: 0x006EA8F0 (FUN_006EA8F0, sub_6EA8F0)
   */
  void LoadWeakPtrCUnitCommandVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<WeakPtrVector*>(objectPtr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    for (auto& weak : *storage) {
      weak.ResetFromObject(nullptr);
    }
    storage->clear();

    // The binary grows the destination with reserve(count)
    // (FUN_006EB1D0, msvc8::vector<WeakPtr<CUnitCommand>>::reserve) then fills
    // each slot with an empty weak link; not resize(), which routes through
    // reallocate_to. Prior contents are explicitly unregistered above (the
    // WeakPtr<T> primary-template dtor is trivial and does not unlink on its
    // own), so the in-place reserve + placement-fill is safe.
    const std::size_t targetCount = static_cast<std::size_t>(count);
    if (targetCount > 0u) {
      storage->reserve(targetCount);
      auto& view = msvc8::AsVectorRuntimeView(*storage);
      auto* const slotsBegin = view.end;
      for (std::size_t i = 0u; i < targetCount; ++i) {
        auto* const slot =
          ::new (static_cast<void*>(slotsBegin + i)) moho::WeakPtr<moho::CUnitCommand>();
        slot->ownerLinkSlot = nullptr;
        slot->nextInOwner = nullptr;
      }
      view.end = slotsBegin + targetCount;
    }

    gpg::RType* const weakType = CachedWeakPtrCUnitCommandType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(weakType, &(*storage)[i], owner);
    }
  }

  /**
   * Address: 0x006EAA40 (FUN_006EAA40, sub_6EAA40)
   */
  void SaveWeakPtrCUnitCommandVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<const WeakPtrVector*>(objectPtr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    gpg::RType* const weakType = CachedWeakPtrCUnitCommandType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(weakType, &(*storage)[i], owner);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005A2220 (FUN_005A2220, Moho::WeakPtr_CUnitCommand::move_range)
   *
   * What it does:
   * Rebinds one half-open weak-pointer range onto destination storage by
   * unlinking each destination node from its old owner chain and relinking it
   * to the source owner chain head.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* MoveWeakPtrCUnitCommandRangeAndReturnEnd(
    WeakPtr<CUnitCommand>* destination,
    WeakPtr<CUnitCommand>* sourceBegin,
    WeakPtr<CUnitCommand>* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      WeakPtr<CUnitCommand>& destinationNode = *destination;
      const WeakPtr<CUnitCommand>& sourceNode = *sourceBegin;

      if (destinationNode.ownerLinkSlot != sourceNode.ownerLinkSlot) {
        if (destinationNode.ownerLinkSlot != nullptr) {
          auto** link = reinterpret_cast<WeakPtr<CUnitCommand>**>(destinationNode.ownerLinkSlot);
          while (*link != &destinationNode) {
            link = &(*link)->nextInOwner;
          }
          *link = destinationNode.nextInOwner;
        }

        destinationNode.ownerLinkSlot = sourceNode.ownerLinkSlot;
        if (sourceNode.ownerLinkSlot == nullptr) {
          destinationNode.nextInOwner = nullptr;
        } else {
          auto** const sourceHead = reinterpret_cast<WeakPtr<CUnitCommand>**>(sourceNode.ownerLinkSlot);
          destinationNode.nextInOwner = *sourceHead;
          *sourceHead = &destinationNode;
        }
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x005A1D00 (FUN_005A1D00, Moho::WeakPtr_CUnitCommand::move_range_0)
   *
   * What it does:
   * Adapts the end-first argument order used by one vector-move lane and
   * forwards to `move_range` with canonical destination-first ordering.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* MoveWeakPtrCUnitCommandRangeAdapter(
    WeakPtr<CUnitCommand>* sourceEnd,
    WeakPtr<CUnitCommand>* sourceBegin,
    WeakPtr<CUnitCommand>* destination
  )
  {
    return MoveWeakPtrCUnitCommandRangeAndReturnEnd(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005FF400 (FUN_005FF400, Moho::WeakPtr_CUnitCommand::cpy_range)
   *
   * What it does:
   * Copies one half-open weak-pointer range, rebinding each destination node to
   * the source owner slot and relinking live nodes at the owner-chain head.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* CopyWeakPtrCUnitCommandRangeAndReturnEnd(
    WeakPtr<CUnitCommand>* destination,
    const WeakPtr<CUnitCommand>* sourceBegin,
    const WeakPtr<CUnitCommand>* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      WeakPtr<CUnitCommand>* const destNode = destination;
      const WeakPtr<CUnitCommand>& sourceNode = *sourceBegin;

      if (destNode != nullptr) {
        destNode->ownerLinkSlot = sourceNode.ownerLinkSlot;
        if (sourceNode.ownerLinkSlot != nullptr) {
          auto** const ownerHead = reinterpret_cast<WeakPtr<CUnitCommand>**>(sourceNode.ownerLinkSlot);
          destNode->nextInOwner = *ownerHead;
          *ownerHead = destNode;
        } else {
          destNode->nextInOwner = nullptr;
        }
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x005FD580 (FUN_005FD580, Moho::WeakPtr_CUnitCommand::cpy_range_0)
   * Address: 0x006EB7F0 (FUN_006EB7F0)
   * Address: 0x006EC500 (FUN_006EC500)
   * Address: 0x006ED0D0 (FUN_006ED0D0)
   *
   * What it does:
   * Adapts the source-first operand order from one VC8 vector-copy lane and
   * forwards into canonical `cpy_range(destination, begin, end)` ordering.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* CopyWeakPtrCUnitCommandRangeAdapter(
    const WeakPtr<CUnitCommand>* sourceBegin,
    const WeakPtr<CUnitCommand>* sourceEnd,
    WeakPtr<CUnitCommand>* destination
  )
  {
    return CopyWeakPtrCUnitCommandRangeAndReturnEnd(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005A2270 (FUN_005A2270, Moho::WeakPtr_CUnitCommand::destruct_range)
   *
   * What it does:
   * Walks one contiguous weak-pointer range and detaches each node from its
   * owner chain by rewriting predecessor links to skip the node.
   */
  void DetachWeakPtrCUnitCommandRange(WeakPtr<CUnitCommand>* begin, WeakPtr<CUnitCommand>* end)
  {
    while (begin != end) {
      WeakPtr<CUnitCommand>& weak = *begin;
      if (weak.ownerLinkSlot != nullptr && !WeakPtr<CUnitCommand>::IsSentinelSlot(weak.ownerLinkSlot)) {
        auto** link = reinterpret_cast<WeakPtr<CUnitCommand>**>(weak.ownerLinkSlot);
        while (*link != nullptr && *link != &weak) {
          link = &(*link)->nextInOwner;
        }

        if (*link == &weak) {
          *link = weak.nextInOwner;
        }
      }

      weak.ownerLinkSlot = nullptr;
      weak.nextInOwner = nullptr;
      ++begin;
    }
  }

  /**
   * Address: 0x005DB610 (FUN_005DB610, std::vector_WeakPtr_CUnitCommand::cpy)
   *
   * What it does:
   * Copies one legacy `vector<WeakPtr<CUnitCommand>>` payload into destination
   * storage using the VC8 vector copy semantics.
   */
  [[nodiscard]] msvc8::vector<WeakPtr<CUnitCommand>>* CopyWeakPtrCUnitCommandVector(
    const msvc8::vector<WeakPtr<CUnitCommand>>& source,
    msvc8::vector<WeakPtr<CUnitCommand>>& destination
  )
  {
    const std::size_t sourceSize = source.size();
    if (sourceSize > 0x1FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    if (&source == &destination) {
      return &destination;
    }

    if (!destination.empty()) {
      auto& view = msvc8::AsVectorRuntimeView(destination);
      if (view.begin && view.end) {
        DetachWeakPtrCUnitCommandRange(view.begin, view.end);
      }
    }

    destination.resize(sourceSize);
    if (sourceSize != 0u) {
      auto& destinationView = msvc8::AsVectorRuntimeView(destination);
      const auto& sourceView = msvc8::AsVectorRuntimeView(source);
      (void)CopyWeakPtrCUnitCommandRangeAndReturnEnd(destinationView.begin, sourceView.begin, sourceView.end);
    }

    return &destination;
  }

  /**
   * Address: 0x005A07A0 (FUN_005A07A0, std::vector_WeakPtr_CUnitCommand::reset_storage)
   *
   * What it does:
   * Destroys one `vector<WeakPtr<CUnitCommand>>` payload, releases the backing
   * heap block, and clears the vector storage lanes to empty.
   */
  void ResetWeakPtrCUnitCommandVectorStorage(WeakPtrVector& storage)
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin != nullptr) {
      DetachWeakPtrCUnitCommandRange(view.begin, view.end);
      ::operator delete(view.begin);
    }

    view.begin = nullptr;
    view.end = nullptr;
    view.capacityEnd = nullptr;
  }

  namespace
  {
    // VC8 `vector<WeakPtr<CUnitCommand>>` enforces `_Myend - _Myfirst <=
    // 0x1FFFFFFF` (max element count for an 8-byte element type). The binary
    // throws `std::length_error("vector<T> too long")` (FUN_005A0DD0) when an
    // insert would exceed it.
    constexpr std::uint32_t kWeakPtrVectorMaxCount = 0x1FFFFFFFu;

    [[noreturn]] void ThrowWeakPtrVectorTooLong()
    {
      throw std::length_error("vector<T> too long");
    }

    [[nodiscard]] std::uint32_t WeakPtrVectorSize(const msvc8::vector_runtime_view<WeakPtr<CUnitCommand>>& view) noexcept
    {
      return view.begin ? static_cast<std::uint32_t>(view.end - view.begin) : 0u;
    }

    [[nodiscard]] std::uint32_t
    WeakPtrVectorCapacity(const msvc8::vector_runtime_view<WeakPtr<CUnitCommand>>& view) noexcept
    {
      return view.begin ? static_cast<std::uint32_t>(view.capacityEnd - view.begin) : 0u;
    }
  } // namespace

  /**
   * Address: 0x006EC5B0 (FUN_006EC5B0)
   * Address: 0x007A5FE0 (FUN_007A5FE0, ICF twin)
   *
   * What it does:
   * Fill-constructs `count` weak lanes from one source node, relinking each
   * filled lane at the source owner-chain head. Typed twin of the ICF-folded
   * generic single-owner-slot fill lane at FUN_006EC5B0 / FUN_007A5FE0.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* FillConstructWeakPtrCUnitCommandLanes(
    WeakPtr<CUnitCommand>* destination,
    std::int32_t count,
    const WeakPtr<CUnitCommand>& source
  ) noexcept
  {
    for (; count != 0; --count, ++destination) {
      if (destination == nullptr) {
        continue;
      }

      void* const ownerLinkSlot = source.ownerLinkSlot;
      destination->ownerLinkSlot = ownerLinkSlot;
      if (ownerLinkSlot == nullptr) {
        destination->nextInOwner = nullptr;
      } else {
        auto** const ownerHead = reinterpret_cast<WeakPtr<CUnitCommand>**>(ownerLinkSlot);
        destination->nextInOwner = *ownerHead;
        *ownerHead = destination;
      }
    }

    return destination;
  }

  namespace
  {
    /**
     * Address: 0x006EC520 (FUN_006EC520)
     *
     * Assign-fills `[destination, end)` from one source node, unlinking each
     * destination lane from its current owner chain (when it differs) and
     * relinking it to the source owner-chain head. Unlike the construct fill
     * (`FillConstructWeakPtrCUnitCommandLanes`), the destination lanes are
     * already live, so the old link is removed first.
     */
    WeakPtr<CUnitCommand>* AssignFillWeakPtrCUnitCommandLanes(
      WeakPtr<CUnitCommand>* destination,
      const WeakPtr<CUnitCommand>& source,
      WeakPtr<CUnitCommand>* const end
    ) noexcept
    {
      const WeakPtr<void>& src = reinterpret_cast<const WeakPtr<void>&>(source);
      for (; destination != end; ++destination) {
        AssignWeakPtrLaneWithRelink(reinterpret_cast<WeakPtr<void>&>(*destination), src);
      }
      return destination;
    }

    /**
     * Address: 0x006EB820 (FUN_006EB820) -> 0x006ED0F0 (FUN_006ED0F0)
     *
     * Range backward assign-with-relink: copy-assigns `[sourceBegin,
     * sourceEnd)` into the storage ending at `destinationEnd`, walking back to
     * front so a right-shift over overlapping storage is safe.
     */
    WeakPtr<CUnitCommand>* AssignWeakPtrCUnitCommandRangeBackward(
      WeakPtr<CUnitCommand>* destinationEnd,
      const WeakPtr<CUnitCommand>* sourceBegin,
      const WeakPtr<CUnitCommand>* sourceEnd
    ) noexcept
    {
      auto* const out = AssignWeakPtrRangeBackward(
        reinterpret_cast<WeakPtr<void>*>(destinationEnd),
        reinterpret_cast<const WeakPtr<void>*>(sourceBegin),
        reinterpret_cast<const WeakPtr<void>*>(sourceEnd));
      return reinterpret_cast<WeakPtr<CUnitCommand>*>(out);
    }
  } // namespace

  /**
   * Address: 0x006EA440 (FUN_006EA440, std::vector_WeakPtr_CUnitCommand::_Insert_n)
   *
   * What it does:
   * MSVC8 `vector<WeakPtr<CUnitCommand>>::_Insert_n` reserve/grow lane. The
   * incoming `value` is the staged source weak node; the binary materializes a
   * by-value copy of it (relinked at the owner-chain head) and fills the
   * inserted run from that copy so the new lanes share the same owner chain.
   * The copy's chain link is restored when the lane goes out of scope.
   *
   * IDA struct field mapping (the IDA names are swapped):
   *   begin       = a1->_M_finish        (_Myfirst)
   *   end (size)  = a1->_M_end_of_storage (_Mylast)
   *   capacityEnd = a1[1]._M_start        (_Myend)
   */
  void GrowAndFillWeakPtrCUnitCommandVector(
    msvc8::vector<WeakPtr<CUnitCommand>>& storage,
    WeakPtr<CUnitCommand>* const insertPosition,
    const std::uint32_t count,
    const WeakPtr<CUnitCommand>& value
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);

    // Materialize the by-value `WeakPtr` parameter: copy `value`'s owner-link
    // slot and splice the local copy in at the owner-chain head so the fill
    // lanes relink against a stable node. The owner head is restored at the
    // end (the by-value copy's destructor).
    WeakPtr<CUnitCommand> stagedValue{};
    void* const stagedOwnerSlot = value.ownerLinkSlot;
    stagedValue.ownerLinkSlot = stagedOwnerSlot;
    WeakPtr<CUnitCommand>* savedNext = nullptr;
    if (stagedOwnerSlot != nullptr) {
      auto** const ownerHead = reinterpret_cast<WeakPtr<CUnitCommand>**>(stagedOwnerSlot);
      savedNext = *ownerHead;
      stagedValue.nextInOwner = savedNext;
      *ownerHead = &stagedValue;
    } else {
      stagedValue.nextInOwner = nullptr;
    }

    if (count != 0u) {
      const std::uint32_t capacity = WeakPtrVectorCapacity(view);
      const std::uint32_t size = WeakPtrVectorSize(view);

      if ((kWeakPtrVectorMaxCount - size) < count) {
        // Restore the staged copy's owner chain before propagating the throw.
        if (stagedOwnerSlot != nullptr) {
          *reinterpret_cast<WeakPtr<CUnitCommand>**>(stagedOwnerSlot) = savedNext;
        }
        ThrowWeakPtrVectorTooLong();
      }

      const std::uint32_t requiredSize = count + size;

      if (capacity >= requiredSize) {
        // In-place arm: enough capacity, tail-shift then fill the seam.
        WeakPtr<CUnitCommand>* const oldEnd = view.end;
        const std::uint32_t tailCount = static_cast<std::uint32_t>(oldEnd - insertPosition);

        if (tailCount >= count) {
          // Tail is at least `count`: append a copy of the trailing run,
          // back-shift the middle, then fill the seam with the staged value.
          (void)CopyWeakPtrCUnitCommandRangeAndReturnEnd(oldEnd, oldEnd - count, oldEnd);
          view.end = oldEnd + count;
          (void)AssignWeakPtrCUnitCommandRangeBackward(oldEnd, insertPosition, oldEnd - count);
          (void)AssignFillWeakPtrCUnitCommandLanes(insertPosition, stagedValue, insertPosition + count);
        } else {
          // Tail shorter than insert run: copy the tail past the gap, fill the
          // gap with the staged value, bump end, then assign-fill the seam.
          (void)CopyWeakPtrCUnitCommandRangeAndReturnEnd(insertPosition + count, insertPosition, oldEnd);
          (void)FillConstructWeakPtrCUnitCommandLanes(
            oldEnd, static_cast<std::int32_t>(count - tailCount), stagedValue);
          view.end = oldEnd + count;
          (void)AssignFillWeakPtrCUnitCommandLanes(insertPosition, stagedValue, oldEnd);
        }
      } else {
        // Reallocate arm: geometric growth = max(capacity * 1.5, required).
        std::uint32_t newCapacity = 0u;
        const std::uint32_t halfCapacity = capacity >> 1;
        if ((kWeakPtrVectorMaxCount - halfCapacity) >= capacity) {
          newCapacity = halfCapacity + capacity;
        }
        if (newCapacity < requiredSize) {
          newCapacity = requiredSize;
        }

        WeakPtr<CUnitCommand>* newBuffer = nullptr;
        if (newCapacity != 0u) {
          newBuffer = static_cast<WeakPtr<CUnitCommand>*>(
            ::operator new(static_cast<std::size_t>(newCapacity) * sizeof(WeakPtr<CUnitCommand>)));
        } else {
          newBuffer = static_cast<WeakPtr<CUnitCommand>*>(::operator new(0u));
        }

        // Copy prefix [begin, insertPos), fill the inserted run, copy suffix
        // [insertPos, end), then detach + release the old buffer.
        WeakPtr<CUnitCommand>* const afterPrefix =
          CopyWeakPtrCUnitCommandRangeAndReturnEnd(newBuffer, view.begin, insertPosition);
        (void)FillConstructWeakPtrCUnitCommandLanes(
          afterPrefix, static_cast<std::int32_t>(count), stagedValue);
        WeakPtr<CUnitCommand>* const afterRun = afterPrefix + count;
        (void)CopyWeakPtrCUnitCommandRangeAndReturnEnd(afterRun, insertPosition, view.end);

        const std::uint32_t finalSize = size + count;
        if (view.begin != nullptr) {
          DetachWeakPtrCUnitCommandRange(view.begin, view.end);
          ::operator delete(view.begin);
        }

        view.capacityEnd = newBuffer + newCapacity;
        view.end = newBuffer + finalSize;
        view.begin = newBuffer;
      }
    }

    // By-value copy destructor: unlink `stagedValue` and restore the head.
    if (stagedValue.ownerLinkSlot != nullptr) {
      auto** cursor = reinterpret_cast<WeakPtr<CUnitCommand>**>(stagedValue.ownerLinkSlot);
      while (*cursor != &stagedValue) {
        cursor = &(*cursor)->nextInOwner;
      }
      *cursor = stagedValue.nextInOwner;
    }
  }

  /**
   * Address: 0x006E9680 (FUN_006E9680, std::vector_WeakPtr_CUnitCommand::push_back)
   *
   * What it does:
   * `push_back(const WeakPtr<CUnitCommand>&)`: grow when at capacity, else
   * fill-construct one lane at the end cursor and bump it.
   */
  void PushBackWeakPtrCUnitCommand(
    msvc8::vector<WeakPtr<CUnitCommand>>& storage,
    const WeakPtr<CUnitCommand>& value
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);

    const std::uint32_t size = WeakPtrVectorSize(view);
    const std::uint32_t capacity = WeakPtrVectorCapacity(view);

    if (view.begin == nullptr || size >= capacity) {
      GrowAndFillWeakPtrCUnitCommandVector(storage, view.end, 1u, value);
      return;
    }

    WeakPtr<CUnitCommand>* const end = view.end;
    (void)FillConstructWeakPtrCUnitCommandLanes(end, 1, value);
    view.end = end + 1;
  }
} // namespace moho

namespace moho
{
  /**
   * Address: 0x006E9890 (FUN_006E9890, Moho::RWeakPtrType_CUnitCommand::GetName)
   */
  const char* RWeakPtrType<CUnitCommand>::GetName() const
  {
    if (gWeakPtrTypeName.empty()) {
      const char* const pointeeName = CachedCUnitCommandType() ? CachedCUnitCommandType()->GetName() : "CUnitCommand";
      gWeakPtrTypeName = gpg::STR_Printf("WeakPtr<%s>", pointeeName ? pointeeName : "CUnitCommand");
      if (!gWeakPtrTypeNameCleanupRegistered) {
        gWeakPtrTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrCUnitCommandTypeName);
      }
    }

    return gWeakPtrTypeName.c_str();
  }

  /**
   * Address: 0x006E9930 (FUN_006E9930, Moho::RWeakPtrType_CUnitCommand::Init)
   */
  void RWeakPtrType<CUnitCommand>::Init()
  {
    size_ = sizeof(WeakPtr<CUnitCommand>);
    version_ = 1;
    serLoadFunc_ = &WeakPtr_CUnitCommand::Deserialize;
    serSaveFunc_ = &WeakPtr_CUnitCommand::Serialize;
  }

  /**
   * Address: 0x006E9950 (FUN_006E9950, Moho::RWeakPtrType_CUnitCommand::GetLexical)
   */
  msvc8::string RWeakPtrType<CUnitCommand>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const weak = static_cast<const WeakPtr<CUnitCommand>*>(ref.mObj);
    if (!weak || !weak->HasValue()) {
      return msvc8::string("NULL");
    }

    const gpg::RRef pointeeRef = MakeCUnitCommandRef(weak->GetObjectPtr());
    if (!pointeeRef.mObj) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x006E9AE0 (FUN_006E9AE0, Moho::RWeakPtrType_CUnitCommand::IsIndexed)
   */
  const gpg::RIndexed* RWeakPtrType<CUnitCommand>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x006E9AF0 (FUN_006E9AF0, Moho::RWeakPtrType_CUnitCommand::IsPointer)
   */
  const gpg::RIndexed* RWeakPtrType<CUnitCommand>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x006E9B00 (FUN_006E9B00, Moho::RWeakPtrType_CUnitCommand::GetCount)
   */
  size_t RWeakPtrType<CUnitCommand>::GetCount(void* obj) const
  {
    auto* const weak = static_cast<WeakPtr<CUnitCommand>*>(obj);
    return (weak && weak->HasValue()) ? 1u : 0u;
  }

  /**
   * Address: 0x006E9B30 (FUN_006E9B30, Moho::RWeakPtrType_CUnitCommand::SubscriptIndex)
   */
  gpg::RRef RWeakPtrType<CUnitCommand>::SubscriptIndex(void* obj, int ind) const
  {
    GPG_ASSERT(ind == 0);

    auto* const weak = static_cast<WeakPtr<CUnitCommand>*>(obj);
    return MakeCUnitCommandRef(weak ? weak->GetObjectPtr() : nullptr);
  }

  /**
   * Address: 0x006EA880 (FUN_006EA880, Moho::RWeakPtrType_CUnitCommand::SerLoad)
   */
  void WeakPtr_CUnitCommand::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<CUnitCommand>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    weak->ResetFromObject(ReadPointerCUnitCommand(archive, owner));
  }

  /**
   * Address: 0x006EA8B0 (FUN_006EA8B0, Moho::RWeakPtrType_CUnitCommand::SerSave)
   */
  void WeakPtr_CUnitCommand::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<CUnitCommand>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef objectRef = MakeCUnitCommandRef(weak->GetObjectPtr());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
  }

  /**
   * Address: 0x006EBE50 (FUN_006EBE50, sub_6EBE50)
   */
  gpg::RType* register_WeakPtr_CUnitCommand_Type_00()
  {
    WeakPtrType* const type = AcquireWeakPtrType();
    gpg::PreRegisterRType(typeid(WeakPtr<CUnitCommand>), type);
    return type;
  }

  /**
   * Address: 0x00BD8FF0 (FUN_00BD8FF0, sub_BD8FF0)
   */
  int register_WeakPtr_CUnitCommand_Type_AtExit()
  {
    (void)register_WeakPtr_CUnitCommand_Type_00();
    return std::atexit(&cleanup_WeakPtr_CUnitCommand_Type);
  }

  /**
   * Address: 0x006EBEC0 (FUN_006EBEC0, sub_6EBEC0)
   */
  gpg::RType* register_WeakPtr_CUnitCommand_VectorType_00()
  {
    WeakPtrVectorType* const type = AcquireWeakPtrVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<WeakPtr<CUnitCommand>>), type);
    return type;
  }

  /**
   * Address: 0x00BD9010 (FUN_00BD9010, sub_BD9010)
   */
  int register_WeakPtr_CUnitCommand_VectorType_AtExit()
  {
    (void)register_WeakPtr_CUnitCommand_VectorType_00();
    return std::atexit(&cleanup_WeakPtr_CUnitCommand_VectorType);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006E9B90 (FUN_006E9B90, gpg::RVectorType_WeakPtr_CUnitCommand::GetName)
   */
  const char* RVectorType<moho::WeakPtr<moho::CUnitCommand>>::GetName() const
  {
    if (gWeakPtrVectorTypeName.empty()) {
      const gpg::RType* const elementType = CachedWeakPtrCUnitCommandType();
      const char* const elementName = elementType ? elementType->GetName() : "WeakPtr<CUnitCommand>";
      gWeakPtrVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "WeakPtr<CUnitCommand>");
      if (!gWeakPtrVectorTypeNameCleanupRegistered) {
        gWeakPtrVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrCUnitCommandVectorTypeName);
      }
    }

    return gWeakPtrVectorTypeName.c_str();
  }

  /**
   * Address: 0x006E9C30 (FUN_006E9C30, gpg::RVectorType_WeakPtr_CUnitCommand::Init)
   */
  void RVectorType<moho::WeakPtr<moho::CUnitCommand>>::Init()
  {
    size_ = sizeof(WeakPtrVector);
    version_ = 1;
    serLoadFunc_ = &LoadWeakPtrCUnitCommandVector;
    serSaveFunc_ = &SaveWeakPtrCUnitCommandVector;
  }

  /**
   * Address: 0x006E9C50 (FUN_006E9C50, gpg::RVectorType_WeakPtr_CUnitCommand::GetLexical)
   */
  msvc8::string RVectorType<moho::WeakPtr<moho::CUnitCommand>>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x006E9CE0 (FUN_006E9CE0, gpg::RVectorType_WeakPtr_CUnitCommand::IsIndexed)
   */
  const gpg::RIndexed* RVectorType<moho::WeakPtr<moho::CUnitCommand>>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x006E9CF0 (FUN_006E9CF0, gpg::RVectorType_WeakPtr_CUnitCommand::GetCount)
   */
  size_t RVectorType<moho::WeakPtr<moho::CUnitCommand>>::GetCount(void* obj) const
  {
    const auto* const storage = static_cast<const WeakPtrVector*>(obj);
    return storage ? storage->size() : 0u;
  }

  /**
   * Address: 0x006E9D10 (FUN_006E9D10, gpg::RVectorType_WeakPtr_CUnitCommand::SetCount)
   */
  void RVectorType<moho::WeakPtr<moho::CUnitCommand>>::SetCount(void* obj, int count) const
  {
    auto* const storage = static_cast<WeakPtrVector*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(count >= 0);
    if (!storage || count < 0) {
      return;
    }

    const std::size_t requested = static_cast<std::size_t>(count);
    if (requested < storage->size()) {
      auto& view = msvc8::AsVectorRuntimeView(*storage);
      if (view.begin && view.end) {
        moho::DetachWeakPtrCUnitCommandRange(view.begin + requested, view.end);
      }
    }

    storage->resize(requested);
  }

  /**
   * Address: 0x006E9D40 (FUN_006E9D40, gpg::RVectorType_WeakPtr_CUnitCommand::SubscriptIndex)
   */
  gpg::RRef RVectorType<moho::WeakPtr<moho::CUnitCommand>>::SubscriptIndex(void* obj, int ind) const
  {
    auto* const storage = static_cast<WeakPtrVector*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(ind >= 0);
    GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

    if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
      return MakeWeakPtrCUnitCommandRef(nullptr);
    }

    return MakeWeakPtrCUnitCommandRef(&(*storage)[static_cast<std::size_t>(ind)]);
  }
} // namespace gpg

namespace
{
  struct CUnitCommandWeakPtrReflectionBootstrap
  {
    CUnitCommandWeakPtrReflectionBootstrap()
    {
      (void)moho::register_Broadcaster_ECommandEvent_RType_AtExit();
      (void)moho::register_WeakPtr_CUnitCommand_Type_AtExit();
      (void)moho::register_WeakPtr_CUnitCommand_VectorType_AtExit();
    }
  };

  CUnitCommandWeakPtrReflectionBootstrap gCUnitCommandWeakPtrReflectionBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_WeakPtr_CUnitCommand_Type_00_c8c64f, moho::register_WeakPtr_CUnitCommand_Type_00)
GPG_PREREGISTER_INIT(register_WeakPtr_CUnitCommand_VectorType_00_c8c64f, moho::register_WeakPtr_CUnitCommand_VectorType_00)
