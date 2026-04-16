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
    storage->resize(static_cast<std::size_t>(count));

    for (auto& weak : *storage) {
      weak.ownerLinkSlot = nullptr;
      weak.nextInOwner = nullptr;
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
