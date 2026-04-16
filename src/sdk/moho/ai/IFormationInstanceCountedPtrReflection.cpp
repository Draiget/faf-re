#include "moho/ai/IFormationInstanceCountedPtrReflection.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/unit/Broadcaster.h"

namespace
{
  using CountedPtrType = moho::RCountedPtrType<moho::IFormationInstance>;
  msvc8::string gCountedPtrTypeName;
  bool gCountedPtrTypeNameCleanupRegistered = false;
  constexpr std::uint32_t kTypeCacheInitMask = 0x1u;
  constexpr std::int32_t kIsDerivedAssertLine = 458;
  constexpr const char* kIsDerivedAssertExpr = "isDer";
  constexpr const char* kReflectionHeaderPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflection.h";

  struct RTypeCacheEntry
  {
    const std::type_info* mTypeInfo;
    gpg::RType* mType;
  };

  struct IFormationInstanceTypeCache
  {
    std::uint32_t mGuard;
    RTypeCacheEntry mEntries[3];
  };

  thread_local IFormationInstanceTypeCache gIFormationInstanceTypeCache{};

  template <class T>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    return CachedRType<moho::IFormationInstance>();
  }

  struct IFormationInstanceSerializationRuntimeView
  {
    std::uint8_t reserved00_03[0x4];
    std::uint32_t mBaseRuntimeWord;
    moho::BroadcasterEventTag<moho::EFormationdStatus> broadcaster;
  };

  static_assert(
    offsetof(IFormationInstanceSerializationRuntimeView, mBaseRuntimeWord) == 0x4,
    "IFormationInstanceSerializationRuntimeView::mBaseRuntimeWord offset must be 0x4"
  );
  static_assert(
    offsetof(IFormationInstanceSerializationRuntimeView, broadcaster) == 0x8,
    "IFormationInstanceSerializationRuntimeView::broadcaster offset must be 0x8"
  );

  [[nodiscard]] gpg::RType* CachedBroadcasterEFormationdStatusType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::BroadcasterEventTag<moho::EFormationdStatus>));
    }
    return cached;
  }

  /**
   * Address: 0x00570F10 (FUN_00570F10)
   *
   * What it does:
   * Resolves `IFormationInstance::sType` on demand and appends it as a base
   * field at offset `0` for one owner runtime type.
   */
  [[maybe_unused]] void AddIFormationInstanceBaseField(gpg::RType* const ownerType)
  {
    if (ownerType == nullptr) {
      return;
    }

    gpg::RType* baseType = moho::IFormationInstance::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::IFormationInstance));
      moho::IFormationInstance::sType = baseType;
    }

    if (baseType == nullptr) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    ownerType->AddBase(baseField);
  }

  void EnsureIFormationInstanceTypeCacheInitialized(IFormationInstanceTypeCache& cache)
  {
    if ((cache.mGuard & kTypeCacheInitMask) != 0u) {
      return;
    }

    cache.mGuard |= kTypeCacheInitMask;
    for (RTypeCacheEntry& entry : cache.mEntries) {
      entry.mTypeInfo = nullptr;
      entry.mType = nullptr;
    }
  }

  [[nodiscard]] bool TypeInfosMatch(const std::type_info* const lhs, const std::type_info* const rhs)
  {
    return lhs == rhs || (lhs != nullptr && rhs != nullptr && (*lhs == *rhs));
  }

  [[nodiscard]] moho::IFormationInstance* const* AsSlot(void* obj) noexcept
  {
    return reinterpret_cast<moho::IFormationInstance**>(obj);
  }

  template <class TObject>
  [[nodiscard]] moho::IntrusiveRefCountView<TObject>& RefCountView(TObject* object) noexcept
  {
    return *reinterpret_cast<moho::IntrusiveRefCountView<TObject>*>(object);
  }

  [[nodiscard]] gpg::RRef MakeIFormationInstanceRef(moho::IFormationInstance* value)
  {
    gpg::RRef out{};
    gpg::RRef_IFormationInstance(&out, value);
    return out;
  }

  [[nodiscard]] moho::IFormationInstance* ReadPointerWeakIFormationInstance(
    gpg::ReadArchive* archive,
    const gpg::RRef& ownerRef
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RType* const expectedType = CachedIFormationInstanceType();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<moho::IFormationInstance*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "IFormationInstance";
    const char* const actual = tracked.type ? tracked.type->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected,
      actual
    );
    throw gpg::SerializationError(message.c_str());
  }

  alignas(CountedPtrType) unsigned char gCountedPtrTypeStorage[sizeof(CountedPtrType)];
  bool gCountedPtrTypeConstructed = false;

  [[nodiscard]] CountedPtrType& GetCountedPtrType() noexcept
  {
    if (!gCountedPtrTypeConstructed) {
      new (gCountedPtrTypeStorage) CountedPtrType();
      gCountedPtrTypeConstructed = true;
    }

    return *reinterpret_cast<CountedPtrType*>(gCountedPtrTypeStorage);
  }

  template <class TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BFED00 (FUN_00BFED00, Moho::RCountedPtrType<Moho::IFormationInstance>::cleanup)
   *
   * What it does:
   * Releases reflected field/base vector storage and restores the base `RObject`
   * vtable lane.
   */
  void cleanup_RCountedPtrType_IFormationInstance()
  {
    if (!gCountedPtrTypeConstructed) {
      return;
    }

    ResetTypeInfoVectors(GetCountedPtrType());
    GetCountedPtrType().~CountedPtrType();
    gCountedPtrTypeConstructed = false;
  }

  /**
   * Address: 0x00BFEC40 (FUN_00BFEC40, Moho::RCountedPtrType<Moho::IFormationInstance>::cleanup name cache)
   *
   * What it does:
   * Releases the cached `CountedPtr<...>` display name string.
   */
  void cleanup_RCountedPtrType_IFormationInstance_Name()
  {
    gCountedPtrTypeName = msvc8::string();
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x0059E640 (FUN_0059E640, gpg::RRef_IFormationInstance)
   *
   * What it does:
   * Builds a reflected reference for `IFormationInstance*` and normalizes the
   * object pointer to the runtime-derived base lane.
   */
  RRef* RRef_IFormationInstance(RRef* const out, moho::IFormationInstance* const value)
  {
    GPG_ASSERT(out != nullptr);

    gpg::RType* baseType = moho::IFormationInstance::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(moho::IFormationInstance));
      moho::IFormationInstance::sType = baseType;
    }

    if (!value || typeid(*value) == typeid(moho::IFormationInstance)) {
      out->mType = baseType;
      out->mObj = value;
      return out;
    }

    const std::type_info* const dynamicTypeInfo = &typeid(*value);
    EnsureIFormationInstanceTypeCacheInitialized(gIFormationInstanceTypeCache);

    std::size_t cacheIndex = 0;
    while (cacheIndex < 3) {
      const RTypeCacheEntry& entry = gIFormationInstanceTypeCache.mEntries[cacheIndex];
      if (TypeInfosMatch(entry.mTypeInfo, dynamicTypeInfo)) {
        break;
      }
      ++cacheIndex;
    }

    gpg::RType* dynamicType = nullptr;
    if (cacheIndex < 3) {
      dynamicType = gIFormationInstanceTypeCache.mEntries[cacheIndex].mType;
    } else {
      dynamicType = gpg::LookupRType(*dynamicTypeInfo);
      cacheIndex = 2;
    }

    if (cacheIndex != 0) {
      for (std::size_t i = cacheIndex; i > 0; --i) {
        gIFormationInstanceTypeCache.mEntries[i] = gIFormationInstanceTypeCache.mEntries[i - 1];
      }

      gIFormationInstanceTypeCache.mEntries[0].mTypeInfo = dynamicTypeInfo;
      gIFormationInstanceTypeCache.mEntries[0].mType = dynamicType;
    }

    if (!dynamicType) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    if (!dynamicType->IsDerivedFrom(baseType, &baseOffset)) {
      gpg::HandleAssertFailure(kIsDerivedAssertExpr, kIsDerivedAssertLine, kReflectionHeaderPath);
    }

    out->mType = dynamicType;
    out->mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
    return out;
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00569450 (FUN_00569450, Moho::IFormationInstance::IFormationInstance)
   *
   * What it does:
   * Initializes the base runtime word at `+0x04` and resets the embedded
   * broadcaster node at `+0x08` to singleton links.
   */
  IFormationInstance::IFormationInstance()
  {
    auto& view = *reinterpret_cast<IFormationInstanceSerializationRuntimeView*>(this);
    view.mBaseRuntimeWord = 0u;
    view.broadcaster.ListResetLinks();
  }

  /**
   * Address: 0x00565C70 (FUN_00565C70, Moho::IFormationInstance::~IFormationInstance)
   *
   * What it does:
   * Unlinks the embedded `Broadcaster<EFormationdStatus>` lane from its
   * intrusive listener list.
   */
  IFormationInstance::~IFormationInstance()
  {
    auto* const view = reinterpret_cast<IFormationInstanceSerializationRuntimeView*>(this);
    if (view != nullptr) {
      view->broadcaster.ListUnlink();
    }
  }

  /**
   * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for
   * `IFormationInstance*`.
   */
  gpg::RType* IFormationInstance::GetPointerType()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::IFormationInstance));
    }

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IFormationInstance*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x00570D80 (FUN_00570D80, Moho::IFormationInstance::MemberDeserialize)
   *
   * What it does:
   * Loads reflected `Broadcaster<EFormationdStatus>` payload from archive into
   * this instance's broadcaster subobject lane.
   */
  void IFormationInstance::MemberDeserialize(
    IFormationInstance* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (archive == nullptr) {
      return;
    }

    auto* const view = reinterpret_cast<IFormationInstanceSerializationRuntimeView*>(object);
    const gpg::RRef ownerRef{};
    archive->Read(
      CachedBroadcasterEFormationdStatusType(),
      view != nullptr ? static_cast<void*>(&view->broadcaster) : nullptr,
      ownerRef
    );
  }

  /**
   * Address: 0x00570DD0 (FUN_00570DD0, Moho::IFormationInstance::MemberSerialize)
   *
   * What it does:
   * Saves reflected `Broadcaster<EFormationdStatus>` payload from this
   * instance's broadcaster subobject lane into archive.
   */
  void IFormationInstance::MemberSerialize(
    const IFormationInstance* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const view = reinterpret_cast<const IFormationInstanceSerializationRuntimeView*>(object);
    const gpg::RRef ownerRef{};
    archive->Write(
      CachedBroadcasterEFormationdStatusType(),
      view != nullptr ? static_cast<const void*>(&view->broadcaster) : nullptr,
      ownerRef
    );
  }

  /**
   * Address: 0x006EBF30 (FUN_006EBF30, Moho::RCountedPtrType<Moho::IFormationInstance>::RCountedPtrType)
   *
   * What it does:
   * Constructs the descriptor and preregisters it for `CountedPtr<IFormationInstance>`
   * RTTI lookup.
   */
  RCountedPtrType<moho::IFormationInstance>::RCountedPtrType()
    : gpg::RType()
    , gpg::RIndexed()
  {
    gpg::PreRegisterRType(typeid(moho::CountedPtr<moho::IFormationInstance>), this);
  }

  /**
   * Address: 0x006EC110 (FUN_006EC110, Moho::RCountedPtrType<Moho::IFormationInstance>::dtr)
   */
  RCountedPtrType<moho::IFormationInstance>::~RCountedPtrType() = default;

  /**
   * Address: 0x006E9D80 (FUN_006E9D80, Moho::RCountedPtrType<Moho::IFormationInstance>::GetName)
   */
  const char* RCountedPtrType<moho::IFormationInstance>::GetName() const
  {
    if (gCountedPtrTypeName.empty()) {
      const char* const pointeeName = CachedIFormationInstanceType() ? CachedIFormationInstanceType()->GetName() : "IFormationInstance";
      gCountedPtrTypeName = gpg::STR_Printf("CountedPtr<%s>", pointeeName ? pointeeName : "IFormationInstance");
      if (!gCountedPtrTypeNameCleanupRegistered) {
        gCountedPtrTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RCountedPtrType_IFormationInstance_Name);
      }
    }

    return gCountedPtrTypeName.c_str();
  }

  /**
   * Address: 0x006E9E40 (FUN_006E9E40, Moho::RCountedPtrType<Moho::IFormationInstance>::GetLexical)
   */
  msvc8::string RCountedPtrType<moho::IFormationInstance>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const slot = AsSlot(ref.mObj);
    if (!slot || !*slot) {
      return msvc8::string("NULL");
    }

    const gpg::RRef instanceRef = MakeIFormationInstanceRef(*slot);
    const msvc8::string inner = instanceRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x006E9FC0 (FUN_006E9FC0, Moho::RCountedPtrType<Moho::IFormationInstance>::IsIndexed)
   */
  const gpg::RIndexed* RCountedPtrType<moho::IFormationInstance>::IsIndexed() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x006E9FD0 (FUN_006E9FD0, Moho::RCountedPtrType<Moho::IFormationInstance>::IsPointer)
   */
  const gpg::RIndexed* RCountedPtrType<moho::IFormationInstance>::IsPointer() const
  {
    return static_cast<const gpg::RIndexed*>(this);
  }

  /**
   * Address: 0x006E9E20 (FUN_006E9E20, Moho::RCountedPtrType<Moho::IFormationInstance>::Init)
   */
  void RCountedPtrType<moho::IFormationInstance>::Init()
  {
    size_ = sizeof(moho::IFormationInstance*);
    version_ = 1;
    serLoadFunc_ = &SerLoad;
    serSaveFunc_ = &SerSave;
  }

  /**
   * Address: 0x006E9FF0 (FUN_006E9FF0, Moho::RCountedPtrType<Moho::IFormationInstance>::SubscriptIndex)
   */
  gpg::RRef RCountedPtrType<moho::IFormationInstance>::SubscriptIndex(void* obj, int ind) const
  {
    (void)ind;
    auto* const slot = AsSlot(obj);
    return MakeIFormationInstanceRef(slot ? *slot : nullptr);
  }

  /**
   * Address: 0x006E9FE0 (FUN_006E9FE0, Moho::RCountedPtrType<Moho::IFormationInstance>::GetCount)
   */
  size_t RCountedPtrType<moho::IFormationInstance>::GetCount(void* obj) const
  {
    auto* const slot = AsSlot(obj);
    return (slot && *slot) ? 1u : 0u;
  }

  /**
   * Address: 0x006EAAC0 (FUN_006EAAC0, Moho::RCountedPtrType<Moho::IFormationInstance>::SerLoad)
   */
  void RCountedPtrType<moho::IFormationInstance>::SerLoad(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    auto* const slot = reinterpret_cast<moho::IFormationInstance**>(objectPtr);
    if (!slot) {
      return;
    }

    moho::IFormationInstance* const oldValue = *slot;
    moho::IFormationInstance* const newValue =
      ReadPointerWeakIFormationInstance(archive, ownerRef ? *ownerRef : gpg::RRef{});

    if (oldValue != newValue) {
      if (oldValue) {
        auto& oldView = RefCountView(oldValue);
        if (--oldView.mRefCount == 0) {
          oldValue->operator_delete(1);
        }
      }

      *slot = newValue;
      if (newValue) {
        ++RefCountView(newValue).mRefCount;
      }
    }
  }

  /**
   * Address: 0x006EAB10 (FUN_006EAB10, Moho::RCountedPtrType<Moho::IFormationInstance>::SerSave)
   */
  void RCountedPtrType<moho::IFormationInstance>::SerSave(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    auto* const slot = reinterpret_cast<moho::IFormationInstance**>(objectPtr);
    const gpg::RRef objectRef = MakeIFormationInstanceRef(slot ? *slot : nullptr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Shared, owner);
  }

  /**
   * Address: 0x00BD9030 (FUN_00BD9030, register_IFormationInstanceCountedPtrReflection)
   */
  void register_IFormationInstanceCountedPtrReflection()
  {
    (void)GetCountedPtrType();
    (void)std::atexit(&cleanup_RCountedPtrType_IFormationInstance);
  }
} // namespace moho

namespace
{
  struct IFormationInstanceCountedPtrReflectionBootstrap
  {
    IFormationInstanceCountedPtrReflectionBootstrap()
    {
      moho::register_IFormationInstanceCountedPtrReflection();
    }
  };

  IFormationInstanceCountedPtrReflectionBootstrap gIFormationInstanceCountedPtrReflectionBootstrap;
} // namespace
