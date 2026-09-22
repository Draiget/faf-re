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
#include "gpg/core/reflection/StaticInitPhase.h"

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

  using FormationStatusBroadcaster = moho::BroadcasterEventTag<moho::EFormationdStatus>;

  /**
   * The binary keeps one global for this descriptor -- `0x010C6F84`, which
   * both serializers below read, test for null, fill from
   * `LookupRType(0x00F68650)` and store back. That global is the
   * instantiation's own `sType` lane, so this reads and writes it rather than
   * caching a second copy in a function-local static.
   */
  [[nodiscard]] gpg::RType* ResolveBroadcasterEFormationdStatusType()
  {
    gpg::RType* type = FormationStatusBroadcaster::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(FormationStatusBroadcaster));
      FormationStatusBroadcaster::sType = type;
    }
    return type;
  }

  // NOTE: 0x00570F10 (Moho::AddIFormationInstanceBaseField-shaped helper) is
  // recovered and wired at its real caller, `CFormationInstanceTypeInfo::Init`
  // (moho/ai/CFormationInstanceTypeInfo.cpp) -- not here. This file's
  // FUN_00570F10 duplicate was an unwired [[maybe_unused]] orphan; removed
  // in favor of the single canonical, actually-called citation.

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
   * Nothing of its own. `mov [eax+4], 0` is `CountedObject()`, the
   * `lea ecx, [eax+8]` plus two self-link stores are the broadcaster base's
   * own constructor, and the vftable store at the end is the compiler's.
   */
  IFormationInstance::IFormationInstance() = default;

  /**
   * Address: 0x00565C70 (FUN_00565C70, Moho::IFormationInstance::~IFormationInstance)
   * Address: 0x00565CA0 (FUN_00565CA0, the slot-0 scalar deleting destructor
   *   MSVC emits from this body: same vftable store, same unlink, same
   *   `mov [esi], 0xE01810` handover to `~CountedObject`, then the
   *   conditional `::operator delete`)
   *
   * What it does:
   * Unlinks the `Broadcaster<EFormationdStatus>` base from its listener ring.
   * The two vftable stores that bracket it are the compiler's, and the trailing
   * one is `~CountedObject` inlined -- the same eight-instruction tail
   * `~CFormationInstance` (0x00569880) ends with, which is what proves the
   * unlink belongs here and not to its owner.
   *
   * `TDatList` carries no destructor in this tree, so the unlink is spelled
   * out; giving one to `Broadcaster` instead would emit it into every
   * broadcaster owner in the engine, which the binary does not do.
   */
  IFormationInstance::~IFormationInstance()
  {
    FormationStatusBroadcaster::ListUnlink();
  }

  namespace
  {
    /**
     * Static `RPointerType<IFormationInstance>` descriptor that the binary
     * exposes as `Moho::IFormationInstance::PointerType`. Default static-init
     * runs the RPointerTypeBase → RType → RObject ctor chain and installs the
     * most-derived vftable lane.
     */
    gpg::RPointerType<moho::IFormationInstance> sIFormationInstancePointerTypeStorage{};

    /**
     * Address: 0x0059D5B0 (FUN_0059D5B0)
     *
     * What it does:
     * Pre-registers the static `RPointerType<IFormationInstance>` descriptor
     * under the `IFormationInstance*` type-info key so subsequent `LookupRType`
     * queries from the lazy `GetPointerType` lane resolve to this descriptor.
     */
    void PreregisterIFormationInstancePointerType()
    {
      gpg::PreRegisterRType(typeid(moho::IFormationInstance*), &sIFormationInstancePointerTypeStorage);
    }

    /**
     * Address: 0x00BF68F0 (FUN_00BF68F0)
     *
     * What it does:
     * Tears down the static `RPointerType<IFormationInstance>` descriptor at
     * process exit: frees heap-backed `bases_`/`fields_` vector storage and
     * resets the RType vftable lane to the `RObject` base. Registered via
     * `atexit` from `GetPointerType`'s once-init path.
     */
    void CleanupIFormationInstancePointerType()
    {
      sIFormationInstancePointerTypeStorage.~RPointerType<moho::IFormationInstance>();
    }
  } // namespace

  /**
   * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<IFormationInstance>`
   * descriptor and installs the matching atexit teardown. After that, lazily
   * caches the `LookupRType(typeid(IFormationInstance*))` result in
   * `sPointerType` and returns it.
   */
  gpg::RType* IFormationInstance::GetPointerType()
  {
    static const bool sOnceInit = []() {
      PreregisterIFormationInstancePointerType();
      (void)std::atexit(&CleanupIFormationInstancePointerType);
      return true;
    }();
    (void)sOnceInit;

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
   * this instance's broadcaster base subobject.
   *
   * The `xor ecx, ecx` / `cmp eax, ecx` / `lea esi, [eax + 8]` at the head is
   * not a hand-written guard: it is exactly what MSVC emits for an upcast to
   * a non-primary base, which is why the +8 and the null test arrive
   * together.
   */
  void IFormationInstance::MemberDeserialize(
    IFormationInstance* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(
      ResolveBroadcasterEFormationdStatusType(),
      static_cast<FormationStatusBroadcaster*>(object),
      ownerRef
    );
  }

  /**
   * Address: 0x00570DD0 (FUN_00570DD0, Moho::IFormationInstance::MemberSerialize)
   *
   * What it does:
   * Saves reflected `Broadcaster<EFormationdStatus>` payload from this
   * instance's broadcaster base subobject into archive. Same base upcast as
   * `MemberDeserialize`, emitted identically at 0x00570DD3-0x00570DDF.
   */
  void IFormationInstance::MemberSerialize(
    const IFormationInstance* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(
      ResolveBroadcasterEFormationdStatusType(),
      static_cast<const FormationStatusBroadcaster*>(object),
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
   *
   * What it does:
   * Reads the referenced instance, and when it differs from the one already
   * in the slot, drops a reference on the outgoing object and takes one on
   * the incoming one.
   *
   * The counting is `CountedObject`'s non-atomic pair, not the atomic one:
   * 0x006EAAE8 is a plain `add dword [ecx + 4], -1` with `jne` off its own
   * flags, and the delete at zero is `mov edx,[ecx]` / `mov eax,[edx]` /
   * `push 1` / `call eax` -- `delete this` through the slot-0 deleting
   * destructor, which is precisely `ReleaseReference()`'s body. 0x006EAAFC is
   * the matching `add dword [esi + 4], 1`.
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
        (void)oldValue->ReleaseReference();
      }

      *slot = newValue;
      if (newValue) {
        newValue->AddReference();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterIFormationInstancePointerType_096ddf, moho::PreregisterIFormationInstancePointerType)
