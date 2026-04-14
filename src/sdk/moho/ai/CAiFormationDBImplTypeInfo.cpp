#include "moho/ai/CAiFormationDBImplTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/misc/Stats.h"

using namespace moho;

namespace
{
  class IFormationInstanceFastVectorTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(IFormationInstanceFastVectorTypeInfo) == 0x68,
    "IFormationInstanceFastVectorTypeInfo size must be 0x68"
  );

  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AE658u>::value = nullptr;

  alignas(CAiFormationDBImplTypeInfo)
  unsigned char gCAiFormationDBImplTypeInfoStorage[sizeof(CAiFormationDBImplTypeInfo)] = {};
  bool gCAiFormationDBImplTypeInfoConstructed = false;

  alignas(IFormationInstanceFastVectorTypeInfo)
  unsigned char
    gFastVectorIFormationInstanceTypeStorage[sizeof(IFormationInstanceFastVectorTypeInfo)] = {};
  bool gFastVectorIFormationInstanceTypeConstructed = false;
  msvc8::string gFastVectorIFormationInstanceTypeName;
  bool gFastVectorIFormationInstanceTypeNameCleanupRegistered = false;

  [[nodiscard]] CAiFormationDBImplTypeInfo* AcquireCAiFormationDBImplTypeInfo()
  {
    if (!gCAiFormationDBImplTypeInfoConstructed) {
      new (gCAiFormationDBImplTypeInfoStorage) CAiFormationDBImplTypeInfo();
      gCAiFormationDBImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiFormationDBImplTypeInfo*>(gCAiFormationDBImplTypeInfoStorage);
  }

  [[nodiscard]] gpg::RRef MakeCAiFormationDBImplRef(CAiFormationDBImpl* const object) noexcept
  {
    gpg::RRef out{};
    (void)gpg::RRef_CAiFormationDBImpl(&out, object);
    return out;
  }

  void InitializeCAiFormationDBImpl(CAiFormationDBImpl* const object) noexcept
  {
    if (!object) {
      return;
    }

    object->mSim = nullptr;
    object->mFormInstances.ResetStorageToInline();
  }

  [[nodiscard]] IFormationInstanceFastVectorTypeInfo* AcquireFastVectorIFormationInstanceType()
  {
    if (!gFastVectorIFormationInstanceTypeConstructed) {
      new (gFastVectorIFormationInstanceTypeStorage) IFormationInstanceFastVectorTypeInfo();
      gFastVectorIFormationInstanceTypeConstructed = true;
    }

    return reinterpret_cast<IFormationInstanceFastVectorTypeInfo*>(gFastVectorIFormationInstanceTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(IFormationInstance));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstancePointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(IFormationInstance*));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeIFormationInstanceRef(IFormationInstance* value)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIFormationInstanceType();
    if (!value) {
      return out;
    }

    gpg::RType* dynamicType = CachedIFormationInstanceType();
    try {
      dynamicType = gpg::LookupRType(typeid(*value));
    } catch (...) {
      dynamicType = CachedIFormationInstanceType();
    }

    int baseOffset = 0;
    if (dynamicType && CachedIFormationInstanceType() && dynamicType->IsDerivedFrom(CachedIFormationInstanceType(), &baseOffset)) {
      out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
      out.mType = dynamicType;
      return out;
    }

    out.mObj = value;
    out.mType = dynamicType ? dynamicType : CachedIFormationInstanceType();
    return out;
  }

  [[nodiscard]] gpg::RRef MakeIFormationInstancePointerSlotRef(IFormationInstance** slot)
  {
    if (gpg::RType* const pointerType = CachedIFormationInstancePointerType(); pointerType != nullptr) {
      gpg::RRef out{};
      out.mObj = slot;
      out.mType = pointerType;
      return out;
    }

    return MakeIFormationInstanceRef(slot ? *slot : nullptr);
  }

  void LoadFastVectorIFormationInstance(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<IFormationInstance*>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    IFormationInstance* fill = nullptr;
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
      if (!tracked.object) {
        view.begin[i] = nullptr;
        continue;
      }

      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;

      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIFormationInstanceType());
      if (upcast.mObj) {
        view.begin[i] = static_cast<IFormationInstance*>(upcast.mObj);
        continue;
      }

      const char* const expected = CachedIFormationInstanceType() ? CachedIFormationInstanceType()->GetName() : "IFormationInstance";
      const char* const actual = source.GetTypeName();
      const msvc8::string message = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
        expected ? expected : "IFormationInstance",
        actual ? actual : "null"
      );
      throw gpg::SerializationError(message.c_str());
    }
  }

  void SaveFastVectorIFormationInstance(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<IFormationInstance*>(reinterpret_cast<const void*>(objectPtr));

    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::RRef objectRef = MakeIFormationInstanceRef(view.begin[i]);
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x0059DED0 (FUN_0059DED0, preregister_FastVectorIFormationInstanceType)
   *
   * What it does:
   * Constructs and preregisters startup RTTI descriptor for
   * `gpg::fastvector<IFormationInstance*>`.
   */
  [[nodiscard]] gpg::RType* preregister_FastVectorIFormationInstanceType()
  {
    IFormationInstanceFastVectorTypeInfo* const type = AcquireFastVectorIFormationInstanceType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<IFormationInstance*>), type);
    return type;
  }

  /**
   * Address: 0x00BF6830 (FUN_00BF6830)
   *
   * What it does:
   * Tears down startup-owned `CAiFormationDBImplTypeInfo` storage.
   */
  void cleanup_CAiFormationDBImplTypeInfo()
  {
    if (!gCAiFormationDBImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiFormationDBImplTypeInfo()->~CAiFormationDBImplTypeInfo();
    gCAiFormationDBImplTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF6980 (FUN_00BF6980, cleanup_FastVectorIFormationInstanceType)
   *
   * What it does:
   * Tears down startup-owned `gpg::fastvector<IFormationInstance*>`
   * reflection storage.
   */
  void cleanup_FastVectorIFormationInstanceType()
  {
    if (!gFastVectorIFormationInstanceTypeConstructed) {
      return;
    }

    AcquireFastVectorIFormationInstanceType()->~IFormationInstanceFastVectorTypeInfo();
    gFastVectorIFormationInstanceTypeConstructed = false;
  }

  /**
   * Address: 0x00BF69E0 (FUN_00BF69E0, cleanup_CAiFormationDBImplStartupStatsSlot)
   *
   * What it does:
   * Tears down one startup-owned engine-stats slot for this lane.
   */
  void cleanup_CAiFormationDBImplStartupStatsSlot()
  {
    EngineStats*& slot = StartupEngineStatsSlot<0x10AE658u>::value;
    if (!slot) {
      return;
    }

    delete slot;
    slot = nullptr;
  }

  void cleanup_FastVectorIFormationInstanceTypeName()
  {
    gFastVectorIFormationInstanceTypeName.clear();
    gFastVectorIFormationInstanceTypeNameCleanupRegistered = false;
  }
} // namespace

/**
 * Address: 0x0059C9A0 (FUN_0059C9A0, gpg::RFastVectorType_IFormationInstance_P::GetName)
 *
 * What it does:
 * Lazily formats and caches the reflected type name for
 * `gpg::fastvector<moho::IFormationInstance*>`.
 */
const char* IFormationInstanceFastVectorTypeInfo::GetName() const
{
  if (gFastVectorIFormationInstanceTypeName.empty()) {
    const gpg::RType* const pointerType = CachedIFormationInstancePointerType();
    const char* const pointerTypeName = pointerType ? pointerType->GetName() : "IFormationInstance *";
    gFastVectorIFormationInstanceTypeName = gpg::STR_Printf("fastvector<%s>", pointerTypeName);
    if (!gFastVectorIFormationInstanceTypeNameCleanupRegistered) {
      gFastVectorIFormationInstanceTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorIFormationInstanceTypeName);
    }
  }

  return gFastVectorIFormationInstanceTypeName.c_str();
}

/**
 * Address: 0x0059CA40 (FUN_0059CA40, gpg::RFastVectorType_IFormationInstanceP::GetLexical)
 *
 * What it does:
 * Formats vector lexical text and appends the runtime pointer count.
 */
msvc8::string IFormationInstanceFastVectorTypeInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

const gpg::RIndexed* IFormationInstanceFastVectorTypeInfo::IsIndexed() const
{
  return this;
}

void IFormationInstanceFastVectorTypeInfo::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorIFormationInstance;
  serSaveFunc_ = &SaveFastVectorIFormationInstance;
}

gpg::RRef IFormationInstanceFastVectorTypeInfo::SubscriptIndex(void* obj, const int ind) const
{
  auto* const storage = static_cast<gpg::fastvector<IFormationInstance*>*>(obj);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return MakeIFormationInstancePointerSlotRef(nullptr);
  }

  return MakeIFormationInstancePointerSlotRef(storage->data() + ind);
}

size_t IFormationInstanceFastVectorTypeInfo::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<IFormationInstance*>(obj);
  if (!view.Data()) {
    return 0u;
  }
  return view.Size();
}

void IFormationInstanceFastVectorTypeInfo::SetCount(void* obj, const int count) const
{
  GPG_ASSERT(obj != nullptr);
  GPG_ASSERT(count >= 0);
  if (!obj || count < 0) {
    return;
  }

  IFormationInstance* fill = nullptr;
  gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), gpg::AsFastVectorRuntimeView<IFormationInstance*>(obj));
}

/**
 * Address: 0x0059C510 (FUN_0059C510, ctor)
 *
 * What it does:
 * Preregisters `CAiFormationDBImpl` RTTI so lookup resolves to this type
 * helper.
 */
CAiFormationDBImplTypeInfo::CAiFormationDBImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiFormationDBImpl), this);
}

/**
 * Address: 0x0059C5C0 (FUN_0059C5C0, scalar deleting thunk)
 */
CAiFormationDBImplTypeInfo::~CAiFormationDBImplTypeInfo() = default;

/**
 * Address: 0x0059C5B0 (FUN_0059C5B0, ?GetName@CAiFormationDBImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiFormationDBImplTypeInfo::GetName() const
{
  return "CAiFormationDBImpl";
}

/**
 * Address: 0x0059C570 (FUN_0059C570, ?Init@CAiFormationDBImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiFormationDBImplTypeInfo::Init()
{
  size_ = sizeof(CAiFormationDBImpl);
  newRefFunc_ = &CAiFormationDBImplTypeInfo::NewRef;
  ctorRefFunc_ = &CAiFormationDBImplTypeInfo::CtrRef;
  deleteFunc_ = &CAiFormationDBImplTypeInfo::Delete;
  dtrFunc_ = &CAiFormationDBImplTypeInfo::Destruct;
  gpg::RType::Init();

  static gpg::RType* sCachedIAiFormationDBType = nullptr;
  if (!sCachedIAiFormationDBType) {
    sCachedIAiFormationDBType = gpg::LookupRType(typeid(IAiFormationDB));
  }

  gpg::RType* const baseType = sCachedIAiFormationDBType;
  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
}

/**
 * Address: 0x0059D390 (FUN_0059D390, Moho::CAiFormationDBImplTypeInfo::NewRef)
 *
 * What it does:
 * Allocates a reflected `CAiFormationDBImpl`, clears its owned AI-sim lane,
 * and returns the object as a typed `gpg::RRef`.
 */
gpg::RRef CAiFormationDBImplTypeInfo::NewRef()
{
  CAiFormationDBImpl* const object = new (std::nothrow) CAiFormationDBImpl();
  InitializeCAiFormationDBImpl(object);
  return MakeCAiFormationDBImplRef(object);
}

/**
 * Address: 0x0059D430 (FUN_0059D430, Moho::CAiFormationDBImplTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-constructs one `CAiFormationDBImpl` in caller storage, resets its
 * owned sim lane, and returns a typed `gpg::RRef`.
 */
gpg::RRef CAiFormationDBImplTypeInfo::CtrRef(void* const objectStorage)
{
  CAiFormationDBImpl* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (object) {
    new (object) CAiFormationDBImpl();
    InitializeCAiFormationDBImpl(object);
  }

  return MakeCAiFormationDBImplRef(object);
}

/**
 * Address: 0x0059D410 (FUN_0059D410, Moho::CAiFormationDBImplTypeInfo::Delete)
 *
 * What it does:
 * Runs deleting-dtor behavior for one reflected `CAiFormationDBImpl`
 * storage lane.
 */
void CAiFormationDBImplTypeInfo::Delete(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (!object) {
    return;
  }

  object->~CAiFormationDBImpl();
  ::operator delete(object);
}

/**
 * Address: 0x0059D4B0 (FUN_0059D4B0, Moho::CAiFormationDBImplTypeInfo::Destruct)
 *
 * What it does:
 * Runs in-place teardown for one reflected `CAiFormationDBImpl` storage lane
 * without freeing the backing allocation.
 */
void CAiFormationDBImplTypeInfo::Destruct(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (!object) {
    return;
  }

  object->~CAiFormationDBImpl();
}

/**
 * Address: 0x00BCC1B0 (FUN_00BCC1B0, register_CAiFormationDBImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiFormationDBImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiFormationDBImplTypeInfo()
{
  (void)AcquireCAiFormationDBImplTypeInfo();
  (void)std::atexit(&cleanup_CAiFormationDBImplTypeInfo);
}

/**
 * Address: 0x00BCC210 (FUN_00BCC210, register_FastVectorIFormationInstanceTypeAtexit)
 *
 * What it does:
 * Preregisters reflected `gpg::fastvector<IFormationInstance*>` type info and
 * installs process-exit cleanup for that descriptor storage.
 */
int moho::register_FastVectorIFormationInstanceTypeAtexit()
{
  (void)preregister_FastVectorIFormationInstanceType();
  return std::atexit(&cleanup_FastVectorIFormationInstanceType);
}

/**
 * Address: 0x00BCC230 (FUN_00BCC230, register_CAiFormationDBImplStartupStatsCleanup)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned engine-stats slot used
 * by this lane.
 */
int moho::register_CAiFormationDBImplStartupStatsCleanup()
{
  return std::atexit(&cleanup_CAiFormationDBImplStartupStatsSlot);
}

namespace
{
  struct CAiFormationDBImplTypeInfoBootstrap
  {
    CAiFormationDBImplTypeInfoBootstrap()
    {
      moho::register_CAiFormationDBImplTypeInfo();
      (void)moho::register_FastVectorIFormationInstanceTypeAtexit();
      (void)moho::register_CAiFormationDBImplStartupStatsCleanup();
    }
  };

  [[maybe_unused]] CAiFormationDBImplTypeInfoBootstrap gCAiFormationDBImplTypeInfoBootstrap;
} // namespace
