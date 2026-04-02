#include "moho/serialization/PrefetchHandleBase.h"

#include <map>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/ResourceManager.h"
#include "moho/serialization/CPrefetchSet.h"
#include "moho/serialization/PrefetchHandleBaseSerializer.h"
#include "moho/serialization/PrefetchHandleBaseTypeInfo.h"

namespace
{
  using PrefetchTypeMap = std::map<std::string, gpg::RType*, std::less<>>;

  PrefetchTypeMap* gPrefetchTypeMap = nullptr;

  /**
   * Address: 0x004A4FB0 (FUN_004A4FB0, Moho::GetPrefetchTypeMap)
   *
   * What it does:
   * Returns process-global map of textual prefetch-kind keys to reflected type
   * descriptors, constructing map storage on first use.
   */
  [[nodiscard]] PrefetchTypeMap* GetPrefetchTypeMap()
  {
    if (gPrefetchTypeMap == nullptr) {
      static PrefetchTypeMap sPrefetchTypeMap{};
      gPrefetchTypeMap = &sPrefetchTypeMap;
    }
    return gPrefetchTypeMap;
  }

  using CPrefetchSetRuntime = moho::CPrefetchSet;

#if defined(_M_IX86)
  static_assert(sizeof(CPrefetchSetRuntime) == 0x10, "CPrefetchSetRuntime size must be 0x10");
#endif

  [[nodiscard]] gpg::RType* ResolvePrefetchSetRuntimeType()
  {
    if (moho::CPrefetchSet::sType == nullptr) {
      moho::CPrefetchSet::sType = gpg::LookupRType(typeid(CPrefetchSetRuntime));
    }
    return moho::CPrefetchSet::sType;
  }

  /**
   * Address: 0x004A89A0 (FUN_004A89A0)
   *
   * What it does:
   * Destroys one half-open `PrefetchHandleBase` range `[begin, end)`.
   */
  void DestroyPrefetchHandleRange(moho::PrefetchHandleBase* begin, moho::PrefetchHandleBase* end)
  {
    while (begin != end) {
      begin->~PrefetchHandleBase();
      ++begin;
    }
  }

  /**
   * Address: 0x004A71B0 (FUN_004A71B0, Moho::CPrefetchset::NewRef)
   *
   * What it does:
   * Allocates one CPrefetchSet object and returns it wrapped in `gpg::RRef`.
   */
  [[nodiscard]] gpg::RRef NewPrefetchSetRuntimeRef()
  {
    CPrefetchSetRuntime* const object = new (std::nothrow) CPrefetchSetRuntime();
    if (object != nullptr) {
      auto& handlesView = msvc8::AsVectorRuntimeView(object->mHandles);
      handlesView.begin = nullptr;
      handlesView.end = nullptr;
      handlesView.capacityEnd = nullptr;
    }
    return gpg::RRef(object, ResolvePrefetchSetRuntimeType());
  }

  /**
   * Address: 0x004A7270 (FUN_004A7270)
   *
   * What it does:
   * Constructs one CPrefetchSet in caller-provided storage and returns the
   * reflected object reference.
   */
  [[nodiscard]] gpg::RRef ConstructPrefetchSetRuntimeRef(void* const objectStorage)
  {
    auto* const object = static_cast<CPrefetchSetRuntime*>(objectStorage);
    if (object != nullptr) {
      new (object) CPrefetchSetRuntime();
      auto& handlesView = msvc8::AsVectorRuntimeView(object->mHandles);
      handlesView.begin = nullptr;
      handlesView.end = nullptr;
      handlesView.capacityEnd = nullptr;
    }
    return gpg::RRef(object, ResolvePrefetchSetRuntimeType());
  }

  /**
   * Address: 0x004A7220 (FUN_004A7220, Moho::CPrefetchset::Delete)
   *
   * What it does:
   * Destroys all `PrefetchHandleBase` elements, frees backing storage, and
   * deletes the owning CPrefetchSet object.
   */
  void DeletePrefetchSetRuntime(void* const objectStorage)
  {
    auto* const object = static_cast<CPrefetchSetRuntime*>(objectStorage);
    if (object == nullptr) {
      return;
    }

    auto& handlesView = msvc8::AsVectorRuntimeView(object->mHandles);
    if (handlesView.begin != nullptr) {
      DestroyPrefetchHandleRange(handlesView.begin, handlesView.end);
      ::operator delete(handlesView.begin);
    }
    handlesView.begin = nullptr;
    handlesView.end = nullptr;
    handlesView.capacityEnd = nullptr;

    ::operator delete(object);
  }

  /**
   * Address: 0x004A72E0 (FUN_004A72E0)
   *
   * What it does:
   * Destroys all `PrefetchHandleBase` elements and frees vector backing storage
   * without deleting the owning CPrefetchSet storage.
   */
  void DestructPrefetchSetRuntime(void* const objectStorage)
  {
    auto* const object = static_cast<CPrefetchSetRuntime*>(objectStorage);
    if (object == nullptr) {
      return;
    }

    auto& handlesView = msvc8::AsVectorRuntimeView(object->mHandles);
    if (handlesView.begin != nullptr) {
      DestroyPrefetchHandleRange(handlesView.begin, handlesView.end);
      ::operator delete(handlesView.begin);
    }
    handlesView.begin = nullptr;
    handlesView.end = nullptr;
    handlesView.capacityEnd = nullptr;
  }

  /**
   * Address: 0x004A5270 (FUN_004A5270)
   *
   * What it does:
   * Assigns CPrefetchSet lifecycle callback lanes in one reflected type
   * descriptor.
   */
  gpg::RType* BindCPrefetchSetLifecycleCallbacks(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    typeInfo->newRefFunc_ = &NewPrefetchSetRuntimeRef;
    typeInfo->ctorRefFunc_ = &ConstructPrefetchSetRuntimeRef;
    typeInfo->deleteFunc_ = &DeletePrefetchSetRuntime;
    typeInfo->dtrFunc_ = &DestructPrefetchSetRuntime;
    return typeInfo;
  }

  class CPrefetchSetTypeInfoRuntime final : public gpg::RType
  {
  public:
    ~CPrefetchSetTypeInfoRuntime() override;

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004A5180 (FUN_004A5180, Moho::CPrefetchSetTypeInfo::Init)
     *
     * What it does:
     * Initializes reflected CPrefetchSet runtime metadata and wires object
     * lifecycle callback lanes.
     */
    void Init() override
    {
      size_ = static_cast<int>(sizeof(CPrefetchSetRuntime));
      gpg::RType::Init();
      (void)BindCPrefetchSetLifecycleCallbacks(this);
      Finish();
    }
  };

  /**
   * Address: 0x004A51D0 (FUN_004A51D0, Moho::CPrefetchSetTypeInfo::dtr)
   */
  CPrefetchSetTypeInfoRuntime::~CPrefetchSetTypeInfoRuntime()
  {
    bases_.clear();
    fields_.clear();
  }

  /**
   * Address: 0x004A51C0 (FUN_004A51C0, Moho::CPrefetchSetTypeInfo::GetName)
   */
  const char* CPrefetchSetTypeInfoRuntime::GetName() const
  {
    return "CPrefetchSet";
  }

  CPrefetchSetTypeInfoRuntime gPrefetchSetTypeInfoRuntime{};

  /**
   * Address: 0x004A5120 (FUN_004A5120)
   *
   * What it does:
   * Constructs and preregisters reflected type-info object for CPrefetchSet.
   */
  [[nodiscard]] gpg::RType* EnsurePrefetchSetTypeRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(CPrefetchSetRuntime), &gPrefetchSetTypeInfoRuntime);
      moho::CPrefetchSet::sType = &gPrefetchSetTypeInfoRuntime;
      return true;
    }();
    (void)kRegistered;
    return &gPrefetchSetTypeInfoRuntime;
  }

  struct PrefetchSetTypeRegistration
  {
    PrefetchSetTypeRegistration()
    {
      (void)EnsurePrefetchSetTypeRegistered();
    }
  };

  PrefetchSetTypeRegistration gPrefetchSetTypeRegistration{};

  moho::PrefetchHandleBaseTypeInfo gPrefetchHandleBaseTypeInfo;
  moho::PrefetchHandleBaseSerializer gPrefetchHandleBaseSerializer;

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(moho::PrefetchHandleBaseSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  gpg::SerHelperBase* ResetSerializerLinks(moho::PrefetchHandleBaseSerializer& serializer)
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  void EnsurePrefetchHandleBaseRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(moho::PrefetchHandleBase), &gPrefetchHandleBaseTypeInfo);
      gPrefetchHandleBaseSerializer.mHelperNext = nullptr;
      gPrefetchHandleBaseSerializer.mHelperPrev = nullptr;
      gPrefetchHandleBaseSerializer.mLoadCallback = &moho::PrefetchHandleBaseSerializer::Deserialize;
      gPrefetchHandleBaseSerializer.mSaveCallback = &moho::PrefetchHandleBaseSerializer::Serialize;
      gPrefetchHandleBaseSerializer.RegisterSerializeFunctions();
      return true;
    }();

    (void)kRegistered;
  }
} // namespace

namespace moho
{
  void EnsurePrefetchSetTypeRegistration()
  {
    (void)EnsurePrefetchSetTypeRegistered();
  }

  /**
   * Address: 0x004ABF30 (FUN_004ABF30, Moho::RES_PrefetchResource)
   *
   * What it does:
   * Ensures the resource-manager singleton and forwards prefetch-handle
   * creation to `ResourceManager::CreatePrefetchData`.
   */
  boost::shared_ptr<PrefetchData>* RES_PrefetchResource(
    boost::shared_ptr<PrefetchData>* const outPrefetchData,
    const gpg::StrArg resourcePath,
    const gpg::RType* const type
  )
  {
    if (outPrefetchData == nullptr) {
      return nullptr;
    }

    RES_EnsureResourceManager();
    ResourceManager* const manager = RES_GetResourceManager();
    if (manager == nullptr) {
      outPrefetchData->reset();
      return outPrefetchData;
    }

    return manager->CreatePrefetchData(outPrefetchData, resourcePath, const_cast<gpg::RType*>(type));
  }

  /**
   * Address: 0x004A5060 (FUN_004A5060, Moho::RES_RegisterPrefetchType)
   *
   * What it does:
   * Registers one textual prefetch kind key to the reflected type used for
   * prefetch payload creation.
   */
  void RES_RegisterPrefetchType(const gpg::StrArg key, gpg::RType* const type)
  {
    if (key == nullptr || key[0] == '\0' || type == nullptr) {
      return;
    }

    PrefetchTypeMap* const typeMap = GetPrefetchTypeMap();
    if (typeMap == nullptr) {
      return;
    }

    (*typeMap)[std::string(key)] = type;
  }

  gpg::RType* RES_FindPrefetchType(const gpg::StrArg key)
  {
    if (key == nullptr || key[0] == '\0') {
      return nullptr;
    }

    PrefetchTypeMap* const typeMap = GetPrefetchTypeMap();
    if (!typeMap) {
      return nullptr;
    }

    const auto it = typeMap->find(std::string(key));
    if (it == typeMap->end()) {
      return nullptr;
    }

    return it->second;
  }

  gpg::RType* PrefetchHandleBase::sType = nullptr;

  gpg::RType* PrefetchHandleBase::StaticGetClass()
  {
    EnsurePrefetchHandleBaseRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(PrefetchHandleBase));
    }
    return sType;
  }

  /**
   * Address: 0x004AF0B0 (FUN_004AF0B0, Moho::PrefetchHandleBase::MemberDeserialize)
   */
  void PrefetchHandleBase::MemberDeserialize(gpg::ReadArchive* archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    msvc8::string resourcePath{};
    archive->ReadString(&resourcePath);

    const gpg::TypeHandle typeHandle = archive->ReadTypeHandle();

    boost::shared_ptr<PrefetchData> payload{};
    RES_PrefetchResource(&payload, resourcePath.c_str(), typeHandle.type);
    mPtr = payload;
  }

  /**
   * Address: 0x004ABE00 (FUN_004ABE00, Moho::PrefetchHandleBase::GetName)
   */
  const msvc8::string& PrefetchHandleBase::GetName() const
  {
    GPG_ASSERT(mPtr.get() != nullptr && mPtr->mRequest != nullptr);
    return mPtr->mRequest->mResourceId.name;
  }

  /**
   * Address: 0x004ABE10 (FUN_004ABE10, Moho::PrefetchHandleBase::GetResourceRType)
   */
  gpg::RType* PrefetchHandleBase::GetResourceRType() const
  {
    GPG_ASSERT(mPtr.get() != nullptr && mPtr->mRequest != nullptr);
    return mPtr->mRequest->mResourceType;
  }

  /**
   * Address: 0x004ABDA0 (FUN_004ABDA0)
   */
  gpg::SerHelperBase* ResetPrefetchHandleBaseSerializerLinksVariant1()
  {
    return ResetSerializerLinks(gPrefetchHandleBaseSerializer);
  }

  /**
   * Address: 0x004ABDD0 (FUN_004ABDD0)
   */
  gpg::SerHelperBase* ResetPrefetchHandleBaseSerializerLinksVariant2()
  {
    return ResetSerializerLinks(gPrefetchHandleBaseSerializer);
  }
} // namespace moho
