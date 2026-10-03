#include <cstddef>
#include "moho/serialization/PrefetchHandleBase.h"

#include <cstdlib>
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
#include "moho/serialization/PrefetchHandleBaseTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

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

#if defined(_M_IX86)
  static_assert(sizeof(moho::CPrefetchSet) == 0x10, "moho::CPrefetchSet size must be 0x10");
#endif

  [[nodiscard]] gpg::RType* ResolvePrefetchSetType()
  {
    if (moho::CPrefetchSet::sType == nullptr) {
      moho::CPrefetchSet::sType = gpg::LookupRType(typeid(moho::CPrefetchSet));
    }
    return moho::CPrefetchSet::sType;
  }


  /**
   * Address: 0x004A71B0 (FUN_004A71B0, Moho::CPrefetchset::NewRef)
   *
   * What it does:
   * Allocates one CPrefetchSet object and returns it wrapped in `gpg::RRef`.
   */
  [[nodiscard]] gpg::RRef NewPrefetchSetRef()
  {
    // msvc8::vector's default constructor already null-initialises all three
    // lanes; the binary's explicit zeroing here IS that constructor inlined.
    moho::CPrefetchSet* const object = new (std::nothrow) moho::CPrefetchSet();
    return gpg::RRef(object, ResolvePrefetchSetType());
  }

  /**
   * Address: 0x004A7270 (FUN_004A7270)
   *
   * What it does:
   * Constructs one CPrefetchSet in caller-provided storage and returns the
   * reflected object reference.
   */
  [[nodiscard]] gpg::RRef ConstructPrefetchSetRef(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CPrefetchSet*>(objectStorage);
    if (object != nullptr) {
      // Placement-new runs msvc8::vector's default constructor, which is what
      // the binary's explicit lane zeroing right after it is.
      new (object) moho::CPrefetchSet();
    }
    return gpg::RRef(object, ResolvePrefetchSetType());
  }

  /**
   * Address: 0x004A7220 (FUN_004A7220, Moho::CPrefetchset::Delete)
   *
   * What it does:
   * Destroys all `PrefetchHandleBase` elements, frees backing storage, and
   * deletes the owning CPrefetchSet object. The empty-vector assignment is
   * VC8 `_Tidy()`: one element sweep, one deallocate, empty triple
   * (FUN_004A89A0 is that sweep's out-of-line body).
   */
  void DeletePrefetchSet(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CPrefetchSet*>(objectStorage);
    if (object == nullptr) {
      return;
    }

    object->mHandles = msvc8::vector<moho::PrefetchHandleBase>{};

    ::operator delete(object);
  }

  /**
   * Address: 0x004A72E0 (FUN_004A72E0)
   *
   * What it does:
   * Destroys all `PrefetchHandleBase` elements and frees vector backing storage
   * without deleting the owning CPrefetchSet storage. As above, the
   * empty-vector assignment is the single `_Tidy()` the binary performed.
   */
  void DestructPrefetchSet(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CPrefetchSet*>(objectStorage);
    if (object == nullptr) {
      return;
    }

    object->mHandles = msvc8::vector<moho::PrefetchHandleBase>{};
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

    typeInfo->newRefFunc_ = &NewPrefetchSetRef;
    typeInfo->ctorRefFunc_ = &ConstructPrefetchSetRef;
    typeInfo->deleteFunc_ = &DeletePrefetchSet;
    typeInfo->dtrFunc_ = &DestructPrefetchSet;
    return typeInfo;
  }

  class CPrefetchSetTypeInfo final : public gpg::RType
  {
  public:
    ~CPrefetchSetTypeInfo() override;

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
      size_ = static_cast<int>(sizeof(moho::CPrefetchSet));
      gpg::RType::Init();
      (void)BindCPrefetchSetLifecycleCallbacks(this);
      Finish();
    }
  };

  /**
   * Address: 0x004A51D0 (FUN_004A51D0, Moho::CPrefetchSetTypeInfo::dtr)
   */
  CPrefetchSetTypeInfo::~CPrefetchSetTypeInfo()
  {
    bases_.clear();
    fields_.clear();
  }

  /**
   * Address: 0x004A51C0 (FUN_004A51C0, Moho::CPrefetchSetTypeInfo::GetName)
   */
  const char* CPrefetchSetTypeInfo::GetName() const
  {
    return "CPrefetchSet";
  }

  CPrefetchSetTypeInfo gPrefetchSetTypeInfo{};

  /**
   * Address: 0x004A5120 (FUN_004A5120)
   *
   * What it does:
   * Constructs and preregisters reflected type-info object for CPrefetchSet.
   */
  [[nodiscard]] gpg::RType* EnsurePrefetchSetTypeRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(moho::CPrefetchSet), &gPrefetchSetTypeInfo);
      moho::CPrefetchSet::sType = &gPrefetchSetTypeInfo;
      return true;
    }();
    (void)kRegistered;
    return &gPrefetchSetTypeInfo;
  }

  struct PrefetchSetTypeRegistration
  {
    PrefetchSetTypeRegistration()
    {
      (void)EnsurePrefetchSetTypeRegistered();
    }
  };

  PrefetchSetTypeRegistration gPrefetchSetTypeRegistration{};

  /**
   * Address: 0x00BF05C0 (FUN_00BF05C0, atexit destructor of the PrefetchHandleBaseTypeInfo object)
   */
  [[nodiscard]] moho::PrefetchHandleBaseTypeInfo* AcquirePrefetchHandleBaseTypeInfo()
  {
    static moho::PrefetchHandleBaseTypeInfo sInstance;
    return &sInstance;
  }

  void EnsurePrefetchHandleBaseRegistered()
  {
    static const bool kRegistered = []() {
      moho::register_PrefetchHandleBaseTypeInfo();
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
   * Address: 0x00BC5BC0 (FUN_00BC5BC0, register_PrefetchHandleBaseTypeInfo)
   *
   * What it does:
   * Materializes prefetch-handle type-info startup registration; the
   * `PrefetchHandleBaseTypeInfo` constructor performs the preregistration.
   */
  void register_PrefetchHandleBaseTypeInfo()
  {
    (void)AcquirePrefetchHandleBaseTypeInfo();
  }

  /**
   * Address: 0x004ABF30 (FUN_004ABF30, ?RES_PrefetchResource@Moho@@YA?AVPrefetchHandleBase@1@VStrArg@gpg@@PBVRType@4@@Z)
   *
   * What it does:
   * `ResourceManager::PrefetchResource` on the singleton.
   */
  PrefetchHandleBase RES_PrefetchResource(const gpg::StrArg resourcePath, const gpg::RType* const type)
  {
    return RES_GetResourceManager()->PrefetchResource(resourcePath, type);
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

    *this = RES_PrefetchResource(resourcePath.c_str(), typeHandle.type);
  }

  void PrefetchHandleBase::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteString(&mPtr->mRecord->mId.name);
    archive->WriteRefCounts(mPtr->mRecord->mType);
  }

  /**
   * Address: 0x004ABE00 (FUN_004ABE00, Moho::PrefetchHandleBase::GetName)
   */
  const msvc8::string& PrefetchHandleBase::GetName() const
  {
    GPG_ASSERT(mPtr.get() != nullptr && mPtr->mRecord != nullptr);
    return mPtr->mRecord->mId.name;
  }

  /**
   * Address: 0x004ABE10 (FUN_004ABE10, Moho::PrefetchHandleBase::GetResourceRType)
   */
  gpg::RType* PrefetchHandleBase::GetResourceRType() const
  {
    GPG_ASSERT(mPtr.get() != nullptr && mPtr->mRecord != nullptr);
    return const_cast<gpg::RType*>(mPtr->mRecord->mType);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_PrefetchHandleBaseTypeInfo_dee002, moho::register_PrefetchHandleBaseTypeInfo)

GPG_PREREGISTER_INIT(EnsurePrefetchSetTypeRegistered_dee002, EnsurePrefetchSetTypeRegistered)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<PrefetchHandleBase>`, vtable 0x00E07658.
   *
   * Address: 0x00BC5BE0 (FUN_00BC5BE0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0620 (FUN_00BF0620 -- the global's destructor.)
   * Address: 0x004ACCF0 (FUN_004ACCF0 -- `Init`.)
   * Address: 0x004ABD30 (FUN_004ABD30 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x004ABD40 (FUN_004ABD40 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct PrefetchHandleBaseSerializer : gpg::SerSaveLoadHelper<PrefetchHandleBase>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8938 -- process-global `PrefetchHandleBaseSerializer` singleton.
  moho::PrefetchHandleBaseSerializer gPrefetchHandleBaseSerializer;
} // namespace
