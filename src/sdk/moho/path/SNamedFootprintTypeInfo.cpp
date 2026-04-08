#include "moho/path/SNamedFootprint.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"

#include <cstdlib>
#include <list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  template <class T>
  [[nodiscard]] gpg::RType* ResolveType()
  {
    return gpg::LookupRType(typeid(T));
  }

  /**
   * Address: 0x00514680 (FUN_00514680)
   *
   * What it does:
   * Resolves/caches `SFootprint` RTTI and appends it as a base descriptor of
   * the current `SNamedFootprint` typeinfo object.
   */
  void AddSFootprintBaseDescriptor(gpg::RType* const owner)
  {
    if (!owner) {
      return;
    }

    static gpg::RType* cachedSFootprintType = nullptr;
    gpg::RType* baseType = cachedSFootprintType;
    if (!baseType) {
      baseType = ResolveType<moho::SFootprint>();
      cachedSFootprintType = baseType;
    }
    if (!baseType) {
      return;
    }

    GPG_ASSERT(!owner->initFinished_);
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    owner->AddBase(baseField);
  }

  void AddFieldDescriptor(gpg::RType* const owner, const char* const name, gpg::RType* const fieldType, const int offset)
  {
    if (!owner || !fieldType) {
      return;
    }

    GPG_ASSERT(!owner->initFinished_);
    gpg::RField field{};
    field.mName = name;
    field.mType = fieldType;
    field.mOffset = offset;
    owner->fields_.push_back(field);
  }

  /**
   * Address: 0x00514870 (FUN_00514870)
   *
   * What it does:
   * Allocates raw storage for `count` intrusive `SRuleFootprintNode` objects
   * and throws `std::bad_alloc` if the byte-count would overflow 32-bit lanes.
   */
  [[nodiscard]] moho::SRuleFootprintNode* AllocateSRuleFootprintNodeBlock(const unsigned int count)
  {
    if (count == 0u || (0xFFFFFFFFu / count) < sizeof(moho::SRuleFootprintNode)) {
      throw std::bad_alloc();
    }

    return static_cast<moho::SRuleFootprintNode*>(
      operator new(static_cast<std::size_t>(count) * sizeof(moho::SRuleFootprintNode))
    );
  }

  /**
   * Address: 0x00514640 (FUN_00514640)
   *
   * What it does:
   * Allocates one intrusive `SRuleFootprintNode` storage slot.
   */
  [[nodiscard]] moho::SRuleFootprintNode* AllocateSingleSRuleFootprintNode()
  {
    return AllocateSRuleFootprintNodeBlock(1u);
  }

  /**
   * Address: 0x00514660 (FUN_00514660, nullsub_1066)
   *
   * What it does:
   * Provides a no-op compatibility lane used by generated helper/vtable
   * tables in the original binary.
   */
  [[maybe_unused]] void SNamedFootprintNoOpLane()
  {
  }

  /**
   * Address: 0x00514670 (FUN_00514670)
   *
   * What it does:
   * Returns the fixed legacy marker value used by this helper lane.
   */
  [[maybe_unused]] [[nodiscard]] int SNamedFootprintLegacyMarkerValue()
  {
    return 0x05555555;
  }

  /**
   * Address: 0x00514960 (FUN_00514960, func_CopySNamedFootprint)
   *
   * What it does:
   * Copies footprint scalar lanes, resets destination string to SSO-empty,
   * then copies full `mName` and trailing `mIndex`.
   */
  [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintValue(
    const moho::SNamedFootprint* const source,
    moho::SNamedFootprint* const destination
  )
  {
    GPG_ASSERT(source != nullptr);
    GPG_ASSERT(destination != nullptr);
    if (!source || !destination) {
      return destination;
    }

    destination->mSizeX = source->mSizeX;
    destination->mSizeZ = source->mSizeZ;
    destination->mOccupancyCaps = source->mOccupancyCaps;
    destination->mFlags = source->mFlags;
    destination->mMaxSlope = source->mMaxSlope;
    destination->mMinWaterDepth = source->mMinWaterDepth;
    destination->mMaxWaterDepth = source->mMaxWaterDepth;
    destination->mName.reset_and_assign(source->mName);
    destination->mIndex = source->mIndex;
    return destination;
  }

  /**
   * Address: 0x005145F0 (FUN_005145F0)
   *
   * What it does:
   * Copies one `SNamedFootprint` object into destination when destination is
   * non-null (lane A).
   */
  [[maybe_unused]] [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintIfTargetPresentA(
    moho::SNamedFootprint* const destination,
    const moho::SNamedFootprint* const source
  )
  {
    if (!destination) {
      return nullptr;
    }
    return CopySNamedFootprintValue(source, destination);
  }

  /**
   * Address: 0x00514820 (FUN_00514820)
   *
   * What it does:
   * Copies one `SNamedFootprint` object into destination when destination is
   * non-null (lane B).
   */
  [[maybe_unused]] [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintIfTargetPresentB(
    moho::SNamedFootprint* const destination,
    const moho::SNamedFootprint* const source
  )
  {
    if (!destination) {
      return nullptr;
    }
    return CopySNamedFootprintValue(source, destination);
  }

  /**
   * Address: 0x005144A0 (FUN_005144A0)
   *
   * What it does:
   * Allocates one intrusive node, wires `next/prev` lanes, and copy-constructs
   * the embedded `SNamedFootprint` payload from source.
   */
  [[maybe_unused]] [[nodiscard]] moho::SRuleFootprintNode* CreateSRuleFootprintNode(
    moho::SRuleFootprintNode* const next,
    moho::SRuleFootprintNode* const prev,
    const moho::SNamedFootprint* const source
  )
  {
    moho::SRuleFootprintNode* const node = AllocateSingleSRuleFootprintNode();
    node->next = next;
    node->prev = prev;
    (void)CopySNamedFootprintValue(source, &node->value);
    return node;
  }

  [[nodiscard]] std::size_t CountSNamedFootprintList(const void* const obj) noexcept
  {
    if (!obj) {
      return 0u;
    }

    const auto* const list = static_cast<const std::list<moho::SNamedFootprint>*>(obj);
    return list ? list->size() : 0u;
  }

  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  void LoadSNamedFootprintList(gpg::ReadArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);
  void SaveSNamedFootprintList(gpg::WriteArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);

  msvc8::string gSNamedFootprintListTypeName;
  bool gSNamedFootprintListTypeNameCleanupRegistered = false;

  /**
   * Address: 0x00BF28E0 (FUN_00BF28E0)
   *
   * What it does:
   * Releases the cached `list<SNamedFootprint>` RTTI name string at process exit.
   */
  void CleanupSNamedFootprintListTypeName()
  {
    gSNamedFootprintListTypeName = msvc8::string{};
    gSNamedFootprintListTypeNameCleanupRegistered = false;
  }

  class SNamedFootprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
     *
     * What it does:
     * Destroys reflected field/base storage through the inherited `gpg::RType`
     * teardown lane.
     */
    ~SNamedFootprintTypeInfo() override;

    /**
     * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the RTTI label for `SNamedFootprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
     *
     * What it does:
     * Registers the base `SFootprint` metadata plus the `Name` and `Index`
     * reflected fields.
     */
    void Init() override;
  };

  static_assert(sizeof(SNamedFootprintTypeInfo) == 0x64, "SNamedFootprintTypeInfo size must be 0x64");

  /**
   * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
   *
   * What it does:
   * Destroys reflected field/base storage through the inherited `gpg::RType`
   * teardown lane.
   */
  SNamedFootprintTypeInfo::~SNamedFootprintTypeInfo() = default;

  /**
   * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the RTTI label for `SNamedFootprint`.
   */
  const char* SNamedFootprintTypeInfo::GetName() const
  {
    return "SNamedFootprint";
  }

  /**
   * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
   *
   * What it does:
   * Registers the base `SFootprint` metadata plus the `Name` and `Index`
   * reflected fields.
   */
  void SNamedFootprintTypeInfo::Init()
  {
    size_ = sizeof(moho::SNamedFootprint);
    gpg::RType::Init();

    AddSFootprintBaseDescriptor(this);
    AddFieldDescriptor(this, "Name", ResolveType<msvc8::string>(), 0x10);
    AddFieldDescriptor(this, "Index", ResolveType<int>(), 0x2C);

    Finish();
  }

  class SNamedFootprintListTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00513FB0 (FUN_00513FB0, gpg::RListType_SNamedFootprint::GetName)
     *
     * What it does:
     * Lazily builds and caches the `list<SNamedFootprint>` RTTI label.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if (gSNamedFootprintListTypeName.empty()) {
        const gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
        const char* const elementName = elementType ? elementType->GetName() : "SNamedFootprint";
        gSNamedFootprintListTypeName = gpg::STR_Printf("list<%s>", elementName ? elementName : "SNamedFootprint");
        if (!gSNamedFootprintListTypeNameCleanupRegistered) {
          gSNamedFootprintListTypeNameCleanupRegistered = true;
          (void)std::atexit(&CleanupSNamedFootprintListTypeName);
        }
      }

      return gSNamedFootprintListTypeName.c_str();
    }

    /**
     * Address: 0x00514070 (FUN_00514070, gpg::RListType_SNamedFootprint::GetLexical)
     *
     * What it does:
     * Formats the inherited list lexical text with the current list size.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00514050 (FUN_00514050, gpg::RListType_SNamedFootprint::Init)
     *
     * What it does:
     * Marks the reflected list as versioned and wires archive callbacks.
     */
    void Init() override;
  };

  static_assert(sizeof(SNamedFootprintListTypeInfo) == 0x64, "SNamedFootprintListTypeInfo size must be 0x64");

  /**
   * Address: 0x00514070 (FUN_00514070, gpg::RListType_SNamedFootprint::GetLexical)
   *
   * What it does:
   * Formats the inherited list lexical text with the current list size.
   */
  msvc8::string SNamedFootprintListTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountSNamedFootprintList(ref.mObj)));
  }

  /**
   * Address: 0x00514050 (FUN_00514050, gpg::RListType_SNamedFootprint::Init)
   *
   * What it does:
   * Marks the reflected list as versioned and wires archive callbacks.
   */
  void SNamedFootprintListTypeInfo::Init()
  {
    size_ = sizeof(std::list<moho::SNamedFootprint>);
    version_ = 1;
    serLoadFunc_ = &LoadSNamedFootprintList;
    serSaveFunc_ = &SaveSNamedFootprintList;
  }

  alignas(SNamedFootprintTypeInfo) unsigned char gSNamedFootprintTypeInfoStorage[sizeof(SNamedFootprintTypeInfo)]{};
  bool gSNamedFootprintTypeInfoConstructed = false;
  bool gSNamedFootprintTypeInfoPreregistered = false;

  alignas(SNamedFootprintListTypeInfo)
    unsigned char gSNamedFootprintListTypeInfoStorage[sizeof(SNamedFootprintListTypeInfo)]{};
  bool gSNamedFootprintListTypeInfoConstructed = false;
  bool gSNamedFootprintListTypeInfoPreregistered = false;

  [[nodiscard]] SNamedFootprintTypeInfo* AcquireSNamedFootprintTypeInfo()
  {
    if (!gSNamedFootprintTypeInfoConstructed) {
      new (gSNamedFootprintTypeInfoStorage) SNamedFootprintTypeInfo();
      gSNamedFootprintTypeInfoConstructed = true;
    }

    return reinterpret_cast<SNamedFootprintTypeInfo*>(gSNamedFootprintTypeInfoStorage);
  }

  [[nodiscard]] SNamedFootprintListTypeInfo* AcquireSNamedFootprintListTypeInfo()
  {
    if (!gSNamedFootprintListTypeInfoConstructed) {
      new (gSNamedFootprintListTypeInfoStorage) SNamedFootprintListTypeInfo();
      gSNamedFootprintListTypeInfoConstructed = true;
    }

    return reinterpret_cast<SNamedFootprintListTypeInfo*>(gSNamedFootprintListTypeInfoStorage);
  }

  void LoadSNamedFootprintList(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    auto* const list = reinterpret_cast<std::list<moho::SNamedFootprint>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(list != nullptr);
    if (!archive || !list) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    std::list<moho::SNamedFootprint> loaded{};
    gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
    const gpg::RRef& owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (unsigned int i = 0; i < count; ++i) {
      loaded.emplace_back();
      archive->Read(elementType, &loaded.back(), owner);
    }

    list->swap(loaded);
  }

  void SaveSNamedFootprintList(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const list = reinterpret_cast<const std::list<moho::SNamedFootprint>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
    archive->WriteUInt(count);

    if (!list) {
      return;
    }

    gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
    const gpg::RRef& owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (const moho::SNamedFootprint& footprint : *list) {
      archive->Write(elementType, &footprint, owner);
    }
  }

  struct SNamedFootprintTypeInfoBootstrap
  {
    SNamedFootprintTypeInfoBootstrap()
    {
      (void)moho::register_SNamedFootprintTypeInfoStartup();
    }
  };

  [[maybe_unused]] SNamedFootprintTypeInfoBootstrap gSNamedFootprintTypeInfoBootstrap;

  struct SNamedFootprintListTypeInfoBootstrap
  {
    SNamedFootprintListTypeInfoBootstrap()
    {
      (void)moho::register_SNamedFootprintListTypeInfoStartup();
    }
  };

  [[maybe_unused]] SNamedFootprintListTypeInfoBootstrap gSNamedFootprintListTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00513CF0 (FUN_00513CF0, preregister_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `SNamedFootprint`.
   */
  gpg::RType* preregister_SNamedFootprintTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireSNamedFootprintTypeInfo();
    if (!gSNamedFootprintTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(SNamedFootprint), typeInfo);
      gSNamedFootprintTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF2820 (FUN_00BF2820, cleanup_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SNamedFootprintTypeInfo` storage at process exit.
   */
  void cleanup_SNamedFootprintTypeInfo()
  {
    if (!gSNamedFootprintTypeInfoConstructed) {
      return;
    }

    AcquireSNamedFootprintTypeInfo()->~SNamedFootprintTypeInfo();
    gSNamedFootprintTypeInfoConstructed = false;
    gSNamedFootprintTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BC8360 (FUN_00BC8360, register_SNamedFootprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SNamedFootprint` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintTypeInfo();
    return std::atexit(&cleanup_SNamedFootprintTypeInfo);
  }

  /**
   * Address: 0x005149D0 (FUN_005149D0, preregister_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `std::list<SNamedFootprint>`.
   */
  gpg::RType* preregister_SNamedFootprintListTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireSNamedFootprintListTypeInfo();
    if (!gSNamedFootprintListTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(std::list<SNamedFootprint>), typeInfo);
      gSNamedFootprintListTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF2910 (FUN_00BF2910, cleanup_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `std::list<SNamedFootprint>` RTTI storage at process exit.
   */
  void cleanup_SNamedFootprintListTypeInfo()
  {
    if (!gSNamedFootprintListTypeInfoConstructed) {
      return;
    }

    AcquireSNamedFootprintListTypeInfo()->~SNamedFootprintListTypeInfo();
    gSNamedFootprintListTypeInfoConstructed = false;
    gSNamedFootprintListTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BC83A0 (FUN_00BC83A0, register_SNamedFootprintListTypeInfoStartup)
   *
   * What it does:
   * Preregisters `std::list<SNamedFootprint>` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintListTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintListTypeInfo();
    return std::atexit(&cleanup_SNamedFootprintListTypeInfo);
  }
} // namespace moho
