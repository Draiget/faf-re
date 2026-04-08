#include "RMeshBlueprintLODTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"

namespace
{
  using TypeInfo = moho::RMeshBlueprintLODTypeInfo;
  using LODVector = msvc8::vector<moho::RMeshBlueprintLOD>;

  class VectorTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x00519300 (FUN_00519300, gpg::RVectorType_RMeshBlueprintLOD::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `msvc8::vector<moho::RMeshBlueprintLOD>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(VectorTypeInfo) == 0x68, "VectorTypeInfo size must be 0x68");

  alignas(TypeInfo) unsigned char gRMeshBlueprintLODTypeInfoStorage[sizeof(TypeInfo)];
  bool gRMeshBlueprintLODTypeInfoConstructed = false;

  alignas(VectorTypeInfo) unsigned char gRMeshBlueprintLODVectorTypeStorage[sizeof(VectorTypeInfo)];
  bool gRMeshBlueprintLODVectorTypeConstructed = false;

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRMeshBlueprintLODType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RMeshBlueprintLOD));
    }
    return cached;
  }

  /**
   * Address: 0x00519240 (FUN_00519240, gpg::RVectorType_RMeshBlueprintLOD::GetName)
   *
   * What it does:
   * Builds and caches lexical reflection name `vector<element>` for
   * `msvc8::vector<moho::RMeshBlueprintLOD>`.
   */
  const char* VectorTypeInfo::GetName() const
  {
    static msvc8::string cachedName{};
    if (cachedName.empty()) {
      const gpg::RType* const elementType = CachedRMeshBlueprintLODType();
      const char* const elementName = elementType ? elementType->GetName() : "RMeshBlueprintLOD";
      cachedName = gpg::STR_Printf("vector<%s>", elementName);
    }
    return cachedName.c_str();
  }

  /**
   * Address: 0x00519300 (FUN_00519300, gpg::RVectorType_RMeshBlueprintLOD::GetLexical)
   *
   * What it does:
   * Returns base lexical text plus reflected vector size for one
   * `msvc8::vector<moho::RMeshBlueprintLOD>` instance.
   */
  msvc8::string VectorTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* VectorTypeInfo::IsIndexed() const
  {
    return this;
  }

  void VectorTypeInfo::Init()
  {
    size_ = sizeof(LODVector);
    version_ = 1;
    serLoadFunc_ = &VectorTypeInfo::SerLoad;
    serSaveFunc_ = &VectorTypeInfo::SerSave;
  }

  /**
   * Address: 0x00519620 (FUN_00519620, gpg::RVectorType_RMeshBlueprintLOD::SerLoad)
   *
   * What it does:
   * Deserializes one `vector<RMeshBlueprintLOD>` payload and replaces destination
   * storage in one assignment.
   */
  void VectorTypeInfo::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const storage = reinterpret_cast<LODVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    LODVector loaded{};
    loaded.reserve(static_cast<std::size_t>(count));

    gpg::RType* const elementType = CachedRMeshBlueprintLODType();
    GPG_ASSERT(elementType != nullptr);
    if (!elementType) {
      *storage = loaded;
      return;
    }

    const gpg::RRef emptyOwner{};
    for (unsigned int i = 0; i < count; ++i) {
      moho::RMeshBlueprintLOD element{};
      archive->Read(elementType, &element, emptyOwner);
      loaded.push_back(element);
    }

    *storage = loaded;
  }

  /**
   * Address: 0x00519750 (FUN_00519750, gpg::RVectorType_RMeshBlueprintLOD::SerSave)
   *
   * What it does:
   * Serializes one `vector<RMeshBlueprintLOD>` payload element-by-element.
   */
  void VectorTypeInfo::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const storage = reinterpret_cast<const LODVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);
    if (count == 0u) {
      return;
    }

    gpg::RType* const elementType = CachedRMeshBlueprintLODType();
    GPG_ASSERT(elementType != nullptr);
    if (!elementType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  gpg::RRef VectorTypeInfo::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedRMeshBlueprintLODType();
    out.mObj = nullptr;

    auto* const storage = static_cast<LODVector*>(obj);
    if (storage == nullptr || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
      return out;
    }

    out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
    return out;
  }

  size_t VectorTypeInfo::GetCount(void* const obj) const
  {
    const auto* const storage = static_cast<const LODVector*>(obj);
    return storage ? storage->size() : 0u;
  }

  void VectorTypeInfo::SetCount(void* const obj, const int count) const
  {
    if (obj == nullptr || count < 0) {
      return;
    }

    auto* const storage = static_cast<LODVector*>(obj);
    storage->resize(static_cast<std::size_t>(count));
  }

  [[nodiscard]] TypeInfo& AcquireRMeshBlueprintLODTypeInfo()
  {
    if (!gRMeshBlueprintLODTypeInfoConstructed) {
      new (gRMeshBlueprintLODTypeInfoStorage) TypeInfo();
      gRMeshBlueprintLODTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRMeshBlueprintLODTypeInfoStorage);
  }

  [[nodiscard]] VectorTypeInfo& AcquireRMeshBlueprintLODVectorType()
  {
    if (!gRMeshBlueprintLODVectorTypeConstructed) {
      new (gRMeshBlueprintLODVectorTypeStorage) VectorTypeInfo();
      gRMeshBlueprintLODVectorTypeConstructed = true;
    }

    return *reinterpret_cast<VectorTypeInfo*>(gRMeshBlueprintLODVectorTypeStorage);
  }

  void cleanup_RMeshBlueprintLODTypeInfoStorage()
  {
    if (!gRMeshBlueprintLODTypeInfoConstructed) {
      return;
    }

    AcquireRMeshBlueprintLODTypeInfo().~TypeInfo();
    gRMeshBlueprintLODTypeInfoConstructed = false;
  }

  void cleanup_VectorRMeshBlueprintLODTypeStorage()
  {
    if (!gRMeshBlueprintLODVectorTypeConstructed) {
      return;
    }

    AcquireRMeshBlueprintLODVectorType().~VectorTypeInfo();
    gRMeshBlueprintLODVectorTypeConstructed = false;
  }

  void AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
  }

  struct RMeshBlueprintLODTypeInfoBootstrap
  {
    RMeshBlueprintLODTypeInfoBootstrap()
    {
      (void)moho::register_RMeshBlueprintLODTypeInfo();
      (void)moho::register_VectorRMeshBlueprintLODTypeAtexit();
    }
  };

  RMeshBlueprintLODTypeInfoBootstrap gRMeshBlueprintLODTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00518460 (FUN_00518460, Moho::RMeshBlueprintLODTypeInfo::RMeshBlueprintLODTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflection descriptor for
   * `RMeshBlueprintLOD`.
   */
  RMeshBlueprintLODTypeInfo::RMeshBlueprintLODTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RMeshBlueprintLOD), this);
  }

  /**
   * Address: 0x005184F0 (FUN_005184F0, scalar deleting destructor thunk)
   */
  RMeshBlueprintLODTypeInfo::~RMeshBlueprintLODTypeInfo() = default;

  /**
   * Address: 0x005184E0 (FUN_005184E0)
   */
  const char* RMeshBlueprintLODTypeInfo::GetName() const
  {
    return "RMeshBlueprintLOD";
  }

  /**
   * Address: 0x00518590 (FUN_00518590, Moho::RMeshBlueprintLODTypeInfo::AddFields)
   *
   * What it does:
   * Publishes reflected LOD field metadata with version/descriptions.
   */
  void RMeshBlueprintLODTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "MeshName", CachedStringType(), 0x00, "Name of mesh to use for this LOD");
    AddFieldWithDescription(typeInfo, "AlbedoName", CachedStringType(), 0x1C, "Name of the albedo to use for this LOD");
    AddFieldWithDescription(typeInfo, "NormalsName", CachedStringType(), 0x38, "Name of the normal map to use for this LOD");
    AddFieldWithDescription(typeInfo, "SpecularName", CachedStringType(), 0x54, "Name of the specular map to use for this LOD");
    AddFieldWithDescription(typeInfo, "LookupName", CachedStringType(), 0x70, "Name of the lookup map to use for this LOD");
    AddFieldWithDescription(typeInfo, "SecondaryName", CachedStringType(), 0x8C, "Name of the secondary map to use for this LOD");
    AddFieldWithDescription(typeInfo, "ShaderName", CachedStringType(), 0xA8, "Name of the shader group to use for this LOD");
    AddFieldWithDescription(typeInfo, "LODCutoff", CachedFloatType(), 0xC4, "Zoom level at which this guy starts fading out");
    AddFieldWithDescription(
      typeInfo,
      "Scrolling",
      CachedBoolType(),
      0xC8,
      "True if this requires texture scrolling in the shader"
    );
    AddFieldWithDescription(
      typeInfo,
      "Occlude",
      CachedBoolType(),
      0xC9,
      "True if this may occlude other meshes (for silhouette generation)"
    );
    AddFieldWithDescription(
      typeInfo,
      "Silhouette",
      CachedBoolType(),
      0xCA,
      "True if this can generate a silhouette if blocked by an occluder"
    );
  }

  /**
   * Address: 0x005184C0 (FUN_005184C0)
   *
   * What it does:
   * Sets `RMeshBlueprintLOD` size, initializes base reflection state,
   * publishes LOD field descriptors, and finalizes the descriptor.
   */
  void RMeshBlueprintLODTypeInfo::Init()
  {
    size_ = sizeof(RMeshBlueprintLOD);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8510 (FUN_00BC8510)
   *
   * What it does:
   * Materializes and startup-registers `RMeshBlueprintLODTypeInfo`, then
   * installs process-exit cleanup.
   */
  int register_RMeshBlueprintLODTypeInfo()
  {
    (void)AcquireRMeshBlueprintLODTypeInfo();
    return std::atexit(&cleanup_RMeshBlueprintLODTypeInfoStorage);
  }

  /**
   * Address: 0x0051A6D0 (FUN_0051A6D0)
   *
   * What it does:
   * Constructs/preregisters RTTI for `msvc8::vector<RMeshBlueprintLOD>`.
   */
  gpg::RType* preregister_VectorRMeshBlueprintLODType()
  {
    auto* const typeInfo = &AcquireRMeshBlueprintLODVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<RMeshBlueprintLOD>), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BC85C0 (FUN_00BC85C0)
   *
   * What it does:
   * Registers `vector<RMeshBlueprintLOD>` reflection and installs process-exit
   * teardown.
   */
  int register_VectorRMeshBlueprintLODTypeAtexit()
  {
    (void)preregister_VectorRMeshBlueprintLODType();
    return std::atexit(&cleanup_VectorRMeshBlueprintLODTypeStorage);
  }
} // namespace moho
