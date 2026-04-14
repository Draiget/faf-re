#include "REmitterCurveTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"

namespace
{
  using CurveTypeInfo = moho::REmitterBlueprintCurveTypeInfo;
  using CurveKeyTypeInfo = moho::REmitterCurveKeyTypeInfo;
  using CurveKeyVector = msvc8::vector<moho::REmitterCurveKey>;

  class CurveKeyVectorTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x00515C60 (FUN_00515C60, gpg::RVectorType_REmitterCurveKey::GetLexical)
     *
     * What it does:
     * Returns base lexical text plus reflected vector size for one
     * `msvc8::vector<moho::REmitterCurveKey>` instance.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    /**
     * Address: 0x00515C40 (FUN_00515C40, gpg::RVectorType_REmitterCurveKey::Init)
     */
    void Init() override;
    /**
     * Address: 0x00516100 (FUN_00516100, gpg::RVectorType_REmitterCurveKey::SerLoad)
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    /**
     * Address: 0x00516230 (FUN_00516230, gpg::RVectorType_REmitterCurveKey::SerSave)
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(CurveKeyVectorTypeInfo) == 0x68, "CurveKeyVectorTypeInfo size must be 0x68");

  alignas(CurveTypeInfo) unsigned char gREmitterBlueprintCurveTypeInfoStorage[sizeof(CurveTypeInfo)];
  bool gREmitterBlueprintCurveTypeInfoConstructed = false;

  alignas(CurveKeyTypeInfo) unsigned char gREmitterCurveKeyTypeInfoStorage[sizeof(CurveKeyTypeInfo)];
  bool gREmitterCurveKeyTypeInfoConstructed = false;

  alignas(CurveKeyVectorTypeInfo) unsigned char gREmitterCurveKeyVectorTypeStorage[sizeof(CurveKeyVectorTypeInfo)];
  bool gREmitterCurveKeyVectorTypeConstructed = false;

  [[nodiscard]] gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
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

  [[nodiscard]] gpg::RType* CachedEmitterCurveKeyType()
  {
    if (!moho::REmitterCurveKey::sType) {
      moho::REmitterCurveKey::sType = gpg::LookupRType(typeid(moho::REmitterCurveKey));
    }
    return moho::REmitterCurveKey::sType;
  }

  [[nodiscard]] gpg::RType* CachedEmitterBlueprintCurveType()
  {
    if (!moho::REmitterBlueprintCurve::sType) {
      moho::REmitterBlueprintCurve::sType = gpg::LookupRType(typeid(moho::REmitterBlueprintCurve));
    }
    return moho::REmitterBlueprintCurve::sType;
  }

  [[nodiscard]] gpg::RType* CachedEmitterCurveKeyVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CurveKeyVector));
    }
    return cached;
  }

  /**
   * Address: 0x00515BA0 (FUN_00515BA0, gpg::RVectorType_REmitterCurveKey::GetName)
   *
   * What it does:
   * Builds and caches lexical reflection name `vector<element>` for
   * `msvc8::vector<moho::REmitterCurveKey>`.
   */
  const char* CurveKeyVectorTypeInfo::GetName() const
  {
    static msvc8::string cachedName{};
    if (cachedName.empty()) {
      const gpg::RType* const elementType = CachedEmitterCurveKeyType();
      const char* const elementName = elementType ? elementType->GetName() : "REmitterCurveKey";
      cachedName = gpg::STR_Printf("vector<%s>", elementName);
    }
    return cachedName.c_str();
  }

  /**
   * Address: 0x00515C60 (FUN_00515C60, gpg::RVectorType_REmitterCurveKey::GetLexical)
   *
   * What it does:
   * Returns base lexical text plus reflected vector size for one
   * `msvc8::vector<moho::REmitterCurveKey>` instance.
   */
  msvc8::string CurveKeyVectorTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* CurveKeyVectorTypeInfo::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00515C40 (FUN_00515C40, gpg::RVectorType_REmitterCurveKey::Init)
   *
   * What it does:
   * Sets vector type metadata and installs serializer callbacks for
   * `msvc8::vector<moho::REmitterCurveKey>`.
   */
  void CurveKeyVectorTypeInfo::Init()
  {
    size_ = sizeof(CurveKeyVector);
    version_ = 1;
    serLoadFunc_ = &CurveKeyVectorTypeInfo::SerLoad;
    serSaveFunc_ = &CurveKeyVectorTypeInfo::SerSave;
  }

  /**
   * Address: 0x00516100 (FUN_00516100, gpg::RVectorType_REmitterCurveKey::SerLoad)
   *
   * What it does:
   * Reads vector element count, deserializes each `REmitterCurveKey` element,
   * and replaces destination storage with the loaded sequence.
   */
  void CurveKeyVectorTypeInfo::SerLoad(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<CurveKeyVector*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    CurveKeyVector loaded;
    loaded.reserve(static_cast<std::size_t>(count));

    gpg::RType* const elementType = CachedEmitterCurveKeyType();
    for (unsigned int index = 0u; index < count; ++index) {
      moho::REmitterCurveKey key{};
      gpg::RRef elementOwner{};
      archive->Read(elementType, &key, elementOwner);
      loaded.push_back(key);
    }

    *destination = loaded;
  }

  /**
   * Address: 0x00516230 (FUN_00516230, gpg::RVectorType_REmitterCurveKey::SerSave)
   *
   * What it does:
   * Writes vector size and serializes each `REmitterCurveKey` element using
   * reflected write callbacks.
   */
  void CurveKeyVectorTypeInfo::SerSave(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const CurveKeyVector*>(objectPtr);
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);

    if (source == nullptr || count == 0u) {
      return;
    }

    const gpg::RType* const elementType = CachedEmitterCurveKeyType();
    gpg::RRef emptyOwner{};
    const gpg::RRef& effectiveOwner = ownerRef != nullptr ? *ownerRef : emptyOwner;
    for (const moho::REmitterCurveKey& element : *source) {
      archive->Write(elementType, &element, effectiveOwner);
    }
  }

  gpg::RRef CurveKeyVectorTypeInfo::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedEmitterCurveKeyType();
    out.mObj = nullptr;

    auto* const storage = static_cast<CurveKeyVector*>(obj);
    if (storage == nullptr || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
      return out;
    }

    out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
    return out;
  }

  size_t CurveKeyVectorTypeInfo::GetCount(void* const obj) const
  {
    const auto* const storage = static_cast<const CurveKeyVector*>(obj);
    return storage ? storage->size() : 0u;
  }

  void CurveKeyVectorTypeInfo::SetCount(void* const obj, const int count) const
  {
    if (obj == nullptr || count < 0) {
      return;
    }

    auto* const storage = static_cast<CurveKeyVector*>(obj);
    storage->resize(static_cast<std::size_t>(count));
  }

  [[nodiscard]] CurveTypeInfo& AcquireREmitterBlueprintCurveTypeInfo()
  {
    if (!gREmitterBlueprintCurveTypeInfoConstructed) {
      new (gREmitterBlueprintCurveTypeInfoStorage) CurveTypeInfo();
      gREmitterBlueprintCurveTypeInfoConstructed = true;
    }

    return *reinterpret_cast<CurveTypeInfo*>(gREmitterBlueprintCurveTypeInfoStorage);
  }

  [[nodiscard]] CurveKeyTypeInfo& AcquireREmitterCurveKeyTypeInfo()
  {
    if (!gREmitterCurveKeyTypeInfoConstructed) {
      new (gREmitterCurveKeyTypeInfoStorage) CurveKeyTypeInfo();
      gREmitterCurveKeyTypeInfoConstructed = true;
    }

    return *reinterpret_cast<CurveKeyTypeInfo*>(gREmitterCurveKeyTypeInfoStorage);
  }

  [[nodiscard]] CurveKeyVectorTypeInfo& AcquireREmitterCurveKeyVectorTypeInfo()
  {
    if (!gREmitterCurveKeyVectorTypeConstructed) {
      new (gREmitterCurveKeyVectorTypeStorage) CurveKeyVectorTypeInfo();
      gREmitterCurveKeyVectorTypeConstructed = true;
    }

    return *reinterpret_cast<CurveKeyVectorTypeInfo*>(gREmitterCurveKeyVectorTypeStorage);
  }

  void cleanup_REmitterBlueprintCurveTypeInfo()
  {
    if (!gREmitterBlueprintCurveTypeInfoConstructed) {
      return;
    }

    AcquireREmitterBlueprintCurveTypeInfo().~CurveTypeInfo();
    gREmitterBlueprintCurveTypeInfoConstructed = false;
  }

  void cleanup_REmitterCurveKeyTypeInfo()
  {
    if (!gREmitterCurveKeyTypeInfoConstructed) {
      return;
    }

    AcquireREmitterCurveKeyTypeInfo().~CurveKeyTypeInfo();
    gREmitterCurveKeyTypeInfoConstructed = false;
  }

  void cleanup_VectorREmitterCurveKeyType()
  {
    if (!gREmitterCurveKeyVectorTypeConstructed) {
      return;
    }

    AcquireREmitterCurveKeyVectorTypeInfo().~CurveKeyVectorTypeInfo();
    gREmitterCurveKeyVectorTypeConstructed = false;
  }

  [[nodiscard]] gpg::RRef MakeEmitterCurveRef(moho::REmitterBlueprintCurve* object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedEmitterBlueprintCurveType();
    return out;
  }

  /**
   * Address: 0x005166A0 (FUN_005166A0, Moho::REmitterBlueprintCurveTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `REmitterBlueprintCurve`, runs constructor initialization,
   * and returns a typed reflection reference.
   */
  [[nodiscard]] gpg::RRef NewEmitterCurveRef()
  {
    return MakeEmitterCurveRef(new moho::REmitterBlueprintCurve());
  }

  void DeleteEmitterCurveObject(void* objectMemory)
  {
    delete static_cast<moho::REmitterBlueprintCurve*>(objectMemory);
  }

  void DestructEmitterCurveObject(void* objectMemory)
  {
    if (!objectMemory) {
      return;
    }

    static_cast<moho::REmitterBlueprintCurve*>(objectMemory)->~REmitterBlueprintCurve();
  }

  [[nodiscard]] gpg::RRef MakeEmitterCurveKeyRef(moho::REmitterCurveKey* object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedEmitterCurveKeyType();
    return out;
  }

  [[nodiscard]] gpg::RRef NewEmitterCurveKeyRef()
  {
    return MakeEmitterCurveKeyRef(new moho::REmitterCurveKey());
  }

  [[nodiscard]] gpg::RRef ConstructEmitterCurveKeyRef(void* objectMemory)
  {
    if (!objectMemory) {
      return MakeEmitterCurveKeyRef(nullptr);
    }

    auto* const object = new (objectMemory) moho::REmitterCurveKey();
    return MakeEmitterCurveKeyRef(object);
  }

  void DeleteEmitterCurveKeyObject(void* objectMemory)
  {
    delete static_cast<moho::REmitterCurveKey*>(objectMemory);
  }

  void DestructEmitterCurveKeyObject(void* objectMemory)
  {
    if (!objectMemory) {
      return;
    }

    static_cast<moho::REmitterCurveKey*>(objectMemory)->~REmitterCurveKey();
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

  struct REmitterCurveTypeInfoBootstrap
  {
    REmitterCurveTypeInfoBootstrap()
    {
      (void)moho::register_REmitterBlueprintCurveTypeInfo();
      (void)moho::register_REmitterCurveKeyTypeInfo();
      (void)moho::register_VectorREmitterCurveKeyTypeAtexit();
    }
  };

  REmitterCurveTypeInfoBootstrap gREmitterCurveTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00515400 (FUN_00515400, Moho::REmitterBlueprintCurveTypeInfo::REmitterBlueprintCurveTypeInfo)
   */
  REmitterBlueprintCurveTypeInfo::REmitterBlueprintCurveTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REmitterBlueprintCurve), this);
  }

  /**
   * Address: 0x005154E0 (FUN_005154E0, scalar deleting destructor thunk)
   */
  REmitterBlueprintCurveTypeInfo::~REmitterBlueprintCurveTypeInfo() = default;

  /**
   * Address: 0x005154D0 (FUN_005154D0)
   */
  const char* REmitterBlueprintCurveTypeInfo::GetName() const
  {
    return "REmitterBlueprintCurve";
  }

  /**
   * Address: 0x00516EC0 (FUN_00516EC0)
   */
  void REmitterBlueprintCurveTypeInfo::AddBaseRObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRObjectType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00516F20 (FUN_00516F20)
   */
  void REmitterBlueprintCurveTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "XRange", CachedFloatType(), 0x04, "Range of X for this curve.");
    AddFieldWithDescription(typeInfo, "Keys", CachedEmitterCurveKeyVectorType(), 0x08, "Keys for this curve.");
  }

  /**
   * Address: 0x00515460 (FUN_00515460)
   *
   * What it does:
   * Sets curve type metadata, binds object lifetime callbacks, and publishes
   * `XRange`/`Keys` reflection fields.
   */
  void REmitterBlueprintCurveTypeInfo::Init()
  {
    size_ = sizeof(REmitterBlueprintCurve);
    newRefFunc_ = &NewEmitterCurveRef;
    ctorRefFunc_ = &REmitterBlueprintCurveTypeInfo::CtrRef;
    deleteFunc_ = &DeleteEmitterCurveObject;
    dtrFunc_ = &DestructEmitterCurveObject;
    AddBaseRObject(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00516740 (FUN_00516740, Moho::REmitterBlueprintCurveTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `REmitterBlueprintCurve` in caller-provided storage and
   * returns a typed reflection reference for that object.
   */
  gpg::RRef REmitterBlueprintCurveTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const curve = static_cast<REmitterBlueprintCurve*>(objectStorage);
    if (curve != nullptr) {
      new (curve) REmitterBlueprintCurve();
    }

    gpg::RRef curveRef{};
    gpg::RRef_REmitterBlueprintCurve(&curveRef, curve);
    return curveRef;
  }

  /**
   * Address: 0x005155C0 (FUN_005155C0, Moho::REmitterCurveKeyTypeInfo::REmitterCurveKeyTypeInfo)
   */
  REmitterCurveKeyTypeInfo::REmitterCurveKeyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(REmitterCurveKey), this);
  }

  /**
   * Address: 0x00515680 (FUN_00515680, scalar deleting destructor thunk)
   */
  REmitterCurveKeyTypeInfo::~REmitterCurveKeyTypeInfo() = default;

  /**
   * Address: 0x00515670 (FUN_00515670)
   */
  const char* REmitterCurveKeyTypeInfo::GetName() const
  {
    return "REmitterCurveKey";
  }

  /**
   * Address: 0x00516FA0 (FUN_00516FA0)
   */
  void REmitterCurveKeyTypeInfo::AddBaseRObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRObjectType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00515720 (FUN_00515720)
   */
  void REmitterCurveKeyTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "x", CachedFloatType(), 0x04, "X pos of this curve.");
    AddFieldWithDescription(typeInfo, "y", CachedFloatType(), 0x08, "Y pos of this curve.");
    AddFieldWithDescription(typeInfo, "z", CachedFloatType(), 0x0C, "Z size of this curve.");
  }

  /**
   * Address: 0x00515620 (FUN_00515620)
   *
   * What it does:
   * Sets curve-key metadata, binds object lifetime callbacks, and publishes
   * `x/y/z` reflection fields.
   */
  void REmitterCurveKeyTypeInfo::Init()
  {
    size_ = sizeof(REmitterCurveKey);
    newRefFunc_ = &NewEmitterCurveKeyRef;
    ctorRefFunc_ = &ConstructEmitterCurveKeyRef;
    deleteFunc_ = &DeleteEmitterCurveKeyObject;
    dtrFunc_ = &DestructEmitterCurveKeyObject;
    AddBaseRObject(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8480 (FUN_00BC8480, register_REmitterBlueprintCurveTypeInfo)
   */
  int register_REmitterBlueprintCurveTypeInfo()
  {
    (void)AcquireREmitterBlueprintCurveTypeInfo();
    return std::atexit(&cleanup_REmitterBlueprintCurveTypeInfo);
  }

  /**
   * Address: 0x00BC84A0 (FUN_00BC84A0, register_REmitterCurveKeyTypeInfo)
   */
  int register_REmitterCurveKeyTypeInfo()
  {
    (void)AcquireREmitterCurveKeyTypeInfo();
    return std::atexit(&cleanup_REmitterCurveKeyTypeInfo);
  }

  /**
   * Address: 0x00517420 (FUN_00517420, preregister_VectorREmitterCurveKeyType)
   *
   * What it does:
   * Constructs/preregisters RTTI for `vector<REmitterCurveKey>`.
   */
  gpg::RType* preregister_VectorREmitterCurveKeyType()
  {
    auto* const typeInfo = &AcquireREmitterCurveKeyVectorTypeInfo();
    gpg::PreRegisterRType(typeid(msvc8::vector<REmitterCurveKey>), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BC84E0 (FUN_00BC84E0, register_VectorREmitterCurveKeyTypeAtexit)
   *
   * What it does:
   * Registers `vector<REmitterCurveKey>` reflection and installs `atexit`
   * teardown.
   */
  int register_VectorREmitterCurveKeyTypeAtexit()
  {
    (void)preregister_VectorREmitterCurveKeyType();
    return std::atexit(&cleanup_VectorREmitterCurveKeyType);
  }
} // namespace moho
