#include "moho/sim/ReconBlipTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/entity/Entity.h"
#include "moho/sim/ReconBlip.h"

namespace
{
  class SPerArmyReconInfoTypeInfoRuntime final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SPerArmyReconInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::SPerArmyReconInfo);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(
    sizeof(SPerArmyReconInfoTypeInfoRuntime) == 0x64, "SPerArmyReconInfoTypeInfoRuntime size must be 0x64"
  );

  [[nodiscard]] gpg::RType* ResolveSPerArmyReconInfoType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPerArmyReconInfo));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("SPerArmyReconInfo");
      }
    }
    return cached;
  }

  class SPerArmyReconInfoVectorTypeRuntime final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
    }

    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override
    {
      return this;
    }

    void Init() override
    {
      size_ = sizeof(msvc8::vector<moho::SPerArmyReconInfo>);
      version_ = 1;
    }

    gpg::RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      auto* const storage = static_cast<msvc8::vector<moho::SPerArmyReconInfo>*>(obj);

      gpg::RRef out{};
      out.mObj = nullptr;
      out.mType = ResolveSPerArmyReconInfoType();
      if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
        return out;
      }

      out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
      return out;
    }

    size_t GetCount(void* const obj) const override
    {
      const auto* const storage = static_cast<const msvc8::vector<moho::SPerArmyReconInfo>*>(obj);
      return storage ? storage->size() : 0u;
    }

    void SetCount(void* const obj, const int count) const override
    {
      auto* const storage = static_cast<msvc8::vector<moho::SPerArmyReconInfo>*>(obj);
      GPG_ASSERT(storage != nullptr);
      GPG_ASSERT(count >= 0);
      if (!storage || count < 0) {
        return;
      }

      const moho::SPerArmyReconInfo zeroFill{};
      storage->resize(static_cast<std::size_t>(count), zeroFill);
    }
  };
  static_assert(
    sizeof(SPerArmyReconInfoVectorTypeRuntime) == 0x68, "SPerArmyReconInfoVectorTypeRuntime size must be 0x68"
  );

  using moho::ReconBlipTypeInfo;

  alignas(moho::ReconBlipTypeInfo) unsigned char gReconBlipTypeInfoStorage[sizeof(moho::ReconBlipTypeInfo)];
  bool gReconBlipTypeInfoConstructed = false;
  alignas(SPerArmyReconInfoTypeInfoRuntime) unsigned char gSPerArmyReconInfoTypeInfoStorage[sizeof(SPerArmyReconInfoTypeInfoRuntime)];
  bool gSPerArmyReconInfoTypeInfoConstructed = false;
  alignas(SPerArmyReconInfoVectorTypeRuntime) unsigned char gSPerArmyReconInfoVectorTypeStorage[sizeof(SPerArmyReconInfoVectorTypeRuntime)];
  bool gSPerArmyReconInfoVectorTypeConstructed = false;
  msvc8::string gSPerArmyReconInfoVectorTypeName;
  bool gSPerArmyReconInfoVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] moho::ReconBlipTypeInfo* AcquireReconBlipTypeInfo()
  {
    if (!gReconBlipTypeInfoConstructed) {
      new (gReconBlipTypeInfoStorage) moho::ReconBlipTypeInfo();
      gReconBlipTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ReconBlipTypeInfo*>(gReconBlipTypeInfoStorage);
  }

  [[nodiscard]] SPerArmyReconInfoTypeInfoRuntime* AcquireSPerArmyReconInfoTypeInfo()
  {
    if (!gSPerArmyReconInfoTypeInfoConstructed) {
      new (gSPerArmyReconInfoTypeInfoStorage) SPerArmyReconInfoTypeInfoRuntime();
      gSPerArmyReconInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<SPerArmyReconInfoTypeInfoRuntime*>(gSPerArmyReconInfoTypeInfoStorage);
  }

  [[nodiscard]] SPerArmyReconInfoVectorTypeRuntime* AcquireSPerArmyReconInfoVectorType()
  {
    if (!gSPerArmyReconInfoVectorTypeConstructed) {
      new (gSPerArmyReconInfoVectorTypeStorage) SPerArmyReconInfoVectorTypeRuntime();
      gSPerArmyReconInfoVectorTypeConstructed = true;
    }

    return reinterpret_cast<SPerArmyReconInfoVectorTypeRuntime*>(gSPerArmyReconInfoVectorTypeStorage);
  }

  /**
   * Address: 0x00BF7870 (FUN_00BF7870, cleanup_ReconBlipTypeInfo)
   *
   * What it does:
   * Tears down recovered static `ReconBlipTypeInfo` storage.
   */
  void cleanup_ReconBlipTypeInfo()
  {
    if (!gReconBlipTypeInfoConstructed) {
      return;
    }

    AcquireReconBlipTypeInfo()->~ReconBlipTypeInfo();
    gReconBlipTypeInfoConstructed = false;
  }

  void cleanup_SPerArmyReconInfoVectorTypeName()
  {
    gSPerArmyReconInfoVectorTypeName = msvc8::string{};
    gSPerArmyReconInfoVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x005C3E50 (FUN_005C3E50, gpg::RVectorType_SPerArmyReconInfo::GetName)
   *
   * What it does:
   * Lazily formats and caches the reflected type label for
   * `vector<SPerArmyReconInfo>` using the registered element RTTI name.
   */
  const char* SPerArmyReconInfoVectorTypeRuntime::GetName() const
  {
    if (gSPerArmyReconInfoVectorTypeName.empty()) {
      gpg::RType* const valueType = ResolveSPerArmyReconInfoType();
      const char* const valueTypeName = valueType ? valueType->GetName() : "SPerArmyReconInfo";
      gSPerArmyReconInfoVectorTypeName = gpg::STR_Printf("vector<%s>", valueTypeName ? valueTypeName : "SPerArmyReconInfo");
      if (!gSPerArmyReconInfoVectorTypeNameCleanupRegistered) {
        gSPerArmyReconInfoVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_SPerArmyReconInfoVectorTypeName);
      }
    }

    return gSPerArmyReconInfoVectorTypeName.c_str();
  }

  struct ReconBlipTypeInfoBootstrap
  {
    ReconBlipTypeInfoBootstrap()
    {
      moho::register_ReconBlipTypeInfo();
      (void)moho::register_SPerArmyReconInfoTypeInfo();
      (void)moho::register_RVectorType_SPerArmyReconInfo();
    }
  };

  [[maybe_unused]] ReconBlipTypeInfoBootstrap gReconBlipTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005BE590 (FUN_005BE590, Moho::ReconBlipTypeInfo::ReconBlipTypeInfo)
   */
  ReconBlipTypeInfo::ReconBlipTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ReconBlip), this);
  }

  /**
   * Address: 0x005BE630 (FUN_005BE630, Moho::ReconBlipTypeInfo::dtr)
   */
  ReconBlipTypeInfo::~ReconBlipTypeInfo() = default;

  /**
   * Address: 0x005BE620 (FUN_005BE620, Moho::ReconBlipTypeInfo::GetName)
   */
  const char* ReconBlipTypeInfo::GetName() const
  {
    return "ReconBlip";
  }

  /**
   * Address: 0x005BE5F0 (FUN_005BE5F0, Moho::ReconBlipTypeInfo::Init)
   */
  void ReconBlipTypeInfo::Init()
  {
    size_ = sizeof(ReconBlip);
    AddBase_Entity(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x005C9010 (FUN_005C9010)
   */
  void ReconBlipTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    static gpg::RType* cachedEntityType = nullptr;
    if (!cachedEntityType) {
      cachedEntityType = gpg::LookupRType(typeid(Entity));
    }

    gpg::RField baseField{};
    baseField.mName = cachedEntityType->GetName();
    baseField.mType = cachedEntityType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BCDC50 (FUN_00BCDC50, register_ReconBlipTypeInfo)
   *
   * What it does:
   * Constructs the recovered `ReconBlipTypeInfo` helper and installs
   * process-exit cleanup.
   */
  void register_ReconBlipTypeInfo()
  {
    (void)AcquireReconBlipTypeInfo();
    (void)std::atexit(&cleanup_ReconBlipTypeInfo);
  }

  /**
   * Address: 0x005BE380 (FUN_005BE380, sub_5BE380)
   *
   * What it does:
   * Constructs/preregisters RTTI for `SPerArmyReconInfo`.
   */
  gpg::RType* preregister_SPerArmyReconInfoTypeInfo()
  {
    auto* const type = AcquireSPerArmyReconInfoTypeInfo();
    gpg::PreRegisterRType(typeid(SPerArmyReconInfo), type);
    return type;
  }

  /**
   * Address: 0x00BF77E0 (FUN_00BF77E0, sub_BF77E0)
   *
   * What it does:
   * Tears down startup-owned `SPerArmyReconInfo` RTTI storage.
   */
  void cleanup_SPerArmyReconInfoTypeInfo()
  {
    if (!gSPerArmyReconInfoTypeInfoConstructed) {
      return;
    }

    AcquireSPerArmyReconInfoTypeInfo()->~SPerArmyReconInfoTypeInfoRuntime();
    gSPerArmyReconInfoTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BCDBB0 (FUN_00BCDBB0, sub_BCDBB0)
   *
   * What it does:
   * Registers `SPerArmyReconInfo` RTTI and installs process-exit cleanup.
   */
  int register_SPerArmyReconInfoTypeInfo()
  {
    (void)preregister_SPerArmyReconInfoTypeInfo();
    return std::atexit(&cleanup_SPerArmyReconInfoTypeInfo);
  }

  /**
   * Address: 0x005CA510 (FUN_005CA510, sub_5CA510)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `msvc8::vector<SPerArmyReconInfo>`.
   */
  gpg::RType* preregister_RVectorType_SPerArmyReconInfo()
  {
    auto* const type = AcquireSPerArmyReconInfoVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<SPerArmyReconInfo>), type);
    return type;
  }

  /**
   * Address: 0x00BF7D20 (FUN_00BF7D20, sub_BF7D20)
   *
   * What it does:
   * Tears down startup-owned `vector<SPerArmyReconInfo>` reflection storage.
   */
  void cleanup_RVectorType_SPerArmyReconInfo()
  {
    if (!gSPerArmyReconInfoVectorTypeConstructed) {
      return;
    }

    AcquireSPerArmyReconInfoVectorType()->~SPerArmyReconInfoVectorTypeRuntime();
    gSPerArmyReconInfoVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BCDF00 (FUN_00BCDF00, sub_BCDF00)
   *
   * What it does:
   * Registers `vector<SPerArmyReconInfo>` reflection metadata and installs
   * process-exit cleanup.
   */
  int register_RVectorType_SPerArmyReconInfo()
  {
    (void)preregister_RVectorType_SPerArmyReconInfo();
    return std::atexit(&cleanup_RVectorType_SPerArmyReconInfo);
  }
} // namespace moho
