#include "moho/misc/LaunchInfoBase.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/STIMap.h"

namespace
{
  using ArmyLaunchInfoVector = msvc8::vector<moho::ArmyLaunchInfo>;

  class ArmyLaunchInfoVectorTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005448D0 (FUN_005448D0, scalar deleting destructor thunk)
     */
    ~ArmyLaunchInfoVectorTypeInfo() override;

    /**
     * Address: 0x00542F60 (FUN_00542F60)
     *
     * What it does:
     * Lazily builds and returns the reflected type name for
     * `vector<ArmyLaunchInfo>`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00543020 (FUN_00543020)
     *
     * What it does:
     * Formats base lexical text with indexed element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x005430B0 (FUN_005430B0)
     *
     * What it does:
     * Returns indexed-view support for `vector<ArmyLaunchInfo>`.
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00543000 (FUN_00543000)
     *
     * What it does:
     * Sets reflected size/version lanes and wires vector serialization
     * callbacks for `ArmyLaunchInfo`.
     */
    void Init() override;

    /**
     * Address: 0x00543120 (FUN_00543120)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005430C0 (FUN_005430C0)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x005430E0 (FUN_005430E0)
     */
    void SetCount(void* obj, int count) const override;

    /**
     * Address: 0x00543530 (FUN_00543530)
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005436C0 (FUN_005436C0)
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  static_assert(sizeof(ArmyLaunchInfoVectorTypeInfo) == 0x68, "ArmyLaunchInfoVectorTypeInfo size must be 0x68");

  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  moho::ArmyLaunchInfoTypeInfo gArmyLaunchInfoTypeInfo;
  ArmyLaunchInfoVectorTypeInfo gArmyLaunchInfoVectorTypeInfo;
  moho::LaunchInfoBaseTypeInfo gLaunchInfoBaseTypeInfo;
  moho::LaunchInfoBaseSerializer gLaunchInfoBaseSerializer;

  alignas(moho::LaunchInfoNewTypeInfo) unsigned char
    gLaunchInfoNewTypeInfoStorage[sizeof(moho::LaunchInfoNewTypeInfo)]{};
  bool gLaunchInfoNewTypeInfoConstructed = false;

  alignas(moho::ArmyLaunchInfoSerializer) unsigned char
    gArmyLaunchInfoSerializerStorage[sizeof(moho::ArmyLaunchInfoSerializer)]{};
  bool gArmyLaunchInfoSerializerConstructed = false;

  alignas(moho::LaunchInfoNewSerializer) unsigned char
    gLaunchInfoNewSerializerStorage[sizeof(moho::LaunchInfoNewSerializer)]{};
  bool gLaunchInfoNewSerializerConstructed = false;

  bool gArmyLaunchInfoTypeRegistered = false;
  bool gArmyLaunchInfoVectorTypeRegistered = false;
  msvc8::string gArmyLaunchInfoVectorTypeName;
  bool gArmyLaunchInfoVectorTypeNameCleanupRegistered = false;
  gpg::RType* gArmyLaunchInfoVectorType = nullptr;
  gpg::RType* gStringVectorType = nullptr;

  [[nodiscard]] moho::LaunchInfoNewTypeInfo& LaunchInfoNewTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::LaunchInfoNewTypeInfo*>(gLaunchInfoNewTypeInfoStorage);
  }

  [[nodiscard]] moho::ArmyLaunchInfoSerializer& ArmyLaunchInfoSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::ArmyLaunchInfoSerializer*>(gArmyLaunchInfoSerializerStorage);
  }

  [[nodiscard]] moho::LaunchInfoNewSerializer& LaunchInfoNewSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::LaunchInfoNewSerializer*>(gLaunchInfoNewSerializerStorage);
  }

  /**
   * Address: 0x00542080 (FUN_00542080)
   *
   * What it does:
   * Startup lane that preregisters reflected RTTI metadata for
   * `ArmyLaunchInfo`.
   */
  [[nodiscard]] gpg::RType* RegisterArmyLaunchInfoTypeInfoStartup()
  {
    if (!gArmyLaunchInfoTypeRegistered) {
      gpg::PreRegisterRType(typeid(moho::ArmyLaunchInfo), &gArmyLaunchInfoTypeInfo);
      gArmyLaunchInfoTypeRegistered = true;
    }

    return &gArmyLaunchInfoTypeInfo;
  }

  /**
   * Address: 0x00545470 (FUN_00545470)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for
   * `msvc8::vector<moho::ArmyLaunchInfo>`.
   */
  [[nodiscard]] gpg::RType* ResolveArmyLaunchInfoVectorTypeFast()
  {
    gpg::RType* type = gArmyLaunchInfoVectorType;
    if (!type) {
      type = gpg::LookupRType(typeid(ArmyLaunchInfoVector));
      gArmyLaunchInfoVectorType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveArmyLaunchInfoVectorType()
  {
    (void)RegisterArmyLaunchInfoTypeInfoStartup();

    if (!gArmyLaunchInfoVectorTypeRegistered) {
      (void)moho::preregister_ArmyLaunchInfoVectorTypeStartup();
    }

    gpg::RType* type = ResolveArmyLaunchInfoVectorTypeFast();
    if (!type) {
      type = gpg::REF_FindTypeNamed("vector<ArmyLaunchInfo>");
      if (!type) {
        type = gpg::REF_FindTypeNamed("vector<Moho::ArmyLaunchInfo>");
      }
      gArmyLaunchInfoVectorType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveArmyLaunchInfoType()
  {
    if (!moho::ArmyLaunchInfo::sType) {
      moho::ArmyLaunchInfo::sType = gpg::LookupRType(typeid(moho::ArmyLaunchInfo));
    }
    return moho::ArmyLaunchInfo::sType;
  }

  [[nodiscard]] gpg::RType* ResolveLaunchInfoNewType()
  {
    if (!gLaunchInfoNewTypeInfoConstructed) {
      new (gLaunchInfoNewTypeInfoStorage) moho::LaunchInfoNewTypeInfo();
      gLaunchInfoNewTypeInfoConstructed = true;
    }
    return gpg::LookupRType(typeid(moho::LaunchInfoNew));
  }

  [[nodiscard]] gpg::RType* ResolveStringVectorType()
  {
    if (!gStringVectorType) {
      gStringVectorType = gpg::LookupRType(typeid(msvc8::vector<msvc8::string>));
    }
    return gStringVectorType;
  }

  /**
   * Address: 0x00543200 (FUN_00543200)
   *
   * What it does:
   * Wires the reflected `LaunchInfoNew` constructor and destructor callback
   * lanes into an initialized `gpg::RType` descriptor.
   */
  void InitializeLaunchInfoNewTypeInfoCallbacks(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    if (!typeInfo) {
      return;
    }

    typeInfo->newRefFunc_ = &moho::LaunchInfoNewTypeInfo::NewRef;
    typeInfo->deleteFunc_ = &moho::LaunchInfoNewTypeInfo::Delete;
    typeInfo->ctorRefFunc_ = &moho::LaunchInfoNewTypeInfo::CtrRef;
    typeInfo->dtrFunc_ = &moho::LaunchInfoNewTypeInfo::Destruct;
  }

  /**
   * Address: 0x00544870 (FUN_00544870)
   *
   * What it does:
   * Lazily resolves `ArmyLaunchInfo` reflection type and dispatches one
   * archive read for the provided object lane.
   */
  void ReadArmyLaunchInfoReflectedObject(
    gpg::ReadArchive* const archive,
    void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = moho::ArmyLaunchInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ArmyLaunchInfo));
      moho::ArmyLaunchInfo::sType = type;
    }
    archive->Read(type, object, ownerRef);
  }

  /**
   * Address: 0x005448A0 (FUN_005448A0)
   *
   * What it does:
   * Lazily resolves `ArmyLaunchInfo` reflection type and dispatches one
   * archive write for the provided object lane.
   */
  void WriteArmyLaunchInfoReflectedObject(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = moho::ArmyLaunchInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::ArmyLaunchInfo));
      moho::ArmyLaunchInfo::sType = type;
    }
    archive->Write(type, object, ownerRef);
  }

  /**
   * Address: 0x00545380 (FUN_00545380)
   *
   * What it does:
   * Lazily resolves `LaunchInfoBase` reflection type and dispatches one
   * archive read for the provided object lane.
   */
  void ReadLaunchInfoBaseReflectedObject(
    gpg::ReadArchive* const archive,
    void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = moho::LaunchInfoBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::LaunchInfoBase));
      moho::LaunchInfoBase::sType = type;
    }
    archive->Read(type, object, ownerRef);
  }

  /**
   * Address: 0x005453B0 (FUN_005453B0)
   *
   * What it does:
   * Lazily resolves `LaunchInfoBase` reflection type and dispatches one
   * archive write for the provided object lane.
   */
  void WriteLaunchInfoBaseReflectedObject(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = moho::LaunchInfoBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::LaunchInfoBase));
      moho::LaunchInfoBase::sType = type;
    }
    archive->Write(type, object, ownerRef);
  }

  /**
   * Address: 0x005453E0 (FUN_005453E0)
   *
   * What it does:
   * Lazily resolves `vector<string>` reflection type and dispatches one archive
   * read for the provided object lane.
   */
  void ReadStringVectorReflectedObject(
    gpg::ReadArchive* const archive,
    void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* const type = ResolveStringVectorType();
    archive->Read(type, object, ownerRef);
  }

  /**
   * Address: 0x00545410 (FUN_00545410)
   *
   * What it does:
   * Lazily resolves `vector<string>` reflection type and dispatches one archive
   * write for the provided object lane.
   */
  void WriteStringVectorReflectedObject(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* const type = ResolveStringVectorType();
    archive->Write(type, object, ownerRef);
  }

  /**
   * Address: 0x00544530 (FUN_00544530)
   *
   * What it does:
   * Lazily resolves `ArmyLaunchInfo` reflection type and dispatches one archive
   * read for the provided object lane.
   */
  gpg::ReadArchive* ReadArmyLaunchInfoArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    ReadArmyLaunchInfoReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x005445A0 (FUN_005445A0)
   *
   * What it does:
   * Lazily resolves `ArmyLaunchInfo` reflection type and dispatches one archive
   * write for the provided object lane.
   */
  gpg::WriteArchive* WriteArmyLaunchInfoArchiveAdapter(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    WriteArmyLaunchInfoReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x005449F0 (FUN_005449F0)
   *
   * What it does:
   * Lazily resolves `vector<ArmyLaunchInfo>` reflection type and dispatches one
   * archive read for the provided object lane.
   */
  gpg::ReadArchive* ReadArmyLaunchInfoVectorArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    gpg::RType* const type = ResolveArmyLaunchInfoVectorType();
    archive->Read(type, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00544A30 (FUN_00544A30)
   *
   * What it does:
   * Lazily resolves `vector<ArmyLaunchInfo>` reflection type and dispatches one
   * archive write for the provided object lane.
   */
  gpg::WriteArchive* WriteArmyLaunchInfoVectorArchiveAdapter(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    gpg::RType* const type = ResolveArmyLaunchInfoVectorType();
    archive->Write(type, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00544B00 (FUN_00544B00)
   *
   * What it does:
   * Lazily resolves `LaunchInfoBase` reflection type and dispatches one archive
   * read for the provided object lane.
   */
  gpg::ReadArchive* ReadLaunchInfoBaseArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    ReadLaunchInfoBaseReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00544B80 (FUN_00544B80)
   *
   * What it does:
   * Lazily resolves `LaunchInfoBase` reflection type and dispatches one archive
   * write for the provided object lane.
   */
  gpg::WriteArchive* WriteLaunchInfoBaseArchiveAdapter(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    WriteLaunchInfoBaseReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00544B40 (FUN_00544B40)
   *
   * What it does:
   * Lazily resolves `vector<string>` reflection type and dispatches one archive
   * read for the provided object lane.
   */
  gpg::ReadArchive* ReadLaunchInfoStringVectorArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    ReadStringVectorReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00544BC0 (FUN_00544BC0)
   *
   * What it does:
   * Lazily resolves `vector<string>` reflection type and dispatches one archive
   * write for the provided object lane.
   */
  gpg::WriteArchive* WriteLaunchInfoStringVectorArchiveAdapter(
    gpg::WriteArchive* const archive,
    const void* const object,
    const gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(ownerRef != nullptr);
    if (!archive || !ownerRef) {
      return archive;
    }

    WriteStringVectorReflectedObject(archive, object, *ownerRef);
    return archive;
  }

  void CleanupArmyLaunchInfoVectorTypeName()
  {
    gArmyLaunchInfoVectorTypeName = msvc8::string{};
    gArmyLaunchInfoVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x005448D0 (FUN_005448D0, scalar deleting destructor thunk)
   */
  ArmyLaunchInfoVectorTypeInfo::~ArmyLaunchInfoVectorTypeInfo() = default;

  /**
   * Address: 0x00542F60 (FUN_00542F60)
   */
  const char* ArmyLaunchInfoVectorTypeInfo::GetName() const
  {
    if (gArmyLaunchInfoVectorTypeName.empty()) {
      const gpg::RType* const elementType = ResolveArmyLaunchInfoType();
      const char* const elementName = elementType ? elementType->GetName() : "ArmyLaunchInfo";
      gArmyLaunchInfoVectorTypeName = gpg::STR_Printf("vector<%s>", elementName);
      if (!gArmyLaunchInfoVectorTypeNameCleanupRegistered) {
        gArmyLaunchInfoVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&CleanupArmyLaunchInfoVectorTypeName);
      }
    }

    return gArmyLaunchInfoVectorTypeName.c_str();
  }

  /**
   * Address: 0x00543020 (FUN_00543020)
   */
  msvc8::string ArmyLaunchInfoVectorTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x005430B0 (FUN_005430B0)
   */
  const gpg::RIndexed* ArmyLaunchInfoVectorTypeInfo::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00543000 (FUN_00543000)
   */
  void ArmyLaunchInfoVectorTypeInfo::Init()
  {
    size_ = sizeof(ArmyLaunchInfoVector);
    version_ = 1;
    serLoadFunc_ = &ArmyLaunchInfoVectorTypeInfo::SerLoad;
    serSaveFunc_ = &ArmyLaunchInfoVectorTypeInfo::SerSave;
  }

  /**
   * Address: 0x00543120 (FUN_00543120)
   */
  gpg::RRef ArmyLaunchInfoVectorTypeInfo::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    auto* const vectorStorage = static_cast<ArmyLaunchInfoVector*>(obj);
    moho::ArmyLaunchInfo* element = nullptr;
    if (vectorStorage != nullptr && !vectorStorage->empty()) {
      element = &((*vectorStorage)[static_cast<std::size_t>(ind)]);
    }
    gpg::RRef_ArmyLaunchInfo(&out, element);
    return out;
  }

  /**
   * Address: 0x005430C0 (FUN_005430C0)
   */
  size_t ArmyLaunchInfoVectorTypeInfo::GetCount(void* const obj) const
  {
    const auto* const vectorStorage = static_cast<const ArmyLaunchInfoVector*>(obj);
    return vectorStorage ? vectorStorage->size() : 0u;
  }

  /**
   * Address: 0x005430E0 (FUN_005430E0)
   */
  void ArmyLaunchInfoVectorTypeInfo::SetCount(void* const obj, const int count) const
  {
    auto* const vectorStorage = static_cast<ArmyLaunchInfoVector*>(obj);
    if (!vectorStorage) {
      return;
    }

    vectorStorage->resize(static_cast<std::size_t>(count));
  }

  /**
   * Address: 0x00543530 (FUN_00543530)
   */
  void ArmyLaunchInfoVectorTypeInfo::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const vectorStorage = reinterpret_cast<ArmyLaunchInfoVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(vectorStorage != nullptr);
    if (!archive || !vectorStorage) {
      return;
    }

    unsigned int itemCount = 0;
    archive->ReadUInt(&itemCount);

    ArmyLaunchInfoVector loaded;
    loaded.resize(itemCount);
    const gpg::RRef owner = NullOwnerRef();
    for (unsigned int i = 0; i < itemCount; ++i) {
      ReadArmyLaunchInfoReflectedObject(archive, &loaded[static_cast<std::size_t>(i)], owner);
    }

    *vectorStorage = std::move(loaded);
  }

  /**
   * Address: 0x005436C0 (FUN_005436C0)
   */
  void ArmyLaunchInfoVectorTypeInfo::SerSave(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    const auto* const vectorStorage = reinterpret_cast<const ArmyLaunchInfoVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const unsigned int itemCount = vectorStorage ? static_cast<unsigned int>(vectorStorage->size()) : 0u;
    archive->WriteUInt(itemCount);
    if (!vectorStorage || itemCount == 0u) {
      return;
    }

    const gpg::RRef& owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (const moho::ArmyLaunchInfo& item : *vectorStorage) {
      WriteArmyLaunchInfoReflectedObject(archive, &item, owner);
    }
  }

  [[noreturn]] void ThrowSerializationError(const char* message)
  {
    throw gpg::SerializationError(message ? message : "");
  }

  /**
   * Address: 0x00544180 (FUN_00544180)
   *
   * What it does:
   * Loads LaunchInfoBase fields in archive order:
   * game-mods text, scenario-info text, army launch info, command-source
   * control lanes, language, and cheat flag.
   */
  void LoadLaunchInfoBase(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::LaunchInfoBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->ReadString(&info->mGameMods);
    archive->ReadString(&info->mScenarioInfo);

    gpg::RType* const vectorType = ResolveArmyLaunchInfoVectorType();
    if (!vectorType) {
      ThrowSerializationError(
        "Error detected in archive: missing reflection type \"vector<ArmyLaunchInfo>\" required by LaunchInfoBase."
      );
    }
    archive->Read(vectorType, &info->mArmyLaunchInfo, NullOwnerRef());

    archive->ReadInt(&info->mCommandSources.v4);
    archive->ReadInt(&info->mCommandSources.mOriginalSource);
    archive->ReadString(&info->mLanguage);
    archive->ReadBool(&info->mCheatsEnabled);
  }

  /**
   * Address: 0x00544220 (FUN_00544220)
   *
   * What it does:
   * Saves LaunchInfoBase fields in the same order as the load callback.
   */
  void SaveLaunchInfoBase(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::LaunchInfoBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->WriteString(&info->mGameMods);
    archive->WriteString(&info->mScenarioInfo);

    gpg::RType* const vectorType = ResolveArmyLaunchInfoVectorType();
    if (!vectorType) {
      ThrowSerializationError(
        "Error while creating archive: missing reflection type \"vector<ArmyLaunchInfo>\" required by LaunchInfoBase."
      );
    }
    archive->Write(vectorType, &info->mArmyLaunchInfo, NullOwnerRef());

    archive->WriteInt(info->mCommandSources.v4);
    archive->WriteInt(info->mCommandSources.mOriginalSource);
    archive->WriteString(&info->mLanguage);
    archive->WriteBool(info->mCheatsEnabled);
  }

  bool gLaunchInfoBaseTypeRegistered = false;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename TShared>
  void ReleaseSharedOwnerControlBlockOnly(boost::SharedPtrRaw<TShared>& shared) noexcept
  {
    if (shared.pi != nullptr) {
      shared.pi->release();
    }
  }

  /**
   * Address: 0x00542040 (FUN_00542040)
   *
   * What it does:
   * Drops one shared-owner lane from `LaunchInfoNew::Create` output without
   * touching the destination pair before reassignment.
   */
  void ReleaseLaunchInfoCreateOutputOwner(boost::SharedPtrRaw<void>& shared) noexcept
  {
    ReleaseSharedOwnerControlBlockOnly(shared);
  }

  /**
   * Address: 0x00542B40 (FUN_00542B40)
   *
   * What it does:
   * Drops one shared-owner lane for `SSessionSaveData` payloads.
   */
  void ReleaseLoadSessionDataOwner(boost::SharedPtrRaw<moho::SSessionSaveData>& shared) noexcept
  {
    ReleaseSharedOwnerControlBlockOnly(shared);
  }

  /**
   * Address: 0x00542C50 (FUN_00542C50)
   */
  [[maybe_unused]] std::int32_t* AssignIntLane(std::int32_t* const lane, const std::int32_t value)
  {
    *lane = value;
    return lane;
  }

  /**
   * Address: 0x00542E80 (FUN_00542E80)
   */
  [[maybe_unused]] std::int32_t* ClearSingleIntLane(std::int32_t* const lane)
  {
    return AssignIntLane(lane, 0);
  }

  /**
   * Address: 0x00542EA0 (FUN_00542EA0)
   */
  [[maybe_unused]] std::int32_t* ClearIntPairLanesPrimary(std::int32_t* const lanes)
  {
    lanes[0] = 0;
    lanes[1] = 0;
    return lanes;
  }

  /**
   * Address: 0x00542EB0 (FUN_00542EB0)
   */
  [[maybe_unused]] std::int32_t* ClearIntPairLanesSecondary(std::int32_t* const lanes)
  {
    lanes[0] = 0;
    lanes[1] = 0;
    return lanes;
  }

  /**
   * Address: 0x00545130 (FUN_00545130)
   * Address: 0x00544770 (FUN_00544770)
   *
   * What it does:
   * Copy-constructs `count` contiguous `BVIntSet` lanes from one source set.
   * On failure, it resets already-constructed lanes to inline storage and
   * rethrows.
   */
  [[maybe_unused]] void CopyConstructBVIntSetFillRange(
    const moho::BVIntSet& source, moho::BVIntSet* const destination, std::size_t count
  )
  {
    if (destination == nullptr || count == 0u) {
      return;
    }

    moho::BVIntSet* write = destination;
    try {
      while (count != 0u) {
        write->mFirstWordIndex = source.mFirstWordIndex;
        write->mWords.RebindInlineNoFree();
        (void)gpg::core::legacy::CopyFrom(
          write->mWords, source.mWords, write->mWords.originalVec_
        );
        --count;
        ++write;
      }
    } catch (...) {
      write->mWords.ResetStorageToInline();
      for (moho::BVIntSet* constructed = destination; constructed != write; ++constructed) {
        constructed->mWords.ResetStorageToInline();
      }
      throw;
    }
  }

  /**
   * Address: 0x00544060 (FUN_00544060)
   *
   * What it does:
   * Register-shape adapter that forwards one counted contiguous `BVIntSet`
   * copy-construction lane into the canonical rollback helper.
   */
  [[maybe_unused]] void CopyConstructBVIntSetFillRangeRegisterAdapter(
    const moho::BVIntSet* const source,
    const std::size_t count,
    moho::BVIntSet* const destination
  )
  {
    CopyConstructBVIntSetFillRange(*source, destination, count);
  }

  /**
   * Address: 0x00545230 (FUN_00545230)
   * Address: 0x00545250 (FUN_00545250)
   *
   * What it does:
   * Copies one `ArmyLaunchInfo::mUnitSources` payload lane from `source` into
   * `destination`, preserving the destination reserved meta-word lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoUnitSourcesLane(
    const moho::ArmyLaunchInfo* const source,
    moho::ArmyLaunchInfo* const destination
  )
  {
    destination->mUnitSources.mFirstWordIndex = source->mUnitSources.mFirstWordIndex;
    (void)gpg::core::legacy::CopyFrom(
      destination->mUnitSources.mWords,
      source->mUnitSources.mWords,
      destination->mUnitSources.mWords.originalVec_
    );
    return destination;
  }

  /**
   * Address: 0x005450C0 (FUN_005450C0)
   *
   * What it does:
   * Copies one `ArmyLaunchInfo::mUnitSources` payload lane from `source` into
   * every destination object in `[destinationBegin, destinationEnd)`.
   */
  [[maybe_unused]] void CopyArmyLaunchInfoUnitSourcesRangeAssign(
    moho::ArmyLaunchInfo* const destinationBegin,
    moho::ArmyLaunchInfo* const destinationEnd,
    const moho::ArmyLaunchInfo* const source
  )
  {
    for (moho::ArmyLaunchInfo* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      (void)CopyArmyLaunchInfoUnitSourcesLane(source, cursor);
    }
  }

  /**
   * Address: 0x00544730 (FUN_00544730)
   *
   * What it does:
   * Alternate register/stack adapter lane for one
   * `ArmyLaunchInfo::mUnitSources` range-assignment call.
   */
  [[maybe_unused]] void CopyArmyLaunchInfoUnitSourcesRangeAssignAdapter(
    moho::ArmyLaunchInfo* const destinationBegin,
    moho::ArmyLaunchInfo* const destinationEnd,
    const moho::ArmyLaunchInfo* const source
  )
  {
    CopyArmyLaunchInfoUnitSourcesRangeAssign(destinationBegin, destinationEnd, source);
  }

  /**
   * Address: 0x00542CD0 (FUN_00542CD0)
   *
   * What it does:
   * Performs copy-style assignment of ArmyLaunchInfo vectors while preserving
   * destination self-assignment behavior.
   */
  [[nodiscard]] ArmyLaunchInfoVector& CopyAssignArmyLaunchInfoVector(
    ArmyLaunchInfoVector& destination, const ArmyLaunchInfoVector& source
  )
  {
    if (&destination != &source) {
      destination = source;
    }
    return destination;
  }

  /**
   * Address: 0x00544E20 (FUN_00544E20)
   *
   * What it does:
   * Rewinds one half-open ArmyLaunchInfo range by releasing heap-backed
   * `BVIntSet::mWords` storage and restoring inline fastvector lanes.
   */
  [[maybe_unused]] moho::ArmyLaunchInfo* ResetArmyLaunchInfoUnitSourcesRange(
    moho::ArmyLaunchInfo* const begin,
    moho::ArmyLaunchInfo* const end
  )
  {
    for (moho::ArmyLaunchInfo* cursor = begin; cursor != end; ++cursor) {
      cursor->mUnitSources.mWords.ResetStorageToInline();
    }
    return begin;
  }

  /**
   * Address: 0x005454A0 (FUN_005454A0)
   *
   * What it does:
   * Copy-constructs one contiguous `ArmyLaunchInfo` range from
   * `[sourceBegin, sourceEnd)` into `destinationBegin`, rebuilding each
   * `mUnitSources.mWords` lane from inline storage and rolling back partial
   * construction on failure.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeRollback(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    const moho::ArmyLaunchInfo* sourceCursor = sourceBegin;
    moho::ArmyLaunchInfo* destinationCursor = destinationBegin;

    try {
      while (sourceCursor != sourceEnd) {
        if (destinationCursor != nullptr) {
          destinationCursor->mUnitSources.mFirstWordIndex = sourceCursor->mUnitSources.mFirstWordIndex;
          destinationCursor->mUnitSources.mWords.RebindInlineNoFree();
          (void)gpg::core::legacy::CopyFrom(
            destinationCursor->mUnitSources.mWords,
            sourceCursor->mUnitSources.mWords,
            destinationCursor->mUnitSources.mWords.originalVec_
          );
        }

        ++sourceCursor;
        ++destinationCursor;
      }
    } catch (...) {
      if (destinationCursor != nullptr) {
        destinationCursor->mUnitSources.mWords.ResetStorageToInline();
      }
      (void)ResetArmyLaunchInfoUnitSourcesRange(destinationBegin, destinationCursor);
      throw;
    }

    return destinationCursor;
  }

  /**
   * Address: 0x00544C60 (FUN_00544C60)
   * Address: 0x00545090 (FUN_00545090)
   * Address: 0x00545580 (FUN_00545580)
   *
   * What it does:
   * Bridges legacy register/EH-shaped wrapper lanes into the canonical
   * `CopyConstructArmyLaunchInfoRangeRollback` helper.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeRollbackRegisterAdapter(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00545620 (FUN_00545620)
   *
   * What it does:
   * Copies one `ArmyLaunchInfo::mUnitSources` payload lane from `source` into
   * `destination`, rebinding destination word storage to inline lanes first.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoUnitSourcesRebindAndCopy(
    const moho::ArmyLaunchInfo* const source,
    moho::ArmyLaunchInfo* const destination
  )
  {
    if (destination == nullptr) {
      return destination;
    }

    destination->mUnitSources.mFirstWordIndex = source->mUnitSources.mFirstWordIndex;
    (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
      &destination->mUnitSources.mWords,
      &source->mUnitSources.mWords
    );
    return destination;
  }

  /**
   * Address: 0x00545270 (FUN_00545270)
   *
   * What it does:
   * Thin adapter lane forwarding one `ArmyLaunchInfo` unit-source copy into
   * the inline-rebind helper.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoUnitSourcesRebindAndCopyAdapter(
    const moho::ArmyLaunchInfo* const source,
    moho::ArmyLaunchInfo* const destination
  )
  {
    return CopyArmyLaunchInfoUnitSourcesRebindAndCopy(source, destination);
  }

  /**
   * Address: 0x005457A0 (FUN_005457A0)
   *
   * What it does:
   * Adapter lane that forwards ArmyLaunchInfo range copy-construction into the
   * canonical rollback-capable helper.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeRollbackAdapterA(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00545880 (FUN_00545880)
   *
   * What it does:
   * Alternate adapter lane that forwards ArmyLaunchInfo range copy-construction
   * into the canonical rollback-capable helper.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeRollbackAdapterB(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00545200 (FUN_00545200)
   *
   * What it does:
   * Register/stack-shape thunk lane forwarding one ArmyLaunchInfo range
   * copy-construction call into `FUN_005457A0`.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeThunkA(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollbackAdapterA(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005445E0 (FUN_005445E0)
   *
   * What it does:
   * Register/stack-shape thunk lane forwarding one ArmyLaunchInfo range
   * copy-construction call into `FUN_00545880`.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeThunkB(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollbackAdapterB(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00544E60 (FUN_00544E60)
   *
   * What it does:
   * Register/stack-shape thunk lane forwarding one ArmyLaunchInfo range
   * copy-construction call into `FUN_00545880`.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeThunkC(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollbackAdapterB(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00545550 (FUN_00545550)
   *
   * What it does:
   * Register/stack-shape thunk lane forwarding one ArmyLaunchInfo range
   * copy-construction call into `FUN_00545880`.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyConstructArmyLaunchInfoRangeThunkD(
    const moho::ArmyLaunchInfo* const sourceBegin,
    const moho::ArmyLaunchInfo* const sourceEnd,
    moho::ArmyLaunchInfo* const destinationBegin
  )
  {
    return CopyConstructArmyLaunchInfoRangeRollbackAdapterB(sourceBegin, sourceEnd, destinationBegin);
  }

  [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoRangeBackwardCore(
    moho::ArmyLaunchInfo* destinationEnd,
    const moho::ArmyLaunchInfo* sourceEnd,
    const moho::ArmyLaunchInfo* const sourceBegin
  )
  {
    const moho::ArmyLaunchInfo* read = sourceEnd;
    moho::ArmyLaunchInfo* write = destinationEnd;
    while (read != sourceBegin) {
      --read;
      --write;
      write->mUnitSources.mFirstWordIndex = read->mUnitSources.mFirstWordIndex;
      (void)gpg::core::legacy::CopyFrom(
        write->mUnitSources.mWords,
        read->mUnitSources.mWords,
        write->mUnitSources.mWords.originalVec_
      );
    }
    return write;
  }

  /**
   * Address: 0x00544740 (FUN_00544740)
   *
   * What it does:
   * Backward-copy adapter lane for one contiguous ArmyLaunchInfo range.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoRangeBackwardAdapterA(
    moho::ArmyLaunchInfo* const destinationEnd,
    const moho::ArmyLaunchInfo* const sourceEnd,
    const moho::ArmyLaunchInfo* const sourceBegin
  )
  {
    return CopyArmyLaunchInfoRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00545100 (FUN_00545100)
   *
   * What it does:
   * Alternate backward-copy adapter lane for one contiguous ArmyLaunchInfo
   * range.
   */
  [[maybe_unused]] [[nodiscard]] moho::ArmyLaunchInfo* CopyArmyLaunchInfoRangeBackwardAdapterB(
    moho::ArmyLaunchInfo* const destinationEnd,
    const moho::ArmyLaunchInfo* const sourceEnd,
    const moho::ArmyLaunchInfo* const sourceBegin
  )
  {
    return CopyArmyLaunchInfoRangeBackwardCore(destinationEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x00543410 (FUN_00543410)
   *
   * What it does:
   * Resets one legacy `vector<ArmyLaunchInfo>` lane by clearing each element's
   * unit-source storage, releasing the heap buffer, and nulling begin/end/
   * capacity pointers.
   */
  [[maybe_unused]] void ResetArmyLaunchInfoVectorStorage(ArmyLaunchInfoVector& storage)
  {
    auto& runtime = msvc8::AsVectorRuntimeView(storage);
    if (runtime.begin != nullptr) {
      (void)ResetArmyLaunchInfoUnitSourcesRange(runtime.begin, runtime.end);
      ::operator delete(runtime.begin);
    }

    runtime.begin = nullptr;
    runtime.end = nullptr;
    runtime.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00544EA0 (FUN_00544EA0)
   * Address: 0x00544660 (FUN_00544660)
   *
   * What it does:
   * Rewinds one half-open command-source range by releasing heap-backed
   * name-string storage and restoring empty SSO lanes for each entry.
   */
  [[maybe_unused]] void ResetCommandSourceNameRange(
    moho::SSTICommandSource* const begin,
    moho::SSTICommandSource* const end
  )
  {
    for (moho::SSTICommandSource* cursor = begin; cursor != end; ++cursor) {
      cursor->mName.tidy(true, 0U);
    }
  }

  /**
   * Address: 0x005434D0 (FUN_005434D0)
   *
   * What it does:
   * Resets one legacy `vector<SSTICommandSource>` lane by clearing each
   * command-source name, releasing the heap buffer, and nulling begin/end/
   * capacity pointers.
   */
  [[maybe_unused]] void ResetCommandSourceVectorStorage(msvc8::vector<moho::SSTICommandSource>& storage)
  {
    auto& runtime = msvc8::AsVectorRuntimeView(storage);
    if (runtime.begin != nullptr) {
      (void)ResetCommandSourceNameRange(runtime.begin, runtime.end);
      ::operator delete(runtime.begin);
    }

    runtime.begin = nullptr;
    runtime.end = nullptr;
    runtime.capacityEnd = nullptr;
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void EnsureLaunchInfoNewTypeInfoConstructed()
  {
    if (gLaunchInfoNewTypeInfoConstructed) {
      return;
    }

    new (gLaunchInfoNewTypeInfoStorage) moho::LaunchInfoNewTypeInfo();
    gLaunchInfoNewTypeInfoConstructed = true;
  }

  void CleanupLaunchInfoNewTypeInfoAtexit()
  {
    if (!gLaunchInfoNewTypeInfoConstructed) {
      return;
    }

    LaunchInfoNewTypeInfoStorageRef().~LaunchInfoNewTypeInfo();
    gLaunchInfoNewTypeInfoConstructed = false;
  }

  moho::ArmyLaunchInfoSerializer* InitializeArmyLaunchInfoSerializerCallbacks()
  {
    if (!gArmyLaunchInfoSerializerConstructed) {
      new (gArmyLaunchInfoSerializerStorage) moho::ArmyLaunchInfoSerializer();
      gArmyLaunchInfoSerializerConstructed = true;
    }

    moho::ArmyLaunchInfoSerializer& serializer = ArmyLaunchInfoSerializerStorageRef();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = &moho::ArmyLaunchInfoSerializer::Deserialize;
    serializer.mSerialize = &moho::ArmyLaunchInfoSerializer::Serialize;
    return &serializer;
  }

  /**
   * Address: 0x00542210 (FUN_00542210)
   */
  gpg::SerHelperBase* ResetArmyLaunchInfoSerializerLinksPrimary()
  {
    if (!gArmyLaunchInfoSerializerConstructed) {
      return nullptr;
    }
    return UnlinkHelperNode(ArmyLaunchInfoSerializerStorageRef());
  }

  /**
   * Address: 0x00542240 (FUN_00542240)
   */
  gpg::SerHelperBase* ResetArmyLaunchInfoSerializerLinksSecondary()
  {
    if (!gArmyLaunchInfoSerializerConstructed) {
      return nullptr;
    }
    return UnlinkHelperNode(ArmyLaunchInfoSerializerStorageRef());
  }

  /**
   * Address: 0x00542A50 (FUN_00542A50)
   */
  moho::LaunchInfoNewSerializer* InitializeLaunchInfoNewSerializerCallbacks()
  {
    if (!gLaunchInfoNewSerializerConstructed) {
      new (gLaunchInfoNewSerializerStorage) moho::LaunchInfoNewSerializer();
      gLaunchInfoNewSerializerConstructed = true;
    }

    moho::LaunchInfoNewSerializer& serializer = LaunchInfoNewSerializerStorageRef();
    InitializeHelperNode(serializer);
    serializer.mDeserialize = &moho::LaunchInfoNewSerializer::Deserialize;
    serializer.mSerialize = &moho::LaunchInfoNewSerializer::Serialize;
    return &serializer;
  }

  /**
   * Address: 0x00542A80 (FUN_00542A80)
   */
  gpg::SerHelperBase* ResetLaunchInfoNewSerializerLinksPrimary()
  {
    if (!gLaunchInfoNewSerializerConstructed) {
      return nullptr;
    }
    return UnlinkHelperNode(LaunchInfoNewSerializerStorageRef());
  }

  /**
   * Address: 0x00542AB0 (FUN_00542AB0)
   */
  gpg::SerHelperBase* ResetLaunchInfoNewSerializerLinksSecondary()
  {
    if (!gLaunchInfoNewSerializerConstructed) {
      return nullptr;
    }
    return UnlinkHelperNode(LaunchInfoNewSerializerStorageRef());
  }

  gpg::SerHelperBase* ResetLaunchInfoBaseSerializerLinksPrimary();
  gpg::SerHelperBase* ResetLaunchInfoBaseSerializerLinksSecondary();

  /**
   * Address: 0x00542270 (FUN_00542270)
   *
   * What it does:
   * Startup lane that preregisters reflected RTTI metadata for
   * `LaunchInfoBase`.
   */
  [[nodiscard]] gpg::RType* EnsureLaunchInfoBaseTypeRegistered()
  {
    if (gLaunchInfoBaseTypeRegistered) {
      return &gLaunchInfoBaseTypeInfo;
    }

    gpg::PreRegisterRType(typeid(moho::LaunchInfoBase), &gLaunchInfoBaseTypeInfo);
    gLaunchInfoBaseTypeRegistered = true;
    return &gLaunchInfoBaseTypeInfo;
  }

  void CleanupLaunchInfoBaseSerializerAtexit()
  {
    (void)ResetLaunchInfoBaseSerializerLinksSecondary();
  }

  void CleanupArmyLaunchInfoSerializerAtexit()
  {
    if (!gArmyLaunchInfoSerializerConstructed) {
      return;
    }

    (void)ResetArmyLaunchInfoSerializerLinksSecondary();
    ArmyLaunchInfoSerializerStorageRef().~ArmyLaunchInfoSerializer();
    gArmyLaunchInfoSerializerConstructed = false;
  }

  /**
   * Address: 0x005425B0 (FUN_005425B0)
   */
  gpg::SerHelperBase* ResetLaunchInfoBaseSerializerLinksPrimary()
  {
    return UnlinkHelperNode(gLaunchInfoBaseSerializer);
  }

  /**
   * Address: 0x005425E0 (FUN_005425E0)
   */
  gpg::SerHelperBase* ResetLaunchInfoBaseSerializerLinksSecondary()
  {
    return UnlinkHelperNode(gLaunchInfoBaseSerializer);
  }

  /**
   * Address: 0x005421B0 (FUN_005421B0)
   */
  [[maybe_unused]] void ArmyLaunchInfoTypeInfoStartupNoop()
  {
  }

  /**
   * Address: 0x005423A0 (FUN_005423A0)
   */
  [[maybe_unused]] void LaunchInfoBaseTypeInfoStartupNoop()
  {
  }

  void CleanupLaunchInfoNewSerializerAtexit()
  {
    if (!gLaunchInfoNewSerializerConstructed) {
      return;
    }

    (void)ResetLaunchInfoNewSerializerLinksSecondary();
    LaunchInfoNewSerializerStorageRef().~LaunchInfoNewSerializer();
    gLaunchInfoNewSerializerConstructed = false;
  }

  struct LaunchInfoBaseSerializerBootstrap
  {
    LaunchInfoBaseSerializerBootstrap()
    {
      moho::register_ArmyLaunchInfoSerializer();
      moho::register_LaunchInfoNewTypeInfo();
      moho::register_LaunchInfoNewSerializer();
      moho::register_LaunchInfoBaseSerializer();
    }
  };

  [[maybe_unused]] LaunchInfoBaseSerializerBootstrap gLaunchInfoBaseSerializerBootstrap;
} // namespace

namespace moho
{
  gpg::RType* ArmyLaunchInfo::sType = nullptr;
  gpg::RType* LaunchInfoBase::sType = nullptr;

  /**
   * Address: 0x00544800 (FUN_00544800, preregister_ArmyLaunchInfoVectorTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `vector<ArmyLaunchInfo>`.
   */
  gpg::RType* preregister_ArmyLaunchInfoVectorTypeStartup()
  {
    auto* const typeInfo = &gArmyLaunchInfoVectorTypeInfo;
    gpg::PreRegisterRType(typeid(ArmyLaunchInfoVector), typeInfo);
    gArmyLaunchInfoVectorTypeRegistered = true;
    return typeInfo;
  }

  /**
   * Address: 0x00544320 (FUN_00544320, boost::shared_ptr_LaunchInfoNew::shared_ptr_LaunchInfoNew)
   *
   * What it does:
   * Constructs one `shared_ptr<LaunchInfoNew>` from one raw launch-info
   * pointer lane.
   */
  boost::shared_ptr<LaunchInfoNew>* ConstructSharedLaunchInfoNewFromRaw(
    boost::shared_ptr<LaunchInfoNew>* const outLaunchInfo,
    LaunchInfoNew* const launchInfo
  )
  {
    return ::new (outLaunchInfo) boost::shared_ptr<LaunchInfoNew>(launchInfo);
  }

  /**
   * Address: 0x00542110 (FUN_00542110, scalar deleting destructor thunk)
   */
  ArmyLaunchInfoTypeInfo::~ArmyLaunchInfoTypeInfo() = default;

  /**
   * Address: 0x00542100 (FUN_00542100)
   */
  const char* ArmyLaunchInfoTypeInfo::GetName() const
  {
    return "ArmyLaunchInfo";
  }

  /**
   * Address: 0x005420E0 (FUN_005420E0)
   */
  void ArmyLaunchInfoTypeInfo::Init()
  {
    size_ = sizeof(ArmyLaunchInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BF3F90 (FUN_00BF3F90, Moho::ArmyLaunchInfoSerializer::~ArmyLaunchInfoSerializer)
   */
  ArmyLaunchInfoSerializer::~ArmyLaunchInfoSerializer()
  {
    (void)UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x005421C0 (FUN_005421C0, Moho::ArmyLaunchInfoSerializer::Deserialize)
   */
  void ArmyLaunchInfoSerializer::Deserialize(gpg::ReadArchive* const, const int, const int, gpg::RRef* const)
  {
  }

  /**
   * Address: 0x005421D0 (FUN_005421D0, Moho::ArmyLaunchInfoSerializer::Serialize)
   */
  void ArmyLaunchInfoSerializer::Serialize(gpg::WriteArchive* const, const int, const int, gpg::RRef* const)
  {
  }

  /**
   * Address: 0x00542EF0 (FUN_00542EF0)
   */
  void ArmyLaunchInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = ArmyLaunchInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(ArmyLaunchInfo));
      ArmyLaunchInfo::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF40B0 (FUN_00BF40B0, Moho::LaunchInfoNewSerializer::~LaunchInfoNewSerializer)
   */
  LaunchInfoNewSerializer::~LaunchInfoNewSerializer()
  {
    (void)UnlinkHelperNode(*this);
  }

  /**
   * Address: 0x00542A20 (FUN_00542A20, Moho::LaunchInfoNewSerializer::Deserialize)
   */
  void LaunchInfoNewSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<LaunchInfoNew*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00542A30 (FUN_00542A30, Moho::LaunchInfoNewSerializer::Serialize)
   */
  void LaunchInfoNewSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<LaunchInfoNew*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x00542610 (FUN_00542610)
   */
  LaunchInfoNewTypeInfo::LaunchInfoNewTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(LaunchInfoNew), this);
  }

  /**
   * Address: 0x005426C0 (FUN_005426C0, scalar deleting destructor thunk)
   */
  LaunchInfoNewTypeInfo::~LaunchInfoNewTypeInfo() = default;

  /**
   * Address: 0x005426B0 (FUN_005426B0)
   */
  const char* LaunchInfoNewTypeInfo::GetName() const
  {
    return "LaunchInfoNew";
  }

  /**
   * Address: 0x00542670 (FUN_00542670)
   */
  void LaunchInfoNewTypeInfo::Init()
  {
    size_ = sizeof(LaunchInfoNew);
    gpg::RType::Init();
    InitializeLaunchInfoNewTypeInfoCallbacks(this);
    AddBase_LaunchInfoBase(this);
    Finish();
  }

  /**
   * Address: 0x005442C0 (FUN_005442C0, AddBase_LaunchInfoBase)
   */
  void __stdcall LaunchInfoNewTypeInfo::AddBase_LaunchInfoBase(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = LaunchInfoBase::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(LaunchInfoBase));
      LaunchInfoBase::sType = baseType;
    }

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00543C50 (FUN_00543C50)
   */
  gpg::RRef LaunchInfoNewTypeInfo::NewRef()
  {
    auto* const object = new LaunchInfoNew();
    return gpg::RRef{object, ResolveLaunchInfoNewType()};
  }

  /**
   * Address: 0x00543CF0 (FUN_00543CF0)
   */
  gpg::RRef LaunchInfoNewTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<LaunchInfoNew*>(objectStorage);
    if (object) {
      new (object) LaunchInfoNew();
    }
    return gpg::RRef{object, ResolveLaunchInfoNewType()};
  }

  /**
   * Address: 0x00543CD0 (FUN_00543CD0)
   */
  void LaunchInfoNewTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<LaunchInfoNew*>(objectStorage);
  }

  /**
   * Address: 0x00543D60 (FUN_00543D60)
   */
  void LaunchInfoNewTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<LaunchInfoNew*>(objectStorage);
    if (!object) {
      return;
    }

    object->~LaunchInfoNew();
  }

  gpg::RType* LaunchInfoBase::StaticGetClass()
  {
    (void)EnsureLaunchInfoBaseTypeRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(LaunchInfoBase));
    }
    return sType;
  }

  /**
   * Address: 0x005423B0 (FUN_005423B0)
   *
   * What it does:
   * Initializes launch-info base runtime ownership and metadata lanes.
   */
  LaunchInfoBase::LaunchInfoBase()
    : mGameRules(nullptr)
    , mMap(nullptr)
    , mGameMods()
    , mScenarioInfo()
    , mArmyLaunchInfo()
    , mCommandSources()
    , mLanguage()
    , mCheatsEnabled(false)
    , pad_89{0, 0, 0}
  {
  }

  /**
   * Address: 0x00541F90 (FUN_00541F90)
   *
   * What it does:
   * Initializes the embedded `BVIntSet` lane used by `ArmyLaunchInfo` to its
   * empty inline-storage state.
   */
  ArmyLaunchInfo::ArmyLaunchInfo()
    : mUnitSources()
  {
  }

  /**
   * Address: 0x00542440 (FUN_00542440, deleting dtor thunk)
   * Address: 0x00542460 (FUN_00542460, destructor core)
   */
  LaunchInfoBase::~LaunchInfoBase()
  {
    if (mMap != nullptr) {
      delete mMap;
      mMap = nullptr;
    }
  }

  /**
   * Address: 0x00541FB0 (FUN_00541FB0)
   *
   * What it does:
   * Base implementation returns no "new game" launch descriptor.
   */
  LaunchInfoNew* LaunchInfoBase::GetNew()
  {
    return nullptr;
  }

  /**
   * Address: 0x00541FC0 (FUN_00541FC0)
   *
   * What it does:
   * Base implementation returns no "load game" launch descriptor.
   */
  LaunchInfoLoad* LaunchInfoBase::GetLoad()
  {
    return nullptr;
  }

  /**
   * Address: 0x00542790 (FUN_00542790)
   *
   * What it does:
   * Initializes "new game" launch-info derived lanes.
   */
  LaunchInfoNew::LaunchInfoNew()
    : LaunchInfoBase()
    , mProps(nullptr)
    , mStrVec()
    , mInitSeed(0)
  {
  }

  /**
   * Address: 0x005427F0 (FUN_005427F0, deleting destructor thunk)
   * Address: 0x00542810 (FUN_00542810)
   */
  LaunchInfoNew::~LaunchInfoNew() = default;

  /**
   * Address: 0x00541FD0 (FUN_00541FD0)
   */
  LaunchInfoNew* LaunchInfoNew::GetNew()
  {
    return this;
  }

  /**
   * Address: 0x00542870 (FUN_00542870)
   *
   * What it does:
   * Allocates and populates a new LaunchInfoNew shared object from this source.
   */
  void LaunchInfoNew::Create(boost::SharedPtrRaw<void>& outCreated)
  {
    LaunchInfoNew* const createdInfo = new LaunchInfoNew();
    createdInfo->mGameMods = mGameMods;
    createdInfo->mScenarioInfo = mScenarioInfo;
    (void)CopyAssignArmyLaunchInfoVector(createdInfo->mArmyLaunchInfo, mArmyLaunchInfo);
    createdInfo->mCommandSources.v4 = mCommandSources.v4;
    createdInfo->mCommandSources.mOriginalSource = mCommandSources.mOriginalSource;
    createdInfo->mLanguage = mLanguage;
    createdInfo->mCheatsEnabled = mCheatsEnabled;
    createdInfo->mStrVec = mStrVec;
    createdInfo->mInitSeed = static_cast<std::int32_t>(gpg::time::GetSystemTimer().ElapsedCycles());

    ReleaseLaunchInfoCreateOutputOwner(outCreated);
    outCreated = boost::SharedPtrRaw<void>::with_deleter(static_cast<void*>(createdInfo), [](void* payload) {
      delete static_cast<LaunchInfoNew*>(payload);
    });
  }

  /**
   * Address: 0x00544360 (FUN_00544360, Moho::LaunchInfoNew::MemberDeserialize)
   */
  void LaunchInfoNew::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RRef baseOwner{};
    ReadLaunchInfoBaseReflectedObject(archive, static_cast<LaunchInfoBase*>(this), baseOwner);

    gpg::RRef stringVectorOwner{};
    ReadStringVectorReflectedObject(archive, &mStrVec, stringVectorOwner);

    unsigned int seed = 0;
    archive->ReadUInt(&seed);
    mInitSeed = static_cast<std::int32_t>(seed);
  }

  /**
   * Address: 0x005443F0 (FUN_005443F0, Moho::LaunchInfoNew::MemberSerialize)
   */
  void LaunchInfoNew::MemberSerialize(gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RRef baseOwner{};
    WriteLaunchInfoBaseReflectedObject(archive, static_cast<const LaunchInfoBase*>(this), baseOwner);

    gpg::RRef stringVectorOwner{};
    WriteStringVectorReflectedObject(archive, &mStrVec, stringVectorOwner);

    archive->WriteUInt(static_cast<unsigned int>(mInitSeed));
  }

  /**
   * Address: 0x00542AE0 (FUN_00542AE0)
   *
   * What it does:
   * Initializes "load game" launch-info derived lanes.
   */
  LaunchInfoLoad::LaunchInfoLoad()
    : LaunchInfoBase()
    , mReadArchive(nullptr)
    , mLoadSessionData()
    , mSharedLaunchInfo()
  {
  }

  /**
   * Address: 0x00542B20 (FUN_00542B20, deleting destructor thunk)
   * Address: 0x00542B80 (FUN_00542B80)
   *
   * What it does:
   * Releases shared session payload lanes and owned props object.
   */
  LaunchInfoLoad::~LaunchInfoLoad()
  {
    mSharedLaunchInfo.release();
    ReleaseLoadSessionDataOwner(mLoadSessionData);
    delete mReadArchive;
    mReadArchive = nullptr;
  }

  /**
   * Address: 0x00541FE0 (FUN_00541FE0)
   */
  LaunchInfoLoad* LaunchInfoLoad::GetLoad()
  {
    return this;
  }

  /**
   * Address: 0x00541FF0 (FUN_00541FF0)
   *
   * What it does:
   * Returns retained shared payload lane for session creation.
   */
  void LaunchInfoLoad::Create(boost::SharedPtrRaw<void>& outCreated)
  {
    boost::SharedPtrRaw<void> sharedLaunchInfo{};
    sharedLaunchInfo.px = static_cast<void*>(mSharedLaunchInfo.px);
    sharedLaunchInfo.pi = mSharedLaunchInfo.pi;
    outCreated.assign_retain(sharedLaunchInfo);
  }

  /**
   * Address: 0x00542550 (FUN_00542550, Moho::LaunchInfoBaseSerializer::Deserialize)
   *
   * What it does:
   * Archive callback thunk forwarding into LaunchInfoBase load body.
   */
  void LaunchInfoBaseSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    LoadLaunchInfoBase(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00542560 (FUN_00542560, Moho::LaunchInfoBaseSerializer::Serialize)
   *
   * What it does:
   * Archive callback thunk forwarding into LaunchInfoBase save body.
   */
  void LaunchInfoBaseSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SaveLaunchInfoBase(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00543190 (FUN_00543190, sub_543190)
   *
   * What it does:
   * Registers load/save callbacks into LaunchInfoBase RTTI.
   */
  void LaunchInfoBaseSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = LaunchInfoBase::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00BC9460 (FUN_00BC9460, register_ArmyLaunchInfoSerializer)
   */
  void register_ArmyLaunchInfoSerializer()
  {
    (void)InitializeArmyLaunchInfoSerializerCallbacks();
    (void)std::atexit(&CleanupArmyLaunchInfoSerializerAtexit);
  }

  /**
   * Address: 0x00BC9500 (FUN_00BC9500, register_LaunchInfoNewTypeInfo)
   */
  void register_LaunchInfoNewTypeInfo()
  {
    EnsureLaunchInfoNewTypeInfoConstructed();
    (void)std::atexit(&CleanupLaunchInfoNewTypeInfoAtexit);
  }

  /**
   * Address: 0x00BC9520 (FUN_00BC9520, register_LaunchInfoNewSerializer)
   */
  void register_LaunchInfoNewSerializer()
  {
    (void)InitializeLaunchInfoNewSerializerCallbacks();
    (void)std::atexit(&CleanupLaunchInfoNewSerializerAtexit);
  }

  /**
   * Address: 0x00BC94C0 (FUN_00BC94C0, register_LaunchInfoBaseSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for `LaunchInfoBase`
   * and schedules process-exit cleanup.
   */
  void register_LaunchInfoBaseSerializer()
  {
    (void)EnsureLaunchInfoBaseTypeRegistered();
    InitializeHelperNode(gLaunchInfoBaseSerializer);
    gLaunchInfoBaseSerializer.mSerLoadFunc = &LaunchInfoBaseSerializer::Deserialize;
    gLaunchInfoBaseSerializer.mSerSaveFunc = &LaunchInfoBaseSerializer::Serialize;
    (void)std::atexit(&CleanupLaunchInfoBaseSerializerAtexit);
  }

  /**
   * Address: 0x00542300 (FUN_00542300, deleting dtor thunk)
   */
  LaunchInfoBaseTypeInfo::~LaunchInfoBaseTypeInfo() = default;

  /**
   * Address: 0x005422F0 (FUN_005422F0)
   */
  const char* LaunchInfoBaseTypeInfo::GetName() const
  {
    return "LaunchInfoBase";
  }

  /**
   * Address: 0x005422D0 (FUN_005422D0)
   */
  void LaunchInfoBaseTypeInfo::Init()
  {
    size_ = sizeof(LaunchInfoBase);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00885170 (FUN_00885170)
   *
   * What it does:
   * Builds an `RRef` for `LaunchInfoBase*`, upcasting derived launch-info
   * objects to their complete-object pointer when needed.
   */
  RRef* RRef_LaunchInfoBase(RRef* outRef, moho::LaunchInfoBase* value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RType* const baseType = moho::LaunchInfoBase::StaticGetClass();
    outRef->mObj = value;
    outRef->mType = baseType;

    if (!value || !baseType) {
      return outRef;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*value));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      outRef->mObj = value;
      outRef->mType = dynamicType;
      return outRef;
    }

    outRef->mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
    outRef->mType = dynamicType;
    return outRef;
  }
} // namespace gpg
