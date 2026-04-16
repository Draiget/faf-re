#include "moho/sim/ReconBlipSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/ReconBlip.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeakPtrReflection.h"

namespace
{
  alignas(moho::SPerArmyReconInfoSerializer) unsigned char
    gSPerArmyReconInfoSerializerStorage[sizeof(moho::SPerArmyReconInfoSerializer)] = {};
  bool gSPerArmyReconInfoSerializerConstructed = false;

  alignas(moho::ReconBlipSerializer) unsigned char gReconBlipSerializerStorage[sizeof(moho::ReconBlipSerializer)] = {};
  bool gReconBlipSerializerConstructed = false;

  gpg::RType* gEntityType = nullptr;
  gpg::RType* gReconBlipType = nullptr;
  gpg::RType* gWeakPtrUnitType = nullptr;
  gpg::RType* gVector3fType = nullptr;
  gpg::RType* gUnitConstDataType = nullptr;
  gpg::RType* gUnitVarDataType = nullptr;
  gpg::RType* gPerArmyReconInfoVectorType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
    return self;
  }

  [[nodiscard]] moho::SPerArmyReconInfoSerializer* AcquireSPerArmyReconInfoSerializer()
  {
    if (!gSPerArmyReconInfoSerializerConstructed) {
      new (gSPerArmyReconInfoSerializerStorage) moho::SPerArmyReconInfoSerializer();
      gSPerArmyReconInfoSerializerConstructed = true;
    }

    return reinterpret_cast<moho::SPerArmyReconInfoSerializer*>(gSPerArmyReconInfoSerializerStorage);
  }

  [[nodiscard]] moho::ReconBlipSerializer* AcquireReconBlipSerializer()
  {
    if (!gReconBlipSerializerConstructed) {
      new (gReconBlipSerializerStorage) moho::ReconBlipSerializer();
      gReconBlipSerializerConstructed = true;
    }

    return reinterpret_cast<moho::ReconBlipSerializer*>(gReconBlipSerializerStorage);
  }

  [[nodiscard]] gpg::RType* ResolveEntityType()
  {
    if (!gEntityType) {
      gEntityType = gpg::LookupRType(typeid(moho::Entity));
    }
    return gEntityType;
  }

  /**
   * Address: 0x005C90A0 (FUN_005C90A0)
   *
   * What it does:
   * Fills one reflected object reference from a `ReconBlip*` lane.
   */
  [[maybe_unused]] gpg::RRef* FillReconBlipObjectRef(gpg::RRef* const outRef, moho::ReconBlip* const object)
  {
    if (!outRef) {
      return nullptr;
    }

    outRef->mObj = object;
    outRef->mType = object ? CachedType<moho::ReconBlip>(gReconBlipType) : nullptr;
    return outRef;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    if (!gWeakPtrUnitType) {
      gWeakPtrUnitType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      if (!gWeakPtrUnitType) {
        gWeakPtrUnitType = moho::register_WeakPtr_Unit_Type_00();
      }
    }
    return gWeakPtrUnitType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    return CachedType<Wm3::Vector3f>(gVector3fType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitConstDataType()
  {
    return CachedType<moho::SSTIUnitConstantData>(gUnitConstDataType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitVarDataType()
  {
    return CachedType<moho::SSTIUnitVariableData>(gUnitVarDataType);
  }

  [[nodiscard]] gpg::RType* ResolvePerArmyReconInfoVectorType()
  {
    return CachedType<msvc8::vector<moho::SPerArmyReconInfo>>(gPerArmyReconInfoVectorType);
  }

  [[nodiscard]] gpg::RType* ResolvePerArmyReconInfoType()
  {
    if (!moho::SPerArmyReconInfo::sType) {
      moho::SPerArmyReconInfo::sType = gpg::LookupRType(typeid(moho::SPerArmyReconInfo));
    }
    return moho::SPerArmyReconInfo::sType;
  }

  /**
   * Address: 0x005CC880 (FUN_005CC880)
   *
   * What it does:
   * Deserializes `ReconBlip` reflected member lanes in binary order.
   */
  void DeserializeReconBlipMembers(moho::ReconBlip* const object, gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Read(ResolveEntityType(), static_cast<moho::Entity*>(object), ownerRef);
    archive->Read(ResolveWeakPtrUnitType(), &object->mCreator, ownerRef);
    archive->ReadBool(reinterpret_cast<bool*>(&object->mDeleteWhenStale));
    archive->Read(ResolveVector3fType(), &object->mJamOffset, ownerRef);
    archive->Read(ResolveUnitConstDataType(), &object->mUnitConstDat, ownerRef);
    archive->Read(ResolveUnitVarDataType(), &object->mUnitVarDat, ownerRef);
    archive->Read(ResolvePerArmyReconInfoVectorType(), &object->mReconDat, ownerRef);
  }

  /**
   * Address: 0x005CC9F0 (FUN_005CC9F0)
   *
   * What it does:
   * Serializes `ReconBlip` reflected member lanes in binary order.
   */
  void SerializeReconBlipMembers(const moho::ReconBlip* const object, gpg::WriteArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Write(ResolveEntityType(), static_cast<const moho::Entity*>(object), ownerRef);
    archive->Write(ResolveWeakPtrUnitType(), &object->mCreator, ownerRef);
    archive->WriteBool(object->mDeleteWhenStale != 0u);
    archive->Write(ResolveVector3fType(), &object->mJamOffset, ownerRef);
    archive->Write(ResolveUnitConstDataType(), &object->mUnitConstDat, ownerRef);
    archive->Write(ResolveUnitVarDataType(), &object->mUnitVarDat, ownerRef);
    archive->Write(ResolvePerArmyReconInfoVectorType(), &object->mReconDat, ownerRef);
  }

  /**
   * Address: 0x005C90D0 (FUN_005C90D0)
   *
   * What it does:
   * Forwarding thunk into canonical ReconBlip-member deserialize helper.
   */
  [[maybe_unused]] void DeserializeReconBlipMembersThunkA(moho::ReconBlip* const object, gpg::ReadArchive* const archive)
  {
    DeserializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x005C90E0 (FUN_005C90E0)
   *
   * What it does:
   * Forwarding thunk into canonical ReconBlip-member serialize helper.
   */
  [[maybe_unused]] void SerializeReconBlipMembersThunkA(
    const moho::ReconBlip* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x005CAF90 (FUN_005CAF90)
   *
   * What it does:
   * Duplicate forwarding thunk into canonical ReconBlip-member deserialize helper.
   */
  [[maybe_unused]] void DeserializeReconBlipMembersThunkB(moho::ReconBlip* const object, gpg::ReadArchive* const archive)
  {
    DeserializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x005CAFA0 (FUN_005CAFA0)
   *
   * What it does:
   * Duplicate forwarding thunk into canonical ReconBlip-member serialize helper.
   */
  [[maybe_unused]] void SerializeReconBlipMembersThunkB(
    const moho::ReconBlip* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x00BF7840 (FUN_00BF7840, cleanup_SPerArmyReconInfoSerializer)
   *
   * What it does:
   * Unlinks static serializer helper storage for `SPerArmyReconInfo`.
   */
  void cleanup_SPerArmyReconInfoSerializer()
  {
    if (!gSPerArmyReconInfoSerializerConstructed) {
      return;
    }

    moho::SPerArmyReconInfoSerializer* const serializer = AcquireSPerArmyReconInfoSerializer();
    (void)UnlinkSerializerNode(*serializer);
  }

  /**
   * Address: 0x005BE530 (FUN_005BE530)
   *
   * What it does:
   * Startup helper-cleanup thunk for `SPerArmyReconInfoSerializer` that unlinks
   * the intrusive node and returns the helper self node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SPerArmyReconInfoSerializerStartupThunkA()
  {
    if (!gSPerArmyReconInfoSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireSPerArmyReconInfoSerializer());
  }

  /**
   * Address: 0x005BE560 (FUN_005BE560)
   *
   * What it does:
   * Secondary startup helper-cleanup thunk for
   * `SPerArmyReconInfoSerializer` with identical unlink/self-link behavior.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_SPerArmyReconInfoSerializerStartupThunkB()
  {
    return cleanup_SPerArmyReconInfoSerializerStartupThunkA();
  }

  /**
   * Address: 0x00BF7930 (FUN_00BF7930, cleanup_ReconBlipSerializer)
   *
   * What it does:
   * Unlinks static serializer helper storage for `ReconBlip`.
   */
  void cleanup_ReconBlipSerializer()
  {
    if (!gReconBlipSerializerConstructed) {
      return;
    }

    moho::ReconBlipSerializer* const serializer = AcquireReconBlipSerializer();
    (void)UnlinkSerializerNode(*serializer);
  }

  /**
   * Address: 0x005BFCE0 (FUN_005BFCE0)
   *
   * What it does:
   * Startup helper-cleanup thunk for `ReconBlipSerializer` that unlinks the
   * intrusive node and returns the helper self node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_ReconBlipSerializerStartupThunkA()
  {
    if (!gReconBlipSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireReconBlipSerializer());
  }

  /**
   * Address: 0x005BFD10 (FUN_005BFD10)
   *
   * What it does:
   * Secondary startup helper-cleanup thunk for `ReconBlipSerializer` with
   * identical unlink/self-link behavior.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_ReconBlipSerializerStartupThunkB()
  {
    return cleanup_ReconBlipSerializerStartupThunkA();
  }

  struct ReconBlipSerializerBootstrap
  {
    ReconBlipSerializerBootstrap()
    {
      moho::register_SPerArmyReconInfoSerializer();
      moho::register_ReconBlipSerializer();
    }
  };

  [[maybe_unused]] ReconBlipSerializerBootstrap gReconBlipSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005BE4C0 (FUN_005BE4C0, Moho::SPerArmyReconInfoSerializer::Deserialize)
   */
  void SPerArmyReconInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const
  )
  {
    auto* const object = reinterpret_cast<SPerArmyReconInfo*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberDeserialize(archive, version);
  }

  /**
   * Address: 0x005BE4E0 (FUN_005BE4E0, Moho::SPerArmyReconInfoSerializer::Serialize)
   */
  void SPerArmyReconInfoSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const
  )
  {
    auto* const object = reinterpret_cast<SPerArmyReconInfo*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberSerialize(archive, version);
  }

  /**
   * Address: 0x005C3DE0 (FUN_005C3DE0, Moho::SPerArmyReconInfoSerializer::RegisterSerializeFunctions)
   */
  void SPerArmyReconInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolvePerArmyReconInfoType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BCDBD0 (FUN_00BCDBD0, register_SPerArmyReconInfoSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `SPerArmyReconInfo` and installs
   * process-exit cleanup.
   */
  void register_SPerArmyReconInfoSerializer()
  {
    SPerArmyReconInfoSerializer* const serializer = AcquireSPerArmyReconInfoSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &SPerArmyReconInfoSerializer::Deserialize;
    serializer->mSaveCallback = &SPerArmyReconInfoSerializer::Serialize;
    (void)std::atexit(&cleanup_SPerArmyReconInfoSerializer);
  }

  /**
   * Address: 0x005BFC90 (FUN_005BFC90, Moho::ReconBlipSerializer::Deserialize)
   */
  void ReconBlipSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const object = reinterpret_cast<ReconBlip*>(static_cast<std::uintptr_t>(objectPtr));
    DeserializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x005BFCA0 (FUN_005BFCA0, Moho::ReconBlipSerializer::Serialize)
   */
  void ReconBlipSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const object = reinterpret_cast<const ReconBlip*>(static_cast<std::uintptr_t>(objectPtr));
    SerializeReconBlipMembers(object, archive);
  }

  /**
   * Address: 0x005C43B0 (FUN_005C43B0, gpg::SerSaveLoadHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void ReconBlipSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BCDCE0 (FUN_00BCDCE0, register_ReconBlipSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `ReconBlip` and installs process-exit
   * cleanup.
   */
  void register_ReconBlipSerializer()
  {
    ReconBlipSerializer* const serializer = AcquireReconBlipSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &ReconBlipSerializer::Deserialize;
    serializer->mSaveCallback = &ReconBlipSerializer::Serialize;
    (void)std::atexit(&cleanup_ReconBlipSerializer);
  }
} // namespace moho
