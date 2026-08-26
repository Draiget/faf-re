#include "moho/entity/SSTIEntityConstantData.h"

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  class SSTIEntityConstantDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIEntityConstantData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIEntityConstantData);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Element-type reflection cache for `SSTIEntityConstantData` itself, mirroring
   * the `Cached<Type>Type()`/`Resolve<Type>Type()` helpers used throughout this
   * codebase for the same lazy-resolve-and-cache need (e.g. `CachedShieldType`
   * in Shield.cpp).
   */
  [[nodiscard]] gpg::RType* CachedSSTIEntityConstantDataType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::SSTIEntityConstantData));
    }
    return sType;
  }

  /**
   * VFTABLE: matches every other `SerSaveLoadHelper<T>` payload in this
   * codebase (vtable + `moho::TDatListItem` link pair + load/save callback
   * lanes = 0x14 bytes total).
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::SSTIEntityConstantData>
   */
  struct SSTIEntityConstantDataSerializerHelperNode : public gpg::SerHelperBase
  {
    /**
     * Address: 0x00BC9FE0 vtable slot 0 dispatch target (dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` once this helper is drained from
     * the pending list).
     *
     * What it does:
     * Binds this helper's already-cited load/save callbacks
     * (`DeserializeSSTIEntityConstantDataSerializerCallback` /
     * `SerializeSSTIEntityConstantDataSerializerCallback`) onto
     * `SSTIEntityConstantData`'s reflected type descriptor.
     */
    void Init() override
    {
      gpg::RType* const type = CachedSSTIEntityConstantDataType();
      GPG_ASSERT(type != nullptr);
      GPG_ASSERT(type->serLoadFunc_ == nullptr);
      type->serLoadFunc_ = mSerLoadFunc;
      GPG_ASSERT(type->serSaveFunc_ == nullptr);
      type->serSaveFunc_ = mSerSaveFunc;
    }

    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(SSTIEntityConstantDataSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SSTIEntityConstantDataSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIEntityConstantDataSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SSTIEntityConstantDataSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SSTIEntityConstantDataSerializerHelperNode) == 0x14,
    "SSTIEntityConstantDataSerializerHelperNode size must be 0x14"
  );

  SSTIEntityConstantDataSerializerHelperNode gSSTIEntityConstantDataSerializer{};

  /**
   * Address: 0x00558170 (FUN_00558170, SerSaveLoadHelper<SSTIEntityConstantData>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTIEntityConstantData` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  void UnlinkSSTIEntityConstantDataSerializerLaneA() noexcept
  {
    gSSTIEntityConstantDataSerializer.ResetLinks();
  }

  // Address 0x005581A0 (unlink "lane B", a duplicate of lane A above)
  // formerly modeled here is dead: zero data_refs/call_edges and no
  // source-level caller anywhere in src/sdk/**.
  // UnlinkSSTIEntityConstantDataSerializerLaneA above is the real body --
  // cleanup_SSTIEntityConstantDataSerializer_atexit below calls it directly,
  // and that cleanup function is atexit-registered from the ctor.

  /**
   * Address: 0x00558110 (FUN_00558110, Moho::SSTIEntityConstantDataSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SSTIEntityConstantData`. Forwards
   * the reflected object pointer to
   * `SSTIEntityConstantData::MemberDeserialize` (FUN_00559990 body);
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  void DeserializeSSTIEntityConstantDataSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const data = reinterpret_cast<moho::SSTIEntityConstantData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00558120 (FUN_00558120, Moho::SSTIEntityConstantDataSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SSTIEntityConstantData`. Forwards
   * the reflected object pointer to
   * `SSTIEntityConstantData::MemberSerialize` (FUN_00559A00 body);
   * `version` and the owner-ref lane are unused by the member (mirrors the
   * binary tail call).
   */
  void SerializeSSTIEntityConstantDataSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const data = reinterpret_cast<const moho::SSTIEntityConstantData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF4E40 (FUN_00BF4E40, Moho::SSTIEntityConstantDataSerializer::~SSTIEntityConstantDataSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `SSTIEntityConstantDataSerializer`
   * helper node, matching the sibling unlink lanes used across other
   * serializer registrars.
   */
  void cleanup_SSTIEntityConstantDataSerializer_atexit()
  {
    UnlinkSSTIEntityConstantDataSerializerLaneA();
  }

  /**
   * Address: 0x00BC9FE0 (FUN_00BC9FE0, register_SSTIEntityConstantDataSerializer)
   *
   * What it does:
   * Binds the global `SSTIEntityConstantData` serializer helper's load/save
   * callback lanes and installs process-exit cleanup via `atexit`. The
   * helper node self-links and splices into `gpg::SerHelperBase::sNewHelpers`
   * automatically as part of its own construction (base-class construction
   * order guarantees this runs before this function does), so this no longer
   * needs to unlink/self-link the node itself before setting the callbacks.
   */
  void register_SSTIEntityConstantDataSerializer()
  {
    gSSTIEntityConstantDataSerializer.mSerLoadFunc = &DeserializeSSTIEntityConstantDataSerializerCallback;
    gSSTIEntityConstantDataSerializer.mSerSaveFunc = &SerializeSSTIEntityConstantDataSerializerCallback;
    (void)std::atexit(&cleanup_SSTIEntityConstantDataSerializer_atexit);
  }

  struct SSTIEntityConstantDataSerializerStartupBootstrap
  {
    SSTIEntityConstantDataSerializerStartupBootstrap()
    {
      register_SSTIEntityConstantDataSerializer();
    }
  };

  [[maybe_unused]] SSTIEntityConstantDataSerializerStartupBootstrap gSSTIEntityConstantDataSerializerStartupBootstrap;

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(std::int32_t));
      }
    }
    return sType;
  }

  /**
   * Address: 0x00559A80 (FUN_00559A80)
   *
   * What it does:
   * Deserializes one reflected `EntId` value lane using lazy type lookup.
   */
  void DeserializeEntIdField(void* const valueStorage, gpg::ReadArchive* const archive)
  {
    if (archive == nullptr || valueStorage == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Read(entIdType, valueStorage, nullOwner);
  }

  /**
   * Address: 0x00559AC0 (FUN_00559AC0)
   *
   * What it does:
   * Serializes one reflected `EntId` value lane using lazy type lookup.
   */
  void SerializeEntIdField(const void* const valueStorage, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || valueStorage == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Write(entIdType, valueStorage, nullOwner);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00557FC0 (FUN_00557FC0, preregister_SSTIEntityConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityConstantData`.
   */
  gpg::RType* preregister_SSTIEntityConstantDataTypeInfo()
  {
    static SSTIEntityConstantDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIEntityConstantData), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00559990 (FUN_00559990, Moho::SSTIEntityConstantData::MemberDeserialize)
   *
   * What it does:
   * Deserializes entity id, unowned entity-blueprint pointer, and creation tick.
   */
  void SSTIEntityConstantData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    DeserializeEntIdField(&mEntityId, archive);
    archive->ReadPointer_REntityBlueprint(&mBlueprint, &nullOwner);
    archive->ReadUInt(&mTickCreated);
  }

  /**
   * Address: 0x00559A00 (FUN_00559A00, Moho::SSTIEntityConstantData::MemberSerialize)
   *
   * What it does:
   * Serializes entity id, unowned entity-blueprint pointer, and creation tick.
   */
  void SSTIEntityConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    SerializeEntIdField(&mEntityId, archive);

    gpg::RRef blueprintRef{};
    gpg::RRef_REntityBlueprint(&blueprintRef, mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->WriteUInt(mTickCreated);
  }

  // Addresses 0x005592C0 ("ThunkA") and 0x005596E0/0x00672500 ("ThunkB",
  // two compiled addresses for the same body) formerly modeled here are
  // dead: zero data_refs/call_edges for all three, and no source-level
  // caller anywhere in src/sdk/**. `SSTIEntityConstantDataSerializer::
  // Serialize` above already calls `SSTIEntityConstantData::MemberSerialize`
  // directly.
} // namespace moho

namespace
{
  struct SSTIEntityConstantDataTypeInfoBootstrap
  {
    SSTIEntityConstantDataTypeInfoBootstrap()
    {
      (void)moho::preregister_SSTIEntityConstantDataTypeInfo();
    }
  };

  [[maybe_unused]] SSTIEntityConstantDataTypeInfoBootstrap gSSTIEntityConstantDataTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTIEntityConstantDataTypeInfo_f23d45, moho::preregister_SSTIEntityConstantDataTypeInfo)
