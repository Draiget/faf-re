#include "moho/entity/SSTIEntityVariableData.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSndParams.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityId.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  constexpr std::uint32_t kAttachmentParentSentinel = moho::ToRaw(moho::EEntityIdSentinel::Invalid);
  constexpr moho::EUserEntityVisibilityMode kDefaultVisibilityMode = moho::EUserEntityVisibilityMode::MapPlayableRect;

  class SSTIEntityAttachInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIEntityAttachInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIEntityAttachInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  class EntityAttributesTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "EntityAttributes";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIIntelAttributes);
      gpg::RType::Init();
      Finish();
    }
  };

  moho::SSTIEntityVariableDataSerializer gSSTIEntityVariableDataSerializer{};

  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes, matching every other SerHelperBase-derived serializer
  // in this codebase) - `gpg::SerSaveLoadHelperListRuntime` only models the
  // leading 0x0C-byte intrusive-list header shared by all of them, so it
  // undersized this specific global. Use the full shape here instead.
  struct EntityAttributesSerializerHelper
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
  static_assert(
    offsetof(EntityAttributesSerializerHelper, mNext) == 0x04,
    "EntityAttributesSerializerHelper::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(EntityAttributesSerializerHelper, mPrev) == 0x08,
    "EntityAttributesSerializerHelper::mPrev offset must be 0x08"
  );
  static_assert(
    sizeof(EntityAttributesSerializerHelper) == 0x14, "EntityAttributesSerializerHelper size must be 0x14"
  );

  EntityAttributesSerializerHelper gEntityAttributesSerializer{};

  // Same 0x14-byte SerHelperBase-derived shape as gEntityAttributesSerializer
  // above (vtable + mNext/mPrev + load/save callback lanes) -- reused here
  // rather than duplicating the layout for a second serializer global.
  EntityAttributesSerializerHelper gSSTIEntityAttachInfoSerializer{};

  [[nodiscard]] gpg::SerSaveLoadHelperListRuntime& AsSerSaveLoadHelperListRuntime(
    EntityAttributesSerializerHelper& helper
  ) noexcept
  {
    return *reinterpret_cast<gpg::SerSaveLoadHelperListRuntime*>(&helper);
  }

  [[nodiscard]] gpg::SerSaveLoadHelperListRuntime&
  AsSerSaveLoadHelperListRuntime(moho::SSTIEntityVariableDataSerializer& serializer) noexcept
  {
    return *reinterpret_cast<gpg::SerSaveLoadHelperListRuntime*>(&serializer);
  }

  /**
   * Address: 0x005583C0 (FUN_005583C0, SerSaveLoadHelper<SSTIEntityAttachInfo>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTIEntityAttachInfo` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityAttachInfoSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gSSTIEntityAttachInfoSerializer));
  }

  /**
   * Address: 0x005583F0 (FUN_005583F0, SerSaveLoadHelper<SSTIEntityAttachInfo>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the
   * `SSTIEntityAttachInfo` serializer helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityAttachInfoSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gSSTIEntityAttachInfoSerializer));
  }

  /**
   * Address: 0x00558310 (FUN_00558310, Moho::SSTIEntityAttachInfoSerializer::Deserialize)
   *
   * What it does:
   * Reads one `SSTIEntityAttachInfo` (a raw `EntId`) from the archive
   * through `moho::EntId`'s reflected type.
   */
  void DeserializeSSTIEntityAttachInfoSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    gpg::RType* type = moho::SSTIEntityAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::EntId));
      moho::SSTIEntityAttachInfo::sType = type;
    }

    const gpg::RRef entIdRef{};
    archive->Read(type, reinterpret_cast<void*>(static_cast<std::uintptr_t>(objectPtr)), entIdRef);
  }

  /**
   * Address: 0x00558350 (FUN_00558350, Moho::SSTIEntityAttachInfoSerializer::Serialize)
   *
   * What it does:
   * Writes one `SSTIEntityAttachInfo` (a raw `EntId`) to the archive through
   * `moho::EntId`'s reflected type.
   */
  void SerializeSSTIEntityAttachInfoSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    gpg::RType* type = moho::SSTIEntityAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::EntId));
      moho::SSTIEntityAttachInfo::sType = type;
    }

    const gpg::RRef entIdRef{};
    archive->Write(type, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr)), entIdRef);
  }

  /**
   * Address: 0x00BF4ED0 (FUN_00BF4ED0, Moho::SSTIEntityAttachInfoSerializer::~SSTIEntityAttachInfoSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `SSTIEntityAttachInfo` serializer
   * helper node, matching the sibling `EntityAttributes` cleanup lane.
   */
  void cleanup_SSTIEntityAttachInfoSerializer_atexit()
  {
    (void)UnlinkSSTIEntityAttachInfoSerializerLaneA();
  }

  /**
   * Address: 0x00BCA040 (FUN_00BCA040, register_SSTIEntityAttachInfoSerializer)
   *
   * What it does:
   * Initializes the global SSTIEntityAttachInfo serializer helper callbacks
   * and installs process-exit cleanup.
   */
  void register_SSTIEntityAttachInfoSerializer()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSSTIEntityAttachInfoSerializer.mNext);
    gSSTIEntityAttachInfoSerializer.mNext = self;
    gSSTIEntityAttachInfoSerializer.mPrev = self;
    gSSTIEntityAttachInfoSerializer.mLoadCallback = &DeserializeSSTIEntityAttachInfoSerializerCallback;
    gSSTIEntityAttachInfoSerializer.mSaveCallback = &SerializeSSTIEntityAttachInfoSerializerCallback;
    (void)std::atexit(&cleanup_SSTIEntityAttachInfoSerializer_atexit);
  }

  /**
   * Address: 0x005585C0 (FUN_005585C0, SerSaveLoadHelper<EntityAttributes>::unlink lane A)
   *
   * What it does:
   * Unlinks `EntityAttributes` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkEntityAttributesSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gEntityAttributesSerializer));
  }

  /**
   * Address: 0x005585F0 (FUN_005585F0, SerSaveLoadHelper<EntityAttributes>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the
   * `EntityAttributes` serializer helper node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkEntityAttributesSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gEntityAttributesSerializer));
  }

  void DeserializeEntityAttributesSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<moho::EntityAttributes*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  void SerializeEntityAttributesSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<const moho::EntityAttributes*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
  }

  void cleanup_EntityAttributesSerializer_atexit()
  {
    (void)UnlinkEntityAttributesSerializerLaneA();
  }

  /**
   * Address: 0x00BCA0A0 (FUN_00BCA0A0, register_EntityAttributesSerializer)
   *
   * What it does:
   * Initializes the global EntityAttributes serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_EntityAttributesSerializer()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gEntityAttributesSerializer.mNext);
    gEntityAttributesSerializer.mNext = self;
    gEntityAttributesSerializer.mPrev = self;
    gEntityAttributesSerializer.mLoadCallback = &DeserializeEntityAttributesSerializerCallback;
    gEntityAttributesSerializer.mSaveCallback = &SerializeEntityAttributesSerializerCallback;
    (void)std::atexit(&cleanup_EntityAttributesSerializer_atexit);
  }

  /**
   * Address: 0x00558900 (FUN_00558900, SerSaveLoadHelper<SSTIEntityVariableData>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTIEntityVariableData` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityVariableDataSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gSSTIEntityVariableDataSerializer));
  }

  /**
   * Address: 0x00558930 (FUN_00558930, SerSaveLoadHelper<SSTIEntityVariableData>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the
   * `SSTIEntityVariableData` serializer helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityVariableDataSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gSSTIEntityVariableDataSerializer));
  }

  void DeserializeSSTIEntityVariableDataSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<moho::SSTIEntityVariableData*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || object == nullptr) {
      return;
    }

    object->MemberDeserialize(archive, 2);
  }

  void SerializeSSTIEntityVariableDataSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<moho::SSTIEntityVariableData*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || object == nullptr) {
      return;
    }

    object->MemberSerialize(archive, 2);
  }

  /**
   * Address: 0x005588D0 (FUN_005588D0)
   *
   * What it does:
   * Initializes callback lanes for global `SSTIEntityVariableDataSerializer`
   * helper storage and returns that helper object.
   */
  [[nodiscard]] moho::SSTIEntityVariableDataSerializer*
  InitializeSSTIEntityVariableDataSerializerStartupThunk()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSSTIEntityVariableDataSerializer.mNext);
    gSSTIEntityVariableDataSerializer.mPrev = self;
    gSSTIEntityVariableDataSerializer.mNext = self;
    gSSTIEntityVariableDataSerializer.mSerLoadFunc = &DeserializeSSTIEntityVariableDataSerializerCallback;
    gSSTIEntityVariableDataSerializer.mSerSaveFunc = &SerializeSSTIEntityVariableDataSerializerCallback;
    return &gSSTIEntityVariableDataSerializer;
  }

  void cleanup_SSTIEntityVariableDataSerializer_atexit()
  {
    (void)UnlinkSSTIEntityVariableDataSerializerLaneA();
  }

  /**
   * Address: 0x00BCA100 (FUN_00BCA100, register_SSTIEntityVariableDataSerializer)
   *
   * What it does:
   * Initializes the global SSTIEntityVariableData serializer helper
   * callbacks and installs process-exit cleanup.
   */
  void register_SSTIEntityVariableDataSerializer()
  {
    (void)InitializeSSTIEntityVariableDataSerializerStartupThunk();
    (void)std::atexit(&cleanup_SSTIEntityVariableDataSerializer_atexit);
  }

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

  [[nodiscard]] gpg::RType* ResolveRScmResourceType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"RScmResource", "Moho::RScmResource"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::RScmResource));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveRMeshBlueprintType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"RMeshBlueprint", "Moho::RMeshBlueprint"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::RMeshBlueprint));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(Wm3::Vec3f));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVTransformType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::VTransform));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveAttachInfoVectorType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName(
        {
          "fastvector<SSTIEntityAttachInfo>",
          "gpg::fastvector<Moho::SSTIEntityAttachInfo>",
          "gpg::fastvector<SSTIEntityAttachInfo>",
        }
      );
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::SSTIInlineUIntVector));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCSndParamsType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"CSndParams", "Moho::CSndParams"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::CSndParams));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVisibilityModeType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EVisibilityMode", "Moho::EVisibilityMode"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveLayerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"ELayer", "Moho::ELayer"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityAttributesType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EntityAttributes", "Moho::EntityAttributes", "SSTIIntelAttributes"});
      if (!sType) {
        sType = moho::preregister_EntityAttributesTypeInfo();
      }
    }
    return sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeObjectRef(TObject* const object, gpg::RType* const type)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = type;
    return ref;
  }

  void ReadBoolByte(gpg::ReadArchive* const archive, std::uint8_t& value)
  {
    bool loaded = false;
    archive->ReadBool(&loaded);
    value = loaded ? 1u : 0u;
  }

  void ReadSharedRScmResourcePointer(
    boost::shared_ptr<moho::RScmResource>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    static_assert(
      sizeof(boost::shared_ptr<moho::RScmResource>) == sizeof(boost::SharedPtrRaw<moho::RScmResource>),
      "boost::shared_ptr<RScmResource> must match legacy raw shared-pointer layout"
    );

    auto& rawPointer = *reinterpret_cast<boost::SharedPtrRaw<moho::RScmResource>*>(&outPointer);
    gpg::ReadPointerShared_RScmResource(rawPointer, archive, ownerRef);
  }

  struct SSTIEntityVariableDataSlotRuntime
  {
    std::uint32_t mHeaderWord0 = 0;               // +0x00
    std::uint32_t mHeaderWord1 = 0;               // +0x04
    moho::SSTIEntityVariableData mVariableData{}; // +0x08
  };

  static_assert(
    offsetof(SSTIEntityVariableDataSlotRuntime, mVariableData) == 0x08,
    "SSTIEntityVariableDataSlotRuntime::mVariableData offset must be 0x08"
  );
  static_assert(sizeof(SSTIEntityVariableDataSlotRuntime) == 0xD8, "SSTIEntityVariableDataSlotRuntime size must be 0xD8");

  /**
   * Address: 0x005616A0 (FUN_005616A0)
   *
   * What it does:
   * Destroys one contiguous slot range by invoking
   * `SSTIEntityVariableData` destructor on each embedded payload lane at
   * slot offset `+0x08`.
   */
  [[maybe_unused]] void DestroySSTIEntityVariableDataSlotPayloadRange(
    SSTIEntityVariableDataSlotRuntime* begin,
    SSTIEntityVariableDataSlotRuntime* const end
  )
  {
    while (begin != end) {
      begin->mVariableData.~SSTIEntityVariableData();
      ++begin;
    }
  }

  /**
   * Address: 0x00676AC0 (FUN_00676AC0)
   *
   * What it does:
   * Initializes one counted slot header to `0xF0000000` and default-constructs
   * the embedded `SSTIEntityVariableData` payload at offset `+0x08`.
   */
  [[maybe_unused]] SSTIEntityVariableDataSlotRuntime* ConstructSSTIEntityVariableDataSlotRuntime(
    SSTIEntityVariableDataSlotRuntime* const slot
  )
  {
    slot->mHeaderWord0 = 0xF0000000u;
    ::new (&slot->mVariableData) moho::SSTIEntityVariableData();
    return slot;
  }

  /**
   * Address: 0x00563380 (FUN_00563380, copy_SSTIEntityVariableData_slot_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one contiguous slot range (`header + SSTIEntityVariableData`)
   * into destination storage and destroys already-constructed payload lanes
   * before rethrowing if a copy step throws.
   */
  SSTIEntityVariableDataSlotRuntime* CopySSTIEntityVariableDataSlotRangeWithRollback(
    const SSTIEntityVariableDataSlotRuntime* sourceBegin,
    const SSTIEntityVariableDataSlotRuntime* sourceEnd,
    SSTIEntityVariableDataSlotRuntime* destinationBegin
  )
  {
    SSTIEntityVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (const SSTIEntityVariableDataSlotRuntime* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
          ::new (&destinationCursor->mVariableData) moho::SSTIEntityVariableData();
          (void)sourceCursor->mVariableData.cpy(&destinationCursor->mVariableData);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (SSTIEntityVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTIEntityVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x00562B40 (FUN_00562B40)
   *
   * What it does:
   * Primary adapter lane that forwards one contiguous
   * `SSTIEntityVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTIEntityVariableDataSlotRangeWithRollbackAdapterLaneA(
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIEntityVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00563030 (FUN_00563030)
   *
   * What it does:
   * Secondary adapter lane that forwards one contiguous
   * `SSTIEntityVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTIEntityVariableDataSlotRangeWithRollbackAdapterLaneB(
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIEntityVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00563220 (FUN_00563220)
   *
   * What it does:
   * Tertiary adapter lane that forwards one contiguous
   * `SSTIEntityVariableData` slot-range copy into the canonical rollback
   * helper.
   */
  [[maybe_unused]] void CopySSTIEntityVariableDataSlotRangeWithRollbackAdapterLaneC(
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIEntityVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00680970 (FUN_00680970, copy_SSTIEntityVariableData_slot_range_with_rollback_counted)
   *
   * What it does:
   * Copy-constructs one counted slot range (`header + SSTIEntityVariableData`)
   * into destination storage and destroys already-constructed payload lanes
   * before rethrowing if a copy step throws.
   */
  SSTIEntityVariableDataSlotRuntime* CopySSTIEntityVariableDataSlotRangeWithRollbackCounted(
    const std::uint32_t count,
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin
  )
  {
    if (count == 0u) {
      return destinationBegin;
    }

    if (destinationBegin == nullptr || sourceBegin == nullptr) {
      return destinationBegin;
    }

    SSTIEntityVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (std::uint32_t i = 0; i < count; ++i, ++destinationCursor) {
        const SSTIEntityVariableDataSlotRuntime* const sourceCursor = sourceBegin + i;
        destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
        ::new (&destinationCursor->mVariableData) moho::SSTIEntityVariableData();
        (void)sourceCursor->mVariableData.cpy(&destinationCursor->mVariableData);
      }
      return destinationCursor;
    } catch (...) {
      for (SSTIEntityVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTIEntityVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x0067F750 (FUN_0067F750)
   *
   * What it does:
   * Register-shape adapter that forwards one pre-counted contiguous
   * `SSTIEntityVariableData` slot copy lane into the canonical counted helper.
   */
  [[maybe_unused]] SSTIEntityVariableDataSlotRuntime* CopySSTIEntityVariableDataSlotRangeWithRollbackCountedRegisterAdapter(
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const std::uint32_t count
  )
  {
    return CopySSTIEntityVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x0067C7C0 (FUN_0067C7C0)
   *
   * What it does:
   * Alternate register-lane adapter for counted contiguous
   * `SSTIEntityVariableData` slot copy-construction.
   */
  [[maybe_unused]] SSTIEntityVariableDataSlotRuntime* CopySSTIEntityVariableDataSlotRangeWithRollbackCountedAdapterLaneB(
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    SSTIEntityVariableDataSlotRuntime* const destinationBegin,
    const std::uint32_t count
  )
  {
    return CopySSTIEntityVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x00562650 (FUN_00562650)
   *
   * What it does:
   * Register-shape adapter for guarded contiguous
   * `SSTIEntityVariableData` slot copy-construction.
   */
  [[maybe_unused]] SSTIEntityVariableDataSlotRuntime* CopySSTIEntityVariableDataSlotRangeWithRollbackRegisterAdapter(
    const SSTIEntityVariableDataSlotRuntime* const sourceBegin,
    const SSTIEntityVariableDataSlotRuntime* const sourceEnd,
    SSTIEntityVariableDataSlotRuntime* const destinationBegin
  )
  {
    if (!sourceBegin || !sourceEnd || sourceEnd < sourceBegin) {
      return destinationBegin;
    }

    const std::uint32_t count = static_cast<std::uint32_t>(sourceEnd - sourceBegin);
    return CopySSTIEntityVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  struct SerSaveLoadHelperInitRuntimeView
  {
    void* mVTable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoadCallback = nullptr; // +0x0C
    gpg::RType::save_func_t mSaveCallback = nullptr; // +0x10
  };
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperInitRuntimeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperInitRuntimeView::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mLoadCallback) == 0x0C,
    "SerSaveLoadHelperInitRuntimeView::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mSaveCallback) == 0x10,
    "SerSaveLoadHelperInitRuntimeView::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerSaveLoadHelperInitRuntimeView) == 0x14,
    "SerSaveLoadHelperInitRuntimeView size must be 0x14"
  );

  /**
   * Address: 0x00558B20 (FUN_00558B20, gpg::SerSaveLoadHelper_SSTIEntityAttachInfo::Init)
   *
   * What it does:
   * Resolves reflected type metadata for `SSTIEntityAttachInfo` and binds one
   * serializer helper's load/save callback lanes into that RTTI entry.
   */
  void InstallSSTIEntityAttachInfoSerializerCallbacks(SerSaveLoadHelperInitRuntimeView* const helper)
  {
    gpg::RType* type = moho::SSTIEntityAttachInfo::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SSTIEntityAttachInfo));
      moho::SSTIEntityAttachInfo::sType = type;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
    }

    const bool saveWasNull = type->serSaveFunc_ == nullptr;
    type->serLoadFunc_ = helper->mLoadCallback;

    if (!saveWasNull) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
    }

    type->serSaveFunc_ = helper->mSaveCallback;
  }
} // namespace

namespace moho
{
  gpg::RType* SSTIEntityVariableData::sType = nullptr;

  void SSTIInlineUIntVector::ResetToInlineStorage() noexcept
  {
    mInlineBegin = &mInlineStorage0;
    mBegin = mInlineBegin;
    mEnd = mInlineBegin;
    mCapacityEnd = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(mInlineStorage0));
  }

  void SSTIInlineUIntVector::ReleaseDynamicStorage() noexcept
  {
    if (mBegin != mInlineBegin) {
      delete[] mBegin;
      mBegin = mInlineBegin;
      mCapacityEnd = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(mInlineStorage0));
    }
    mEnd = mBegin;
  }

  void SSTIInlineUIntVector::AssignFrom(const SSTIInlineUIntVector& rhs)
  {
    if (this == &rhs) {
      return;
    }

    const std::size_t srcCount = rhs.Size();
    if (Capacity() < srcCount) {
      std::uint32_t* const newStorage = new std::uint32_t[srcCount];
      if (mBegin == mInlineBegin) {
        mInlineStorage0 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mCapacityEnd));
      } else {
        delete[] mBegin;
      }
      mBegin = newStorage;
      mCapacityEnd = newStorage + srcCount;
    }

    if (srcCount != 0u) {
      std::memcpy(mBegin, rhs.mBegin, srcCount * sizeof(std::uint32_t));
    }
    mEnd = mBegin + srcCount;
  }

  std::size_t SSTIInlineUIntVector::Size() const noexcept
  {
    if (!mBegin || !mEnd || mEnd < mBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(mEnd - mBegin);
  }

  std::size_t SSTIInlineUIntVector::Capacity() const noexcept
  {
    if (!mBegin || !mCapacityEnd || mCapacityEnd < mBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(mCapacityEnd - mBegin);
  }

  /**
   * Address: 0x00558760 (FUN_00558760, ??0SSTIEntityVariableData@Moho@@QAE@XZ)
   */
  SSTIEntityVariableData::SSTIEntityVariableData()
    : mScmResource()
    , mMeshBlueprint(nullptr)
    , mScale{1.0f, 1.0f, 1.0f}
    , mHealth(0.0f)
    , mMaxHealth(0.0f)
    , mIsBeingBuilt(0)
    , mIsDead(0)
    , mRequestRefreshUI(0)
    , pad_0023(0)
    , mCurTransform()
    , mLastTransform()
    , mCurImpactValue(1.0f)
    , mFractionComplete(1.0f)
    , mAttachmentParentRef(kAttachmentParentSentinel)
    , mAuxValueVector()
    , mScroll0U(0.0f)
    , mScroll0V(0.0f)
    , mScroll1U(0.0f)
    , mScroll1V(0.0f)
    , mAmbientSound(nullptr)
    , mRumbleSound(nullptr)
    , mVisibilityHidden(0)
    , pad_0099_009B{0, 0, 0}
    , mVisibilityMode(kDefaultVisibilityMode)
    , mLayerMask(0)
    , mUsingAltFootprint(0)
    , pad_00A5_00A7{0, 0, 0}
    , mUnderlayTexture()
    , mIntelAttributes{0, 0, 0, 0, 0, 0, 0, 0}
  {
    mAuxValueVector.mInlineStorage0 =
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&mAuxValueVector.mInlineStorage1));
    mAuxValueVector.ResetToInlineStorage();
  }

  /**
   * Address: 0x00560310 (FUN_00560310, ??1SSTIEntityVariableData@Moho@@QAE@XZ)
   */
  SSTIEntityVariableData::~SSTIEntityVariableData()
  {
    mUnderlayTexture.reset();
    mAuxValueVector.ReleaseDynamicStorage();
    mScmResource.reset();
  }

  /**
   * Address: 0x0067A3E0 (FUN_0067A3E0, ??4SSTIEntityVariableData@Moho@@QAEAAU01@ABU01@@Z)
   */
  SSTIEntityVariableData& SSTIEntityVariableData::operator=(const SSTIEntityVariableData& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    mScmResource = rhs.mScmResource;
    mMeshBlueprint = rhs.mMeshBlueprint;
    mScale = rhs.mScale;
    mHealth = rhs.mHealth;
    mMaxHealth = rhs.mMaxHealth;
    mIsBeingBuilt = rhs.mIsBeingBuilt;
    mIsDead = rhs.mIsDead;
    mRequestRefreshUI = rhs.mRequestRefreshUI;
    mCurTransform = rhs.mCurTransform;
    mLastTransform = rhs.mLastTransform;
    mCurImpactValue = rhs.mCurImpactValue;
    mFractionComplete = rhs.mFractionComplete;
    mAttachmentParentRef = rhs.mAttachmentParentRef;
    mAuxValueVector.AssignFrom(rhs.mAuxValueVector);
    mScroll0U = rhs.mScroll0U;
    mScroll0V = rhs.mScroll0V;
    mScroll1U = rhs.mScroll1U;
    mScroll1V = rhs.mScroll1V;
    mAmbientSound = rhs.mAmbientSound;
    mRumbleSound = rhs.mRumbleSound;
    mVisibilityHidden = rhs.mVisibilityHidden;
    mVisibilityMode = rhs.mVisibilityMode;
    mLayerMask = rhs.mLayerMask;
    mUsingAltFootprint = rhs.mUsingAltFootprint;
    mUnderlayTexture = rhs.mUnderlayTexture;
    mIntelAttributes = rhs.mIntelAttributes;
    return *this;
  }

  /**
   * Address: 0x00560150 (FUN_00560150, Moho::SSTIEntityVariableData::cpy)
   */
  SSTIEntityVariableData* SSTIEntityVariableData::cpy(SSTIEntityVariableData* const destination) const
  {
    if (destination == nullptr) {
      return nullptr;
    }

    if (destination == this) {
      return destination;
    }

    destination->mScmResource = mScmResource;
    destination->mMeshBlueprint = mMeshBlueprint;
    destination->mScale = mScale;
    destination->mHealth = mHealth;
    destination->mMaxHealth = mMaxHealth;
    destination->mIsBeingBuilt = mIsBeingBuilt;
    destination->mIsDead = mIsDead;
    destination->mRequestRefreshUI = mRequestRefreshUI;
    destination->mCurTransform = mCurTransform;
    destination->mLastTransform = mLastTransform;
    destination->mCurImpactValue = mCurImpactValue;
    destination->mFractionComplete = mFractionComplete;
    destination->mAttachmentParentRef = mAttachmentParentRef;
    destination->mAuxValueVector.AssignFrom(mAuxValueVector);
    destination->mScroll0U = mScroll0U;
    destination->mScroll0V = mScroll0V;
    destination->mScroll1U = mScroll1U;
    destination->mScroll1V = mScroll1V;
    destination->mAmbientSound = mAmbientSound;
    destination->mRumbleSound = mRumbleSound;
    destination->mVisibilityHidden = mVisibilityHidden;
    destination->mVisibilityMode = mVisibilityMode;
    destination->mLayerMask = mLayerMask;
    destination->mUsingAltFootprint = mUsingAltFootprint;
    destination->mUnderlayTexture = mUnderlayTexture;
    destination->mIntelAttributes = mIntelAttributes;
    return destination;
  }

  /**
   * Address: 0x00559B00 (FUN_00559B00, Moho::SSTIEntityVariableData::MemberDeserialize)
   *
   * What it does:
   * Deserializes the version-2 reflected payload in the same field order used
   * by `MemberSerialize` and rejects older serializer versions.
   */
  void SSTIEntityVariableData::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
  {
    if (version < 2) {
      throw gpg::SerializationError("Unsupported version.");
    }

    const gpg::RRef ownerRef{};

    ReadSharedRScmResourcePointer(mScmResource, archive, ownerRef);

    RMeshBlueprint* meshBlueprint = const_cast<RMeshBlueprint*>(mMeshBlueprint);
    (void)archive->ReadPointer_RMeshBlueprint(&meshBlueprint, &ownerRef);
    mMeshBlueprint = meshBlueprint;

    gpg::RType* const vector3Type = ResolveVector3fType();
    GPG_ASSERT(vector3Type != nullptr);
    archive->Read(vector3Type, &mScale, ownerRef);
    archive->ReadFloat(&mHealth);
    archive->ReadFloat(&mMaxHealth);
    ReadBoolByte(archive, mIsBeingBuilt);
    ReadBoolByte(archive, mIsDead);
    ReadBoolByte(archive, mRequestRefreshUI);

    gpg::RType* const transformType = ResolveVTransformType();
    GPG_ASSERT(transformType != nullptr);
    archive->Read(transformType, &mCurTransform, ownerRef);
    archive->Read(transformType, &mLastTransform, ownerRef);
    archive->ReadFloat(&mCurImpactValue);
    archive->ReadFloat(&mFractionComplete);

    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Read(entIdType, &mAttachmentParentRef, ownerRef);

    gpg::RType* const attachInfoType = ResolveAttachInfoVectorType();
    GPG_ASSERT(attachInfoType != nullptr);
    archive->Read(attachInfoType, &mAuxValueVector, ownerRef);

    archive->ReadFloat(&mScroll0U);
    archive->ReadFloat(&mScroll0V);
    archive->ReadFloat(&mScroll1U);
    archive->ReadFloat(&mScroll1V);

    (void)archive->ReadPointer_CSndParams2(&mAmbientSound, &ownerRef);
    (void)archive->ReadPointer_CSndParams2(&mRumbleSound, &ownerRef);

    ReadBoolByte(archive, mVisibilityHidden);

    gpg::RType* const visibilityModeType = ResolveVisibilityModeType();
    GPG_ASSERT(visibilityModeType != nullptr);
    archive->Read(visibilityModeType, &mVisibilityMode, ownerRef);

    gpg::RType* const layerType = ResolveLayerType();
    GPG_ASSERT(layerType != nullptr);
    archive->Read(layerType, &mLayerMask, ownerRef);

    ReadBoolByte(archive, mUsingAltFootprint);

    gpg::RType* const attributesType = ResolveEntityAttributesType();
    GPG_ASSERT(attributesType != nullptr);
    archive->Read(attributesType, &mIntelAttributes, ownerRef);
  }

  /**
   * Address: 0x00559E00 (FUN_00559E00, Moho::SSTIEntityVariableData::MemberSerialize)
   */
  void SSTIEntityVariableData::MemberSerialize(gpg::WriteArchive* const archive, const int version)
  {
    if (version < 2) {
      throw gpg::SerializationError("Unsupported version.");
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const scmType = ResolveRScmResourceType();
    GPG_ASSERT(scmType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(const_cast<RScmResource*>(mScmResource.get()), scmType),
      gpg::TrackedPointerState::Shared,
      ownerRef
    );

    gpg::RType* const meshType = ResolveRMeshBlueprintType();
    GPG_ASSERT(meshType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(const_cast<RMeshBlueprint*>(mMeshBlueprint), meshType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );

    gpg::RType* const vector3Type = ResolveVector3fType();
    GPG_ASSERT(vector3Type != nullptr);
    archive->Write(vector3Type, &mScale, ownerRef);
    archive->WriteFloat(mHealth);
    archive->WriteFloat(mMaxHealth);
    archive->WriteBool(mIsBeingBuilt != 0u);
    archive->WriteBool(mIsDead != 0u);
    archive->WriteBool(mRequestRefreshUI != 0u);

    gpg::RType* const transformType = ResolveVTransformType();
    GPG_ASSERT(transformType != nullptr);
    archive->Write(transformType, &mCurTransform, ownerRef);
    archive->Write(transformType, &mLastTransform, ownerRef);
    archive->WriteFloat(mCurImpactValue);
    archive->WriteFloat(mFractionComplete);

    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Write(entIdType, &mAttachmentParentRef, ownerRef);

    gpg::RType* const attachInfoType = ResolveAttachInfoVectorType();
    GPG_ASSERT(attachInfoType != nullptr);
    archive->Write(attachInfoType, &mAuxValueVector, ownerRef);

    archive->WriteFloat(mScroll0U);
    archive->WriteFloat(mScroll0V);
    archive->WriteFloat(mScroll1U);
    archive->WriteFloat(mScroll1V);

    gpg::RType* const soundType = ResolveCSndParamsType();
    GPG_ASSERT(soundType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(mAmbientSound, soundType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(mRumbleSound, soundType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );

    archive->WriteBool(mVisibilityHidden != 0u);

    gpg::RType* const visibilityModeType = ResolveVisibilityModeType();
    GPG_ASSERT(visibilityModeType != nullptr);
    archive->Write(visibilityModeType, &mVisibilityMode, ownerRef);

    gpg::RType* const layerType = ResolveLayerType();
    GPG_ASSERT(layerType != nullptr);
    archive->Write(layerType, &mLayerMask, ownerRef);

    archive->WriteBool(mUsingAltFootprint != 0u);

    gpg::RType* const attributesType = ResolveEntityAttributesType();
    GPG_ASSERT(attributesType != nullptr);
    archive->Write(attributesType, &mIntelAttributes, ownerRef);
  }

  std::uint32_t SSTIEntityVariableData::GetVisibilityGridMask() const noexcept
  {
    return mLayerMask;
  }

  void SSTIEntityVariableData::SetVisibilityGridMask(const std::uint32_t gridMask) noexcept
  {
    mLayerMask = gridMask;
  }

  bool SSTIEntityVariableData::UsesUnderwaterReconGrid() const noexcept
  {
    return (mLayerMask & kUserEntityUnderwaterLayerMaskBits) != 0u;
  }

  /**
   * Address: 0x00558E40 (FUN_00558E40, sub_558E40)
   */
  void SSTIEntityVariableDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTIEntityVariableData::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SSTIEntityVariableData));
      SSTIEntityVariableData::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x005581D0 (FUN_005581D0, preregister_SSTIEntityAttachInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityAttachInfo`.
   */
  gpg::RType* preregister_SSTIEntityAttachInfoTypeInfo()
  {
    static SSTIEntityAttachInfoTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIEntityAttachInfo), &typeInfo);
    SSTIEntityAttachInfo::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x00558420 (FUN_00558420, preregister_EntityAttributesTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntityAttributes`.
   */
  gpg::RType* preregister_EntityAttributesTypeInfo()
  {
    static EntityAttributesTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIIntelAttributes), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00558620 (FUN_00558620, preregister_SSTIEntityVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityVariableData`.
   */
  gpg::RType* preregister_SSTIEntityVariableDataTypeInfo()
  {
    static SSTIEntityVariableDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIEntityVariableData), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x005586B0 (FUN_005586B0, sub_5586B0)
   */
  SSTIEntityVariableDataTypeInfo::~SSTIEntityVariableDataTypeInfo() = default;

  /**
   * Address: 0x005586A0 (FUN_005586A0, Moho::SSTIEntityVariableDataTypeInfo::GetName)
   */
  const char* SSTIEntityVariableDataTypeInfo::GetName() const
  {
    return "SSTIEntityVariableData";
  }

  /**
   * Address: 0x00558680 (FUN_00558680, Moho::SSTIEntityVariableDataTypeInfo::Init)
   */
  void SSTIEntityVariableDataTypeInfo::Init()
  {
    size_ = sizeof(SSTIEntityVariableData);
    gpg::RType::Init();
    version_ = 2;
    Finish();
  }

  // Cached reflected `SSTIEntityAttachInfo` lane.
  gpg::RType* SSTIEntityAttachInfo::sType = nullptr;
} // namespace moho

namespace
{
  struct SSTIEntityVariableDataSerializerStartupBootstrap
  {
    SSTIEntityVariableDataSerializerStartupBootstrap()
    {
      register_SSTIEntityVariableDataSerializer();
      register_EntityAttributesSerializer();
      register_SSTIEntityAttachInfoSerializer();
    }
  };

  [[maybe_unused]] SSTIEntityVariableDataSerializerStartupBootstrap gSSTIEntityVariableDataSerializerStartupBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTIEntityAttachInfoTypeInfo_a1a5ff, moho::preregister_SSTIEntityAttachInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_EntityAttributesTypeInfo_a1a5ff, moho::preregister_EntityAttributesTypeInfo)
GPG_PREREGISTER_INIT(preregister_SSTIEntityVariableDataTypeInfo_a1a5ff, moho::preregister_SSTIEntityVariableDataTypeInfo)
