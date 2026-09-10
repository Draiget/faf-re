#include "moho/ai/CAiFormationInstance.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <initializer_list>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "legacy/algorithms/Sort.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/Listener.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  bool COORDS_CanMoveAt(SOCellPos* pos, COGrid* grid, Unit* moveUnit, bool disallowAttached, Unit* ignoreUnit);
}

namespace
{
  using UnitOffsetMap = msvc8::map<moho::EntId, moho::SUnitOffsetInfo>;
  using CoordMap = msvc8::map<moho::EntId, moho::SCoordsVec2>;
  using UnitWeakSet = gpg::fastvector_n<moho::WeakPtr<moho::IUnit>, 4>;

  [[nodiscard]] gpg::RType* CachedEntIdType();
  [[nodiscard]] gpg::RType* CachedSUnitOffsetInfoType();
  [[nodiscard]] gpg::RType* CachedSCoordsVec2Type();
  [[nodiscard]] gpg::RType* CachedSOffsetInfoType();
  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoType();
  [[nodiscard]] gpg::RType* CachedIFormationInstanceType();

  [[nodiscard]] gpg::RType* CachedBroadcasterEFormationdStatusType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::BroadcasterEventTag<moho::EFormationdStatus>));
    }
    return type;
  }

  /// Recovers the owning listener from its ring link node; the binary spells
  /// this as `node - 4`, which is `offsetof(Listener<EFormationdStatus>, mListenerLink)`.
  [[nodiscard]] moho::Listener<moho::EFormationdStatus>* ListenerFromEFormationdStatusLinkNode(
    moho::Broadcaster* const node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    auto* const bytePtr = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<moho::Listener<moho::EFormationdStatus>*>(
      bytePtr - offsetof(moho::Listener<moho::EFormationdStatus>, mListenerLink)
    );
  }

  /**
   * Address: 0x0056DCA0 (FUN_0056DCA0, Moho::RBroadcasterRType_EFormationdStatus::SerLoad)
   *
   * What it does:
   * Reads listener pointers until a null sentinel and relinks each
   * `Listener<EFormationdStatus>` node before the destination broadcaster
   * sentinel.
   */
  void LoadBroadcasterEFormationdStatusListeners(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (archive == nullptr || broadcaster == nullptr) {
      return;
    }

    moho::Listener<moho::EFormationdStatus>* listener = nullptr;
    archive->ReadPointer_Listener_EFormationdStatus(&listener, ownerRef);
    while (listener != nullptr) {
      listener->mListenerLink.ListUnlink();
      listener->mListenerLink.ListLinkBefore(broadcaster);
      archive->ReadPointer_Listener_EFormationdStatus(&listener, ownerRef);
    }
  }

  /**
   * Address: 0x0056DD10 (FUN_0056DD10, sub_56DD10)
   *
   * IDA signature:
   * void __cdecl sub_56DD10(BinaryWriteArchive* archive, int broadcaster);
   *
   * What it does:
   * Save mirror of `LoadBroadcasterEFormationdStatusListeners`: walks the
   * broadcaster ring writing each listener as an unowned tracked pointer,
   * then writes a null pointer as the terminator the loader reads for.
   */
  void SaveBroadcasterEFormationdStatusListeners(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (archive == nullptr || broadcaster == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RRef pointerRef{};

    for (
      moho::Broadcaster* node = static_cast<moho::Broadcaster*>(broadcaster->mNext);
      node != broadcaster;
      node = static_cast<moho::Broadcaster*>(node->mNext)
    ) {
      (void)gpg::RRef_Listener_EFormationdStatus(&pointerRef, ListenerFromEFormationdStatusLinkNode(node));
      gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

    (void)gpg::RRef_Listener_EFormationdStatus(&pointerRef, nullptr);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  /**
   * Address: 0x00570D20 (FUN_00570D20)
   *
   * What it does:
   * Registers `Broadcaster<EFormationdStatus>` as one reflected base of
   * `IFormationInstance` at offset `+0x08`.
   */
  void AddBroadcasterEFormationdStatusBaseToIFormationInstanceType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedBroadcasterEFormationdStatusType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 8;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  class SUnitOffsetInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SUnitOffsetInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::SUnitOffsetInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x005667A0 (FUN_005667A0, ctor)
   *
   * What it does:
   * Preregisters `SAssignedLocInfo` RTTI so lookup resolves to this type
   * helper. `GetName`/`Init` follow the same shape as every other scalar
   * `RType` leaf in this file (`SUnitOffsetInfoTypeInfo` above,
   * `IFormationInstanceTypeInfo` below): no dedicated `FUN_*` addresses were
   * found for them, matching the pattern where MSVC folds a trivial
   * override into the same COMDAT group as its neighbors when the bodies
   * are byte-identical apart from the constant they return.
   */
  class SAssignedLocInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SAssignedLocInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::SAssignedLocInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  class IFormationInstanceTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "IFormationInstance";
    }

    void Init() override
    {
      size_ = sizeof(moho::IFormationInstance);
      gpg::RType::Init();
      AddBroadcasterEFormationdStatusBaseToIFormationInstanceType(this);
      Finish();
    }
  };

  // The binary globals are 0x14 bytes (vtable + `moho::TDatListItem` link
  // pair + load/save callback slots, matching every other SerHelperBase-
  // derived serializer in this codebase). Each targets a different reflected
  // type, so each needs its own `Init()` override.

  /// Demangled: gpg::SerSaveLoadHelper<class Moho::SUnitOffsetInfo>
  struct SUnitOffsetInfoSerializerHelperNode : public gpg::SerHelperBase
  {
    /**
     * Address: 0x00BCAAC0 vtable slot 0 dispatch target (dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` once this helper is drained from
     * the pending list).
     *
     * What it does:
     * Binds this helper's already-cited load/save callbacks
     * (`DeserializeSUnitOffsetInfoSerializerCallback` /
     * `SerializeSUnitOffsetInfoSerializerCallback`) onto `SUnitOffsetInfo`'s
     * reflected type descriptor.
     */
    void Init() override
    {
      gpg::RType* const type = CachedSUnitOffsetInfoType();
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
    offsetof(SUnitOffsetInfoSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SUnitOffsetInfoSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SUnitOffsetInfoSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SUnitOffsetInfoSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SUnitOffsetInfoSerializerHelperNode) == 0x14, "SUnitOffsetInfoSerializerHelperNode size must be 0x14"
  );

  /// Demangled: gpg::SerSaveLoadHelper<class Moho::SOffsetInfo>
  struct SOffsetInfoSerializerHelperNode : public gpg::SerHelperBase
  {
    /**
     * Address: 0x00BCAB20 vtable slot 0 dispatch target.
     *
     * What it does:
     * Binds this helper's already-cited load/save callbacks (bound directly
     * from `moho::SOffsetInfoSerializer::Deserialize`/`::Serialize`) onto
     * `SOffsetInfo`'s reflected type descriptor.
     */
    void Init() override
    {
      gpg::RType* const type = CachedSOffsetInfoType();
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
    offsetof(SOffsetInfoSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SOffsetInfoSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SOffsetInfoSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SOffsetInfoSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SOffsetInfoSerializerHelperNode) == 0x14, "SOffsetInfoSerializerHelperNode size must be 0x14"
  );

  /// Demangled: gpg::SerSaveLoadHelper<class Moho::IFormationInstance>
  struct IFormationInstanceSerializerHelperNode : public gpg::SerHelperBase
  {
    /**
     * Address: 0x00BCAB80 vtable slot 0 dispatch target.
     *
     * What it does:
     * Binds this helper's already-cited load/save callbacks
     * (`DeserializeIFormationInstanceSerializerCallback` /
     * `SerializeIFormationInstanceSerializerCallback`) onto
     * `IFormationInstance`'s reflected type descriptor.
     */
    void Init() override
    {
      gpg::RType* const type = CachedIFormationInstanceType();
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
    offsetof(IFormationInstanceSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "IFormationInstanceSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(IFormationInstanceSerializerHelperNode, mSerSaveFunc) == 0x10,
    "IFormationInstanceSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(IFormationInstanceSerializerHelperNode) == 0x14,
    "IFormationInstanceSerializerHelperNode size must be 0x14"
  );

  /// Demangled: gpg::SerSaveLoadHelper<class Moho::SAssignedLocInfo>
  struct SAssignedLocInfoSerializerHelperNode : public gpg::SerHelperBase
  {
    /**
     * Address: 0x00BCABE0 vtable slot 0 dispatch target.
     *
     * What it does:
     * Binds this helper's already-cited load/save callbacks
     * (`DeserializeSAssignedLocInfoSerializerCallback` /
     * `SerializeSAssignedLocInfoSerializerCallback`) onto
     * `SAssignedLocInfo`'s reflected type descriptor.
     */
    void Init() override
    {
      gpg::RType* const type = CachedSAssignedLocInfoType();
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
    offsetof(SAssignedLocInfoSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SAssignedLocInfoSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SAssignedLocInfoSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SAssignedLocInfoSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SAssignedLocInfoSerializerHelperNode) == 0x14,
    "SAssignedLocInfoSerializerHelperNode size must be 0x14"
  );

  SUnitOffsetInfoSerializerHelperNode gSUnitOffsetInfoSerializer{};
  SOffsetInfoSerializerHelperNode gSOffsetInfoSerializer{};
  IFormationInstanceSerializerHelperNode gIFormationInstanceSerializer{};
  SAssignedLocInfoSerializerHelperNode gSAssignedLocInfoSerializer{};

  /**
   * Address: 0x00566360 (FUN_00566360, SerSaveLoadHelper<SUnitOffsetInfo>::unlink)
   *
   * What it does:
   * Unlinks the `SUnitOffsetInfo` serializer helper node and restores its
   * self-links for intrusive-list sentinel state.
   */
  void UnlinkSUnitOffsetInfoSerializer() noexcept
  {
    gSUnitOffsetInfoSerializer.ResetLinks();
  }

  /**
   * Address: 0x00566550 (FUN_00566550, SerSaveLoadHelper<SOffsetInfo>::unlink)
   *
   * What it does:
   * Unlinks the `SOffsetInfo` serializer helper node and restores its
   * self-links for intrusive-list sentinel state.
   */
  void UnlinkSOffsetInfoSerializer() noexcept
  {
    gSOffsetInfoSerializer.ResetLinks();
  }

  /**
   * Address: 0x00566740 (FUN_00566740, SerSaveLoadHelper<IFormationInstance>::unlink)
   *
   * The duplicate emissions of this file's serializer glue -- second entry
   * points for the same work, each a single call and referenced by nothing.
   * A thunk has no source line behind it; the source called the target.
   *
   * Address: 0x00566770  duplicate of this unlink
   * Address: 0x00566970  duplicate of the SAssignedLocInfo unlink
   * Address: 0x00566580  duplicate of the SOffsetInfo unlink
   * Address: 0x00566390  duplicate of the SUnitOffsetInfo unlink
   * Address: 0x0059DB60 / 0x0059E000  bridges into
   *   CAiFormationInstance::MemberDeserialize
   * Address: 0x0059DB70 / 0x0059E010  bridges into
   *   CAiFormationInstance::MemberSerialize
   *
   * What it does:
   * Unlinks the `IFormationInstance` serializer helper node and restores
   * its self-links for intrusive-list sentinel state.
   */
  void UnlinkIFormationInstanceSerializer() noexcept
  {
    gIFormationInstanceSerializer.ResetLinks();
  }

  /**
   * Address: 0x00566940 (FUN_00566940, SerSaveLoadHelper<SAssignedLocInfo>::unlink)
   *
   * What it does:
   * Unlinks the `SAssignedLocInfo` serializer helper node and restores its
   * self-links for intrusive-list sentinel state.
   */
  void UnlinkSAssignedLocInfoSerializer() noexcept
  {
    gSAssignedLocInfoSerializer.ResetLinks();
  }

  /**
   * Address: 0x00566300 (FUN_00566300, Moho::SUnitOffsetInfoSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for SUnitOffsetInfo. Forwards the
   * reflected object pointer to SUnitOffsetInfo::MemberDeserialize
   * (FUN_005707B0 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void DeserializeSUnitOffsetInfoSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::SUnitOffsetInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00566310 (FUN_00566310, Moho::SUnitOffsetInfoSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for SUnitOffsetInfo. Forwards the
   * reflected object pointer to SUnitOffsetInfo::MemberSerialize
   * (FUN_005708A0 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void SerializeSUnitOffsetInfoSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::SUnitOffsetInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF5860 (FUN_00BF5860, Moho::SUnitOffsetInfoSerializer::~SUnitOffsetInfoSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the SUnitOffsetInfoSerializer helper
   * node, matching the sibling unlinks used across other serializer
   * registrars.
   */
  void cleanup_SUnitOffsetInfoSerializer_atexit()
  {
    UnlinkSUnitOffsetInfoSerializer();
  }

  /**
   * Address: 0x00BCAAC0 (FUN_00BCAAC0, register_SUnitOffsetInfoSerializer)
   *
   * What it does:
   * Binds the global SUnitOffsetInfo serializer helper load/save callbacks
   * and installs process-exit cleanup via atexit. The helper node
   * self-links and splices into `gpg::SerHelperBase::sNewHelpers`
   * automatically as part of its own construction, which runs before this
   * function does, so this no longer needs to unlink/self-link the node
   * itself first.
   */
  void register_SUnitOffsetInfoSerializer()
  {
    gSUnitOffsetInfoSerializer.mSerLoadFunc = &DeserializeSUnitOffsetInfoSerializerCallback;
    gSUnitOffsetInfoSerializer.mSerSaveFunc = &SerializeSUnitOffsetInfoSerializerCallback;
    (void)std::atexit(&cleanup_SUnitOffsetInfoSerializer_atexit);
  }

  /**
   * Address: 0x00BF58F0 (FUN_00BF58F0, Moho::SOffsetInfoSerializer::~SOffsetInfoSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the SOffsetInfoSerializer helper node,
   * matching the sibling unlinks used across other serializer registrars.
   */
  void cleanup_SOffsetInfoSerializer_atexit()
  {
    UnlinkSOffsetInfoSerializer();
  }

  /**
   * Address: 0x00BCAB20 (FUN_00BCAB20, register_SOffsetInfoSerializer)
   *
   * What it does:
   * Binds the global SOffsetInfo serializer helper load/save callbacks and
   * installs process-exit cleanup via atexit. The helper node self-links and
   * splices into `gpg::SerHelperBase::sNewHelpers` automatically as part of
   * its own construction, which runs before this function does, so this no
   * longer needs to unlink/self-link the node itself first.
   */
  void register_SOffsetInfoSerializer()
  {
    gSOffsetInfoSerializer.mSerLoadFunc = &moho::SOffsetInfoSerializer::Deserialize;
    gSOffsetInfoSerializer.mSerSaveFunc = &moho::SOffsetInfoSerializer::Serialize;
    (void)std::atexit(&cleanup_SOffsetInfoSerializer_atexit);
  }

  /**
   * Address: 0x005666F0 (FUN_005666F0, Moho::IFormationInstanceSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for IFormationInstance. Forwards the
   * reflected object pointer to IFormationInstance::MemberDeserialize
   * (FUN_00570D80 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void DeserializeIFormationInstanceSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const instance = reinterpret_cast<moho::IFormationInstance*>(objectPtr);
    if (instance == nullptr) {
      return;
    }
    moho::IFormationInstance::MemberDeserialize(instance, archive);
  }

  /**
   * Address: 0x00566700 (FUN_00566700, Moho::IFormationInstanceSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for IFormationInstance. Forwards the
   * reflected object pointer to IFormationInstance::MemberSerialize
   * (FUN_00570DD0 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void SerializeIFormationInstanceSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const instance = reinterpret_cast<moho::IFormationInstance*>(objectPtr);
    if (instance == nullptr) {
      return;
    }
    moho::IFormationInstance::MemberSerialize(instance, archive);
  }

  /**
   * Address: 0x00BF5980 (FUN_00BF5980, Moho::IFormationInstanceSerializer::~IFormationInstanceSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the IFormationInstanceSerializer
   * helper node, matching the sibling unlinks used across other
   * serializer registrars.
   */
  void cleanup_IFormationInstanceSerializer_atexit()
  {
    UnlinkIFormationInstanceSerializer();
  }

  /**
   * Address: 0x00BCAB80 (FUN_00BCAB80, register_IFormationInstanceSerializer)
   *
   * What it does:
   * Binds the global IFormationInstance serializer helper load/save
   * callbacks and installs process-exit cleanup via atexit. The helper node
   * self-links and splices into `gpg::SerHelperBase::sNewHelpers`
   * automatically as part of its own construction, which runs before this
   * function does, so this no longer needs to unlink/self-link the node
   * itself first.
   */
  void register_IFormationInstanceSerializer()
  {
    gIFormationInstanceSerializer.mSerLoadFunc = &DeserializeIFormationInstanceSerializerCallback;
    gIFormationInstanceSerializer.mSerSaveFunc = &SerializeIFormationInstanceSerializerCallback;
    (void)std::atexit(&cleanup_IFormationInstanceSerializer_atexit);
  }

  /**
   * Address: 0x005668E0 (FUN_005668E0, Moho::SAssignedLocInfoSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for SAssignedLocInfo. Forwards the
   * reflected object pointer to SAssignedLocInfo::MemberDeserialize
   * (FUN_00570E20 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void DeserializeSAssignedLocInfoSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const slot = reinterpret_cast<moho::SAssignedLocInfo*>(objectPtr);
    if (slot == nullptr) {
      return;
    }
    moho::SAssignedLocInfo::MemberDeserialize(slot, archive);
  }

  /**
   * Address: 0x005668F0 (FUN_005668F0, Moho::SAssignedLocInfoSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for SAssignedLocInfo. Forwards the
   * reflected object pointer to SAssignedLocInfo::MemberSerialize
   * (FUN_00570E80 body); version and the owner-ref are unused by the
   * member (mirrors the binary tail call).
   */
  void SerializeSAssignedLocInfoSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const slot = reinterpret_cast<const moho::SAssignedLocInfo*>(objectPtr);
    if (slot == nullptr) {
      return;
    }
    moho::SAssignedLocInfo::MemberSerialize(slot, archive);
  }

  /**
   * Address: 0x00BF5A10 (FUN_00BF5A10, Moho::SAssignedLocInfoSerializer::~SAssignedLocInfoSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the SAssignedLocInfoSerializer helper
   * node, matching the sibling unlinks used across other serializer
   * registrars.
   */
  void cleanup_SAssignedLocInfoSerializer_atexit()
  {
    UnlinkSAssignedLocInfoSerializer();
  }

  /**
   * Address: 0x00BCABE0 (FUN_00BCABE0, register_SAssignedLocInfoSerializer)
   *
   * What it does:
   * Binds the global SAssignedLocInfo serializer helper load/save callbacks
   * and installs process-exit cleanup via atexit. The helper node self-links
   * and splices into `gpg::SerHelperBase::sNewHelpers` automatically as part
   * of its own construction, which runs before this function does, so this
   * no longer needs to unlink/self-link the node itself first.
   */
  void register_SAssignedLocInfoSerializer()
  {
    gSAssignedLocInfoSerializer.mSerLoadFunc = &DeserializeSAssignedLocInfoSerializerCallback;
    gSAssignedLocInfoSerializer.mSerSaveFunc = &SerializeSAssignedLocInfoSerializerCallback;
    (void)std::atexit(&cleanup_SAssignedLocInfoSerializer_atexit);
  }

  struct FormationSerializerStartupBootstrap
  {
    FormationSerializerStartupBootstrap()
    {
      register_SUnitOffsetInfoSerializer();
      register_SOffsetInfoSerializer();
      register_IFormationInstanceSerializer();
      register_SAssignedLocInfoSerializer();
    }
  };

  [[maybe_unused]] FormationSerializerStartupBootstrap gFormationSerializerStartupBootstrap;

  msvc8::string gRMapTypeEntIdSUnitOffsetInfoName;
  bool gRMapTypeEntIdSUnitOffsetInfoNameCleanupRegistered = false;
  msvc8::string gRBroadcasterEFormationdStatusTypeName;
  bool gRBroadcasterEFormationdStatusTypeNameCleanupRegistered = false;
  msvc8::string gRListenerEFormationdStatusTypeName;
  bool gRListenerEFormationdStatusTypeNameCleanupRegistered = false;
  msvc8::string gRMapTypeEntIdSCoordsVec2TypeName;
  bool gRMapTypeEntIdSCoordsVec2TypeNameCleanupRegistered = false;

  void cleanup_RMapTypeEntIdSUnitOffsetInfoName()
  {
    gRMapTypeEntIdSUnitOffsetInfoName = msvc8::string{};
    gRMapTypeEntIdSUnitOffsetInfoNameCleanupRegistered = false;
  }

  void cleanup_RBroadcasterEFormationdStatusTypeName()
  {
    gRBroadcasterEFormationdStatusTypeName = msvc8::string{};
    gRBroadcasterEFormationdStatusTypeNameCleanupRegistered = false;
  }

  void cleanup_RListenerEFormationdStatusTypeName()
  {
    gRListenerEFormationdStatusTypeName = msvc8::string{};
    gRListenerEFormationdStatusTypeNameCleanupRegistered = false;
  }

  void cleanup_RMapTypeEntIdSCoordsVec2TypeName()
  {
    gRMapTypeEntIdSCoordsVec2TypeName = msvc8::string{};
    gRMapTypeEntIdSCoordsVec2TypeNameCleanupRegistered = false;
  }

  [[nodiscard]] gpg::RType* CachedEFormationdStatusType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::EFormationdStatus));
    }
    return sType;
  }

  class RMapType_EntId_SUnitOffsetInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00571F60 (FUN_00571F60, gpg::RMapType_EntId_SUnitOffsetInfo::dtr)
     */
    ~RMapType_EntId_SUnitOffsetInfo() override = default;

    /**
     * Address: 0x0056B930 (FUN_0056B930, gpg::RMapType_EntId_SUnitOffsetInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0056BA10 (FUN_0056BA10, gpg::RMapType_EntId_SUnitOffsetInfo::GetLexical)
     *
     * IDA signature:
     * std::string *__thiscall gpg::RMapType_EntId_SUnitOffsetInfo::GetLexical(
     *     gpg::RType *this, std::string *dest, _DWORD *a3);
     *
     * What it does:
     * Appends `", size=<n>"` to the base `RType::GetLexical` text, taking the
     * element count straight off the reflected map's node-count word.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0056DC00 (FUN_0056DC00, gpg::RMapType_EntId_SUnitOffsetInfo::SerSave)
     *
     * What it does:
     * Serializes one `std::map<EntId,SUnitOffsetInfo>` by writing the
     * element count, then every key/value pair through the reflected
     * `EntId` and `SUnitOffsetInfo` descriptors in tree order.
     * `objectPtr` is `&SOffsetInfo::mUnitOffsets` (`SOffsetInfo::
     * MemberSerialize` hands this type its first member). `Init` below sets
     * `size_ = 0x0C`, the `{proxy, head, size}` map footprint.
     */
    static void SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      const auto* const mapObject = reinterpret_cast<const UnitOffsetMap*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive || !mapObject) {
        return;
      }

      archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));

      gpg::RType* const keyType = CachedEntIdType();
      gpg::RType* const valueType = CachedSUnitOffsetInfoType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (const auto& [key, value] : *mapObject) {
        archive->Write(keyType, &key, owner);
        archive->Write(valueType, &value, owner);
      }
    }

    /**
     * Address: 0x0056D9D0 (FUN_0056D9D0, gpg::RMapType_EntId_SUnitOffsetInfo::SerLoad)
     *
     * IDA signature:
     * gpg::RType *__cdecl sub_56D9D0(gpg::ReadArchive *archive, int objectPtr, int version, gpg::RRef *ownerRef);
     *
     * What it does:
     * Read mirror of `SerSave`: empties the map (the inlined `_Tree::clear`
     * at 0x0056D9F4-0x0056DA34), reads the element count and, for each
     * element, reads one `EntId` key and one reflected `SUnitOffsetInfo`
     * value into a scratch pair (0x0056DA97 / 0x0056DAC0), then inserts the
     * pair (`_Tree::insert`, 0x0056EA80). The scratch value's `mUnit` weak
     * link, which the reflected read spliced into the unit's chain, is
     * unlinked again by the scratch destructor at loop end -- the map node's
     * own copy owns the membership from then on.
     */
    static void SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const mapObject = reinterpret_cast<UnitOffsetMap*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive) {
        return;
      }

      unsigned int count = 0u;
      archive->ReadUInt(&count);

      if (mapObject) {
        mapObject->clear();
      }
      if (!mapObject || count == 0u) {
        return;
      }

      gpg::RType* const keyType = CachedEntIdType();
      gpg::RType* const valueType = CachedSUnitOffsetInfoType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        moho::EntId key{};
        archive->Read(keyType, &key, owner);

        moho::SUnitOffsetInfo value{};
        archive->Read(valueType, &value, owner);

        (void)mapObject->insert(UnitOffsetMap::value_type(key, value));
      }
    }

    void Init() override
    {
      size_ = sizeof(UnitOffsetMap);
      version_ = 1;
      serSaveFunc_ = &RMapType_EntId_SUnitOffsetInfo::SerSave;
      serLoadFunc_ = &RMapType_EntId_SUnitOffsetInfo::SerLoad;
      gpg::RType::Init();
      Finish();
    }
  };

  class RBroadcasterRType_EFormationdStatus final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0056BB40 (FUN_0056BB40, Moho::RBroadcasterRType_EFormationdStatus::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(moho::BroadcasterEventTag<moho::EFormationdStatus>);
      version_ = 1;
      serLoadFunc_ = &LoadBroadcasterEFormationdStatusListeners;
      serSaveFunc_ = &SaveBroadcasterEFormationdStatusListeners;
      gpg::RType::Init();
      Finish();
    }
  };

  class RListenerRType_EFormationdStatus final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0056BC00 (FUN_0056BC00, Moho::RListenerRType_EFormationdStatus::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(moho::Listener<moho::EFormationdStatus>);
      gpg::RType::Init();
      Finish();
    }
  };

  class RMapType_EntId_SCoordsVec2 final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005721A0 (FUN_005721A0, gpg::RMapType_EntId_SCoordsVec2::dtr)
     */
    ~RMapType_EntId_SCoordsVec2() override = default;

    /**
     * Address: 0x0056C430 (FUN_0056C430, gpg::RMapType_EntId_SCoordsVec2::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0056C510 (FUN_0056C510, gpg::RMapType_EntId_SCoordsVec2::GetLexical)
     *
     * IDA signature:
     * std::string *__thiscall gpg::RMapType_EntId_SCoordsVec2::GetLexical(
     *     gpg::RType *this, std::string *dest, _DWORD *a3);
     *
     * What it does:
     * Appends `", size=<n>"` to the base `RType::GetLexical` text, taking the
     * element count straight off the reflected map's node-count word.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0056E220 (FUN_0056E220, gpg::RMapType_EntId_SCoordsVec2::SerSave)
     *
     * What it does:
     * Serializes one `std::map<EntId,SCoordsVec2>` payload by writing key/value
     * pairs with the reflected EntId and SCoordsVec2 descriptors.
     */
    static void SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      const auto* const mapObject = reinterpret_cast<const CoordMap*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive || !mapObject) {
        return;
      }

      archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));

      gpg::RType* const keyType = CachedEntIdType();
      gpg::RType* const valueType = CachedSCoordsVec2Type();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (const auto& [key, value] : *mapObject) {
        archive->Write(keyType, &key, owner);
        archive->Write(valueType, &value, owner);
      }
    }

    /**
     * Address: 0x0056E110 (FUN_0056E110, gpg::RMapType_EntId_SCoordsVec2::SerLoad)
     *
     * What it does:
     * Deserializes one `std::map<EntId,SCoordsVec2>` payload: clears the
     * destination map, reads an element count, then reads that many
     * reflected EntId/SCoordsVec2 pairs, inserting each by key.
     */
    static void SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const mapObject = reinterpret_cast<CoordMap*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive) {
        return;
      }

      unsigned int count = 0u;
      archive->ReadUInt(&count);

      if (mapObject) {
        mapObject->clear();
      }
      if (!mapObject || count == 0u) {
        return;
      }

      gpg::RType* const keyType = CachedEntIdType();
      gpg::RType* const valueType = CachedSCoordsVec2Type();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        moho::EntId key{};
        archive->Read(keyType, &key, owner);

        moho::SCoordsVec2 value{};
        archive->Read(valueType, &value, owner);

        (*mapObject)[key] = value;
      }
    }

    void Init() override
    {
      size_ = sizeof(CoordMap);
      version_ = 1;
      serSaveFunc_ = &RMapType_EntId_SCoordsVec2::SerSave;
      serLoadFunc_ = &RMapType_EntId_SCoordsVec2::SerLoad;
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x0056B930 (FUN_0056B930, gpg::RMapType_EntId_SUnitOffsetInfo::GetName)
   *
   * What it does:
   * Lazily builds one reflected map type label from cached `EntId` and
   * `SUnitOffsetInfo` RTTI names and returns stable string storage.
   */
  const char* RMapType_EntId_SUnitOffsetInfo::GetName() const
  {
    if (gRMapTypeEntIdSUnitOffsetInfoName.empty()) {
      gpg::RType* const valueType = CachedSUnitOffsetInfoType();
      gpg::RType* const keyType = CachedEntIdType();
      const char* const keyName = keyType ? keyType->GetName() : "EntId";
      const char* const valueName = valueType ? valueType->GetName() : "SUnitOffsetInfo";
      gRMapTypeEntIdSUnitOffsetInfoName = gpg::STR_Printf(
        "map<%s,%s>",
        keyName ? keyName : "EntId",
        valueName ? valueName : "SUnitOffsetInfo"
      );
      if (!gRMapTypeEntIdSUnitOffsetInfoNameCleanupRegistered) {
        gRMapTypeEntIdSUnitOffsetInfoNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RMapTypeEntIdSUnitOffsetInfoName);
      }
    }
    return gRMapTypeEntIdSUnitOffsetInfoName.c_str();
  }

  /**
   * Address: 0x0056BA10 (FUN_0056BA10, gpg::RMapType_EntId_SUnitOffsetInfo::GetLexical)
   *
   * What it does:
   * Renders the reflected map as `"<base RType lexical>, size=<count>"`. The
   * binary reads the count straight out of the map object's node-count word
   * rather than dispatching a virtual, because this descriptor has no
   * `RIndexed` sub-object; the typed `size()` accessor is that same word.
   */
  msvc8::string RMapType_EntId_SUnitOffsetInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    const auto* const mapObject = static_cast<const UnitOffsetMap*>(ref.mObj);
    const int count = mapObject ? static_cast<int>(mapObject->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), count);
  }

  /**
   * Address: 0x0056BB40 (FUN_0056BB40, Moho::RBroadcasterRType_EFormationdStatus::GetName)
   *
   * What it does:
   * Lazily builds one reflected `Broadcaster<...>` type name from cached
   * `EFormationdStatus` RTTI and returns stable string storage.
   */
  const char* RBroadcasterRType_EFormationdStatus::GetName() const
  {
    if (gRBroadcasterEFormationdStatusTypeName.empty()) {
      gpg::RType* const statusType = CachedEFormationdStatusType();
      const char* const statusName = statusType ? statusType->GetName() : "EFormationdStatus";
      gRBroadcasterEFormationdStatusTypeName = gpg::STR_Printf(
        "Broadcaster<%s>",
        statusName ? statusName : "EFormationdStatus"
      );
      if (!gRBroadcasterEFormationdStatusTypeNameCleanupRegistered) {
        gRBroadcasterEFormationdStatusTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RBroadcasterEFormationdStatusTypeName);
      }
    }
    return gRBroadcasterEFormationdStatusTypeName.c_str();
  }

  /**
   * Address: 0x0056BC00 (FUN_0056BC00, Moho::RListenerRType_EFormationdStatus::GetName)
   *
   * What it does:
   * Lazily builds one reflected `Listener<...>` type name from cached
   * `EFormationdStatus` RTTI and returns stable string storage.
   */
  const char* RListenerRType_EFormationdStatus::GetName() const
  {
    if (gRListenerEFormationdStatusTypeName.empty()) {
      gpg::RType* const statusType = CachedEFormationdStatusType();
      const char* const statusName = statusType ? statusType->GetName() : "EFormationdStatus";
      gRListenerEFormationdStatusTypeName = gpg::STR_Printf(
        "Listener<%s>",
        statusName ? statusName : "EFormationdStatus"
      );
      if (!gRListenerEFormationdStatusTypeNameCleanupRegistered) {
        gRListenerEFormationdStatusTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RListenerEFormationdStatusTypeName);
      }
    }
    return gRListenerEFormationdStatusTypeName.c_str();
  }

  /**
   * Address: 0x0056C430 (FUN_0056C430, gpg::RMapType_EntId_SCoordsVec2::GetName)
   *
   * What it does:
   * Lazily builds one reflected map type label from cached `EntId` and
   * `SCoordsVec2` RTTI names and returns stable string storage.
   */
  const char* RMapType_EntId_SCoordsVec2::GetName() const
  {
    if (gRMapTypeEntIdSCoordsVec2TypeName.empty()) {
      gpg::RType* const valueType = CachedSCoordsVec2Type();
      gpg::RType* const keyType = CachedEntIdType();
      const char* const keyName = keyType ? keyType->GetName() : "EntId";
      const char* const valueName = valueType ? valueType->GetName() : "SCoordsVec2";
      gRMapTypeEntIdSCoordsVec2TypeName = gpg::STR_Printf(
        "map<%s,%s>",
        keyName ? keyName : "EntId",
        valueName ? valueName : "SCoordsVec2"
      );
      if (!gRMapTypeEntIdSCoordsVec2TypeNameCleanupRegistered) {
        gRMapTypeEntIdSCoordsVec2TypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RMapTypeEntIdSCoordsVec2TypeName);
      }
    }
    return gRMapTypeEntIdSCoordsVec2TypeName.c_str();
  }

  /**
   * Address: 0x0056C510 (FUN_0056C510, gpg::RMapType_EntId_SCoordsVec2::GetLexical)
   *
   * What it does:
   * Renders the reflected map as `"<base RType lexical>, size=<count>"`. The
   * binary reads the count straight out of the map object's node-count word
   * rather than dispatching a virtual, because this descriptor has no
   * `RIndexed` sub-object; the typed `size()` accessor is that same word.
   */
  msvc8::string RMapType_EntId_SCoordsVec2::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    const auto* const mapObject = static_cast<const CoordMap*>(ref.mObj);
    const int count = mapObject ? static_cast<int>(mapObject->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), count);
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

  /// Caches into `CFormationInstance::sType`, which is where the binary keeps
  /// it - a function-local cache leaves the class static null for every other
  /// reader.
  [[nodiscard]] gpg::RType* CachedCFormationInstanceType()
  {
    if (!moho::CFormationInstance::sType) {
      moho::CFormationInstance::sType =
        ResolveTypeByAnyName({"CFormationInstance", "Moho::CFormationInstance"});
    }
    return moho::CFormationInstance::sType;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!moho::Sim::sType) {
      moho::Sim::sType = gpg::LookupRType(typeid(moho::Sim));
    }
    return moho::Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrIUnitType()
  {
    if (!moho::WeakPtr<moho::IUnit>::sType) {
      moho::WeakPtr<moho::IUnit>::sType = gpg::LookupRType(typeid(moho::WeakPtr<moho::IUnit>));
    }
    return moho::WeakPtr<moho::IUnit>::sType;
  }

  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntId));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSUnitOffsetInfoType()
  {
    gpg::RType* type = moho::SUnitOffsetInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SUnitOffsetInfo));
      if (!type) {
        type = moho::preregister_SUnitOffsetInfoTypeInfo();
      }
      moho::SUnitOffsetInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSCoordsVec2Type()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SCoordsVec2));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return type;
  }

  // Reflected-type caches for the fields CFormationInstance serializes. The
  // binary keeps one global per type in a single .data cluster; these mirror
  // them, following the gXxxType convention in Reflection.cpp. They are not
  // function-local statics on purpose - see the descriptor-cache defects fixed
  // in 39bd696 / 322b105 / b20cc03.
  gpg::RType* gEUnitCommandTypeType = nullptr;          // binary 0x010C6EDC
  gpg::RType* gMapEntIdSCoordsVec2Type = nullptr;       // binary 0x010C6F90
  gpg::RType* gFastVectorWeakPtrIUnitType = nullptr;    // binary 0x010C6F94
  gpg::RType* gFastVectorSOffsetInfoType = nullptr;     // binary 0x010C6F98
  gpg::RType* gFastVectorSAssignedLocInfoType = nullptr;
  gpg::RType* gQuaternionfType = nullptr;

  /// One reflected field, skipped when its descriptor has not resolved. The
  /// binary emits the same null-guarded Write/Read at every field; lifting it
  /// keeps the eighteen call sites readable.
  void WriteFormationField(
    gpg::WriteArchive* const archive, gpg::RType* const type, const void* const field, const gpg::RRef& ownerRef
  )
  {
    GPG_ASSERT(type != nullptr);
    if (type != nullptr) {
      archive->Write(type, field, ownerRef);
    }
  }

  void ReadFormationField(
    gpg::ReadArchive* const archive, gpg::RType* const type, void* const field, const gpg::RRef& ownerRef
  )
  {
    GPG_ASSERT(type != nullptr);
    if (type != nullptr) {
      archive->Read(type, field, ownerRef);
    }
  }

  [[nodiscard]] gpg::RType* CachedEUnitCommandTypeType()
  {
    if (!gEUnitCommandTypeType) {
      gEUnitCommandTypeType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return gEUnitCommandTypeType;
  }

  [[nodiscard]] gpg::RType* CachedMapEntIdSCoordsVec2Type()
  {
    if (!gMapEntIdSCoordsVec2Type) {
      gMapEntIdSCoordsVec2Type = gpg::LookupRType(typeid(CoordMap));
    }
    return gMapEntIdSCoordsVec2Type;
  }

  // The three fastvector descriptors are registered under the base
  // `gpg::fastvector<T>` type ids (IUnitWeakPtrReflection.cpp:599,
  // FastVectorUIntReflection.cpp:2081/2212), which is what the binary's own
  // `LookupRType` calls at 0x00574518/0x0057453F/0x00574588 key on -- the
  // inline capacity is not part of the reflected type.

  [[nodiscard]] gpg::RType* CachedFastVectorWeakPtrIUnitType()
  {
    if (!gFastVectorWeakPtrIUnitType) {
      gFastVectorWeakPtrIUnitType = gpg::LookupRType(typeid(gpg::fastvector<moho::WeakPtr<moho::IUnit>>));
    }
    return gFastVectorWeakPtrIUnitType;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorSOffsetInfoType()
  {
    if (!gFastVectorSOffsetInfoType) {
      gFastVectorSOffsetInfoType = gpg::LookupRType(typeid(gpg::fastvector<moho::SOffsetInfo>));
    }
    return gFastVectorSOffsetInfoType;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorSAssignedLocInfoType()
  {
    if (!gFastVectorSAssignedLocInfoType) {
      gFastVectorSAssignedLocInfoType = gpg::LookupRType(typeid(gpg::fastvector<moho::SAssignedLocInfo>));
    }
    return gFastVectorSAssignedLocInfoType;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    if (!gQuaternionfType) {
      gQuaternionfType = gpg::LookupRType(typeid(Wm3::Quatf));
    }
    return gQuaternionfType;
  }

  /**
   * Reflection cache for `map<EntId,SUnitOffsetInfo>`.
   *
   * The binary keeps this in its own global (`std::map<EntId,SUnitOffsetInfo>::sType`
   * at 0x010C6F8C, filled at 0x00570B8D by `SOffsetInfo::MemberSerialize`),
   * separate from the element-type cache `Moho::SOffsetInfo::sType` at
   * 0x010C6F6C that `RFastVectorType<SOffsetInfo>::SerLoad` fills at
   * 0x0056DF43.
   */
  gpg::RType* gMapEntIdSUnitOffsetInfoType = nullptr;

  [[nodiscard]] gpg::RType* CachedMapEntIdSUnitOffsetInfoType()
  {
    if (!gMapEntIdSUnitOffsetInfoType) {
      gMapEntIdSUnitOffsetInfoType = gpg::LookupRType(typeid(UnitOffsetMap));
    }
    return gMapEntIdSUnitOffsetInfoType;
  }

  /**
   * Element-type cache for `SOffsetInfo`, mirroring the binary's
   * `Moho::SOffsetInfo::sType` global (0x010C6F6C).
   */
  [[nodiscard]] gpg::RType* CachedSOffsetInfoType()
  {
    gpg::RType* type = moho::SOffsetInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SOffsetInfo));
      moho::SOffsetInfo::sType = type;
    }
    return type;
  }

  /**
   * Element-type cache for `SAssignedLocInfo`, mirroring the binary's
   * `Moho::SAssignedLocInfo::sType` global.
   */
  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoType()
  {
    gpg::RType* type = moho::SAssignedLocInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SAssignedLocInfo));
      moho::SAssignedLocInfo::sType = type;
    }
    return type;
  }

  /**
   * Element-type cache for `IFormationInstance`, mirroring the binary's
   * `Moho::IFormationInstance::sType` global.
   */
  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    gpg::RType* type = moho::IFormationInstance::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IFormationInstance));
      moho::IFormationInstance::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeSimRef(moho::Sim* sim)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedSimType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!sim || !staticType) {
      out.mObj = sim;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*sim));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = sim;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(sim) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] moho::Sim* ReadPointerSim(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedSimType();
    if (!expectedType || !tracked.type) {
      return static_cast<moho::Sim*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<moho::Sim*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "Sim",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  void WritePointerSim(gpg::WriteArchive* const archive, moho::Sim* const sim, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef objectRef = MakeSimRef(sim);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  /// The binary's `quat0`: a function-local `static const Quaternionf(0,0,0,0)`
  /// (guarded init at every reader) that the orientation compares test against.
  constexpr Wm3::Quatf kZeroQuaternion{0.0f, 0.0f, 0.0f, 0.0f};

  /// Formation layer indices into `CFormationInstance::mOffsetInfo`. `GetLayer`
  /// (0x00569BD0) returns exactly one of these, and `UpdateFormation`
  /// (0x00568CA0) drives its rebuild loop over `[0, kFormationLayerCount)`.
  constexpr std::int32_t kGroundFormationLayer = 0;
  constexpr std::int32_t kAirFormationLayer = 1;
  constexpr std::int32_t kFormationLayerCount = 2;

  constexpr float kPi = 3.1415927f;
  constexpr float kTwoPi = 6.2831855f;

  /// Wraps a heading difference into `(-pi, pi]`, the way every orientation
  /// compare in this file does it.
  [[nodiscard]] float WrapAngle(const float angle) noexcept
  {
    if (angle > kPi) {
      return angle - kTwoPi;
    }
    if (angle < -kPi) {
      return angle + kTwoPi;
    }
    return angle;
  }

  /// Yaw of a unit's orientation quaternion, as the binary computes it from
  /// the transform: `atan2(2(xz + wy), 1 - 2(x^2 + y^2))`.
  [[nodiscard]] float HeadingOf(const Wm3::Quatf& q) noexcept
  {
    return std::atan2((q.z * q.x + q.y * q.w) * 2.0f, 1.0f - (q.y * q.y + q.x * q.x) * 2.0f);
  }

  /// The unit-forward vector (third rotation-matrix column) of `q`, the
  /// formula `SetOrientation` (0x0056A520) and the constructor share.
  [[nodiscard]] Wm3::Vec3f ForwardOf(const Wm3::Quatf& q) noexcept
  {
    return Wm3::Vec3f{
      ((q.x * q.z) + (q.w * q.y)) * 2.0f,
      ((q.y * q.z) - (q.w * q.x)) * 2.0f,
      1.0f - (((q.x * q.x) + (q.y * q.y)) * 2.0f),
    };
  }

  /// Rotation about the Y axis by `angle`, stored scalar-first: the shape
  /// `UpdateFormation` writes into `mOrientationChange` and `Update` builds
  /// for each unit's heading correction.
  [[nodiscard]] Wm3::Quatf YawQuaternion(const float angle) noexcept
  {
    const float halfAngle = angle * 0.5f;
    const float sinHalf = std::sin(halfAngle);
    return Wm3::Quatf{std::cos(halfAngle), sinHalf * 0.0f, sinHalf, sinHalf * 0.0f};
  }

  /// Flat (XZ) distance between two positions, `sqrtf(dz*dz + dx*dx)`.
  [[nodiscard]] float FlatDistance(const Wm3::Vec3f& a, const Wm3::Vec3f& b) noexcept
  {
    const float dx = a.x - b.x;
    const float dz = a.z - b.z;
    return std::sqrt(dz * dz + dx * dx);
  }

  [[nodiscard]] moho::Unit* UnitOf(const moho::WeakPtr<moho::IUnit>& link) noexcept
  {
    return static_cast<moho::Unit*>(link.GetObjectPtr());
  }

  /**
   * Address: 0x00568980 (FUN_00568980, sub_568980)
   *
   * What it does:
   * For every non-guard formation, pairs each ground group against every
   * group of both layers and, where their overlap boxes intersect, gives
   * both the ground group's centre, the larger extent (floored at 10 on
   * each axis) and the slower speed, so overlapping groups move as one.
   */
  void MergeOverlappingOffsetInfos(moho::CFormationInstance& formation)
  {
    if (formation.mCommandType == moho::EUnitCommandType::UNITCOMMAND_Guard) {
      return;
    }

    constexpr float kMinMergedExtent = 10.0f;
    for (moho::SOffsetInfo& ground : formation.mOffsetInfo[kGroundFormationLayer]) {
      for (std::int32_t layer = 0; layer < kFormationLayerCount; ++layer) {
        for (moho::SOffsetInfo& other : formation.mOffsetInfo[layer]) {
          if (!other.Overlaps(ground)) {
            continue;
          }

          float extentZ = std::max(ground.mExtent.z, other.mExtent.z);
          if (extentZ < kMinMergedExtent) {
            extentZ = kMinMergedExtent;
          }
          float extentX = std::max(ground.mExtent.x, other.mExtent.x);
          if (extentX < kMinMergedExtent) {
            extentX = kMinMergedExtent;
          }
          const float speed = std::min(ground.mSpeed, other.mSpeed);

          other.mCenter = ground.mCenter;
          other.mExtent = moho::SCoordsVec2{extentX, extentZ};
          other.mSpeed = speed;
          ground.mExtent = moho::SCoordsVec2{extentX, extentZ};
          ground.mSpeed = speed;
        }
      }
    }
  }

  /**
   * The leader lookup `CAiFormationInstance::GetLeader` (0x0059A870) and
   * `GetOffsetInfoLeader` below share: the group's own leader, except that an
   * air group (layer 1) follows the leader of the first ground group whose
   * overlap box it intersects.
   */
  [[nodiscard]] moho::Unit* ResolveGroupLeader(
    moho::CFormationInstance& formation, const std::int32_t layer, moho::SOffsetInfo& info
  )
  {
    moho::Unit* leader = info.GetLeader();
    if (layer == kAirFormationLayer) {
      for (moho::SOffsetInfo& ground : formation.mOffsetInfo[kGroundFormationLayer]) {
        if (ground.Overlaps(info)) {
          leader = ground.GetLeader();
          break;
        }
      }
    }
    return leader;
  }

  /**
   * Address: 0x0059A970 (FUN_0059A970, sub_59A970)
   *
   * What it does:
   * The leader `Update` drives one group by: `ResolveGroupLeader`, then for
   * guard formations the unit that leader is guarding instead.
   */
  [[nodiscard]] moho::Unit* GetOffsetInfoLeader(
    const std::int32_t layer, moho::CAiFormationInstance& formation, moho::SOffsetInfo& info
  )
  {
    moho::Unit* const leader = ResolveGroupLeader(formation, layer, info);
    if (formation.mCommandType != moho::EUnitCommandType::UNITCOMMAND_Guard || leader == nullptr) {
      return leader;
    }
    return leader->IsUnit()->GuardedUnitRef.ResolveObjectPtr<moho::Unit>();
  }

  /**
   * Address: 0x00569CC2 (inside FUN_00569CB0), 0x00569F82 (inside FUN_00569F70),
   *          0x0059AE90 (inside FUN_0059AE80), 0x005692A5 (inside FUN_005692A0),
   *          0x0056A6B5 (inside FUN_0056A6B0)
   *
   * What it does:
   * The lazy formation-plan rebuild the binary inlines at the head of every
   * entry point that reads plan state. When `mPlanUpdate` is set it clears
   * the flag, drops dead units, tears the current plan down and rebuilds
   * it: `RemoveDeadUnits` -> `CleanupFormation` -> `UpdateFormation`, in that
   * order (see 0x0059AEA8 / 0x0059AEAF / 0x0059AEB5).
   */
  void RefreshFormationPlanIfRequested(moho::CFormationInstance& formation)
  {
    if (formation.mPlanUpdate == 0u) {
      return;
    }

    formation.mPlanUpdate = 0u;
    (void)formation.RemoveDeadUnits(nullptr);
    formation.CleanupFormation();
    formation.UpdateFormation();
  }

  /**
   * Address: 0x007212B0 (FUN_007212B0, func_UnitCanMoveAt)
   *
   * What it does:
   * Converts one world-space slot position to footprint-anchored grid cell
   * coordinates and asks `COORDS_CanMoveAt` whether the unit can occupy it.
   */
  [[nodiscard]] bool UnitCanMoveAt(moho::Unit* const unit, const moho::SCoordsVec2& position, moho::COGrid* const grid)
  {
    const moho::SFootprint& footprint = unit->GetFootprint();
    // FUN_007212B0 converts both coordinates with bare fistp and never calls
    // __ftol, so this rounds to nearest rather than truncating.
    moho::SOCellPos cell = footprint.ToCellPos(Wm3::Vec3f{position.x, 0.0f, position.z});
    return moho::COORDS_CanMoveAt(&cell, grid, unit, false, nullptr);
  }

  /**
   * The four-way slot test `CAiFormationInstance::FindSlotFor` (0x0059AA20)
   * runs on the requested position (0x0059AB10-0x0059AB8A) and on every
   * spiral candidate (0x0059ACE1-0x0059AD66): the footprint fits the
   * occupancy grid, the unit may move there, the point lies within the
   * playable map and no already-assigned slot of the layer overlaps it.
   */
  [[nodiscard]] bool FormationSlotIsFree(
    const moho::CAiFormationInstance& formation,
    const moho::SCoordsVec2& position,
    const moho::SFootprint& footprint,
    const std::int32_t maxSize,
    const bool useWholeMap,
    const std::int32_t layer,
    moho::Unit* const unit
  )
  {
    moho::COGrid* const grid = formation.mSim->mOGrid;
    if (static_cast<std::uint8_t>(footprint.FitsAt(position, *grid)) == 0u) {
      return false;
    }
    if (!UnitCanMoveAt(unit, position, grid)) {
      return false;
    }
    if (!formation.mSim->mMapData->IsWithin(
          Wm3::Vec3f{position.x, 0.0f, position.z}, static_cast<float>(maxSize), useWholeMap
        )) {
      return false;
    }
    return formation.PosIsFree(position, maxSize, layer);
  }

  /**
   * One unit's position relative to the formation's mean, built during
   * `RunScript` phase 4. "Desc32" in the escalation notes
   * (`decomp/recovery/escalations/FUN_00567300.md`); 0x20 bytes, proven
   * from FUN_00567300.asm 0x005676A0..0x005676F3 (weak-target write at
   * +0x00, six float writes at +0x04..+0x1C) and the destroy-range funclet
   * at 0x00BADE31.
   */
  struct SFormationRunScriptUnitDesc
  {
    moho::Unit* unit;              // +0x00
    Wm3::Vec3f relative;           // +0x04
    Wm3::Vec3f relativeRotated;    // +0x10
    float weight;                  // +0x1C (constant 1.0f in the shipped binary)
  };
  static_assert(sizeof(SFormationRunScriptUnitDesc) == 0x20, "SFormationRunScriptUnitDesc size must be 0x20");

  /**
   * One formation-slot candidate scored for greedy unit assignment.
   * "Cand72" in the escalation notes; 0x48 bytes, proven from stride
   * arithmetic at 0x00567C3D/0x00568028 and the destroy-range funclet at
   * 0x00BADE52.
   */
  struct SFormationRunScriptCandidate
  {
    SFormationRunScriptCandidate() = default;

    /**
     * Address: 0x0056CB60 (FUN_0056CB60 -- the compiler-generated copy
     * constructor: six floats and the `weight`, then the
     * `EntityCategorySet` member's copy, whose own body writes the universe
     * word and the bit set but leaves the two reserved words at +0x24 and
     * +0x2C untouched. Reached from the `fastvector_n<Candidate,16>` grow
     * path (0x0056C940, FastVector.h) and from the temporaries `std::sort`'s
     * `iter_swap` (0x00575210) and `pop_heap` (0x00575490/0x00575660) make.)
     */
    SFormationRunScriptCandidate(const SFormationRunScriptCandidate&) = default;

    /**
     * Address: 0x00573340 (FUN_00573340 -- the compiler-generated copy
     * assignment, same field profile as the copy constructor above. Reached
     * from `std::sort`'s `iter_swap` (0x00575210) and `_Pop_heap` hole write
     * (0x00575950); see legacy/algorithms/Sort.h.)
     */
    SFormationRunScriptCandidate& operator=(const SFormationRunScriptCandidate&) = default;

    Wm3::Vec3f position;                  // +0x00
    Wm3::Vec3f anchorDelta;               // +0x0C
    float distanceSq;                     // +0x18 (sort key)
    float weight;                         // +0x1C
    moho::EntityCategorySet category;     // +0x20 (0x28 bytes)
  };
  static_assert(sizeof(SFormationRunScriptCandidate) == 0x48, "SFormationRunScriptCandidate size must be 0x48");

  /**
   * Comparator for the `msvc8::sort(candidates.begin(), candidates.end(), ...)`
   * call in `RunScript` phase 6 below: candidates are ordered by *decreasing*
   * squared distance, the far slots first.
   *
   * The direction is read off the instantiation's `_Insertion_sort`
   * (0x00574170): it rotates an element to the front when its `+0x18` key is
   * greater than `*first`'s and scans back while the key is greater than the
   * predecessor's, which is VC8's `pred(*next, *first)` / `pred(*next, *--first1)`
   * with `pred = greater`; `_Adjust_heap` (0x00575280) picks the child whose
   * key is greater the same way. The whole `std::sort<SFormationRunScriptCandidate*>`
   * family -- the entry (0x00572350), the introsort driver (0x005734F0),
   * `_Unguarded_partition`/`_Median`/`_Med3` (0x00574830/0x005751C0),
   * `_Insertion_sort` and its `_Rotate` (0x00574170/0x00575690), `make_heap`,
   * `sort_heap`, `_Adjust_heap`, `_Push_heap` and `_Pop_heap`
   * (0x00574A30/0x00574B40/0x00575280/0x00575500/0x00575950) and the element
   * swap (0x00575210) -- is cited on legacy/algorithms/Sort.h; this call is the
   * source line that instantiates it.
   */
  [[nodiscard]] bool CompareRunScriptCandidateByDistanceSq(
    const SFormationRunScriptCandidate& lhs,
    const SFormationRunScriptCandidate& rhs
  ) noexcept
  {
    return lhs.distanceSq > rhs.distanceSq;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0056B070 (FUN_0056B070,
   * ?BroadcastEvent@?$Broadcaster@W4EFormationdStatus@Moho@@@Moho@@IAEXW4EFormationdStatus@2@@Z)
   *
   * What it does:
   * Broadcasts one formation-status event to every linked listener while
   * preserving iteration safety if listeners relink/unlink themselves during
   * the callback: the ring is detached onto a stack node, each listener is
   * moved back before `this` and then told the event, and whatever is left
   * on the stack node is spliced back at the end.
   */
  void Broadcaster::BroadcastEvent(const EFormationdStatus event)
  {
    Broadcaster detached{};

    if (mNext == this) {
      return;
    }

    detached.mNext = mNext;
    detached.mPrev = mPrev;
    detached.mPrev->mNext = &detached;
    detached.mNext->mPrev = &detached;
    mNext = this;
    mPrev = this;

    while (detached.mNext != &detached) {
      auto* const listenerLink = static_cast<Broadcaster*>(detached.mNext);
      listenerLink->ListLinkBefore(this);

      if (Listener<EFormationdStatus>* const listener = ListenerFromEFormationdStatusLinkNode(listenerLink)) {
        listener->OnEvent(event);
      }
    }

    detached.mPrev->mNext = detached.mNext;
    detached.mNext->mPrev = detached.mPrev;
  }

  /**
   * Address: 0x00565AB0 (FUN_00565AB0, Moho::SOffsetInfo::SOffsetInfo)
   *
   * What it does:
   * Default state for a fresh group. The body re-clears the (already empty)
   * unit map and re-drops the (already null) leader -- both inlined
   * `clear()`/`Set(nullptr)` calls the binary keeps at 0x00565B2A and
   * 0x00565B8F -- around the scalar defaults.
   */
  SOffsetInfo::SOffsetInfo()
  {
    mUnitOffsets.clear();
    mPos = Wm3::Vec3f::ZERO;
    mSlotCenter = SCoordsVec2{0.0f, 0.0f};
    mCenter = SCoordsVec2{0.0f, 0.0f};
    mDynamicOffset = SCoordsVec2{0.0f, 0.0f};
    mExtent = SCoordsVec2{2.0f, 2.0f};
    mUseDynamicOffset = false;
    mInFormation = false;
    mSpeed = std::numeric_limits<float>::infinity();
    mAvgDistToTarget = 0.0f;
    mLeader.Set(nullptr);
  }

  /**
   * Address: 0x005688C0 (FUN_005688C0, sub_5688C0)
   *
   * What it does:
   * Axis-aligned overlap test of the two groups' `mCenter +/- mExtent`
   * boxes, X first, then Z.
   */
  bool SOffsetInfo::Overlaps(const SOffsetInfo& other) const noexcept
  {
    const bool overlapX = (mCenter.x - mExtent.x) <= (other.mExtent.x + other.mCenter.x)
      && (other.mCenter.x - other.mExtent.x) <= (mExtent.x + mCenter.x);
    if (!overlapX) {
      return false;
    }

    return (mCenter.z - mExtent.z) <= (other.mExtent.z + other.mCenter.z)
      && (other.mCenter.z - other.mExtent.z) <= (mExtent.z + mCenter.z);
  }

  /**
   * Address: 0x0059A300 (FUN_0059A300, sub_59A300)
   *
   * What it does:
   * Returns the cached leader. When `mLeader` is empty, walks the unit map
   * in key order for the live unit with the highest `mLeaderPriority`
   * (strictly above zero) and rebinds `mLeader` to it -- the relink is the
   * inlined `WeakPtr::operator=` at 0x0059A35F-0x0059A386.
   */
  Unit* SOffsetInfo::GetLeader()
  {
    if (!mLeader.HasValue()) {
      Unit* best = nullptr;
      std::int32_t bestPriority = 0;
      for (auto& [entityId, info] : mUnitOffsets) {
        Unit* const unit = UnitOf(info.mUnit);
        if (unit != nullptr && info.mLeaderPriority > bestPriority) {
          bestPriority = info.mLeaderPriority;
          best = unit;
        }
      }
      mLeader.Set(best);
    }

    return UnitOf(mLeader);
  }

  /**
   * Address: 0x0056C1A0 (FUN_0056C1A0, gpg::RFastVectorType_SOffsetInfo::SetCount)
   *
   * IDA signature:
   * int __stdcall gpg::RFastVectorType_SOffsetInfo::SetCount(void *obj, int count);
   *
   * What it does:
   * `RIndexed::SetCount` slot of the `fastvector<SOffsetInfo>` reflection
   * descriptor: resizes the reflected group vector, copy-constructing any
   * appended groups from one default-constructed prototype (built at
   * 0x0056C1B3, torn down at 0x0056C1D2 around the `Resize` at 0x0056C1C6).
   */
  void SetFastVectorSOffsetInfoCount(void* const vector, const int count)
  {
    auto& groups = *static_cast<gpg::fastvector_n<SOffsetInfo, 2>*>(vector);
    groups.Resize(static_cast<std::size_t>(count), SOffsetInfo());
  }

  /**
   * Address: 0x0056DEC0 (FUN_0056DEC0, gpg::RFastVectorType_SOffsetInfo::SerLoad)
   *
   * IDA signature:
   * void __cdecl sub_56DEC0(gpg::ReadArchive *a1, _DWORD *a2, int a3, gpg::RRef *a6);
   *
   * What it does:
   * Reads the serialized group count, grows the reflected
   * `fastvector<SOffsetInfo>` to that count -- copy-filling appended groups
   * from a freshly default-constructed prototype (0x0056DF00 / 0x0056DF0C /
   * 0x0056DF17) -- then deserializes each group through `ReadArchive::Read`
   * with the element descriptor cached in `SOffsetInfo::sType` (0x0056DF43).
   */
  void LoadFastVectorSOffsetInfo(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const groups = reinterpret_cast<gpg::fastvector_n<SOffsetInfo, 2>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(groups != nullptr);
    if (!archive || !groups) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);
    groups->Resize(count, SOffsetInfo());

    gpg::RType* const elementType = CachedSOffsetInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &(*groups)[i], owner);
    }
  }

  /**
   * Address: 0x0056DF80 (FUN_0056DF80, gpg::RFastVectorType_SOffsetInfo::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<SOffsetInfo>` payload as archive count
   * plus per-group reflected serialization, mirroring `LoadFastVectorSOffsetInfo`.
   */
  void SaveFastVectorSOffsetInfo(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const groups = reinterpret_cast<gpg::fastvector_n<SOffsetInfo, 2>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(groups != nullptr);
    if (!archive || !groups) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(groups->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSOffsetInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*groups)[i], owner);
    }
  }

  /**
   * Address: 0x0056C3B0 (FUN_0056C3B0, gpg::RFastVectorType_SAssignedLocInfo::SetCount)
   *
   * What it does:
   * `RIndexed::SetCount` slot of the `fastvector<SAssignedLocInfo>`
   * descriptor. Resizes the reflected slot vector, filling appended entries
   * from a zeroed prototype -- the retail body clears the 0x10 stack
   * prototype with `xorps xmm0` plus two `movss` stores and two zeroed dwords
   * (0x0056C3B3-0x0056C3D3) before calling the resize (0x0056D650, the
   * `fastvector_n<SAssignedLocInfo,16>::Resize` emission for this element).
   */
  void SetFastVectorSAssignedLocInfoCount(void* const vector, const int count)
  {
    auto& slots = *static_cast<gpg::fastvector_n<SAssignedLocInfo, 16>*>(vector);
    slots.Resize(static_cast<std::size_t>(count), SAssignedLocInfo{});
  }

  /**
   * Address: 0x0056E000 (FUN_0056E000, gpg::RFastVectorType_SAssignedLocInfo::SerLoad)
   *
   * What it does:
   * Reads the serialized slot count, resizes the reflected
   * `fastvector<SAssignedLocInfo>` filling appended entries from a zeroed
   * prototype, then deserializes each 0x10 entry through `ReadArchive::Read`.
   */
  void LoadFastVectorSAssignedLocInfo(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const slots = reinterpret_cast<gpg::fastvector_n<SAssignedLocInfo, 16>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(slots != nullptr);
    if (!archive || !slots) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);
    slots->Resize(count, SAssignedLocInfo{});

    gpg::RType* const elementType = CachedSAssignedLocInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &(*slots)[i], owner);
    }
  }

  /**
   * Address: 0x0056E0A0 (FUN_0056E0A0, gpg::RFastVectorType_SAssignedLocInfo::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<SAssignedLocInfo>` payload as archive
   * count plus per-entry reflected serialization, mirroring
   * `LoadFastVectorSAssignedLocInfo`.
   */
  void SaveFastVectorSAssignedLocInfo(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const slots = reinterpret_cast<gpg::fastvector_n<SAssignedLocInfo, 16>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(slots != nullptr);
    if (!archive || !slots) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(slots->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSAssignedLocInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*slots)[i], owner);
    }
  }

  /**
   * Address: 0x0059A3F0 (FUN_0059A3F0)
   *
   * What it does:
   * Initializes one assigned slot from `(position, size, layer)`.
   */
  SAssignedLocInfo::SAssignedLocInfo(
    const SCoordsVec2& position,
    const std::int32_t size,
    const std::int32_t layer
  ) noexcept
    : mPos(position)
    , mSize(size)
    , mLayer(layer)
  {
  }

  /**
   * Address: 0x00570E20 (FUN_00570E20, Moho::SAssignedLocInfo::MemberDeserialize)
   *
   * What it does:
   * Loads one assigned slot: position, footprint size and layer.
   */
  void SAssignedLocInfo::MemberDeserialize(SAssignedLocInfo* const slot, gpg::ReadArchive* const archive)
  {
    if (!archive || !slot) {
      return;
    }

    const gpg::RRef ownerRef{};
    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Read(coordsType, &slot->mPos, ownerRef);
    }

    archive->ReadInt(&slot->mSize);
    archive->ReadInt(&slot->mLayer);
  }

  /**
   * Address: 0x00570E80 (FUN_00570E80, Moho::SAssignedLocInfo::MemberSerialize)
   *
   * What it does:
   * Stores one assigned slot: position, footprint size and layer.
   */
  void SAssignedLocInfo::MemberSerialize(const SAssignedLocInfo* const slot, gpg::WriteArchive* const archive)
  {
    if (!archive || !slot) {
      return;
    }

    const gpg::RRef ownerRef{};
    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Write(coordsType, &slot->mPos, ownerRef);
    }

    archive->WriteInt(slot->mSize);
    archive->WriteInt(slot->mLayer);
  }

  /**
   * Address: 0x005707B0 (FUN_005707B0, Moho::SUnitOffsetInfo::MemberDeserialize)
   *
   * What it does:
   * Loads one unit slot: weak-unit link, leader priority, 2D offset, 3D
   * target position, heading angle, both distances and the weight.
   */
  void SUnitOffsetInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    GPG_ASSERT(weakPtrType != nullptr);
    if (weakPtrType) {
      archive->Read(weakPtrType, &mUnit, ownerRef);
    }

    archive->ReadInt(&mLeaderPriority);

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Read(coordsType, &mOffset, ownerRef);
    }

    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    if (vectorType) {
      archive->Read(vectorType, &mTargetPos, ownerRef);
    }

    archive->ReadFloat(&mHeadingAngle);
    archive->ReadFloat(&mDistToTarget);
    archive->ReadFloat(&mDistFromLeader);
    archive->ReadFloat(&mWeight);
  }

  /**
   * Address: 0x005708A0 (FUN_005708A0, Moho::SUnitOffsetInfo::MemberSerialize)
   *
   * What it does:
   * Stores one unit slot: weak-unit link, leader priority, 2D offset, 3D
   * target position, heading angle, both distances and the weight.
   */
  void SUnitOffsetInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    GPG_ASSERT(weakPtrType != nullptr);
    if (weakPtrType) {
      archive->Write(weakPtrType, &mUnit, ownerRef);
    }

    archive->WriteInt(mLeaderPriority);

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Write(coordsType, &mOffset, ownerRef);
    }

    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    if (vectorType) {
      archive->Write(vectorType, &mTargetPos, ownerRef);
    }

    archive->WriteFloat(mHeadingAngle);
    archive->WriteFloat(mDistToTarget);
    archive->WriteFloat(mDistFromLeader);
    archive->WriteFloat(mWeight);
  }

  /**
   * Address: 0x00570B60 (FUN_00570B60, Moho::SOffsetInfo::MemberSerialize)
   *
   * What it does:
   * Writes one group: the whole unit map, position, the four coordinate
   * pairs, both flags, both scalars and the leader weak-link, each through
   * its reflected RTTI serializer.
   */
  void SOffsetInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const mapType = CachedMapEntIdSUnitOffsetInfoType();
    GPG_ASSERT(mapType != nullptr);
    if (mapType) {
      archive->Write(mapType, &mUnitOffsets, ownerRef);
    }

    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    if (vectorType) {
      archive->Write(vectorType, &mPos, ownerRef);
    }

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Write(coordsType, &mSlotCenter, ownerRef);
      archive->Write(coordsType, &mCenter, ownerRef);
      archive->Write(coordsType, &mDynamicOffset, ownerRef);
      archive->Write(coordsType, &mExtent, ownerRef);
    }

    archive->WriteBool(mUseDynamicOffset);
    archive->WriteBool(mInFormation);
    archive->WriteFloat(mSpeed);
    archive->WriteFloat(mAvgDistToTarget);

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    GPG_ASSERT(weakPtrType != nullptr);
    if (weakPtrType) {
      archive->Write(weakPtrType, &mLeader, ownerRef);
    }
  }

  /**
   * Address: 0x00566510 (FUN_00566510, Moho::SOffsetInfoSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade: forwards one `SOffsetInfo` payload to
   * `SOffsetInfo::MemberSerialize`; `version` and the owner-ref are unused
   * by the member (mirrors the binary tail call).
   */
  void SOffsetInfoSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const offsetInfo = reinterpret_cast<SOffsetInfo*>(objectPtr);
    if (offsetInfo != nullptr) {
      offsetInfo->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x005709A0 (FUN_005709A0, Moho::SOffsetInfo::MemberDeserialize)
   *
   * What it does:
   * Read mirror of `MemberSerialize`: reads the unit map, position, four
   * coordinate pairs, two flags, two scalars and the leader weak-link, each
   * through its reflected RTTI serializer.
   */
  void SOffsetInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const mapType = CachedMapEntIdSUnitOffsetInfoType();
    GPG_ASSERT(mapType != nullptr);
    if (mapType) {
      archive->Read(mapType, &mUnitOffsets, ownerRef);
    }

    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    if (vectorType) {
      archive->Read(vectorType, &mPos, ownerRef);
    }

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    GPG_ASSERT(coordsType != nullptr);
    if (coordsType) {
      archive->Read(coordsType, &mSlotCenter, ownerRef);
      archive->Read(coordsType, &mCenter, ownerRef);
      archive->Read(coordsType, &mDynamicOffset, ownerRef);
      archive->Read(coordsType, &mExtent, ownerRef);
    }

    archive->ReadBool(&mUseDynamicOffset);
    archive->ReadBool(&mInFormation);
    archive->ReadFloat(&mSpeed);
    archive->ReadFloat(&mAvgDistToTarget);

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    GPG_ASSERT(weakPtrType != nullptr);
    if (weakPtrType) {
      archive->Read(weakPtrType, &mLeader, ownerRef);
    }
  }

  /**
   * Address: 0x00566500 (FUN_00566500, Moho::SOffsetInfoSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade: forwards one `SOffsetInfo` payload to
   * `SOffsetInfo::MemberDeserialize`; `version` and the owner-ref are unused
   * by the member (mirrors the binary tail call).
   */
  void SOffsetInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const offsetInfo = reinterpret_cast<SOffsetInfo*>(objectPtr);
    if (offsetInfo != nullptr) {
      offsetInfo->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x005744E0 (FUN_005744E0, Moho::CFormationInstance::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::CFormationInstance::MemberSerialize(
   *     Moho::CFormationInstance* this@<edi>, BinaryWriteArchive* archive@<esi>);
   *
   * What it does:
   * Writes the reflected base payload, then the owning Lua-state and game-rules
   * references as unowned tracked pointers, then every formation field in a
   * fixed order. `mSim` and the trailing word are runtime-only and deliberately
   * not written - a loaded formation re-binds them from its owner.
   */
  void CFormationInstance::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (archive == nullptr) {
      return;
    }

    auto* const self = const_cast<CFormationInstance*>(this);
    const gpg::RRef ownerRef{};

    if (gpg::RType* const baseType = CachedCFormationInstanceType(); baseType != nullptr) {
      archive->Write(baseType, self, ownerRef);
    }

    gpg::RRef pointerRef{};
    (void)gpg::RRef_LuaState(&pointerRef, mState);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);
    (void)gpg::RRef_RRuleGameRules(&pointerRef, mGamerules);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    WriteFormationField(archive, CachedEUnitCommandTypeType(), &self->mCommandType, ownerRef);
    WriteFormationField(archive, CachedFastVectorWeakPtrIUnitType(), &self->mUnits, ownerRef);
    WriteFormationField(archive, CachedFastVectorSOffsetInfoType(), &self->mOffsetInfo[0], ownerRef);
    WriteFormationField(archive, CachedFastVectorSOffsetInfoType(), &self->mOffsetInfo[1], ownerRef);
    WriteFormationField(archive, CachedFastVectorSAssignedLocInfoType(), &self->mSlots, ownerRef);
    WriteFormationField(archive, CachedMapEntIdSCoordsVec2Type(), &self->mFormationPosCache, ownerRef);
    WriteFormationField(archive, CachedMapEntIdSCoordsVec2Type(), &self->mOffsetPosCache, ownerRef);
    WriteFormationField(archive, CachedVector3fType(), &self->mForwardVector, ownerRef);
    WriteFormationField(archive, CachedQuaternionfType(), &self->mOrientation, ownerRef);
    WriteFormationField(archive, CachedQuaternionfType(), &self->mOrientationChange, ownerRef);

    archive->WriteString(&self->mScriptName);
    WriteFormationField(archive, CachedSCoordsVec2Type(), &self->mCoords, ownerRef);
    archive->WriteFloat(mScale);
    archive->WriteBool(mPlanUpdate != 0u);
    archive->WriteInt(mMaxSize);
  }

  /**
   * Address: 0x005741D0 (FUN_005741D0, Moho::CFormationInstance::MemberDeserialize)
   *
   * What it does:
   * Reads the eighteen fields back in the order `MemberSerialize` wrote them.
   * The two owning references come back through typed pointer readers, which
   * is what re-establishes tracking for the Lua state and the game rules.
   */
  void CFormationInstance::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    if (gpg::RType* const baseType = CachedCFormationInstanceType(); baseType != nullptr) {
      archive->Read(baseType, this, ownerRef);
    }

    (void)archive->ReadPointer_LuaState(&mState, &ownerRef);
    (void)archive->ReadPointer_RRuleGameRules(&mGamerules, &ownerRef);

    ReadFormationField(archive, CachedEUnitCommandTypeType(), &mCommandType, ownerRef);
    ReadFormationField(archive, CachedFastVectorWeakPtrIUnitType(), &mUnits, ownerRef);
    ReadFormationField(archive, CachedFastVectorSOffsetInfoType(), &mOffsetInfo[0], ownerRef);
    ReadFormationField(archive, CachedFastVectorSOffsetInfoType(), &mOffsetInfo[1], ownerRef);
    ReadFormationField(archive, CachedFastVectorSAssignedLocInfoType(), &mSlots, ownerRef);
    ReadFormationField(archive, CachedMapEntIdSCoordsVec2Type(), &mFormationPosCache, ownerRef);
    ReadFormationField(archive, CachedMapEntIdSCoordsVec2Type(), &mOffsetPosCache, ownerRef);
    ReadFormationField(archive, CachedVector3fType(), &mForwardVector, ownerRef);
    ReadFormationField(archive, CachedQuaternionfType(), &mOrientation, ownerRef);
    ReadFormationField(archive, CachedQuaternionfType(), &mOrientationChange, ownerRef);

    archive->ReadString(&mScriptName);
    ReadFormationField(archive, CachedSCoordsVec2Type(), &mCoords, ownerRef);
    archive->ReadFloat(&mScale);

    bool planUpdate = false;
    archive->ReadBool(&planUpdate);
    mPlanUpdate = planUpdate ? 1u : 0u;

    archive->ReadInt(&mMaxSize);
  }

  /**
   * Address: 0x005661C0 (FUN_005661C0, preregister_SUnitOffsetInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SUnitOffsetInfo`.
   */
  gpg::RType* preregister_SUnitOffsetInfoTypeInfo()
  {
    static SUnitOffsetInfoTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SUnitOffsetInfo), &typeInfo);
    SUnitOffsetInfo::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x005667A0 (FUN_005667A0, preregister_SAssignedLocInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SAssignedLocInfo`. Reached
   * from `sub_BCABC0` (`0x00BCABC0`, `.CRT$XCL` phase via `__xc_a`), which
   * additionally schedules teardown for the constructed descriptor
   * (`FUN_00BF59B0`) - reproduced here by the local static's own destructor
   * running at process exit, the same simplification already used for
   * `preregister_SUnitOffsetInfoTypeInfo` above.
   */
  gpg::RType* preregister_SAssignedLocInfoTypeInfo()
  {
    static SAssignedLocInfoTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SAssignedLocInfo), &typeInfo);
    SAssignedLocInfo::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x005665B0 (FUN_005665B0, preregister_IFormationInstanceTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `IFormationInstance`.
   */
  gpg::RType* preregister_IFormationInstanceTypeInfo()
  {
    static IFormationInstanceTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(IFormationInstance), &typeInfo);
    IFormationInstance::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x00571A70 (FUN_00571A70, preregister_RMapType_EntId_SUnitOffsetInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `std::map<EntId,SUnitOffsetInfo>`.
   */
  gpg::RType* preregister_RMapType_EntId_SUnitOffsetInfo()
  {
    static RMapType_EntId_SUnitOffsetInfo typeInfo;
    gpg::PreRegisterRType(typeid(UnitOffsetMap), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00571AD0 (FUN_00571AD0, preregister_RBroadcasterRType_EFormationdStatus)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `Broadcaster<EFormationdStatus>`.
   */
  gpg::RType* preregister_RBroadcasterRType_EFormationdStatus()
  {
    static RBroadcasterRType_EFormationdStatus typeInfo;
    gpg::PreRegisterRType(typeid(BroadcasterEventTag<EFormationdStatus>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00571B30 (FUN_00571B30, preregister_RListenerRType_EFormationdStatus)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `Listener<EFormationdStatus>`.
   */
  gpg::RType* preregister_RListenerRType_EFormationdStatus()
  {
    static RListenerRType_EFormationdStatus typeInfo;
    gpg::PreRegisterRType(typeid(Listener<EFormationdStatus>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00571CE0 (FUN_00571CE0, preregister_RMapType_EntId_SCoordsVec2)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::map<EntId,SCoordsVec2>`.
   */
  gpg::RType* preregister_RMapType_EntId_SCoordsVec2()
  {
    static RMapType_EntId_SCoordsVec2 typeInfo;
    gpg::PreRegisterRType(typeid(CoordMap), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00566070 (FUN_00566070, Moho::CFormationInstance::GetDistFromLeader)
   * Slot: 10
   *
   * What it does:
   * Base implementation: no leader distance, always zero.
   */
  float CFormationInstance::GetDistFromLeader(Unit* const, SOffsetInfo* const)
  {
    return 0.0f;
  }

  /**
   * Address: 0x00566080 (FUN_00566080, Moho::CFormationInstance::GetPriority)
   * Slot: 11
   *
   * What it does:
   * Base implementation: every unit has priority 1.
   */
  std::int32_t CFormationInstance::GetPriority(Unit* const, SOffsetInfo* const)
  {
    return 1;
  }

  /**
   * Address: 0x00569CA0 (FUN_00569CA0, Moho::CFormationInstance::CalcFormationSpeed)
   * Slot: 12
   *
   * What it does:
   * Base implementation: zero formation speed; `CAiFormationInstance`
   * overrides it with the group-relative speed computation.
   */
  float CFormationInstance::CalcFormationSpeed(Unit* const, float* const, SOffsetInfo* const)
  {
    return 0.0f;
  }

  /**
   * Address: 0x0056A6E0 (FUN_0056A6E0, Moho::CFormationInstance::GetLeader)
   * Slot: 13
   *
   * What it does:
   * Base implementation: no leader, always null.
   */
  Unit* CFormationInstance::GetLeader(Unit* const, SOffsetInfo* const)
  {
    return nullptr;
  }

  /**
   * Address: 0x0056A700 (FUN_0056A700, Moho::CFormationInstance::FindSlotFor)
   * Slot: 25
   *
   * What it does:
   * Base implementation: hands `pos` straight back through `dest` without
   * consulting the assigned-slot table.
   */
  SCoordsVec2* CFormationInstance::FindSlotFor(SCoordsVec2* const dest, const SCoordsVec2* const pos, Unit* const)
  {
    *dest = *pos;
    return dest;
  }

  /**
   * Address: 0x005692D0 (FUN_005692D0, Moho::CFormationInstance::CFormationInstance)
   *
   * What it does:
   * Reference count zero, listener ring self-linked (the `Broadcaster`
   * member's own constructor), no Lua state, rules or command, every
   * container on its inline storage with both cache heads standing (the
   * members' own constructors), an empty script name, a NaN centre, no
   * pending plan, zero max footprint and zero scale. The orientation lanes
   * and the two spare words are left untouched, exactly as the binary
   * leaves them.
   */
  CFormationInstance::CFormationInstance()
    : mSharedCount(0)
    , mState(nullptr)
    , mGamerules(nullptr)
    , mCommandType(EUnitCommandType::UNITCOMMAND_None)
  {
    const float quietNan = std::numeric_limits<float>::quiet_NaN();
    mCoords.x = quietNan;
    mCoords.z = quietNan;
    mPlanUpdate = 0u;
    mMaxSize = 0;
    mScale = 0.0f;
  }

  /**
   * Mangled: ??0CAiFormationInstance@Moho@@QAE@@Z
   *
   * A standalone out-of-line body for this constructor exists at 0x0059A470,
   * but has zero incoming references of any kind (code, data, or vtable) in
   * the callgraph index - every construction site found
   * (`Moho::CAiFormationInstance::operator new`, 0x0059D0F0) inlines this
   * exact sequence instead of calling out to it, so 0x0059A470 itself is not
   * citable as reachable. The behavior recovered here - the base
   * `CFormationInstance` default construction (0x005692D0), vtable
   * publication, and clearing the owning-`Sim` back-reference - is proven
   * directly from that inlined copy, which the recovered `NewRef`
   * (`CAiFormationInstanceTypeInfo.cpp`) invokes as `new CAiFormationInstance()`.
   */
  CAiFormationInstance::CAiFormationInstance()
    : CFormationInstance()
    , mSim(nullptr)
  {
  }

  /**
   * Inlined into `CAiFormationDBImpl::NewFormation` (0x0059C120,
   * 0x0059C1F6-0x0059C22B): `::operator new(0x330)`, the base constructor
   * with the sim's rules and Lua state, the `CAiFormationInstance` vtable,
   * then `mSim`.
   *
   * What it does:
   * Builds a formation for `sim` over `units` (see the base constructor,
   * which runs its first `UpdateFormation` pass with the base vtable still
   * in place, exactly as the binary does) and binds the owning sim.
   */
  CAiFormationInstance::CAiFormationInstance(
    Sim* const sim,
    RRuleGameRules* const rules,
    const EUnitCommandType commandType,
    LuaPlus::LuaState* const state,
    const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
    const char* const name,
    const SCoordsVec2& coords,
    const Wm3::Quatf& orientation
  )
    : CFormationInstance(rules, commandType, state, units, name, coords, orientation)
    , mSim(sim)
  {
  }

  /**
   * Address: 0x0059A500 (FUN_0059A500, ??1CAiFormationInstance@Moho@@QAE@@Z)
   * Mangled: ??1CAiFormationInstance@Moho@@QAE@@Z
   *
   * What it does:
   * Resets the transient plan, unregisters this instance from the owning
   * formation DB, then lets `~CFormationInstance` tear the members down.
   */
  CAiFormationInstance::~CAiFormationInstance()
  {
    CleanupFormation();
    mSim->mFormationDB->RemoveFormation(this);
  }

  /**
   * Address: 0x0059BD60 (FUN_0059BD60, ??3CAiFormationInstance@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes CAiFormationInstance teardown and conditionally frees this object
   * when `deleteFlags & 1` is set.
   */
  void CAiFormationInstance::operator_delete(const std::int32_t deleteFlags)
  {
    this->~CAiFormationInstance();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(this);
    }
  }

  /**
   * Address: 0x0059E950 (FUN_0059E950, Moho::CAiFormationInstance::MemberDeserialize)
   *
   * What it does:
   * Reads the serialized base-formation payload, then restores `mSim` as an
   * unowned tracked pointer.
   */
  void CAiFormationInstance::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    gpg::RType* const baseType = CachedCFormationInstanceType();
    GPG_ASSERT(baseType != nullptr);
    if (baseType) {
      archive->Read(baseType, this, owner);
    }

    mSim = ReadPointerSim(archive, owner);
  }

  /**
   * Address: 0x0059E9B0 (FUN_0059E9B0, Moho::CAiFormationInstance::MemberSerialize)
   *
   * What it does:
   * Writes the serialized base-formation payload, then saves `mSim` as an
   * unowned tracked pointer.
   */
  void CAiFormationInstance::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    gpg::RType* const baseType = CachedCFormationInstanceType();
    GPG_ASSERT(baseType != nullptr);
    if (baseType) {
      archive->Write(baseType, this, owner);
    }

    WritePointerSim(archive, mSim, owner);
  }

  /**
   * Address: 0x00569A10 (FUN_00569A10)
   *
   * What it does:
   * Copies the formation centre into `outCoords`.
   */
  SCoordsVec2* CFormationInstance::GetCoords(SCoordsVec2* const outCoords) const
  {
    outCoords->x = mCoords.x;
    outCoords->z = mCoords.z;
    return outCoords;
  }

  /**
   * Address: 0x00569A30 (FUN_00569A30, Moho::CFormationInstance::SetCoords)
   *
   * What it does:
   * Moves the formation centre when the new one differs (the `ucomiss`/
   * `lahf` pair at 0x00569A4C treats NaN as different, i.e. plain `!=`)
   * and is not NaN itself, dropping every assigned slot and both caches.
   */
  void CFormationInstance::SetCoords(const SCoordsVec2& coords)
  {
    if (mCoords.x != coords.x || mCoords.z != coords.z) {
      if (!std::isnan(coords.x) && !std::isnan(coords.z)) {
        mCoords = coords;
        ClearSlotCaches();
      }
    }
  }

  /**
   * Address: 0x005694B0 (FUN_005694B0, Moho::CFormationInstance::CFormationInstance)
   *
   * IDA signature:
   * Moho::CAiFormationInstance *__fastcall Moho::CFormationInstance::CFormationInstance(
   *     Moho::RRuleGameRulesImpl *rules, int commandType, Moho::CFormationInstance *this,
   *     LuaPlus::LuaState *state, gpg::fastvector_n<WeakPtr<IUnit>, 4> *units,
   *     const char *name, Moho::SCoordsVec2 *coords, Wm3::Quaternionf orientation);
   *
   * What it does:
   * Self-links the listener ring, stamps the Lua state/game-rules/command-type
   * fields, and copies the caller's initial unit set into `mUnits` (the
   * binary's `sub_56B200` is the `fastvector_n<WeakPtr<IUnit>,4>` copy
   * constructor: every copied link is spliced into its unit's weak chain).
   * Both group vectors and the slot vector default-construct inline (the
   * binary's own `eh vector constructor iterator` / inline-buffer setup),
   * both cache heads are allocated (`sub_570300`, the map constructor), the
   * forward vector is zeroed, the orientation and script name copied and the
   * centre, scale (1.0), max size and pending flag set. When `coords`
   * resolves to a valid flat ground-plane point, the initial forward vector
   * is derived from `orientation` with the same formula `SetOrientation`
   * uses, the slot caches are cleared and one `UpdateFormation` pass runs.
   * `mUnknown_0x01C` is left untouched, matching the binary.
   */
  CFormationInstance::CFormationInstance(
    RRuleGameRules* const rules,
    const EUnitCommandType commandType,
    LuaPlus::LuaState* const state,
    const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
    const char* const name,
    const SCoordsVec2& coords,
    const Wm3::Quatf& orientation
  )
    : mSharedCount(0)
    , mState(state)
    , mGamerules(rules)
    , mCommandType(commandType)
    , mUnits(units)
    , mForwardVector(Wm3::Vec3f::ZERO)
    , mOrientation(orientation)
    , mOrientationChange(kZeroQuaternion)
    , mScriptName(name)
    , mCoords(coords)
    , mScale(1.0f)
    , mPlanUpdate(0)
    , mMaxSize(0)
  {
    const Wm3::Vec3f groundPoint{mCoords.x, 0.0f, mCoords.z};
    if (!IsValidVector3f(groundPoint)) {
      return;
    }

    if (mOrientation != kZeroQuaternion) {
      mForwardVector = ForwardOf(mOrientation);
    }

    ClearSlotCaches();
    UpdateFormation();
  }

  /**
   * Address: 0x0056A920 (FUN_0056A920, ??2CFormationInstance@Moho@@QAE@@Z,
   * Moho::CFormationInstance::operator new)
   *
   * What it does:
   * Allocates one `sizeof(CFormationInstance)` (0x328) block via a throwing
   * `::operator new` guarded by the binary's own explicit post-allocation
   * null check (0x0056A949/0x0056A953; reproduced here with the `nothrow`
   * form), then placement-constructs a `CFormationInstance` on it with
   * `commandType` hardcoded to `UNITCOMMAND_None` (the binary's own
   * `xor edx, edx` before the ctor call). Returns `nullptr` when the
   * allocation itself fails; the caller (`CFormation::Finalize`, 0x0083843B)
   * never observes a null return in practice, since it only calls this once
   * `mBestFormation >= 0`.
   */
  CFormationInstance* CFormationInstance::Create(
    RRuleGameRules* const rules,
    LuaPlus::LuaState* const state,
    const gpg::fastvector_n<WeakPtr<IUnit>, 4>& units,
    const char* const name,
    const SCoordsVec2& coords,
    const Wm3::Quatf& orientation
  )
  {
    void* const storage = ::operator new(sizeof(CFormationInstance), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CFormationInstance(
      rules, EUnitCommandType::UNITCOMMAND_None, state, units, name, coords, orientation);
  }

  /**
   * Address: 0x00569880 (FUN_00569880, Moho::CFormationInstance::~CFormationInstance)
   *
   * IDA signature:
   * void __stdcall Moho::CFormationInstance::~CFormationInstance(Moho::CFormationInstance *a1);
   *
   * What it does:
   * Resets the transient formation plan. Everything after that in the binary
   * is the compiler's own teardown, emitted inline: the script name, both
   * caches (`sub_56F430` erase-all plus the head free), the slot vector, the
   * two group vectors (`eh vector destructor iterator` over `sub_56B4D0`)
   * and the unit vector (`sub_56D3C0` destroy-range plus the heap free) are
   * destroyed in reverse declaration order, and the trailing broadcaster
   * unlink belongs to `~IFormationInstance`.
   */
  CFormationInstance::~CFormationInstance()
  {
    CleanupFormation();
  }

  /**
   * Address: 0x00569430 (FUN_00569430, Moho::CFormationInstance::operator delete)
   * Slot: 0
   *
   * What it does:
   * Runs the destructor, then frees storage when bit0 of `deleteFlags` is set.
   */
  void CFormationInstance::operator_delete(const std::int32_t deleteFlags)
  {
    this->~CFormationInstance();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(this);
    }
  }

  /**
   * The three-step slot reset inlined at 0x00569A30 (`SetCoords`),
   * 0x005694B0 (the constructor tail) and 0x00568AC0 (`CleanupFormation`):
   * the slot vector back to inline storage (`sub_56F430`-style free plus the
   * inline rebind), then both caches emptied in place (`sub_56D8E0` subtree
   * destroy plus the head self-link, the map's `clear()`).
   */
  void CFormationInstance::ClearSlotCaches()
  {
    mSlots.ResetStorageToInline();
    mFormationPosCache.clear();
    mOffsetPosCache.clear();
  }

  /**
   * Address: 0x00568AC0 (FUN_00568AC0, Moho::CFormationInstance::CleanupFormation)
   *
   * IDA signature:
   * void __usercall Moho::CFormationInstance::CleanupFormation@<eax>(
   *     Moho::CFormationInstance *this@<eax>);
   *
   * What it does:
   * Resets transient formation-plan state so a fresh plan can be recomputed:
   * clears the assigned slots and both caches, zeroes the orientation
   * change, and destroys every group of both layers (each group's destructor
   * unlinks its leader and frees its unit map -- the per-element
   * `sub_56EB40` erase plus head free at 0x00568B4A-0x00568B9F) before the
   * group vectors return to inline storage.
   */
  void CFormationInstance::CleanupFormation()
  {
    ClearSlotCaches();
    mOrientationChange = kZeroQuaternion;

    for (std::int32_t layer = 0; layer < kFormationLayerCount; ++layer) {
      mOffsetInfo[layer].ResetStorageToInline();
    }
  }

  /**
   * Address: 0x0056A6B0 (FUN_0056A6B0, Moho::CFormationInstance::Update)
   * Slot: 17
   *
   * What it does:
   * When a plan update is pending, clears the pending flag and runs one
   * cleanup+rebuild pass: drops dead unit links, resets transient formation
   * state, and rebuilds the formation plan. `CAiFormationInstance` overrides
   * this same vtable slot with its own, much larger update pass
   * (`FUN_0059AE80`), so this base implementation only runs for a bare
   * `CFormationInstance` (the `CFormation::Finalize` preview instances).
   */
  void CFormationInstance::Update()
  {
    RefreshFormationPlanIfRequested(*this);
  }

  /**
   * Address: 0x0056A210 (FUN_0056A210)
   *
   * What it does:
   * Returns number of unit links currently held by this formation.
   */
  int CFormationInstance::UnitCount() const
  {
    return static_cast<int>(mUnits.size());
  }

  /**
   * Address: 0x00569BD0 (FUN_00569BD0)
   *
   * IDA signature:
   * int __stdcall Moho::CFormationInstance::GetLayer(Moho::Unit *unit);
   *
   * What it does:
   * Classifies the unit into its formation layer: air-motion blueprints get
   * layer 1, everything else layer 0. The value indexes `mOffsetInfo`.
   */
  std::int32_t CFormationInstance::GetLayer(Unit* const unit) const
  {
    const bool isAirLayer = unit->GetBlueprint()->Physics.MotionType == RULEUMT_Air;
    return isAirLayer ? kAirFormationLayer : kGroundFormationLayer;
  }

  /**
   * Address: 0x005669A0 (FUN_005669A0, Moho::CFormationInstance::GetOffsetInfo)
   *
   * What it does:
   * Returns the first group of the unit's layer whose unit map holds the
   * unit's entity id (`std::map::find`, 0x0056AFE0), warning and returning
   * null when none does.
   */
  SOffsetInfo* CFormationInstance::GetOffsetInfo(Unit* const unit)
  {
    for (SOffsetInfo& info : mOffsetInfo[GetLayer(unit)]) {
      if (info.mUnitOffsets.find(unit->GetEntityId()) != info.mUnitOffsets.end()) {
        return &info;
      }
    }

    gpg::Warnf("unit %s not part of formation.", unit->GetBlueprint()->mBlueprintId.c_str());
    return nullptr;
  }

  /**
   * Address: 0x00566A30 (FUN_00566A30, Moho::CFormationInstance::ComputeRunScriptOffset)
   *
   * What it does:
   * Scales one script-local formation offset by `mScale`, rotates it by the
   * formation orientation when that is non-zero, then multiplies by the
   * slot-span scale `mMaxSize + 2`.
   */
  SCoordsVec2* CFormationInstance::ComputeRunScriptOffset(
    const SCoordsVec2* const sourceOffset,
    SCoordsVec2* const dest
  ) const
  {
    const Wm3::Vec3f scaled{sourceOffset->x * mScale, mScale * 0.0f, sourceOffset->z * mScale};

    float rotatedX = scaled.x;
    float rotatedZ = scaled.z;
    if (mOrientation != kZeroQuaternion) {
      Wm3::Vec3f rotated{};
      (void)MultQuadVec(&rotated, &scaled, &mOrientation);
      rotatedX = rotated.x;
      rotatedZ = rotated.z;
    }

    const float slotSpanScale = static_cast<float>(mMaxSize + 2);
    dest->x = slotSpanScale * rotatedX;
    dest->z = rotatedZ * slotSpanScale;
    return dest;
  }

  /**
   * Address: 0x00566B10 (FUN_00566B10, Moho::CFormationInstance::PreRunScript)
   *
   * What it does:
   * Empties `layerUnitsOut` (`sub_56D3C0` destroy-range plus the inline
   * rebind), then walks `candidateUnits`: every live unit whose layer
   * matches `layerIndex` is copied into `layerUnitsOut` (the temporary
   * `WeakPtr<IUnit>` at 0x00566B6A pushed through `sub_56B2F0`/the inline
   * append and destroyed again) and erased from the shared list
   * (`sub_5725A0`, the relinking shift, plus the tail unlink); units of a
   * different layer are left in place.
   */
  void CFormationInstance::PreRunScript(
    gpg::fastvector_n<WeakPtr<IUnit>, 4>& layerUnitsOut,
    gpg::fastvector_n<WeakPtr<IUnit>, 4>& candidateUnits,
    const std::int32_t layerIndex
  )
  {
    layerUnitsOut.ResetStorageToInline();

    for (auto it = candidateUnits.begin(); it != candidateUnits.end();) {
      Unit* const unit = UnitOf(*it);
      if (unit != nullptr && GetLayer(unit) == layerIndex) {
        layerUnitsOut.push_back(WeakPtr<IUnit>(unit));
        it = candidateUnits.erase(it);
        continue;
      }
      ++it;
    }
  }

  /**
   * Address: 0x00568820 (FUN_00568820, Moho::CFormationInstance::Setup)
   *
   * What it does:
   * Claims this layer's units out of the shared candidate list via
   * `PreRunScript`, runs the formation script over them via `RunScript`
   * when any were claimed, then releases the per-layer scratch list (its
   * destructor: `sub_56D3C0` plus the heap free).
   */
  void CFormationInstance::Setup(gpg::fastvector_n<WeakPtr<IUnit>, 4>& candidateUnits, const std::int32_t layerIndex)
  {
    gpg::fastvector_n<WeakPtr<IUnit>, 4> layerUnits{};
    PreRunScript(layerUnits, candidateUnits, layerIndex);

    if (!layerUnits.empty()) {
      RunScript(layerUnits, layerIndex);
    }
  }

  /**
   * Address: 0x00567300 (FUN_00567300, Moho::CFormationInstance::RunScript)
   *
   * ASM-only recovery (no `.c` decompile). See
   * `decomp/recovery/escalations/FUN_00567300.md` for the stack-frame
   * decode key, EH funclet table, and call-table evidence this follows.
   * 1010 instructions.
   *
   * What it does (seven phases):
   *  1. Builds a Lua table of unit LuaObjects from `units`.
   *  2. Calls `Moho::FORMATION_RunScript`; early-exits if it produced no
   *     slots.
   *  3. Computes the mean unit XZ position.
   *  4. Builds one `SFormationRunScriptUnitDesc` per unit: position
   *     relative to the mean, optionally rotated by `mOrientationChange`
   *     when the script succeeded and the change is non-zero. Folds the
   *     group's speed (min over units of
   *     `CanFly ? MaxAirspeed*0.85f/CalcTransportLoadFactor() : MaxSpeed*0.85f`).
   *  5. Computes slot-table span/mean statistics feeding
   *     `mExtent = max(2.0f, span)`, `mCenter = mean unit XZ` and
   *     `mSlotCenter = mean slot offset`.
   *  6. Builds one `SFormationRunScriptCandidate` per script slot (rotated
   *     offset, category, weight) and sorts them ascending by squared
   *     distance from the formation mean.
   *  7. Greedily assigns each sorted candidate's nearest still-free
   *     category-matching unit, storing one `SUnitOffsetInfo` per
   *     assignment in the new group's `mUnitOffsets` (`operator[]`,
   *     0x0056AAF0, at 0x00567E06/0x00567F9A; leader priority counting from
   *     1), warns on duplicate assignment, calls `RemoveUnit` for anything
   *     left unassigned, and appends the finished group to
   *     `mOffsetInfo[layerIndex]` (`push_back`, 0x0056B590).
   */
  void CFormationInstance::RunScript(gpg::fastvector_n<WeakPtr<IUnit>, 4>& units, const std::int32_t layerIndex)
  {
    // Phase 1 (0x00567364-0x005673B9). The binary does not null-check the
    // resolved unit -- every caller (Setup, via PreRunScript) guarantees
    // live units in this list.
    LuaPlus::LuaObject unitTable;
    unitTable.AssignNewTable(mState, 0, 0);
    std::int32_t unitLuaIndex = 0;
    for (WeakPtr<IUnit>& link : units) {
      Unit* const unit = UnitOf(link);
      LuaPlus::LuaObject luaUnit = unit->GetLuaObject();
      unitTable.Insert(unitLuaIndex, luaUnit);
      ++unitLuaIndex;
    }

    // Phase 2 (0x005673BB-0x00567415).
    SFormationScriptResult scriptResult =
      FORMATION_RunScript(mState, mGamerules, gpg::StrArg(mScriptName.c_str()), unitTable);
    if (scriptResult.mObjs.empty()) {
      return;
    }

    // Phase 3 (0x00567459-0x00567520): mean unit XZ.
    float meanX = 0.0f;
    float meanZ = 0.0f;
    if (!units.empty()) {
      for (const WeakPtr<IUnit>& link : units) {
        const Wm3::Vec3f& pos = UnitOf(link)->GetPosition();
        meanX += pos.x;
        meanZ += pos.z;
      }
      const float invCount = 1.0f / static_cast<float>(units.size());
      meanX *= invCount;
      meanZ *= invCount;
    } else {
      meanX = std::numeric_limits<float>::max();
      meanZ = std::numeric_limits<float>::max();
    }

    // Phase 4 (0x00567526-0x005677CD): per-unit relative descriptors +
    // group speed. `gpg::fastvector_n<Desc32,16>` is the local's real
    // binary shape, per the escalation doc's funclet table (0x00BADE3C,
    // D=0x154). Left un-reserved: the binary never reserves it either,
    // relying on the 16 inline slots plus `push_back`'s own grow.
    gpg::fastvector_n<SFormationRunScriptUnitDesc, 16> unitDescs;
    float groupSpeed = std::numeric_limits<float>::max();
    for (WeakPtr<IUnit>& link : units) {
      Unit* const unit = UnitOf(link);
      const Wm3::Vec3f& pos = unit->GetPosition();

      SFormationRunScriptUnitDesc desc{};
      desc.unit = unit;
      desc.relative = Wm3::Vec3f{pos.x - meanX, 0.0f, pos.z - meanZ};
      desc.relativeRotated = desc.relative;
      if (scriptResult.mSuccess && mOrientationChange != kZeroQuaternion) {
        Wm3::Vec3f rotated{};
        (void)MultQuadVec(&rotated, &desc.relative, &mOrientationChange);
        desc.relativeRotated = rotated;
      }
      desc.weight = 1.0f;
      unitDescs.push_back(desc);

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      const float unitSpeed = (blueprint->Air.CanFly != 0u)
        ? (blueprint->Air.MaxAirspeed * 0.85f) / unit->CalcTransportLoadFactor()
        : blueprint->Physics.MaxSpeed * 0.85f;
      groupSpeed = std::min(groupSpeed, unitSpeed);
    }

    // Phase 5 (0x005677E4-0x005679D4): slot-table span/mean statistics.
    float slotMinX = std::numeric_limits<float>::infinity();
    float slotMaxX = -std::numeric_limits<float>::infinity();
    float slotMinZ = std::numeric_limits<float>::infinity();
    float slotMaxZ = -std::numeric_limits<float>::infinity();
    float slotSumX = 0.0f;
    float slotSumZ = 0.0f;
    for (const SFormationScriptSlot& slot : scriptResult.mObjs) {
      SCoordsVec2 rotatedOffset{};
      ComputeRunScriptOffset(&slot.mOffset, &rotatedOffset);
      slotSumX += rotatedOffset.x;
      slotSumZ += rotatedOffset.z;
      slotMinX = std::min(slotMinX, rotatedOffset.x);
      slotMaxX = std::max(slotMaxX, rotatedOffset.x);
      slotMinZ = std::min(slotMinZ, rotatedOffset.z);
      slotMaxZ = std::max(slotMaxZ, rotatedOffset.z);
    }
    const float invSlotCount = 1.0f / static_cast<float>(scriptResult.mObjs.size());

    SOffsetInfo group;
    group.mExtent = SCoordsVec2{std::max(2.0f, slotMaxX - slotMinX), std::max(2.0f, slotMaxZ - slotMinZ)};
    group.mCenter = SCoordsVec2{meanX, meanZ};
    group.mSlotCenter = SCoordsVec2{slotSumX * invSlotCount, slotSumZ * invSlotCount};
    group.mSpeed = groupSpeed;

    // Phase 6 (0x00567A40-0x00567C71): one candidate per script slot,
    // sorted by decreasing squared distance from the formation mean.
    // `gpg::fastvector_n<Cand72,16>` is the local's real binary shape, per
    // the escalation doc's funclet table (0x00BADE47, D=0x364); `push_back`'s
    // grow lane is FUN_0056C940 / FUN_0056E620 / FUN_0056FAB0 / FUN_0056FB90 /
    // FUN_00573000, cited on FastVector.h's push_back/InsertAt/
    // GrowInsertDeepCopy/UninitializedCopyForward/CopyBackwardAssign for
    // this element type.
    gpg::fastvector_n<SFormationRunScriptCandidate, 16> candidates;
    for (const SFormationScriptSlot& slot : scriptResult.mObjs) {
      SCoordsVec2 rotatedOffset{};
      ComputeRunScriptOffset(&slot.mOffset, &rotatedOffset);

      SFormationRunScriptCandidate candidate{};
      candidate.position = Wm3::Vec3f{rotatedOffset.x, 0.0f, rotatedOffset.z};
      candidate.anchorDelta = candidate.position;
      candidate.distanceSq = rotatedOffset.x * rotatedOffset.x + rotatedOffset.z * rotatedOffset.z;
      candidate.weight = slot.mWeight;
      candidate.category = slot.mCategory;
      candidates.push_back(candidate);
    }
    msvc8::sort(candidates.begin(), candidates.end(), CompareRunScriptCandidateByDistanceSq);

    // Phase 7 (0x00567D97-0x00568280): greedy nearest-unit assignment. The
    // per-assignment `SUnitOffsetInfo` is the stack value filled at
    // 0x00567EED-0x00567FA3: the unit, the running priority, the slot
    // offset, a zero target, an unset (+inf) heading, zero distances and the
    // script weight.
    std::int32_t leaderPriority = 0;
    for (const SFormationRunScriptCandidate& candidate : candidates) {
      auto bestIt = unitDescs.end();
      float bestDistSq = std::numeric_limits<float>::infinity();
      for (auto it = unitDescs.begin(); it != unitDescs.end(); ++it) {
        if (it->unit == nullptr) {
          continue;
        }
        if (!EntityCategory::HasBlueprint(it->unit->GetBlueprint(), &candidate.category)) {
          continue;
        }

        const float dx = candidate.anchorDelta.x - it->relativeRotated.x;
        const float dz = candidate.anchorDelta.z - it->relativeRotated.z;
        const float distSq = dx * dx + dz * dz;
        if (distSq < bestDistSq) {
          bestDistSq = distSq;
          bestIt = it;
        }
      }

      if (bestIt == unitDescs.end()) {
        continue;
      }

      Unit* const bestUnit = bestIt->unit;
      const EntId entityId = bestUnit->GetEntityId();
      if (group.mUnitOffsets.find(entityId) != group.mUnitOffsets.end()) {
        gpg::Warnf(
          "HASH duplicated on %d in formation %d",
          static_cast<int>(reinterpret_cast<std::uintptr_t>(bestUnit)),
          static_cast<int>(reinterpret_cast<std::uintptr_t>(this))
        );
      }

      ++leaderPriority;
      SUnitOffsetInfo info{};
      info.mUnit.Set(bestUnit);
      info.mLeaderPriority = leaderPriority;
      info.mOffset = SCoordsVec2{candidate.position.x, candidate.position.z};
      info.mTargetPos = Wm3::Vec3f::ZERO;
      info.mHeadingAngle = std::numeric_limits<float>::infinity();
      info.mDistToTarget = 0.0f;
      info.mDistFromLeader = 0.0f;
      info.mWeight = candidate.weight;
      group.mUnitOffsets[entityId] = info;

      // Consumed: skip this unit in subsequent candidates' nearest search.
      bestIt->unit = nullptr;
    }

    for (const SFormationRunScriptUnitDesc& desc : unitDescs) {
      if (desc.unit == nullptr) {
        continue;
      }

      gpg::Warnf(
        "Failed to assaign unit %s a slot in the formation %s (units=%d, formation slots=%d)",
        desc.unit->GetBlueprint()->mBlueprintId.c_str(),
        mScriptName.c_str(),
        static_cast<int>(units.size()),
        static_cast<int>(scriptResult.mObjs.size())
      );
      RemoveUnit(desc.unit);
    }

    mOffsetInfo[layerIndex].push_back(group);
  }

  /**
   * Address: 0x00568CA0 (FUN_00568CA0, Moho::CFormationInstance::UpdateFormation)
   *
   * What it does:
   * Snapshots every live, mobile, built, non-destroy-queued unit with a
   * valid position into a scratch unit set (the temporary `WeakPtr<IUnit>`
   * push at 0x00568D2C-0x00568D4F), accumulating the units' mean forward
   * vector and the largest footprint size. Refreshes `mOrientationChange`
   * from the difference between the formation heading and the mean unit
   * heading when the two differ by less than 108 degrees. Rebuilds each
   * layer in turn -- destroys its previous groups (0x00568EE4-0x00568F63)
   * and calls `Setup` to claim and script the layer's units -- then merges
   * overlapping groups for `Form*` commands and broadcasts
   * `FORMATIONSTATUS_FormationUpdated`.
   */
  void CFormationInstance::UpdateFormation()
  {
    gpg::fastvector_n<WeakPtr<IUnit>, 4> units{};
    float forwardXSum = 0.0f;
    float forwardZSum = 0.0f;

    for (WeakPtr<IUnit>& link : mUnits) {
      Unit* const unit = UnitOf(link);
      if (unit == nullptr || !unit->IsMobile() || unit->IsDead() || unit->IsBeingBuilt() || unit->DestroyQueued()) {
        continue;
      }

      if (!IsValidVector3f(unit->GetPosition())) {
        continue;
      }

      units.push_back(WeakPtr<IUnit>(unit));

      const Wm3::Vec3f forward = ForwardOf(unit->GetTransform().orient_);
      forwardXSum += forward.x;
      forwardZSum += forward.z;

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      std::int32_t footprintSize;
      if (blueprint->Physics.MotionType == RULEUMT_Air) {
        footprintSize = (static_cast<std::int32_t>(blueprint->mFootprint.mSizeX)
                        + static_cast<std::int32_t>(blueprint->mFootprint.mSizeZ)) / 2;
      } else {
        // 0x00568DC5: the ground path reads the blueprint footprint bytes at
        // +0xD8/+0xD9 off the IUnit::GetBlueprint result and keeps the larger
        // one. It never calls the sim-side Unit::GetMaxFootprintSize - the
        // participants here are IUnit bridges that, on the user side of the
        // formation preview, are UserUnits with no Entity blueprint, and that
        // call threw "Attempt to get footprint on nameless entity" out of
        // every right-click order.
        const auto sizeX = static_cast<std::int32_t>(blueprint->mFootprint.mSizeX);
        const auto sizeZ = static_cast<std::int32_t>(blueprint->mFootprint.mSizeZ);
        footprintSize = (sizeX > sizeZ) ? sizeX : sizeZ;
      }
      mMaxSize = std::max(mMaxSize, footprintSize);
    }

    if (units.empty()) {
      return;
    }

    const float unitCount = static_cast<float>(units.size());
    const float meanForwardX = (1.0f / unitCount) * forwardXSum;
    const float meanForwardZ = forwardZSum * (1.0f / unitCount);

    if (mOrientation != kZeroQuaternion) {
      const float delta = WrapAngle(HeadingOf(mOrientation) - std::atan2(meanForwardX, meanForwardZ));
      if (std::fabs(delta) < 1.8849558f) {
        mOrientationChange = YawQuaternion(delta);
      }
    }

    for (std::int32_t layer = 0; layer < kFormationLayerCount; ++layer) {
      mOffsetInfo[layer].ResetStorageToInline();
      Setup(units, layer);
    }

    if (CommandIsForm()) {
      MergeOverlappingOffsetInfos(*this);
    }

    mStatusListeners.BroadcastEvent(FORMATIONSTATUS_FormationUpdated);
  }

  /**
   * Address: 0x00569CB0 (FUN_00569CB0, Moho::CFormationInstance::GetFormationPosition)
   *
   * What it does:
   * Refreshes a pending plan, then answers with the unit's own position for
   * a dead unit, the cached slot for a unit already resolved this plan
   * (`mFormationPosCache`, `sub_56B7B0`), or otherwise the unit's slot
   * (`mCoords + mOffset`, plus the dynamic offset when enabled) passed
   * through `FindSlotFor` and cached (`sub_56B6C0`, the map's `operator[]`).
   * Units in no group resolve to their own position.
   */
  SCoordsVec2* CFormationInstance::GetFormationPosition(
    SCoordsVec2* const dest,
    Unit* const unit,
    SOffsetInfo* info
  )
  {
    RefreshFormationPlanIfRequested(*this);

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    SCoordsVec2 position{unitPos.x, unitPos.z};
    if (unit->IsDead()) {
      *dest = position;
      return dest;
    }

    const EntId entityId = unit->GetEntityId();
    if (const SCoordsVec2* const cached = mFormationPosCache.try_get(entityId)) {
      *dest = *cached;
      return dest;
    }

    if (info == nullptr) {
      if (!Contains(unit, false)) {
        *dest = position;
        return dest;
      }
      info = GetOffsetInfo(unit);
    }

    if (info != nullptr) {
      if (const SUnitOffsetInfo* const unitInfo = info->mUnitOffsets.try_get(entityId)) {
        SCoordsVec2 offset = unitInfo->mOffset;
        if (info->mUseDynamicOffset) {
          offset.x += info->mDynamicOffset.x;
          offset.z += info->mDynamicOffset.z;
        }

        const SCoordsVec2 requested{mCoords.x + offset.x, mCoords.z + offset.z};
        SCoordsVec2 slot{};
        FindSlotFor(&slot, &requested, unit);
        position = slot;
      }
    }

    mFormationPosCache[entityId] = position;
    *dest = position;
    return dest;
  }

  /**
   * Address: 0x00569EA0 (FUN_00569EA0, Moho::CFormationInstance::GetAdjustedFormationPosition)
   *
   * What it does:
   * Converts the unit's formation position to its footprint-origin cell
   * (`fistp`, round to nearest); a null or dead unit yields cell (0, 0).
   */
  SOCellPos* CFormationInstance::GetAdjustedFormationPosition(
    SOCellPos* const dest,
    Unit* const unit,
    SOffsetInfo* info
  )
  {
    dest->x = 0;
    dest->z = 0;
    if (unit != nullptr && !unit->IsDead()) {
      SCoordsVec2 position{};
      GetFormationPosition(&position, unit, info);

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      SOCellPos cell{};
      cell.x = static_cast<std::int16_t>(std::lrintf(position.x - static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f));
      cell.z = static_cast<std::int16_t>(std::lrintf(position.z - static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f));
      *dest = cell;
    }
    return dest;
  }

  /**
   * Address: 0x00569F70 (FUN_00569F70, Moho::CFormationInstance::GetOffsetPosition)
   *
   * What it does:
   * Refreshes a pending plan, then answers with the unit's own position for
   * a dead unit or a unit in no group, the cached value for a unit already
   * resolved this plan (`mOffsetPosCache`, `sub_56B7B0`), or otherwise the
   * raw slot `mCoords + mOffset` (plus the dynamic offset when enabled) for
   * a mobile unit and its own position for an immobile one, cached through
   * the map's `operator[]` (`sub_56B6C0`).
   */
  SCoordsVec2* CFormationInstance::GetOffsetPosition(SCoordsVec2* const dest, Unit* const unit, SOffsetInfo* info)
  {
    RefreshFormationPlanIfRequested(*this);

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    SCoordsVec2 position{unitPos.x, unitPos.z};
    if (unit->IsDead()) {
      *dest = position;
      return dest;
    }

    const EntId entityId = unit->GetEntityId();
    if (const SCoordsVec2* const cached = mOffsetPosCache.try_get(entityId)) {
      *dest = *cached;
      return dest;
    }

    if (info == nullptr) {
      *dest = position;
      return dest;
    }

    if (!unit->IsMobile()) {
      position = SCoordsVec2{unitPos.x, unitPos.z};
    } else if (const SUnitOffsetInfo* const unitInfo = info->mUnitOffsets.try_get(entityId)) {
      SCoordsVec2 offset = unitInfo->mOffset;
      if (info->mUseDynamicOffset) {
        offset.x += info->mDynamicOffset.x;
        offset.z += info->mDynamicOffset.z;
      }
      position = SCoordsVec2{mCoords.x + offset.x, mCoords.z + offset.z};
    }

    mOffsetPosCache[entityId] = position;
    *dest = position;
    return dest;
  }

  /**
   * Address: 0x0056A150 (FUN_0056A150, Moho::CFormationInstance::GetTargetPosition)
   *
   * What it does:
   * Zero for a null or dead unit; otherwise the unit's smoothed
   * `SUnitOffsetInfo::mTargetPos`, falling back to the unit's own position
   * while that is still zero or the unit has no slot in `info`.
   */
  Wm3::Vec3f* CFormationInstance::GetTargetPosition(Wm3::Vec3f* const out, Unit* const unit, SOffsetInfo* info)
  {
    if (unit == nullptr || unit->IsDead()) {
      *out = Wm3::Vec3f::ZERO;
      return out;
    }

    const SUnitOffsetInfo* const unitInfo = info != nullptr ? info->mUnitOffsets.try_get(unit->GetEntityId()) : nullptr;
    if (unitInfo == nullptr || unitInfo->mTargetPos == Wm3::Vec3f::ZERO) {
      *out = unit->GetPosition();
    } else {
      *out = unitInfo->mTargetPos;
    }
    return out;
  }

  /**
   * Address: 0x0056A220 (FUN_0056A220, Moho::CFormationInstance::AddUnit)
   *
   * What it does:
   * For a live unit: prunes dead links (`RemoveDeadUnits`, which also
   * reports whether the unit is already listed) and either warns about the
   * duplicate or appends a fresh link (the temporary `WeakPtr<IUnit>` at
   * 0x0056A26A pushed and destroyed) and flags the plan for a rebuild.
   */
  void CFormationInstance::AddUnit(Unit* const unit)
  {
    if (unit == nullptr || unit->IsDead()) {
      return;
    }

    if (RemoveDeadUnits(unit)) {
      gpg::Warnf(
        "Attempted to re-add existing unit (%d - %s) to formation (%d)",
        static_cast<int>(reinterpret_cast<std::uintptr_t>(unit)),
        unit->GetBlueprint()->mBlueprintId.c_str(),
        static_cast<int>(reinterpret_cast<std::uintptr_t>(this))
      );
      return;
    }

    mUnits.push_back(WeakPtr<IUnit>(unit));
    mPlanUpdate = 1u;
  }

  /**
   * Address: 0x0056A300 (FUN_0056A300, Moho::CFormationInstance::RemoveUnit)
   *
   * What it does:
   * Erases the unit from the first group of its layer that holds it
   * (`sub_56AC60`, the map's `erase(iterator)`), dropping that group's
   * cached leader when it was this unit, then erases the unit's link from
   * `mUnits` (`sub_5725A0` shift plus the tail unlink).
   */
  void CFormationInstance::RemoveUnit(Unit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    for (SOffsetInfo& info : mOffsetInfo[GetLayer(unit)]) {
      const auto it = info.mUnitOffsets.find(unit->GetEntityId());
      if (it == info.mUnitOffsets.end()) {
        continue;
      }

      (void)info.mUnitOffsets.erase(it);
      if (UnitOf(info.mLeader) == unit) {
        info.mLeader.UnlinkFromOwnerChain();
      }
      break;
    }

    for (auto it = mUnits.begin(); it != mUnits.end(); ++it) {
      if (UnitOf(*it) == unit) {
        (void)mUnits.erase(it);
        return;
      }
    }
  }

  /**
   * Address: 0x0056A440 (FUN_0056A440, Moho::CFormationInstance::Contains)
   *
   * What it does:
   * True when a group of the unit's layer holds its entity id, or -- with
   * `checkAll` -- when `mUnits` links it.
   */
  bool CFormationInstance::Contains(Unit* const unit, const bool checkAll) const
  {
    if (unit == nullptr) {
      return false;
    }

    for (const SOffsetInfo& info : mOffsetInfo[GetLayer(unit)]) {
      if (info.mUnitOffsets.find(unit->GetEntityId()) != info.mUnitOffsets.end()) {
        return true;
      }
    }

    if (!checkAll) {
      return false;
    }

    for (const WeakPtr<IUnit>& link : mUnits) {
      if (UnitOf(link) == unit) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x005691E0 (FUN_005691E0, Moho::CFormationInstance::RemoveDeadUnits)
   *
   * What it does:
   * Walks `mUnits`, erasing every null, dead or destroy-queued link in place
   * (`sub_5725A0` shift plus the tail unlink) and noting whether
   * `checkForUnit` was met among the survivors.
   */
  bool CFormationInstance::RemoveDeadUnits(Unit* const checkForUnit)
  {
    bool found = false;
    for (auto it = mUnits.begin(); it != mUnits.end();) {
      Unit* const unit = UnitOf(*it);
      if (unit == nullptr || unit->IsDead() || unit->DestroyQueued()) {
        it = mUnits.erase(it);
        continue;
      }

      if (checkForUnit != nullptr && checkForUnit == unit) {
        found = true;
      }
      ++it;
    }
    return found;
  }

  /**
   * Address: 0x00569B60 (FUN_00569B60, Moho::CFormationInstance::GetForwardVector)
   *
   * What it does:
   * The formation forward vector for a placed unit, zero otherwise.
   */
  Wm3::Vec3f* CFormationInstance::GetForwardVector(Wm3::Vec3f* const out, Unit* const unit) const
  {
    if (Contains(unit, false)) {
      *out = mForwardVector;
    } else {
      *out = Wm3::Vec3f::ZERO;
    }
    return out;
  }

  /**
   * Address: 0x00569C20 (FUN_00569C20, Moho::CFormationInstance::IsInFormation)
   *
   * What it does:
   * For a live, placed unit: its group's `mInFormation` flag (true when the
   * group lookup fails). Otherwise: whether every group of both layers is
   * in formation.
   */
  bool CFormationInstance::IsInFormation(Unit* const unit) const
  {
    if (unit != nullptr && !unit->IsDead() && Contains(unit, false)) {
      if (SOffsetInfo* const info = const_cast<CFormationInstance*>(this)->GetOffsetInfo(unit)) {
        return info->mInFormation;
      }
      return true;
    }

    for (std::int32_t layer = 0; layer < kFormationLayerCount; ++layer) {
      for (const SOffsetInfo& info : mOffsetInfo[layer]) {
        if (!info.mInFormation) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Address: 0x00569BF0 (FUN_00569BF0)
   *
   * What it does:
   * Returns true when current command type is one of the formation commands.
   */
  bool CFormationInstance::CommandIsForm() const
  {
    switch (mCommandType) {
    case EUnitCommandType::UNITCOMMAND_FormMove:
    case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
    case EUnitCommandType::UNITCOMMAND_FormPatrol:
    case EUnitCommandType::UNITCOMMAND_FormAttack:
    case EUnitCommandType::UNITCOMMAND_Guard:
      return true;
    default:
      return false;
    }
  }

  /**
   * Address: 0x0056A4F0 (FUN_0056A4F0, Moho::CFormationInstance::SetScale)
   *
   * What it does:
   * Stores a changed scale (the `ucomiss`/`lahf` pair at 0x0056A4FE is a
   * plain `!=`) and requests a plan rebuild.
   */
  void CFormationInstance::SetScale(const float scale)
  {
    if (mScale != scale) {
      mScale = scale;
      mPlanUpdate = 1u;
    }
  }

  /**
   * Address: 0x0056A520 (FUN_0056A520, Moho::CFormationInstance::SetOrientation)
   *
   * What it does:
   * Stores a changed orientation, derives the forward vector from it (zero
   * for a zero orientation or a plain `Move` command) and requests a plan
   * rebuild.
   */
  void CFormationInstance::SetOrientation(const Wm3::Quatf& orientation)
  {
    if (orientation == mOrientation) {
      return;
    }

    mOrientation = orientation;
    if (mOrientation == kZeroQuaternion || mCommandType == EUnitCommandType::UNITCOMMAND_Move) {
      mForwardVector = Wm3::Vec3f::ZERO;
    } else {
      mForwardVector = ForwardOf(mOrientation);
    }
    mPlanUpdate = 1u;
  }

  /**
   * Address: 0x0056A680 (FUN_0056A680)
   *
   * What it does:
   * Copies the current orientation into `outOrientation`.
   */
  Wm3::Quatf* CFormationInstance::GetOrientation(Wm3::Quatf* const outOrientation) const
  {
    *outOrientation = mOrientation;
    return outOrientation;
  }

  /**
   * Address: 0x00569A00 (FUN_00569A00)
   *
   * What it does:
   * Returns the active command type for this formation.
   */
  EUnitCommandType CFormationInstance::GetCommandType() const
  {
    return mCommandType;
  }

  /**
   * Address: 0x0059A790 (FUN_0059A790, Moho::CAiFormationInstance::GetDistFromLeader)
   *
   * What it does:
   * The unit's `SUnitOffsetInfo::mDistFromLeader` (node +0x38), zero when
   * `info` is null or has no slot for the unit.
   */
  float CAiFormationInstance::GetDistFromLeader(Unit* const unit, SOffsetInfo* const info)
  {
    if (info == nullptr) {
      return 0.0f;
    }

    const SUnitOffsetInfo* const unitInfo = info->mUnitOffsets.try_get(unit->GetEntityId());
    return unitInfo != nullptr ? unitInfo->mDistFromLeader : 0.0f;
  }

  /**
   * Address: 0x0059A7D0 (FUN_0059A7D0, Moho::CAiFormationInstance::GetPriority)
   *
   * What it does:
   * Priority 1 for a unit that is guarding something, has no group or no
   * slot, or a non-positive weight; otherwise `10 * (int)mWeight`, floored
   * at 1.
   */
  std::int32_t CAiFormationInstance::GetPriority(Unit* const unit, SOffsetInfo* info)
  {
    Unit* const runtimeUnit = unit->IsUnit();
    if (runtimeUnit == nullptr) {
      return 1;
    }
    if (runtimeUnit->GuardedUnitRef.AsWeakPtr<Unit>().HasValue()) {
      return 1;
    }

    if (info == nullptr) {
      info = GetOffsetInfo(unit);
      if (info == nullptr) {
        return 1;
      }
    }

    const SUnitOffsetInfo* const unitInfo = info->mUnitOffsets.try_get(unit->GetEntityId());
    if (unitInfo == nullptr || unitInfo->mWeight <= 0.0f) {
      return 1;
    }

    const std::int32_t priority = 10 * static_cast<std::int32_t>(unitInfo->mWeight);
    return priority > 1 ? priority : 1;
  }

  /**
   * Address: 0x0059A620 (FUN_0059A620, Moho::CAiFormationInstance::CalcFormationSpeed)
   *
   * What it does:
   * For `Form*` commands only: zero when the unit's leader is neither placed
   * nor mobile, when the unit's navigator ignores the formation, or when no
   * group is given. Otherwise the group's `mSpeed`, with `*speedScaleOut`
   * at 0.85 -- or, for a unit that follows its leader (or is the leader)
   * once the group has a positive `mAvgDistToTarget`, a scale derived from
   * how far the unit's `mDistToTarget` sits from that average (x4 on the
   * ground, x1.5 in the air, clamped to [-5, 20], then `0.1 * delta + 1`).
   */
  float CAiFormationInstance::CalcFormationSpeed(
    Unit* const unit,
    float* const speedScaleOut,
    SOffsetInfo* const info
  )
  {
    if (!CommandIsForm()) {
      return 0.0f;
    }

    Unit* const leader = GetLeader(unit, info);
    if (leader != nullptr) {
      if (!Contains(leader, false) && !leader->IsMobile()) {
        return 0.0f;
      }
    }

    if (unit->IsUnit()->AiNavigator->IsIgnoringFormation() || info == nullptr) {
      return 0.0f;
    }

    *speedScaleOut = 0.85f;
    const bool followsLeader = unit->IsUnit()->AiNavigator->FollowingLeader() || leader == unit;
    if (info->mAvgDistToTarget > 0.0f && followsLeader) {
      if (const SUnitOffsetInfo* const unitInfo = info->mUnitOffsets.try_get(unit->GetEntityId())) {
        const float distFactor = (unit->GetBlueprint()->Air.CanFly != 0u) ? 1.5f : 4.0f;
        float delta = (unitInfo->mDistToTarget - info->mAvgDistToTarget) * distFactor;
        if (delta >= 20.0f) {
          delta = 20.0f;
        }
        if (delta < -5.0f) {
          delta = -5.0f;
        }
        *speedScaleOut = (delta * 0.1f) + 1.0f;
      }
    }

    return info->mSpeed;
  }

  /**
   * Address: 0x0059A870 (FUN_0059A870, Moho::CAiFormationInstance::GetLeader)
   *
   * What it does:
   * For guard commands, the unit the queried unit is guarding. Otherwise
   * null without a group or for a dead unit, else the group's leader --
   * with an air group following the first overlapping ground group's
   * leader instead (`ResolveGroupLeader`).
   */
  Unit* CAiFormationInstance::GetLeader(Unit* const unit, SOffsetInfo* const info)
  {
    if (mCommandType == EUnitCommandType::UNITCOMMAND_Guard && unit->IsUnit() != nullptr) {
      return unit->IsUnit()->GuardedUnitRef.ResolveObjectPtr<Unit>();
    }

    if (info == nullptr || unit->IsDead()) {
      return nullptr;
    }

    return ResolveGroupLeader(*this, GetLayer(unit), *info);
  }

  /**
   * Address: 0x0059AE80 (FUN_0059AE80, Moho::CAiFormationInstance::Update)
   *
   * What it does:
   * Refreshes a pending plan, then for `Form*`/guard formations with units
   * drives every group of both layers:
   *  - resolves the group's driving leader (`GetOffsetInfoLeader`) and the
   *    leader's goal: its own position (guard), the world position of its
   *    formation cell (air), or its navigator's current target while it is
   *    steering (ground) -- yielding a look-ahead vector from the leader
   *    towards that goal, clamped to 20;
   *  - measures how far the leader sits from its own formation cell, the
   *    mean formation cell of the group's units and the largest leader-to-
   *    unit distance;
   *  - for every unit: a unit whose navigator ignores the formation only
   *    gets its distance measured; a unit whose leader is within five cells
   *    of its own slot (and not guarding) steers straight for the world
   *    position of its formation cell; otherwise the slot offset is rotated
   *    by a heading correction blended from the leader's heading error, and
   *    the target is the leader's position plus that offset plus the
   *    look-ahead, smoothed 1:9 into `mTargetPos`. Every unit's
   *    `mDistToTarget` and `mDistFromLeader` are refreshed;
   *  - stores the midpoint of the extreme unit distances as
   *    `mAvgDistToTarget`;
   *  - finally checks the group's arrival: a refueling unit vetoes it, each
   *    unit that must be checked (every ground unit of a non-top-speed
   *    group, else the leader alone) has to sit within the group's
   *    threshold of its formation position and either have a busy follow-up
   *    command queued or face along the formation forward vector; when the
   *    check passes, `mInFormation` is raised and
   *    `FORMATIONSTATUS_FormationAtGoal` broadcast.
   */
  void CAiFormationInstance::Update()
  {
    RefreshFormationPlanIfRequested(*this);

    if (!CommandIsForm() || UnitCount() == 0) {
      return;
    }

    const STIMap* const mapData = mSim->mMapData;
    for (std::int32_t layer = 0; layer < kFormationLayerCount; ++layer) {
      for (SOffsetInfo& group : mOffsetInfo[layer]) {
        Unit* const leader = GetOffsetInfoLeader(layer, *this, group);
        if (leader == nullptr) {
          continue;
        }

        const std::size_t unitCount = group.mUnitOffsets.size();
        group.mAvgDistToTarget = 0.0f;
        if (unitCount == 0u) {
          continue;
        }

        float minDistToTarget = mCommandType == EUnitCommandType::UNITCOMMAND_Guard
          ? 0.0f
          : std::numeric_limits<float>::infinity();
        float maxDistToTarget = 0.0f;

        // The leader's goal (0x0059AEF6-0x0059B033, air tail at 0x0059B5B7).
        const RUnitBlueprint* const leaderBlueprint = leader->GetBlueprint();
        Wm3::Vec3f leaderGoal = leader->GetPosition();
        if (mCommandType == EUnitCommandType::UNITCOMMAND_Guard) {
          leaderGoal = leader->GetPosition();
        } else if (leaderBlueprint->Air.CanFly) {
          SOCellPos leaderCell{};
          GetAdjustedFormationPosition(&leaderCell, leader, &group);
          leaderGoal = COORDS_ToWorldPos(
            mapData,
            leaderCell,
            static_cast<ELayer>(leaderBlueprint->mFootprint.mOccupancyCaps),
            leaderBlueprint->mFootprint.mSizeX,
            leaderBlueprint->mFootprint.mSizeZ
          );
        } else if (leader->IsUnit()->AiNavigator->GetStatus() == AINAVSTATUS_Steering) {
          leaderGoal = leader->IsUnit()->AiNavigator->GetCurrentTargetPos();
        }

        // Look-ahead from the leader towards its goal, at most 20 long.
        const Wm3::Vec3f& leaderPos = leader->GetPosition();
        Wm3::Vec3f lookAhead{leaderGoal.x - leaderPos.x, 0.0f, leaderGoal.z - leaderPos.z};
        const float goalDistance = std::sqrt(lookAhead.z * lookAhead.z + lookAhead.x * lookAhead.x);
        if (goalDistance > 0.0f) {
          const float clamped = goalDistance < 20.0f ? goalDistance : 20.0f;
          const float invDistance = 1.0f / goalDistance;
          lookAhead = Wm3::Vec3f{
            clamped * (lookAhead.x * invDistance), (invDistance * 0.0f) * clamped, (lookAhead.z * invDistance) * clamped
          };
        }

        // How far the leader stands from its own formation cell, in cells.
        const std::int16_t leaderOriginX = static_cast<std::int16_t>(
          std::lrintf(leaderPos.x - static_cast<float>(leaderBlueprint->mFootprint.mSizeX) * 0.5f)
        );
        const std::int16_t leaderOriginZ = static_cast<std::int16_t>(
          std::lrintf(leaderPos.z - static_cast<float>(leaderBlueprint->mFootprint.mSizeZ) * 0.5f)
        );
        SOCellPos leaderFormationCell{};
        GetAdjustedFormationPosition(&leaderFormationCell, leader, &group);
        const std::int16_t leaderCellDx = static_cast<std::int16_t>(leaderFormationCell.x - leaderOriginX);
        const std::int16_t leaderCellDz = static_cast<std::int16_t>(leaderFormationCell.z - leaderOriginZ);

        // Mean formation cell and the largest leader-to-unit distance.
        float maxLeaderDistance = 0.001f;
        SCoordsVec2 cellSum{0.0f, 0.0f};
        for (auto& [entityId, unitInfo] : group.mUnitOffsets) {
          Unit* const unit = UnitOf(unitInfo.mUnit);
          if (unit == nullptr) {
            continue;
          }

          const float leaderDistance = FlatDistance(unit->GetPosition(), leader->GetPosition());
          if (leaderDistance > maxLeaderDistance) {
            maxLeaderDistance = leaderDistance;
          }

          SOCellPos cell{};
          GetAdjustedFormationPosition(&cell, unit, &group);
          cellSum.x += static_cast<float>(cell.x);
          cellSum.z += static_cast<float>(cell.z);
        }
        const float invUnitCount = 1.0f / static_cast<float>(static_cast<int>(unitCount));
        cellSum.x = invUnitCount * cellSum.x;
        cellSum.z = invUnitCount * cellSum.z;

        SCoordsVec2 groupCenter = cellSum;
        if (mCommandType != EUnitCommandType::UNITCOMMAND_Guard) {
          GetOffsetPosition(&groupCenter, leader, &group);
        }

        // Per-unit targets and distances (0x0059B1DE-0x0059B5A3).
        for (auto& [entityId, unitInfo] : group.mUnitOffsets) {
          Unit* const unit = UnitOf(unitInfo.mUnit);
          if (unit == nullptr) {
            continue;
          }

          const RUnitBlueprint* const blueprint = unit->GetBlueprint();
          SCoordsVec2 target{};
          if (unit->IsUnit()->AiNavigator->IsIgnoringFormation()) {
            SCoordsVec2 formationPos{};
            GetFormationPosition(&formationPos, unit, &group);
            (void)mapData->mHeightField->GetElevation(formationPos.x, formationPos.z);
            target = formationPos;
          } else {
            const float distToLeader = FlatDistance(unit->GetPosition(), leader->GetPosition());
            const bool leaderOffSlot = std::sqrt(
                                         static_cast<double>(leaderCellDx) * static_cast<double>(leaderCellDx)
                                         + static_cast<double>(leaderCellDz) * static_cast<double>(leaderCellDz)
                                       ) >= 5.0;
            if (leaderOffSlot || mCommandType == EUnitCommandType::UNITCOMMAND_Guard) {
              SCoordsVec2 offsetPos{};
              GetOffsetPosition(&offsetPos, unit, &group);
              Wm3::Vec3f relative{offsetPos.x - groupCenter.x, 0.0f, offsetPos.z - groupCenter.z};

              float heading = 0.0f;
              if (unitInfo.mHeadingAngle != std::numeric_limits<float>::infinity()) {
                const float leaderHeading = HeadingOf(leader->GetTransform().orient_);
                const float headingError = WrapAngle(leaderHeading - std::atan2(mForwardVector.x, mForwardVector.z));
                const float blend = (distToLeader / maxLeaderDistance) * 0.050000001f + 0.94f;
                heading = (1.0f - blend) * headingError + unitInfo.mHeadingAngle * blend;
              }

              const Wm3::Quatf correction = YawQuaternion(heading);
              Wm3::Vec3f rotated{};
              (void)MultQuadVec(&rotated, &relative, &correction);
              relative = Wm3::Vec3f{rotated.x, 0.0f, rotated.z};

              const Wm3::Vec3f& lp = leader->GetPosition();
              const Wm3::Vec3f goal{
                (lp.x + relative.x) + lookAhead.x, lp.y + lookAhead.y, (lp.z + relative.z) + lookAhead.z
              };
              target = SCoordsVec2{goal.x, goal.z};

              if (unitInfo.mTargetPos != Wm3::Vec3f::ZERO) {
                unitInfo.mTargetPos = Wm3::Vec3f{
                  goal.x * 0.1f + unitInfo.mTargetPos.x * 0.89999998f,
                  goal.y * 0.1f + unitInfo.mTargetPos.y * 0.89999998f,
                  goal.z * 0.1f + unitInfo.mTargetPos.z * 0.89999998f,
                };
              } else {
                unitInfo.mTargetPos = goal;
              }
              unitInfo.mHeadingAngle = heading;
            } else {
              SOCellPos cell{};
              GetAdjustedFormationPosition(&cell, unit, &group);
              const Wm3::Vec3f world = COORDS_ToWorldPos(
                mapData,
                cell,
                static_cast<ELayer>(blueprint->mFootprint.mOccupancyCaps),
                blueprint->mFootprint.mSizeX,
                blueprint->mFootprint.mSizeZ
              );
              unitInfo.mTargetPos = world;
              target = SCoordsVec2{world.x, world.z};
              unitInfo.mHeadingAngle = std::numeric_limits<float>::infinity();
            }
          }

          const Wm3::Vec3f& unitPos = unit->GetPosition();
          const float distToTarget =
            std::sqrt((unitPos.x - target.x) * (unitPos.x - target.x) + (unitPos.z - target.z) * (unitPos.z - target.z));
          unitInfo.mDistToTarget = distToTarget;
          if (distToTarget <= minDistToTarget) {
            minDistToTarget = distToTarget;
          }
          if (distToTarget > maxDistToTarget) {
            maxDistToTarget = distToTarget;
          }

          SCoordsVec2 offsetPos{};
          GetOffsetPosition(&offsetPos, unit, &group);
          const double dx = static_cast<double>(groupCenter.x) - static_cast<double>(offsetPos.x);
          const double dz = static_cast<double>(groupCenter.z) - static_cast<double>(offsetPos.z);
          unitInfo.mDistFromLeader = static_cast<float>(std::sqrt(dx * dx + dz * dz));
        }

        group.mAvgDistToTarget = (maxDistToTarget + minDistToTarget) * 0.5f;

        // Arrival check (0x0059B5FD-0x0059B7A5).
        Unit* const groupLeader = group.GetLeader();
        const bool alwaysTopSpeed = groupLeader->IsUnit()->UnitMotion->mAlwaysUseTopSpeed;
        float arrivalThreshold = static_cast<float>(mMaxSize) * 2.0f;
        const float speedThreshold = group.mSpeed * (alwaysTopSpeed ? 0.67000002f : 0.25f);
        if (speedThreshold > arrivalThreshold) {
          arrivalThreshold = speedThreshold;
        }

        bool inFormation = true;
        for (auto& [entityId, unitInfo] : group.mUnitOffsets) {
          Unit* const unit = UnitOf(unitInfo.mUnit);
          if (unit == nullptr) {
            continue;
          }

          if (unit->IsUnitState(UNITSTATE_Refueling)) {
            inFormation = false;
            break;
          }

          if (!alwaysTopSpeed && (!CommandIsForm() || !unit->IsUnit()->mIsAir)) {
            if (unit->IsUnit()->AiNavigator->IsIgnoringFormation()) {
              continue;
            }
          } else if (groupLeader != unit) {
            continue;
          }

          (void)unit->GetBlueprint();
          SCoordsVec2 formationPos{};
          GetFormationPosition(&formationPos, unit, &group);
          (void)mapData->mHeightField->GetElevation(formationPos.x, formationPos.z);
          const Wm3::Vec3f& unitPos = unit->GetPosition();
          const float distance = std::sqrt(
            (unitPos.z - formationPos.z) * (unitPos.z - formationPos.z)
            + (unitPos.x - formationPos.x) * (unitPos.x - formationPos.x)
          );
          if (distance > arrivalThreshold) {
            inFormation = false;
            break;
          }

          const CUnitCommandQueue* const queue = unit->IsUnit()->CommandQueue;
          const CUnitCommand* const nextCommand = queue->mCommandVec.size() >= 2u
            ? queue->mCommandVec[1].GetObjectPtr()
            : nullptr;
          if (nextCommand != nullptr && IsSpeedThroughBusyCommandType(nextCommand->mVarDat.mCmdType)) {
            continue;
          }

          if (mForwardVector != Wm3::Vec3f::ZERO) {
            const Wm3::Quatf& q = unit->GetTransform().orient_;
            const float facing = mForwardVector.z * (1.0f - (q.y * q.y + q.x * q.x) * 2.0f)
              + mForwardVector.y * ((q.z * q.y - q.w * q.x) * 2.0f)
              + ((q.w * q.y + q.z * q.x) * 2.0f) * mForwardVector.x;
            if (facing < 0.94999999f) {
              inFormation = false;
              break;
            }
          }
        }

        if (inFormation) {
          group.mInFormation = true;
          mStatusListeners.BroadcastEvent(FORMATIONSTATUS_FormationAtGoal);
        }
      }
    }
  }

  /**
   * Address: 0x0059AA20 (FUN_0059AA20, Moho::CAiFormationInstance::FindSlotFor)
   *
   * What it does:
   * Hands `pos` straight back for units that cannot take a grid slot (no
   * runtime unit, dead, no command queue, guard formations, a scale below
   * one, or the air layer). Otherwise reserves `pos` itself when it is free
   * (`FormationSlotIsFree`), else the first free cell of an expanding
   * square spiral around it (ring by ring, at most 2000 probes, each
   * ring's inner rows sampled only at their two ends). When the spiral
   * finds nothing, a busy follow-up command keeps `pos` (without reserving
   * it), and anything else falls back to the unit's own position.
   */
  SCoordsVec2* CAiFormationInstance::FindSlotFor(SCoordsVec2* const dest, const SCoordsVec2* const pos, Unit* const unit)
  {
    Unit* const runtimeUnit = unit->IsUnit();
    std::int32_t layer = 0;
    if (runtimeUnit == nullptr || runtimeUnit->IsDead() || runtimeUnit->CommandQueue == nullptr
        || mCommandType == EUnitCommandType::UNITCOMMAND_Guard || mScale < 1.0f
        || (layer = GetLayer(unit)) == kAirFormationLayer) {
      *dest = *pos;
      return dest;
    }

    const SFootprint footprint = unit->GetBlueprint()->mFootprint;
    const std::int32_t maxSize = std::max<std::int32_t>(footprint.mSizeX, footprint.mSizeZ);
    const bool useWholeMap = runtimeUnit->ArmyRef->UseWholeMap();

    if (FormationSlotIsFree(*this, *pos, footprint, maxSize, useWholeMap, layer, runtimeUnit)) {
      mSlots.push_back(SAssignedLocInfo(*pos, maxSize, layer));
      *dest = *pos;
      return dest;
    }

    std::int32_t attempts = 0;
    for (std::int32_t radius = 1; attempts < 2000; ++radius) {
      for (std::int32_t dx = -radius; dx <= radius; ++dx) {
        const std::int32_t step = (dx == -radius || dx == radius) ? 1 : radius * 2;
        for (std::int32_t dz = -radius; dz <= radius; dz += step) {
          ++attempts;
          const SCoordsVec2 candidate{static_cast<float>(dx) + pos->x, static_cast<float>(dz) + pos->z};
          if (!FormationSlotIsFree(*this, candidate, footprint, maxSize, useWholeMap, layer, runtimeUnit)) {
            continue;
          }

          mSlots.push_back(SAssignedLocInfo(candidate, maxSize, layer));
          *dest = candidate;
          return dest;
        }
      }
    }

    if (const CUnitCommand* const nextCommand = runtimeUnit->CommandQueue->GetNextCommand();
        nextCommand != nullptr && IsSpeedThroughBusyCommandType(nextCommand->mVarDat.mCmdType)) {
      *dest = *pos;
      return dest;
    }

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    dest->x = unitPos.x;
    dest->z = unitPos.z;
    return dest;
  }

  /**
   * Address: 0x0059A570 (FUN_0059A570, Moho::CAiFormationInstance::PosIsFree)
   *
   * What it does:
   * True when no assigned slot of `layer` lies within `max(slot size, size)`
   * of `position` on both axes.
   */
  bool CAiFormationInstance::PosIsFree(
    const SCoordsVec2& position,
    const std::int32_t size,
    const std::int32_t layer
  ) const
  {
    for (const SAssignedLocInfo& slot : mSlots) {
      if (layer != slot.mLayer) {
        continue;
      }

      const float dx = std::fabs(position.x - slot.mPos.x);
      const std::int32_t spacing = slot.mSize < size ? size : slot.mSize;
      if (static_cast<float>(spacing) > dx) {
        const float dz = std::fabs(position.z - slot.mPos.z);
        if (static_cast<float>(spacing) > dz) {
          return false;
        }
      }
    }

    return true;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SUnitOffsetInfoTypeInfo_12dfcf, moho::preregister_SUnitOffsetInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_SAssignedLocInfoTypeInfo_12dfcf, moho::preregister_SAssignedLocInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_IFormationInstanceTypeInfo_12dfcf, moho::preregister_IFormationInstanceTypeInfo)
GPG_PREREGISTER_INIT(preregister_RMapType_EntId_SUnitOffsetInfo_12dfcf, moho::preregister_RMapType_EntId_SUnitOffsetInfo)
GPG_PREREGISTER_INIT(preregister_RBroadcasterRType_EFormationdStatus_12dfcf, moho::preregister_RBroadcasterRType_EFormationdStatus)
GPG_PREREGISTER_INIT(preregister_RListenerRType_EFormationdStatus_12dfcf, moho::preregister_RListenerRType_EFormationdStatus)
GPG_PREREGISTER_INIT(preregister_RMapType_EntId_SCoordsVec2_12dfcf, moho::preregister_RMapType_EntId_SCoordsVec2)
