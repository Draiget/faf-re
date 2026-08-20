#include "moho/command/SSTITarget.h"

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  class EntIdTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "EntId";
    }

    void Init() override
    {
      size_ = sizeof(std::int32_t);
      gpg::RType::Init();
      Finish();
    }
  };

  class SSTITargetTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTITarget";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTITarget);
      gpg::RType::Init();
      Finish();
    }
  };

  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes, matching every other SerHelperBase-derived serializer in
  // this codebase); `gpg::SerSaveLoadHelperListRuntime` only models the
  // leading 0x0C-byte intrusive-list header shared by all of them.
  struct SSTITargetSerializerHelperNode
  {
    gpg::SerSaveLoadHelperListRuntime mListLinks{};
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(SSTITargetSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SSTITargetSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTITargetSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SSTITargetSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SSTITargetSerializerHelperNode) == 0x14,
    "SSTITargetSerializerHelperNode size must be 0x14"
  );

  SSTITargetSerializerHelperNode gSSTITargetSerializer{};

  /**
   * Address: 0x0055B170 (FUN_0055B170, SerSaveLoadHelper<SSTITarget>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTITarget` serializer helper links and restores self-links for
   * intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSSTITargetSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTITargetSerializer.mListLinks);
  }

  /**
   * Address: 0x0055B1A0 (FUN_0055B1A0, SerSaveLoadHelper<SSTITarget>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the `SSTITarget` serializer
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTITargetSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTITargetSerializer.mListLinks);
  }

  /**
   * Address: 0x0055B120 (FUN_0055B120, Moho::SSTITargetSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SSTITarget`. Forwards the
   * reflected object pointer to `SSTITarget::MemberDeserialize`
   * (FUN_0055B3A0 body); `version` and the owner-ref lane are unused by the
   * member (mirrors the binary tail call).
   */
  void DeserializeSSTITargetSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const target = reinterpret_cast<moho::SSTITarget*>(objectPtr);
    if (target == nullptr) {
      return;
    }
    target->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0055B130 (FUN_0055B130, Moho::SSTITargetSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SSTITarget`. Forwards the
   * reflected object pointer to `SSTITarget::MemberSerialize`
   * (FUN_0055B460 body); `version` and the owner-ref lane are unused by the
   * member (mirrors the binary tail call).
   */
  void SerializeSSTITargetSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const target = reinterpret_cast<const moho::SSTITarget*>(objectPtr);
    if (target == nullptr) {
      return;
    }
    target->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF5170 (FUN_00BF5170, Moho::SSTITargetSerializer::~SSTITargetSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `SSTITargetSerializer` helper node,
   * matching the sibling unlink lanes used across other serializer
   * registrars.
   */
  void cleanup_SSTITargetSerializer_atexit()
  {
    (void)UnlinkSSTITargetSerializerLaneA();
  }

  /**
   * Address: 0x00BCA310 (FUN_00BCA310, register_SSTITargetSerializer)
   *
   * What it does:
   * Initializes the global `SSTITarget` serializer helper's load/save
   * callback lanes (self-linking the intrusive helper node) and installs
   * process-exit cleanup via `atexit`.
   */
  void register_SSTITargetSerializer()
  {
    (void)UnlinkSSTITargetSerializerLaneA();
    gSSTITargetSerializer.mSerLoadFunc = &DeserializeSSTITargetSerializerCallback;
    gSSTITargetSerializer.mSerSaveFunc = &SerializeSSTITargetSerializerCallback;
    (void)std::atexit(&cleanup_SSTITargetSerializer_atexit);
  }

  struct SSTITargetSerializerStartupBootstrap
  {
    SSTITargetSerializerStartupBootstrap()
    {
      register_SSTITargetSerializer();
    }
  };

  [[maybe_unused]] SSTITargetSerializerStartupBootstrap gSSTITargetSerializerStartupBootstrap;

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

  [[nodiscard]] gpg::RType* ResolveTargetType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = ResolveTypeByAnyName(
        {"ESTITargetType", "Moho::ESTITargetType", "EAiTargetType", "Moho::EAiTargetType"}
      );
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::EAiTargetType));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (sType == nullptr) {
        sType = moho::preregister_EntIdTypeInfo();
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(Wm3::Vec3f));
    }
    return sType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00557DB0 (FUN_00557DB0, preregister_EntIdTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntId`.
   */
  gpg::RType* preregister_EntIdTypeInfo()
  {
    static EntIdTypeInfo typeInfo;
    // 0x00557DE4 pushes `??_R0?AVEntId@Moho@@@8` — the descriptor for the
    // *class* `Moho::EntId`, which is a different `type_info` from `int`'s.
    // Keying this on `typeid(std::int32_t)` instead made it race `intTypeInfo`
    // (RIntegerTypes.cpp) for the one `typeid(int)` slot in the first-wins
    // preregistration map, and win it: every reflected `int` field in the
    // engine then resolved to this descriptor, which has no `SetLexical`, so
    // `SCR_LuaBuildObject` rejected every integer blueprint value with
    // "Invalid value for EntId at 0x…" and left the field at its default.
    gpg::PreRegisterRType(typeid(EntIdValue), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0055AFE0 (FUN_0055AFE0, preregister_SSTITargetTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTITarget`.
   */
  gpg::RType* preregister_SSTITargetTypeInfo()
  {
    static SSTITargetTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTITarget), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0055B3A0 (FUN_0055B3A0, Moho::SSTITarget::MemberDeserialize)
   *
   * What it does:
   * Reads target-kind enum, then conditionally deserializes either entity-id
   * payload or ground-position payload.
   */
  void SSTITarget::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RType* const targetType = ResolveTargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Read(targetType, &mType, nullOwner);

    if (mType == EAiTargetType::AITARGET_Entity) {
      gpg::RType* const entIdType = ResolveEntIdType();
      GPG_ASSERT(entIdType != nullptr);
      archive->Read(entIdType, &mEntityId, nullOwner);
      return;
    }

    if (mType == EAiTargetType::AITARGET_Ground) {
      gpg::RType* const vec3Type = ResolveVector3fType();
      GPG_ASSERT(vec3Type != nullptr);
      archive->Read(vec3Type, &mPos, nullOwner);
    }
  }

  /**
   * Address: 0x0055B460 (FUN_0055B460, Moho::SSTITarget::MemberSerialize)
   *
   * What it does:
   * Writes target-kind enum, then conditionally serializes either entity-id
   * payload or ground-position payload.
   */
  void SSTITarget::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RType* const targetType = ResolveTargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Write(targetType, &mType, nullOwner);

    if (mType == EAiTargetType::AITARGET_Entity) {
      gpg::RType* const entIdType = ResolveEntIdType();
      GPG_ASSERT(entIdType != nullptr);
      archive->Write(entIdType, &mEntityId, nullOwner);
      return;
    }

    if (mType == EAiTargetType::AITARGET_Ground) {
      gpg::RType* const vec3Type = ResolveVector3fType();
      GPG_ASSERT(vec3Type != nullptr);
      archive->Write(vec3Type, &mPos, nullOwner);
    }
  }
} // namespace moho

namespace
{
  struct SSTITargetTypeInfoBootstrap
  {
    SSTITargetTypeInfoBootstrap()
    {
      (void)moho::preregister_EntIdTypeInfo();
      (void)moho::preregister_SSTITargetTypeInfo();
    }
  };

  [[maybe_unused]] SSTITargetTypeInfoBootstrap gSSTITargetTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EntIdTypeInfo_dd3051, moho::preregister_EntIdTypeInfo)
GPG_PREREGISTER_INIT(preregister_SSTITargetTypeInfo_dd3051, moho::preregister_SSTITargetTypeInfo)
