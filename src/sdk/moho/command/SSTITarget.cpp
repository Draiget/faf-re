#include "moho/command/SSTITarget.h"

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
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

  // Forward declarations: SSTITargetSerializer's constructor below binds
  // these as its load/save callback pointers; their bodies are defined
  // further down in this same anonymous namespace.
  void DeserializeSSTITargetSerializerCallback(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  void SerializeSSTITargetSerializerCallback(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);

  [[nodiscard]] gpg::RType* CachedSSTITargetType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::SSTITarget));
    }
    return cached;
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

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTITarget>`, vtable 0x00E18080.
   *
   * Address: 0x00BCA310 (FUN_00BCA310 -- constructs the global and registers its destructor.)
   * Address: 0x00BF5170 (FUN_00BF5170 -- the global's destructor.)
   * Address: 0x0055B2A0 (FUN_0055B2A0 -- `Init`.)
   * Address: 0x0055B120 (FUN_0055B120 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055B130 (FUN_0055B130 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SSTITargetSerializer : gpg::SerSaveLoadHelper<SSTITarget>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ACA0C -- process-global `SSTITargetSerializer` singleton.
  moho::SSTITargetSerializer gSSTITargetSerializer;
} // namespace
