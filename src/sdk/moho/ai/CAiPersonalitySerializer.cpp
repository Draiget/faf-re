#include "moho/ai/CAiPersonalitySerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPersonality.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  using SValuePair = moho::SAiPersonalityRange;

  /**
   * VFTABLE: 0x00E1CA88
   * COL:  0x00E72A48
   */
  class SValuePairTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005B6670 (FUN_005B6670, Moho::SValuePairTypeInfo::dtr)
     *
     * What it does:
     * Tears down one `SValuePair` reflection type-info object and releases
     * inherited `gpg::RType` field/base vector storage.
     */
    ~SValuePairTypeInfo() override;

    /**
     * Address: 0x005B6660 (FUN_005B6660, Moho::SValuePairTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      return "SValuePair";
    }

    /**
     * Address: 0x005B6640 (FUN_005B6640, Moho::SValuePairTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(SValuePair);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(SValuePairTypeInfo) == 0x64, "SValuePairTypeInfo size must be 0x64");

  /**
   * Address: 0x005B6670 (FUN_005B6670, Moho::SValuePairTypeInfo::dtr)
   *
   * What it does:
   * Tears down one `SValuePair` reflection type-info object and releases
   * inherited `gpg::RType` field/base vector storage.
   */
  SValuePairTypeInfo::~SValuePairTypeInfo() = default;

  /**
   * VFTABLE: 0x00E1CA80
   * COL:  0x00E729FC
   *
   * Same `gpg::SerHelperBase` defect family as `CAiPersonalitySerializer`
   * (see that class's own doc comments): raw disassembly for FUN_00BCD5C0
   * (register_SValuePairSerializer) calls
   * `gpg::SerHelperBase::SerHelperBase()` directly, sets the load/save
   * callback fields, installs `??_7SValuePairSerializer@Moho@@6B@`, and
   * pushes the real `~SValuePairSerializer` (0x00BF7640) as the `atexit`
   * target -- no eager `Init()` call exists in the real body.
   */
  class SValuePairSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCD5C0 (FUN_00BCD5C0, dynamic initializer for the global
     * `SValuePairSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields.
     */
    SValuePairSerializer();

    /**
     * Address: 0x00BF7640 (FUN_00BF7640, Moho::SValuePairSerializer::~SValuePairSerializer)
     * Address: 0x005B67B0 (FUN_005B67B0), Address: 0x005B67E0 (FUN_005B67E0)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCD5C0) as the global's `atexit` teardown.
     */
    ~SValuePairSerializer();

    /**
     * Address: 0x005B6720 (FUN_005B6720, Moho::SValuePairSerializer::Deserialize)
     *
     * What it does:
     * Loads both `float` lanes of one `SValuePair`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B6750 (FUN_005B6750, Moho::SValuePairSerializer::Serialize)
     *
     * What it does:
     * Saves both `float` lanes of one `SValuePair`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B6770 (FUN_005B6770, serializer callback binder lane)
     *
     * What it does:
     * Binds `SValuePair` load/save callbacks into the reflected type
     * descriptor. Dispatched by `gpg::SerHelperBase::InitNewHelpers` when
     * this helper is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };
  static_assert(offsetof(SValuePairSerializer, mDeserialize) == 0x0C, "SValuePairSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SValuePairSerializer, mSerialize) == 0x10, "SValuePairSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SValuePairSerializer) == 0x14, "SValuePairSerializer size must be 0x14");

  alignas(SValuePairTypeInfo) unsigned char gSValuePairTypeInfoStorage[sizeof(SValuePairTypeInfo)];
  bool gSValuePairTypeInfoConstructed = false;

  /**
   * Address: 0x005B95F0 (FUN_005B95F0, j_Moho::CAiPersonality::MemberSerialize)
   * Address: 0x0087CF70 (FUN_0087CF70)
   *
   * What it does:
   * Thin forwarding thunk to `CAiPersonality::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPersonalityMemberSerializeThunk(
    moho::CAiPersonality* const personality, gpg::WriteArchive* const archive
  )
  {
    if (!personality) {
      return;
    }

    personality->MemberSerialize(archive);
  }

  /**
   * Address: 0x005B9660 (FUN_005B9660, j_Moho::CAiPersonality::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiPersonality::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPersonalityMemberSerializeThunkSecondary(
    moho::CAiPersonality* const personality, gpg::WriteArchive* const archive
  )
  {
    if (!personality) {
      return;
    }

    personality->MemberSerialize(archive);
  }

  [[nodiscard]] SValuePairTypeInfo* AcquireSValuePairTypeInfo()
  {
    if (!gSValuePairTypeInfoConstructed) {
      new (gSValuePairTypeInfoStorage) SValuePairTypeInfo();
      gSValuePairTypeInfoConstructed = true;
    }

    return reinterpret_cast<SValuePairTypeInfo*>(gSValuePairTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedSValuePairType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SValuePair));
    }
    return cached;
  }

  /**
   * Address: 0x005B65E0 (FUN_005B65E0, preregister_SValuePairTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI for `SValuePair`.
   */
  [[nodiscard]] gpg::RType* preregister_SValuePairTypeInfo()
  {
    SValuePairTypeInfo* const typeInfo = AcquireSValuePairTypeInfo();
    gpg::PreRegisterRType(typeid(SValuePair), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF7620 (FUN_00BF7620, cleanup_SValuePairTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SValuePair` reflection type descriptor.
   */
  void cleanup_SValuePairTypeInfo()
  {
    if (!gSValuePairTypeInfoConstructed) {
      return;
    }

    AcquireSValuePairTypeInfo()->~SValuePairTypeInfo();
    gSValuePairTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCAiPersonalityType()
  {
    gpg::RType* type = CAiPersonality::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPersonality));
      CAiPersonality::sType = type;
    }
    return type;
  }

  // Address: 0x010AF168 -- process-global `SValuePairSerializer` singleton.
  // Constructing it runs SValuePairSerializer::SValuePairSerializer()
  // (0x00BCD5C0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SValuePairSerializer,
  // 0x00BF7640) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  SValuePairSerializer gSValuePairSerializer;

  // Address: 0x010AF154 -- process-global `CAiPersonalitySerializer`
  // singleton. Constructing it runs CAiPersonalitySerializer::
  // CAiPersonalitySerializer() (0x00BCD660), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiPersonalitySerializer,
  // 0x00BF7740) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiPersonalitySerializer gCAiPersonalitySerializer;
} // namespace

/**
 * Address: 0x005B6720 (FUN_005B6720, Moho::SValuePairSerializer::Deserialize)
 */
void SValuePairSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const valuePair = reinterpret_cast<SValuePair*>(static_cast<std::uintptr_t>(objectPtr));
  archive->ReadFloat(&valuePair->mMinValue);
  archive->ReadFloat(&valuePair->mMaxValue);
}

/**
 * Address: 0x005B6750 (FUN_005B6750, Moho::SValuePairSerializer::Serialize)
 */
void SValuePairSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const valuePair = reinterpret_cast<const SValuePair*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteFloat(valuePair->mMinValue);
  archive->WriteFloat(valuePair->mMaxValue);
}

/**
 * Address: 0x00BCD5C0 (FUN_00BCD5C0, dynamic initializer for the global
 * `SValuePairSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
SValuePairSerializer::SValuePairSerializer()
  : mDeserialize(&SValuePairSerializer::Deserialize)
  , mSerialize(&SValuePairSerializer::Serialize)
{}

/**
 * Address: 0x00BF7640 (FUN_00BF7640, Moho::SValuePairSerializer::~SValuePairSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
SValuePairSerializer::~SValuePairSerializer()
{
  ResetLinks();
}

void SValuePairSerializer::Init()
{
  gpg::RType* const type = CachedSValuePairType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x00BCD5A0 (FUN_00BCD5A0)
 *
 * What it does:
 * Preregisters startup RTTI for the legacy AI `SValuePair` lane and installs
 * process-exit cleanup.
 */
int moho::register_SValuePairTypeInfo()
{
  (void)preregister_SValuePairTypeInfo();
  return std::atexit(&cleanup_SValuePairTypeInfo);
}

/**
 * Address: 0x005B6A80 (FUN_005B6A80, Moho::CAiPersonalitySerializer::Deserialize)
 */
void CAiPersonalitySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const personality = reinterpret_cast<CAiPersonality*>(static_cast<std::uintptr_t>(objectPtr));
  personality->MemberDeserialize(archive);
}

/**
 * Address: 0x005B6A90 (FUN_005B6A90, Moho::CAiPersonalitySerializer::Serialize)
 */
void CAiPersonalitySerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const personality = reinterpret_cast<CAiPersonality*>(static_cast<std::uintptr_t>(objectPtr));
  if (ownerRef != nullptr) {
    personality->MemberSerialize(archive);
    return;
  }

  CAiPersonalityMemberSerializeThunk(personality, archive);
}

/**
 * Address: 0x00BCD660 (FUN_00BCD660, dynamic initializer for the global
 * `CAiPersonalitySerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiPersonalitySerializer::CAiPersonalitySerializer()
  : mLoadCallback(&CAiPersonalitySerializer::Deserialize)
  , mSaveCallback(&CAiPersonalitySerializer::Serialize)
{}

/**
 * Address: 0x00BF7740 (FUN_00BF7740, Moho::CAiPersonalitySerializer::~CAiPersonalitySerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiPersonalitySerializer::~CAiPersonalitySerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005B9350 (FUN_005B9350)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPersonalitySerializer::Init()
{
  gpg::RType* type = CachedCAiPersonalityType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SValuePairTypeInfo_95b24f, moho::register_SValuePairTypeInfo)

GPG_PREREGISTER_INIT(preregister_SValuePairTypeInfo_95b24f, preregister_SValuePairTypeInfo)
