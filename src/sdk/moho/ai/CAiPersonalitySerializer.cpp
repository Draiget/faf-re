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
     * Address: 0x00BF7680 (FUN_00BF7680, dynamic atexit destructor for
     *   `gSValuePairSerializer`, pushed by 0x00BCD5C0)
     * Address: 0x005B67B0 (FUN_005B67B0), Address: 0x005B67E0 (FUN_005B67E0)
     * -- unreferenced out-of-line copies of the same body.
     *
     * What it does:
     * Unlinks this helper node from the serializer-helper list (the
     * `DListItem` base destructor). The tree cited 0x00BF7640, which is inside
     * `cleanup_SValuePairTypeInfo` (0x00BF7620), and unlinked twice.
     */
    ~SValuePairSerializer() = default;

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

  /**
   * Address: 0x00BF7620 (FUN_00BF7620, atexit destructor of the SValuePairTypeInfo object)
   */
  [[nodiscard]] SValuePairTypeInfo* AcquireSValuePairTypeInfo()
  {
    static SValuePairTypeInfo sInstance;
    return &sInstance;
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

  // Address: 0x010AF168 -- process-global `SValuePairSerializer` singleton.
  // Constructing it runs SValuePairSerializer::SValuePairSerializer()
  // (0x00BCD5C0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SValuePairSerializer,
  // 0x00BF7640) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  SValuePairSerializer gSValuePairSerializer;

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
void moho::register_SValuePairTypeInfo()
{
  (void)preregister_SValuePairTypeInfo();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SValuePairTypeInfo_95b24f, moho::register_SValuePairTypeInfo)

GPG_PREREGISTER_INIT(preregister_SValuePairTypeInfo_95b24f, preregister_SValuePairTypeInfo)
