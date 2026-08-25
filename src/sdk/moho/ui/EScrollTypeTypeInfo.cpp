#include "moho/ui/EScrollTypeTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EScrollTypeTypeInfo> gEScrollTypeTypeInfoStorage{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007771B0 (FUN_007771B0, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EScrollTypeTypeInfo()
  {
    return &gEScrollTypeTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x007771B0 (FUN_007771B0, Moho::EScrollTypeTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EScrollType` enum metadata.
   */
  EScrollTypeTypeInfo::EScrollTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EScrollType), this);
  }

  /**
   * Address: 0x00777240 (FUN_00777240, Moho::EScrollTypeTypeInfo::dtr)
   */
  EScrollTypeTypeInfo::~EScrollTypeTypeInfo() = default;

  /**
   * Address: 0x00777230 (FUN_00777230, Moho::EScrollTypeTypeInfo::GetName)
   */
  const char* EScrollTypeTypeInfo::GetName() const
  {
    return "EScrollType";
  }

  /**
   * Address: 0x00777210 (FUN_00777210, Moho::EScrollTypeTypeInfo::Init)
   */
  void EScrollTypeTypeInfo::Init()
  {
    size_ = sizeof(EScrollType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00777270 (FUN_00777270, Moho::EScrollTypeTypeInfo::AddEnums)
   */
  void EScrollTypeTypeInfo::AddEnums()
  {
    mPrefix = "SCROLLTYPE_";

    AddEnum(StripPrefix("SCROLLTYPE_None"), static_cast<std::int32_t>(SCROLLTYPE_None));
    AddEnum(StripPrefix("SCROLLTYPE_PingPong"), static_cast<std::int32_t>(SCROLLTYPE_PingPong));
    AddEnum(StripPrefix("SCROLLTYPE_Manual"), static_cast<std::int32_t>(SCROLLTYPE_Manual));
    AddEnum(StripPrefix("SCROLLTYPE_MotionDerived"), static_cast<std::int32_t>(SCROLLTYPE_MotionDerived));
  }
} // namespace moho

namespace
{
  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes) -- same shape as the sibling CUnitFerryTask /
  // CUnitCarrierRetrieve serializer-helper globals in
  // gpg/core/reflection/SerSaveLoadHelperListRuntime.h.
  struct EScrollTypePrimitiveSerializerHelper
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
  static_assert(
    offsetof(EScrollTypePrimitiveSerializerHelper, mNext) == 0x04,
    "EScrollTypePrimitiveSerializerHelper::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(EScrollTypePrimitiveSerializerHelper, mPrev) == 0x08,
    "EScrollTypePrimitiveSerializerHelper::mPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EScrollTypePrimitiveSerializerHelper, mLoadCallback) == 0x0C,
    "EScrollTypePrimitiveSerializerHelper::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EScrollTypePrimitiveSerializerHelper, mSaveCallback) == 0x10,
    "EScrollTypePrimitiveSerializerHelper::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EScrollTypePrimitiveSerializerHelper) == 0x14,
    "EScrollTypePrimitiveSerializerHelper size must be 0x14"
  );

  EScrollTypePrimitiveSerializerHelper gEScrollTypePrimitiveSerializer{};

  [[nodiscard]] gpg::SerSaveLoadHelperListRuntime& AsSerSaveLoadHelperListRuntime(
    EScrollTypePrimitiveSerializerHelper& helper
  ) noexcept
  {
    return *reinterpret_cast<gpg::SerSaveLoadHelperListRuntime*>(&helper);
  }

  /**
   * Address: 0x00777FF0 (FUN_00777FF0, gpg::PrimitiveSerHelper<Moho::EScrollType,int>::Deserialize)
   *
   * IDA signature:
   * int __cdecl sub_777FF0(int a1, _DWORD *a2);
   *
   * What it does:
   * `gpg::RType::load_func_t`-shaped callback bound by
   * `register_EScrollTypePrimitiveSerializer`. Reads one raw int through the
   * archive's virtual `ReadInt` (vtable slot 9 / offset 0x24 -- see
   * `gpg::ReadArchive::ReadInt`) and stores it at the reflected field
   * address. `version`/`ownerRef` are pushed by the generic reflection
   * dispatcher but unused here, matching the binary (no stack access beyond
   * the first two arguments).
   */
  void DeserializeEScrollTypeSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::EScrollType*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::EScrollType>(value);
  }

  /**
   * Address: 0x00778010 (FUN_00778010, gpg::PrimitiveSerHelper<Moho::EScrollType,int>::Serialize)
   *
   * IDA signature:
   * int __cdecl sub_778010(int a1, _DWORD *a2);
   *
   * What it does:
   * `gpg::RType::save_func_t`-shaped callback bound by
   * `register_EScrollTypePrimitiveSerializer`. Writes the reflected field's
   * raw int value through the archive's virtual `WriteInt` (vtable slot 9 /
   * offset 0x24 -- see `gpg::WriteArchive::WriteInt`). Same unused-trailing-
   * argument shape as the load side.
   */
  void SerializeEScrollTypeSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    archive->WriteInt(
      static_cast<int>(*reinterpret_cast<const moho::EScrollType*>(static_cast<std::uintptr_t>(objectPtr)))
    );
  }

  /**
   * Address: 0x00C02650 (FUN_00C02650, cleanup_EScrollTypePrimitiveSerializer)
   *
   * What it does:
   * Process-exit cleanup registered by `register_EScrollTypePrimitiveSerializer`
   * via `atexit`. Unlinks the global `PrimitiveSerHelper<EScrollType,int>`
   * helper node and restores its self-linked sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupEScrollTypePrimitiveSerializerAtExit()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gEScrollTypePrimitiveSerializer));
  }

  void cleanup_EScrollTypePrimitiveSerializer_atexit()
  {
    (void)CleanupEScrollTypePrimitiveSerializerAtExit();
  }

  /**
   * Address: 0x00BDD690 (FUN_00BDD690, register_EScrollTypePrimitiveSerializer)
   *
   * What it does:
   * Static-init constructor for the global
   * `gpg::PrimitiveSerHelper<Moho::EScrollType,int>` helper: self-links its
   * intrusive-list node, binds `DeserializeEScrollTypeSerializerCallback` /
   * `SerializeEScrollTypeSerializerCallback` as its load/save callbacks
   * (real typed `load_func_t`/`save_func_t`, no type erasure needed --
   * matching the CUnitFerryTask/CUnitCarrierRetrieve registration shape),
   * and installs process-exit cleanup. The callbacks are later copied onto
   * `EScrollType`'s reflected `RType` by `InstallMohoEScrollTypeSerializerCallbacks`
   * (0x00777E20, in ArchiveSerialization.cpp) when the pending helper list
   * is drained.
   */
  void register_EScrollTypePrimitiveSerializer()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gEScrollTypePrimitiveSerializer.mNext);
    gEScrollTypePrimitiveSerializer.mNext = self;
    gEScrollTypePrimitiveSerializer.mPrev = self;
    gEScrollTypePrimitiveSerializer.mLoadCallback = &DeserializeEScrollTypeSerializerCallback;
    gEScrollTypePrimitiveSerializer.mSaveCallback = &SerializeEScrollTypeSerializerCallback;
    (void)std::atexit(&cleanup_EScrollTypePrimitiveSerializer_atexit);
  }

  struct EScrollTypePrimitiveSerializerStartupBootstrap
  {
    EScrollTypePrimitiveSerializerStartupBootstrap()
    {
      register_EScrollTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EScrollTypePrimitiveSerializerStartupBootstrap gEScrollTypePrimitiveSerializerStartupBootstrap;
} // namespace

// Phase-1 pre-registration: CTextureScroller caches the reflected EScrollType
// through gpg::LookupRType, so the descriptor must exist before that consumer
// runs. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EScrollTypeTypeInfo_7771b0, moho::preregister_EScrollTypeTypeInfo)
