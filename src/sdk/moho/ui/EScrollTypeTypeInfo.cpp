#include "moho/ui/EScrollTypeTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"
#include "moho/containers/TDatList.h"

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
  // CUnitCarrierRetrieve serializer-helper globals, and byte-identical to
  // `gpg::SerSaveLoadHelperInitView` (gpg/core/containers/ArchiveSerialization.cpp),
  // the runtime view `InstallMohoEScrollTypeSerializerCallbacks` (0x00777E20)
  // actually binds through when it drains this helper's load/save lanes onto
  // `EScrollType`'s reflected RType by looked-up type name. That install
  // function -- and the dispatcher that calls it -- lives outside this file
  // and is not part of this pass; this struct only replaces its hand-rolled
  // `gpg::SerHelperBase* mNext, mPrev` pair with the project's real
  // `moho::TDatListItem` node (the same base `gpg::SerHelperBase` itself
  // derives from) so the two lanes below stop routing through the deprecated
  // `gpg::SerSaveLoadHelperListRuntime` reach-in view. It deliberately does
  // NOT inherit `gpg::SerHelperBase` here: that would require this file to
  // also own binding this helper's callbacks onto `EScrollType`'s RType (an
  // `Init()` override), which is the job the real, already-cited
  // `InstallMohoEScrollTypeSerializerCallbacks` performs elsewhere -- adding a
  // second, competing binder here would risk double-registering the callback.
  struct EScrollTypePrimitiveSerializerHelper
  {
    void* mVtable = nullptr;
    moho::TDatListItem<gpg::SerHelperBase, void> mLink{};
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
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
  void CleanupEScrollTypePrimitiveSerializerAtExit() noexcept
  {
    gEScrollTypePrimitiveSerializer.mLink.ListUnlinkSelf();
  }

  void cleanup_EScrollTypePrimitiveSerializer_atexit()
  {
    CleanupEScrollTypePrimitiveSerializerAtExit();
  }

  /**
   * Address: 0x00BDD690 (FUN_00BDD690, register_EScrollTypePrimitiveSerializer)
   *
   * What it does:
   * Static-init constructor for the global
   * `gpg::PrimitiveSerHelper<Moho::EScrollType,int>` helper: binds
   * `DeserializeEScrollTypeSerializerCallback` /
   * `SerializeEScrollTypeSerializerCallback` as its load/save callbacks
   * (real typed `load_func_t`/`save_func_t`, no type erasure needed --
   * matching the CUnitFerryTask/CUnitCarrierRetrieve registration shape),
   * and installs process-exit cleanup. `gEScrollTypePrimitiveSerializer.mLink`
   * self-links as part of the global's own construction (its `moho::TDatListItem`
   * default constructor), which runs before this function does, so this no
   * longer needs to self-link the node itself. The callbacks are later copied onto
   * `EScrollType`'s reflected `RType` by `InstallMohoEScrollTypeSerializerCallbacks`
   * (0x00777E20, in ArchiveSerialization.cpp) when the pending helper list
   * is drained.
   */
  void register_EScrollTypePrimitiveSerializer()
  {
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
