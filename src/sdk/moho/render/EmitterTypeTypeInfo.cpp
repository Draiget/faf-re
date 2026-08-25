#include "moho/render/EmitterTypeTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/render/EmitterType.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EmitterTypeTypeInfo) unsigned char gEmitterTypeTypeInfoStorage[sizeof(moho::EmitterTypeTypeInfo)] = {};
  bool gEmitterTypeTypeInfoConstructed = false;

  /**
   * Address: 0x00BD42B0 (FUN_00BD42B0, dynamic initializer for the global
   * `PrimitiveSerHelper<EmitterType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (which self-links this
   * helper onto the process-global pending-helper list) and binds the
   * load/save callback fields; `Init()` is dispatched later, from
   * `gpg::SerHelperBase::InitNewHelpers`. Prior to this recovery, this
   * global was a hand-rolled POD that never actually inherited
   * `SerHelperBase`, so `EmitterType`'s serialize/deserialize callbacks
   * were never installed under any code path.
   */
  moho::EmitterTypePrimitiveSerializer gEmitterTypePrimitiveSerializer;

  [[nodiscard]] moho::EmitterTypeTypeInfo* AcquireEmitterTypeTypeInfo()
  {
    if (!gEmitterTypeTypeInfoConstructed) {
      new (gEmitterTypeTypeInfoStorage) moho::EmitterTypeTypeInfo();
      gEmitterTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EmitterTypeTypeInfo*>(gEmitterTypeTypeInfoStorage);
  }

  struct DwordVectorHeaderRuntimeView
  {
    std::uint32_t* begin = nullptr; // +0x00
    std::uint32_t* end = nullptr; // +0x04
    std::uint32_t* capacityEnd = nullptr; // +0x08
    std::uint32_t* metadata = nullptr; // +0x0C
  };
  static_assert(sizeof(DwordVectorHeaderRuntimeView) == 0x10, "DwordVectorHeaderRuntimeView size must be 0x10");
  static_assert(offsetof(DwordVectorHeaderRuntimeView, begin) == 0x00, "DwordVectorHeaderRuntimeView::begin offset must be 0x00");
  static_assert(offsetof(DwordVectorHeaderRuntimeView, end) == 0x04, "DwordVectorHeaderRuntimeView::end offset must be 0x04");
  static_assert(
    offsetof(DwordVectorHeaderRuntimeView, capacityEnd) == 0x08,
    "DwordVectorHeaderRuntimeView::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(DwordVectorHeaderRuntimeView, metadata) == 0x0C,
    "DwordVectorHeaderRuntimeView::metadata offset must be 0x0C"
  );

  template <std::size_t InlineCapacityWords>
  [[nodiscard]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeader(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    auto* const inlineStorage = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::byte*>(outHeader) + 0x10u);
    outHeader->begin = inlineStorage;
    outHeader->end = inlineStorage;
    outHeader->capacityEnd = inlineStorage + InlineCapacityWords;
    outHeader->metadata = inlineStorage;
    return outHeader;
  }

  template <std::size_t CapacityWords>
  [[nodiscard]] DwordVectorHeaderRuntimeView* BindDwordVectorHeaderToExternalStorage(
    DwordVectorHeaderRuntimeView* const outHeader,
    std::uint32_t* const base
  ) noexcept
  {
    outHeader->begin = base;
    outHeader->end = base;
    outHeader->capacityEnd = base + CapacityWords;
    outHeader->metadata = base;
    return outHeader;
  }

  /**
   * Address: 0x0065EC00 (FUN_0065EC00)
   *
   * What it does:
   * Initializes one inline dword-vector header with 6-word inline capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeaderCapacity6(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    return InitializeInlineDwordVectorHeader<6u>(outHeader);
  }

  /**
   * Address: 0x0065EC60 (FUN_0065EC60)
   *
   * What it does:
   * Initializes one inline dword-vector header with 294-word inline capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* InitializeInlineDwordVectorHeaderCapacity294(
    DwordVectorHeaderRuntimeView* const outHeader
  ) noexcept
  {
    return InitializeInlineDwordVectorHeader<294u>(outHeader);
  }

  /**
   * Address: 0x0065F380 (FUN_0065F380)
   *
   * What it does:
   * Binds one dword-vector header to external storage with 294-word capacity.
   */
  [[maybe_unused]] DwordVectorHeaderRuntimeView* BindDwordVectorHeaderCapacity294(
    DwordVectorHeaderRuntimeView* const outHeader,
    std::uint32_t* const base
  ) noexcept
  {
    return BindDwordVectorHeaderToExternalStorage<294u>(outHeader, base);
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
   */
  EmitterTypeTypeInfo::~EmitterTypeTypeInfo() = default;

  /**
   * Address: 0x0065DF30 (FUN_0065DF30)
   *
   * What it does:
   * Returns the reflection type name literal for EmitterType.
   */
  const char* EmitterTypeTypeInfo::GetName() const
  {
    return "EmitterType";
  }

  /**
   * Address: 0x0065DF10 (FUN_0065DF10)
   *
   * What it does:
   * Writes enum width and finalizes metadata.
   */
  void EmitterTypeTypeInfo::Init()
  {
    size_ = sizeof(EmitterType);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0065DEB0 (FUN_0065DEB0, register_EmitterTypeTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::EmitterType`.
   */
  gpg::RType* register_EmitterTypeTypeInfo_00()
  {
    EmitterTypeTypeInfo* const typeInfo = AcquireEmitterTypeTypeInfo();
    gpg::PreRegisterRType(typeid(EmitterType), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFBD10 (FUN_00BFBD10, cleanup_EmitterTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EmitterTypeTypeInfo` reflection storage.
   */
  void cleanup_EmitterTypeTypeInfo()
  {
    if (!gEmitterTypeTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::REnumType*>(AcquireEmitterTypeTypeInfo())->~REnumType();
    gEmitterTypeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo_AtExit)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_EmitterTypeTypeInfo_AtExit()
  {
    (void)register_EmitterTypeTypeInfo_00();
    return std::atexit(&cleanup_EmitterTypeTypeInfo);
  }
} // namespace moho

namespace
{
  struct EmitterTypeTypeInfoBootstrap
  {
    EmitterTypeTypeInfoBootstrap()
    {
      (void)moho::register_EmitterTypeTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] EmitterTypeTypeInfoBootstrap gEmitterTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EmitterTypeTypeInfo_00_78818e, moho::register_EmitterTypeTypeInfo_00)
