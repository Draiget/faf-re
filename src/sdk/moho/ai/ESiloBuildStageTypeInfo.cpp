#include "moho/ai/ESiloBuildStageTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(ESiloBuildStageTypeInfo) unsigned char gESiloBuildStageTypeInfoStorage[sizeof(ESiloBuildStageTypeInfo)];
  bool gESiloBuildStageTypeInfoConstructed = false;

  [[nodiscard]] ESiloBuildStageTypeInfo* AcquireESiloBuildStageTypeInfo()
  {
    if (!gESiloBuildStageTypeInfoConstructed) {
      auto* const typeInfo = new (gESiloBuildStageTypeInfoStorage) ESiloBuildStageTypeInfo();
      gpg::PreRegisterRType(typeid(ESiloBuildStage), typeInfo);
      gESiloBuildStageTypeInfoConstructed = true;
    }

    return reinterpret_cast<ESiloBuildStageTypeInfo*>(gESiloBuildStageTypeInfoStorage);
  }

  /**
   * Address: 0x005CE9F0 (FUN_005CE9F0, sub_5CE9F0)
   *
   * What it does:
   * Constructs and preregisters the static `ESiloBuildStageTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloBuildStageTypeInfo()
  {
    return AcquireESiloBuildStageTypeInfo();
  }

  /**
   * Address: 0x00BF7E00 (FUN_00BF7E00, sub_BF7E00)
   *
   * What it does:
   * Tears down recovered static `ESiloBuildStageTypeInfo` storage.
   */
  void cleanup_ESiloBuildStageTypeInfo()
  {
    if (!gESiloBuildStageTypeInfoConstructed) {
      return;
    }

    AcquireESiloBuildStageTypeInfo()->~ESiloBuildStageTypeInfo();
    gESiloBuildStageTypeInfoConstructed = false;
  }

  // Address: 0x010AFBBC -- process-global `PrimitiveSerHelper<ESiloBuildStage,int>`
  // singleton (constructed by FUN_00BCE050, self-registering via `__xc_a`; see
  // ESiloBuildStageTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::ESiloBuildStagePrimitiveSerializer gESiloBuildStagePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005CEA80 (FUN_005CEA80, scalar deleting thunk)
 */
ESiloBuildStageTypeInfo::~ESiloBuildStageTypeInfo() = default;

/**
 * Address: 0x005CEA70 (FUN_005CEA70, ?GetName@ESiloBuildStageTypeInfo@Moho@@UBEPBDXZ)
 */
const char* ESiloBuildStageTypeInfo::GetName() const
{
  return "ESiloBuildStage";
}

/**
 * Address: 0x005CEA50 (FUN_005CEA50, ?Init@ESiloBuildStageTypeInfo@Moho@@UAEXXZ)
 */
void ESiloBuildStageTypeInfo::Init()
{
  size_ = sizeof(ESiloBuildStage);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
 *
 * What it does:
 * Registers `ESiloBuildStage` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_ESiloBuildStageTypeInfo()
{
  (void)preregister_ESiloBuildStageTypeInfo();
  return std::atexit(&cleanup_ESiloBuildStageTypeInfo);
}

namespace
{
  struct ESiloBuildStageReflectionBootstrap
  {
    ESiloBuildStageReflectionBootstrap()
    {
      (void)moho::register_ESiloBuildStageTypeInfo();
    }
  };

  [[maybe_unused]] ESiloBuildStageReflectionBootstrap gESiloBuildStageReflectionBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESiloBuildStageTypeInfo_ea41ff, moho::register_ESiloBuildStageTypeInfo)

GPG_PREREGISTER_INIT(AcquireESiloBuildStageTypeInfo_ea41ff, AcquireESiloBuildStageTypeInfo)
