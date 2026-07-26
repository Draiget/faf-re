#include "moho/ai/SPickUpInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/SPickUpInfo.h"

// SPickUpInfo registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query SPickUpInfo RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::SPickUpInfoTypeInfo) unsigned char gSPickUpInfoTypeInfoStorage[sizeof(moho::SPickUpInfoTypeInfo)];
  bool gSPickUpInfoTypeInfoConstructed = false;

  [[nodiscard]] moho::SPickUpInfoTypeInfo* AcquireSPickUpInfoTypeInfo()
  {
    if (!gSPickUpInfoTypeInfoConstructed) {
      new (gSPickUpInfoTypeInfoStorage) moho::SPickUpInfoTypeInfo();
      gSPickUpInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SPickUpInfoTypeInfo*>(gSPickUpInfoTypeInfoStorage);
  }

  /**
   * Address: 0x00BFA4C0 (FUN_00BFA4C0)
   *
   * What it does:
   * Runs startup-registered teardown for the global `SPickUpInfo` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_SPickUpInfoTypeInfo()
  {
    if (!gSPickUpInfoTypeInfoConstructed) {
      return;
    }

    AcquireSPickUpInfoTypeInfo()->~SPickUpInfoTypeInfo();
    gSPickUpInfoTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006246D0 (FUN_006246D0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `SPickUpInfo` RTTI so lookup resolves to this type helper.
   */
  SPickUpInfoTypeInfo::SPickUpInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPickUpInfo), this);
  }

  /**
   * Address: 0x00624760 (FUN_00624760, scalar deleting thunk)
   */
  SPickUpInfoTypeInfo::~SPickUpInfoTypeInfo() = default;

  /**
   * Address: 0x00624750 (FUN_00624750)
   *
   * What it does:
   * Returns the reflection type name literal for SPickUpInfo.
   */
  const char* SPickUpInfoTypeInfo::GetName() const
  {
    return "SPickUpInfo";
  }

  /**
   * Address: 0x00624730 (FUN_00624730)
   *
   * What it does:
   * Writes `size_` for SPickUpInfo, then performs base-init/finalization.
   */
  void SPickUpInfoTypeInfo::Init()
  {
    size_ = sizeof(SPickUpInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD1C30 (FUN_00BD1C30, register_SPickUpInfoTypeInfo)
   *
   * What it does:
   * Registers the `SPickUpInfo` type-info object and installs process-exit cleanup.
   */
  int register_SPickUpInfoTypeInfo()
  {
    (void)AcquireSPickUpInfoTypeInfo();
    return std::atexit(&cleanup_SPickUpInfoTypeInfo);
  }
} // namespace moho

namespace
{
  struct SPickUpInfoTypeInfoRegistration
  {
    SPickUpInfoTypeInfoRegistration()
    {
      (void)moho::register_SPickUpInfoTypeInfo();
    }
  };

  [[maybe_unused]] SPickUpInfoTypeInfoRegistration gSPickUpInfoTypeInfoRegistration;
} // namespace
