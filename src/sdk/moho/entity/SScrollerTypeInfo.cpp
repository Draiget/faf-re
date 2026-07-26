#include "moho/entity/SScrollerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/CTextureScroller.h"

// SScroller registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query SScroller RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::SScrollerTypeInfo) unsigned char gSScrollerTypeInfoStorage[sizeof(moho::SScrollerTypeInfo)];
  bool gSScrollerTypeInfoConstructed = false;

  [[nodiscard]] moho::SScrollerTypeInfo* AcquireSScrollerTypeInfo()
  {
    if (!gSScrollerTypeInfoConstructed) {
      new (gSScrollerTypeInfoStorage) moho::SScrollerTypeInfo();
      gSScrollerTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SScrollerTypeInfo*>(gSScrollerTypeInfoStorage);
  }

  /**
   * Address: 0x00C02680 (FUN_00C02680)
   *
   * What it does:
   * Runs startup-registered teardown for the global `SScroller` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_SScrollerTypeInfo()
  {
    if (!gSScrollerTypeInfoConstructed) {
      return;
    }

    AcquireSScrollerTypeInfo()->~SScrollerTypeInfo();
    gSScrollerTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00777330 (FUN_00777330, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `SScroller` RTTI so lookup resolves to this type helper.
   */
  SScrollerTypeInfo::SScrollerTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SScroller), this);
  }

  /**
   * Address: 0x007773C0 (FUN_007773C0, scalar deleting thunk)
   */
  SScrollerTypeInfo::~SScrollerTypeInfo() = default;

  /**
   * Address: 0x007773B0 (FUN_007773B0)
   *
   * What it does:
   * Returns the reflection type name literal for SScroller.
   */
  const char* SScrollerTypeInfo::GetName() const
  {
    return "SScroller";
  }

  /**
   * Address: 0x00777390 (FUN_00777390)
   *
   * What it does:
   * Writes `size_` for SScroller, then performs base-init/finalization.
   */
  void SScrollerTypeInfo::Init()
  {
    size_ = sizeof(SScroller);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDD6D0 (FUN_00BDD6D0, register_SScrollerTypeInfo)
   *
   * What it does:
   * Registers the `SScroller` type-info object and installs process-exit cleanup.
   */
  int register_SScrollerTypeInfo()
  {
    (void)AcquireSScrollerTypeInfo();
    return std::atexit(&cleanup_SScrollerTypeInfo);
  }
} // namespace moho

namespace
{
  struct SScrollerTypeInfoRegistration
  {
    SScrollerTypeInfoRegistration()
    {
      (void)moho::register_SScrollerTypeInfo();
    }
  };

  [[maybe_unused]] SScrollerTypeInfoRegistration gSScrollerTypeInfoRegistration;
} // namespace
