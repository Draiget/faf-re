#include "moho/ai/SOffsetInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

// SOffsetInfo registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query SOffsetInfo RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  alignas(moho::SOffsetInfoTypeInfo) unsigned char gSOffsetInfoTypeInfoStorage[sizeof(moho::SOffsetInfoTypeInfo)];
  bool gSOffsetInfoTypeInfoConstructed = false;

  [[nodiscard]] moho::SOffsetInfoTypeInfo* AcquireSOffsetInfoTypeInfo()
  {
    if (!gSOffsetInfoTypeInfoConstructed) {
      new (gSOffsetInfoTypeInfoStorage) moho::SOffsetInfoTypeInfo();
      gSOffsetInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SOffsetInfoTypeInfo*>(gSOffsetInfoTypeInfoStorage);
  }

  /**
   * Address: 0x00BF5890 (FUN_00BF5890)
   *
   * What it does:
   * Runs startup-registered teardown for the global `SOffsetInfo` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_SOffsetInfoTypeInfo()
  {
    if (!gSOffsetInfoTypeInfoConstructed) {
      return;
    }

    AcquireSOffsetInfoTypeInfo()->~SOffsetInfoTypeInfo();
    gSOffsetInfoTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005663C0 (FUN_005663C0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `SOffsetInfo` RTTI so lookup resolves to this type helper.
   */
  SOffsetInfoTypeInfo::SOffsetInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SOffsetInfo), this);
  }

  /**
   * Address: 0x00566450 (FUN_00566450, scalar deleting thunk)
   */
  SOffsetInfoTypeInfo::~SOffsetInfoTypeInfo() = default;

  /**
   * Address: 0x00566440 (FUN_00566440)
   *
   * What it does:
   * Returns the reflection type name literal for SOffsetInfo.
   */
  const char* SOffsetInfoTypeInfo::GetName() const
  {
    return "SOffsetInfo";
  }

  /**
   * Address: 0x00566420 (FUN_00566420)
   *
   * What it does:
   * Writes `size_` for SOffsetInfo, then performs base-init/finalization.
   */
  void SOffsetInfoTypeInfo::Init()
  {
    size_ = sizeof(SOffsetInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BCAB00 (FUN_00BCAB00, register_SOffsetInfoTypeInfo)
   *
   * What it does:
   * Registers the `SOffsetInfo` type-info object and installs process-exit cleanup.
   */
  int register_SOffsetInfoTypeInfo()
  {
    (void)AcquireSOffsetInfoTypeInfo();
    return std::atexit(&cleanup_SOffsetInfoTypeInfo);
  }
} // namespace moho

namespace
{
  struct SOffsetInfoTypeInfoRegistration
  {
    SOffsetInfoTypeInfoRegistration()
    {
      (void)moho::register_SOffsetInfoTypeInfo();
    }
  };

  [[maybe_unused]] SOffsetInfoTypeInfoRegistration gSOffsetInfoTypeInfoRegistration;
} // namespace
