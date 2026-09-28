#include "moho/ai/SOffsetInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// SOffsetInfo registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query SOffsetInfo RTTI during static initialization.
namespace
{
  /**
   * Address: 0x00BF5890 (FUN_00BF5890, atexit destructor of the moho::SOffsetInfoTypeInfo object)
   */
  [[nodiscard]] moho::SOffsetInfoTypeInfo* AcquireSOffsetInfoTypeInfo()
  {
    static moho::SOffsetInfoTypeInfo sInstance;
    return &sInstance;
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
  void register_SOffsetInfoTypeInfo()
  {
    (void)AcquireSOffsetInfoTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SOffsetInfoTypeInfo_99627c, moho::register_SOffsetInfoTypeInfo)
