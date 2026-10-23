#include "moho/unit/tasks/CBuildTaskHelperTypeInfo.h"

#include <typeinfo>

#include "moho/unit/tasks/CBuildTaskHelper.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CBuildTaskHelperTypeInfo;

  /**
   * Address: 0x00BF9240 (FUN_00BF9240, atexit destructor of the CBuildTaskHelperTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F5820 (FUN_005F5820, ??0CBuildTaskHelperTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CBuildTaskHelper` RTTI into the reflection lookup table.
   */
  CBuildTaskHelperTypeInfo::CBuildTaskHelperTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CBuildTaskHelper), this);
  }

  /**
   * Address: 0x005F58B0 (FUN_005F58B0, scalar deleting thunk)
   */
  CBuildTaskHelperTypeInfo::~CBuildTaskHelperTypeInfo() = default;

  /**
   * Address: 0x005F58A0 (FUN_005F58A0)
   */
  const char* CBuildTaskHelperTypeInfo::GetName() const
  {
    return "CBuildTaskHelper";
  }

  /**
   * Address: 0x005F5880 (FUN_005F5880)
   *
   * What it does:
   * Sets the reflected size (0x44) and finalizes metadata. No allocator
   * callbacks — CBuildTaskHelper is not independently constructable via
   * the reflection system.
   */
  void CBuildTaskHelperTypeInfo::Init()
  {
    static_assert(sizeof(moho::CBuildTaskHelper) == 0x44, "moho::CBuildTaskHelper is 0x44 bytes on x86");
    size_ = sizeof(moho::CBuildTaskHelper);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BCF810 (FUN_00BCF810, register_CBuildTaskHelperTypeInfo)
   */
  void register_CBuildTaskHelperTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CBuildTaskHelperTypeInfo_c85ec8, moho::register_CBuildTaskHelperTypeInfo)
