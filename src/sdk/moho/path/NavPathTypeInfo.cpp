#include "moho/path/NavPathTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

// NavPath registration is emitted into the earliest C++ initializer segment
// (binary __xc_a) so the descriptor is preregistered before default-segment
// bootstrap objects query NavPath RTTI during static initialization.
#pragma init_seg(lib)

namespace moho
{
  /**
   * Address: 0x00763050 (FUN_00763050, sub_763050 construct-and-preregister worker)
   * Ctor body ICF-folded with 0x00401460 (Moho::BVIntSetTypeInfo::BVIntSetTypeInfo)
   *
   * What it does:
   * Constructs the descriptor and preregisters it for `SNavPath` RTTI lookup.
   */
  NavPathTypeInfo::NavPathTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SNavPath), this);
  }

  /**
   * Address: 0x007630E0 (FUN_007630E0, scalar deleting dtor lane)
   */
  NavPathTypeInfo::~NavPathTypeInfo() = default;

  /**
   * Address: 0x007630D0 (FUN_007630D0, Moho::NavPathTypeInfo::GetName)
   */
  const char* NavPathTypeInfo::GetName() const
  {
    return "NavPath";
  }

  /**
   * Address: 0x007630B0 (FUN_007630B0, Moho::NavPathTypeInfo::Init)
   *
   * What it does:
   * Sets NavPath size metadata and finalizes reflection setup.
   */
  void NavPathTypeInfo::Init()
  {
    size_ = sizeof(SNavPath);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

namespace
{
  extern moho::NavPathTypeInfo gNavPathTypeInfo;

  /**
   * Address: 0x00C01710 (FUN_00C01710, sub_C01710)
   *
   * What it does:
   * Process-exit cleanup for global `NavPathTypeInfo` dynamic field/base lanes.
   */
  void cleanup_NavPathTypeInfo()
  {
    gNavPathTypeInfo.fields_.clear();
    gNavPathTypeInfo.bases_.clear();
  }

  moho::NavPathTypeInfo gNavPathTypeInfo;

  struct NavPathReflectionRegistration
  {
    NavPathReflectionRegistration()
    {
      moho::register_NavPathTypeInfo();
    }
  };

  NavPathReflectionRegistration gNavPathReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDC670 (FUN_00BDC670, register_NavPathTypeInfo)
   *
   * What it does:
   * Materializes startup `NavPathTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_NavPathTypeInfo()
  {
    (void)gNavPathTypeInfo;
    (void)std::atexit(&cleanup_NavPathTypeInfo);
  }
} // namespace moho
