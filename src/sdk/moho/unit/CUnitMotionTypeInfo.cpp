#include "moho/unit/CUnitMotionTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/CUnitMotion.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitMotionTypeInfo;

  /**
   * Address: 0x00BFE010 (FUN_00BFE010, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetCUnitMotionTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitMotion::sType = nullptr;

  gpg::RType* CUnitMotion::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitMotion));
    }
    return sType;
  }

  /**
   * Address: 0x006B77A0 (FUN_006B77A0, Moho::CUnitMotionTypeInfo::CUnitMotionTypeInfo)
   */
  CUnitMotionTypeInfo::CUnitMotionTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitMotion), this);
  }

  /**
   * Address: 0x006B7830 (FUN_006B7830, gpg::RType::~RType thunk owner)
   */
  CUnitMotionTypeInfo::~CUnitMotionTypeInfo() = default;

  /**
   * Address: 0x006B7820 (FUN_006B7820, Moho::CUnitMotionTypeInfo::GetName)
   */
  const char* CUnitMotionTypeInfo::GetName() const
  {
    return "CUnitMotion";
  }

  /**
   * Address: 0x006B7800 (FUN_006B7800, Moho::CUnitMotionTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_6B7800(_DWORD *this);
   */
  void CUnitMotionTypeInfo::Init()
  {
    size_ = sizeof(CUnitMotion);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD7220 (FUN_00BD7220, register_CUnitMotionTypeInfo)
   *
   * What it does:
   * Forces CUnitMotionTypeInfo startup construction and registers process-exit
   * cleanup.
   */
  void register_CUnitMotionTypeInfo()
  {
    (void)GetCUnitMotionTypeInfo();
  }
} // namespace moho

namespace
{
  struct CUnitMotionTypeInfoBootstrap
  {
    CUnitMotionTypeInfoBootstrap()
    {
      (void)moho::register_CUnitMotionTypeInfo();
    }
  };

  [[maybe_unused]] CUnitMotionTypeInfoBootstrap gCUnitMotionTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitMotionTypeInfo_72f79c, moho::register_CUnitMotionTypeInfo)
