#include "moho/effects/rendering/SEfxCurveTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/SEfxCurve.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::SEfxCurveTypeInfo;

  [[nodiscard]] TypeInfo& AcquireSEfxCurveTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  struct SEfxCurveTypeInfoBootstrap
  {
    SEfxCurveTypeInfoBootstrap()
    {
      (void)moho::register_SEfxCurveTypeInfo();
    }
  };

  SEfxCurveTypeInfoBootstrap gSEfxCurveTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00514C00 (FUN_00514C00, Moho::SEfxCurveTypeInfo::SEfxCurveTypeInfo)
   */
  SEfxCurveTypeInfo::SEfxCurveTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SEfxCurve), this);
  }

  /**
   * Address: 0x00514C90 (FUN_00514C90, Moho::SEfxCurveTypeInfo::dtr)
   */
  SEfxCurveTypeInfo::~SEfxCurveTypeInfo() = default;

  /**
   * Address: 0x00514C80 (FUN_00514C80, Moho::SEfxCurveTypeInfo::GetName)
   */
  const char* SEfxCurveTypeInfo::GetName() const
  {
    return "SEfxCurve";
  }

  /**
   * Address: 0x00514C60 (FUN_00514C60, Moho::SEfxCurveTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::SEfxCurveTypeInfo::Init(_DWORD *this);
   */
  void SEfxCurveTypeInfo::Init()
  {
    size_ = sizeof(SEfxCurve);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC8420 (FUN_00BC8420, register_SEfxCurveTypeInfo)
   */
  void register_SEfxCurveTypeInfo()
  {
    (void)AcquireSEfxCurveTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SEfxCurveTypeInfo_49049d, moho::register_SEfxCurveTypeInfo)
