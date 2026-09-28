#include "moho/audio/SParamKeyTypeInfo.h"

#include <typeinfo>

#include "moho/audio/SParamKey.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::SParamKeyTypeInfo;

  /**
   * Address: 0x00BF0DF0 (FUN_00BF0DF0, atexit destructor of the SParamKeyTypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetSParamKeyTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004DEE90 (FUN_004DEE90)
   */
  SParamKeyTypeInfo::SParamKeyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SParamKey), this);
  }

  /**
   * Address: 0x004DEF20 (FUN_004DEF20, Moho::SParamKeyTypeInfo::dtr)
   */
  SParamKeyTypeInfo::~SParamKeyTypeInfo() = default;

  /**
   * Address: 0x004DEF10 (FUN_004DEF10, Moho::SParamKeyTypeInfo::GetName)
   */
  const char* SParamKeyTypeInfo::GetName() const
  {
    return "SParamKey";
  }

  /**
   * Address: 0x004DEEF0 (FUN_004DEEF0, Moho::SParamKeyTypeInfo::Init)
   */
  void SParamKeyTypeInfo::Init()
  {
    size_ = sizeof(SParamKey);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC6840 (FUN_00BC6840, register_SParamKeyTypeInfo)
   */
  void register_SParamKeyTypeInfo()
  {
    (void)GetSParamKeyTypeInfo();
  }
} // namespace moho

namespace
{
  struct SParamKeyTypeInfoBootstrap
  {
    SParamKeyTypeInfoBootstrap()
    {
      moho::register_SParamKeyTypeInfo();
    }
  };

  [[maybe_unused]] SParamKeyTypeInfoBootstrap gSParamKeyTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SParamKeyTypeInfo_20c8e5, moho::register_SParamKeyTypeInfo)
