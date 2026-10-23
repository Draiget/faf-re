#include "moho/entity/intel/CIntelPosHandleTypeInfo.h"

#include <typeinfo>

#include "moho/entity/intel/CIntelPosHandle.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00C01E40 (FUN_00C01E40, atexit destructor of the CIntelPosHandleTypeInfo object)
   */
  [[nodiscard]] moho::CIntelPosHandleTypeInfo& GetCIntelPosHandleTypeInfo()
  {
    static moho::CIntelPosHandleTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076F040 (FUN_0076F040, Moho::CIntelPosHandleTypeInfo::CIntelPosHandleTypeInfo)
   */
  CIntelPosHandleTypeInfo::CIntelPosHandleTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CIntelPosHandle), this);
  }

  /**
   * Address: 0x0076F0D0 (FUN_0076F0D0, Moho::CIntelPosHandleTypeInfo::dtr)
   */
  CIntelPosHandleTypeInfo::~CIntelPosHandleTypeInfo() = default;

  /**
   * Address: 0x0076F0C0 (FUN_0076F0C0, Moho::CIntelPosHandleTypeInfo::GetName)
   */
  const char* CIntelPosHandleTypeInfo::GetName() const
  {
    return "CIntelPosHandle";
  }

  /**
   * Address: 0x0076F0A0 (FUN_0076F0A0, Moho::CIntelPosHandleTypeInfo::Init)
   */
  void CIntelPosHandleTypeInfo::Init()
  {
    size_ = sizeof(CIntelPosHandle);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BDCC90 (FUN_00BDCC90, register_CIntelPosHandleTypeInfo)
   *
   * What it does:
   * Builds the startup `CIntelPosHandleTypeInfo` object.
   */
  void register_CIntelPosHandleTypeInfo()
  {
    (void)GetCIntelPosHandleTypeInfo();
  }
} // namespace moho

namespace
{
  struct CIntelPosHandleTypeInfoBootstrap
  {
    CIntelPosHandleTypeInfoBootstrap()
    {
      moho::register_CIntelPosHandleTypeInfo();
    }
  };

  [[maybe_unused]] CIntelPosHandleTypeInfoBootstrap gCIntelPosHandleTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CIntelPosHandleTypeInfo_d34bd8, moho::register_CIntelPosHandleTypeInfo)
