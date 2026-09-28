#include "moho/audio/CSndVarTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/CSndVar.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CSndVarTypeInfo;

  /**
   * Address: 0x00BF0EA0 (FUN_00BF0EA0, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetCSndVarTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004E0170 (FUN_004E0170, Moho::CSndVarTypeInfo::CSndVarTypeInfo)
   */
  CSndVarTypeInfo::CSndVarTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSndVar), this);
  }

  /**
   * Address: 0x004E0200 (FUN_004E0200, Moho::CSndVarTypeInfo::dtr)
   */
  CSndVarTypeInfo::~CSndVarTypeInfo() = default;

  /**
   * Address: 0x004E01F0 (FUN_004E01F0, Moho::CSndVarTypeInfo::GetName)
   */
  const char* CSndVarTypeInfo::GetName() const
  {
    return "CSndVar";
  }

  /**
   * Address: 0x004E01D0 (FUN_004E01D0, Moho::CSndVarTypeInfo::Init)
   */
  void CSndVarTypeInfo::Init()
  {
    size_ = sizeof(CSndVar);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC6910 (FUN_00BC6910, register_CSndVarTypeInfo)
   */
  void register_CSndVarTypeInfo()
  {
    (void)GetCSndVarTypeInfo();
  }
} // namespace moho

namespace
{
  struct CSndVarTypeInfoBootstrap
  {
    CSndVarTypeInfoBootstrap()
    {
      (void)moho::register_CSndVarTypeInfo();
    }
  };

  [[maybe_unused]] CSndVarTypeInfoBootstrap gCSndVarTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CSndVarTypeInfo_c4ba99, moho::register_CSndVarTypeInfo)
