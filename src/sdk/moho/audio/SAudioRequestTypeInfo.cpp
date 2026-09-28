#include "moho/audio/SAudioRequestTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/SAudioRequest.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::SAudioRequestTypeInfo;

  /**
   * Address: 0x00BF1020 (FUN_00BF1020, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetSAudioRequestTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004E0F00 (FUN_004E0F00, Moho::SAudioRequestTypeInfo::SAudioRequestTypeInfo)
   */
  SAudioRequestTypeInfo::SAudioRequestTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SAudioRequest), this);
  }

  /**
   * Address: 0x004E0F90 (FUN_004E0F90, Moho::SAudioRequestTypeInfo::dtr)
   */
  SAudioRequestTypeInfo::~SAudioRequestTypeInfo() = default;

  /**
   * Address: 0x004E0F80 (FUN_004E0F80, Moho::SAudioRequestTypeInfo::GetName)
   */
  const char* SAudioRequestTypeInfo::GetName() const
  {
    return "SAudioRequest";
  }

  /**
   * Address: 0x004E0F60 (FUN_004E0F60, Moho::SAudioRequestTypeInfo::Init)
   */
  void SAudioRequestTypeInfo::Init()
  {
    size_ = sizeof(SAudioRequest);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC6A30 (FUN_00BC6A30, register_SAudioRequestTypeInfo)
   */
  void register_SAudioRequestTypeInfo()
  {
    (void)GetSAudioRequestTypeInfo();
  }
} // namespace moho

namespace
{
  struct SAudioRequestTypeInfoBootstrap
  {
    SAudioRequestTypeInfoBootstrap()
    {
      (void)moho::register_SAudioRequestTypeInfo();
    }
  };

  [[maybe_unused]] SAudioRequestTypeInfoBootstrap gSAudioRequestTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SAudioRequestTypeInfo_9a8385, moho::register_SAudioRequestTypeInfo)
