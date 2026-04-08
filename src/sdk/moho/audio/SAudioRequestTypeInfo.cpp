#include "moho/audio/SAudioRequestTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/SAudioRequest.h"

namespace
{
  using TypeInfo = moho::SAudioRequestTypeInfo;

  alignas(TypeInfo) unsigned char gSAudioRequestTypeInfoStorage[sizeof(TypeInfo)];
  bool gSAudioRequestTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetSAudioRequestTypeInfo() noexcept
  {
    if (!gSAudioRequestTypeInfoConstructed) {
      new (gSAudioRequestTypeInfoStorage) TypeInfo();
      gSAudioRequestTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gSAudioRequestTypeInfoStorage);
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
   * Address: 0x00BF1020 (FUN_00BF1020, cleanup_SAudioRequestTypeInfo)
   */
  void cleanup_SAudioRequestTypeInfo()
  {
    if (!gSAudioRequestTypeInfoConstructed) {
      return;
    }

    GetSAudioRequestTypeInfo().~SAudioRequestTypeInfo();
    gSAudioRequestTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC6A30 (FUN_00BC6A30, register_SAudioRequestTypeInfo)
   */
  int register_SAudioRequestTypeInfo()
  {
    (void)GetSAudioRequestTypeInfo();
    return std::atexit(&cleanup_SAudioRequestTypeInfo);
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

