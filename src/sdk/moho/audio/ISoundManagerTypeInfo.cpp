#include "moho/audio/ISoundManagerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/ISoundManager.h"

namespace
{
  using TypeInfo = moho::ISoundManagerTypeInfo;

  alignas(TypeInfo) unsigned char gISoundManagerTypeInfoStorage[sizeof(TypeInfo)];
  bool gISoundManagerTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetISoundManagerTypeInfo() noexcept
  {
    if (!gISoundManagerTypeInfoConstructed) {
      new (gISoundManagerTypeInfoStorage) TypeInfo();
      gISoundManagerTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gISoundManagerTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00760A90 (FUN_00760A90, Moho::ISoundManagerTypeInfo::ISoundManagerTypeInfo)
   */
  ISoundManagerTypeInfo::ISoundManagerTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(ISoundManager), this);
  }

  /**
   * Address: 0x00760B20 (FUN_00760B20, Moho::ISoundManagerTypeInfo::dtr)
   */
  ISoundManagerTypeInfo::~ISoundManagerTypeInfo() = default;

  /**
   * Address: 0x00760B10 (FUN_00760B10, Moho::ISoundManagerTypeInfo::GetName)
   */
  const char* ISoundManagerTypeInfo::GetName() const
  {
    return "ISoundManager";
  }

  /**
   * Address: 0x00760AF0 (FUN_00760AF0, Moho::ISoundManagerTypeInfo::Init)
   */
  void ISoundManagerTypeInfo::Init()
  {
    size_ = sizeof(ISoundManager);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00C01470 (FUN_00C01470, cleanup_ISoundManagerTypeInfo)
   *
   * What it does:
   * Releases process-exit ISoundManagerTypeInfo storage.
   */
  void cleanup_ISoundManagerTypeInfo()
  {
    if (!gISoundManagerTypeInfoConstructed) {
      return;
    }

    GetISoundManagerTypeInfo().~ISoundManagerTypeInfo();
    gISoundManagerTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BDC4A0 (FUN_00BDC4A0, register_ISoundManagerTypeInfo)
   *
   * What it does:
   * Forces ISoundManagerTypeInfo startup construction and installs process-exit
   * cleanup.
   */
  int register_ISoundManagerTypeInfo()
  {
    (void)GetISoundManagerTypeInfo();
    return std::atexit(&cleanup_ISoundManagerTypeInfo);
  }
} // namespace moho

namespace
{
  struct ISoundManagerTypeInfoBootstrap
  {
    ISoundManagerTypeInfoBootstrap()
    {
      (void)moho::register_ISoundManagerTypeInfo();
    }
  };

  [[maybe_unused]] ISoundManagerTypeInfoBootstrap gISoundManagerTypeInfoBootstrap;
} // namespace
