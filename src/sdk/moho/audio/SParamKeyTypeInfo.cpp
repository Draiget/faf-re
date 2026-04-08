#include "moho/audio/SParamKeyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/SParamKey.h"

namespace
{
  using TypeInfo = moho::SParamKeyTypeInfo;

  alignas(TypeInfo) unsigned char gSParamKeyTypeInfoStorage[sizeof(TypeInfo)];
  bool gSParamKeyTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetSParamKeyTypeInfo() noexcept
  {
    return *reinterpret_cast<TypeInfo*>(gSParamKeyTypeInfoStorage);
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
   * Address: 0x00BF0DF0 (FUN_00BF0DF0, cleanup_SParamKeyTypeInfo)
   */
  void cleanup_SParamKeyTypeInfo()
  {
    if (!gSParamKeyTypeInfoConstructed) {
      return;
    }

    GetSParamKeyTypeInfo().~SParamKeyTypeInfo();
    gSParamKeyTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC6840 (FUN_00BC6840, register_SParamKeyTypeInfo)
   */
  int register_SParamKeyTypeInfo()
  {
    if (!gSParamKeyTypeInfoConstructed) {
      new (gSParamKeyTypeInfoStorage) SParamKeyTypeInfo();
      gSParamKeyTypeInfoConstructed = true;
    }

    return std::atexit(&cleanup_SParamKeyTypeInfo);
  }
} // namespace moho

namespace
{
  struct SParamKeyTypeInfoBootstrap
  {
    SParamKeyTypeInfoBootstrap()
    {
      (void)moho::register_SParamKeyTypeInfo();
    }
  };

  [[maybe_unused]] SParamKeyTypeInfoBootstrap gSParamKeyTypeInfoBootstrap;
} // namespace
