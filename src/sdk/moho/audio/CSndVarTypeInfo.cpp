#include "moho/audio/CSndVarTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/CSndVar.h"

namespace
{
  using TypeInfo = moho::CSndVarTypeInfo;

  alignas(TypeInfo) unsigned char gCSndVarTypeInfoStorage[sizeof(TypeInfo)];
  bool gCSndVarTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCSndVarTypeInfo() noexcept
  {
    if (!gCSndVarTypeInfoConstructed) {
      new (gCSndVarTypeInfoStorage) TypeInfo();
      gCSndVarTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCSndVarTypeInfoStorage);
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
   * Address: 0x00BF0EA0 (FUN_00BF0EA0, cleanup_CSndVarTypeInfo)
   */
  void cleanup_CSndVarTypeInfo()
  {
    if (!gCSndVarTypeInfoConstructed) {
      return;
    }

    GetCSndVarTypeInfo().~CSndVarTypeInfo();
    gCSndVarTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC6910 (FUN_00BC6910, register_CSndVarTypeInfo)
   */
  void register_CSndVarTypeInfo()
  {
    (void)GetCSndVarTypeInfo();
    (void)std::atexit(&cleanup_CSndVarTypeInfo);
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
