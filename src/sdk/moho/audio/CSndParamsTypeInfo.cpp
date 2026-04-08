#include "moho/audio/CSndParamsTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/audio/CSndParams.h"

namespace
{
  using TypeInfo = moho::CSndParamsTypeInfo;

  alignas(TypeInfo) unsigned char gCSndParamsTypeInfoStorage[sizeof(TypeInfo)];
  bool gCSndParamsTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCSndParamsTypeInfo() noexcept
  {
    if (!gCSndParamsTypeInfoConstructed) {
      new (gCSndParamsTypeInfoStorage) TypeInfo();
      gCSndParamsTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCSndParamsTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004E0600 (FUN_004E0600)
   */
  CSndParamsTypeInfo::CSndParamsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSndParams), this);
  }

  /**
   * Address: 0x004E0690 (FUN_004E0690, Moho::CSndParamsTypeInfo::dtr)
   */
  CSndParamsTypeInfo::~CSndParamsTypeInfo() = default;

  /**
   * Address: 0x004E0680 (FUN_004E0680, Moho::CSndParamsTypeInfo::GetName)
   */
  const char* CSndParamsTypeInfo::GetName() const
  {
    return "CSndParams";
  }

  /**
   * Address: 0x004E0660 (FUN_004E0660, Moho::CSndParamsTypeInfo::Init)
   */
  void CSndParamsTypeInfo::Init()
  {
    size_ = sizeof(CSndParams);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BF0F60 (FUN_00BF0F60, cleanup_CSndParamsTypeInfo)
   */
  void cleanup_CSndParamsTypeInfo()
  {
    if (!gCSndParamsTypeInfoConstructed) {
      return;
    }

    GetCSndParamsTypeInfo().~CSndParamsTypeInfo();
    gCSndParamsTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC69A0 (FUN_00BC69A0, register_CSndParamsTypeInfo)
   */
  void register_CSndParamsTypeInfo()
  {
    (void)GetCSndParamsTypeInfo();
    (void)std::atexit(&cleanup_CSndParamsTypeInfo);
  }
} // namespace moho

namespace
{
  struct CSndParamsTypeInfoBootstrap
  {
    CSndParamsTypeInfoBootstrap()
    {
      moho::register_CSndParamsTypeInfo();
    }
  };

  [[maybe_unused]] CSndParamsTypeInfoBootstrap gCSndParamsTypeInfoBootstrap;
} // namespace
