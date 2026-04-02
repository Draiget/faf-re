#include "moho/command/CCommandDbTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/command/CCommandDb.h"

namespace
{
  alignas(moho::CCommandDBTypeInfo) unsigned char gCCommandDBTypeInfoStorage[sizeof(moho::CCommandDBTypeInfo)];
  bool gCCommandDBTypeInfoConstructed = false;

  [[nodiscard]] moho::CCommandDBTypeInfo& GetCCommandDBTypeInfo() noexcept
  {
    if (!gCCommandDBTypeInfoConstructed) {
      new (gCCommandDBTypeInfoStorage) moho::CCommandDBTypeInfo();
      gCCommandDBTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::CCommandDBTypeInfo*>(gCCommandDBTypeInfoStorage);
  }

  /**
   * Address: 0x00BFE940 (FUN_00BFE940, sub_BFE940)
   *
   * What it does:
   * Releases recovered `CCommandDBTypeInfo` field/base vector lanes at exit.
   */
  void cleanup_CCommandDBTypeInfo()
  {
    if (!gCCommandDBTypeInfoConstructed) {
      return;
    }

    moho::CCommandDBTypeInfo& typeInfo = GetCCommandDBTypeInfo();
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006E0880 (FUN_006E0880, sub_6E0880)
   */
  CCommandDBTypeInfo::CCommandDBTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CCommandDb), this);
  }

  /**
   * Address: 0x006E0910 (FUN_006E0910, Moho::CCommandDBTypeInfo::dtr)
   */
  CCommandDBTypeInfo::~CCommandDBTypeInfo() = default;

  /**
   * Address: 0x006E0900 (FUN_006E0900, Moho::CCommandDBTypeInfo::GetName)
   */
  const char* CCommandDBTypeInfo::GetName() const
  {
    return "CCommandDB";
  }

  /**
   * Address: 0x006E08E0 (FUN_006E08E0, Moho::CCommandDBTypeInfo::Init)
   */
  void CCommandDBTypeInfo::Init()
  {
    size_ = sizeof(CCommandDb);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD8C40 (FUN_00BD8C40, sub_BD8C40)
   */
  int register_CCommandDBTypeInfo()
  {
    (void)GetCCommandDBTypeInfo();
    return std::atexit(&cleanup_CCommandDBTypeInfo);
  }
} // namespace moho

namespace
{
  struct CCommandDBTypeInfoBootstrap
  {
    CCommandDBTypeInfoBootstrap()
    {
      (void)moho::register_CCommandDBTypeInfo();
    }
  };

  CCommandDBTypeInfoBootstrap gCCommandDBTypeInfoBootstrap;
} // namespace
