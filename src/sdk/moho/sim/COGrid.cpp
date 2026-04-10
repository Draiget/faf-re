#include "moho/sim/COGrid.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::COGridTypeInfo;

  alignas(TypeInfo) unsigned char gCOGridTypeInfoStorage[sizeof(TypeInfo)];
  bool gCOGridTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCOGridTypeInfo() noexcept
  {
    if (!gCOGridTypeInfoConstructed) {
      new (gCOGridTypeInfoStorage) TypeInfo();
      gCOGridTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCOGridTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00722B80 (FUN_00722B80, Moho::COGridTypeInfo::COGridTypeInfo)
   */
  COGridTypeInfo::COGridTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(COGrid), this);
  }

  /**
   * Address: 0x00722C10 (FUN_00722C10, Moho::COGridTypeInfo::dtr)
   */
  COGridTypeInfo::~COGridTypeInfo() = default;

  /**
   * Address: 0x00722C00 (FUN_00722C00, Moho::COGridTypeInfo::GetName)
   */
  const char* COGridTypeInfo::GetName() const
  {
    return "COGrid";
  }

  /**
   * Address: 0x00722BE0 (FUN_00722BE0, Moho::COGridTypeInfo::Init)
   */
  void COGridTypeInfo::Init()
  {
    size_ = sizeof(COGrid);
    gpg::RType::Init();
    Finish();
  }

  /**
   * What it does:
   * Releases startup-owned `COGridTypeInfo` storage at process teardown.
   */
  void cleanup_COGridTypeInfo()
  {
    if (!gCOGridTypeInfoConstructed) {
      return;
    }

    GetCOGridTypeInfo().~COGridTypeInfo();
    gCOGridTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BDAA90 (FUN_00BDAA90, register_COGridTypeInfo)
   */
  int register_COGridTypeInfo()
  {
    (void)GetCOGridTypeInfo();
    return std::atexit(&cleanup_COGridTypeInfo);
  }
} // namespace moho

namespace
{
  struct COGridTypeInfoBootstrap
  {
    COGridTypeInfoBootstrap()
    {
      (void)moho::register_COGridTypeInfo();
    }
  };

  [[maybe_unused]] COGridTypeInfoBootstrap gCOGridTypeInfoBootstrap;
} // namespace
