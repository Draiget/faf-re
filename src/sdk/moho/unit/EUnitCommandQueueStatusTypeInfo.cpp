#include "moho/unit/EUnitCommandQueueStatusTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  using EUnitCommandQueueStatusTypeInfo = moho::EUnitCommandQueueStatusTypeInfo;

  alignas(EUnitCommandQueueStatusTypeInfo) unsigned char gEUnitCommandQueueStatusTypeInfoStorage[sizeof(EUnitCommandQueueStatusTypeInfo)];
  bool gEUnitCommandQueueStatusTypeInfoConstructed = false;

  [[nodiscard]] EUnitCommandQueueStatusTypeInfo& GetEUnitCommandQueueStatusTypeInfo() noexcept
  {
    if (!gEUnitCommandQueueStatusTypeInfoConstructed) {
      new (gEUnitCommandQueueStatusTypeInfoStorage) EUnitCommandQueueStatusTypeInfo();
      gEUnitCommandQueueStatusTypeInfoConstructed = true;
    }

    return *reinterpret_cast<EUnitCommandQueueStatusTypeInfo*>(gEUnitCommandQueueStatusTypeInfoStorage);
  }

  /**
   * Address: 0x00BFEEA0 (FUN_00BFEEA0, Moho::EUnitCommandQueueStatusTypeInfo::dtr)
   *
   * What it does:
   * Tears down the enum descriptor at process exit.
   */
  void cleanup_EUnitCommandQueueStatusTypeInfo()
  {
    if (!gEUnitCommandQueueStatusTypeInfoConstructed) {
      return;
    }

    GetEUnitCommandQueueStatusTypeInfo().~EUnitCommandQueueStatusTypeInfo();
    gEUnitCommandQueueStatusTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006ED9D0 (FUN_006ED9D0, Moho::EUnitCommandQueueStatusTypeInfo::EUnitCommandQueueStatusTypeInfo)
   *
   * What it does:
   * Constructs the descriptor and preregisters it for `EUnitCommandQueueStatus`
   * RTTI lookup.
   */
  EUnitCommandQueueStatusTypeInfo::EUnitCommandQueueStatusTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EUnitCommandQueueStatus), this);
  }

  /**
   * Address: 0x00BFEEA0 (FUN_00BFEEA0, Moho::EUnitCommandQueueStatusTypeInfo::dtr)
   */
  EUnitCommandQueueStatusTypeInfo::~EUnitCommandQueueStatusTypeInfo() = default;

  /**
   * Address: 0x006EDA50 (FUN_006EDA50, Moho::EUnitCommandQueueStatusTypeInfo::GetName)
   */
  const char* EUnitCommandQueueStatusTypeInfo::GetName() const
  {
    return "EUnitCommandQueueStatus";
  }

  /**
   * Address: 0x006EDA30 (FUN_006EDA30, Moho::EUnitCommandQueueStatusTypeInfo::Init)
   */
  void EUnitCommandQueueStatusTypeInfo::Init()
  {
    size_ = sizeof(EUnitCommandQueueStatus);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD9260 (FUN_00BD9260, register_EUnitCommandQueueStatusTypeInfo)
   */
  void register_EUnitCommandQueueStatusTypeInfo()
  {
    (void)GetEUnitCommandQueueStatusTypeInfo();
    (void)std::atexit(&cleanup_EUnitCommandQueueStatusTypeInfo);
  }
} // namespace moho

namespace
{
  struct EUnitCommandQueueStatusTypeInfoBootstrap
  {
    EUnitCommandQueueStatusTypeInfoBootstrap()
    {
      moho::register_EUnitCommandQueueStatusTypeInfo();
    }
  };

  EUnitCommandQueueStatusTypeInfoBootstrap gEUnitCommandQueueStatusTypeInfoBootstrap;
} // namespace

