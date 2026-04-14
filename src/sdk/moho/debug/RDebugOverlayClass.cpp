#include "RDebugOverlayClass.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/debug/RDebugGrid.h"
#include "moho/debug/RDebugGridTypeInfo.h"
#include "moho/debug/RDebugNavSteering.h"
#include "moho/debug/RDebugNavSteeringTypeInfo.h"
#include "moho/debug/RDebugNavWaypoints.h"
#include "moho/debug/RDebugNavWaypointsTypeInfo.h"
#include "moho/debug/RDebugOverlay.h"
#include "moho/debug/RDebugOverlayClassTypeInfo.h"
#include "moho/debug/RDebugOverlayTypeInfo.h"
#include "moho/debug/RDebugRadar.h"
#include "moho/debug/RDebugRadarTypeInfo.h"
#include "moho/path/RDebugNavPath.h"
#include "moho/path/RDebugNavPathTypeInfo.h"
#include "moho/unit/core/RDebugWeapons.h"
#include "moho/unit/core/RDebugWeaponsTypeInfo.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedRDebugOverlayClassType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RDebugOverlayClass));
    }
    return sType;
  }

  [[nodiscard]] moho::TDatList<moho::RDebugOverlayClass, void>& GlobalDebugOverlayClassList()
  {
    static moho::TDatList<moho::RDebugOverlayClass, void> sOverlayClassList;
    return sOverlayClassList;
  }

  /**
   * Address: 0x00BFB730 (??1sDBGOverlays@Moho@@QAE@@Z, cleanup_sDBGOverlays)
   *
   * What it does:
   * Unlinks the global debug-overlay registry head and restores singleton
   * list state.
   */
  void cleanup_sDBGOverlays()
  {
    moho::TDatList<moho::RDebugOverlayClass, void>& overlays = GlobalDebugOverlayClassList();
    overlays.ListUnlink();
  }

  moho::RDebugGridTypeInfo* gRDebugGridTypeInfo = nullptr;
  moho::RDebugRadarTypeInfo* gRDebugRadarTypeInfo = nullptr;
  moho::RDebugNavPathTypeInfo* gRDebugNavPathTypeInfo = nullptr;
  moho::RDebugNavWaypointsTypeInfo* gRDebugNavWaypointsTypeInfo = nullptr;
  moho::RDebugNavSteeringTypeInfo* gRDebugNavSteeringTypeInfo = nullptr;
  moho::RDebugOverlayClassTypeInfo* gRDebugOverlayClassTypeInfo = nullptr;
  moho::RDebugOverlayTypeInfo* gRDebugOverlayTypeInfo = nullptr;
  moho::RDebugWeaponsTypeInfo* gRDebugWeaponsTypeInfo = nullptr;

  [[nodiscard]] moho::RDebugGridTypeInfo& GetRDebugGridTypeInfo()
  {
    if (gRDebugGridTypeInfo == nullptr) {
      gRDebugGridTypeInfo = new moho::RDebugGridTypeInfo();
    }
    return *gRDebugGridTypeInfo;
  }

  [[nodiscard]] moho::RDebugRadarTypeInfo& GetRDebugRadarTypeInfo()
  {
    if (gRDebugRadarTypeInfo == nullptr) {
      gRDebugRadarTypeInfo = new moho::RDebugRadarTypeInfo();
    }
    return *gRDebugRadarTypeInfo;
  }

  [[nodiscard]] moho::RDebugNavPathTypeInfo& GetRDebugNavPathTypeInfo()
  {
    if (gRDebugNavPathTypeInfo == nullptr) {
      gRDebugNavPathTypeInfo = new moho::RDebugNavPathTypeInfo();
    }
    return *gRDebugNavPathTypeInfo;
  }

  [[nodiscard]] moho::RDebugNavWaypointsTypeInfo& GetRDebugNavWaypointsTypeInfo()
  {
    if (gRDebugNavWaypointsTypeInfo == nullptr) {
      gRDebugNavWaypointsTypeInfo = new moho::RDebugNavWaypointsTypeInfo();
    }
    return *gRDebugNavWaypointsTypeInfo;
  }

  [[nodiscard]] moho::RDebugNavSteeringTypeInfo& GetRDebugNavSteeringTypeInfo()
  {
    if (gRDebugNavSteeringTypeInfo == nullptr) {
      gRDebugNavSteeringTypeInfo = new moho::RDebugNavSteeringTypeInfo();
    }
    return *gRDebugNavSteeringTypeInfo;
  }

  [[nodiscard]] moho::RDebugOverlayClassTypeInfo& GetRDebugOverlayClassTypeInfo()
  {
    if (gRDebugOverlayClassTypeInfo == nullptr) {
      gRDebugOverlayClassTypeInfo = new moho::RDebugOverlayClassTypeInfo();
    }
    return *gRDebugOverlayClassTypeInfo;
  }

  [[nodiscard]] moho::RDebugOverlayTypeInfo& GetRDebugOverlayTypeInfo()
  {
    if (gRDebugOverlayTypeInfo == nullptr) {
      gRDebugOverlayTypeInfo = new moho::RDebugOverlayTypeInfo();
    }
    return *gRDebugOverlayTypeInfo;
  }

  [[nodiscard]] moho::RDebugWeaponsTypeInfo& GetRDebugWeaponsTypeInfo()
  {
    if (gRDebugWeaponsTypeInfo == nullptr) {
      gRDebugWeaponsTypeInfo = new moho::RDebugWeaponsTypeInfo();
    }
    return *gRDebugWeaponsTypeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0064C170 (FUN_0064C170, ?GetClass@RDebugOverlayClass@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugOverlayClass::GetClass() const
  {
    return CachedRDebugOverlayClassType();
  }

  /**
   * Address: 0x0064C190 (FUN_0064C190, ?GetDerivedObjectRef@RDebugOverlayClass@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef RDebugOverlayClass::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0064C4D0 (FUN_0064C4D0, scalar deleting body)
   */
  RDebugOverlayClass::~RDebugOverlayClass() = default;

  /**
   * Address: 0x00651920 (FUN_00651920)
   */
  void RDebugOverlayClass::RegisterOverlayClass(const char* const overlayDescription, const char* const overlayToken)
  {
    mOverlayToken = overlayToken ? overlayToken : "";
    mOverlayDescription = overlayDescription ? overlayDescription : "";
    mOverlayClassLink.ListLinkAfter(GetDbgOverlays());
  }

  void RDebugOverlayClass::RegisterOverlayClassToken(const char* const overlayToken)
  {
    RegisterOverlayClass(GetName(), overlayToken);
  }

  /**
   * Address: 0x00651760 (FUN_00651760, GetDbgOverlays)
   *
   * What it does:
   * Lazily initializes the global active-overlay intrusive list head and
   * registers its teardown handler.
   */
  TDatListItem<RDebugOverlayClass, void>* GetDbgOverlays()
  {
    static bool sInitialized = false;
    if (!sInitialized) {
      sInitialized = true;
      GlobalDebugOverlayClassList().ListResetLinks();
      (void)std::atexit(&cleanup_sDBGOverlays);
    }
    return &GlobalDebugOverlayClassList();
  }

  /**
   * Address: 0x0064D060 (FUN_0064D060, register_RDebugGridTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugGridTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugGridTypeInfo()
  {
    auto& typeInfo = GetRDebugGridTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugGrid), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x0064D8C0 (FUN_0064D8C0, register_RDebugRadarTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugRadarTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugRadarTypeInfo()
  {
    auto& typeInfo = GetRDebugRadarTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugRadar), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00650560 (FUN_00650560, register_RDebugNavPathTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugNavPathTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugNavPathTypeInfo()
  {
    auto& typeInfo = GetRDebugNavPathTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugNavPath), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00650770 (FUN_00650770, register_RDebugNavWaypointsTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugNavWaypointsTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugNavWaypointsTypeInfo()
  {
    auto& typeInfo = GetRDebugNavWaypointsTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugNavWaypoints), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00650970 (FUN_00650970, register_RDebugNavSteeringTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugNavSteeringTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugNavSteeringTypeInfo()
  {
    auto& typeInfo = GetRDebugNavSteeringTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugNavSteering), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x006517D0 (FUN_006517D0, register_RDebugOverlayClassTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugOverlayClassTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugOverlayClassTypeInfo()
  {
    auto& typeInfo = GetRDebugOverlayClassTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugOverlayClass), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x006519D0 (FUN_006519D0, register_RDebugOverlayTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugOverlayTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugOverlayTypeInfo()
  {
    auto& typeInfo = GetRDebugOverlayTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugOverlay), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00652CD0 (FUN_00652CD0, register_RDebugWeaponsTypeInfo)
   *
   * What it does:
   * Allocates and registers the `RDebugWeaponsTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugWeaponsTypeInfo()
  {
    auto& typeInfo = GetRDebugWeaponsTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugWeapons), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFB6A0 (FUN_00BFB6A0, cleanup_RDebugGridTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugGridTypeInfo` singleton slot.
   */
  void cleanup_RDebugGridTypeInfo()
  {
    delete gRDebugGridTypeInfo;
    gRDebugGridTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB6B0 (FUN_00BFB6B0, cleanup_RDebugRadarTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugRadarTypeInfo` singleton slot.
   */
  void cleanup_RDebugRadarTypeInfo()
  {
    delete gRDebugRadarTypeInfo;
    gRDebugRadarTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB6E0 (FUN_00BFB6E0, cleanup_RDebugNavPathTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugNavPathTypeInfo` singleton slot.
   */
  void cleanup_RDebugNavPathTypeInfo()
  {
    delete gRDebugNavPathTypeInfo;
    gRDebugNavPathTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB6F0 (FUN_00BFB6F0, cleanup_RDebugNavWaypointsTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugNavWaypointsTypeInfo` singleton slot.
   */
  void cleanup_RDebugNavWaypointsTypeInfo()
  {
    delete gRDebugNavWaypointsTypeInfo;
    gRDebugNavWaypointsTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB700 (FUN_00BFB700, cleanup_RDebugNavSteeringTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugNavSteeringTypeInfo` singleton slot.
   */
  void cleanup_RDebugNavSteeringTypeInfo()
  {
    delete gRDebugNavSteeringTypeInfo;
    gRDebugNavSteeringTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB760 (FUN_00BFB760, cleanup_RDebugOverlayClassTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugOverlayClassTypeInfo` singleton slot.
   */
  void cleanup_RDebugOverlayClassTypeInfo()
  {
    delete gRDebugOverlayClassTypeInfo;
    gRDebugOverlayClassTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB7C0 (FUN_00BFB7C0, cleanup_RDebugOverlayTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugOverlayTypeInfo` singleton slot.
   */
  void cleanup_RDebugOverlayTypeInfo()
  {
    delete gRDebugOverlayTypeInfo;
    gRDebugOverlayTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BFB850 (FUN_00BFB850, cleanup_RDebugWeaponsTypeInfo)
   *
   * What it does:
   * Deletes the cached `RDebugWeaponsTypeInfo` singleton slot.
   */
  void cleanup_RDebugWeaponsTypeInfo()
  {
    delete gRDebugWeaponsTypeInfo;
    gRDebugWeaponsTypeInfo = nullptr;
  }

  /**
   * Address: 0x00BD3BC0 (FUN_00BD3BC0, register_RDebugGridTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugGridTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugGridTypeInfoStartup()
  {
    (void)register_RDebugGridTypeInfo();
    return std::atexit(&cleanup_RDebugGridTypeInfo);
  }

  /**
   * Address: 0x00BD3BE0 (FUN_00BD3BE0, register_RDebugRadarTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugRadarTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugRadarTypeInfoStartup()
  {
    (void)register_RDebugRadarTypeInfo();
    return std::atexit(&cleanup_RDebugRadarTypeInfo);
  }

  /**
   * Address: 0x00BD3C70 (FUN_00BD3C70, register_RDebugNavPathTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavPathTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugNavPathTypeInfoStartup()
  {
    (void)register_RDebugNavPathTypeInfo();
    return std::atexit(&cleanup_RDebugNavPathTypeInfo);
  }

  /**
   * Address: 0x00BD3C90 (FUN_00BD3C90, register_RDebugNavWaypointsTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavWaypointsTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugNavWaypointsTypeInfoStartup()
  {
    (void)register_RDebugNavWaypointsTypeInfo();
    return std::atexit(&cleanup_RDebugNavWaypointsTypeInfo);
  }

  /**
   * Address: 0x00BD3CB0 (FUN_00BD3CB0, register_RDebugNavSteeringTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavSteeringTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugNavSteeringTypeInfoStartup()
  {
    (void)register_RDebugNavSteeringTypeInfo();
    return std::atexit(&cleanup_RDebugNavSteeringTypeInfo);
  }

  /**
   * Address: 0x00BD3D40 (FUN_00BD3D40, register_RDebugOverlayClassTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugOverlayClassTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugOverlayClassTypeInfoStartup()
  {
    (void)register_RDebugOverlayClassTypeInfo();
    return std::atexit(&cleanup_RDebugOverlayClassTypeInfo);
  }

  /**
   * Address: 0x00BD3D60 (FUN_00BD3D60, register_RDebugOverlayTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugOverlayTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugOverlayTypeInfoStartup()
  {
    (void)register_RDebugOverlayTypeInfo();
    return std::atexit(&cleanup_RDebugOverlayTypeInfo);
  }

  /**
   * Address: 0x00BD3E60 (FUN_00BD3E60, register_RDebugWeaponsTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugWeaponsTypeInfo` and schedules its atexit cleanup.
   */
  int register_RDebugWeaponsTypeInfoStartup()
  {
    (void)register_RDebugWeaponsTypeInfo();
    return std::atexit(&cleanup_RDebugWeaponsTypeInfo);
  }
} // namespace moho

namespace
{
  struct RDebugOverlayClassTypeInfoBootstrap
  {
    RDebugOverlayClassTypeInfoBootstrap()
    {
      (void)moho::register_RDebugGridTypeInfoStartup();
      (void)moho::register_RDebugRadarTypeInfoStartup();
      (void)moho::register_RDebugNavPathTypeInfoStartup();
      (void)moho::register_RDebugNavWaypointsTypeInfoStartup();
      (void)moho::register_RDebugNavSteeringTypeInfoStartup();
      (void)moho::register_RDebugOverlayClassTypeInfoStartup();
      (void)moho::register_RDebugOverlayTypeInfoStartup();
      (void)moho::register_RDebugWeaponsTypeInfoStartup();
    }
  };

  [[maybe_unused]] const RDebugOverlayClassTypeInfoBootstrap gRDebugOverlayClassTypeInfoBootstrap{};
} // namespace
