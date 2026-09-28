#include "RDebugOverlayClass.h"

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
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * Address: 0x00BFB6A0 (FUN_00BFB6A0, atexit destructor of the RDebugGridTypeInfo object)
   */
  [[nodiscard]] moho::RDebugGridTypeInfo& GetRDebugGridTypeInfo()
  {
    static moho::RDebugGridTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB6B0 (FUN_00BFB6B0, atexit destructor of the RDebugRadarTypeInfo object)
   */
  [[nodiscard]] moho::RDebugRadarTypeInfo& GetRDebugRadarTypeInfo()
  {
    static moho::RDebugRadarTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB6E0 (FUN_00BFB6E0, atexit destructor of the RDebugNavPathTypeInfo object)
   */
  [[nodiscard]] moho::RDebugNavPathTypeInfo& GetRDebugNavPathTypeInfo()
  {
    static moho::RDebugNavPathTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB6F0 (FUN_00BFB6F0, atexit destructor of the RDebugNavWaypointsTypeInfo object)
   */
  [[nodiscard]] moho::RDebugNavWaypointsTypeInfo& GetRDebugNavWaypointsTypeInfo()
  {
    static moho::RDebugNavWaypointsTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB700 (FUN_00BFB700, atexit destructor of the RDebugNavSteeringTypeInfo object)
   */
  [[nodiscard]] moho::RDebugNavSteeringTypeInfo& GetRDebugNavSteeringTypeInfo()
  {
    static moho::RDebugNavSteeringTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB760 (FUN_00BFB760, atexit destructor of the RDebugOverlayClassTypeInfo object)
   */
  [[nodiscard]] moho::RDebugOverlayClassTypeInfo& GetRDebugOverlayClassTypeInfo()
  {
    static moho::RDebugOverlayClassTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB7C0 (FUN_00BFB7C0, atexit destructor of the RDebugOverlayTypeInfo object)
   */
  [[nodiscard]] moho::RDebugOverlayTypeInfo& GetRDebugOverlayTypeInfo()
  {
    static moho::RDebugOverlayTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFB850 (FUN_00BFB850, atexit destructor of the RDebugWeaponsTypeInfo object)
   */
  [[nodiscard]] moho::RDebugWeaponsTypeInfo& GetRDebugWeaponsTypeInfo()
  {
    static moho::RDebugWeaponsTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0064C3C0 (FUN_0064C3C0, Moho::RDebugOverlayClass::RDebugOverlayClass)
   */
  RDebugOverlayClass::RDebugOverlayClass()
    : gpg::RType()
    , mOverlayClassPad0064(0)
    , mOverlayClassLink()
    , mOverlayToken()
    , mOverlayDescription()
  {}

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
   * Address: 0x0064C400 (FUN_0064C400, non-deleting destructor body)
   * Thunk entry: 0x0064C4D0 (FUN_0064C4D0, scalar deleting destructor)
   */
  RDebugOverlayClass::~RDebugOverlayClass()
  {
    mOverlayDescription.assign_owned("");
    mOverlayToken.assign_owned("");
    fields_ = {};
    bases_ = {};
  }

  // Addresses 0x0064C4C0/0x0064D170/0x0064D9D0/0x00650670/0x00650880
  // ("ThunkA" through "ThunkE", five compiled duplicates of the same
  // one-line dtor-call formerly modeled here) are dead: zero data_refs/
  // call_edges for all five, and no source-level caller anywhere in
  // src/sdk/**. RDebugOverlayClass::~RDebugOverlayClass above (0x0064C400,
  // with a separate scalar-deleting-destructor bridge at 0x0064C4D0, not
  // one of these five) is the real, C++-guaranteed destructor.

  /**
   * Address: 0x00651920 (FUN_00651920)
   */
  void RDebugOverlayClass::RegisterOverlayClass(const char* const overlayDescription, const char* const overlayToken)
  {
    mOverlayToken = overlayToken ? overlayToken : "";
    mOverlayDescription = overlayDescription ? overlayDescription : "";
    // 0x006519A4: unlink, then link before the head (appends).
    mOverlayClassLink.ListLinkBefore(&GetDbgOverlays());
  }

  void RDebugOverlayClass::RegisterOverlayClassToken(const char* const overlayToken)
  {
    RegisterOverlayClass(GetName(), overlayToken);
  }

  /**
   * Address: 0x00651760 (FUN_00651760, GetDbgOverlays)
   * Address: 0x00651F20 (FUN_00651F20, the static's constructor out of line:
   *   self-link the head; zero callers)
   * Address: 0x00BFB730 (FUN_00BFB730, the static's `atexit` destructor:
   *   unlink and self-link the head; formerly `cleanup_sDBGOverlays`)
   * Address: 0x006517A0 (FUN_006517A0, byte-identical copy of that
   *   destructor; zero callers)
   *
   * What it does:
   * Returns the registry of debug-overlay classes (`sDBGOverlays`).
   */
  TDatList<RDebugOverlayClass, void>& GetDbgOverlays()
  {
    static TDatList<RDebugOverlayClass, void> sDBGOverlays;
    return sDBGOverlays;
  }

  /**
   * Address: 0x0064D060 (FUN_0064D060, register_RDebugGridTypeInfo)
   *
   * What it does:
   * Constructs and registers the `RDebugGridTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugRadarTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugNavPathTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugNavWaypointsTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugNavSteeringTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugOverlayClassTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugOverlayTypeInfo` reflection object.
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
   * Constructs and registers the `RDebugWeaponsTypeInfo` reflection object.
   */
  gpg::RType* register_RDebugWeaponsTypeInfo()
  {
    auto& typeInfo = GetRDebugWeaponsTypeInfo();
    gpg::PreRegisterRType(typeid(moho::RDebugWeapons), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BD3BC0 (FUN_00BD3BC0, register_RDebugGridTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugGridTypeInfo`.
   */
  void register_RDebugGridTypeInfoStartup()
  {
    (void)register_RDebugGridTypeInfo();
  }

  /**
   * Address: 0x00BD3BE0 (FUN_00BD3BE0, register_RDebugRadarTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugRadarTypeInfo`.
   */
  void register_RDebugRadarTypeInfoStartup()
  {
    (void)register_RDebugRadarTypeInfo();
  }

  /**
   * Address: 0x00BD3C70 (FUN_00BD3C70, register_RDebugNavPathTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavPathTypeInfo`.
   */
  void register_RDebugNavPathTypeInfoStartup()
  {
    (void)register_RDebugNavPathTypeInfo();
  }

  /**
   * Address: 0x00BD3C90 (FUN_00BD3C90, register_RDebugNavWaypointsTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavWaypointsTypeInfo`.
   */
  void register_RDebugNavWaypointsTypeInfoStartup()
  {
    (void)register_RDebugNavWaypointsTypeInfo();
  }

  /**
   * Address: 0x00BD3CB0 (FUN_00BD3CB0, register_RDebugNavSteeringTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugNavSteeringTypeInfo`.
   */
  void register_RDebugNavSteeringTypeInfoStartup()
  {
    (void)register_RDebugNavSteeringTypeInfo();
  }

  /**
   * Address: 0x00BD3D40 (FUN_00BD3D40, register_RDebugOverlayClassTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugOverlayClassTypeInfo`.
   */
  void register_RDebugOverlayClassTypeInfoStartup()
  {
    (void)register_RDebugOverlayClassTypeInfo();
  }

  /**
   * Address: 0x00BD3D60 (FUN_00BD3D60, register_RDebugOverlayTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugOverlayTypeInfo`.
   */
  void register_RDebugOverlayTypeInfoStartup()
  {
    (void)register_RDebugOverlayTypeInfo();
  }

  /**
   * Address: 0x00BD3E60 (FUN_00BD3E60, register_RDebugWeaponsTypeInfoStartup)
   *
   * What it does:
   * Registers `RDebugWeaponsTypeInfo`.
   */
  void register_RDebugWeaponsTypeInfoStartup()
  {
    (void)register_RDebugWeaponsTypeInfo();
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RDebugGridTypeInfoStartup_e193c2, moho::register_RDebugGridTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugRadarTypeInfoStartup_e193c2, moho::register_RDebugRadarTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugNavPathTypeInfoStartup_e193c2, moho::register_RDebugNavPathTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugNavWaypointsTypeInfoStartup_e193c2, moho::register_RDebugNavWaypointsTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugNavSteeringTypeInfoStartup_e193c2, moho::register_RDebugNavSteeringTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugOverlayClassTypeInfoStartup_e193c2, moho::register_RDebugOverlayClassTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugOverlayTypeInfoStartup_e193c2, moho::register_RDebugOverlayTypeInfoStartup)
GPG_PREREGISTER_INIT(register_RDebugWeaponsTypeInfoStartup_e193c2, moho::register_RDebugWeaponsTypeInfoStartup)

GPG_PREREGISTER_INIT(register_RDebugGridTypeInfo_e193c2, moho::register_RDebugGridTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugRadarTypeInfo_e193c2, moho::register_RDebugRadarTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugNavPathTypeInfo_e193c2, moho::register_RDebugNavPathTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugNavWaypointsTypeInfo_e193c2, moho::register_RDebugNavWaypointsTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugNavSteeringTypeInfo_e193c2, moho::register_RDebugNavSteeringTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugOverlayClassTypeInfo_e193c2, moho::register_RDebugOverlayClassTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugOverlayTypeInfo_e193c2, moho::register_RDebugOverlayTypeInfo)
GPG_PREREGISTER_INIT(register_RDebugWeaponsTypeInfo_e193c2, moho::register_RDebugWeaponsTypeInfo)
