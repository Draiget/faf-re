#include "moho/entity/CollisionBeamStartupRegistrations.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/console/CConCommand.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  void LoadAndBroadcastManyToOneListenerECollisionBeamEvent(
    gpg::ReadArchive* archive,
    moho::ManyToOneBroadcaster<moho::ECollisionBeamEvent>* broadcaster,
    int version,
    gpg::RRef* ownerRef
  );

  void SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive,
    std::uint32_t* intrusiveListHeadSlot
  );
} // namespace gpg

namespace moho
{
  bool dbg_CollisionBeam = false;

  float gCollisionBeamConeCosine = 0.0f;
  float gCollisionBeamConeAxisScaleX = 0.0f;
  float gCollisionBeamConeSine = 0.0f;
  float gCollisionBeamConeAxisScaleY = 0.0f;

  gpg::RType* ManyToOneBroadcaster_ECollisionBeamEvent::sType = nullptr;
} // namespace moho

namespace
{
  gpg::RType* gCollisionBeamEventType = nullptr;

  [[nodiscard]] gpg::RType* LookupCollisionBeamEventType()
  {
    if (gCollisionBeamEventType == nullptr) {
      gCollisionBeamEventType = gpg::LookupRType(typeid(moho::ECollisionBeamEvent));
    }
    return gCollisionBeamEventType;
  }

  [[nodiscard]] const char* GetCollisionBeamEventTypeName()
  {
    const gpg::RType* const type = LookupCollisionBeamEventType();
    return type ? type->GetName() : "ECollisionBeamEvent";
  }

  msvc8::string gManyToOneBroadcasterCollisionBeamEventTypeName;
  bool gManyToOneBroadcasterCollisionBeamEventTypeNameCleanupRegistered = false;

  msvc8::string gManyToOneListenerCollisionBeamEventTypeName;
  bool gManyToOneListenerCollisionBeamEventTypeNameCleanupRegistered = false;

  void cleanup_ManyToOneBroadcasterCollisionBeamEventTypeName()
  {
    gManyToOneBroadcasterCollisionBeamEventTypeName = msvc8::string{};
    gManyToOneBroadcasterCollisionBeamEventTypeNameCleanupRegistered = false;
  }

  void cleanup_ManyToOneListenerCollisionBeamEventTypeName()
  {
    gManyToOneListenerCollisionBeamEventTypeName = msvc8::string{};
    gManyToOneListenerCollisionBeamEventTypeNameCleanupRegistered = false;
  }

  class RManyToOneBroadcasterCollisionBeamEventTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00674740 (FUN_00674740, Moho::RManyBroadcasterRType_ECollisionBeamEvent::GetName)
     *
     * What it does:
     * Lazily caches the lexical reflection name for the collision-beam
     * many-to-one broadcaster type descriptor.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if (gManyToOneBroadcasterCollisionBeamEventTypeName.empty()) {
        gManyToOneBroadcasterCollisionBeamEventTypeName =
          gpg::STR_Printf("ManyToOneBroadcaster<%s>", GetCollisionBeamEventTypeName());
        if (!gManyToOneBroadcasterCollisionBeamEventTypeNameCleanupRegistered) {
          gManyToOneBroadcasterCollisionBeamEventTypeNameCleanupRegistered = true;
          (void)std::atexit(&cleanup_ManyToOneBroadcasterCollisionBeamEventTypeName);
        }
      }

      return gManyToOneBroadcasterCollisionBeamEventTypeName.c_str();
    }

    /**
     * Address: 0x006747E0 (FUN_006747E0, Moho::RManyBroadcasterRType_ECollisionBeamEvent::Init)
     *
     * What it does:
     * Binds serializer load/save callback lanes and version metadata for
     * `ManyToOneBroadcaster<ECollisionBeamEvent>` reflection: `size_ = 8`,
     * `version_ = 1`, `serLoadFunc_` at +0x1C installs
     * `LoadAndBroadcastManyToOneListenerECollisionBeamEvent`
     * (`FUN_00675140`), `serSaveFunc_` at +0x14 installs
     * `SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1`
     * (`FUN_00675170`). Matches the sibling
     * `RManyToOneBroadcasterProjectileImpactTypeInfo::Init` shape exactly
     * (same field offsets, same 8-byte broadcaster object).
     */
    void Init() override
    {
      size_ = sizeof(moho::ManyToOneBroadcaster_ECollisionBeamEvent);
      version_ = 1;
      serLoadFunc_ = reinterpret_cast<gpg::RType::load_func_t>(
        &gpg::LoadAndBroadcastManyToOneListenerECollisionBeamEvent
      );
      serSaveFunc_ = reinterpret_cast<gpg::RType::save_func_t>(
        &gpg::SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1
      );
    }
  };

  class RManyToOneListenerCollisionBeamEventTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00674800 (FUN_00674800, Moho::RManyListenerRType_ECollisionBeamEvent::GetName)
     *
     * What it does:
     * Lazily caches the lexical reflection name for the collision-beam many-
     * to-one listener type descriptor.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if (gManyToOneListenerCollisionBeamEventTypeName.empty()) {
        gManyToOneListenerCollisionBeamEventTypeName =
          gpg::STR_Printf("ManyToOneListener<%s>", GetCollisionBeamEventTypeName());
        if (!gManyToOneListenerCollisionBeamEventTypeNameCleanupRegistered) {
          gManyToOneListenerCollisionBeamEventTypeNameCleanupRegistered = true;
          (void)std::atexit(&cleanup_ManyToOneListenerCollisionBeamEventTypeName);
        }
      }

      return gManyToOneListenerCollisionBeamEventTypeName.c_str();
    }

    void Init() override
    {
      size_ = sizeof(moho::ManyToOneListener_ECollisionBeamEvent);
      gpg::RType::Init();
      Finish();
    }
  };

  alignas(moho::ECollisionBeamEventTypeInfo)
    unsigned char gECollisionBeamEventTypeInfoStorage[sizeof(moho::ECollisionBeamEventTypeInfo)];
  bool gECollisionBeamEventTypeInfoConstructed = false;

  alignas(RManyToOneBroadcasterCollisionBeamEventTypeInfo)
    unsigned char gManyToOneBroadcasterCollisionBeamEventTypeInfoStorage[sizeof(RManyToOneBroadcasterCollisionBeamEventTypeInfo)];
  bool gManyToOneBroadcasterCollisionBeamEventTypeInfoConstructed = false;

  alignas(RManyToOneListenerCollisionBeamEventTypeInfo)
    unsigned char gManyToOneListenerCollisionBeamEventTypeInfoStorage[sizeof(RManyToOneListenerCollisionBeamEventTypeInfo)];
  bool gManyToOneListenerCollisionBeamEventTypeInfoConstructed = false;

  [[nodiscard]] moho::ECollisionBeamEventTypeInfo& ECollisionBeamEventTypeInfoStorageRef()
  {
    return *reinterpret_cast<moho::ECollisionBeamEventTypeInfo*>(gECollisionBeamEventTypeInfoStorage);
  }

  [[nodiscard]] RManyToOneBroadcasterCollisionBeamEventTypeInfo& ManyToOneBroadcasterTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneBroadcasterCollisionBeamEventTypeInfo*>(gManyToOneBroadcasterCollisionBeamEventTypeInfoStorage);
  }

  [[nodiscard]] RManyToOneListenerCollisionBeamEventTypeInfo& ManyToOneListenerTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneListenerCollisionBeamEventTypeInfo*>(gManyToOneListenerCollisionBeamEventTypeInfoStorage);
  }

  [[nodiscard]] gpg::REnumType* ConstructECollisionBeamEventTypeInfo()
  {
    if (!gECollisionBeamEventTypeInfoConstructed) {
      new (gECollisionBeamEventTypeInfoStorage) moho::ECollisionBeamEventTypeInfo();
      gECollisionBeamEventTypeInfoConstructed = true;
    }

    auto& typeInfo = ECollisionBeamEventTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::ECollisionBeamEvent), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00675990 (FUN_00675990, sub_675990)
   *
   * What it does:
   * Constructs/preregisters startup RTTI for
   * `ManyToOneBroadcaster<ECollisionBeamEvent>` and updates the lane `sType`.
   */
  [[nodiscard]] gpg::RType* ConstructManyToOneBroadcasterCollisionBeamEventTypeInfo()
  {
    if (!gManyToOneBroadcasterCollisionBeamEventTypeInfoConstructed) {
      new (gManyToOneBroadcasterCollisionBeamEventTypeInfoStorage) RManyToOneBroadcasterCollisionBeamEventTypeInfo();
      gManyToOneBroadcasterCollisionBeamEventTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneBroadcasterTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::ManyToOneBroadcaster_ECollisionBeamEvent), &typeInfo);
    moho::ManyToOneBroadcaster_ECollisionBeamEvent::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x006759F0 (FUN_006759F0, sub_6759F0)
   *
   * What it does:
   * Constructs/preregisters startup RTTI for
   * `ManyToOneListener<ECollisionBeamEvent>` and updates the lane `sType`.
   */
  [[nodiscard]] gpg::RType* ConstructManyToOneListenerCollisionBeamEventTypeInfo()
  {
    if (!gManyToOneListenerCollisionBeamEventTypeInfoConstructed) {
      new (gManyToOneListenerCollisionBeamEventTypeInfoStorage) RManyToOneListenerCollisionBeamEventTypeInfo();
      gManyToOneListenerCollisionBeamEventTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneListenerTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::ManyToOneListener_ECollisionBeamEvent), &typeInfo);
    moho::ManyToOneListener_ECollisionBeamEvent::sType = &typeInfo;
    return &typeInfo;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgCollisionBeamConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_CollisionBeam",
      "Enable collision beam debug diagnostics",
      &moho::dbg_CollisionBeam
    );
    return conVar;
  }

  /**
   * Address: 0x00BFC2A0 (FUN_00BFC2A0, Moho::TConVar_dbg_CollisionBeam::~TConVar_dbg_CollisionBeam)
   *
   * What it does:
   * Tears down the static `dbg_CollisionBeam` console-variable registration via
   * the shared `TeardownConCommandRegistration` helper. Registered via
   * `atexit` from the convar startup path.
   */
  void cleanup_TConVar_dbg_CollisionBeam_atexit()
  {
    moho::TeardownConCommandRegistration(GetDbgCollisionBeamConVar());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD4BA0 (FUN_00BD4BA0, register_TConVar_dbg_CollisionBeam)
   */
  void register_TConVar_dbg_CollisionBeam()
  {
    RegisterConCommand(GetDbgCollisionBeamConVar());
    (void)std::atexit(&cleanup_TConVar_dbg_CollisionBeam_atexit);
  }

  /**
   * Address: 0x00BD4B40 (FUN_00BD4B40, initialize_CollisionBeamTrigConstants)
   */
  void initialize_CollisionBeamTrigConstants()
  {
    constexpr float kCollisionBeamConeHalfAngleRadians = 0.39269909f;
    const float sinValue = std::sinf(kCollisionBeamConeHalfAngleRadians);
    gCollisionBeamConeCosine = std::cosf(kCollisionBeamConeHalfAngleRadians);
    gCollisionBeamConeSine = sinValue;

    // Preserve original lane (`sinValue * 0.0f`) including signed-zero behavior.
    const float axisScale = sinValue * 0.0f;
    gCollisionBeamConeAxisScaleX = axisScale;
    gCollisionBeamConeAxisScaleY = axisScale;
  }

  /**
   * Address: 0x00672CC0 (FUN_00672CC0, Moho::ECollisionBeamEventTypeInfo::ECollisionBeamEventTypeInfo)
   */
  ECollisionBeamEventTypeInfo::ECollisionBeamEventTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ECollisionBeamEvent), this);
  }

  /**
   * Address: 0x00BFC2D0 (FUN_00BFC2D0, Moho::ECollisionBeamEventTypeInfo::dtr)
   * Address: 0x00672D50 (FUN_00672D50, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ECollisionBeamEventTypeInfo::~ECollisionBeamEventTypeInfo() = default;

  /**
   * Address: 0x00672D40 (FUN_00672D40, Moho::ECollisionBeamEventTypeInfo::GetName)
   */
  const char* ECollisionBeamEventTypeInfo::GetName() const
  {
    return "ECollisionBeamEvent";
  }

  /**
   * Address: 0x00672D20 (FUN_00672D20, Moho::ECollisionBeamEventTypeInfo::Init)
   */
  void ECollisionBeamEventTypeInfo::Init()
  {
    size_ = sizeof(ECollisionBeamEvent);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x00672D80 (FUN_00672D80, Moho::ECollisionBeamEventTypeInfo::AddEnums)
   */
  void ECollisionBeamEventTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->mPrefix = "COLLISIONBEAMEVENT_";
    typeInfo->AddEnum(typeInfo->StripPrefix("COLLISIONBEAMEVENT_HitTarget"), CollisionBeamEvent_HitTarget);
    typeInfo->AddEnum(typeInfo->StripPrefix("COLLISIONBEAMEVENT_MissTarget"), CollisionBeamEvent_MissTarget);
    typeInfo->AddEnum(typeInfo->StripPrefix("COLLISIONBEAMEVENT_Irrelavent"), CollisionBeamEvent_Irrelavent);
  }

  /**
   * Address: 0x00BFC2D0 (FUN_00BFC2D0, cleanup_ECollisionBeamEventTypeInfo)
   */
  void cleanup_ECollisionBeamEventTypeInfo()
  {
    if (!gECollisionBeamEventTypeInfoConstructed) {
      return;
    }

    ECollisionBeamEventTypeInfoStorageRef().~ECollisionBeamEventTypeInfo();
    gECollisionBeamEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4C20 (FUN_00BD4C20, register_ECollisionBeamEventTypeInfo)
   */
  void register_ECollisionBeamEventTypeInfo()
  {
    (void)ConstructECollisionBeamEventTypeInfo();
    (void)std::atexit(&cleanup_ECollisionBeamEventTypeInfo);
  }

  /**
   * Address: 0x00BFC5B0 (FUN_00BFC5B0, cleanup_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo)
   */
  void cleanup_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo()
  {
    if (!gManyToOneBroadcasterCollisionBeamEventTypeInfoConstructed) {
      return;
    }

    ManyToOneBroadcasterTypeInfoStorageRef().~RManyToOneBroadcasterCollisionBeamEventTypeInfo();
    gManyToOneBroadcasterCollisionBeamEventTypeInfoConstructed = false;
    ManyToOneBroadcaster_ECollisionBeamEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD4D90 (FUN_00BD4D90, register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo)
   */
  int register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo()
  {
    (void)ConstructManyToOneBroadcasterCollisionBeamEventTypeInfo();
    return std::atexit(&cleanup_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo);
  }

  /**
   * Address: 0x00BFC550 (FUN_00BFC550, cleanup_ManyToOneListener_ECollisionBeamEvent_TypeInfo)
   */
  void cleanup_ManyToOneListener_ECollisionBeamEvent_TypeInfo()
  {
    if (!gManyToOneListenerCollisionBeamEventTypeInfoConstructed) {
      return;
    }

    ManyToOneListenerTypeInfoStorageRef().~RManyToOneListenerCollisionBeamEventTypeInfo();
    gManyToOneListenerCollisionBeamEventTypeInfoConstructed = false;
    ManyToOneListener_ECollisionBeamEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD4DB0 (FUN_00BD4DB0, register_ManyToOneListener_ECollisionBeamEvent_TypeInfo)
   */
  int register_ManyToOneListener_ECollisionBeamEvent_TypeInfo()
  {
    (void)ConstructManyToOneListenerCollisionBeamEventTypeInfo();
    return std::atexit(&cleanup_ManyToOneListener_ECollisionBeamEvent_TypeInfo);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00675140 (FUN_00675140, gpg::LoadAndBroadcastManyToOneListenerECollisionBeamEvent)
   *
   * IDA signature:
   * int __cdecl sub_675140(gpg::ReadArchive *a1, int result, int a3, struct gpg::RRef *a4);
   *
   * What it does:
   * The `serLoadFunc_` lane `RManyToOneBroadcasterCollisionBeamEventTypeInfo::Init`
   * (FUN_006747E0) binds at +0x1C. Reads the archive's tracked pointer back as a
   * `ManyToOneListener<ECollisionBeamEvent>` and hands it to the broadcaster,
   * which re-points its owner-link slot at the restored node. The version word
   * is not consulted -- the lane has only ever had one layout. Matches the
   * sibling `gpg::LoadAndBroadcastManyToOneListenerEProjectileImpactEvent`
   * shape exactly (`ProjectileStartupRegistrations.cpp`).
   */
  void LoadAndBroadcastManyToOneListenerECollisionBeamEvent(
    ReadArchive* const archive,
    moho::ManyToOneBroadcaster<moho::ECollisionBeamEvent>* const broadcaster,
    const int version,
    RRef* const ownerRef
  )
  {
    (void)version;

    moho::ManyToOneListener<moho::ECollisionBeamEvent>* listener = nullptr;
    (void)archive->ReadPointer_ManyToOneListener_ECollisionBeamEvent(&listener, ownerRef);
    broadcaster->BroadcastEvent(listener);
  }
} // namespace gpg

namespace
{
  struct CollisionBeamStartupRegistrationsBootstrap
  {
    CollisionBeamStartupRegistrationsBootstrap()
    {
      moho::initialize_CollisionBeamTrigConstants();
      moho::register_TConVar_dbg_CollisionBeam();
      (void)moho::register_ECollisionBeamEventTypeInfo();
      (void)moho::register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo();
      (void)moho::register_ManyToOneListener_ECollisionBeamEvent_TypeInfo();
    }
  };

  [[maybe_unused]] CollisionBeamStartupRegistrationsBootstrap gCollisionBeamStartupRegistrationsBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ECollisionBeamEventTypeInfo_f04c7b, moho::register_ECollisionBeamEventTypeInfo)
GPG_PREREGISTER_INIT(register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo_f04c7b, moho::register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo)
GPG_PREREGISTER_INIT(register_ManyToOneListener_ECollisionBeamEvent_TypeInfo_f04c7b, moho::register_ManyToOneListener_ECollisionBeamEvent_TypeInfo)

GPG_PREREGISTER_INIT(ConstructECollisionBeamEventTypeInfo_f04c7b, ConstructECollisionBeamEventTypeInfo)
GPG_PREREGISTER_INIT(ConstructManyToOneBroadcasterCollisionBeamEventTypeInfo_f04c7b, ConstructManyToOneBroadcasterCollisionBeamEventTypeInfo)
GPG_PREREGISTER_INIT(ConstructManyToOneListenerCollisionBeamEventTypeInfo_f04c7b, ConstructManyToOneListenerCollisionBeamEventTypeInfo)
