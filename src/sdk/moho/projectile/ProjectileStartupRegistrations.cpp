#include "moho/projectile/ProjectileStartupRegistrations.h"

#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/console/CConCommand.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/projectile/Projectile.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/Sim.h"

#pragma init_seg(lib)

namespace gpg
{
  void LoadAndBroadcastManyToOneListenerEProjectileImpactEvent(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef
  );

  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive,
    std::uint32_t* intrusiveListHeadSlot
  );
} // namespace gpg

namespace moho
{
  bool dbg_Projectile = false;
  gpg::RType* CProjectileAttributes::sType = nullptr;
  gpg::RType* ManyToOneBroadcaster<EProjectileImpactEvent>::sType = nullptr;
  gpg::RType* ManyToOneListener<EProjectileImpactEvent>::sType = nullptr;
  CScrLuaMetatableFactory<Projectile> CScrLuaMetatableFactory<Projectile>::sInstance{};
} // namespace moho

namespace
{
  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgProjectileConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_Projectile",
      "Enable projectile debug diagnostics",
      &moho::dbg_Projectile
    );
    return conVar;
  }

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kSetDamageHelpText =
    "Projectile:SetDamage(amount, radius) -- change how much damage this projectile will"
    " do. Either amount or radius can be nil to leave unchanged.";
  constexpr const char* kGetLauncherHelpText = "Get who launched this projectile";
  constexpr const char* kGetTrackingTargetHelpText = "Projectile:GetTrackingTarget()";
  constexpr const char* kGetCurrentTargetPositionHelpText = "Projectile:GetCurrentTargetPosition()";
  constexpr const char* kSetNewTargetHelpText = "Projectile:SetNewTarget( entity )";
  constexpr const char* kSetNewTargetGroundHelpText = "Projectile:SetNewTargetGround( location )";
  constexpr const char* kSetLifetimeHelpText = "Projectile:SetLifetime(seconds)";
  constexpr const char* kSetMaxSpeedHelpText = "Projectile:SetMaxSpeed(speed)";
  constexpr const char* kSetAccelerationHelpText = "Projectile:SetAcceleration(accel)";
  constexpr const char* kSetBallisticAccelerationArgCountError =
    "Wrong number of arguments to Projectile:SetAccelerationVector(), expected 1, 2, or 4 but got %d";
  constexpr const char* kSetDestroyOnWaterHelpText = "Projectile:SetDestroyOnWater(flag)";
  constexpr const char* kSetTurnRateHelpText = "Projectile:SetTurnRate(radians_per_second)";
  constexpr const char* kGetCurrentSpeedHelpText = "Projectile:GetCurrentSpeed() -> val";
  constexpr const char* kGetVelocityHelpText = "Projectile:GetVelocity() -> x,y,z";
  constexpr const char* kSetVelocityHelpText = "Projectile:SetVelocity(speed) or Projectile:SetVelocity(vx,vy,vz)";
  constexpr const char* kSetVelocityArgCountError =
    "Wrong number of arguments to Projectile:SetVelocity(x,y,z), expected 2 or 4 but got %d";
  constexpr const char* kSetScaleVelocityHelpText =
    "Projectile:SetScaleVelocity(vs) or Projectile:SetScaleVelocity(vsx, vsy, vsz)";
  constexpr const char* kSetScaleVelocityArgCountError =
    "Wrong number of arguments to Projectile:SetScaleVelocity, expected 2 or 4 but got %d";
  constexpr const char* kSetLocalAngularVelocityHelpText = "Projectile:SetLocalAngularVelocity(x,y,z)";
  constexpr const char* kSetCollisionHelpText = "Projectile:SetCollision(onoff)";
  constexpr const char* kSetCollideSurfaceHelpText = "Projectile:SetCollideSurface(onoff)";
  constexpr const char* kSetCollideEntityHelpText = "Projectile:SetCollideEntity(onoff)";
  constexpr const char* kStayUnderwaterHelpText = "Projectile:StayUnderwater(onoff)";
  constexpr const char* kTrackTargetHelpText = "Projectile:TrackTarget(onoff)";
  constexpr const char* kSetStayUprightHelpText = "Projectile:SetStayUpright(truefalse)";
  constexpr const char* kSetVelocityAlignHelpText = "Projectile:SetVelocityAlign(truefalse)";
  constexpr const char* kCreateChildProjectileHelpText = "Projectile:CreateChildProjectile(blueprint)";
  constexpr const char* kSetVelocityRandomUpVectorHelpText = "SetVelocityRandomUpVector(self)";
  constexpr const char* kChangeMaxZigZagHelpText = "Change the amount of zig zag";
  constexpr const char* kChangeZigZagFrequencyHelpText = "Change the frequency of the zig zag";
  constexpr const char* kChangeDetonateAboveHeightHelpText = "Change the detonate above height for the projectile";
  constexpr const char* kChangeDetonateBelowHeightHelpText = "Change the detonate below height for the projectile";
  constexpr const char* kMissingProjectileBlueprintError =
    "Blueprint for projectile %s not found!, returning a nil object instead";

  /**
   * Address: 0x006A1370 (FUN_006A1370)
   *
   * What it does:
   * Clears and reassigns one destination string from projectile
   * `mDamageTypeName`.
   */
  [[maybe_unused]] msvc8::string* CopyProjectileDamageTypeNameRuntime(
    const moho::Projectile* const projectile,
    msvc8::string* const outName
  )
  {
    if (outName == nullptr) {
      return nullptr;
    }

    outName->clear();
    if (projectile != nullptr) {
      *outName = projectile->mDamageTypeName;
    }
    return outName;
  }

  struct ProjectileVelocityRuntimeView
  {
    std::uint8_t mUnknown0000[0x280];
    Wm3::Vector3f mVelocity;
  };
  static_assert(
    offsetof(ProjectileVelocityRuntimeView, mVelocity) == 0x280,
    "ProjectileVelocityRuntimeView::mVelocity offset must be 0x280"
  );
  static_assert(sizeof(ProjectileVelocityRuntimeView) == 0x28C, "ProjectileVelocityRuntimeView size must be 0x28C");

  struct ProjectileTargetingRuntimeView
  {
    std::uint8_t mUnknown0000[0x278];
    moho::WeakPtr<moho::Entity> mLauncherWeak; // +0x278
    std::uint8_t mUnknown0280[0x28];
    bool mCollideSurface; // +0x2A8
    bool mDoCollision;    // +0x2A9
    bool mTrackTarget;    // +0x2AA
    bool mVelocityAlign;  // +0x2AB
    bool mStayUpright;    // +0x2AC
    bool mLeadTarget;     // +0x2AD
    bool mStayUnderwater; // +0x2AE
  };
  static_assert(
    offsetof(ProjectileTargetingRuntimeView, mLauncherWeak) == 0x278,
    "ProjectileTargetingRuntimeView::mLauncherWeak offset must be 0x278"
  );
  static_assert(
    offsetof(ProjectileTargetingRuntimeView, mTrackTarget) == 0x2AA,
    "ProjectileTargetingRuntimeView::mTrackTarget offset must be 0x2AA"
  );
  static_assert(
    offsetof(ProjectileTargetingRuntimeView, mStayUnderwater) == 0x2AE,
    "ProjectileTargetingRuntimeView::mStayUnderwater offset must be 0x2AE"
  );
  static_assert(sizeof(ProjectileTargetingRuntimeView) == 0x2B0, "ProjectileTargetingRuntimeView size must be 0x2B0");

  struct ProjectileMotionControlRuntimeView
  {
    std::uint8_t mUnknown0000[0x2B0];
    float mTurnRateDegrees; // +0x2B0
    float mMaxSpeed;        // +0x2B4
    float mAcceleration;    // +0x2B8
    Wm3::Vector3f mBallisticAcceleration; // +0x2BC
  };
  static_assert(
    offsetof(ProjectileMotionControlRuntimeView, mTurnRateDegrees) == 0x2B0,
    "ProjectileMotionControlRuntimeView::mTurnRateDegrees offset must be 0x2B0"
  );
  static_assert(
    offsetof(ProjectileMotionControlRuntimeView, mMaxSpeed) == 0x2B4,
    "ProjectileMotionControlRuntimeView::mMaxSpeed offset must be 0x2B4"
  );
  static_assert(
    offsetof(ProjectileMotionControlRuntimeView, mAcceleration) == 0x2B8,
    "ProjectileMotionControlRuntimeView::mAcceleration offset must be 0x2B8"
  );
  static_assert(
    offsetof(ProjectileMotionControlRuntimeView, mBallisticAcceleration) == 0x2BC,
    "ProjectileMotionControlRuntimeView::mBallisticAcceleration offset must be 0x2BC"
  );
  static_assert(
    sizeof(ProjectileMotionControlRuntimeView) == 0x2C8,
    "ProjectileMotionControlRuntimeView size must be 0x2C8"
  );

  struct ProjectileWaterBehaviorRuntimeView
  {
    std::uint8_t mUnknown0000[0x2AF];
    bool mDestroyOnWater; // +0x2AF
  };
  static_assert(
    offsetof(ProjectileWaterBehaviorRuntimeView, mDestroyOnWater) == 0x2AF,
    "ProjectileWaterBehaviorRuntimeView::mDestroyOnWater offset must be 0x2AF"
  );
  static_assert(
    sizeof(ProjectileWaterBehaviorRuntimeView) == 0x2B0,
    "ProjectileWaterBehaviorRuntimeView size must be 0x2B0"
  );

  struct ProjectileAttributesRuntimeView
  {
    std::uint8_t mUnknown0000[0x368];
    moho::CProjectileAttributes mAttributes; // +0x368
  };
  static_assert(
    offsetof(ProjectileAttributesRuntimeView, mAttributes) == 0x368,
    "ProjectileAttributesRuntimeView::mAttributes offset must be 0x368"
  );
  static_assert(
    sizeof(ProjectileAttributesRuntimeView) == 0x37C,
    "ProjectileAttributesRuntimeView size must be 0x37C"
  );

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("sim");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] ProjectileVelocityRuntimeView& AccessProjectileVelocityView(moho::Projectile& projectile) noexcept
  {
    return *reinterpret_cast<ProjectileVelocityRuntimeView*>(&projectile);
  }

  [[nodiscard]] ProjectileTargetingRuntimeView& AccessProjectileTargetingView(moho::Projectile& projectile) noexcept
  {
    return *reinterpret_cast<ProjectileTargetingRuntimeView*>(&projectile);
  }

  [[nodiscard]] ProjectileMotionControlRuntimeView&
  AccessProjectileMotionControlView(moho::Projectile& projectile) noexcept
  {
    return *reinterpret_cast<ProjectileMotionControlRuntimeView*>(&projectile);
  }

  [[nodiscard]] ProjectileWaterBehaviorRuntimeView&
  AccessProjectileWaterBehaviorView(moho::Projectile& projectile) noexcept
  {
    return *reinterpret_cast<ProjectileWaterBehaviorRuntimeView*>(&projectile);
  }

  [[nodiscard]] moho::CProjectileAttributes&
  AccessProjectileAttributesView(moho::Projectile& projectile) noexcept
  {
    return reinterpret_cast<ProjectileAttributesRuntimeView*>(&projectile)->mAttributes;
  }

  /**
   * Address: 0x006A11C0 (FUN_006A11C0)
   *
   * What it does:
   * Writes projectile collide-entity enable lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileCollideEntity(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mDoCollision = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A11D0 (FUN_006A11D0)
   *
   * What it does:
   * Writes projectile collide-surface enable lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileCollideSurface(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mCollideSurface = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A11E0 (FUN_006A11E0)
   *
   * What it does:
   * Writes projectile target-tracking enable lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileTrackTarget(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mTrackTarget = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A11F0 (FUN_006A11F0)
   *
   * What it does:
   * Writes projectile stay-underwater lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileStayUnderwater(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mStayUnderwater = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A1200 (FUN_006A1200)
   *
   * What it does:
   * Writes projectile stay-upright enable lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileStayUpright(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mStayUpright = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A1210 (FUN_006A1210)
   *
   * What it does:
   * Writes projectile velocity-alignment enable lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileVelocityAlign(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileTargetingView(*projectile).mVelocityAlign = enabled;
    return projectile;
  }

  /**
   * Address: 0x006A1220 (FUN_006A1220)
   *
   * What it does:
   * Writes projectile destroy-on-water lane.
   */
  [[maybe_unused]] moho::Projectile* SetProjectileDestroyOnWater(
    moho::Projectile* const projectile,
    const bool enabled
  ) noexcept
  {
    AccessProjectileWaterBehaviorView(*projectile).mDestroyOnWater = enabled;
    return projectile;
  }

  [[nodiscard]] float ReadProjectileRandomUpSpeed(const moho::Projectile& projectile) noexcept
  {
    const auto* const blueprint = static_cast<const moho::RProjectileBlueprint*>(projectile.BluePrint);
    if (blueprint == nullptr) {
      return 0.0f;
    }

    return blueprint->Physics.MaxSpeed;
  }

  void SetVectorLengthIfNonZero(Wm3::Vector3f& value, const float length) noexcept
  {
    const float magnitudeSquared = (value.x * value.x) + (value.y * value.y) + (value.z * value.z);
    if (magnitudeSquared <= 0.0f) {
      return;
    }

    const float scale = length / std::sqrt(magnitudeSquared);
    value.x *= scale;
    value.y *= scale;
    value.z *= scale;
  }

  [[nodiscard]] gpg::RType* CachedRProjectileBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCProjectileAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CProjectileAttributes));
    }
    return cached;
  }

  [[nodiscard]] moho::RProjectileBlueprint* ReadProjectileBlueprintPointer(
    gpg::ReadArchive* archive,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRProjectileBlueprintType());
    GPG_ASSERT(upcast.mObj != nullptr);
    return static_cast<moho::RProjectileBlueprint*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RRef MakeProjectileBlueprintRef(moho::RProjectileBlueprint* blueprint)
  {
    gpg::RRef ref{};
    ref.mObj = blueprint;
    ref.mType = CachedRProjectileBlueprintType();
    return ref;
  }

  class RManyToOneBroadcasterProjectileImpactTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0069FBC0 (FUN_0069FBC0, Moho::RManyBroadcasterRType_EProjectileImpactEvent::RManyBroadcasterRType_EProjectileImpactEvent)
     *
     * What it does:
     * Preregisters `ManyToOneBroadcaster<EProjectileImpactEvent>` reflection
     * metadata at startup.
     */
    RManyToOneBroadcasterProjectileImpactTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(moho::ManyToOneBroadcaster_EProjectileImpactEvent), this);
    }

    /**
     * Address: 0x0069FC80 (FUN_0069FC80, Moho::RManyBroadcasterRType_EProjectileImpactEvent::dtr)
     *
     * What it does:
     * Tears down one broadcaster type-info descriptor and releases inherited
     * `gpg::RType` reflection storage lanes.
     */
    ~RManyToOneBroadcasterProjectileImpactTypeInfo() override;

    [[nodiscard]] const char* GetName() const override
    {
      return "ManyToOneBroadcaster<EProjectileImpactEvent>";
    }

    /**
     * Address: 0x0069EA10 (FUN_0069EA10)
     *
     * What it does:
     * Binds serializer load/save callback lanes and version metadata for
     * `ManyToOneBroadcaster<EProjectileImpactEvent>` reflection.
     */
    void Init() override
    {
      size_ = 0x08;
      version_ = 1;
      serLoadFunc_ = reinterpret_cast<gpg::RType::load_func_t>(
        &gpg::LoadAndBroadcastManyToOneListenerEProjectileImpactEvent
      );
      serSaveFunc_ = reinterpret_cast<gpg::RType::save_func_t>(
        &gpg::SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1
      );
    }
  };

  class RManyToOneListenerProjectileImpactTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0069FC20 (FUN_0069FC20, Moho::RManyListenerRType_EProjectileImpactEvent::RManyListenerRType_EProjectileImpactEvent)
     *
     * What it does:
     * Preregisters `ManyToOneListener<EProjectileImpactEvent>` reflection
     * metadata at startup.
     */
    RManyToOneListenerProjectileImpactTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(moho::ManyToOneListener_EProjectileImpactEvent), this);
    }

    /**
     * Address: 0x0069FCE0 (FUN_0069FCE0, Moho::RManyListenerRType_EProjectileImpactEvent::dtr)
     *
     * What it does:
     * Tears down one listener type-info descriptor and releases inherited
     * `gpg::RType` reflection storage lanes.
     */
    ~RManyToOneListenerProjectileImpactTypeInfo() override;

    [[nodiscard]] const char* GetName() const override
    {
      return "ManyToOneListener<EProjectileImpactEvent>";
    }

    /**
     * Address: 0x0069EAD0 (FUN_0069EAD0)
     *
     * What it does:
     * Sets the reflected runtime object size for
     * `ManyToOneListener<EProjectileImpactEvent>`.
     */
    void Init() override
    {
      size_ = 0x08;
    }
  };

  /**
   * Address: 0x0069FC80 (FUN_0069FC80, Moho::RManyBroadcasterRType_EProjectileImpactEvent::dtr)
   *
   * What it does:
   * Tears down one broadcaster type-info descriptor and releases inherited
   * `gpg::RType` reflection storage lanes.
   */
  RManyToOneBroadcasterProjectileImpactTypeInfo::~RManyToOneBroadcasterProjectileImpactTypeInfo() = default;

  /**
   * Address: 0x0069FCE0 (FUN_0069FCE0, Moho::RManyListenerRType_EProjectileImpactEvent::dtr)
   *
   * What it does:
   * Tears down one listener type-info descriptor and releases inherited
   * `gpg::RType` reflection storage lanes.
   */
  RManyToOneListenerProjectileImpactTypeInfo::~RManyToOneListenerProjectileImpactTypeInfo() = default;

  template <typename TEnum>
  class PrimitiveEnumSerializer
  {
  public:
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mHelperNext) == 0x04,
    "PrimitiveEnumSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mHelperPrev) == 0x08,
    "PrimitiveEnumSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mDeserialize) == 0x0C,
    "PrimitiveEnumSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mSerialize) == 0x10,
    "PrimitiveEnumSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>) == 0x14,
    "PrimitiveEnumSerializer size must be 0x14"
  );

  alignas(moho::EProjectileImpactEventTypeInfo)
    unsigned char gEProjectileImpactEventTypeInfoStorage[sizeof(moho::EProjectileImpactEventTypeInfo)];
  bool gEProjectileImpactEventTypeInfoConstructed = false;

  alignas(moho::CProjectileAttributesTypeInfo)
    unsigned char gCProjectileAttributesTypeInfoStorage[sizeof(moho::CProjectileAttributesTypeInfo)];
  bool gCProjectileAttributesTypeInfoConstructed = false;

  alignas(moho::CProjectileAttributesSerializer)
    unsigned char gCProjectileAttributesSerializerStorage[sizeof(moho::CProjectileAttributesSerializer)];
  bool gCProjectileAttributesSerializerConstructed = false;

  alignas(RManyToOneBroadcasterProjectileImpactTypeInfo)
    unsigned char gManyToOneBroadcasterProjectileImpactTypeInfoStorage[sizeof(RManyToOneBroadcasterProjectileImpactTypeInfo)];
  bool gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = false;

  alignas(RManyToOneListenerProjectileImpactTypeInfo)
    unsigned char gManyToOneListenerProjectileImpactTypeInfoStorage[sizeof(RManyToOneListenerProjectileImpactTypeInfo)];
  bool gManyToOneListenerProjectileImpactTypeInfoConstructed = false;

  PrimitiveEnumSerializer<moho::EProjectileImpactEvent> gEProjectileImpactEventPrimitiveSerializer{};

  [[nodiscard]] moho::EProjectileImpactEventTypeInfo& EProjectileImpactEventTypeInfoStorageRef()
  {
    return *reinterpret_cast<moho::EProjectileImpactEventTypeInfo*>(gEProjectileImpactEventTypeInfoStorage);
  }

  [[nodiscard]] moho::CProjectileAttributesTypeInfo& CProjectileAttributesTypeInfoStorageRef()
  {
    return *reinterpret_cast<moho::CProjectileAttributesTypeInfo*>(gCProjectileAttributesTypeInfoStorage);
  }

  [[nodiscard]] moho::CProjectileAttributesSerializer& CProjectileAttributesSerializerStorageRef()
  {
    return *reinterpret_cast<moho::CProjectileAttributesSerializer*>(gCProjectileAttributesSerializerStorage);
  }

  [[nodiscard]] RManyToOneBroadcasterProjectileImpactTypeInfo& ManyToOneBroadcasterTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneBroadcasterProjectileImpactTypeInfo*>(gManyToOneBroadcasterProjectileImpactTypeInfoStorage);
  }

  [[nodiscard]] RManyToOneListenerProjectileImpactTypeInfo& ManyToOneListenerTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneListenerProjectileImpactTypeInfo*>(gManyToOneListenerProjectileImpactTypeInfoStorage);
  }

  [[nodiscard]] gpg::REnumType* ConstructEProjectileImpactEventTypeInfo()
  {
    if (!gEProjectileImpactEventTypeInfoConstructed) {
      new (gEProjectileImpactEventTypeInfoStorage) moho::EProjectileImpactEventTypeInfo();
      gEProjectileImpactEventTypeInfoConstructed = true;
    }

    auto& typeInfo = EProjectileImpactEventTypeInfoStorageRef();
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructCProjectileAttributesTypeInfo()
  {
    if (!gCProjectileAttributesTypeInfoConstructed) {
      new (gCProjectileAttributesTypeInfoStorage) moho::CProjectileAttributesTypeInfo();
      gCProjectileAttributesTypeInfoConstructed = true;
    }

    auto& typeInfo = CProjectileAttributesTypeInfoStorageRef();
    moho::CProjectileAttributes::sType = &typeInfo;
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructManyToOneBroadcasterProjectileImpactTypeInfo()
  {
    if (!gManyToOneBroadcasterProjectileImpactTypeInfoConstructed) {
      new (gManyToOneBroadcasterProjectileImpactTypeInfoStorage) RManyToOneBroadcasterProjectileImpactTypeInfo();
      gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneBroadcasterTypeInfoStorageRef();
    moho::ManyToOneBroadcaster_EProjectileImpactEvent::sType = &typeInfo;
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructManyToOneListenerProjectileImpactTypeInfo()
  {
    if (!gManyToOneListenerProjectileImpactTypeInfoConstructed) {
      new (gManyToOneListenerProjectileImpactTypeInfoStorage) RManyToOneListenerProjectileImpactTypeInfo();
      gManyToOneListenerProjectileImpactTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneListenerTypeInfoStorageRef();
    moho::ManyToOneListener_EProjectileImpactEvent::sType = &typeInfo;
    return &typeInfo;
  }

} // namespace

/**
 * Address: 0x005DC230 (FUN_005DC230, Moho::ManyToOneBroadcaster_EProjectileImpactEvent::BroadcastEvent)
 *
 * What it does:
 * Rebinds one projectile-impact broadcaster node to the supplied listener
 * chain head while preserving intrusive owner-chain integrity.
 */
void moho::ManyToOneBroadcaster<moho::EProjectileImpactEvent>::BroadcastEvent(
  moho::ManyToOneListener_EProjectileImpactEvent* const listener
)
{
  void** const newOwnerLinkSlot = listener != nullptr
    ? reinterpret_cast<void**>(static_cast<moho::WeakObject*>(listener)->WeakLinkHeadSlot())
    : nullptr;
  void** const currentOwnerLinkSlot = static_cast<void**>(ownerLinkSlot);
  if (newOwnerLinkSlot == currentOwnerLinkSlot) {
    return;
  }

  if (currentOwnerLinkSlot != nullptr) {
    void** cursor = currentOwnerLinkSlot;
    while (static_cast<moho::ManyToOneBroadcaster_EProjectileImpactEvent*>(*cursor) != this) {
      cursor = &static_cast<moho::ManyToOneBroadcaster_EProjectileImpactEvent*>(*cursor)->nextInOwner;
    }
    *cursor = nextInOwner;
  }

  ownerLinkSlot = newOwnerLinkSlot;
  if (newOwnerLinkSlot != nullptr) {
    nextInOwner = *newOwnerLinkSlot;
    *newOwnerLinkSlot = this;
  } else {
    nextInOwner = nullptr;
  }
}

namespace
{

  /**
   * Address: 0x0069EEC0 (FUN_0069EEC0)
   */
  void Deserialize_EProjectileImpactEvent_Primitive(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::EProjectileImpactEvent*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::EProjectileImpactEvent>(value);
  }

  /**
   * Address: 0x0069EEE0 (FUN_0069EEE0)
   */
  void Serialize_EProjectileImpactEvent_Primitive(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const moho::EProjectileImpactEvent*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0069F470 (FUN_0069F470)
   */
  void Deserialize_CProjectileAttributesBody(
    gpg::ReadArchive* archive,
    moho::CProjectileAttributes& attributes,
    const gpg::RRef& ownerRef
  )
  {
    attributes.mBlueprint = ReadProjectileBlueprintPointer(archive, ownerRef);
    archive->ReadFloat(&attributes.mMaxZigZag);
    archive->ReadFloat(&attributes.mZigZagFrequency);
    archive->ReadFloat(&attributes.mDetonateAboveHeight);
    archive->ReadFloat(&attributes.mDetonateBelowHeight);
  }

  /**
   * Address: 0x0069F4D0 (FUN_0069F4D0)
   */
  void Serialize_CProjectileAttributesBody(
    gpg::WriteArchive* archive,
    const moho::CProjectileAttributes& attributes,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef blueprintRef = MakeProjectileBlueprintRef(attributes.mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WriteFloat(attributes.mMaxZigZag);
    archive->WriteFloat(attributes.mZigZagFrequency);
    archive->WriteFloat(attributes.mDetonateAboveHeight);
    archive->WriteFloat(attributes.mDetonateBelowHeight);
  }

  void cleanup_EProjectileImpactEventPrimitiveSerializer_atexit()
  {
    (void)moho::cleanup_EProjectileImpactEventPrimitiveSerializer();
  }

  void cleanup_CProjectileAttributesSerializer_atexit()
  {
    (void)moho::cleanup_CProjectileAttributesSerializer();
  }

  /**
   * Address: 0x0069A9F0 (FUN_0069A9F0)
   *
   * What it does:
   * Unlinks global `CProjectileAttributesSerializer` helper links and resets
   * the node to the canonical self-linked state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCProjectileAttributesSerializerHelperNodePrimary() noexcept
  {
    return UnlinkSerializerNode(CProjectileAttributesSerializerStorageRef());
  }

  /**
   * Address: 0x0069AA20 (FUN_0069AA20)
   *
   * What it does:
   * Secondary unlink/reset entry for the global
   * `CProjectileAttributesSerializer` helper node.
   */
  [[nodiscard, maybe_unused]] gpg::SerHelperBase* UnlinkCProjectileAttributesSerializerHelperNodeSecondary() noexcept
  {
    return UnlinkSerializerNode(CProjectileAttributesSerializerStorageRef());
  }

  struct ProjectileStartupBootstrap
  {
    ProjectileStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_Projectile_Index();
      moho::register_TConVar_dbg_Projectile();
      (void)moho::register_EProjectileImpactEventTypeInfo();
      (void)moho::register_EProjectileImpactEventPrimitiveSerializer();
      (void)moho::register_CProjectileAttributesTypeInfo();
      (void)moho::register_CProjectileAttributesSerializer();
      (void)moho::register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo();
      (void)moho::register_ManyToOneListener_EProjectileImpactEvent_TypeInfo();
    }
  };

  [[maybe_unused]] ProjectileStartupBootstrap gProjectileStartupBootstrap;

  template <typename TEnum>
  void PrimitiveEnumSerializer<TEnum>::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = gpg::LookupRType(typeid(TEnum));
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0067FFE0 (FUN_0067FFE0, Moho::CScrLuaMetatableFactory<Moho::Projectile>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<Projectile>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<Projectile>& CScrLuaMetatableFactory<Projectile>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x0067F0E0 (FUN_0067F0E0, func_GetProjectileFactory)
   *
   * What it does:
   * Returns cached `Projectile` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject*
  func_GetProjectileFactory(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<Projectile>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00BD50D0 (FUN_00BD50D0, register_CScrLuaMetatableFactory_Projectile_Index)
   *
   * What it does:
   * Allocates one factory-object index and assigns it to projectile metatable factory singleton.
   */
  int register_CScrLuaMetatableFactory_Projectile_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<Projectile>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x006A0FB0 (FUN_006A0FB0, Moho::PROJ_Create)
   *
   * What it does:
   * Allocates one projectile and forwards launch parameters into the
   * projectile constructor path.
   */
  Projectile* PROJ_Create(
    Sim* const sim,
    const RProjectileBlueprint* const blueprint,
    CArmyImpl* const army,
    Entity* const sourceEntity,
    const VTransform& launchTransform,
    const float damage,
    const float damageRadius,
    const msvc8::string& damageTypeName,
    const CAiTarget& target,
    const bool isChildProjectile
  )
  {
    if (blueprint == nullptr) {
      return nullptr;
    }

    return new Projectile(
      blueprint,
      sim,
      army,
      sourceEntity,
      launchTransform,
      damage,
      damageRadius,
      damageTypeName,
      target,
      isChildProjectile
    );
  }

  int cfunc_ProjectileGetLauncher(lua_State* luaContext);
  int cfunc_ProjectileGetLauncherL(LuaPlus::LuaState* state);
  int cfunc_ProjectileGetTrackingTarget(lua_State* luaContext);
  int cfunc_ProjectileGetTrackingTargetL(LuaPlus::LuaState* state);
  int cfunc_ProjectileGetCurrentTargetPosition(lua_State* luaContext);
  int cfunc_ProjectileGetCurrentTargetPositionL(LuaPlus::LuaState* state);
  int cfunc_ProjectileSetNewTarget(lua_State* luaContext);
  int cfunc_ProjectileSetNewTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A13B0 (FUN_006A13B0, cfunc_ProjectileGetLauncher)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileGetLauncherL`.
   */
  int cfunc_ProjectileGetLauncher(lua_State* const luaContext)
  {
    return cfunc_ProjectileGetLauncherL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1430 (FUN_006A1430, cfunc_ProjectileGetLauncherL)
   *
   * What it does:
   * Reads one projectile from Lua and pushes its launcher entity Lua object when
   * available; otherwise pushes `nil`.
   */
  int cfunc_ProjectileGetLauncherL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetLauncherHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    Entity* const launcher = projectile->GetLauncherEntity();
    if (launcher != nullptr) {
      launcher->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x006A13D0 (FUN_006A13D0, func_ProjectileGetLauncher_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetLauncher()` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetLauncher_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetLauncher",
      &moho::cfunc_ProjectileGetLauncher,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kGetLauncherHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1510 (FUN_006A1510, cfunc_ProjectileGetTrackingTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileGetTrackingTargetL`.
   */
  int cfunc_ProjectileGetTrackingTarget(lua_State* const luaContext)
  {
    return cfunc_ProjectileGetTrackingTargetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1590 (FUN_006A1590, cfunc_ProjectileGetTrackingTargetL)
   *
   * What it does:
   * Reads one projectile and pushes its current tracking-target entity Lua
   * object when tracking is enabled and target data resolves; otherwise pushes
   * `nil`.
   */
  int cfunc_ProjectileGetTrackingTargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetTrackingTargetHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    Entity* trackingTarget = nullptr;
    ProjectileTargetingRuntimeView& targetingView = AccessProjectileTargetingView(*projectile);
    if (targetingView.mTrackTarget && projectile->mTargetPosData.HasTarget()) {
      trackingTarget = projectile->mTargetPosData.GetEntity();
    }

    if (trackingTarget != nullptr) {
      trackingTarget->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x006A1530 (FUN_006A1530, func_ProjectileGetTrackingTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetTrackingTarget()` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetTrackingTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetTrackingTarget",
      &moho::cfunc_ProjectileGetTrackingTarget,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kGetTrackingTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1680 (FUN_006A1680, cfunc_ProjectileGetCurrentTargetPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileGetCurrentTargetPositionL`.
   */
  int cfunc_ProjectileGetCurrentTargetPosition(lua_State* const luaContext)
  {
    return cfunc_ProjectileGetCurrentTargetPositionL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1700 (FUN_006A1700, cfunc_ProjectileGetCurrentTargetPositionL)
   *
   * What it does:
   * Reads one projectile, resolves one current target-position vector, and
   * pushes that vector in Lua table form.
   */
  int cfunc_ProjectileGetCurrentTargetPositionL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentTargetPositionHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    Wm3::Vector3f targetPosition(0.0f, 0.0f, 0.0f);
    if (projectile->mTargetPosData.targetType != EAiTargetType::AITARGET_None) {
      targetPosition = projectile->mTargetPosData.GetTargetPosGun(false);
    }

    LuaPlus::LuaObject targetPositionObject = SCR_ToLua<Wm3::Vector3<float>>(state, targetPosition);
    targetPositionObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A16A0 (FUN_006A16A0, func_ProjectileGetCurrentTargetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetCurrentTargetPosition()` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetCurrentTargetPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetCurrentTargetPosition",
      &moho::cfunc_ProjectileGetCurrentTargetPosition,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kGetCurrentTargetPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1820 (FUN_006A1820, cfunc_ProjectileSetNewTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetNewTargetL`.
   */
  int cfunc_ProjectileSetNewTarget(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetNewTargetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A18A0 (FUN_006A18A0, cfunc_ProjectileSetNewTargetL)
   *
   * What it does:
   * Reads `(projectile, entity)` from Lua and rewrites projectile target data
   * to one entity-tracking target payload.
   */
  int cfunc_ProjectileSetNewTargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetNewTargetHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetEntityObject, state);

    CAiTarget targetData;
    targetData.UpdateTarget(targetEntity);
    projectile->mTargetPosData = targetData;
    return 0;
  }

  /**
   * Address: 0x006A1840 (FUN_006A1840, func_ProjectileSetNewTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetNewTarget(entity)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetNewTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetNewTarget",
      &moho::cfunc_ProjectileSetNewTarget,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetNewTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1A40 (FUN_006A1A40, cfunc_ProjectileSetNewTargetGroundL)
   *
   * What it does:
   * Reads `(projectile, location)` from Lua and rewrites projectile target data
   * to one ground target at the supplied world-space location.
   */
  int cfunc_ProjectileSetNewTargetGroundL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetNewTargetGroundHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f location = SCR_FromLuaCopy<Wm3::Vector3f>(locationObject);

    CAiTarget newTarget{};
    newTarget.position = location;
    newTarget.targetPoint = -1;
    newTarget.targetType = EAiTargetType::AITARGET_Ground;
    newTarget.targetEntity.ClearLinkState();
    newTarget.targetIsMobile = false;

    projectile->mTargetPosData = newTarget;
    return 0;
  }

  /**
   * Address: 0x006A19C0 (FUN_006A19C0, cfunc_ProjectileSetNewTargetGround)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetNewTargetGroundL`.
   */
  int cfunc_ProjectileSetNewTargetGround(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetNewTargetGroundL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A19E0 (FUN_006A19E0, func_ProjectileSetNewTargetGround_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetNewTargetGround(location)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetNewTargetGround_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetNewTargetGround",
      &moho::cfunc_ProjectileSetNewTargetGround,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetNewTargetGroundHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1C10 (FUN_006A1C10, cfunc_ProjectileSetLifetimeL)
   *
   * What it does:
   * Reads `(projectile, seconds)` from Lua, stores the computed lifetime-end
   * tick (`mCurTick + seconds*10`), and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetLifetimeL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetLifetimeHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject lifetimeArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&lifetimeArg, "number");
    }

    projectile->SetLifetime(static_cast<float>(lua_tonumber(rawState, 2)));
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A1B90 (FUN_006A1B90, cfunc_ProjectileSetLifetime)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetLifetimeL`.
   */
  int cfunc_ProjectileSetLifetime(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetLifetimeL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1BB0 (FUN_006A1BB0, func_ProjectileSetLifetime_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetLifetime(seconds)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetLifetime_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetLifetime",
      &moho::cfunc_ProjectileSetLifetime,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetLifetimeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1DB0 (FUN_006A1DB0, cfunc_ProjectileSetDamageL)
   *
   * What it does:
   * Reads optional `(amount, radius)` number lanes from Lua and assigns each
   * non-nil lane to projectile damage storage.
   */
  int cfunc_ProjectileSetDamageL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state,
        kLuaExpectedBetweenArgsWarning,
        kSetDamageHelpText,
        2,
        3,
        argumentCount
      );
    }

    lua_settop(rawState, 3);

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    if (lua_type(rawState, 2) != LUA_TNIL) {
      LuaPlus::LuaStackObject amountArg(state, 2);
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&amountArg, "number");
      }
      projectile->mDamage = static_cast<float>(lua_tonumber(rawState, 2));
    }

    if (lua_type(rawState, 3) != LUA_TNIL) {
      LuaPlus::LuaStackObject radiusArg(state, 3);
      if (lua_type(rawState, 3) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
      }
      // Binary stores both optional arguments into the same `mDamage` lane.
      projectile->mDamage = static_cast<float>(lua_tonumber(rawState, 3));
    }

    return 0;
  }

  /**
   * Address: 0x006A1D30 (FUN_006A1D30, cfunc_ProjectileSetDamage)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetDamageL`.
   */
  int cfunc_ProjectileSetDamage(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetDamageL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1D50 (FUN_006A1D50, func_ProjectileSetDamage_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetDamage(amount, radius)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetDamage_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetDamage",
      &moho::cfunc_ProjectileSetDamage,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetDamageHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A1F90 (FUN_006A1F90, cfunc_ProjectileSetMaxSpeedL)
   *
   * What it does:
   * Reads `(projectile, speed)` from Lua, writes projectile max-speed lane,
   * and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetMaxSpeedL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetMaxSpeedHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject speedArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&speedArg, "number");
    }

    AccessProjectileMotionControlView(*projectile).mMaxSpeed = static_cast<float>(lua_tonumber(rawState, 2));
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A1F10 (FUN_006A1F10, cfunc_ProjectileSetMaxSpeed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetMaxSpeedL`.
   */
  int cfunc_ProjectileSetMaxSpeed(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetMaxSpeedL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A1F30 (FUN_006A1F30, func_ProjectileSetMaxSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetMaxSpeed(speed)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetMaxSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetMaxSpeed",
      &moho::cfunc_ProjectileSetMaxSpeed,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetMaxSpeedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2110 (FUN_006A2110, cfunc_ProjectileSetAccelerationL)
   *
   * What it does:
   * Reads `(projectile, acceleration)` from Lua, writes projectile
   * acceleration lane, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetAccelerationL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAccelerationHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject accelerationArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&accelerationArg, "number");
    }

    AccessProjectileMotionControlView(*projectile).mAcceleration = static_cast<float>(lua_tonumber(rawState, 2));
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A2090 (FUN_006A2090, cfunc_ProjectileSetAcceleration)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetAccelerationL`.
   */
  int cfunc_ProjectileSetAcceleration(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetAccelerationL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A20B0 (FUN_006A20B0, func_ProjectileSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetAcceleration(accel)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetAcceleration_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetAcceleration",
      &moho::cfunc_ProjectileSetAcceleration,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetAccelerationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2290 (FUN_006A2290, cfunc_ProjectileSetBallisticAccelerationL)
   *
   * What it does:
   * Reads one projectile argument plus optional acceleration lanes and writes
   * projectile ballistic-acceleration storage. Accepted forms are:
   * `(projectile)`, `(projectile, y)`, and `(projectile, x, y, z)`.
   */
  int cfunc_ProjectileSetBallisticAccelerationL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1 && argumentCount != 2 && argumentCount != 4) {
      const msvc8::string message = gpg::STR_Printf(kSetBallisticAccelerationArgCountError, argumentCount);
      lua_pushstring(rawState, message.c_str());
      (void)lua_gettop(rawState);
      lua_error(rawState);
      return 0;
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    ProjectileMotionControlRuntimeView& motion = AccessProjectileMotionControlView(*projectile);

    switch (argumentCount) {
      case 1: {
        Sim* const sim = lua_getglobaluserdata(rawState);
        motion.mBallisticAcceleration = sim->mPhysConstants->mGravity;
        break;
      }

      case 2: {
        LuaPlus::LuaStackObject yArg(state, 2);
        motion.mBallisticAcceleration.x = 0.0f;
        motion.mBallisticAcceleration.y = static_cast<float>(yArg.GetNumber());
        motion.mBallisticAcceleration.z = 0.0f;
        break;
      }

      case 4: {
        LuaPlus::LuaStackObject xArg(state, 2);
        LuaPlus::LuaStackObject yArg(state, 3);
        LuaPlus::LuaStackObject zArg(state, 4);
        motion.mBallisticAcceleration.x = static_cast<float>(xArg.GetNumber());
        motion.mBallisticAcceleration.y = static_cast<float>(yArg.GetNumber());
        motion.mBallisticAcceleration.z = static_cast<float>(zArg.GetNumber());
        break;
      }

      default:
        break;
    }

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A2210 (FUN_006A2210, cfunc_ProjectileSetBallisticAcceleration)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetBallisticAccelerationL`.
   */
  int cfunc_ProjectileSetBallisticAcceleration(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetBallisticAccelerationL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2230 (FUN_006A2230, func_ProjectileSetBallisticAcceleration_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetBallisticAcceleration(...)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetBallisticAcceleration_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetBallisticAcceleration",
      &moho::cfunc_ProjectileSetBallisticAcceleration,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetBallisticAccelerationArgCountError
    );
    return &binder;
  }

  /**
   * Address: 0x006A24F0 (FUN_006A24F0, cfunc_ProjectileSetDestroyOnWaterL)
   *
   * What it does:
   * Reads `(projectile, flag)` from Lua and writes projectile destroy-on-water
   * behavior lane.
   */
  int cfunc_ProjectileSetDestroyOnWaterL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetDestroyOnWaterHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject destroyOnWaterArg(state, 2);
    (void)SetProjectileDestroyOnWater(projectile, destroyOnWaterArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x006A2470 (FUN_006A2470, cfunc_ProjectileSetDestroyOnWater)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetDestroyOnWaterL`.
   */
  int cfunc_ProjectileSetDestroyOnWater(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetDestroyOnWaterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2490 (FUN_006A2490, func_ProjectileSetDestroyOnWater_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetDestroyOnWater(flag)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetDestroyOnWater_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetDestroyOnWater",
      &moho::cfunc_ProjectileSetDestroyOnWater,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetDestroyOnWaterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2630 (FUN_006A2630, cfunc_ProjectileSetTurnRateL)
   *
   * What it does:
   * Reads `(projectile, radiansPerSecond)` from Lua, writes projectile
   * turn-rate lane, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetTurnRateL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetTurnRateHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject turnRateArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&turnRateArg, "number");
    }

    AccessProjectileMotionControlView(*projectile).mTurnRateDegrees = static_cast<float>(lua_tonumber(rawState, 2));
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A25B0 (FUN_006A25B0, cfunc_ProjectileSetTurnRate)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetTurnRateL`.
   */
  int cfunc_ProjectileSetTurnRate(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetTurnRateL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A25D0 (FUN_006A25D0, func_ProjectileSetTurnRate_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetTurnRate(radians_per_second)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetTurnRate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetTurnRate",
      &moho::cfunc_ProjectileSetTurnRate,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetTurnRateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A27B0 (FUN_006A27B0, cfunc_ProjectileGetCurrentSpeedL)
   *
   * What it does:
   * Reads one projectile argument, computes velocity magnitude, and pushes one
   * numeric result to Lua.
   */
  int cfunc_ProjectileGetCurrentSpeedL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentSpeedHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    const Wm3::Vector3f velocity = projectile->GetVelocity();
    const float speed = std::sqrt((velocity.x * velocity.x) + (velocity.y * velocity.y) + (velocity.z * velocity.z));
    lua_pushnumber(rawState, speed);
    (void)lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x006A2730 (FUN_006A2730, cfunc_ProjectileGetCurrentSpeed)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileGetCurrentSpeedL`.
   */
  int cfunc_ProjectileGetCurrentSpeed(lua_State* const luaContext)
  {
    return cfunc_ProjectileGetCurrentSpeedL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2750 (FUN_006A2750, func_ProjectileGetCurrentSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetCurrentSpeed()` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetCurrentSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetCurrentSpeed",
      &moho::cfunc_ProjectileGetCurrentSpeed,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kGetCurrentSpeedHelpText
    );
    return &binder;
  }

  int cfunc_ProjectileGetVelocityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006A2890 (FUN_006A2890, cfunc_ProjectileGetVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileGetVelocityL`.
   */
  int cfunc_ProjectileGetVelocity(lua_State* const luaContext)
  {
    return cfunc_ProjectileGetVelocityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2910 (FUN_006A2910, cfunc_ProjectileGetVelocityL)
   *
   * What it does:
   * Reads one projectile argument and pushes velocity components `(x, y, z)` as
   * three Lua numbers.
   */
  int cfunc_ProjectileGetVelocityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetVelocityHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    const Wm3::Vector3f velocity = projectile->GetVelocity();

    lua_pushnumber(rawState, velocity.x);
    (void)lua_gettop(rawState);
    lua_pushnumber(rawState, velocity.y);
    (void)lua_gettop(rawState);
    lua_pushnumber(rawState, velocity.z);
    (void)lua_gettop(rawState);
    return 3;
  }

  /**
   * Address: 0x006A28B0 (FUN_006A28B0, func_ProjectileGetVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:GetVelocity() -> x,y,z` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileGetVelocity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetVelocity",
      &moho::cfunc_ProjectileGetVelocity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kGetVelocityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2A90 (FUN_006A2A90, cfunc_ProjectileSetVelocityL)
   *
   * What it does:
   * Reads `(projectile, speed)` or `(projectile, vx, vy, vz)` from Lua,
   * updates projectile velocity, and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetVelocityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2 && argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kSetVelocityArgCountError, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    Wm3::Vector3f& velocity = AccessProjectileVelocityView(*projectile).mVelocity;

    LuaPlus::LuaStackObject speedOrXArg(state, 2);
    if (argumentCount == 2) {
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&speedOrXArg, "number");
      }

      const float speed = static_cast<float>(lua_tonumber(rawState, 2));
      Wm3::Vector3f::Normalize(&velocity);
      velocity.x *= speed;
      velocity.y *= speed;
      velocity.z *= speed;
    } else {
      if (lua_type(rawState, 2) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&speedOrXArg, "number");
      }
      const float velocityX = static_cast<float>(lua_tonumber(rawState, 2));

      LuaPlus::LuaStackObject yArg(state, 3);
      if (lua_type(rawState, 3) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&yArg, "number");
      }
      const float velocityY = static_cast<float>(lua_tonumber(rawState, 3));

      LuaPlus::LuaStackObject zArg(state, 4);
      if (lua_type(rawState, 4) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&zArg, "number");
      }
      velocity.z = static_cast<float>(lua_tonumber(rawState, 4));
      velocity.x = velocityX;
      velocity.y = velocityY;
    }

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A2A10 (FUN_006A2A10, cfunc_ProjectileSetVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetVelocityL`.
   */
  int cfunc_ProjectileSetVelocity(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetVelocityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2A30 (FUN_006A2A30, func_ProjectileSetVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocity(speed)` /
   * `Projectile:SetVelocity(vx,vy,vz)` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetVelocity",
      &moho::cfunc_ProjectileSetVelocity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetVelocityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2D70 (FUN_006A2D70, cfunc_ProjectileSetScaleVelocityL)
   *
   * What it does:
   * Reads `(projectile, uniformScaleVelocity)` or `(projectile, x, y, z)` from
   * Lua, writes projectile `mScaleVelocity`, and returns the projectile Lua
   * object (or `nil` when projectile resolution fails).
   */
  int cfunc_ProjectileSetScaleVelocityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2 && argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kSetScaleVelocityArgCountError, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_ProjectileOpt(projectileObject, state);
    if (projectile != nullptr) {
      LuaPlus::LuaStackObject scaleXArg(state, 2);
      if (argumentCount == 2) {
        const float uniformScaleVelocity = static_cast<float>(scaleXArg.GetNumber());
        projectile->mScaleVelocity.x = uniformScaleVelocity;
        projectile->mScaleVelocity.y = uniformScaleVelocity;
        projectile->mScaleVelocity.z = uniformScaleVelocity;
      } else {
        projectile->mScaleVelocity.x = static_cast<float>(scaleXArg.GetNumber());

        LuaPlus::LuaStackObject scaleYArg(state, 3);
        projectile->mScaleVelocity.y = static_cast<float>(scaleYArg.GetNumber());

        LuaPlus::LuaStackObject scaleZArg(state, 4);
        projectile->mScaleVelocity.z = static_cast<float>(scaleZArg.GetNumber());
      }

      projectile->mLuaObj.PushStack(state);
      return 1;
    }

    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x006A2CF0 (FUN_006A2CF0, cfunc_ProjectileSetScaleVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetScaleVelocityL`.
   */
  int cfunc_ProjectileSetScaleVelocity(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetScaleVelocityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2D10 (FUN_006A2D10, func_ProjectileSetScaleVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetScaleVelocity(vs)` /
   * `Projectile:SetScaleVelocity(vsx, vsy, vsz)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetScaleVelocity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetScaleVelocity",
      &moho::cfunc_ProjectileSetScaleVelocity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetScaleVelocityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A2FE0 (FUN_006A2FE0, cfunc_ProjectileSetLocalAngularVelocityL)
   *
   * What it does:
   * Reads `(projectile, x, y, z)` from Lua and writes local angular velocity
   * lanes before returning the projectile Lua object.
   */
  int cfunc_ProjectileSetLocalAngularVelocityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetLocalAngularVelocityHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&xArg, "number");
    }
    const float localAngularVelocityX = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&yArg, "number");
    }
    const float localAngularVelocityY = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject zArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&zArg, "number");
    }
    projectile->mLocalAngularVelocity.z = static_cast<float>(lua_tonumber(rawState, 4));
    projectile->mLocalAngularVelocity.x = localAngularVelocityX;
    projectile->mLocalAngularVelocity.y = localAngularVelocityY;

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A2F60 (FUN_006A2F60, cfunc_ProjectileSetLocalAngularVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetLocalAngularVelocityL`.
   */
  int cfunc_ProjectileSetLocalAngularVelocity(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetLocalAngularVelocityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2F80 (FUN_006A2F80, func_ProjectileSetLocalAngularVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetLocalAngularVelocity(x,y,z)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetLocalAngularVelocity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetLocalAngularVelocity",
      &moho::cfunc_ProjectileSetLocalAngularVelocity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetLocalAngularVelocityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A31F0 (FUN_006A31F0, cfunc_ProjectileSetCollisionL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates both collision booleans,
   * and returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollisionL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCollisionHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    const bool enabled = enabledArg.GetBoolean();
    (void)SetProjectileCollideSurface(projectile, enabled);
    (void)SetProjectileCollideEntity(projectile, enabled);

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A3170 (FUN_006A3170, cfunc_ProjectileSetCollision)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileSetCollisionL`.
   */
  int cfunc_ProjectileSetCollision(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetCollisionL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3190 (FUN_006A3190, func_ProjectileSetCollision_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollision(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollision_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetCollision",
      &moho::cfunc_ProjectileSetCollision,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetCollisionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3360 (FUN_006A3360, cfunc_ProjectileSetCollideSurfaceL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates surface-collision lane, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollideSurfaceL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCollideSurfaceHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileCollideSurface(projectile, enabledArg.GetBoolean());
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A32E0 (FUN_006A32E0, cfunc_ProjectileSetCollideSurface)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetCollideSurfaceL`.
   */
  int cfunc_ProjectileSetCollideSurface(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetCollideSurfaceL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3300 (FUN_006A3300, func_ProjectileSetCollideSurface_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollideSurface(onoff)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollideSurface_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetCollideSurface",
      &moho::cfunc_ProjectileSetCollideSurface,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetCollideSurfaceHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A34B0 (FUN_006A34B0, cfunc_ProjectileSetCollideEntityL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates entity-collision lane, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileSetCollideEntityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCollideEntityHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileCollideEntity(projectile, enabledArg.GetBoolean());
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A3430 (FUN_006A3430, cfunc_ProjectileSetCollideEntity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetCollideEntityL`.
   */
  int cfunc_ProjectileSetCollideEntity(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetCollideEntityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3450 (FUN_006A3450, func_ProjectileSetCollideEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetCollideEntity(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetCollideEntity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetCollideEntity",
      &moho::cfunc_ProjectileSetCollideEntity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetCollideEntityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3600 (FUN_006A3600, cfunc_ProjectileStayUnderwaterL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates stay-underwater flag, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileStayUnderwaterL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kStayUnderwaterHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileStayUnderwater(projectile, enabledArg.GetBoolean());
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A3580 (FUN_006A3580, cfunc_ProjectileStayUnderwater)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileStayUnderwaterL`.
   */
  int cfunc_ProjectileStayUnderwater(lua_State* const luaContext)
  {
    return cfunc_ProjectileStayUnderwaterL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A35A0 (FUN_006A35A0, func_ProjectileStayUnderwater_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:StayUnderwater(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileStayUnderwater_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "StayUnderwater",
      &moho::cfunc_ProjectileStayUnderwater,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kStayUnderwaterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3750 (FUN_006A3750, cfunc_ProjectileTrackTargetL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua, updates target-tracking flag, and
   * returns the projectile Lua object.
   */
  int cfunc_ProjectileTrackTargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kTrackTargetHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileTrackTarget(projectile, enabledArg.GetBoolean());
    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A36D0 (FUN_006A36D0, cfunc_ProjectileTrackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_ProjectileTrackTargetL`.
   */
  int cfunc_ProjectileTrackTarget(lua_State* const luaContext)
  {
    return cfunc_ProjectileTrackTargetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A36F0 (FUN_006A36F0, func_ProjectileTrackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:TrackTarget(onoff)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileTrackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "TrackTarget",
      &moho::cfunc_ProjectileTrackTarget,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kTrackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A38A0 (FUN_006A38A0, cfunc_ProjectileSetStayUprightL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua and updates stay-upright flag.
   */
  int cfunc_ProjectileSetStayUprightL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetStayUprightHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileStayUpright(projectile, enabledArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x006A3820 (FUN_006A3820, cfunc_ProjectileSetStayUpright)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetStayUprightL`.
   */
  int cfunc_ProjectileSetStayUpright(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetStayUprightL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3840 (FUN_006A3840, func_ProjectileSetStayUpright_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetStayUpright(truefalse)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetStayUpright_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetStayUpright",
      &moho::cfunc_ProjectileSetStayUpright,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetStayUprightHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A39E0 (FUN_006A39E0, cfunc_ProjectileSetVelocityAlignL)
   *
   * What it does:
   * Reads `(projectile, enabled)` from Lua and updates velocity-align flag.
   */
  int cfunc_ProjectileSetVelocityAlignL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetVelocityAlignHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);
    LuaPlus::LuaStackObject enabledArg(state, 2);
    (void)SetProjectileVelocityAlign(projectile, enabledArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x006A3960 (FUN_006A3960, cfunc_ProjectileSetVelocityAlign)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetVelocityAlignL`.
   */
  int cfunc_ProjectileSetVelocityAlign(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetVelocityAlignL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3980 (FUN_006A3980, func_ProjectileSetVelocityAlign_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocityAlign(truefalse)` Lua binder definition in
   * the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocityAlign_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetVelocityAlign",
      &moho::cfunc_ProjectileSetVelocityAlign,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetVelocityAlignHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3B20 (FUN_006A3B20, cfunc_ProjectileCreateChildProjectileL)
   *
   * What it does:
   * Reads `(projectile, blueprintId)`, creates one child projectile from the
   * source projectile launch profile, and returns the created Lua projectile.
   */
  int cfunc_ProjectileCreateChildProjectileL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateChildProjectileHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const sourceProjectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* blueprintText = lua_tostring(rawState, 2);
    if (!blueprintText) {
      LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
      blueprintText = "";
    }

    RResId projectileId{};
    gpg::STR_InitFilename(&projectileId.name, blueprintText);

    Sim* const sim = sourceProjectile ? sourceProjectile->SimulationRef : nullptr;
    RProjectileBlueprint* const blueprint =
      (sim && sim->mRules) ? sim->mRules->GetProjectileBlueprint(projectileId) : nullptr;
    if (!blueprint) {
      LuaPlus::LuaState::Error(state, kMissingProjectileBlueprintError, blueprintText);
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    msvc8::string copiedDamageTypeName{};
    (void)CopyProjectileDamageTypeNameRuntime(sourceProjectile, &copiedDamageTypeName);

    Projectile* const childProjectile = PROJ_Create(
      sim,
      blueprint,
      sourceProjectile->GetArmyOwner(),
      sourceProjectile,
      sourceProjectile->GetTransformWm3(),
      sourceProjectile->mDamage,
      sourceProjectile->mDamageRadius,
      copiedDamageTypeName,
      sourceProjectile->mTargetPosData,
      true
    );
    childProjectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A3AA0 (FUN_006A3AA0, cfunc_ProjectileCreateChildProjectile)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileCreateChildProjectileL`.
   */
  int cfunc_ProjectileCreateChildProjectile(lua_State* const luaContext)
  {
    return cfunc_ProjectileCreateChildProjectileL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3AC0 (FUN_006A3AC0, func_ProjectileCreateChildProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:CreateChildProjectile(blueprint)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileCreateChildProjectile_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateChildProjectile",
      &moho::cfunc_ProjectileCreateChildProjectile,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kCreateChildProjectileHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3CF0 (FUN_006A3CF0, cfunc_ProjectileSetVelocityRandomUpVector)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetVelocityRandomUpVectorL`.
   */
  int cfunc_ProjectileSetVelocityRandomUpVector(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetVelocityRandomUpVectorL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3D70 (FUN_006A3D70, cfunc_ProjectileSetVelocityRandomUpVectorL)
   *
   * What it does:
   * Reads one projectile arg and replaces projectile velocity with a random
   * upward-direction vector scaled to projectile blueprint max speed.
   */
  int cfunc_ProjectileSetVelocityRandomUpVectorL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetVelocityRandomUpVectorHelpText, 1, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);
    CRandomStream* const random = (sim != nullptr) ? sim->mRngState : nullptr;
    if (random == nullptr) {
      return 0;
    }

    Wm3::Vector3f randomDirection{};
    randomDirection.x = static_cast<float>(static_cast<double>(random->twister.NextUInt32()) * 2.3283064e-10);
    randomDirection.y =
      static_cast<float>(static_cast<double>(random->twister.NextUInt32()) * 2.2118911e-10 + 0.050000001);
    randomDirection.z = static_cast<float>(static_cast<double>(random->twister.NextUInt32()) * 2.3283064e-10);

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    SetVectorLengthIfNonZero(randomDirection, ReadProjectileRandomUpSpeed(*projectile));
    AccessProjectileVelocityView(*projectile).mVelocity = randomDirection;
    return 0;
  }

  /**
   * Address: 0x006A3D10 (FUN_006A3D10, func_ProjectileSetVelocityRandomUpVector_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetVelocityRandomUpVector(self)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetVelocityRandomUpVector_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetVelocityRandomUpVector",
      &moho::cfunc_ProjectileSetVelocityRandomUpVector,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetVelocityRandomUpVectorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3F80 (FUN_006A3F80, cfunc_ProjectileChangeMaxZigZagL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile zig-zag
   * amplitude lane.
   */
  int cfunc_ProjectileChangeMaxZigZagL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kChangeMaxZigZagHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject maxZigZagArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&maxZigZagArg, "number");
    }
    AccessProjectileAttributesView(*projectile).mMaxZigZag = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006A3F00 (FUN_006A3F00, cfunc_ProjectileChangeMaxZigZag)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeMaxZigZagL`.
   */
  int cfunc_ProjectileChangeMaxZigZag(lua_State* const luaContext)
  {
    return cfunc_ProjectileChangeMaxZigZagL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3F20 (FUN_006A3F20, func_ProjectileChangeMaxZigZag_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeMaxZigZag(value)` Lua binder definition in the
   * `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeMaxZigZag_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ChangeMaxZigZag",
      &moho::cfunc_ProjectileChangeMaxZigZag,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kChangeMaxZigZagHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A40F0 (FUN_006A40F0, cfunc_ProjectileChangeZigZagFrequencyL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile zig-zag
   * frequency lane.
   */
  int cfunc_ProjectileChangeZigZagFrequencyL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kChangeZigZagFrequencyHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject zigZagFrequencyArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&zigZagFrequencyArg, "number");
    }
    AccessProjectileAttributesView(*projectile).mZigZagFrequency = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006A4070 (FUN_006A4070, cfunc_ProjectileChangeZigZagFrequency)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeZigZagFrequencyL`.
   */
  int cfunc_ProjectileChangeZigZagFrequency(lua_State* const luaContext)
  {
    return cfunc_ProjectileChangeZigZagFrequencyL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A4090 (FUN_006A4090, func_ProjectileChangeZigZagFrequency_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeZigZagFrequency(value)` Lua binder definition
   * in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeZigZagFrequency_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ChangeZigZagFrequency",
      &moho::cfunc_ProjectileChangeZigZagFrequency,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kChangeZigZagFrequencyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A4260 (FUN_006A4260, cfunc_ProjectileChangeDetonateAboveHeightL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile detonate-above
   * height lane.
   */
  int cfunc_ProjectileChangeDetonateAboveHeightL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kChangeDetonateAboveHeightHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject detonateAboveHeightArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&detonateAboveHeightArg, "number");
    }
    AccessProjectileAttributesView(*projectile).mDetonateAboveHeight = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006A41E0 (FUN_006A41E0, cfunc_ProjectileChangeDetonateAboveHeight)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeDetonateAboveHeightL`.
   */
  int cfunc_ProjectileChangeDetonateAboveHeight(lua_State* const luaContext)
  {
    return cfunc_ProjectileChangeDetonateAboveHeightL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A4200 (FUN_006A4200, func_ProjectileChangeDetonateAboveHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeDetonateAboveHeight(value)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeDetonateAboveHeight_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ChangeDetonateAboveHeight",
      &moho::cfunc_ProjectileChangeDetonateAboveHeight,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kChangeDetonateAboveHeightHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A43D0 (FUN_006A43D0, cfunc_ProjectileChangeDetonateBelowHeightL)
   *
   * What it does:
   * Reads `(projectile, value)` from Lua and updates projectile detonate-below
   * height lane.
   */
  int cfunc_ProjectileChangeDetonateBelowHeightL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kChangeDetonateBelowHeightHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject detonateBelowHeightArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&detonateBelowHeightArg, "number");
    }
    AccessProjectileAttributesView(*projectile).mDetonateBelowHeight = static_cast<float>(lua_tonumber(rawState, 2));
    return 0;
  }

  /**
   * Address: 0x006A4350 (FUN_006A4350, cfunc_ProjectileChangeDetonateBelowHeight)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileChangeDetonateBelowHeightL`.
   */
  int cfunc_ProjectileChangeDetonateBelowHeight(lua_State* const luaContext)
  {
    return cfunc_ProjectileChangeDetonateBelowHeightL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A4370 (FUN_006A4370, func_ProjectileChangeDetonateBelowHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:ChangeDetonateBelowHeight(value)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileChangeDetonateBelowHeight_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "ChangeDetonateBelowHeight",
      &moho::cfunc_ProjectileChangeDetonateBelowHeight,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kChangeDetonateBelowHeightHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0069A720 (FUN_0069A720, Moho::EProjectileImpactEventTypeInfo::EProjectileImpactEventTypeInfo)
   */
  EProjectileImpactEventTypeInfo::EProjectileImpactEventTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EProjectileImpactEvent), this);
  }

  /**
   * Address: 0x0069A7B0 (FUN_0069A7B0, Moho::EProjectileImpactEventTypeInfo::dtr)
   */
  EProjectileImpactEventTypeInfo::~EProjectileImpactEventTypeInfo() = default;

  /**
   * Address: 0x0069A7A0 (FUN_0069A7A0, Moho::EProjectileImpactEventTypeInfo::GetName)
   */
  const char* EProjectileImpactEventTypeInfo::GetName() const
  {
    return "EProjectileImpactEvent";
  }

  /**
   * Address: 0x0069A780 (FUN_0069A780, Moho::EProjectileImpactEventTypeInfo::Init)
   */
  void EProjectileImpactEventTypeInfo::Init()
  {
    size_ = sizeof(EProjectileImpactEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0069A4A0 (FUN_0069A4A0, Moho::CProjectileAttributes::CProjectileAttributes)
   *
   * What it does:
   * Initializes projectile zig-zag/detonation override lanes to unset
   * sentinel values and clears blueprint pointer ownership.
   */
  CProjectileAttributes::CProjectileAttributes() noexcept
    : mBlueprint(nullptr)
    , mMaxZigZag(-1.0f)
    , mZigZagFrequency(-1.0f)
    , mDetonateAboveHeight(-1.0f)
    , mDetonateBelowHeight(-1.0f)
  {
  }

  /**
   * Address: 0x0069A4D0 (FUN_0069A4D0, Moho::CProjectileAttributes::CProjectileAttributes)
   *
   * What it does:
   * Initializes one projectile-attributes payload from a blueprint pointer
   * while keeping zig-zag/detonation override lanes unset.
   */
  CProjectileAttributes::CProjectileAttributes(RProjectileBlueprint* const blueprint) noexcept
    : CProjectileAttributes()
  {
    mBlueprint = blueprint;
  }

  /**
   * Address: 0x0069A850 (FUN_0069A850, Moho::CProjectileAttributesTypeInfo::CProjectileAttributesTypeInfo)
   *
   * What it does:
   * Preregisters `CProjectileAttributes` reflection metadata at startup.
   */
  CProjectileAttributesTypeInfo::CProjectileAttributesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CProjectileAttributes), this);
  }

  /**
   * Address: 0x0069A940 (FUN_0069A940, CProjectileAttributesTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one
   * `CProjectileAttributesTypeInfo` instance while preserving outer storage
   * ownership.
   */
  [[maybe_unused]] void DestroyCProjectileAttributesTypeInfoBody(CProjectileAttributesTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x0069A8E0 (FUN_0069A8E0, Moho::CProjectileAttributesTypeInfo::dtr)
   */
  CProjectileAttributesTypeInfo::~CProjectileAttributesTypeInfo()
  {
    DestroyCProjectileAttributesTypeInfoBody(this);
  }

  /**
   * Address: 0x0069A8D0 (FUN_0069A8D0, Moho::CProjectileAttributesTypeInfo::GetName)
   */
  const char* CProjectileAttributesTypeInfo::GetName() const
  {
    return "CProjectileAttributes";
  }

  /**
   * Address: 0x0069A8B0 (FUN_0069A8B0, Moho::CProjectileAttributesTypeInfo::Init)
   */
  void CProjectileAttributesTypeInfo::Init()
  {
    size_ = sizeof(CProjectileAttributes);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0069A990 (FUN_0069A990, Moho::CProjectileAttributesSerializer::Deserialize)
   */
  void CProjectileAttributesSerializer::Deserialize(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    gpg::RRef owner{};
    if (ownerRef != nullptr) {
      owner = *ownerRef;
    }

    auto& attributes = *reinterpret_cast<CProjectileAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    Deserialize_CProjectileAttributesBody(archive, attributes, owner);
  }

  /**
   * Address: 0x0069A9A0 (FUN_0069A9A0, Moho::CProjectileAttributesSerializer::Serialize)
   */
  void CProjectileAttributesSerializer::Serialize(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    gpg::RRef owner{};
    if (ownerRef != nullptr) {
      owner = *ownerRef;
    }

    const auto& attributes = *reinterpret_cast<const CProjectileAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    Serialize_CProjectileAttributesBody(archive, attributes, owner);
  }

  /**
   * Address: 0x0069E900 (FUN_0069E900, serializer registration lane)
   */
  void CProjectileAttributesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = CachedCProjectileAttributesType();
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD510 (FUN_00BFD510, cleanup_TConVar_dbg_Projectile)
   */
  void cleanup_TConVar_dbg_Projectile()
  {
    TeardownConCommandRegistration(GetDbgProjectileConVar());
  }

  /**
   * Address: 0x00BD62F0 (FUN_00BD62F0, register_TConVar_dbg_Projectile)
   */
  void register_TConVar_dbg_Projectile()
  {
    RegisterConCommand(GetDbgProjectileConVar());
    (void)std::atexit(&cleanup_TConVar_dbg_Projectile);
  }

  /**
   * Address: 0x00BFD540 (FUN_00BFD540, cleanup_EProjectileImpactEventTypeInfo)
   */
  void cleanup_EProjectileImpactEventTypeInfo()
  {
    if (!gEProjectileImpactEventTypeInfoConstructed) {
      return;
    }

    EProjectileImpactEventTypeInfoStorageRef().~EProjectileImpactEventTypeInfo();
    gEProjectileImpactEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6330 (FUN_00BD6330, register_EProjectileImpactEventTypeInfo)
   */
  int register_EProjectileImpactEventTypeInfo()
  {
    (void)ConstructEProjectileImpactEventTypeInfo();
    return std::atexit(&cleanup_EProjectileImpactEventTypeInfo);
  }

  /**
   * Address: 0x00BFD550 (FUN_00BFD550, cleanup_EProjectileImpactEventPrimitiveSerializer)
   */
  gpg::SerHelperBase* cleanup_EProjectileImpactEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEProjectileImpactEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BD6350 (FUN_00BD6350, register_EProjectileImpactEventPrimitiveSerializer)
   */
  int register_EProjectileImpactEventPrimitiveSerializer()
  {
    new (&gEProjectileImpactEventPrimitiveSerializer) PrimitiveEnumSerializer<EProjectileImpactEvent>();
    InitializeSerializerNode(gEProjectileImpactEventPrimitiveSerializer);
    gEProjectileImpactEventPrimitiveSerializer.mDeserialize = &Deserialize_EProjectileImpactEvent_Primitive;
    gEProjectileImpactEventPrimitiveSerializer.mSerialize = &Serialize_EProjectileImpactEvent_Primitive;
    return std::atexit(&cleanup_EProjectileImpactEventPrimitiveSerializer_atexit);
  }

  /**
   * Address: 0x00BFD580 (FUN_00BFD580, cleanup_CProjectileAttributesTypeInfo)
   */
  void cleanup_CProjectileAttributesTypeInfo()
  {
    if (!gCProjectileAttributesTypeInfoConstructed) {
      return;
    }

    CProjectileAttributesTypeInfoStorageRef().~CProjectileAttributesTypeInfo();
    gCProjectileAttributesTypeInfoConstructed = false;
    CProjectileAttributes::sType = nullptr;
  }

  /**
   * Address: 0x00BD6390 (FUN_00BD6390, register_CProjectileAttributesTypeInfo)
   */
  int register_CProjectileAttributesTypeInfo()
  {
    (void)ConstructCProjectileAttributesTypeInfo();
    return std::atexit(&cleanup_CProjectileAttributesTypeInfo);
  }

  /**
   * Address: 0x00BFD5E0 (FUN_00BFD5E0, cleanup_CProjectileAttributesSerializer)
   */
  gpg::SerHelperBase* cleanup_CProjectileAttributesSerializer()
  {
    return UnlinkCProjectileAttributesSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x00BD63B0 (FUN_00BD63B0, register_CProjectileAttributesSerializer)
   */
  int register_CProjectileAttributesSerializer()
  {
    if (!gCProjectileAttributesSerializerConstructed) {
      new (gCProjectileAttributesSerializerStorage) CProjectileAttributesSerializer();
      gCProjectileAttributesSerializerConstructed = true;
    }

    CProjectileAttributesSerializer& serializer = CProjectileAttributesSerializerStorageRef();
    InitializeSerializerNode(serializer);
    serializer.mDeserialize = &CProjectileAttributesSerializer::Deserialize;
    serializer.mSerialize = &CProjectileAttributesSerializer::Serialize;
    return std::atexit(&cleanup_CProjectileAttributesSerializer_atexit);
  }

  /**
   * Address: 0x00BFD7C0 (FUN_00BFD7C0, cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   */
  void cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo()
  {
    if (!gManyToOneBroadcasterProjectileImpactTypeInfoConstructed) {
      return;
    }

    ManyToOneBroadcasterTypeInfoStorageRef().~RManyToOneBroadcasterProjectileImpactTypeInfo();
    gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = false;
    ManyToOneBroadcaster_EProjectileImpactEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD64C0 (FUN_00BD64C0, register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   */
  int register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo()
  {
    (void)ConstructManyToOneBroadcasterProjectileImpactTypeInfo();
    return std::atexit(&cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo);
  }

  /**
   * Address: 0x00BFD760 (FUN_00BFD760, cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   */
  void cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo()
  {
    if (!gManyToOneListenerProjectileImpactTypeInfoConstructed) {
      return;
    }

    ManyToOneListenerTypeInfoStorageRef().~RManyToOneListenerProjectileImpactTypeInfo();
    gManyToOneListenerProjectileImpactTypeInfoConstructed = false;
    ManyToOneListener_EProjectileImpactEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD64E0 (FUN_00BD64E0, register_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   */
  int register_ManyToOneListener_EProjectileImpactEvent_TypeInfo()
  {
    (void)ConstructManyToOneListenerProjectileImpactTypeInfo();
    return std::atexit(&cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo);
  }
} // namespace moho
