#include "CScriptEvent.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAimManipulator.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiNavigatorImpl.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/animation/CAnimationManipulator.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/audio/HSound.h"
#include "moho/collision/CCollisionManipulator.h"
#include "moho/debug/CPathDebugger.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/entity/Entity.h"
#include "moho/entity/MotorFallDown.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/projectile/Projectile.h"
#include "moho/render/CDecalHandle.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/misc/StatItem.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CUnitScriptTask.h"
#include "moho/script/ScriptedDecal.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/CPlatoon.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

namespace
{
  moho::CScriptEventSerializer gCScriptEventSerializer{};

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mNext);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    auto* const next = static_cast<gpg::SerHelperBase*>(serializer.mNext);
    auto* const prev = static_cast<gpg::SerHelperBase*>(serializer.mPrev);
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mPrev = self;
    serializer.mNext = self;
    return self;
  }

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mNext == nullptr || serializer.mPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mPrev = self;
      serializer.mNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  gpg::RType* CachedCScriptEventType()
  {
    if (!CScriptEvent::sType) {
      CScriptEvent::sType = gpg::LookupRType(typeid(CScriptEvent));
    }
    return CScriptEvent::sType;
  }

  gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  gpg::RType* CachedCTaskEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTaskEvent));
    }
    return cached;
  }

  gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject*));
    }
    return cached;
  }

  gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Unit));
    }
    return cached;
  }

  gpg::RType* CachedCUnitScriptTaskType()
  {
    if (!CUnitScriptTask::sType) {
      CUnitScriptTask::sType = gpg::LookupRType(typeid(CUnitScriptTask));
    }
    return CUnitScriptTask::sType;
  }

  gpg::RType* CachedUnitWeaponType()
  {
    if (!UnitWeapon::sType) {
      UnitWeapon::sType = gpg::LookupRType(typeid(UnitWeapon));
    }
    return UnitWeapon::sType;
  }

  gpg::RType* CachedUserUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UserUnit));
    }
    return cached;
  }

  gpg::RType* CachedCPathDebuggerType()
  {
    if (!CPathDebugger::sType) {
      CPathDebugger::sType = gpg::LookupRType(typeid(CPathDebugger));
    }
    return CPathDebugger::sType;
  }

  gpg::RType* CachedUserEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UserEntity));
    }
    return cached;
  }

  gpg::RType* CachedCAiBrainType()
  {
    if (!CAiBrain::sType) {
      CAiBrain::sType = gpg::LookupRType(typeid(CAiBrain));
    }
    return CAiBrain::sType;
  }

  gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
    }
    return cached;
  }

  gpg::RType* CachedCAimManipulatorType()
  {
    if (!CAimManipulator::sType) {
      CAimManipulator::sType = gpg::LookupRType(typeid(CAimManipulator));
    }
    return CAimManipulator::sType;
  }

  gpg::RType* CachedCBoneEntityManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CBoneEntityManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CBoneEntityManipulator");
    }
    return cached;
  }

  gpg::RType* CachedCBuilderArmManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CBuilderArmManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CBuilderArmManipulator");
    }
    return cached;
  }

  gpg::RType* CachedCCollisionManipulatorType()
  {
    if (!CCollisionManipulator::sType) {
      CCollisionManipulator::sType = gpg::LookupRType(typeid(CCollisionManipulator));
    }
    return CCollisionManipulator::sType;
  }

  gpg::RType* CachedIAniManipulatorType()
  {
    if (!IAniManipulator::sType) {
      IAniManipulator::sType = gpg::LookupRType(typeid(IAniManipulator));
    }
    return IAniManipulator::sType;
  }

  gpg::RType* CachedIEffectType()
  {
    if (!IEffect::sType) {
      IEffect::sType = gpg::LookupRType(typeid(IEffect));
    }
    return IEffect::sType;
  }

  gpg::RType* CachedCDecalHandleType()
  {
    if (!CDecalHandle::sType) {
      CDecalHandle::sType = gpg::LookupRType(typeid(CDecalHandle));
    }
    return CDecalHandle::sType;
  }

  gpg::RType* CachedCAnimationManipulatorType()
  {
    if (!CAnimationManipulator::sType) {
      CAnimationManipulator::sType = gpg::LookupRType(typeid(CAnimationManipulator));
    }
    return CAnimationManipulator::sType;
  }

  gpg::RType* CachedCSlaveManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CSlaveManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CSlaveManipulator");
    }
    return cached;
  }

  gpg::RType* CachedCThrustManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CThrustManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CThrustManipulator");
    }
    return cached;
  }

  gpg::RType* CachedCSlideManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CSlideManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CSlideManipulator");
    }
    return cached;
  }

  gpg::RType* CachedCAiPersonalityType()
  {
    if (!CAiPersonality::sType) {
      CAiPersonality::sType = gpg::LookupRType(typeid(CAiPersonality));
    }
    return CAiPersonality::sType;
  }

  gpg::RType* CachedCAiNavigatorImplType()
  {
    if (!CAiNavigatorImpl::sType) {
      CAiNavigatorImpl::sType = gpg::LookupRType(typeid(CAiNavigatorImpl));
    }
    return CAiNavigatorImpl::sType;
  }

  gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Entity));
    }
    return cached;
  }

  gpg::RType* CachedReconBlipType()
  {
    if (!ReconBlip::sType) {
      ReconBlip::sType = gpg::LookupRType(typeid(ReconBlip));
    }
    return ReconBlip::sType;
  }

  gpg::RType* CachedProjectileType()
  {
    if (!Projectile::sType) {
      Projectile::sType = gpg::LookupRType(typeid(Projectile));
    }
    return Projectile::sType;
  }

  gpg::RType* CachedPropType()
  {
    if (!Prop::sType) {
      Prop::sType = gpg::LookupRType(typeid(Prop));
    }
    return Prop::sType;
  }

  gpg::RType* CachedMotorFallDownType()
  {
    if (!MotorFallDown::sType) {
      MotorFallDown::sType = gpg::LookupRType(typeid(MotorFallDown));
    }
    return MotorFallDown::sType;
  }

  gpg::RType* CachedCUnitCommandType()
  {
    return CUnitCommand::StaticGetClass();
  }

  gpg::RType* CachedHSoundType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(HSound));
    }
    return cached;
  }

  gpg::RType* CachedCDamageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CDamage");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CDamage");
    }
    return cached;
  }

  gpg::RType* CachedCPlatoonType()
  {
    if (!CPlatoon::sType) {
      CPlatoon::sType = gpg::LookupRType(typeid(CPlatoon));
    }
    return CPlatoon::sType;
  }

  gpg::RType* CachedCMauiBorderType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiBorder");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiBorder");
    }
    return cached;
  }

  gpg::RType* CachedCMauiMeshType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiMesh");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiMesh");
    }
    return cached;
  }

  gpg::RType* CachedCDiscoveryServiceType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CDiscoveryService");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CDiscoveryService");
    }
    return cached;
  }

  gpg::RType* CachedCollisionBeamEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CollisionBeamEntity");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CollisionBeamEntity");
    }
    return cached;
  }

  gpg::RType* CachedCLobbyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CLobby");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CLobby");
    }
    return cached;
  }

  gpg::RType* CachedCameraImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CameraImpl));
    }
    return cached;
  }

  gpg::RType* CachedCUIWorldViewType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CUIWorldView");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CUIWorldView");
    }
    return cached;
  }

  gpg::RType* CachedCMauiHistogramType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiHistogram");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiHistogram");
    }
    return cached;
  }

  gpg::RType* CachedCUIMapPreviewType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CUIMapPreview");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CUIMapPreview");
    }
    return cached;
  }

  gpg::RType* CachedCMauiCursorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiCursor");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiCursor");
    }
    return cached;
  }

  gpg::RType* CachedCMauiItemListType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiItemList");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiItemList");
    }
    return cached;
  }

  gpg::RType* CachedCMauiMovieType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiMovie");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiMovie");
    }
    return cached;
  }

  gpg::RType* CachedCMauiScrollbarType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiScrollbar");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiScrollbar");
    }
    return cached;
  }

  gpg::RType* CachedCMauiTextType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiText");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiText");
    }
    return cached;
  }

  gpg::RType* CachedCMauiControlType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiControl");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiControl");
    }
    return cached;
  }

  gpg::RType* CachedCMauiEditType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiEdit");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiEdit");
    }
    return cached;
  }

  gpg::RType* CachedCMauiBitmapType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiBitmap");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiBitmap");
    }
    return cached;
  }

  gpg::RType* CachedCMauiFrameType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiFrame");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiFrame");
    }
    return cached;
  }

  gpg::RType* CachedCMauiLuaDraggerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiLuaDragger");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiLuaDragger");
    }
    return cached;
  }

  gpg::RType* CachedScriptedDecalType()
  {
    if (!ScriptedDecal::sType) {
      ScriptedDecal::sType = gpg::LookupRType(typeid(ScriptedDecal));
    }
    return ScriptedDecal::sType;
  }

  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const raw = lua_touserdata(lstate, -1);
    if (raw) {
      out = *static_cast<gpg::RRef*>(raw);
    }
    lua_settop(lstate, top);
    return out;
  }

  CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<CScriptObject**>(upcast.mObj);
  }

  template <typename T>
  gpg::RRef MakeTypedRef(T* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x004CB570 (FUN_004CB570, CScriptEventTypeInfo::newRefFunc_)
   */
  [[nodiscard]]
  gpg::RRef CreateScriptEventRefOwned()
  {
    return MakeTypedRef(new CScriptEvent(), CachedCScriptEventType());
  }

  /**
   * Address: 0x004CB5E0 (FUN_004CB5E0, CScriptEventTypeInfo::deleteFunc_)
   */
  void DeleteScriptEventOwned(void* object)
  {
    delete static_cast<CScriptEvent*>(object);
  }

  /**
   * Address: 0x004CB600 (FUN_004CB600, CScriptEventTypeInfo::ctorRefFunc_)
   */
  [[nodiscard]]
  gpg::RRef ConstructScriptEventRefInPlace(void* objectStorage)
  {
    auto* const event = static_cast<CScriptEvent*>(objectStorage);
    if (event) {
      new (event) CScriptEvent();
    }
    return MakeTypedRef(event, CachedCScriptEventType());
  }

  /**
   * Address: 0x004CB670 (FUN_004CB670, CScriptEventTypeInfo::dtrFunc_)
   */
  void DestroyScriptEventInPlace(void* object)
  {
    auto* const event = static_cast<CScriptEvent*>(object);
    if (event) {
      event->~CScriptEvent();
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CScriptEvent::sType = nullptr;
}

/**
 * Address: 0x004CB2A0 (FUN_004CB2A0, Moho::InstanceCounter<Moho::CScriptEvent>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CScriptEvent
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CScriptEvent>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CScriptEvent).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x004C9420 (FUN_004C9420, ??0CScriptEvent@Moho@@QAE@@Z)
 */
CScriptEvent::CScriptEvent()
{
  AddStatCounter(InstanceCounter<CScriptEvent>::GetStatItem(), 1);
}

/**
 * Address: 0x006D30F0 (FUN_006D30F0, ??0CScriptEvent@Moho@@QAE@@Z_0)
 */
CScriptEvent::CScriptEvent(const LuaPlus::LuaObject& scriptFactory)
  : CTaskEvent()
  , CScriptObject(scriptFactory, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
{
  AddStatCounter(InstanceCounter<CScriptEvent>::GetStatItem(), 1);
}

/**
 * Address: 0x004C94C0 (FUN_004C94C0, ??1CScriptEvent@Moho@@UAE@XZ)
 */
CScriptEvent::~CScriptEvent()
{
  AddStatCounter(InstanceCounter<CScriptEvent>::GetStatItem(), -1);
}

/**
 * Address: 0x004C93E0 (FUN_004C93E0, ?GetClass@CScriptEvent@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CScriptEvent::GetClass() const
{
  return CachedCScriptEventType();
}

/**
 * Address: 0x004C9400 (FUN_004C9400, ?GetDerivedObjectRef@CScriptEvent@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CScriptEvent::GetDerivedObjectRef()
{
  return MakeTypedRef(this, CachedCScriptEventType());
}

/**
 * Address: 0x004CB820 (FUN_004CB820, Moho::CScriptEvent::MemberDeserialize)
 */
void CScriptEvent::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef ownerRef{};

  gpg::RType* const taskEventType = CachedCTaskEventType();
  archive->Read(taskEventType, static_cast<CTaskEvent*>(this), ownerRef);

  gpg::RType* scriptObjectType = CScriptObject::sType;
  if (!scriptObjectType) {
    scriptObjectType = gpg::LookupRType(typeid(CScriptObject));
    CScriptObject::sType = scriptObjectType;
  }
  archive->Read(scriptObjectType, static_cast<CScriptObject*>(this), ownerRef);
}

/**
 * Address: 0x004CB8A0 (FUN_004CB8A0, Moho::CScriptEvent::MemberSerialize)
 */
void CScriptEvent::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RRef ownerRef{};

  gpg::RType* const taskEventType = CachedCTaskEventType();
  archive->Write(taskEventType, static_cast<CTaskEvent*>(this), ownerRef);

  gpg::RType* scriptObjectType = CScriptObject::sType;
  if (!scriptObjectType) {
    scriptObjectType = gpg::LookupRType(typeid(CScriptObject));
    CScriptObject::sType = scriptObjectType;
  }
  archive->Write(scriptObjectType, static_cast<CScriptObject*>(this), ownerRef);
}

/**
 * Address: 0x004C8270 (FUN_004C8270, func_GetCObj_CScriptObject)
 */
CScriptObject* moho::SCR_GetScriptObjectFromLuaObject(const LuaPlus::LuaObject& object)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    return nullptr;
  }

  return *scriptObjectSlot;
}

CScriptObject** moho::SCR_FromLua_CScriptObject(const LuaPlus::LuaObject& object)
{
  return ExtractScriptObjectSlotFromLuaObject(object);
}

/**
 * Address: 0x004CBA60 (FUN_004CBA60, Moho::SCR_FromLua_CScriptEvent)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CScriptEvent*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CScriptEvent* moho::SCR_FromLua_CScriptEvent(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCScriptEventType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CScriptEvent*>(upcast.mObj);
}

/**
 * Address: 0x005936C0 (FUN_005936C0, Moho::SCR_FromLua_Unit)
 */
Unit* moho::SCR_FromLua_Unit(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaState* const activeState = object.GetActiveState();
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitType());
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Unit*>(upcast.mObj);
}

/**
 * Address: 0x00623FF0 (FUN_00623FF0, Moho::SCR_FromLua_CUnitScriptTask)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CUnitScriptTask*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CUnitScriptTask* moho::SCR_FromLua_CUnitScriptTask(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitScriptTaskType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CUnitScriptTask*>(upcast.mObj);
}

/**
 * Address: 0x00633220 (FUN_00633220, Moho::SCR_FromLua_UnitWeapon)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UnitWeapon*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
UnitWeapon* moho::SCR_FromLua_UnitWeapon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitWeaponType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UnitWeapon*>(upcast.mObj);
}

/**
 * Address: 0x006DD930 (FUN_006DD930, func_GetUnitWeaponOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UnitWeapon*`; raises Lua errors
 * for missing payload or wrong runtime type, and returns nullptr for
 * destroyed game objects.
 */
UnitWeapon* moho::SCR_FromLua_UnitWeaponOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitWeaponType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UnitWeapon*>(upcast.mObj);
}

/**
 * Address: 0x006332F0 (FUN_006332F0, Moho::SCR_FromLua_CAimManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAimManipulator*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAimManipulator* moho::SCR_FromLua_CAimManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAimManipulatorType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAimManipulator*>(upcast.mObj);
}

/**
 * Address: 0x00635390 (FUN_00635390, Moho::SCR_FromLua_CBoneEntityManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CBoneEntityManipulator*` and raises
 * Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CBoneEntityManipulator* moho::SCR_FromLua_CBoneEntityManipulator(
  const LuaPlus::LuaObject& object,
  LuaPlus::LuaState* const state
)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const manipulatorType = CachedCBoneEntityManipulatorType();
  const gpg::RRef upcast = manipulatorType ? gpg::REF_UpcastPtr(sourceRef, manipulatorType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CBoneEntityManipulator*>(upcast.mObj);
}

/**
 * Address: 0x006371D0 (FUN_006371D0, Moho::SCR_FromLua_CBuilderArmManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CBuilderArmManipulator*` and
 * raises Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CBuilderArmManipulator* moho::SCR_FromLua_CBuilderArmManipulator(
  const LuaPlus::LuaObject& object,
  LuaPlus::LuaState* const state
)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const builderArmType = CachedCBuilderArmManipulatorType();
  const gpg::RRef upcast = builderArmType ? gpg::REF_UpcastPtr(sourceRef, builderArmType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CBuilderArmManipulator*>(upcast.mObj);
}

/**
 * Address: 0x00638AF0 (FUN_00638AF0, Moho::SCR_FromLua_CCollisionManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CCollisionManipulator*` and raises
 * Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CCollisionManipulator* moho::SCR_FromLua_CCollisionManipulator(
  const LuaPlus::LuaObject& object,
  LuaPlus::LuaState* const state
)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCCollisionManipulatorType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CCollisionManipulator*>(upcast.mObj);
}

/**
 * Address: 0x0063CDE0 (FUN_0063CDE0, Moho::SCR_FromLua_IAniManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `IAniManipulator*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
IAniManipulator* moho::SCR_FromLua_IAniManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedIAniManipulatorType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<IAniManipulator*>(upcast.mObj);
}

/**
 * Address: 0x0063CEB0 (FUN_0063CEB0, func_GetIAniManipulatorOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `IAniManipulator*`; raises Lua
 * errors for missing payload or wrong runtime type, and returns nullptr for
 * destroyed game objects.
 */
IAniManipulator* moho::SCR_FromLua_IAniManipulatorOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedIAniManipulatorType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<IAniManipulator*>(upcast.mObj);
}

/**
 * Address: 0x006585F0 (FUN_006585F0, Moho::SCR_FromLua_IEffect)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `IEffect*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
IEffect* moho::SCR_FromLua_IEffect(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedIEffectType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<IEffect*>(upcast.mObj);
}

/**
 * Address: 0x00670F90 (FUN_00670F90, func_GetIEffectOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `IEffect*`; raises Lua errors for
 * missing payload or wrong runtime type, and returns nullptr for destroyed
 * game objects.
 */
IEffect* moho::SCR_FromLua_IEffectOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedIEffectType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<IEffect*>(upcast.mObj);
}

/**
 * Address: 0x00671050 (FUN_00671050, func_GetCDecalHandleOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CDecalHandle*`; raises Lua errors
 * for missing payload or wrong runtime type, and returns nullptr for
 * destroyed game objects.
 */
CDecalHandle* moho::SCR_FromLua_CDecalHandleOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCDecalHandleType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CDecalHandle*>(upcast.mObj);
}

/**
 * Address: 0x006423E0 (FUN_006423E0, Moho::SCR_FromLua_CAnimationManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAnimationManipulator*` and raises
 * Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CAnimationManipulator* moho::SCR_FromLua_CAnimationManipulator(
  const LuaPlus::LuaObject& object,
  LuaPlus::LuaState* const state
)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAnimationManipulatorType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAnimationManipulator*>(upcast.mObj);
}

/**
 * Address: 0x00646900 (FUN_00646900, Moho::SCR_FromLua_CSlaveManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CSlaveManipulator*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CSlaveManipulator* moho::SCR_FromLua_CSlaveManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const manipulatorType = CachedCSlaveManipulatorType();
  const gpg::RRef upcast = manipulatorType ? gpg::REF_UpcastPtr(sourceRef, manipulatorType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CSlaveManipulator*>(upcast.mObj);
}

/**
 * Address: 0x0064B3A0 (FUN_0064B3A0, Moho::SCR_FromLua_CThrustManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CThrustManipulator*` and raises
 * Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CThrustManipulator* moho::SCR_FromLua_CThrustManipulator(
  const LuaPlus::LuaObject& object,
  LuaPlus::LuaState* const state
)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const manipulatorType = CachedCThrustManipulatorType();
  const gpg::RRef upcast = manipulatorType ? gpg::REF_UpcastPtr(sourceRef, manipulatorType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CThrustManipulator*>(upcast.mObj);
}

/**
 * Address: 0x00648710 (FUN_00648710, Moho::SCR_FromLua_CSlideManipulator)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CSlideManipulator*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CSlideManipulator* moho::SCR_FromLua_CSlideManipulator(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const slideType = CachedCSlideManipulatorType();
  const gpg::RRef upcast = slideType ? gpg::REF_UpcastPtr(sourceRef, slideType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CSlideManipulator*>(upcast.mObj);
}

/**
 * Address: 0x006755F0 (FUN_006755F0, Moho::SCR_FromLua_CollisionBeamEntity)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CollisionBeamEntity*` and raises
 * Lua errors for missing, destroyed, or type-mismatched game objects.
 */
CollisionBeamEntity* moho::SCR_FromLua_CollisionBeamEntity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const collisionBeamType = CachedCollisionBeamEntityType();
  const gpg::RRef upcast = collisionBeamType ? gpg::REF_UpcastPtr(sourceRef, collisionBeamType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CollisionBeamEntity*>(upcast.mObj);
}

/**
 * Address: 0x00695E00 (FUN_00695E00, Moho::SCR_FromLua_MotorFallDown)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `MotorFallDown*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
MotorFallDown* moho::SCR_FromLua_MotorFallDown(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedMotorFallDownType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<MotorFallDown*>(upcast.mObj);
}

/**
 * Address: 0x006F8E40 (FUN_006F8E40, Moho::SCR_FromLua_CUnitCommand)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CUnitCommand*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CUnitCommand* moho::SCR_FromLua_CUnitCommand(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitCommandType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CUnitCommand*>(upcast.mObj);
}

/**
 * Address: 0x008AFCE0 (FUN_008AFCE0, func_GetHSoundOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `HSound*`; raises Lua errors for
 * missing payload or wrong runtime type, and returns nullptr for destroyed
 * game objects.
 */
HSound* moho::SCR_FromLua_HSoundOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedHSoundType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<HSound*>(upcast.mObj);
}

/**
 * Address: 0x00762460 (FUN_00762460, Moho::SCR_FromLua_HSound)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `HSound*` and raises Lua errors for
 * missing, destroyed, or type-mismatched game objects.
 */
HSound* moho::SCR_FromLua_HSound(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedHSoundType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<HSound*>(upcast.mObj);
}

/**
 * Address: 0x0073A830 (FUN_0073A830, Moho::SCR_FromLua_CDamage)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CDamage*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CDamage* moho::SCR_FromLua_CDamage(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const damageType = CachedCDamageType();
  const gpg::RRef upcast = damageType ? gpg::REF_UpcastPtr(sourceRef, damageType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CDamage*>(upcast.mObj);
}

/**
 * Address: 0x007B62C0 (FUN_007B62C0, Moho::SCR_FromLua_CPathDebugger)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CPathDebugger*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CPathDebugger* moho::SCR_FromLua_CPathDebugger(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCPathDebuggerType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CPathDebugger*>(upcast.mObj);
}

/**
 * Address: 0x008C6220 (FUN_008C6220, Moho::SCR_FromLua_UserEntity)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UserEntity*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
UserEntity* moho::SCR_FromLua_UserEntity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserEntityType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UserEntity*>(upcast.mObj);
}

/**
 * Address: 0x00822B80 (FUN_00822B80, Moho::SCR_FromLua_UserUnit)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UserUnit*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
UserUnit* moho::SCR_FromLua_UserUnit(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UserUnit*>(upcast.mObj);
}

/**
 * Address: 0x005930D0 (FUN_005930D0, Moho::SCR_FromLua_CAiBrain)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiBrain*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CAiBrain* moho::SCR_FromLua_CAiBrain(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiBrainType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiBrain*>(upcast.mObj);
}

/**
 * Address: 0x005DEF90 (FUN_005DEF90, Moho::SCR_FromLua_CAiAttackerImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiAttackerImpl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiAttackerImpl* moho::SCR_FromLua_CAiAttackerImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiAttackerImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiAttackerImpl*>(upcast.mObj);
}

/**
 * Address: 0x005BD320 (FUN_005BD320, Moho::SCR_FromLua_CAiPersonality)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiPersonality*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiPersonality* moho::SCR_FromLua_CAiPersonality(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiPersonalityType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiPersonality*>(upcast.mObj);
}

/**
 * Address: 0x005A7F50 (FUN_005A7F50, Moho::SCR_FromLua_CAiNavigatorImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiNavigatorImpl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiNavigatorImpl* moho::SCR_FromLua_CAiNavigatorImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiNavigatorImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiNavigatorImpl*>(upcast.mObj);
}

/**
 * Address: 0x00593A30 (FUN_00593A30, func_GetCPlatoonOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CPlatoon*`; raises Lua errors for
 * missing payload or wrong runtime type, and returns nullptr for destroyed
 * game objects.
 */
CPlatoon* moho::SCR_FromLua_CPlatoonOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCPlatoonType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CPlatoon*>(upcast.mObj);
}

/**
 * Address: 0x00593AF0 (FUN_00593AF0, Moho::SCR_FromLua_CPlatoon)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CPlatoon*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CPlatoon* moho::SCR_FromLua_CPlatoon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCPlatoonType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CPlatoon*>(upcast.mObj);
}

/**
 * Address: 0x00786210 (FUN_00786210, Moho::SCR_FromLua_CMauiBorder)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiBorder*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiBorder* moho::SCR_FromLua_CMauiBorder(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiBorderType = CachedCMauiBorderType();
  const gpg::RRef upcast = mauiBorderType ? gpg::REF_UpcastPtr(sourceRef, mauiBorderType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiBorder*>(upcast.mObj);
}

/**
 * Address: 0x0079EB20 (FUN_0079EB20, Moho::SCR_FromLua_CMauiMesh)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiMesh*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CMauiMesh* moho::SCR_FromLua_CMauiMesh(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiMeshType = CachedCMauiMeshType();
  const gpg::RRef upcast = mauiMeshType ? gpg::REF_UpcastPtr(sourceRef, mauiMeshType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiMesh*>(upcast.mObj);
}

/**
 * Address: 0x007CB4A0 (FUN_007CB4A0, Moho::SCR_FromLua_CDiscoveryService)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CDiscoveryService*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CDiscoveryService* moho::SCR_FromLua_CDiscoveryService(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const discoveryServiceType = CachedCDiscoveryServiceType();
  const gpg::RRef upcast = discoveryServiceType ? gpg::REF_UpcastPtr(sourceRef, discoveryServiceType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CDiscoveryService*>(upcast.mObj);
}

/**
 * Address: 0x007CB570 (FUN_007CB570, func_GetCDiscoveryServiceOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CDiscoveryService*`; raises Lua
 * errors for missing payload or wrong runtime type, and returns nullptr for
 * destroyed game objects.
 */
CDiscoveryService* moho::SCR_FromLua_CDiscoveryServiceOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const discoveryServiceType = CachedCDiscoveryServiceType();
  const gpg::RRef upcast = discoveryServiceType ? gpg::REF_UpcastPtr(sourceRef, discoveryServiceType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CDiscoveryService*>(upcast.mObj);
}

/**
 * Address: 0x007CB720 (FUN_007CB720, func_GetCLobbyOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CLobby*`; raises Lua errors for
 * missing payload or wrong runtime type, and returns nullptr for destroyed
 * game objects.
 */
CLobby* moho::SCR_FromLua_CLobbyOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const lobbyType = CachedCLobbyType();
  const gpg::RRef upcast = lobbyType ? gpg::REF_UpcastPtr(sourceRef, lobbyType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CLobby*>(upcast.mObj);
}

/**
 * Address: 0x007CB7E0 (FUN_007CB7E0, Moho::SCR_FromLua_CLobby)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CLobby*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CLobby* moho::SCR_FromLua_CLobby(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const lobbyType = CachedCLobbyType();
  const gpg::RRef upcast = lobbyType ? gpg::REF_UpcastPtr(sourceRef, lobbyType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CLobby*>(upcast.mObj);
}

/**
 * Address: 0x007B0E90 (FUN_007B0E90, Moho::SCR_FromLua_CameraImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CameraImpl*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CameraImpl* moho::SCR_FromLua_CameraImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCameraImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CameraImpl*>(upcast.mObj);
}

/**
 * Address: 0x00873A70 (FUN_00873A70, Moho::SCR_FromLua_CUIWorldView)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CUIWorldView*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CUIWorldView* moho::SCR_FromLua_CUIWorldView(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  LuaPlus::LuaState* activeState = state;
  if (!activeState) {
    activeState = object.GetActiveState();
  }

  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const worldViewType = CachedCUIWorldViewType();
  const gpg::RRef upcast = worldViewType ? gpg::REF_UpcastPtr(sourceRef, worldViewType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CUIWorldView*>(upcast.mObj);
}

/**
 * Address: 0x007989B0 (FUN_007989B0, Moho::SCR_FromLua_CMauiHistogram)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiHistogram*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiHistogram* moho::SCR_FromLua_CMauiHistogram(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const histogramType = CachedCMauiHistogramType();
  const gpg::RRef upcast = histogramType ? gpg::REF_UpcastPtr(sourceRef, histogramType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiHistogram*>(upcast.mObj);
}

/**
 * Address: 0x00851440 (FUN_00851440, Moho::SCR_FromLua_CUIMapPreview)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CUIMapPreview*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CUIMapPreview* moho::SCR_FromLua_CUIMapPreview(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mapPreviewType = CachedCUIMapPreviewType();
  const gpg::RRef upcast = mapPreviewType ? gpg::REF_UpcastPtr(sourceRef, mapPreviewType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CUIMapPreview*>(upcast.mObj);
}

/**
 * Address: 0x0078D9D0 (FUN_0078D9D0, Moho::SCR_FromLua_CMauiCursor)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiCursor*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiCursor* moho::SCR_FromLua_CMauiCursor(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiCursorType = CachedCMauiCursorType();
  const gpg::RRef upcast = mauiCursorType ? gpg::REF_UpcastPtr(sourceRef, mauiCursorType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiCursor*>(upcast.mObj);
}

/**
 * Address: 0x0087FB30 (FUN_0087FB30, Moho::SCR_FromLua_ScriptedDecal)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `ScriptedDecal*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
ScriptedDecal* moho::SCR_FromLua_ScriptedDecal(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedScriptedDecalType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<ScriptedDecal*>(upcast.mObj);
}

/**
 * Address: 0x0079C9C0 (FUN_0079C9C0, Moho::SCR_FromLua_CMauiItemList)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiItemList*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiItemList* moho::SCR_FromLua_CMauiItemList(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiItemListType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiItemList*>(upcast.mObj);
}

/**
 * Address: 0x007A01A0 (FUN_007A01A0, Moho::SCR_FromLua_CMauiMovie)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiMovie*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiMovie* moho::SCR_FromLua_CMauiMovie(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiMovieType = CachedCMauiMovieType();
  const gpg::RRef upcast = mauiMovieType ? gpg::REF_UpcastPtr(sourceRef, mauiMovieType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiMovie*>(upcast.mObj);
}

/**
 * Address: 0x007A2760 (FUN_007A2760, Moho::SCR_FromLua_CMauiScrollbar)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiScrollbar*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiScrollbar* moho::SCR_FromLua_CMauiScrollbar(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const scrollbarType = CachedCMauiScrollbarType();
  const gpg::RRef upcast = scrollbarType ? gpg::REF_UpcastPtr(sourceRef, scrollbarType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiScrollbar*>(upcast.mObj);
}

/**
 * Address: 0x007A42E0 (FUN_007A42E0, Moho::SCR_FromLua_CMauiText)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiText*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiText* moho::SCR_FromLua_CMauiText(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiTextType = CachedCMauiTextType();
  const gpg::RRef upcast = mauiTextType ? gpg::REF_UpcastPtr(sourceRef, mauiTextType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiText*>(upcast.mObj);
}

/**
 * Address: 0x00783BA0 (FUN_00783BA0, Moho::SCR_FromLua_CMauiControl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiControl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiControl* moho::SCR_FromLua_CMauiControl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiControlType = CachedCMauiControlType();
  const gpg::RRef upcast = mauiControlType ? gpg::REF_UpcastPtr(sourceRef, mauiControlType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiControl*>(upcast.mObj);
}

/**
 * Address: 0x0078F560 (FUN_0078F560, Moho::SCR_FromLua_CMauiEdit)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiEdit*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiEdit* moho::SCR_FromLua_CMauiEdit(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiEditType = CachedCMauiEditType();
  const gpg::RRef upcast = mauiEditType ? gpg::REF_UpcastPtr(sourceRef, mauiEditType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiEdit*>(upcast.mObj);
}

/**
 * Address: 0x00783C70 (FUN_00783C70, Moho::SCR_FromLua_CMauiBitmap)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiBitmap*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiBitmap* moho::SCR_FromLua_CMauiBitmap(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiBitmapType = CachedCMauiBitmapType();
  const gpg::RRef upcast = mauiBitmapType ? gpg::REF_UpcastPtr(sourceRef, mauiBitmapType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiBitmap*>(upcast.mObj);
}

/**
 * Address: 0x0078E7B0 (FUN_0078E7B0, Moho::SCR_FromLua_CMauiFrame)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiFrame*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiFrame* moho::SCR_FromLua_CMauiFrame(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const frameType = CachedCMauiFrameType();
  const gpg::RRef upcast = frameType ? gpg::REF_UpcastPtr(sourceRef, frameType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiFrame*>(upcast.mObj);
}

/**
 * Address: 0x0078EA20 (FUN_0078EA20, Moho::SCR_FromLua_CMauiLuaDragger)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiLuaDragger*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiLuaDragger* moho::SCR_FromLua_CMauiLuaDragger(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const draggerType = CachedCMauiLuaDraggerType();
  const gpg::RRef upcast = draggerType ? gpg::REF_UpcastPtr(sourceRef, draggerType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiLuaDragger*>(upcast.mObj);
}

/**
 * Address: 0x005A8020 (FUN_005A8020, Moho::SCR_FromLua_Entity)
 */
Entity* moho::SCR_FromLua_Entity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  LuaPlus::LuaState* activeState = state;
  if (!activeState) {
    activeState = object.GetActiveState();
  }

  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedEntityType());
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Entity*>(upcast.mObj);
}

/**
 * Address: 0x006208D0 (FUN_006208D0, func_GetEntityOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `Entity*`; raises Lua errors for
 * missing payload or wrong runtime type, and returns nullptr for destroyed
 * game objects.
 */
Entity* moho::SCR_FromLua_EntityOpt(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaState* const activeState = object.GetActiveState();

  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedEntityType());
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Entity*>(upcast.mObj);
}

/**
 * Address: 0x005C98E0 (FUN_005C98E0, Moho::SCR_FromLua_ReconBlip)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `ReconBlip*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
ReconBlip* moho::SCR_FromLua_ReconBlip(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedReconBlipType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<ReconBlip*>(upcast.mObj);
}

/**
 * Address: 0x005E3800 (FUN_005E3800, Moho::SCR_FromLuaNoError_Entity)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `Entity*` without raising Lua
 * errors; returns nullptr for missing, destroyed, or type-mismatched values.
 */
Entity* moho::SCR_FromLuaNoError_Entity(const LuaPlus::LuaObject& object)
{
  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(object);
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedEntityType());
  if (!upcast.mObj) {
    return nullptr;
  }

  return static_cast<Entity*>(upcast.mObj);
}

/**
 * Address: 0x006A44C0 (FUN_006A44C0, Moho::SCR_FromLua_Projectile)
 */
Projectile* moho::SCR_FromLua_Projectile(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedProjectileType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Projectile*>(upcast.mObj);
}

/**
 * Address: 0x006A4590 (FUN_006A4590, func_GetProjectileOpt)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `Projectile*`; raises Lua errors
 * for missing payload or wrong runtime type, and returns nullptr for
 * destroyed game objects.
 */
Projectile* moho::SCR_FromLua_ProjectileOpt(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedProjectileType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Projectile*>(upcast.mObj);
}

/**
 * Address: 0x006FD1C0 (FUN_006FD1C0, Moho::SCR_FromLua_Prop)
 */
Prop* moho::SCR_FromLua_Prop(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedPropType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Prop*>(upcast.mObj);
}

/**
 * Address: 0x004C9030 (FUN_004C9030, func_RRefCScriptObject)
 */
gpg::RRef moho::SCR_MakeScriptObjectRef(CScriptObject* object)
{
  return MakeTypedRef(object, CachedCScriptObjectType());
}

/**
 * Address: 0x004CBE30 (FUN_004CBE30, func_UpCastCScriptEventUnsafe)
 */
CScriptEvent* moho::SCR_UpCastScriptEventUnsafe(const gpg::RRef& source)
{
  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCScriptEventType());
  return static_cast<CScriptEvent*>(upcast.mObj);
}

/**
 * Address: 0x004CB980 (FUN_004CB980, sub_4CB980)
 */
CScriptEvent* moho::SCR_GetScriptEventFromLuaObject(const LuaPlus::LuaObject& object)
{
  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(object);
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef ref = SCR_MakeScriptObjectRef(scriptObject);
  return SCR_UpCastScriptEventUnsafe(ref);
}

/**
 * Address: 0x004CA280 (FUN_004CA280, Moho::CScriptEventSerializer::Deserialize)
 */
void CScriptEventSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const object = reinterpret_cast<CScriptEvent*>(objectPtr);
  object->MemberDeserialize(archive);
}

/**
 * Address: 0x004CA290 (FUN_004CA290, Moho::CScriptEventSerializer::Serialize)
 */
void CScriptEventSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const object = reinterpret_cast<CScriptEvent*>(objectPtr);
  object->MemberSerialize(archive);
}

/**
 * Address: 0x004CB0A0 (FUN_004CB0A0, sub_4CB0A0)
 */
void CScriptEventSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCScriptEventType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

static void InitializeCScriptEventSerializer()
{
  ResetSerializerNode(gCScriptEventSerializer);
  gCScriptEventSerializer.mSerLoadFunc = &moho::CScriptEventSerializer::Deserialize;
  gCScriptEventSerializer.mSerSaveFunc = &moho::CScriptEventSerializer::Serialize;
}

static void CleanupCScriptEventSerializerAtExit()
{
  (void)moho::cleanup_CScriptEventSerializer();
}

gpg::SerHelperBase* moho::cleanup_CScriptEventSerializer()
{
  return UnlinkSerializerNode(gCScriptEventSerializer);
}

/**
 * Address: 0x00BC6240 (FUN_00BC6240, register_CScriptEventSerializer)
 *
 * What it does:
 * Initializes startup serializer callback lanes for `CScriptEvent` and
 * schedules intrusive helper cleanup at process exit.
 */
void moho::register_CScriptEventSerializer()
{
  InitializeCScriptEventSerializer();
  (void)std::atexit(&CleanupCScriptEventSerializerAtExit);
}

/**
 * Address: 0x004CB760 (FUN_004CB760, Moho::CScriptEventTypeInfo::AddBase_CScriptObject)
 */
void CScriptEventTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
{
  gpg::RType* const scriptObjectType = CachedCScriptObjectType();
  gpg::RField baseField{};
  baseField.mName = scriptObjectType->GetName();
  baseField.mType = scriptObjectType;
  baseField.mOffset = 0x10;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x004CB7C0 (FUN_004CB7C0, Moho::CScriptEventTypeInfo::AddBase_CTaskEvent)
 */
void CScriptEventTypeInfo::AddBase_CTaskEvent(gpg::RType* const typeInfo)
{
  gpg::RType* const taskEventType = CachedCTaskEventType();
  gpg::RField baseField{};
  baseField.mName = taskEventType->GetName();
  baseField.mType = taskEventType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x004CA1D0 (FUN_004CA1D0, scalar deleting destructor thunk)
 */
CScriptEventTypeInfo::~CScriptEventTypeInfo() = default;

/**
 * Address: 0x004CA1C0 (FUN_004CA1C0, ?GetName@CScriptEventTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CScriptEventTypeInfo::GetName() const
{
  return "CScriptEvent";
}

/**
 * Address: 0x004CA170 (FUN_004CA170, ?Init@CScriptEventTypeInfo@Moho@@UAEXXZ)
 */
void CScriptEventTypeInfo::Init()
{
  size_ = sizeof(CScriptEvent);
  newRefFunc_ = &CreateScriptEventRefOwned;
  deleteFunc_ = &DeleteScriptEventOwned;
  ctorRefFunc_ = &ConstructScriptEventRefInPlace;
  dtrFunc_ = &DestroyScriptEventInPlace;
  gpg::RType::Init();
  AddBase_CScriptObject(this);
  AddBase_CTaskEvent(this);
  Finish();
}
