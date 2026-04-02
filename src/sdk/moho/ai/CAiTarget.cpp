#include "moho/ai/CAiTarget.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <typeinfo>

#include "moho/command/SSTITarget.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityDb.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr std::uint32_t kMissingTargetEntityId = 0xF0000000u;

  [[nodiscard]] Entity* FindEntityById(CEntityDb* entityDb, const EntId entityId)
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      Entity* const entity = *it;
      if (entity && entity->id_ == entityId) {
        return entity;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* CachedEAiTargetType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiTargetType));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakPtr<Entity>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  [[nodiscard]] const char* ToAiTargetTypeLexical(const EAiTargetType targetType) noexcept
  {
    switch (targetType) {
      case EAiTargetType::AITARGET_Entity:
        return "Entity";
      case EAiTargetType::AITARGET_Ground:
        return "Ground";
      default:
        return "None";
    }
  }

  [[nodiscard]] EAiTargetType ParseAiTargetTypeLexical(const char* const lexical) noexcept
  {
    if (!lexical) {
      return EAiTargetType::AITARGET_None;
    }

    if (std::strcmp(lexical, "Entity") == 0 || std::strcmp(lexical, "AITARGET_Entity") == 0) {
      return EAiTargetType::AITARGET_Entity;
    }
    if (std::strcmp(lexical, "Ground") == 0 || std::strcmp(lexical, "AITARGET_Ground") == 0) {
      return EAiTargetType::AITARGET_Ground;
    }
    return EAiTargetType::AITARGET_None;
  }

  [[nodiscard]] Wm3::Vec3f ReadVector3FromLuaObject(const LuaPlus::LuaObject& object) noexcept
  {
    Wm3::Vec3f out = Wm3::Vec3f::Zero();
    if (!object.IsTable()) {
      return out;
    }

    const LuaPlus::LuaObject xObject = object[1];
    const LuaPlus::LuaObject yObject = object[2];
    const LuaPlus::LuaObject zObject = object[3];
    out.x = static_cast<float>(xObject.GetNumber());
    out.y = static_cast<float>(yObject.GetNumber());
    out.z = static_cast<float>(zObject.GetNumber());
    return out;
  }
} // namespace

gpg::RType* CAiTarget::sType = nullptr;

/**
 * Address: 0x005D5670 (FUN_005D5670)
 *
 * What it does:
 * Copy-constructs target payload/link state from another target object.
 */
CAiTarget::CAiTarget(const CAiTarget& source)
{
  CopyFromLinkedTarget(source);
}

/**
 * Address: 0x005D5670 (FUN_005D5670)
 *
 * What it does:
 * Assigns payload/link state from another target object.
 */
CAiTarget& CAiTarget::operator=(const CAiTarget& source)
{
  if (this == &source) {
    return *this;
  }

  CopyFromLinkedTarget(source);
  return *this;
}

/**
 * Address: 0x005D57E0 (FUN_005D57E0)
 *
 * What it does:
 * Unlinks this target node from its current entity weak-link chain.
 */
CAiTarget::~CAiTarget()
{
  UnlinkEntityTargetRef();
}

/**
 * Address: 0x005D5670 (FUN_005D5670)
 *
 * What it does:
 * Core link/payload copier used by copy-ctor and assignment.
 */
void CAiTarget::CopyFromLinkedTarget(const CAiTarget& source)
{
  targetType = source.targetType;
  if (targetEntity.ownerLinkSlot != source.targetEntity.ownerLinkSlot) {
    targetEntity.ResetFromOwnerLinkSlot(source.targetEntity.ownerLinkSlot);
  }
  position = source.position;
  targetPoint = source.targetPoint;
  targetIsMobile = source.targetIsMobile;
}

/**
 * Address: 0x005D57E0 (FUN_005D57E0)
 *
 * What it does:
 * Unlinks this target from owner weak-link slot chain.
 */
void CAiTarget::UnlinkEntityTargetRef()
{
  targetEntity.UnlinkFromOwnerChain();
}

/**
 * Address: 0x005E3880 (FUN_005E3880)
 *
 * What it does:
 * Deserializes reflected CAiTarget payload fields in fixed binary order.
 */
void CAiTarget::DeserializeFromArchive(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
{
  auto* const target = reinterpret_cast<CAiTarget*>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(target != nullptr);
  if (!archive || !target) {
    return;
  }

  const gpg::RRef nullOwner{};
  archive->Read(CachedEAiTargetType(), &target->targetType, nullOwner);
  archive->Read(CachedWeakPtrEntityType(), &target->targetEntity, nullOwner);
  archive->Read(CachedVector3fType(), &target->position, nullOwner);
  archive->ReadInt(&target->targetPoint);
  archive->ReadBool(&target->targetIsMobile);
}

/**
 * Address: 0x005E3950 (FUN_005E3950)
 *
 * What it does:
 * Serializes reflected CAiTarget payload fields in fixed binary order.
 */
void CAiTarget::SerializeToArchive(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
{
  const auto* const target = reinterpret_cast<const CAiTarget*>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(target != nullptr);
  if (!archive || !target) {
    return;
  }

  const gpg::RRef nullOwner{};
  archive->Write(CachedEAiTargetType(), &target->targetType, nullOwner);
  archive->Write(CachedWeakPtrEntityType(), &target->targetEntity, nullOwner);
  archive->Write(CachedVector3fType(), &target->position, nullOwner);
  archive->WriteInt(target->targetPoint);
  archive->WriteBool(target->targetIsMobile);
}

/**
 * Address: 0x005D55B0 (FUN_005D55B0)
 *
 * What it does:
 * Rebinds this target to `entity`, then recomputes mobility/target-point data.
 */
CAiTarget* CAiTarget::UpdateTarget(Entity* const entity)
{
  targetType = EAiTargetType::AITARGET_Entity;
  targetEntity.ResetFromObject(entity);
  targetPoint = -1;
  targetIsMobile = false;

  if (entity) {
    UpdateTargetIsMobile(entity->SimulationRef);
  }

  PickTargetPoint();
  return this;
}

/**
 * Address: 0x005E2860 (FUN_005E2860)
 *
 * What it does:
 * Refreshes `targetIsMobile` by checking the target entity category bitset.
 */
void CAiTarget::UpdateTargetIsMobile(Sim* const sim)
{
  Entity* const entity = targetEntity.GetObjectPtr();
  if (!entity || !entity->BluePrint || !sim || !sim->mRules) {
    return;
  }

  const CategoryWordRangeView* const mobileRange = sim->mRules->GetEntityCategory("MOBILE");
  if (!mobileRange || !mobileRange->mWordsBegin || mobileRange->mWordsEnd < mobileRange->mWordsBegin) {
    return;
  }

  const std::uint32_t blueprintOrdinal = entity->BluePrint->mCategoryBitIndex;
  const std::uint32_t absoluteWordIndex = blueprintOrdinal >> 5u;
  if (absoluteWordIndex < mobileRange->mStartWordIndex) {
    targetIsMobile = false;
    return;
  }

  const std::size_t localWordIndex = static_cast<std::size_t>(absoluteWordIndex - mobileRange->mStartWordIndex);
  const std::size_t wordCount = static_cast<std::size_t>(mobileRange->mWordsEnd - mobileRange->mWordsBegin);
  if (localWordIndex >= wordCount) {
    targetIsMobile = false;
    return;
  }

  const std::uint32_t word = mobileRange->mWordsBegin[localWordIndex];
  targetIsMobile = ((word >> (blueprintOrdinal & 0x1Fu)) & 1u) != 0u;
}

/**
 * Address: 0x005E28F0 (FUN_005E28F0)
 *
 * What it does:
 * Selects a target-point index for unit/recon-blip entity targets.
 */
void CAiTarget::PickTargetPoint()
{
  Entity* const entity = targetEntity.GetObjectPtr();
  if (!entity) {
    return;
  }

  if (Unit* const unit = entity->IsUnit()) {
    unit->PickTargetPoint(targetPoint);
    return;
  }

  auto* const blip = entity->IsReconBlip();
  if (!blip) {
    return;
  }

  if (Unit* const sourceUnit = blip->GetSourceUnit()) {
    sourceUnit->PickTargetPoint(targetPoint);
    return;
  }

  targetPoint = -1;
}

/**
 * Address: 0x005E2620 (FUN_005E2620)
 *
 * What it does:
 * Decodes command-network `SSTITarget` payload into this runtime target object.
 */
CAiTarget* CAiTarget::DecodeFromSSTITarget(const SSTITarget& source, Sim* const sim)
{
  targetEntity.ClearLinkState();
  targetIsMobile = false;

  switch (source.mType) {
    case EAiTargetType::AITARGET_Entity: {
      CAiTarget updated{};
      Entity* const entity =
        FindEntityById(sim ? sim->mEntityDB : nullptr, static_cast<EntId>(source.mEntityId));
      updated.UpdateTarget(entity);
      *this = updated;
      break;
    }
    case EAiTargetType::AITARGET_Ground: {
      CAiTarget updated{};
      updated.targetType = EAiTargetType::AITARGET_Ground;
      updated.position = source.mPos;
      updated.targetPoint = -1;
      updated.targetIsMobile = false;
      *this = updated;
      break;
    }
    default: {
      CAiTarget updated{};
      updated.targetType = EAiTargetType::AITARGET_None;
      updated.targetPoint = -1;
      updated.targetIsMobile = false;
      *this = updated;
      break;
    }
  }

  UpdateTargetIsMobile(sim);
  return this;
}

/**
 * Address: 0x005E27D0 (FUN_005E27D0)
 *
 * What it does:
 * Encodes this runtime target object into command-network `SSTITarget` payload.
 */
void CAiTarget::EncodeToSSTITarget(SSTITarget& out) const
{
  if (targetType == EAiTargetType::AITARGET_Entity) {
    out.mType = EAiTargetType::AITARGET_Entity;
    if (targetEntity.HasValue()) {
      const Entity* const entity = targetEntity.GetObjectPtr();
      out.mEntityId = entity ? static_cast<std::uint32_t>(entity->id_) : kMissingTargetEntityId;
    } else {
      out.mEntityId = kMissingTargetEntityId;
    }
    out.mPos = Wm3::Vec3f::Zero();
    return;
  }

  if (targetType == EAiTargetType::AITARGET_Ground) {
    out.mType = EAiTargetType::AITARGET_Ground;
    out.mEntityId = kMissingTargetEntityId;
    out.mPos = position;
    return;
  }

  out.mType = EAiTargetType::AITARGET_None;
  out.mEntityId = kMissingTargetEntityId;
  out.mPos = Wm3::Vec3f::Zero();
}

/**
 * Address: 0x005E2EC0 (FUN_005E2EC0, Moho::SCR_ToLua<Moho::CAiTarget>)
 *
 * What it does:
 * Serializes one AI target payload into Lua table form.
 */
void moho::SCR_ToLua_CAiTarget(LuaPlus::LuaObject& outObject, LuaPlus::LuaState* const state, const CAiTarget& target)
{
  outObject.AssignNewTable(state, 2, 0);
  outObject.SetString("Type", ToAiTargetTypeLexical(target.targetType));

  if (target.targetType == EAiTargetType::AITARGET_Entity) {
    if (Entity* const entity = target.targetEntity.GetObjectPtr(); entity != nullptr) {
      outObject.SetObject("Entity", entity->mLuaObj);
    }
    return;
  }

  if (target.targetType == EAiTargetType::AITARGET_Ground) {
    const LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, target.position);
    outObject.SetObject("Position", positionObject);
  }
}

/**
 * Address: 0x005E3000 (FUN_005E3000, Moho::SCR_FromLuaCopy<Moho::CAiTarget>)
 *
 * What it does:
 * Parses one Lua target table (`Type` + payload fields) into `outTarget`.
 */
void moho::SCR_FromLuaCopy_CAiTarget(CAiTarget& outTarget, const LuaPlus::LuaObject& object)
{
  const LuaPlus::LuaObject typeObject = object.GetByName("Type");
  const EAiTargetType parsedType = ParseAiTargetTypeLexical(typeObject.GetString());

  if (parsedType == EAiTargetType::AITARGET_Entity) {
    const LuaPlus::LuaObject entityObject = object.GetByName("Entity");
    Entity* const entity = SCR_FromLua_Entity(entityObject, object.GetActiveState());
    outTarget.UpdateTarget(entity);
    return;
  }

  if (parsedType == EAiTargetType::AITARGET_Ground) {
    const LuaPlus::LuaObject positionObject = object.GetByName("Position");
    outTarget.targetType = EAiTargetType::AITARGET_Ground;
    outTarget.targetEntity.ClearLinkState();
    outTarget.position = ReadVector3FromLuaObject(positionObject);
    outTarget.targetPoint = -1;
    outTarget.targetIsMobile = false;
    return;
  }

  outTarget.targetType = EAiTargetType::AITARGET_None;
  outTarget.targetEntity.ClearLinkState();
  outTarget.targetPoint = -1;
  outTarget.targetIsMobile = false;
}
