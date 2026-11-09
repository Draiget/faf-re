// Part of Unit.cpp, included there: stats.

StatItem* Unit::GetStat(gpg::StrArg name, const std::string&)
{
  return moho::ResolveStatString(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B70
StatItem* Unit::GetStat(gpg::StrArg name, const float&)
{
  return moho::ResolveStatFloat(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B50
StatItem* Unit::GetStat(gpg::StrArg name, const int&)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 1);
}

// 0x006A4B30
StatItem* Unit::GetStat(gpg::StrArg name)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 0);
}

/**
 * Address: 0x006A73A0 (FUN_006A73A0)
 *
 * What it does:
 * Stores the auto-mode flag and dispatches the matching script callback.
 */
void Unit::SetAutoMode(const bool enabled)
{
  mUnitVarDat.mAutoMode = enabled;
  CallbackStr(enabled ? "OnAutoModeOn" : "OnAutoModeOff");
}

/**
 * Address: 0x006A73E0 (FUN_006A73E0)
 *
 * What it does:
 * Stores the auto-surface-mode flag.
 */
void Unit::SetAutoSurfaceMode(const bool enabled)
{
  mUnitVarDat.mAutoSurfaceMode = enabled;
}

/**
 * Address: 0x006A4A30 (FUN_006A4A30)
 *
 * What it does:
 * Returns the current auto-mode flag.
 */
bool Unit::IsAutoMode() const
{
  return mUnitVarDat.mAutoMode;
}

/**
 * Address: 0x006A4A40 (FUN_006A4A40)
 *
 * What it does:
 * Returns the current auto-surface-mode flag.
 */
bool Unit::IsAutoSurfaceMode() const
{
  return mUnitVarDat.mAutoSurfaceMode;
}

/**
 * Address: 0x006A4A50 (FUN_006A4A50)
 *
 * What it does:
 * Copies a caller-provided name into the unit custom-name lane.
 */
void Unit::SetCustomName(const std::string name)
{
  mUnitVarDat.mCustomName = name.c_str();
}

/**
 * Address: 0x006A4AB0 (FUN_006A4AB0)
 *
 * What it does:
 * Copies and returns the current custom-name lane.
 */
std::string Unit::GetCustomName() const
{
  return std::string(mUnitVarDat.mCustomName.c_str(), mUnitVarDat.mCustomName.size());
}

/**
 * Address: 0x0062D460 (FUN_0062D460, Moho::Unit::CollectAllOverlapping)
 *
 * What it does:
 * Gathers nearby non-mobile same-army same-layer structures and appends
 * those whose skirt rectangles overlap `unit`.
 */
EntitySetTemplate<Unit>* Unit::CollectAllOverlapping(EntitySetTemplate<Unit>* const outSet, Unit* const unit)
{
  if (outSet == nullptr) {
    return nullptr;
  }

  outSet->ListResetLinks();
  outSet->mVec.RebindInlineNoFree();

  if (unit == nullptr || unit->SimulationRef == nullptr || unit->SimulationRef->mOGrid == nullptr) {
    return outSet;
  }

  // 0x0062D4C2-0x0062D531: sphere {unit->GetPosition(), 20.0f} (radius at
  // 0x00DFF25C), unit mask 0x100, through COGrid::ForAllEntitiesIterator
  // (0x00721FB0) into a fastvector_n<CollisionResult, 10>. The iterator owns
  // the acceptance test (inner-box containment for radius > 3, otherwise the
  // collision primitive's sphere test; no primitive -> skipped).
  const Wm3::Sphere3f querySphere{unit->GetPosition(), 20.0f};
  gpg::core::FastVectorN<CollisionResult, 10> sphereHits{};
  unit->SimulationRef->mOGrid->ForAllEntitiesIterator(sphereHits, ENTITYTYPE_Unit, querySphere);

  for (const CollisionResult& hit : sphereHits) {
    // 0x0062D561: `hit.sourceEntity->IsUnit()` -- no null check on the entity.
    Unit* const other = hit.sourceEntity->IsUnit();
    if (other == nullptr) {
      continue;
    }

    if (other->IsDead() || other->IsMobile()) {
      continue;
    }
    if (unit->ArmyRef != other->ArmyRef) {
      continue;
    }
    if (other == unit) {
      continue;
    }
    if (other->mVarDat.mLayerMask != unit->mVarDat.mLayerMask) {
      continue;
    }
    if (!unit->OverlapsWith(other)) {
      continue;
    }

    (void)outSet->Add(other);
  }

  return outSet;
}

/**
 * Address: 0x006A7E00 (FUN_006A7E00, ?LookForStructureRebuilder@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Scans same-army REBUILDER units for guard commands matching this structure
 * blueprint/position and queues one rebuild entry on the first matching
 * command per builder.
 */
void Unit::LookForStructureRebuilder()
{
  if (ArmyRef == nullptr || SimulationRef == nullptr || SimulationRef->mRules == nullptr) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return;
  }

  const EntityCategorySet* const rebuilderCategory = SimulationRef->mRules->GetEntityCategory("REBUILDER");
  if (rebuilderCategory == nullptr) {
    return;
  }

  EntitySetTemplate<Unit> rebuilderUnits{};
  (void)ArmyRef->GetUnits(&rebuilderUnits, const_cast<EntityCategorySet*>(rebuilderCategory));

  for (Entity* const entry : rebuilderUnits.mVec) {
    Unit* const rebuilder = static_cast<Unit*>(entry);
    if (rebuilder == nullptr) {
      continue;
    }

    if (rebuilder->IsDead() || rebuilder->DestroyQueued() || rebuilder->IsBeingBuilt() || rebuilder->AiBuilder == nullptr ||
        rebuilder->CommandQueue == nullptr) {
      continue;
    }

    const fa::vector<WeakPtr<CUnitCommand>> commandSnapshot(rebuilder->CommandQueue->mCommandVec);
    for (const WeakPtr<CUnitCommand>& commandRef : commandSnapshot) {
      CUnitCommand* const command = commandRef.GetObjectPtr();
      if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Guard) {
        continue;
      }

      const RUnitBlueprint* const commandBlueprint = static_cast<const RUnitBlueprint*>(command->mConstDat.blueprint);
      if (commandBlueprint != blueprint) {
        continue;
      }

      const Wm3::Vec3f targetPosition = command->mTarget.GetTargetPosGun(false);
      const Wm3::Vec3f& myPosition = GetPosition();
      const float deltaX = targetPosition.x - myPosition.x;
      const float deltaZ = targetPosition.z - myPosition.z;
      if (std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ)) >= 0.001f) {
        continue;
      }

      const SOCellPos cellPos = GetFootprint().ToCellPos(GetPosition());
      rebuilder->AiBuilder->BuilderAddRebuildStructure(cellPos, blueprint);
      break;
    }
  }
}
