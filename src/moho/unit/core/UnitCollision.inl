// Part of Unit.cpp, included there: collision and bomb drops.

/**
 * Address: 0x006AB520 (FUN_006AB520, Moho::Unit::UpdateCollision)
 *
 * What it does:
 * Pushes the current transform into the collision primitive. Uses a widened
 * temporary box for skirt bucket membership and preserves the primitive
 * shape when refreshing the cached collision bounds.
 */
void Unit::UpdateCollision()
{
  if (CollisionExtents == nullptr) {
    return;
  }

  CollisionExtents->SetTransform(mVarDat.mCurTransform);
  if (CollisionExtents->GetBox() != nullptr) {
    Wm3::Box3f expandedBox(*CollisionExtents->GetBox());
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint != nullptr) {
      const float skirtExtentX = std::fabs(blueprint->Physics.SkirtOffsetX) + blueprint->Physics.SkirtSizeX;
      const float skirtExtentZ = std::fabs(blueprint->Physics.SkirtOffsetZ) + blueprint->Physics.SkirtSizeZ;
      expandedBox.Extent[0] = 0.5f * std::max(blueprint->mSizeX, skirtExtentX);
      expandedBox.Extent[2] = 0.5f * std::max(blueprint->mSizeZ, skirtExtentZ);
      UpdateRect(moho::AxisAlignedBoundsFromBox(expandedBox));
    } else {
      UpdateRect(CollisionExtents);
    }
  } else {
    UpdateRect(CollisionExtents);
  }
  UpdateAABox();
}

/**
 * Address: 0x006ABC30 (FUN_006ABC30, Moho::Unit::UpdateVisibility)
 *
 * What it does:
 * Recomputes base entity visibility lanes, then keeps unit visibility enabled
 * only for the focused army or when no army is focused.
 */
void Unit::UpdateVisibility()
{
  Entity::UpdateVisibility();
  const std::int32_t focusArmy = SimulationRef->mSyncFilter.focusArmy;
  mVarDat.mVisibilityHidden = static_cast<std::uint8_t>(focusArmy == -1 || focusArmy == ArmyRef->mConstDat.mArmyIndex);
}

/**
 * Address: 0x006AB410 (FUN_006AB410, ?AttachTo@Unit@Moho@@UAE_NABUSEntAttachInfo@2@@Z)
 *
 * What it does:
 * Attaches through `Entity::AttachTo`, then (for mobile units) notifies unit
 * motion and sets attached-state bit; resets cached transport load factor.
 */
bool Unit::AttachTo(const SEntAttachInfo& attachInfo)
{
  if (!Entity::AttachTo(attachInfo)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyAttached(attachInfo);
    mUnitVarDat.mUnitStates |= (1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  return true;
}

/**
 * Address: 0x006AB480 (FUN_006AB480, ?DetachFrom@Unit@Moho@@UAE_NPAVEntity@2@_N@Z)
 *
 * What it does:
 * Detaches through `Entity::DetachFrom`, then (for mobile units) notifies unit
 * motion and clears attached-state bit; resets cached transport load factor
 * and unlinks the transport weak-pointer chain.
 */
bool Unit::DetachFrom(Entity* const parent, const bool skipBallistic)
{
  if (!Entity::DetachFrom(parent, skipBallistic)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyDetached(parent, skipBallistic);
    mUnitVarDat.mUnitStates &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  TransportedByRef.UnlinkFromOwnerChain();
  return true;
}

/**
 * Address: 0x0062CD40 (FUN_0062CD40, Moho::Unit::PredictAheadBomb)
 *
 * What it does:
 * Predicts near-future XZ stop position by repeatedly rotating velocity with
 * impulse-derived roll and integrating over `precision * 10` ticks.
 *
 * Ground truth (`FUN_0062CD40.c`) builds `rollRotation` via
 * `Moho::EulerRollToQuat(&v15, &v17.x, a2a.y * 0.1)`, not
 * `Wm3::Quaternionf::MakeFromAxisAngle` (numerically identical for this
 * axis+angle, but not the function the binary actually calls), and rotates
 * via `Moho::MultQuadVec(&a2a, &v14, &v17)` each iteration, not the generic
 * `Wm3::MultiplyQuaternionVector` -- same quaternion-convention
 * mismatch as the other `MultQuadVec` consumers in this bug class.
 */
Wm3::Vec3f* Unit::PredictAheadBomb(Wm3::Vec3f* const out, const float precision) const
{
  if (!out) {
    return nullptr;
  }

  Wm3::Vec3f predicted = GetPosition();
  if (UnitMotion == nullptr) {
    *out = predicted;
    return out;
  }

  SPhysBody* const physBody = Entity::mPhysBody;
  if (physBody == nullptr) {
    *out = predicted;
    return out;
  }

  Wm3::Vec3f impulse = Wm3::Vec3f::Zero();
  physBody->GetImpulse(&impulse);

  // 0x0062CDDE: a virtual call through the entity vtable (+0x3C), so a unit
  // off the air layer predicts from its motion velocity (Unit::GetVelocity).
  Wm3::Vec3f velocity = GetVelocity();
  const Wm3::Vec3f upAxis(0.0f, 1.0f, 0.0f);
  Wm3::Quaternionf rollRotation{};
  (void)EulerRollToQuat(&upAxis, &rollRotation, impulse.y * 0.1f);

  float stepsRemaining = precision * 10.0f;
  while (stepsRemaining > 0.0f) {
    Wm3::Vec3f rotatedVelocity = Wm3::Vec3f::Zero();
    MultQuadVec(&rotatedVelocity, &velocity, &rollRotation);
    velocity = rotatedVelocity;

    float stepX = rotatedVelocity.x;
    float stepZ = rotatedVelocity.z;
    if (stepsRemaining <= 1.0f) {
      stepX *= stepsRemaining;
      stepZ *= stepsRemaining;
    }

    predicted.x += stepX;
    predicted.z += stepZ;
    stepsRemaining -= 1.0f;
  }

  *out = predicted;
  return out;
}

/**
 * Address: 0x006D3A40 (FUN_006D3A40, Moho::Unit::CalcBombDrop)
 *
 * What it does:
 * Scales current world velocity by ten ticks and resolves one ballistic
 * drop-point lane against `targetPosition` using sim gravity.
 */
Wm3::Vec3f* Unit::CalcBombDrop(Wm3::Vec3f* const out, const Wm3::Vec3f& targetPosition) const
{
  // 0x006D3A67: virtual, like PredictAheadBomb.
  Wm3::Vec3f velocity = GetVelocity();
  velocity.x *= 10.0f;
  velocity.y *= 10.0f;
  velocity.z *= 10.0f;

  return ComputeBombDropAimPoint(
    velocity,
    out,
    SimulationRef->mPhysConstants->mGravity,
    targetPosition,
    GetPosition()
  );
}

/**
 * Address: 0x006A7B90 (FUN_006A7B90, ?InitializeArmor@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Loads armor-definition rows for the blueprint armor type and seeds
 * `ArmorMultipliers` map entries from parsed `<damageType multiplier>` pairs.
 */
void Unit::InitializeArmor()
{
  const LuaPlus::LuaObject unitObject = GetLuaObject();

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const char* const armorTypeName = (blueprint != nullptr) ? blueprint->Defense.ArmorType.c_str() : "";
  const fa::list<fa::string> armorDefinitions = ARMOR_GetArmorDefinations(unitObject.GetActiveState(), armorTypeName);

  for (const fa::string& armorDefinition : armorDefinitions) {
    const char* definitionCursor = armorDefinition.c_str();
    fa::string damageTypeName{};
    if (!gpg::STR_GetToken(definitionCursor, " ", damageTypeName)) {
      continue;
    }

    const float armorMultiplier = static_cast<float>(std::atof(definitionCursor));
    ArmorMultipliers[damageTypeName] = armorMultiplier;
  }
}

/**
 * Address: 0x006A9D60 (FUN_006A9D60, ?ProcessArmorOnDamage@Unit@Moho@@QBEMMV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
 *
 * What it does:
 * Applies one armor multiplier lane to incoming damage when the incoming
 * damage-type token exists in `ArmorMultipliers`.
 */
float Unit::ProcessArmorOnDamage(const float amount, const fa::string damageType) const
{
  float scaledAmount = amount;
  if (const auto match = ArmorMultipliers.find(damageType); match != ArmorMultipliers.end()) {
    scaledAmount *= match->second;
  }

  return scaledAmount;
}

/**
 * Address: 0x006A9E10 (FUN_006A9E10, Moho::Unit::GetArmorMult)
 *
 * What it does:
 * Returns this unit's armor multiplier for one damage type. A damage type the
 * blueprint never listed returns 1.0, so it passes through unmodified.
 */
float Unit::GetArmorMult(const fa::string& damageType) const
{
  if (const auto match = ArmorMultipliers.find(damageType); match != ArmorMultipliers.end()) {
    return match->second;
  }

  return 1.0f;
}

/**
 * Address: 0x006A9F40 (FUN_006A9F40, Moho::Unit::Materialize)
 * Slot: 29 of ??_7Unit@Moho@@6BEntity@Moho@@@ (0x00E2A5EC)
 *
 * What it does:
 * Advances construction by `delta` and scales health to match. See the header
 * for the completion side effects.
 *
 * Returns the change actually applied to the build fraction: 0x006AA03E..
 * 0x006AA042 stores (new fraction - old fraction) into the frame slot the
 * epilogue at 0x006AA2F2 loads, on every path past the zero-delta exit.
 * CUnitReclaimTask credits reclaimed resources in proportion to it.
 */
float Unit::Materialize(const float delta)
{
  SimulationRef->Logf(
    "Unit[0x%08x]->Materialize(%.5f [0x%08x])\n", static_cast<std::uint32_t>(id_), delta,
    std::bit_cast<std::uint32_t>(delta)
  );

  // Any non-reversing step restamps the creation tick, so a unit dates from
  // when it finished rather than when it was placed.
  if (delta >= 0.0f) {
    mCreationTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
  }

  if (delta == 0.0f) {
    return 0.0f;
  }

  const float previousFraction = mVarDat.mFractionComplete;
  const float stepped = previousFraction + delta;
  if (delta <= 0.0f) {
    mVarDat.mFractionComplete = std::clamp(stepped, 0.0f, 1.0f);
  } else {
    float progressed = (stepped < 1.0f) ? stepped : 1.0f;
    if (progressed < 0.0f) {
      progressed = 0.0f;
    }
    // Never report less complete than the health already implies - health runs
    // ahead of the fraction when a part-built unit is repaired.
    const float healthRatio = mVarDat.mHealth / mVarDat.mMaxHealth;
    mVarDat.mFractionComplete = (healthRatio > progressed) ? healthRatio : progressed;
  }

  const float appliedFraction = mVarDat.mFractionComplete - previousFraction;
  AdjustHealth(nullptr, mVarDat.mMaxHealth * delta);

  if (mVarDat.mIsBeingBuilt == 0u || mVarDat.mFractionComplete != 1.0f) {
    return appliedFraction;
  }

  VarDat().mUnitStates &= ~(1ull << UNITSTATE_BeingBuilt);
  mVarDat.mIsBeingBuilt = 0u;

  const char* const layerName = (static_cast<unsigned int>(mVarDat.mLayerMask) > LAYER_Orbit)
                                  ? ""
                                  : Entity::LayerToString(mVarDat.mLayerMask);
  RunScriptOnStopBeingBuilt(CreatorRef, layerName);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint != nullptr && blueprint->General.CapCost > 0.0f) {
    if (CArmyStats* const armyStats = (ArmyRef != nullptr) ? ArmyRef->GetArmyStats() : nullptr;
        armyStats != nullptr) {
      const std::int32_t one = 1;
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_Active", &one);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &one);

      // Booked at blueprint cost, not at what the builder actually spent.
      float massCost = blueprint->Economy.BuildCostMass;
      float energyCost = blueprint->Economy.BuildCostEnergy;
      (void)AddArmyStatFloatByName(armyStats, &massCost, "Units_MassValue_Built");
      (void)AddArmyStatFloatByName(armyStats, &energyCost, "Units_EnergyValue_Built");

      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
    }
  }

  // Adjacency is a structure concept; mobile units never bond to neighbours.
  if (!IsMobile()) {
    EntitySetTemplate<Unit> overlapping{};
    (void)CollectAllOverlapping(&overlapping, this);
    for (Entity* const entry : overlapping.mVec) {
      Unit* const neighbour = static_cast<Unit*>(entry);
      if (neighbour == nullptr) {
        continue;
      }
      // Both directions: each side gets told about the other.
      RunScriptOnAdjacentTo(neighbour, this);
      neighbour->RunScriptOnAdjacentTo(this, this);
    }
  }

  return appliedFraction;
}
