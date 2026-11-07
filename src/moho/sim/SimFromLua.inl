// Part of Sim.cpp, included there: resolving the sim and armies from Lua, and placement checks.

/**
 * Address: 0x0074B110 (FUN_0074B110, ?SIM_FromLuaState@Moho@@YAPAVSim@1@PAVLuaState@LuaPlus@@@Z)
 *
 * What it does:
 * Returns the global Sim pointer carried on the Lua state's global user-data.
 */
Sim* moho::SIM_FromLuaState(LuaPlus::LuaState* const state)
{
  return ResolveGlobalSim(state->m_state);
}

/**
 * Address: 0x0074B120 (FUN_0074B120, ?FlattenMapRect@Sim@Moho@@QAEXABV?$Rect2@H@gpg@@M@Z)
 * Mangled: ?FlattenMapRect@Sim@Moho@@QAEXABV?$Rect2@H@gpg@@M@Z
 *
 * IDA signature:
 * void __thiscall Moho::Sim::FlattenMapRect(Moho::Sim *this, const gpg::Rect2i &rect, float elevation);
 *
 * What it does:
 * Clamps the requested rect to the heightfield, stamps `elevation` into every
 * covered cell, records the flattened rect into both map-rect accumulation
 * lists, then re-seats each live land/seabed unit overlapping the flattened
 * area onto the new terrain.
 */
void Sim::FlattenMapRect(const gpg::Rect2i& rect, const float elevation)
{
  CHeightField* const heightField = mMapData->mHeightField.get();

  // Clamp the requested rect (expanded by one on the far edges) to the map's
  // valid cell range: [x0, min(width-1, x1+1)] x [z0, min(height-1, z1+1)].
  gpg::Rect2i clampedRect{};
  clampedRect.x0 = rect.x0;
  clampedRect.z0 = rect.z0;
  clampedRect.x1 = std::min(heightField->width - 1, rect.x1 + 1);
  clampedRect.z1 = std::min(heightField->height - 1, rect.z1 + 1);

  if (rect.x0 >= clampedRect.x1 || rect.z0 >= clampedRect.z1) {
    gpg::Warnf(kFlattenMapRectOutsideBoundaryWarning);
    return;
  }

  heightField->SetElevationRect(clampedRect, &elevation);
  SIM_NoteFlatten({clampedRect.x0, clampedRect.z0, clampedRect.x1, clampedRect.z1, elevation}); // keyframes

  // Record the flattened rect (near edges pulled back by one, far edges kept
  // clamped) into the cached and loaded map-rect lists.
  const int loX = std::max(0, rect.x0 - 1);
  const int loZ = std::max(0, rect.z0 - 1);
  const gpg::Rect2i flattenedRect{loX, loZ, clampedRect.x1, clampedRect.z1};
  mCachedMapRects.push_back(flattenedRect);
  mLoadedMapRects.push_back(flattenedRect);

  // Build the world-space query box covering the flattened area. Center is the
  // rect midpoint; extents span the full clamped rect (Y half-extent 100).
  Wm3::Vector3f boxCenter{};
  boxCenter.x = static_cast<float>(loX + clampedRect.x1) * 0.5f;
  boxCenter.y = 0.0f;
  boxCenter.z = static_cast<float>(loZ + clampedRect.z1) * 0.5f;

  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(clampedRect.x1 - loX);
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(clampedRect.z1 - loZ);

  const VAxes3 boxAxes{Wm3::Quaternionf(0.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  mOGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr) {
      continue;
    }
    if (unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }
    if (unit->mVarDat.mLayerMask != LAYER_Land && unit->mVarDat.mLayerMask != LAYER_Seabed) {
      continue;
    }

    CUnitMotion* const motion = unit->UnitMotion;
    if (motion != nullptr) {
      // Defer the re-seat to the motion controller's next surface-collision pass.
      motion->mProcessSurfaceCollision = true;
      continue;
    }

    // No motion controller: warp the unit onto the freshly-flattened terrain now.
    unit->Warp(unit->GetTransform());
  }
}

/**
 * Address: 0x00707D60 (FUN_00707D60, ?ARMY_FromLuaState@Moho@@YAPAVSimArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z)
 *
 * What it does:
 * Resolves a Lua army selector (number or name) into `CArmyImpl*`.
 */
CArmyImpl* moho::ARMY_FromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
{
  Sim* const sim = SIM_FromLuaState(state);
  if (!sim) {
    return nullptr;
  }

  if (armyObject.IsNumber()) {
    const int requestedArmy = armyObject.GetInteger();
    const int zeroBasedArmy = requestedArmy - 1;
    CArmyImpl* army = nullptr;

    if (zeroBasedArmy >= 0 && static_cast<std::size_t>(zeroBasedArmy) < sim->mArmiesList.size()) {
      army = sim->mArmiesList[static_cast<std::size_t>(zeroBasedArmy)];
    }

    if (!army) {
      if (zeroBasedArmy >= 0) {
        LuaPlus::LuaState::Error(state, "Invalid army %d", zeroBasedArmy);
      } else {
        LuaPlus::LuaState::Error(state, "Invalid army %d. (Use a 1-based index)", requestedArmy);
      }
    }
    return army;
  }

  if (armyObject.IsString()) {
    const std::string_view armyName = armyObject.GetString() ? armyObject.GetString() : "";
    const ArmyListCursor begin = sim->mArmiesList.begin();
    const ArmyListCursor end = sim->mArmiesList.end();
    const ArmyListCursor match = func_GetArmyWithName(begin, end, armyName);

    if (match == end) {
      LuaPlus::LuaState::Error(state, kUnknownArmyMessage, armyName.data());
      return nullptr;
    }

    return *match;
  }

  LuaPlus::LuaState::Error(state, kUnexpectedArmyTypeMessage);
  return nullptr;
}

/**
 * Address: 0x00707F40 (FUN_00707F40, ?ARMY_IndexFromLuaState@Moho@@YAHPAVLuaState@LuaPlus@@VLuaObject@3@@Z)
 *
 * What it does:
 * Resolves a Lua army selector (number or name) into a zero-based index.
 */
int moho::ARMY_IndexFromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
{
  Sim* const sim = SIM_FromLuaState(state);
  if (!sim) {
    return -1;
  }

  if (armyObject.IsNumber()) {
    const int requestedArmy = armyObject.GetInteger();
    if (requestedArmy > 0) {
      return requestedArmy - 1;
    }

    if (requestedArmy == 0) {
      LuaPlus::LuaState::Error(state, "Invalid army %d, (Use a 1-based index)", 0);
    }
    return -1;
  }

  if (armyObject.IsString()) {
    const std::string_view armyName = armyObject.GetString() ? armyObject.GetString() : "";
    const ArmyListCursor begin = sim->mArmiesList.begin();
    const ArmyListCursor end = sim->mArmiesList.end();
    const ArmyListCursor match = func_GetArmyWithName(begin, end, armyName);

    if (match == end) {
      LuaPlus::LuaState::Error(state, kUnknownArmyMessage, armyName.data());
      return -1;
    }

    CArmyImpl* const army = *match;
    return army ? army->mConstDat.mArmyIndex : -1;
  }

  return -1;
}

gpg::RType* Sim::sType = nullptr;
namespace
{
  // Address: 0x010BA3F0 -- process-global `SimSerializer` singleton.
  SimSerializer gSimSerializer;
}



/**
 * Address: 0x00BDBC90 (FUN_00BDBC90, dynamic initializer for the global
 * `SimSerializer` singleton)
 */
SimSerializer::SimSerializer()
  : mSerLoadFunc(&SimSerializerLoadThunk)
  , mSerSaveFunc(&SimSerializerSaveThunk)
{}

/**
 * Address: 0x0074CFB0 (FUN_0074CFB0, Moho::SimSerializer::Init)
 */
void SimSerializer::Init()
{
  gpg::RType* const type = gpg::LookupRType(typeid(Sim));
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x007432B0 (FUN_007432B0, sub_7432B0)
 */
const char* SimTypeInfo::GetName() const
{
  return "Sim";
}

/**
 * Address: 0x00743290 (FUN_00743290, sub_743290)
 */
void SimTypeInfo::Init()
{
  size_ = sizeof(Sim);
  // 0x0074329A calls nullsub_45 (0x008D8680), which is RType::Init in this build.
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00743230 (FUN_00743230, preregister_SimTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `moho::Sim`.
 */
[[nodiscard]] gpg::RType* preregister_SimTypeInfo()
{
  static SimTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(Sim), &typeInfo);
  return &typeInfo;
}
namespace moho
{

/**
 * Address: 0x00597CD0 (FUN_00597CD0, Moho::Sim::DoCollisionsFor)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DoCollisionsFor(Moho::Sim *sim, Moho::Unit *unit,
 *   gpg::fastvector_n<CollisionResult,10> *collisions);
 *
 * What it does:
 * Physical surface-collision resolution for `unit` against the pre-gathered
 * `collisions` box query. See header. The impulse math is a mass-weighted
 * separation along the XZ plane.
 */
void Sim::DoCollisionsFor(
  Sim* const sim, Unit* const owner, gpg::core::FastVectorN<CollisionResult, 10>* const collisions
)
{
  constexpr float kMinPenetration = 0.001f;      // dword_DFF0AC
  constexpr float kMinSeparationSq = 0.000001f;  // flt_DFFBE8 (1e-6)
  constexpr float kMaxSpeedFactor = 0.1f;        // dbl_E4F710+4
  constexpr float kMinPushFactor = 0.1f;         // dbl_E4F710+4 (reused as impulse-share cutoff)
  constexpr float kHalfExtentScale = 0.5f;       // flt_E4F724

  // Debug/dead/queued/naval short-circuits (asm 0x597CE4-0x597D26).
  if (ReadSimConVarBool(sim, &gSimConVar_AI_DebugCollision, false) || owner->mIsNaval || owner->IsDead() ||
      owner->DestroyQueued()) {
    return;
  }

  // Owner mass proxy + a per-owner approach-speed factor: the smaller of
  // (blueprint MaxSpeed * 0.1) and the current velocity magnitude
  // (asm 0x597D33-0x597DDA: `comiss share, speed; jbe` keeps `share` only
  // when it does not exceed `speed`). MaxSpeed lives at blueprint
  // Physics.MaxSpeed.
  const RUnitBlueprint* const ownerBlueprint = owner->GetBlueprint();
  const float ownerMass = BlueprintCollisionMass(*ownerBlueprint);

  const Wm3::Vec3f ownerVelocity = owner->GetVelocity();
  const float ownerSpeed =
    std::sqrt((ownerVelocity.x * ownerVelocity.x) + (ownerVelocity.y * ownerVelocity.y) +
      (ownerVelocity.z * ownerVelocity.z));
  const float maxSpeedShare = ownerBlueprint->Physics.MaxSpeed * kMaxSpeedFactor;
  const float approachSpeed = (maxSpeedShare > ownerSpeed) ? ownerSpeed : maxSpeedShare;

  for (const CollisionResult& hit : *collisions) {
    // Skip shallow contacts and empty records (asm 0x597E2D-0x597E4A).
    if (hit.penetrationDepth < kMinPenetration) {
      continue;
    }
    Entity* const contact = hit.sourceEntity;
    if (contact == nullptr) {
      continue;
    }

    // Props receive their OnCollision Lua callback (self, other, dir, depth).
    // `other` is the colliding unit: 0x00598660 pushes exactly one dword for
    // that argument (0x005986F5 `mov eax,[edx]` then `push eax` at
    // 0x00598700), alongside `self` copied from `this+0x20` and the four
    // floats, so what the Lua side receives is a single object pointer.
    //
    // This used to pass `*(const LuaPlus::LuaObject*)sim`, on the reading that
    // the shipped call's first argument slot holds the `Sim*`. It cannot:
    // `Sim` derives from `ICommandSink` and has nothing LuaObject-shaped at
    // offset 0, so `m_state` came out as the vtable pointer and LuaPlus threw
    // `state->l_G == m_state->m_state->l_G` on every prop collision - caught
    // and logged by `RunScriptOnCollision`, so the only symptom was that no
    // prop ever ran its collision script. IDA names that slot `a1` after
    // `DoCollisionsFor`'s first parameter, but MSVC reuses a dead argument
    // slot for a local and the decompile of this function is not reliable
    // enough to say which local; the Lua contract
    // `Prop:OnCollision(other, x, y, z, depth)` is.
    if (contact->IsProp() != nullptr) {
      contact->RunScriptOnCollision(
        owner,
        hit.direction.x,
        hit.direction.y,
        hit.direction.z,
        hit.penetrationDepth
      );
    }

    // Physical resolution only applies to unit contacts (asm 0x597EA9-0x597EB9).
    Unit* const candidate = contact->IsUnit();
    if (candidate == nullptr) {
      continue;
    }

    // Ignore "source" units (self/attached/air/etc.) and airborne colliders
    // (asm 0x597EBF-0x597ED9). mode 2 = blocker/collision-scan policy.
    if (func_IsSourceUnit(2, *owner, candidate) || candidate->mIsAir) {
      continue;
    }

    // Two units executing the exact same head command are cooperating (e.g.
    // one build order): abort the whole pass to avoid fighting them apart
    // (asm 0x597EDF-0x597F06).
    CUnitCommandQueue* const ownerQueue = owner->CommandQueue;
    if (ownerQueue->GetCurrentCommand() != nullptr) {
      CUnitCommand* const candidateCommand = candidate->CommandQueue->GetCurrentCommand();
      if (ownerQueue->GetCurrentCommand() == candidateCommand) {
        return;
      }
    }

    // Only mobile colliders on a different formation layer are resolved
    // (asm 0x597F0C-0x597F28).
    if (!candidate->IsMobile() || owner->IsSameFormationLayerWith(candidate)) {
      continue;
    }

    // Separation direction on the XZ plane, from the candidate's current
    // position toward the owner's previous-frame ("last move") position. The
    // Hex-Rays export labels the owner reference as `mVarDat.mLastTransform.pos`
    // (asm 0x597F3A/0x597F47); AdvanceCoords (FUN_00678F10, asm 0x678F20 copy)
    // proves `mVarDat.mLastTransform` is the Entity previous-frame transform at
    // +0xB8 whose position lane is Entity::PrevPosition (+0xC8) — accessed by
    // name here rather than through the export's mis-sized offsets.
    const Wm3::Vec3f& candidatePos = candidate->GetPosition();
    Wm3::Vector3f pushDir{};
    pushDir.x = owner->mVarDat.mLastTransform.pos_.x - candidatePos.x;
    pushDir.y = 0.0f;
    pushDir.z = owner->mVarDat.mLastTransform.pos_.z - candidatePos.z;

    // Coincident units get a random XZ jitter so they can still separate
    // (asm 0x597F73-0x597FD5).
    const float separationSq = (pushDir.z * pushDir.z) + (pushDir.x * pushDir.x);
    if (separationSq < kMinSeparationSq) {
      CRandomStream* const rng = sim->mRngState;
      pushDir.x = rng->FRand(-1.0f, 1.0f);
      pushDir.y = 0.0f;
      pushDir.z = rng->FRand(-1.0f, 1.0f);
    }
    Wm3::Vector3f::Normalize(&pushDir);

    // Push magnitude = max(halfMaxFootprint, penetration) + approachSpeed
    // (asm 0x597FE4-0x59802B). halfMaxFootprint = 0.5 * max(sizeX, sizeZ).
    float maxFootprintDim = ownerBlueprint->mSizeX;
    if (ownerBlueprint->mSizeZ > maxFootprintDim) {
      maxFootprintDim = ownerBlueprint->mSizeZ;
    }
    // 0x0059800A-0x0059801B: `comiss half, depth` / `jbe` keeps the depth, so
    // an unordered depth (not rejected by the 0.001 gate above) survives.
    const float halfFootprint = maxFootprintDim * kHalfExtentScale;
    float pushMagnitude = hit.penetrationDepth;
    if (halfFootprint > pushMagnitude) {
      pushMagnitude = halfFootprint;
    }
    pushMagnitude += approachSpeed;

    // Mass-weighted momentum split (asm 0x598031-0x59807A):
    //   candidateShare = ownerMass / (ownerMass + candidateMass)
    //   ownerShare     = 1 - candidateShare
    // A heavier owner claims a larger candidateShare, shoving the candidate
    // more while itself yielding less. The two AddImpulse branches below apply
    // these complementary shares.
    const float candidateMass = BlueprintCollisionMass(*candidate->GetBlueprint());
    const float candidateShare = ownerMass / (candidateMass + ownerMass);
    const float ownerShare = 1.0f - candidateShare;

    // Owner impulse (asm 0x598080-0x59811F): pushes the owner away from the
    // candidate, scaled by pushMagnitude and the owner's share.
    if (ownerShare > kMinPushFactor && CollisionImpulseAllowed(*owner, *candidate) &&
        !owner->IsUnitState(UNITSTATE_Immobile)) {
      const Wm3::Vector3f ownerImpulse{
        (pushDir.x * pushMagnitude) * ownerShare,
        (pushDir.y * pushMagnitude) * ownerShare,
        (pushDir.z * pushMagnitude) * ownerShare,
      };
      owner->UnitMotion->AddImpulse(ownerImpulse, false);
    }

    // Candidate impulse (asm 0x598131-0x5981E3): pushes the candidate the
    // opposite way (negated pushDir), scaled by pushMagnitude and the
    // candidate's share.
    if (candidateShare > kMinPushFactor && CollisionImpulseAllowed(*candidate, *owner) &&
        !candidate->IsUnitState(UNITSTATE_Immobile)) {
      const Wm3::Vector3f candidateImpulse{
        (-pushDir.x * pushMagnitude) * candidateShare,
        (-pushDir.y * pushMagnitude) * candidateShare,
        (-pushDir.z * pushMagnitude) * candidateShare,
      };
      candidate->UnitMotion->AddImpulse(candidateImpulse, false);
    }
  }
}

/**
 * Address: 0x0062DA50 (FUN_0062DA50, ?LocationIsFree@Sim@Moho@@SA_NPAV12@PAVUnit@2@PAV?$Rect2@H@gpg@@D@Z)
 *
 * IDA signature:
 * bool __cdecl Moho::Sim::LocationIsFree(Moho::Sim *sim, Moho::Unit *ignore,
 *   gpg::Rect2i *loc, char requireIdle);
 *
 * What it does:
 * Returns true when the ogrid cell rectangle `loc` is clear of live blocking
 * units (see header).
 */
bool Sim::LocationIsFree(Sim* const sim, Unit* const ignore, gpg::Rect2i* const loc, const char requireIdle)
{
  // Identity-oriented query box centered on the rect, Y half-extent 100.
  Wm3::Vector3f boxCenter{};
  boxCenter.x = static_cast<float>(loc->x0 + loc->x1) * 0.5f;
  boxCenter.y = 0.0f;
  boxCenter.z = static_cast<float>(loc->z0 + loc->z1) * 0.5f;

  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(loc->x1 - loc->x0) * 0.5f;
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(loc->z1 - loc->z0) * 0.5f;

  const VAxes3 boxAxes{Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  sim->mOGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr) {
      continue;
    }
    if (unit->IsDead() || unit == ignore) {
      continue;
    }

    // requireIdle gate: only idle units (no active head command) count as
    // blockers. Idle = null queue, empty queue, or a null/sentinel head weak-ptr.
    if (requireIdle) {
      CUnitCommandQueue* const queue = unit->CommandQueue;
      bool idle = (queue == nullptr);
      if (!idle) {
        const fa::vector<WeakPtr<CUnitCommand>>& commands = queue->mCommandVec;
        if (commands.empty()) {
          idle = true;
        } else {
          const WeakPtr<CUnitCommand>& head = commands.data()[0];
          idle = head.GetObjectPtr() == nullptr;
        }
      }
      if (!idle) {
        continue;
      }
    }

    if (unit->mVarDat.mLayerMask == LAYER_Air) {
      continue;
    }

    bool blocks;
    if (unit->IsMobile()) {
      blocks = true;
    } else {
      // Static unit: blocks only when its blueprint skirt rect overlaps `loc`.
      const Wm3::Vec3f& unitPos = unit->GetPosition();
      SCoordsVec2 unitCoords{};
      unitCoords.x = unitPos.x;
      unitCoords.z = unitPos.z;
      const gpg::Rect2f skirt = unit->GetBlueprint()->GetSkirtRect(unitCoords);

      const float locX1 = static_cast<float>(loc->x1);
      const float locX0 = static_cast<float>(loc->x0);
      const float locZ0 = static_cast<float>(loc->z0);
      const float locZ1 = static_cast<float>(loc->z1);
      blocks = locX1 > skirt.x0 && skirt.x1 > locX0 && locZ1 > skirt.z0 && skirt.z1 > locZ0 &&
        skirt.x1 > skirt.x0 && skirt.z0 < skirt.z1 && locX1 > locX0 && locZ0 < locZ1;
    }

    if (blocks) {
      // Blocking unit found. Exempt it only if it is stored in `ignore`'s transport.
      if (ignore == nullptr) {
        return false;
      }
      IAiTransport* const transport = ignore->AiTransport;
      if (transport == nullptr || !transport->TransportIsStoredUnit(unit)) {
        return false;
      }
    }
  }

  return true;
}
namespace
{
  // Per-cell displacement gate shared by both search phases. (cellCenterX,
  // cellCenterZ) is the candidate footprint-center; on success writes the
  // reserved rect and returns true. Mirrors FUN_0062DD40 asm 0x62E235-0x62E42E.
  [[nodiscard]] bool TryDisplacementCell(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, const float cellCenterX, const float cellCenterZ,
    gpg::Rect2i& outRect)
  {
    const int x0 = static_cast<int>(std::lrint(cellCenterX - static_cast<float>(footprint.mSizeX) * 0.5f));
    const int z0 = static_cast<int>(std::lrint(cellCenterZ - static_cast<float>(footprint.mSizeZ) * 0.5f));
    gpg::Rect2i rect{};
    rect.x0 = static_cast<std::int16_t>(x0);
    rect.z0 = static_cast<std::int16_t>(z0);
    rect.x1 = static_cast<std::int16_t>(x0 + footprint.mSizeX);
    rect.z1 = static_cast<std::int16_t>(z0 + footprint.mSizeZ);

    // Only test cells that (partly) escape the build rect; a candidate fully
    // inside the rect (and non-degenerate) is skipped.
    const bool insideAndValid = rect.x1 >= buildRect.x0 && buildRect.x1 >= rect.x0 &&
      rect.z1 >= buildRect.z0 && buildRect.z1 >= rect.z0 && buildRect.x0 < buildRect.x1 &&
      buildRect.z0 < buildRect.z1 && rect.x0 < rect.x1 && rect.z0 < rect.z1;
    if (insideAndValid) {
      return false;
    }

    const SOCellPos cellPos{static_cast<std::int16_t>(x0), static_cast<std::int16_t>(z0)};
    EOccupancyCaps caps = OCCUPY_MobileCheck(footprint, *sim.mMapData, cellPos);
    if (blocker.mVarDat.mLayerMask == LAYER_Water) {
      caps = static_cast<EOccupancyCaps>(
        static_cast<std::uint8_t>(caps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB));
    }
    if (static_cast<std::uint8_t>(OCCUPY_FootprintFits(oGrid, cellPos, footprint, caps)) == 0) {
      return false;
    }
    if (!blocker.CanReserveOgridRect(rect)) {
      return false;
    }
    if (!Sim::LocationIsFree(&sim, &blocker, &rect, 0)) {
      return false;
    }
    outRect = rect;
    return true;
  }

  // Phase 1: integer DDA line walk from the blocker toward a point pushed 3x the
  // rect extent along the escape direction, reconstructed from struct_Line
  // (FUN_0040D860, step=1) + the walk (FUN_0062DD40 asm 0x62E1E0-0x62E4AB).
  [[nodiscard]] bool TryPlaceAlongLine(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, const float blockerX, const float blockerZ,
    const float farX, const float farZ, gpg::Rect2i& outRect)
  {
    const float x1 = farX + 0.5f;      // far
    const float x2 = blockerX + 0.5f;  // blocker
    const float z1 = blockerZ + 0.5f;  // blocker
    const float z2 = farZ + 0.5f;      // far

    // FUN_0040D860: each axis runs blocker -> far, mirrored (and masked) when
    // the far end lies below the blocker.
    const int dirMaskX = (x1 < x2) ? -1 : 0;
    const float p0x = (dirMaskX != 0) ? -x2 : x2;  // cursorX origin (blocker)
    const float p0z = (dirMaskX != 0) ? -x1 : x1;  // xLimit (far)
    const int dirMaskZ = (z2 < z1) ? -1 : 0;
    const float p0y = (dirMaskZ != 0) ? -z1 : z1;  // cursorZ origin (blocker)
    const float p1x = (dirMaskZ != 0) ? -z2 : z2;  // zLimit (far)

    const float extentX = p0z - p0x;
    const float extentZ = p1x - p0y;
    // FUN_0040D860's inlined floor (0x0040D908, 0x0040D93A); the step-1 mask is -1.
    int cursorX = fa::FloorToIntX87(p0x);
    int cursorZ = fa::FloorToIntX87(p0y);

    for (;;) {
      const int cellDX = dirMaskX ^ cursorX;
      const int cellDZ = dirMaskZ ^ cursorZ;
      if (TryDisplacementCell(sim, oGrid, blocker, footprint, buildRect,
                              static_cast<float>(cellDX), static_cast<float>(cellDZ), outRect)) {
        return true;
      }

      const int advancedX = cursorX + 1;
      const int advancedZ = cursorZ + 1;
      const float errX = (static_cast<float>(advancedX) - p0z) * extentZ;
      const float errZ = (static_cast<float>(advancedZ) - p1x) * extentX;
      if (errZ <= errX) {
        cursorZ = advancedZ;
      } else {
        cursorX = advancedX;
      }
      if (static_cast<float>(cursorX) > p0z) {
        return false;
      }
      if (static_cast<float>(cursorZ) > p1x) {
        return false;
      }
    }
  }

  // Phase 2: expanding square-ring perimeter scan (900-cell cap), ring stride
  // 4*max(sizeX,sizeZ). Mirrors FUN_0062DD40 asm 0x62E4B1-0x62E90B.
  [[nodiscard]] bool TryPlaceInRing(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, gpg::Rect2i& outRect)
  {
    const int ringStep = 4 * std::max<int>(footprint.mSizeX, footprint.mSizeZ);
    const Wm3::Vec3f& pos = blocker.GetPosition();

    int cellsTested = 0;
    for (int radius = 1; cellsTested < 900; ++radius) {
      for (int row = -radius; row <= radius; ++row) {
        const int colStep = (row == -radius || row == radius) ? 1 : (2 * radius);
        for (int col = -radius; col <= radius; col += colStep) {
          ++cellsTested;
          // 0x0062E5A1..0x0062E626: the outer (row) offset moves along X and
          // the inner (column) offset along Z.
          const float cellX = pos.x + static_cast<float>(row * ringStep);
          const float cellZ = static_cast<float>(col * ringStep) + pos.z;
          if (TryDisplacementCell(sim, oGrid, blocker, footprint, buildRect, cellX, cellZ, outRect)) {
            return true;
          }
        }
      }
    }
    return false;
  }
}



/**
 * Address: 0x0062DD40 (FUN_0062DD40, Moho::SIM_TryToBuild)
 *
 * IDA signature:
 * void __cdecl Moho::SIM_TryToBuild(Moho::Sim *sim, Moho::CArmyImpl *army,
 *   gpg::Rect2i *rect, char requireIdle);
 *
 * What it does:
 * Clears a pending build rect of the army's own stationary/air mobile units by
 * relocating each to the nearest free footprint cell (a line walk toward the
 * rect, then an expanding ring scan), committing the new ogrid occupation and
 * issuing a one-cell navigator goal so the unit vacates the site.
 */
void SIM_TryToBuild(Sim* const sim, CArmyImpl* const army, gpg::Rect2i* const rect, const char requireIdle)
{
  COGrid* const oGrid = sim->mOGrid;

  const float centerX = static_cast<float>(rect->x0 + rect->x1) * 0.5f;
  const float centerZ = static_cast<float>(rect->z0 + rect->z1) * 0.5f;

  Wm3::Vector3f boxCenter{centerX, 0.0f, centerZ};
  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(rect->x1 - rect->x0) * 0.5f;
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(rect->z1 - rect->z0) * 0.5f;

  const float pushExtent = (boxExtents.z > boxExtents.x) ? boxExtents.z : boxExtents.x;

  const VAxes3 boxAxes{Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  oGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  // Collect our own mobile blockers that are air or currently at rest (moving
  // ground units will clear on their own), not in the air layer, not dead, and
  // (when requireIdle) idle.
  std::vector<Unit*> blockers{};
  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr || !unit->IsMobile()) {
      continue;
    }
    const bool airOrAtRest =
      unit->mIsAir || (unit->mVarDat.mCurTransform.pos_ == unit->mVarDat.mLastTransform.pos_);
    if (!airOrAtRest || unit->mVarDat.mLayerMask == LAYER_Air || unit->IsDead()) {
      continue;
    }
    if (unit->ArmyRef != army) {
      continue;
    }
    if (requireIdle && !unit->IsIdleState()) {
      continue;
    }
    blockers.push_back(unit);
  }

  for (Unit* const blocker : blockers) {
    const SFootprint& footprint = blocker->GetFootprint();
    gpg::Rect2i placedRect{};
    bool placed = false;

    // Phase 1: line walk toward a point pushed away from the rect center.
    const Wm3::Vec3f& blockerPos = blocker->GetPosition();
    float dirX = blockerPos.x - centerX;
    float dirZ = blockerPos.z - centerZ;
    Wm3::Vector3f delta{dirX, 0.0f, dirZ};
    const Wm3::Vector3f zeroVec{0.0f, 0.0f, 0.0f};
    float unitDirX;
    float unitDirZ;
    if (delta == zeroVec) {
      unitDirX = 0.0f;
      unitDirZ = 1.0f;
    } else {
      const float len = std::sqrt((dirX * dirX) + (dirZ * dirZ));
      if (len <= 0.000001f) {
        unitDirX = 0.0f;
        unitDirZ = 0.0f;
      } else {
        // 0x0062E0A9..0x0062E0D8: one reciprocal, multiplied into each lane.
        const float inverseLength = 1.0f / len;
        unitDirX = dirX * inverseLength;
        unitDirZ = dirZ * inverseLength;
      }
    }
    const float farX = blockerPos.x + (unitDirX * pushExtent) * 3.0f;
    const float farZ = blockerPos.z + (unitDirZ * pushExtent) * 3.0f;
    placed = TryPlaceAlongLine(*sim, *oGrid, *blocker, footprint, *rect,
                               blockerPos.x, blockerPos.z, farX, farZ, placedRect);

    // Phase 2: expanding ring scan if the line walk found no free cell.
    if (!placed) {
      placed = TryPlaceInRing(*sim, *oGrid, *blocker, footprint, *rect, placedRect);
    }
    if (!placed) {
      continue;
    }

    blocker->FreeOgridRect();
    blocker->ReservedOgridRectMinX = placedRect.x0;
    blocker->ReservedOgridRectMinZ = placedRect.z0;
    blocker->ReservedOgridRectMaxX = placedRect.x1;
    blocker->ReservedOgridRectMaxZ = placedRect.z1;
    blocker->SimulationRef->mOGrid->OccupyRect(placedRect);

    if (IAiNavigator* const navigator = blocker->AiNavigator) {
      const SOCellPos goalCell{static_cast<std::int16_t>(placedRect.x0), static_cast<std::int16_t>(placedRect.z0)};
      const SNavGoal goal{goalCell};
      navigator->SetGoal(goal);
    }
  }

  // 0x0062EA31..0x0062EA4F: every collected blocker -- placed or not -- then
  // gives its reserved rect back; only the navigator goals remain.
  for (Unit* const blocker : blockers) {
    blocker->FreeOgridRect();
  }
}
}




// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SimTypeInfo_e0dc23, preregister_SimTypeInfo)

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct SimLuaBinderBootstrap
  {
    SimLuaBinderBootstrap()
    {
      (void)::moho::register_RegisterUnitBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterPropBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterProjectileBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterMeshBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterTrailEmitterBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterEmitterBlueprint_LuaFuncDef();
    }
  };

  const SimLuaBinderBootstrap gSimLuaBinderBootstrap{};
} // namespace
namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct SimLuaFuncDefBootstrap
  {
    SimLuaFuncDefBootstrap()
    {
      (void)::moho::func_SpecFootprints_LuaFuncDef();
      (void)::moho::func_RandomSim_LuaFuncDef();
      (void)::moho::func_SelectedUnit_LuaFuncDef();
      (void)::moho::func_SimConExecute_LuaFuncDef();
      (void)::moho::func_TryCopyPose_LuaFuncDef();
      (void)::moho::func_FlattenMapRect_LuaFuncDef();
      (void)::moho::func_ParseEntityCategorySim_LuaFuncDef();
      (void)::moho::func_EntityCategoryContainsSim_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterDownSim_LuaFuncDef();
      (void)::moho::func_EntityCategoryCount_LuaFuncDef();
      (void)::moho::func_EntityCategoryCountAroundPosition_LuaFuncDef();
      (void)::moho::func_Warp_LuaFuncDef();
      (void)::moho::func_ChangeUnitArmy_LuaFuncDef();
      (void)::moho::func_DebugGetSelection_LuaFuncDef();
      (void)::moho::func_IsEntity_LuaFuncDef();
      (void)::moho::func_IsUnit_LuaFuncDef();
      (void)::moho::func_IsProp_LuaFuncDef();
      (void)::moho::func_IsBlip_LuaFuncDef();
      (void)::moho::func_IsProjectile_LuaFuncDef();
      (void)::moho::func_IsCollisionBeam_LuaFuncDef();
      (void)::moho::func_BlueprintLoaderUpdateProgress_LuaFuncDef();
      (void)::moho::func_RegisterBeamBlueprint_LuaFuncDef();
      (void)::moho::func_SessionIsReplaySim_LuaFuncDef();
      (void)::moho::func_SetFocusArmySim_LuaFuncDef();
      (void)::moho::func_GetTimeForProfileSim_LuaFuncDef();
      (void)::moho::func_GetMouseWorldPosSim_LuaFuncDef();
      (void)::moho::func_GetDepositsAroundPoint_LuaFuncDef();
      (void)::moho::func_SetCommandSourceSim_LuaFuncDef();
      // FAF FA-Binary-Patches additions, not in the shipped registration sequence.
      (void)::moho::func_printSim_LuaFuncDef();
      (void)::moho::func_CheatsEnabled_LuaFuncDef();
      (void)::moho::func_GetCurrentCommandSource_LuaFuncDef();
      (void)::moho::func_GenerateRandomOrientation_LuaFuncDef();
      (void)::moho::func_GetGameTimeSecondsSim_LuaFuncDef();
      (void)::moho::func_GetGameTick_LuaFuncDef();
      (void)::moho::func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef();
      (void)::moho::func_GetEntitiesInRect_LuaFuncDef();
      (void)::moho::func_GetUnitsInRect_LuaFuncDef();
      (void)::moho::func_GetReclaimablesInRect_LuaFuncDef();
      (void)::moho::func_GetMapSize_LuaFuncDef();
      (void)::moho::func_GetTerrainHeight_LuaFuncDef();
      (void)::moho::func_GetSurfaceHeight_LuaFuncDef();
      (void)::moho::func_GetTerrainTypeOffset_LuaFuncDef();
      (void)::moho::func_GetTerrainType_LuaFuncDef();
      (void)::moho::func_SetTerrainType_LuaFuncDef();
      (void)::moho::func_SetTerrainTypeRect_LuaFuncDef();
      (void)::moho::func_FlushIntelInRect_LuaFuncDef();
      (void)::moho::func_SetArmyStatsSyncArmy_LuaFuncDef();
      (void)::moho::func_GetUnitBlueprintByName_LuaFuncDef();
      (void)::moho::func_DrawLine_LuaFuncDef();
      (void)::moho::func_DrawLinePop_LuaFuncDef();
      (void)::moho::func_DrawCircle_LuaFuncDef();
      (void)::moho::func_EntityAttachTo_LuaFuncDef();
      (void)::moho::func_EntitySetOrientation_LuaFuncDef();
      (void)::moho::func_EntitySetPosition_LuaFuncDef();
      (void)::moho::func_EntityGetPosition_LuaFuncDef();
      (void)::moho::func_EntityGetPositionXYZ_LuaFuncDef();
      (void)::moho::func_EntityIsIntelEnabled_LuaFuncDef();
      (void)::moho::func_EntityEnableIntel_LuaFuncDef();
      (void)::moho::func_EntityDisableIntel_LuaFuncDef();
      (void)::moho::func_EntitySetIntelRadius_LuaFuncDef();
      (void)::moho::func_EntityGetIntelRadius_LuaFuncDef();
      (void)::moho::func_EntityInitIntel_LuaFuncDef();
      (void)::moho::func_EntityAddShooter_LuaFuncDef();
      (void)::moho::func_EntityRemoveShooter_LuaFuncDef();
      (void)::moho::func_CreateProp_LuaFuncDef();
      (void)::moho::func_EntityCreatePropAtBone_LuaFuncDef();
      (void)::moho::func_CreateResourceDeposit_LuaFuncDef();
      (void)::moho::func_ShouldCreateInitialArmyUnits_LuaFuncDef();
      (void)::moho::func_ListArmies_LuaFuncDef();
      (void)::moho::func_GetArmyBrain_LuaFuncDef();
      (void)::moho::func_SetArmyStart_LuaFuncDef();
      (void)::moho::func_GenerateArmyStart_LuaFuncDef();
      (void)::moho::func_ArmyInitializePrebuiltUnits_LuaFuncDef();
      (void)::moho::func_SetIgnoreArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetIgnorePlayableRect_LuaFuncDef();
      (void)::moho::func_IsAllySim_LuaFuncDef();
      (void)::moho::func_IsEnemySim_LuaFuncDef();
      (void)::moho::func_IsNeutralSim_LuaFuncDef();
      (void)::moho::func_ArmyIsCivilian_LuaFuncDef();
      (void)::moho::func_SetArmyFactionIndex_LuaFuncDef();
      (void)::moho::func_OkayToMessWithArmy_LuaFuncDef();
      (void)::moho::func_ArmyIsOutOfGame_LuaFuncDef();
      (void)::moho::func_SetArmyOutOfGame_LuaFuncDef();
      (void)::moho::func_SetAlliance_LuaFuncDef();
      (void)::moho::func_SetAllianceOneWay_LuaFuncDef();
      (void)::moho::func_SetAlliedVictory_LuaFuncDef();
      (void)::moho::func_ArmyGetHandicap_LuaFuncDef();
      (void)::moho::func_SetArmyEconomy_LuaFuncDef();
      (void)::moho::func_GetArmyUnitCostTotal_LuaFuncDef();
      (void)::moho::func_GetArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetArmyAIPersonality_LuaFuncDef();
      (void)::moho::func_SetArmyShowScore_LuaFuncDef();
      (void)::moho::func_SetArmyPlans_LuaFuncDef();
      (void)::moho::func_InitializeArmyAI_LuaFuncDef();
      (void)::moho::func_SetArmyColor_LuaFuncDef();
      (void)::moho::func_EndGame_LuaFuncDef();
      (void)::moho::func_IsGameOver_LuaFuncDef();
      (void)::moho::func_GetEntityById_LuaFuncDef();
      (void)::moho::func_GetUnitByIdSim_LuaFuncDef();
      (void)::moho::func_SetPlayableRect_LuaFuncDef();
      (void)::moho::func_GetFocusArmySim_LuaFuncDef();
      (void)::moho::func_AudioSetLanguageSim_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOSim_LuaFuncDef();
      (void)::moho::func_SubmitXMLArmyStats_LuaFuncDef();
      (void)::moho::func_PlayLoop_LuaFuncDef();
      (void)::moho::func_StopLoop_LuaFuncDef();
    }
  };

  const SimLuaFuncDefBootstrap gSimLuaFuncDefBootstrap{};
}

/**
 * Address: 0x00C00EC0 (FUN_00C00EC0, Moho::SimSerializer::~SimSerializer)
 */
SimSerializer::~SimSerializer() = default;

/**
 * Address: 0x007432C0 (FUN_007432C0, sub_7432C0)
 */
SimTypeInfo::~SimTypeInfo() = default;
