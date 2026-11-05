#include "moho/sim/CPlatoonPrivate.h"

namespace moho
{
}

namespace
{
  using moho::EUnitState;
  // Sentinel entity id for ground-target commands (mirrors the value in
  // CCommandLuaFunctionRegistrations.cpp; the engine uses -0x10000000).
  constexpr std::int32_t kGroundTargetEntitySentinel = -0x10000000;

  /**
   * Address: 0x00723AA0 (FUN_00723AA0)
   *
   * What it does:
   * Resolves and caches the `CPlatoon` reflection type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCPlatoonType()
  {
    if (moho::CPlatoon::sType == nullptr) {
      moho::CPlatoon::sType = gpg::LookupRType(typeid(moho::CPlatoon));
    }
    return moho::CPlatoon::sType;
  }

  /**
   * Address: 0x0072ABD0 (FUN_0072ABD0)
   *
   * What it does:
   * Registers `CScriptObject` as the reflected base of `CPlatoon`, at
   * offset 0.
   */
  void AddBase_CSCcriptObject(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CScriptObject>(typeInfo);
  }

  /**
   * Address: 0x00724B90 (FUN_00724B90)
   *
   * What it does:
   * Forwards to `AddBase_CSCcriptObject`.
   */
  [[maybe_unused]] void AddBase_CSCcriptObjectThunk(gpg::RType* const typeInfo)
  {
    AddBase_CSCcriptObject(typeInfo);
  }

  // 0x00736450 / 0x00736470 are `rb_max`/`rb_min` of `sSimConList`'s
  // `fa::map` (node 0x30, isNil@+0x2D), cited on those members in
  // legacy/containers/RbTree.h.

  /**
   * Address: 0x0072A210 (FUN_0072A210, sub_72A210)
   *
   * What it does:
   * Reads the platoon's owned squad pointers from the archive and appends each
   * recovered squad into the platoon's squad storage until the archive returns
   * a null pointer.
   */
  [[nodiscard]] gpg::ReadArchive* ReadPlatoonSquadsFromArchive(
    gpg::ReadArchive* const archive,
    moho::CPlatoon* const platoon
  )
  {
    if (archive == nullptr || platoon == nullptr) {
      return archive;
    }

    moho::CSquad* loadedSquad = nullptr;
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned(&loadedSquad, &ownerRef);
    while (loadedSquad != nullptr) {
      platoon->mSquadList.PushBack(loadedSquad);

      loadedSquad = nullptr;
      ownerRef = {};
      archive->ReadPointerOwned(&loadedSquad, &ownerRef);
    }

    return archive;
  }

  /**
   * Address: 0x0072A290 (FUN_0072A290)
   *
   * What it does:
   * Writes each squad pointer as owned, then a null unowned squad pointer
   * that ends the list.
   */
  void WritePlatoonSquadPointersToArchive(
    gpg::WriteArchive* const archive,
    moho::CPlatoon* const platoon
  )
  {
    const gpg::RRef ownerRef{};

    for (moho::CSquad** squadIt = platoon->mSquadList.begin(); squadIt != platoon->mSquadList.end(); ++squadIt) {
      gpg::RRef squadRef{};
      squadRef.mObj = *squadIt;
      squadRef.mType = gpg::RTypeOf<moho::CSquad>();
      gpg::WriteRawPointer(archive, squadRef, gpg::TrackedPointerState::Owned, ownerRef);
    }

    gpg::RRef terminatorRef{};
    terminatorRef.mObj = nullptr;
    terminatorRef.mType = gpg::RTypeOf<moho::CSquad>();
    gpg::WriteRawPointer(archive, terminatorRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }
}

namespace moho
{
  CScrLuaMetatableFactory<CPlatoon> CScrLuaMetatableFactory<CPlatoon>::sInstance{};

  CScrLuaMetatableFactory<CPlatoon>& CScrLuaMetatableFactory<CPlatoon>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x0072B1D0 (FUN_0072B1D0)
   *
   * What it does:
   * Assigns the metatable-factory index of
   * `CScrLuaMetatableFactory<CPlatoon>` and returns that singleton.
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CPlatoon>* startup_CScrLuaMetatableFactory_CPlatoon_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CPlatoon>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CPlatoon>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00723AC0 (FUN_00723AC0, Moho::CPlatoon::GetClass)
   */
  gpg::RType* CPlatoon::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CPlatoon));
    }
    return sType;
  }

  /**
   * Address: 0x00723AE0 (FUN_00723AE0, Moho::CPlatoon::GetDerivedObjectRef)
   */
  gpg::RRef CPlatoon::GetDerivedObjectRef()
  {
    return gpg::MakeSelfRef(this);
  }

  /**
   * Address: 0x0072A300 (FUN_0072A300, Moho::CPlatoon::operator new)
   */
  CPlatoon* CPlatoon::Create(
    Sim* const sim,
    CArmyImpl* const army,
    const char* const platoonName,
    const char* const aiPlan
  )
  {
    return new (std::nothrow) CPlatoon(sim, army, platoonName, aiPlan);
  }

  /**
   * Address: 0x00724BA0 (FUN_00724BA0, Moho::CPlatoon::CPlatoon)
   */
  CPlatoon::CPlatoon()
    : CScriptObject()
    , mSim(nullptr)
    , mArmy(nullptr)
    , mUnknown_0x03C(0u)
    , mSquadList()
    , mName()
    , mPlan()
    , mUniqueName()
    , mFormation()
    , mDisbandOnIdle(false)
    , mPad_0x0E1{0u, 0u, 0u}
    , mKills(0)
    , mLosses(0)
    , mDamageDealt(0.0f)
    , mDamageReceived(0.0f)
    , mLuaUnitList()
    , mHasLuaList(false)
    , mPad_0x109{0u, 0u, 0u, 0u, 0u, 0u, 0u}
  {}
namespace
{
    [[nodiscard]] LuaPlus::LuaObject ResolvePlatoonLuaClassForCtor(LuaPlus::LuaState* const state)
    {
      LuaPlus::LuaObject platoonClass{};
      (void)func_LoadPlatoon(state, &platoonClass);
      return platoonClass;
    }
}


  /**
   * Address: 0x00724CC0 (FUN_00724CC0, Moho::CPlatoon::CPlatoon)
   */
  CPlatoon::CPlatoon(Sim* const sim, CArmyImpl* const army, const char* const platoonName, const char* const aiPlan)
    : CScriptObject(
      ResolvePlatoonLuaClassForCtor(sim ? sim->mLuaState : nullptr),
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{},
      LuaPlus::LuaObject{}
    )
    , mSim(sim)
    , mArmy(army)
    , mUnknown_0x03C(0u)
    , mSquadList()
    , mName()
    , mPlan()
    , mUniqueName()
    , mFormation()
    , mDisbandOnIdle(false)
    , mPad_0x0E1{0u, 0u, 0u}
    , mKills(0)
    , mLosses(0)
    , mDamageDealt(0.0f)
    , mDamageReceived(0.0f)
    , mLuaUnitList()
    , mHasLuaList(false)
    , mPad_0x109{0u, 0u, 0u, 0u, 0u, 0u, 0u}
  {
    if (platoonName != nullptr) {
      mName.assign(platoonName);
    }

    if (aiPlan != nullptr) {
      mPlan.assign(aiPlan);
    }

    const char* planArg = mPlan.c_str();
    CallbackStr("OnCreate", &planArg);
  }

  /**
   * Address: 0x0072A0D0 (FUN_0072A0D0, sub_72A0D0)
   */
  void CPlatoon::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CPlatoon()), 0u);
  }

  /**
   * Address: 0x0072B200 (FUN_0072B200, Moho::CSquad::MemberDeserialize)
   *
   * What it does:
   * Loads `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats` in binary
   * archive order.
   */
  void CSquad::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    gpg::RRef ownerRef{};
    archive->ReadPointer(&mSim, &ownerRef);
    archive->Read(gpg::RTypeOf<moho::EntitySetTemplate<moho::Unit>>(), &mUnits, ownerRef);

    ownerRef = {};
    archive->Read(gpg::RTypeOf<moho::ESquadClass>(), &mSquadClass, ownerRef);
    archive->ReadString(&mName);

    ownerRef = {};
    archive->Read(gpg::RTypeOf<fa::vector<moho::EntityCategorySet>>(), &mCats, ownerRef);
  }

  /**
   * Address: 0x0072B2E0 (FUN_0072B2E0, Moho::CSquad::MemberSerialize)
   *
   * What it does:
   * Saves `mSim`, `mUnits`, `mSquadClass`, `mName`, then `mCats` in binary
   * archive order.
   */
  void CSquad::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    gpg::RRef ownerRef{};
    gpg::RRef simRef{};
    gpg::AssignSimRef(&simRef, mSim);
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    ownerRef = {};
    archive->Write(gpg::RTypeOf<moho::EntitySetTemplate<moho::Unit>>(), const_cast<EntitySetTemplate<Unit>*>(&mUnits), ownerRef);

    ownerRef = {};
    archive->Write(gpg::RTypeOf<moho::ESquadClass>(), const_cast<ESquadClass*>(&mSquadClass), ownerRef);
    archive->WriteString(const_cast<fa::string*>(&mName));

    ownerRef = {};
    archive->Write(
      gpg::RTypeOf<fa::vector<moho::EntityCategorySet>>(),
      const_cast<fa::vector<EntityCategorySet>*>(&mCats),
      ownerRef
    );
  }

  /**
   * Address: 0x0072B3C0 (FUN_0072B3C0, Moho::CPlatoon::MemberDeserialize)
   *
   * What it does:
   * Loads `CScriptObject` base state, sim/army pointers, squad list, name
   * strings, and lifetime stats, in archive order.
   */
  void CPlatoon::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    gpg::RRef ownerRef{};
    archive->Read(gpg::RTypeOf<moho::CScriptObject>(), this, ownerRef);

    ownerRef = {};
    archive->ReadPointer(&mSim, &ownerRef);

    ownerRef = {};
    SimArmy* army = nullptr;
    archive->ReadPointer(&army, &ownerRef);
    mArmy = army;

    (void)ReadPlatoonSquadsFromArchive(archive, this);
    archive->ReadString(&mName);
    archive->ReadString(&mPlan);
    archive->ReadString(&mUniqueName);
    archive->ReadString(&mFormation);

    bool disbandOnIdle = false;
    archive->ReadBool(&disbandOnIdle);
    mDisbandOnIdle = disbandOnIdle;
    archive->ReadInt(&mKills);
    archive->ReadInt(&mLosses);
    archive->ReadFloat(&mDamageDealt);
    archive->ReadFloat(&mDamageReceived);

    // Engine addition (replay keyframes): see MemberSerialize.
    if (gSimExactArchive.load()) {
      bool hasLuaList = false;
      archive->ReadBool(&hasLuaList);
      if (hasLuaList) {
        ownerRef = {};
        archive->Read(gpg::LookupRType(typeid(LuaPlus::LuaObject)), &mLuaUnitList, ownerRef);
      }
      mHasLuaList = hasLuaList;
    }
  }

  /**
   * Address: 0x0072B4D0 (FUN_0072B4D0, Moho::CPlatoon::MemberSerialize)
   *
   * What it does:
   * Saves `CScriptObject` base state, sim/army pointers, squad list, name
   * strings, and lifetime stats, in archive order.
   */
  void CPlatoon::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    gpg::RRef ownerRef{};
    archive->Write(gpg::RTypeOf<moho::CScriptObject>(), const_cast<CPlatoon*>(this), ownerRef);

    ownerRef = {};
    gpg::RRef simRef{};
    gpg::AssignSimRef(&simRef, mSim);
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    ownerRef = {};
    archive->WritePointer<moho::SimArmy>(mArmy, gpg::TrackedPointerState::Unowned, ownerRef);

    WritePlatoonSquadPointersToArchive(archive, const_cast<CPlatoon*>(this));

    archive->WriteString(const_cast<fa::string*>(&mName));
    archive->WriteString(const_cast<fa::string*>(&mPlan));
    archive->WriteString(const_cast<fa::string*>(&mUniqueName));
    archive->WriteString(const_cast<fa::string*>(&mFormation));
    archive->WriteBool(mDisbandOnIdle);
    archive->WriteInt(mKills);
    archive->WriteInt(mLosses);
    archive->WriteFloat(mDamageDealt);
    archive->WriteFloat(mDamageReceived);

    // Engine addition (replay keyframes): a script gets this same table until the platoon changes,
    // with any unit that has died since. A list built again leaves those out, and the script can
    // decide otherwise. Retail saves leave it out.
    if (gSimExactArchive.load()) {
      archive->WriteBool(mHasLuaList);
      if (mHasLuaList) {
        ownerRef = {};
        archive->Write(gpg::LookupRType(typeid(LuaPlus::LuaObject)), &const_cast<CPlatoon*>(this)->mLuaUnitList, ownerRef);
      }
    }
  }

  /**
   * Address: 0x00724EB0 (FUN_00724EB0, Moho::CPlatoon::~CPlatoon)
   * Address: 0x00724CA0 (FUN_00724CA0, vtable-slot-2 scalar deleting
   * destructor dispatched through the `CScriptObject` sub-object vtable:
   * casts back to `CPlatoon*` and tail-calls the body below, then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  CPlatoon::~CPlatoon()
  {
    for (CSquad* const squad : mSquadList) {
      delete squad;
    }
    mSquadList.ResetStorageToInline();
  }

  /**
   * Address: 0x00725630 (FUN_00725630, Moho::CPlatoon::GetSquad)
   */
  CSquad* CPlatoon::GetSquad(const ESquadClass squadClass) const
  {
    for (CSquad* const squad : mSquadList) {
      if (squad->mSquadClass == squadClass) {
        return squad;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00725770 (FUN_00725770, sub_725770)
   */
  EntitySetTemplate<Unit> CPlatoon::GetPlatoonUnits() const
  {
    EntitySetTemplate<Unit> units;
    for (const CSquad* const squad : mSquadList) {
      if (squad != nullptr && !squad->mUnits.Empty()) {
        const EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        units.AddRange(squadUnits.mVec.begin(), squadUnits.mVec.end());
      }
    }
    return units;
  }

  /**
   * Address: 0x00725660 (FUN_00725660, Moho::CPlatoon::CountUnassignedUnitsWithBP)
   */
  int CPlatoon::CountUnassignedUnitsWithBP(const char* const blueprintId)
  {
    const CSquad* const squad = GetSquad(ESquadClass::Unassigned);
    return squad != nullptr ? squad->CountUnitsWithBP(blueprintId) : 0;
  }

  /**
   * Address: 0x007256A0 (FUN_007256A0, Moho::CPlatoon::CountUnassignedUnitsInCategory)
   */
  int CPlatoon::CountUnassignedUnitsInCategory(const EntityCategorySet* const categorySet)
  {
    const CSquad* const squad = GetSquad(ESquadClass::Unassigned);
    return squad != nullptr ? squad->CountUnitsInCategory(categorySet) : 0;
  }

  /**
   * Address: 0x007256E0 (FUN_007256E0, Moho::CPlatoon::GetUnassignedUnitsInCategory)
   */
  void CPlatoon::GetUnassignedUnitsInCategory(
    const EntityCategorySet* const categorySet, const int maxCount, EntitySetTemplate<Unit>& outUnits
  )
  {
    if (CSquad* const squad = GetSquad(ESquadClass::Unassigned)) {
      squad->AppendUnitsInCategory(categorySet, maxCount, outUnits);
    }
  }

  /**
   * Address: 0x00725730 (FUN_00725730, Moho::CPlatoon::GetUnassignedUnitsWithBP)
   */
  void CPlatoon::GetUnassignedUnitsWithBP(
    const char* const blueprintId, const int maxCount, EntitySetTemplate<Unit>& outUnits
  )
  {
    if (CSquad* const squad = GetSquad(ESquadClass::Unassigned)) {
      squad->AppendUnitsWithBP(blueprintId, maxCount, outUnits);
    }
  }

  /**
   * Address: 0x00725840 (FUN_00725840, sub_725840)
   */
  int CPlatoon::CountUnits() const
  {
    int count = 0;
    for (const CSquad* const squad : mSquadList) {
      count += static_cast<int>(squad->mUnits.Size());
    }
    return count;
  }

  /**
   * Address: 0x007253B0 (FUN_007253B0, Moho::CPlatoon::RemoveUnit)
   */
  void CPlatoon::RemoveUnit(Unit* const unit)
  {
    mHasLuaList = false;
    for (CSquad* const squad : mSquadList) {
      if (squad->HasUnit(unit)) {
        squad->RemoveUnit(unit);
        return;
      }
    }
  }

  /**
   * Address: 0x007251D0 (FUN_007251D0, Moho::CPlatoon::IsInPlatoon)
   */
  bool CPlatoon::IsInPlatoon(const Unit* const unit) const
  {
    for (const CSquad* const squad : mSquadList) {
      if (squad->HasUnit(unit)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Address: 0x00725220 (FUN_00725220, Moho::CPlatoon::GetSquadClass)
   */
  ESquadClass CPlatoon::GetSquadClass(const Unit* const unit) const
  {
    for (const CSquad* const squad : mSquadList) {
      if (squad->HasUnit(unit)) {
        return squad->mSquadClass;
      }
    }
    return ESquadClass::Unassigned;
  }

  /**
   * Address: 0x007241F0 (FUN_007241F0)
   */
  void CPlatoon::AppendUnitsToSquad(CSquad* const squad, const EntitySetTemplate<Unit>& units)
  {
    squad->mUnits.AddRange(units.mVec.begin(), units.mVec.end());
    mHasLuaList = false;
  }

  /**
   * Address: 0x00725280 (FUN_00725280, sub_725280)
   */
  void CPlatoon::AppendUnitsToSquad(const ESquadClass squadClass, const EntitySetTemplate<Unit>& units)
  {
    if (CSquad* const squad = GetSquad(squadClass)) {
      AppendUnitsToSquad(squad, units);
    }
    mHasLuaList = false;
  }

  /**
   * Address: 0x007252D0 (FUN_007252D0, sub_7252D0)
   */
  void CPlatoon::AppendUnitToSquad(const ESquadClass squadClass, Unit* const unit)
  {
    EntitySetTemplate<Unit> singleUnitSet{};
    (void)singleUnitSet.Add(unit);
    AppendUnitsToSquad(squadClass, singleUnitSet);
  }

  /**
   * Address: 0x00725990 (FUN_00725990, sub_725990)
   */
  void CPlatoon::SetPrioritizedTargetList(
    const ESquadClass squadClass, const fa::vector<EntityCategorySet>& categories
  )
  {
    if (CSquad* const squad = GetSquad(squadClass)) {
      squad->SetPrioritizedTargetList(categories);
    }
  }

  /**
   * Address: 0x00729F90 (FUN_00729F90, Moho::CPlatoon::SquadHasState)
   *
   * What it does:
   * The binary looks up `GetSquad(squadClass)` on every pass, not the class
   * being scanned, so with the all-classes selector (no squad has class 6)
   * the answer is always false. Kept as the binary has it.
   */
  bool CPlatoon::SquadHasState(const ESquadClass squadClass, CPlatoon* const platoon, const EUnitState state)
  {
    for (std::int32_t checkedClass = 1; checkedClass < static_cast<std::int32_t>(kAllSquadClasses); ++checkedClass) {
      if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != checkedClass) {
        continue;
      }

      const CSquad* const squad = platoon->GetSquad(squadClass);
      if (squad != nullptr && squad->HasUnitWithState(state)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Address: 0x007261B0 (FUN_007261B0, Moho::CPlatoon::Stop)
   */
  void CPlatoon::Stop(const ESquadClass squadClass)
  {
    if (squadClass == kAllSquadClasses) {
      for (CSquad* const squad : mSquadList) {
        if (squad != nullptr && squad->mSquadClass != ESquadClass::Unassigned) {
          squad->Stop();
        }
      }
    } else if (CSquad* const squad = GetSquad(squadClass)) {
      squad->Stop();
    }
  }

  /**
   * Address: 0x00728A70 (FUN_00728A70, Moho::CPlatoon::LoadUnits)
   *
   * What it does:
   * Scans assigned squads for payload/transport candidates, reserves load slots
   * per transport, issues `UNITCOMMAND_TransportLoadUnits`, and returns issued
   * command weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::LoadUnits(const EntityCategorySet* const categorySet)
  {
    constexpr const char* kTransportationCategoryName = "TRANSPORTATION";

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};
    EntitySetTemplate<Unit> transportUnits{};
    EntitySetTemplate<Unit> unitsToLoad{};

    for (int squadClassValue = 1; squadClassValue < static_cast<int>(kAllSquadClasses); ++squadClassValue) {
      CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassValue));
      if (squad == nullptr) {
        continue;
      }

      const EntitySetTemplate<Unit> squadUnits(squad->mUnits);

      for (Entity* const* unitEntry = squadUnits.mVec.begin(); unitEntry != squadUnits.mVec.end(); ++unitEntry) {
        Unit* const unit = static_cast<Unit*>(*unitEntry);
        if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
          continue;
        }

        if (!unit->IsInCategory(kTransportationCategoryName)
            && EntityCategory::HasBlueprint(unit->GetBlueprint(), categorySet)) {
          (void)unitsToLoad.Add(unit);
        }
      }

      for (Entity* const* unitEntry = squadUnits.mVec.begin(); unitEntry != squadUnits.mVec.end(); ++unitEntry) {
        Unit* const unit = static_cast<Unit*>(*unitEntry);
        if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
          continue;
        }

        if (unit->IsInCategory(kTransportationCategoryName)) {
          (void)transportUnits.Add(unit);
        }
      }
    }

    if (transportUnits.Empty() || unitsToLoad.Empty()) {
      gpg::Logf(
        "Cannot perform load operation. Attempted to load %d units onto %d transports",
        static_cast<int>(unitsToLoad.Size()),
        static_cast<int>(transportUnits.Size())
      );
      return issuedCommands;
    }

    EntitySetTemplate<Unit> assignedUnits{};
    for (Entity* const* transportEntry = transportUnits.mVec.begin(); transportEntry != transportUnits.mVec.end();
         ++transportEntry) {
      Unit* const transportUnit = static_cast<Unit*>(*transportEntry);
      if (transportUnit == nullptr) {
        continue;
      }

      IAiTransport* const aiTransport = transportUnit->AiTransport;
      if (aiTransport == nullptr) {
        continue;
      }

      EntitySetTemplate<Unit> commandUnits{};
      for (Entity* const* unitEntry = unitsToLoad.mVec.begin(); unitEntry != unitsToLoad.mVec.end(); ++unitEntry) {
        Unit* const loadUnit = static_cast<Unit*>(*unitEntry);
        if (loadUnit == nullptr || assignedUnits.Contains(loadUnit)) {
          continue;
        }

        if (aiTransport->TransportAssignSlot(loadUnit, -1)) {
          (void)commandUnits.Add(loadUnit);
          (void)assignedUnits.Add(loadUnit);
        }
      }

      for (Entity* const* unitEntry = commandUnits.mVec.begin(); unitEntry != commandUnits.mVec.end(); ++unitEntry) {
        Unit* const reservedUnit = static_cast<Unit*>(*unitEntry);
        aiTransport->TransportRemoveUnitReservation(reservedUnit);
      }

      (void)commandUnits.Add(transportUnit);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(transportUnit->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, commandUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00729FE0 (FUN_00729FE0, Moho::CPlatoon::SquadsHaveOrders)
   *
   * What it does:
   * Scans assigned squad classes (1..5) and returns true only when each
   * present squad has no active orders.
   */
  bool CPlatoon::AssignedSquadsAreIdle() const
  {
    for (std::int32_t squadClass = 1; squadClass < static_cast<std::int32_t>(kAllSquadClasses); ++squadClass) {
      const CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClass));
      if (squad != nullptr && !squad->IsIdle()) {
        return false;
      }
    }
    return true;
  }

  /**
   * Address: 0x00725150 (FUN_00725150, Moho::CPlatoon::SwitchAIPlan)
   *
   * What it does:
   * Replaces platoon plan string and dispatches script `OnDestroy/OnCreate`
   * when the plan text changes.
   */
  void CPlatoon::SwitchAIPlan(const char* const planName)
  {
    const char* const normalizedPlan = (planName != nullptr) ? planName : "";
    if (mPlan == normalizedPlan) {
      return;
    }

    CScriptObject* const scriptObject = this;
    scriptObject->RunScript("OnDestroy");

    mPlan.assign(normalizedPlan);

    const char* callbackArg = normalizedPlan;
    scriptObject->CallbackStr("OnCreate", &callbackArg);
  }

  /**
   * Address: 0x0072B720 (FUN_0072B720, Moho::CPlatoon::GetArmy)
   */
  SimArmy* CPlatoon::GetArmy() const
  {
    return mArmy;
  }

  /**
   * Address: 0x0072B7A0 (FUN_0072B7A0, Moho::CPlatoon::GetLifetimeStat1)
   */
  std::int32_t CPlatoon::GetKills() const
  {
    return mKills;
  }

  /**
   * Address: 0x0072B7B0 (FUN_0072B7B0, Moho::CPlatoon::GetLifetimeStat2)
   */
  std::int32_t CPlatoon::GetLosses() const
  {
    return mLosses;
  }

  /**
   * Address: 0x0072B790 (FUN_0072B790, sub_72B790)
   */
  CPlatoon* CPlatoon::MarkDisbandOnIdle()
  {
    mDisbandOnIdle = true;
    return this;
  }

  /**
   * Address: 0x0072B7C0 (FUN_0072B7C0, sub_72B7C0)
   */
  float CPlatoon::GetDamageDealt() const
  {
    return mDamageDealt;
  }

  /**
   * Address: 0x0072B7D0 (FUN_0072B7D0, sub_72B7D0)
   */
  float CPlatoon::GetDamageReceived() const
  {
    return mDamageReceived;
  }

  /**
   * Address: 0x0072B7F0 (FUN_0072B7F0, sub_72B7F0)
   */
  bool CPlatoon::HasLuaUnitList() const
  {
    return mHasLuaList;
  }

  /**
   * Address: 0x00736D70 (FUN_00736D70, sub_736D70)
   */
  CPlatoon* CPlatoon::AddDamageDealt(const float amount)
  {
    mDamageDealt += amount;
    return this;
  }

  /**
   * Address: 0x00736D90 (FUN_00736D90, sub_736D90)
   */
  CPlatoon* CPlatoon::AddDamageReceived(const float amount)
  {
    mDamageReceived += amount;
    return this;
  }

  /**
   * Address: 0x0072B730 (FUN_0072B730, Moho::CPlatoon::SetPlatoonFormationOverride)
   */
  void CPlatoon::SetPlatoonFormationOverride(const fa::string& formationName)
  {
    mFormation = formationName;
  }

  /**
   * Address: 0x00725410 (FUN_00725410, Moho::CPlatoon::PullUnassignedUnitsFrom)
   *
   * What it does:
   * `this` is EDI and the pool ECX (CArmyImpl::DisbandPlatoon 0x0070058E);
   * the inlined `AppendUnitsToSquad` clears EDI's flag, which pins which is
   * which. Each squad's units are copied out (0x00723A50), removed from it
   * (0x007241C0 inlined), the squad is deleted, and the copy lands in the
   * pool's unassigned squad (0x007241F0 inlined). The earlier recovery
   * instead handed the units to `SimArmy::AssignUnitsToPlatoon(units,
   * "ArmyPool")` and left the squads alive; the binary never calls it.
   */
  void CPlatoon::ReturnUnitsTo(CPlatoon* const armyPool)
  {
    mHasLuaList = false;

    CSquad* const poolSquad = armyPool->GetSquad(ESquadClass::Unassigned);
    if (poolSquad == nullptr) {
      return;
    }
    armyPool->mHasLuaList = false;

    for (CSquad* const squad : mSquadList) {
      const EntitySetTemplate<Unit> units = squad->GetUnitSet();
      squad->RemoveUnits(units);
      delete squad;
      AppendUnitsToSquad(poolSquad, units);
    }
    mSquadList.ResetStorageToInline();
  }

  /**
   * Address: 0x00BDAE70 (FUN_00BDAE70, register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Forwards startup registration to `func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    return func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
  }

  /**
   * Address: 0x007259D0 (FUN_007259D0, Moho::CPlatoon::FindPrioritizedUnit)
   *
   * IDA signature (true form; the decompiler's 33-arg __userpurge is a
   * stack-analysis failure — real params derived from the caller call site
   * at 0x0072ED7B and register/stack usage in the .asm):
   * Moho::Unit *__userpurge FindPrioritizedUnit@<eax>(
   *   Moho::ESquadClass squadClass@<ecx>, Moho::CPlatoon *this@<edx>,
   *   Moho::EAlliance alliance, bool canAttack,
   *   Wm3::Vector3f const *center, float radius);
   *
   * What it does:
   * Resolves the squad for `squadClass`, snapshots that squad's prioritized
   * target-category list, gathers every unit within `radius` of `center`, and
   * for each live, attackable candidate computes its priority rank = 1-based
   * index of the first category set the unit's blueprint matches. Keeps the unit
   * with the best (lowest) rank, breaking ties by smallest squared distance to
   * `center`. Returns the best `Unit*`, or null when no candidate is admissible.
   */
  Unit* CPlatoon::FindPrioritizedUnit(
    const ESquadClass squadClass,
    const EAlliance alliance,
    const bool canAttack,
    const Wm3::Vector3f& center,
    const float radius)
  {
    // Resolve the squad for `squadClass`; it supplies the priority list and
    // gates candidates via CanAttackTarget.
    CSquad* squad = nullptr;
    for (CSquad* const candidate : mSquadList) {
      if (candidate->mSquadClass == squadClass) {
        squad = candidate;
        break;
      }
    }
    if (squad == nullptr) {
      return nullptr;
    }

    // Snapshot the squad's prioritized target-category list (the binary copies
    // squad->mCats into a local vector and frees it in the epilogue).
    const fa::vector<EntityCategorySet> priorityList = squad->mCats;

    // Gather every unit within `radius` of `center` ("ALLUNITS", alliance-filtered).
    EntitySetTemplate<Unit> gatheredUnits{};
    (void)CollectUnitsAroundPointFiltered(
      mArmy->GetArmyBrain(),
      &gatheredUnits,
      mSim->mRules->GetEntityCategory("ALLUNITS"),
      center,
      radius,
      alliance);

    // "no best yet" sentinels so the first admissible candidate always wins.
    constexpr int kBestRankUnset = 99999;

    Unit* bestUnit = nullptr;
    int bestRank = kBestRankUnset;
    float bestDistSq = gpg::pInf;

    for (Entity* const* entrySlot = gatheredUnits.mVec.begin(); entrySlot != gatheredUnits.mVec.end(); ++entrySlot) {
      Unit* const unit = (*entrySlot != nullptr) ? static_cast<Unit*>(*entrySlot) : nullptr;

      // Attack-eligibility gate runs first in this leaf (unlike FindClosestUnitToPos).
      if (canAttack && !squad->CanAttackTarget(unit)) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();

      // Rank = 1-based index of the first priority category the blueprint matches;
      // a candidate that cannot beat the current best rank is abandoned mid-scan.
      int rank = 1;
      bool matched = false;
      for (const EntityCategorySet& priorityCategory : priorityList) {
        if (EntityCategory::HasBlueprint(blueprint, &priorityCategory)) {
          matched = true;
          break;
        }
        if (++rank > bestRank) {
          break;
        }
      }
      if (!matched) {
        continue;
      }

      const Wm3::Vector3f& unitPos = unit->GetPosition();
      const float dx = center.x - unitPos.x;
      const float dy = center.y - unitPos.y;
      const float dz = center.z - unitPos.z;
      // (dy*dy + dz*dz) + dx*dx: a sum in another order can round differently and pick the other of two near-equal units.
      const float distSq = (dy * dy + dz * dz) + dx * dx;

      if (rank < bestRank || (rank == bestRank && bestDistSq > distSq)) {
        bestUnit = unit;
        bestRank = rank;
        bestDistSq = distSq;
      }
    }

    return bestUnit;
  }

  /**
   * Address: 0x00725CF0 (FUN_00725CF0, Moho::CPlatoon::FindClosestUnitToPos)
   *
   * IDA signature:
   * Moho::Unit *__userpurge FindClosestUnitToPos@<eax>(
   *   Moho::ESquadClass squadClass@<ecx>, Moho::CPlatoon *this,
   *   Moho::EntityCategorySet *category, Moho::ECompareType cmpType,
   *   Moho::EAlliance alliance, bool canAttack, Wm3::Vector3f const *pos);
   *
   * What it does:
   * Walks the owning army's recon-DB blip list and returns the live,
   * category-matching, alliance-matching source unit that best satisfies
   * `cmpType` relative to `pos`. When `canAttack` is set a candidate must also
   * pass the requested squad's attack check.
   */
  Unit* CPlatoon::FindClosestUnitToPos(
    EntityCategorySet* const category,
    const ECompareType cmpType,
    const ESquadClass squadClass,
    const EAlliance alliance,
    const bool canAttack,
    const Wm3::Vector3f& pos)
  {
    // flt_E4F6E8: negative sentinel so the first admissible candidate always wins.
    constexpr float kBestValueUnset = -1.0f;
    // dword_DFF31C: footprint-dimension -> gather-radius scale (COMPARE_LeastDefended).
    constexpr float kLeastDefendedRadiusScale = 10.0f;

    // Re-resolve the squad for `squadClass`; it also gates candidates via CanAttackTarget.
    CSquad* squad = nullptr;
    for (CSquad* const candidate : mSquadList) {
      if (candidate->mSquadClass == squadClass) {
        squad = candidate;
        break;
      }
    }
    if (squad == nullptr) {
      return nullptr;
    }

    Unit* bestUnit = nullptr;
    float bestValue = kBestValueUnset;

    for (ReconBlip* const blip : mArmy->GetReconDB()->ReconGetBlips()) {
      Unit* const unit = blip->mCreator.GetObjectPtr();
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (!EntityCategory::HasBlueprint(blueprint, category)) {
        continue;
      }

      Entity* const unitEntity = unit;
      if (mArmy->GetAllianceWith(static_cast<IArmy*>(unitEntity->ArmyRef)) != alliance) {
        continue;
      }

      float candidateValue = 0.0f;
      switch (cmpType) {
        case COMPARE_Closest:
        case COMPARE_Furthest: {
          const Wm3::Vector3f& unitPos = unit->GetPosition();
          const float dx = unitPos.x - pos.x;
          const float dy = unitPos.y - pos.y;
          const float dz = unitPos.z - pos.z;
          // 0x00725E8F: (dy*dy + dz*dz) + dx*dx; a sum in another order can round differently and pick the other of two
          // near-equal units (26902525 at beat 16871: 12825.258 and 12825.259).
          candidateValue = (dy * dy + dz * dz) + dx * dx;
          const bool better = (cmpType == COMPARE_Closest) ? (bestValue > candidateValue)
                                                           : (candidateValue > bestValue);
          if (!better && bestValue >= 0.0f) {
            continue;
          }
          break;
        }
        case COMPARE_HighestValue: {
          candidateValue = blueprint->Economy.BuildCostMass + blueprint->Economy.BuildCostEnergy;
          if (candidateValue <= bestValue && bestValue >= 0.0f) {
            continue;
          }
          break;
        }
        case COMPARE_LeastDefended: {
          // Not reached at runtime (no caller passes COMPARE_LeastDefended); recovered
          // for 1:1 completeness. Score = summed build value of nearby armed allies.
          const SFootprint& footprint = unitEntity->GetFootprint();
          std::uint8_t maxDimension = footprint.mSizeX;
          if (footprint.mSizeZ > maxDimension) {
            maxDimension = footprint.mSizeZ;
          }
          const float gatherRadius = static_cast<float>(maxDimension) * kLeastDefendedRadiusScale;

          EntitySetTemplate<Unit> nearbyDefenders{};
          (void)CollectUnitsAroundPointFiltered(
            unitEntity->ArmyRef->GetArmyBrain(),
            &nearbyDefenders,
            category,
            unit->GetPosition(),
            gatherRadius,
            ALLIANCE_Ally);

          candidateValue = 0.0f;
          for (Entity* const* defenderSlot = nearbyDefenders.mVec.begin();
               defenderSlot != nearbyDefenders.mVec.end();
               ++defenderSlot) {
            const Unit* const defender = static_cast<Unit*>(*defenderSlot);
            if (defender == nullptr) {
              continue;
            }
            const RUnitBlueprint* const defenderBlueprint = defender->GetBlueprint();
            if (!defenderBlueprint->Weapons.WeaponBlueprints.empty()) {
              candidateValue +=
                defenderBlueprint->Economy.BuildCostMass + defenderBlueprint->Economy.BuildCostEnergy;
            }
          }
          if (bestValue <= candidateValue && bestValue >= 0.0f) {
            continue;
          }
          break;
        }
        default:
          continue;
      }

      if (canAttack && !squad->CanAttackTarget(unit)) {
        continue;
      }
      bestUnit = unit;
      bestValue = candidateValue;
    }

    return bestUnit;
  }

  /**
   * Address: 0x00726120 (FUN_00726120, Moho::CPlatoon::FindClosestUnit)
   *
   * IDA signature:
   * Moho::Unit *__userpurge FindClosestUnit@<eax>(Moho::CPlatoon *this@<edi>,
   *   Moho::EntityCategorySet *category, Moho::ECompareType cmpType,
   *   Moho::ESquadClass squadClass, Moho::EAlliance alliance, bool canAttack);
   *
   * What it does:
   * Resolves the squad for `squadClass`; when it has a non-zero center delegates
   * to `FindClosestUnitToPos` using that center, otherwise returns null.
   */
  Unit* CPlatoon::FindClosestUnit(
    EntityCategorySet* const category,
    const ECompareType cmpType,
    const ESquadClass squadClass,
    const EAlliance alliance,
    const bool canAttack)
  {
    CSquad* squad = nullptr;
    for (CSquad* const candidate : mSquadList) {
      if (candidate->mSquadClass == squadClass) {
        squad = candidate;
        break;
      }
    }
    if (squad == nullptr) {
      return nullptr;
    }

    Wm3::Vector3f center;
    (void)squad->GetCenter(&center);
    if (center != Wm3::Vector3f::ZERO) {
      return FindClosestUnitToPos(category, cmpType, squadClass, alliance, canAttack, center);
    }
    return nullptr;
  }

  /**
   * What it does:
   * Issues one attack order over `units` against `target`. When a formation
   * script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormAttack carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Attack. The target is an entity
   * (AITARGET_Entity, zero position). Appends the issued command (if any) to
   * `issuedCommands`. Shared by both CPlatoon::AttackTarget dispatch branches.
   */
  static void IssuePlatoonAttackCommand(
    Sim* const sim,
    EntitySetTemplate<Unit>& units,
    Entity* const target,
    const int formationScriptIndex,
    fa::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormAttack : EUnitCommandType::UNITCOMMAND_Attack
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(target->id_);
    commandIssueData.mTarget.mPos.x = 0.0f;
    commandIssueData.mTarget.mPos.y = 0.0f;
    commandIssueData.mTarget.mPos.z = 0.0f;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // formation script index
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormAttack orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
    }
  }

  /**
   * Address: 0x00727F50 (FUN_00727F50, Moho::CPlatoon::AttackTarget)
   *
   * IDA signature:
   * void __stdcall CPlatoon::AttackTarget(CPlatoon *this,
   *     fa::vector<WeakPtr<CUnitCommand>> *outCommands, Entity *target,
   *     ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to attack `target`. If the platoon has a named formation
   * it attacks as one formation set (whole platoon); otherwise it attacks with
   * each requested attack-capable squad class independently (Attack and Artillery
   * only -- classes 1..2, or both when `squadClass` is the all-classes sentinel).
   * Each set is issued as FormAttack when a formation script resolves and it holds
   * more than one unit, else a plain Attack. Returns the issued command weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::AttackTarget(Entity* const target, const ESquadClass squadClass)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    if (mFormation.empty()) {
      // Per-squad attack: only the Attack (1) and Artillery (2) squad classes.
      for (std::int32_t squadClassIndex = 1; squadClassIndex <= 2; ++squadClassIndex) {
        if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonAttackCommand(mSim, squadUnits, target, formationScriptIndex, issuedCommands);
        }
      }
    } else {
      // Platoon-wide formation attack.
      EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonAttackCommand(mSim, platoonUnits, target, formationScriptIndex, issuedCommands);
    }

    return issuedCommands;
  }

  /**
   * What it does:
   * Issues one move order over `units` toward the entity `target`. When a
   * formation script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormMove carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Move. Appends the issued command
   * (if any) to `issuedCommands`.
   */
  static void IssuePlatoonMoveCommand(
    Sim* const sim,
    EntitySetTemplate<Unit>& units,
    Entity* const target,
    const int formationScriptIndex,
    fa::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormMove : EUnitCommandType::UNITCOMMAND_Move
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(target->id_);
    commandIssueData.mTarget.mPos.x = 0.0f;
    commandIssueData.mTarget.mPos.y = 0.0f;
    commandIssueData.mTarget.mPos.z = 0.0f;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // formation script index
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormMove orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
    }
  }

  /**
   * Address: 0x00727740 (FUN_00727740, Moho::CPlatoon::MoveToTarget)
   *
   * IDA signature:
   * void __stdcall CPlatoon::MoveToTarget(CPlatoon *this,
   *     fa::vector<WeakPtr<CUnitCommand>> *outCommands, Entity *target,
   *     char useTransports, ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to move to an entity target. Dispatches three ways:
   *   - useTransports: gathers the requested squad classes' units into one move
   *     set, plus every alive TRANSPORTATION unit across all classes, and issues a
   *     single UNITCOMMAND_Move to the combined set.
   *   - else if a named formation exists: moves the whole platoon as one formation
   *     set (FormMove / Move by the usual threshold).
   *   - else: moves each requested squad class independently (classes 1..5).
   * Returns the issued command weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::MoveToTarget(
    Entity* const target, const bool useTransports, const ESquadClass squadClass
  )
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    if (useTransports) {
      EntitySetTemplate<Unit> transports{};
      EntitySetTemplate<Unit> moveSet{};

      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();

          // Collect alive transports from every class.
          for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
            Entity* const entity = *entry;
            if (entity == nullptr) {
              continue;
            }
            Unit* const unit = static_cast<Unit*>(entity);
            if (unit == nullptr || unit->IsDead()) {
              continue;
            }
            if (unit->IsInCategory("TRANSPORTATION")) {
              (void)transports.Add(unit);
            }
          }

          // Only the requested classes' units join the move set.
          if (squadClass == kAllSquadClasses || static_cast<std::int32_t>(squadClass) == squadClassIndex) {
            moveSet.AddRange(squadUnits.mVec.begin(), squadUnits.mVec.end());
          }
        }
      }

      if (!moveSet.Empty()) {
        if (!transports.Empty()) {
          moveSet.AddRange(transports.mVec.begin(), transports.mVec.end());
        }
        IssuePlatoonMoveCommand(mSim, moveSet, target, -1, issuedCommands);
      }
    } else if (!mFormation.empty()) {
      EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonMoveCommand(mSim, platoonUnits, target, formationScriptIndex, issuedCommands);
    } else {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonMoveCommand(mSim, squadUnits, target, formationScriptIndex, issuedCommands);
        }
      }
    }

    return issuedCommands;
  }

  /**
   * What it does:
   * Issues one move order over `units` toward the ground point `target`. When a
   * formation script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormMove carrying the formation script index + identity
   * orientation; otherwise a plain UNITCOMMAND_Move. Appends the issued command
   * (if any) to `issuedCommands`.
   */
  static void IssuePlatoonMoveToLocationCommand(
    Sim* const sim,
    EntitySetTemplate<Unit>& units,
    const Wm3::Vector3f& target,
    const int formationScriptIndex,
    fa::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormMove : EUnitCommandType::UNITCOMMAND_Move
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = target;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // formation script index
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormMove orientation weight
    }

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
    }
  }

  /**
   * Address: 0x00726DE0 (FUN_00726DE0, Moho::CPlatoon::MoveToLocation)
   *
   * IDA signature:
   * void __stdcall CPlatoon::MoveToLocation(CPlatoon *this,
   *     fa::vector<WeakPtr<CUnitCommand>> *outCommands, Wm3::Vector3f *pos,
   *     char useTransports, ESquadClass squadClass)
   *
   * What it does:
   * Orders the platoon to move to a ground point (first snapped to the map/water
   * surface elevation). Dispatches three ways, mirroring MoveToTarget:
   *   - useTransports: gathers the requested squad classes' units plus every alive
   *     TRANSPORTATION unit across all classes into one move set, issues a single
   *     UNITCOMMAND_Move to the ground point.
   *   - else if a named formation exists: moves the whole platoon as one formation
   *     set (FormMove / Move by the usual threshold).
   *   - else: moves each requested squad class independently (classes 1..5).
   * Returns the issued command weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::MoveToLocation(
    Wm3::Vector3f& pos, const bool useTransports, const ESquadClass squadClass
  )
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    if (useTransports) {
      EntitySetTemplate<Unit> transports{};
      EntitySetTemplate<Unit> moveSet{};

      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();

          for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
            Entity* const entity = *entry;
            if (entity == nullptr) {
              continue;
            }
            Unit* const unit = static_cast<Unit*>(entity);
            if (unit == nullptr || unit->IsDead()) {
              continue;
            }
            if (unit->IsInCategory("TRANSPORTATION")) {
              (void)transports.Add(unit);
            }
          }

          if (squadClass == kAllSquadClasses || static_cast<std::int32_t>(squadClass) == squadClassIndex) {
            moveSet.AddRange(squadUnits.mVec.begin(), squadUnits.mVec.end());
          }
        }
      }

      if (!moveSet.Empty()) {
        if (!transports.Empty()) {
          moveSet.AddRange(transports.mVec.begin(), transports.mVec.end());
        }
        IssuePlatoonMoveToLocationCommand(mSim, moveSet, pos, -1, issuedCommands);
      }
    } else if (!mFormation.empty()) {
      EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonMoveToLocationCommand(mSim, platoonUnits, pos, formationScriptIndex, issuedCommands);
    } else {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonMoveToLocationCommand(mSim, squadUnits, pos, formationScriptIndex, issuedCommands);
        }
      }
    }

    return issuedCommands;
  }

  /**
   * Issues one aggressive-move order to a prepared unit set at `pos`.
   *
   * Unlike Move/Patrol, AggressiveMove always selects the Form* variant whenever a
   * formation script exists (`formationScriptIndex >= 0`) with no unit-count gate,
   * and always writes the orientation (script index clamped to >= 0, zero
   * quaternion, weight 1.0f) regardless of the chosen variant.
   */
  static void IssuePlatoonAggressiveMoveCommand(
    Sim* const sim,
    EntitySetTemplate<Unit>& units,
    const Wm3::Vector3f& pos,
    const int formationScriptIndex,
    fa::vector<WeakPtr<CUnitCommand>>& issuedCommands
  )
  {
    SSTICommandIssueData commandIssueData(
      formationScriptIndex >= 0 ? EUnitCommandType::UNITCOMMAND_FormAggressiveMove
                                : EUnitCommandType::UNITCOMMAND_AggressiveMove
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = pos;
    commandIssueData.unk38 = formationScriptIndex > 0 ? formationScriptIndex : 0;  // formation script index, clamped to >= 0
    commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
    commandIssueData.unk4C = 1.0f;                                                 // orientation weight

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
    if (issuedCommand != nullptr) {
      issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
    }
  }

  /**
   * Address: 0x007268E0 (FUN_007268E0, Moho::CPlatoon::AggressiveMoveToLocation)
   *
   * IDA signature:
   * std::vector<WeakPtr<CUnitCommand>>* __userpurge
   *   CPlatoon::AggressiveMoveToLocation(float* point@<edi>, CPlatoon* this,
   *                                      std::vector* out, ESquadClass squadClass);
   *
   * What it does:
   * Snaps `pos` to the terrain/water surface, then orders an aggressive move there.
   * If the platoon has a named formation it moves the whole platoon as one
   * formation set; otherwise it moves each requested squad class (1..5)
   * independently. Every command is a FormAggressiveMove when the target set has a
   * formation script, else a plain AggressiveMove. Returns the issued command
   * weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::AggressiveMoveToLocation(Wm3::Vector3f& pos, const ESquadClass squadClass)
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    if (mFormation.empty()) {
      for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
        if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
          const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
          IssuePlatoonAggressiveMoveCommand(mSim, squadUnits, pos, formationScriptIndex, issuedCommands);
        }
      }
    } else {
      EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonAggressiveMoveCommand(mSim, platoonUnits, pos, formationScriptIndex, issuedCommands);
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00728700 (FUN_00728700, Moho::CPlatoon::FerryToLocation)
   *
   * What it does:
   * Snaps `targetPos.y` to the terrain/water surface, collects transport-capable
   * (and alive, not-being-built) units across all squad classes, and issues a
   * single `UNITCOMMAND_Ferry` to that ground point.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::FerryToLocation(Wm3::Vector3f& targetPos)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(targetPos.x, targetPos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    targetPos.y = surfaceElevation;

    EntitySetTemplate<Unit> transports{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = static_cast<Unit*>(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
            continue;
          }
          if (unit->IsInCategory("TRANSPORTATION")) {
            (void)transports.Add(unit);
          }
        }
      }
    }

    if (!transports.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Ferry);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = targetPos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, transports, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x007291C0 (FUN_007291C0, Moho::CPlatoon::UnloadUnitsAtLocation)
   *
   * IDA signature:
   * gpg::fastvector_shared_ptr_CUnitCommand* __stdcall
   *   CPlatoon::UnloadUnitsAtLocation(CPlatoon* this, gpg::fastvector* out,
   *                                   EntityCategory* category, float* point);
   *
   * What it does:
   * Snaps `pos` to the terrain/water surface, then walks every squad class (1..5)
   * looking for alive, not-being-built transport/carrier units. For each such
   * carrier it inspects the units it currently holds (attached entities); every
   * held unit whose blueprint category-bit index is a member of `category` is
   * added to the unload set, and if a carrier gave up at least one held unit the
   * carrier itself is added too. Finally issues one
   * UNITCOMMAND_TransportUnloadSpecificUnits to the snapped ground point.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::UnloadUnitsAtLocation(const EntityCategorySet* const category, Wm3::Vector3f& pos)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(pos.x, pos.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    pos.y = surfaceElevation;

    EntitySetTemplate<Unit> unitsToUnload{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const carrier = static_cast<Unit*>(*entry);
          if (carrier == nullptr || carrier->IsDead() || carrier->IsBeingBuilt()) {
            continue;
          }
          if (!carrier->IsInCategory("TRANSPORTATION") && !carrier->IsInCategory("CARRIER")) {
            continue;
          }

          bool carrierGaveUpAUnit = false;
          for (Entity* const attachedEntity : carrier->GetAttachedEntities()) {
            Unit* const heldUnit = attachedEntity->IsUnit();
            if (heldUnit == nullptr) {
              continue;
            }
            const std::uint32_t ordinal = heldUnit->GetBlueprint()->mCategoryBitIndex;
            if (category->mBits.Contains(ordinal)) {
              (void)unitsToUnload.Add(heldUnit);
              carrierGaveUpAUnit = true;
            }
          }
          if (carrierGaveUpAUnit) {
            (void)unitsToUnload.Add(carrier);
          }
        }
      }
    }

    if (!unitsToUnload.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = pos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, unitsToUnload, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00729690 (FUN_00729690, Moho::CPlatoon::UnloadAllAtLocation)
   *
   * What it does:
   * Collects transport/carrier units (alive, not-being-built) across all squad
   * classes and issues one `UNITCOMMAND_TransportUnloadUnits` to `targetPos`.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::UnloadAllAtLocation(const Wm3::Vector3f& targetPos)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    EntitySetTemplate<Unit> carriers{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = static_cast<Unit*>(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt()) {
            continue;
          }
          if (unit->IsInCategory("TRANSPORTATION") || unit->IsInCategory("CARRIER")) {
            (void)carriers.Add(unit);
          }
        }
      }
    }

    if (!carriers.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = targetPos;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, carriers, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * What it does:
   * Issues one patrol order over `units` toward `target`. When a valid formation
   * script resolved and the set holds more than one unit, issues
   * UNITCOMMAND_FormPatrol carrying the formation script index and an identity
   * orientation; otherwise a plain UNITCOMMAND_Patrol. Shared by both
   * CPlatoon::Patrol dispatch branches.
   */
  static void IssuePlatoonPatrolCommand(
    Sim* const sim,
    EntitySetTemplate<Unit>& units,
    const Wm3::Vector3f& target,
    const int formationScriptIndex
  )
  {
    const bool useFormation = formationScriptIndex >= 0 && units.Size() > 1u;

    SSTICommandIssueData commandIssueData(
      useFormation ? EUnitCommandType::UNITCOMMAND_FormPatrol : EUnitCommandType::UNITCOMMAND_Patrol
    );
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = target;

    if (useFormation) {
      commandIssueData.unk38 = formationScriptIndex;  // formation script index
      commandIssueData.mOri = Zeroed<Wm3::Quaternionf>();
      commandIssueData.unk4C = 1.0f;                   // FormPatrol orientation weight
    }

    (void)IssueCommandToSelectedUnits(sim, units, commandIssueData, false);
  }

  /**
   * Address: 0x00726420 (FUN_00726420, Moho::CPlatoon::Patrol)
   *
   * IDA signature:
   * void __userpurge CPlatoon::Patrol(Wm3::Vector3f *target@<edi>, CPlatoon *this,
   *                                   ESquadClass squadClass)
   *
   * What it does:
   * Issues a patrol order for the platoon toward `target`, first snapping the
   * point to the map/water surface elevation. If the platoon has a named
   * formation it patrols the whole platoon as one formation set; otherwise it
   * patrols each requested squad class independently (Attack..Scout, or every
   * class when `squadClass` is the all-classes sentinel 6). Each set is issued as
   * FormPatrol when a formation script resolves and it holds more than one unit,
   * else a plain Patrol.
   */
  void CPlatoon::Patrol(Wm3::Vector3f& target, const ESquadClass squadClass)
  {
    // Snap the requested point to the terrain (or water, when higher) surface.
    STIMap* const mapData = mSim->mMapData;
    float surfaceElevation = mapData->mHeightField->GetElevation(target.x, target.z);
    if (mapData->mWaterEnabled && mapData->mWaterElevation > surfaceElevation) {
      surfaceElevation = mapData->mWaterElevation;
    }
    target.y = surfaceElevation;

    CAiFormationDBImpl* const formationDb = mSim->mFormationDB;

    // Platoon-wide formation patrol.
    if (!mFormation.empty()) {
      EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();
      const int formationScriptIndex = formationDb->GetScriptIndex(mFormation.c_str(), &platoonUnits);
      IssuePlatoonPatrolCommand(mSim, platoonUnits, target, formationScriptIndex);
      return;
    }

    // Per-squad-class patrol: each requested class patrols on its own.
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        const int formationScriptIndex = formationDb->GetScriptIndex(squad->mName.c_str(), &squadUnits);
        IssuePlatoonPatrolCommand(mSim, squadUnits, target, formationScriptIndex);
      }
    }
  }

  /**
   * Address: 0x00728420 (FUN_00728420, func_IssueGuardTargetToPlatoon)
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::GuardTarget(Unit* const guardTarget, const ESquadClass squadClass)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    const auto issueGuardOnUnits = [&](EntitySetTemplate<Unit>& units) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Guard);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(guardTarget->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, units, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    };

    if (mFormation.empty()) {
      for (std::int32_t squadClassIndex = 1; squadClassIndex <= 2; ++squadClassIndex) {
        if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
          continue;
        }

        if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
          EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
          issueGuardOnUnits(squadUnits);
        }
      }
    } else {
      EntitySetTemplate<Unit> formationUnits = GetPlatoonUnits();
      issueGuardOnUnits(formationUnits);
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00726210 (FUN_00726210, sub_726210)
   */
  void CPlatoon::DestroySquads(const ESquadClass squadClass)
  {
    mHasLuaList = false;

    EntitySetTemplate<Unit> doomedUnits{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < static_cast<std::int32_t>(kAllSquadClasses); ++squadClassIndex) {
      if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        const EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const entity : squadUnits.mVec) {
          Unit* const unit = static_cast<Unit*>(entity);
          if (unit != nullptr && !unit->IsDead()) {
            (void)doomedUnits.Add(unit);
          }
        }
        squad->RemoveUnits(squadUnits);
      }
    }

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_DestroySelf);
    (void)IssueCommandToSelectedUnits(mSim, doomedUnits, commandIssueData, false);
  }

  /**
   * Address: 0x00725870 (FUN_00725870, Moho::CPlatoon::GetFerryBeacons)
   *
   * IDA signature:
   * EntitySetTemplate<Unit>* __stdcall CPlatoon::GetFerryBeacons(CPlatoon* this,
   *                                                             EntitySetTemplate<Unit>* out);
   *
   * What it does:
   * Collects the ferry-beacon units the platoon is currently ferrying to: for every
   * platoon unit in the Ferrying state, the beacon named by the head of its command
   * queue (Unit::GetTransportFerryBeacon) is added to `outBeacons` (deduplicated by
   * the entity set). The decompiler mislabels the result as `std::map_uint_Entity`;
   * it is the intrusive unit set the callback then exposes to Lua.
   */
  void CPlatoon::GetFerryBeacons(EntitySetTemplate<Unit>& outBeacons)
  {
    EntitySetTemplate<Unit> platoonUnits = GetPlatoonUnits();

    for (Entity* const* entry = platoonUnits.mVec.begin(); entry != platoonUnits.mVec.end(); ++entry) {
      Unit* const unit = static_cast<Unit*>(*entry);
      if (unit == nullptr || !unit->IsUnitState(EUnitState::UNITSTATE_Ferrying)) {
        continue;
      }
      if (Unit* const beacon = unit->GetTransportFerryBeacon()) {
        (void)outBeacons.Add(beacon);
      }
    }
  }

  /**
   * Address: 0x00729A70 (FUN_00729A70, Moho::CPlatoon::UseFerryBeacon)
   *
   * IDA signature:
   * gpg::fastvector_shared_ptr_CUnitCommand* __userpurge
   *   CPlatoon::UseFerryBeacon(EntityCategory* cat@<edi>, CPlatoon* this,
   *                            gpg::fastvector* out, int beacon);
   *
   * What it does:
   * Scans every squad class (1..5) of the platoon and collects the alive,
   * not-being-built, mobile units whose blueprint ordinal is a member of
   * `category` into a single set, then issues one UNITCOMMAND_TransportLoadUnits
   * targeted at the ferry-beacon entity so those units load onto the beacon.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::UseFerryBeacon(const EntityCategorySet* const category, Unit* const beacon)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    EntitySetTemplate<Unit> loadableUnits{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          Unit* const unit = static_cast<Unit*>(*entry);
          if (unit == nullptr || unit->IsDead() || unit->IsBeingBuilt() || !unit->IsMobile()) {
            continue;
          }
          // The category bitset is keyed by the blueprint's category-bit index
          // (REntityBlueprint::mCategoryBitIndex, +0x5C -- the decompiler's
          // "mBlueprintOrdinal" on the RUnitBlueprint returned by GetBlueprint).
          const std::uint32_t ordinal = unit->GetBlueprint()->mCategoryBitIndex;
          if (category->mBits.Contains(ordinal)) {
            (void)loadableUnits.Add(unit);
          }
        }
      }
    }

    if (!loadableUnits.Empty()) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(beacon->id_);
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, loadableUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00729D20 (FUN_00729D20, Moho::CPlatoon::UseTeleporter)
   *
   * What it does:
   * Accumulates units from the matching squad classes (1..5, or all when
   * `kAllSquadClasses`) into one set, appends the teleporter unit, and issues a
   * single `UNITCOMMAND_TransportLoadUnits` targeting the teleporter. Returns
   * the issued command weak-links.
   */
  fa::vector<WeakPtr<CUnitCommand>> CPlatoon::UseTeleporter(Unit* const teleporter, const ESquadClass squadClass)
  {
    fa::vector<WeakPtr<CUnitCommand>> issuedCommands{};

    EntitySetTemplate<Unit> selectedUnits{};
    for (std::int32_t squadClassIndex = 1; squadClassIndex < 6; ++squadClassIndex) {
      if (squadClass != kAllSquadClasses && static_cast<std::int32_t>(squadClass) != squadClassIndex) {
        continue;
      }

      if (CSquad* const squad = GetSquad(static_cast<ESquadClass>(squadClassIndex))) {
        EntitySetTemplate<Unit> squadUnits = squad->GetUnitSet();
        for (Entity* const* entry = squadUnits.mVec.begin(); entry != squadUnits.mVec.end(); ++entry) {
          (void)selectedUnits.Add(static_cast<Unit*>(*entry));
        }
      }
    }

    if (!selectedUnits.Empty() && teleporter != nullptr) {
      (void)selectedUnits.Add(teleporter);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Entity;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(teleporter->GetEntityId());
      commandIssueData.mTarget.mPos.x = 0.0f;
      commandIssueData.mTarget.mPos.y = 0.0f;
      commandIssueData.mTarget.mPos.z = 0.0f;

      CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(mSim, selectedUnits, commandIssueData, false);
      if (issuedCommand != nullptr) {
        issuedCommands.push_back(WeakPtr<CUnitCommand>(issuedCommand));
      }
    }

    return issuedCommands;
  }

  /**
   * Address: 0x00BDAD90 (FUN_00BDAD90) -- record at 0x00F5A060
   *
   * What it does:
   * Publishes CPlatoon's method table as `moho.platoon_methods`;
   * /lua/sim/Platoon.lua builds its class from this table.
   */
  moho::CScrLuaInitForm* register_moho_platoon_methods()
  {
    static moho::CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.platoon_methods", &moho::CScrLuaMetatableFactory<moho::CPlatoon>::Instance(), "CPlatoon", ""
    );
    return &binder;
  }
}

namespace
{
  struct CPlatoonLuaBindingBootstrap
  {
    CPlatoonLuaBindingBootstrap()
    {
      (void)moho::register_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonUnits_LuaFuncDef();
      (void)moho::func_CPlatoonCanFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonFormPlatoon_LuaFuncDef();
      (void)moho::func_CPlatoonIsOpponentAIRunning_LuaFuncDef();
      (void)moho::func_CPlatoonDisbandOnIdle_LuaFuncDef();
      (void)moho::func_CPlatoonIsCommandsActive_LuaFuncDef();
      (void)moho::func_CPlatoonIsAttacking_LuaFuncDef();
      (void)moho::func_CPlatoonIsMoving_LuaFuncDef();
      (void)moho::func_CPlatoonIsPatrolling_LuaFuncDef();
      (void)moho::func_CPlatoonIsFerrying_LuaFuncDef();
      (void)moho::func_CPlatoonSetPrioritizedTargetList_LuaFuncDef();
      (void)moho::func_CPlatoonFindPrioritizedUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindClosestUnitToBase_LuaFuncDef();
      (void)moho::func_CPlatoonFindFurthestUnit_LuaFuncDef();
      (void)moho::func_CPlatoonFindHighestValueUnit_LuaFuncDef();
      (void)moho::func_CPlatoonCanAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonStop_LuaFuncDef();
      (void)moho::func_CPlatoonAttackTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToTarget_LuaFuncDef();
      (void)moho::func_CPlatoonMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonAggressiveMoveToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonFerryToLocation_LuaFuncDef();
      (void)moho::func_CPlatoonLoadUnits_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonUnloadAllAtLocation_LuaFuncDef();
      (void)moho::func_CPlatoonPatrol_LuaFuncDef();
      (void)moho::func_CPlatoonGuardTarget_LuaFuncDef();
      (void)moho::func_CPlatoonDestroy_LuaFuncDef();
      (void)moho::func_CPlatoonGetFerryBeacons_LuaFuncDef();
      (void)moho::func_CPlatoonUseFerryBeacon_LuaFuncDef();
      (void)moho::func_CPlatoonUseTeleporter_LuaFuncDef();
      (void)moho::func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef();
      (void)moho::func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreat_LuaFuncDef();
      (void)moho::func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef();
      (void)moho::func_CPlatoonPlatoonCategoryCount_LuaFuncDef();
      (void)::moho::register_moho_platoon_methods();
    }
  };

  [[maybe_unused]] CPlatoonLuaBindingBootstrap gCPlatoonLuaBindingBootstrap;
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
  struct CPlatoonLuaFuncDefBootstrap
  {
    CPlatoonLuaFuncDefBootstrap()
    {
      (void)::moho::func_CPlatoonGetPersonality_LuaFuncDef();
      (void)::moho::func_CPlatoonGetBrain_LuaFuncDef();
      (void)::moho::func_CPlatoonGetFactionIndex_LuaFuncDef();
      (void)::moho::func_CPlatoonUniquelyNamePlatoon_LuaFuncDef();
      (void)::moho::func_CPlatoonGetPlatoonUniqueName_LuaFuncDef();
      (void)::moho::func_CPlatoonGetAIPlan_LuaFuncDef();
      (void)::moho::func_CPlatoonSwitchAIPlan_LuaFuncDef();
      (void)::moho::func_CPlatoonGetPlatoonPosition_LuaFuncDef();
      (void)::moho::func_CPlatoonGetSquadPosition_LuaFuncDef();
      (void)::moho::func_CPlatoonGetSquadUnits_LuaFuncDef();
    }
  };

  const CPlatoonLuaFuncDefBootstrap gCPlatoonLuaFuncDefBootstrap{};
}

namespace moho
{
  /**
   * Address: 0x00724920 (FUN_00724920)
   */
  void CSquad::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CSquad()), 0u);
  }

  /**
   * `gpg::SerConstructHelper<CSquad>`, vtable 0x00E31B68.
   *
   * Address: 0x00BDABE0 (FUN_00BDABE0 -- constructs the global and registers its destructor.)
   * Address: 0x00C004D0 (FUN_00C004D0 -- the global's destructor.)
   * Address: 0x00724880 (FUN_00724880 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0072A570 (FUN_0072A570 -- `Init`.)
   * Address: 0x00724910 (FUN_00724910 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x0072AB50 (FUN_0072AB50 -- `Delete`.)
   */
  struct CSquadConstruct : gpg::SerConstructHelper<CSquad>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CSquad>`, vtable 0x00E31B78.
   *
   * Address: 0x00BDAC20 (FUN_00BDAC20 -- constructs the global and registers its destructor.)
   * Address: 0x00C00500 (FUN_00C00500 -- the global's destructor.)
   * Address: 0x007249D0 (FUN_007249D0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0072A5F0 (FUN_0072A5F0 -- `Init`.)
   * Address: 0x007249B0 (FUN_007249B0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x007249C0 (FUN_007249C0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CSquadSerializer : gpg::SerSaveLoadHelper<CSquad>
  {};
}

namespace
{
  // Address: 0x010B9688 -- process-global `CSquadConstruct` singleton.
  moho::CSquadConstruct gCSquadConstruct;

  // Address: 0x010B9820 -- process-global `CSquadSerializer` singleton.
  moho::CSquadSerializer gCSquadSerializer;
}

namespace moho
{
  /**
   * `gpg::SerConstructHelper<CPlatoon>`, vtable 0x00E31B88.
   *
   * Address: 0x00BDAC80 (FUN_00BDAC80 -- constructs the global and registers its destructor.)
   * Address: 0x00C00590 (FUN_00C00590 -- the global's destructor.)
   * Address: 0x0072A030 (FUN_0072A030 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0072A690 (FUN_0072A690 -- `Init`.)
   * Address: 0x0072A0C0 (FUN_0072A0C0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x0072AC50 (FUN_0072AC50 -- `Delete`.)
   */
  struct CPlatoonConstruct : gpg::SerConstructHelper<CPlatoon>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CPlatoon>`, vtable 0x00E31B98.
   *
   * Address: 0x00BDACC0 (FUN_00BDACC0 -- constructs the global and registers its destructor.)
   * Address: 0x00C005C0 (FUN_00C005C0 -- the global's destructor.)
   * Address: 0x0072A180 (FUN_0072A180 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0072A710 (FUN_0072A710 -- `Init`.)
   * Address: 0x0072A160 (FUN_0072A160 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0072A170 (FUN_0072A170 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CPlatoonSerializer : gpg::SerSaveLoadHelper<CPlatoon>
  {};
}

namespace
{
  // Address: 0x010B9714 -- process-global `CPlatoonConstruct` singleton.
  moho::CPlatoonConstruct gCPlatoonConstruct;

  // Address: 0x010B969C -- process-global `CPlatoonSerializer` singleton.
  moho::CPlatoonSerializer gCPlatoonSerializer;
}

