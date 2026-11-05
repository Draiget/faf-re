// Part of Unit.cpp, included there: unit data reflection and weapon info.

/**
 * Address: 0x0055C620 (FUN_0055C620, preregister_SSTIUnitVariableDataTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `SSTIUnitVariableData`.
 */
gpg::RType* preregister_SSTIUnitVariableDataTypeInfo()
{
  static SSTIUnitVariableDataTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(SSTIUnitVariableData), &typeInfo);
  return &typeInfo;
}
}

namespace
{
  struct UnitTypeInfoPreRegisterBootstrap
  {
    UnitTypeInfoPreRegisterBootstrap()
    {
      (void)moho::preregister_UnitWeaponInfoTypeInfo();
      (void)moho::preregister_SSTIUnitVariableDataTypeInfo();
    }
  };

  [[maybe_unused]] UnitTypeInfoPreRegisterBootstrap gUnitTypeInfoPreRegisterBootstrap;

  /**
   * Address: 0x0055D980 (FUN_0055D980, copy_UnitWeaponInfo_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one half-open `UnitWeaponInfo` range into destination
   * storage using the engine `UnitWeaponInfo(const UnitWeaponInfo&)` copy
   * constructor (`FUN_0055D6F0`), destroying already-constructed entries
   * before rethrowing if a copy step throws.
   */
  [[maybe_unused]] UnitWeaponInfo* CopyUnitWeaponInfoRangeWithRollback(
    const UnitWeaponInfo* const sourceBegin,
    const UnitWeaponInfo* const sourceEnd,
    UnitWeaponInfo* const destinationBegin
  )
  {
    if (sourceBegin == sourceEnd) {
      return destinationBegin;
    }

    if (sourceBegin == nullptr || sourceEnd == nullptr || destinationBegin == nullptr) {
      return destinationBegin;
    }

    UnitWeaponInfo* destinationCursor = destinationBegin;
    try {
      for (const UnitWeaponInfo* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        ::new (destinationCursor) UnitWeaponInfo(*sourceCursor);
      }
      return destinationCursor;
    } catch (...) {
      while (destinationCursor != destinationBegin) {
        --destinationCursor;
        destinationCursor->~UnitWeaponInfo();
      }
      throw;
    }
  }
}



/**
 * Address: 0x0055B6E0 (FUN_0055B6E0, ??0UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes both category bitset lanes to empty inline storage and seeds
 * default layer/radius/UI range visual-id values.
 */
UnitWeaponInfo::UnitWeaponInfo()
  : mCat1()
  , mCat2()
  , mLayer(LAYER_None)
  , mMinRadius(0.0f)
  , mMaxRadius(10000.0f)
  , mEffectiveRadius(0.0f)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  mCat1.ResetToEmpty(EntityCategoryHelper{});
  mCat2.ResetToEmpty(EntityCategoryHelper{});
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
}

/**
 * Address: 0x0055D170 (FUN_0055D170, ??1UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Releases both UI visual-id strings and restores category bitset fastvector
 * lanes to their inline storage windows.
 */
UnitWeaponInfo::~UnitWeaponInfo()
{
  mUIMaxRangeVisualId.tidy(true, 0U);
  mUIMinRangeVisualId.tidy(true, 0U);
  mCat2.mBits.mWords.ResetStorageToInline();
  mCat1.mBits.mWords.ResetStorageToInline();
}

/**
 * Address: 0x0055D6F0 (FUN_0055D6F0, ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z)
 * Mangled: ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z
 *
 * IDA signature:
 * int __userpurge sub_55D6F0@<eax>(int source@<edi>, int destination);
 *
 * What it does:
 * Copy-constructs one `UnitWeaponInfo` from `other`. Each `EntityCategorySet`
 * lane is cloned field-wise (mUniverse + mBits.mFirstWordIndex header, then
 * the variable word list via `FastVectorN2RebindAndCopy`). Scalar layer/radius
 * lanes use plain assignment. Both UI range visual-id strings are brought up
 * to inline storage defaults (size 0, capacity 15) and then assigned from the
 * source strings.
 */
UnitWeaponInfo::UnitWeaponInfo(const UnitWeaponInfo& other)
  : mCat1()
  , mCat2()
  , mLayer(other.mLayer)
  , mMinRadius(other.mMinRadius)
  , mMaxRadius(other.mMaxRadius)
  , mEffectiveRadius(other.mEffectiveRadius)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  // --- mCat1: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat1.mBits.mWords, &other.mCat1.mBits.mWords
  );

  // --- mCat2: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat2.mBits.mWords, &other.mCat2.mBits.mWords
  );

  // --- UI range visual-id strings: inline-default then assign from source. ---
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);
}

/**
 * Address: 0x0055F210 (FUN_0055F210, sub_55F210)
 *
 * IDA signature:
 * int __usercall sub_55F210@<eax>(int a1@<eax>, int a2@<esi>);
 *
 * What it does:
 * Copy-assigns one already-constructed `UnitWeaponInfo` over another. Each
 * category lane is updated header-first (`mUniverse`, then
 * `mBits.mFirstWordIndex`) and its word list copy-assigned through the
 * `gpg::fastvector_uint::cpy` lane; layer/radius values are plain stores; both
 * UI range visual-id strings are re-assigned from the source.
 *
 * Unlike the copy constructor this does NOT rebind the word lists to inline
 * storage first - the destination already owns whatever buffer it has, which is
 * why the binary calls the copy lane directly at 0x0055F225 / 0x0055F23D.
 */
UnitWeaponInfo& UnitWeaponInfo::operator=(const UnitWeaponInfo& other)
{
  // No self-assignment guard: the binary has none. Aliasing is absorbed by the
  // fastvector copy lane and by fa::string::assign.
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  {
    mCat1.mBits.mWords = other.mCat1.mBits.mWords;
  }

  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  {
    mCat2.mBits.mWords = other.mCat2.mBits.mWords;
  }

  mLayer = other.mLayer;
  mMinRadius = other.mMinRadius;
  mMaxRadius = other.mMaxRadius;
  mEffectiveRadius = other.mEffectiveRadius;

  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);

  return *this;
}

/**
 * Address: 0x0055DA10 (FUN_0055DA10, Moho::UnitWeaponInfo::MemberDeserialize)
 *
 * What it does:
 * Loads category masks, layer/radius lanes, and both UI range visual-id
 * strings from one archive payload.
 */
void UnitWeaponInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(gpg::RTypeOf<EntityCategorySet>(), &mCat1, ownerRef);
  archive->Read(gpg::RTypeOf<EntityCategorySet>(), &mCat2, ownerRef);
  archive->Read(gpg::RTypeOf<ELayer>(), &mLayer, ownerRef);
  archive->ReadFloat(&mMinRadius);
  archive->ReadFloat(&mMaxRadius);
  archive->ReadFloat(&mEffectiveRadius);
  archive->ReadString(&mUIMinRangeVisualId);
  archive->ReadString(&mUIMaxRangeVisualId);
}

/**
 * Address: 0x0055DB00 (FUN_0055DB00, Moho::UnitWeaponInfo::MemberSerialize)
 *
 * What it does:
 * Stores category masks, layer/radius lanes, and both UI range visual-id
 * strings into one archive payload.
 */
void UnitWeaponInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(gpg::RTypeOf<EntityCategorySet>(), &mCat1, ownerRef);
  archive->Write(gpg::RTypeOf<EntityCategorySet>(), &mCat2, ownerRef);
  archive->Write(gpg::RTypeOf<ELayer>(), &mLayer, ownerRef);
  archive->WriteFloat(mMinRadius);
  archive->WriteFloat(mMaxRadius);
  archive->WriteFloat(mEffectiveRadius);
  archive->WriteString(const_cast<fa::string*>(&mUIMinRangeVisualId));
  archive->WriteString(const_cast<fa::string*>(&mUIMaxRangeVisualId));
}

SSTIUnitVariableData& Unit::VarDat() noexcept
{
  return mUnitVarDat;
}

SSTIUnitVariableData const& Unit::VarDat() const noexcept
{
  return mUnitVarDat;
}

/**
 * Address: 0x006A4920 (FUN_006A4920, Moho::Unit::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::StaticGetClass()
{
  return gpg::RTypeOf<Unit>();
}

/**
 * Address: 0x006A4940 (FUN_006A4940, Moho::Unit::GetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x006A4960 (FUN_006A4960, Moho::Unit::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef Unit::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}
namespace moho
{
  bool sim_DeferBlipUnlinks = true;

  bool sim_ParallelBlipFlush = true;

  int sim_DeferBlipUnlinksTicks = 4;

  TConVar<bool> gTConVar_sim_DeferBlipUnlinks(
    "sim_DeferBlipUnlinks",
    "Take dropped blips-in-range lists off their weak chains in bulk every few ticks (same results, less work).",
    &sim_DeferBlipUnlinks
  );

  TConVar<bool> gTConVar_sim_ParallelBlipFlush(
    "sim_ParallelBlipFlush",
    "Run sim_DeferBlipUnlinks' bulk unlink on sim workers, one weak chain per job (same chains; needs sim_Workers > 0).",
    &sim_ParallelBlipFlush
  );

  TConVar<int> gTConVar_sim_DeferBlipUnlinksTicks(
    "sim_DeferBlipUnlinksTicks",
    "Ticks between the bulk unlinks of sim_DeferBlipUnlinks (at least 1).",
    &sim_DeferBlipUnlinksTicks
  );
}

namespace
{
  using BlipList = gpg::core::FastVectorN<moho::WeakPtr<moho::Entity>, 20>;

  /**
   * Engine addition (`sim_DeferBlipUnlinks`): the replaced (or, as a unit dies, dropped) heap
   * blocks of `Unit::mBlipsInRange`.
   *
   * Every refresh drops the old list, and dropping a weak pointer walks its owner's chain from the
   * head to find it. Every other unit in range linked onto that chain since, ahead of it, so each
   * drop walks nearly the whole chain - in a large fight, most of `UpdateBlipsInRange`.
   *
   * Instead the old heap block is kept, its nodes still on their chains, and every
   * `sim_DeferBlipUnlinksTicks` ticks (or once enough are waiting) every chain they are on is walked
   * once and they are all spliced out. Splicing never reorders the nodes that stay, and a new node
   * always goes in at the head, so each chain holds exactly the live nodes, in exactly the order,
   * the immediate drops leave. Until then the waiting nodes are referenced by nothing: an owner that
   * dies meanwhile blanks them with the rest of its chain, and the walk skips them. Sim thread only,
   * like all chain work.
   */
  class DeferredBlipUnlinks
  {
  public:
    /// Takes over `list`'s heap block, if it has one; the list is left empty either way.
    void Adopt(BlipList& list, const std::uint32_t tick)
    {
      const std::uint32_t interval = static_cast<std::uint32_t>(std::max(moho::sim_DeferBlipUnlinksTicks, 1));
      if (tick - mTick >= interval) {
        Flush();
        mTick = tick;
      }
      Park(list);
    }

    /// `Adopt` without the flush check, for a dying unit's list.
    void Park(BlipList& list)
    {
      const BlipList::ReleasedBlock released = list.ReleaseHeapStorage();
      if (released.begin == nullptr) {
        list.ResetStorageToInline();
        return;
      }
      mBlocks.push_back(released);
      mNodeCount += static_cast<std::size_t>(released.end - released.begin);
      if (mNodeCount >= kFlushNodeCount) {
        Flush();
      }
    }

    /// Splices every waiting node out of its chain and frees the blocks.
    void Flush()
    {
      if (mBlocks.empty()) {
        return;
      }

      mChains.clear();
      for (const BlipList::ReleasedBlock& block : mBlocks) {
        for (const moho::WeakPtr<moho::Entity>* node = block.begin; node != block.end; ++node) {
          if (node->ownerLinkSlot != nullptr) {
            mChains.push_back(node->ownerLinkSlot);
          }
        }
      }
      std::sort(mChains.begin(), mChains.end());
      std::sort(mBlocks.begin(), mBlocks.end(), [](const auto& lhs, const auto& rhs) { return lhs.begin < rhs.begin; });

      const auto isWaiting = [this](const moho::WeakPtrNode* const node) {
        const auto after = std::upper_bound(
          mBlocks.begin(), mBlocks.end(), node, [](const auto* const value, const auto& block) { return value < block.begin; }
        );
        return after != mBlocks.begin() && node < std::prev(after)->end;
      };
      mChainRuns.clear();
      for (auto first = mChains.begin(); first != mChains.end();) {
        const auto last = std::upper_bound(first, mChains.end(), *first);
        mChainRuns.push_back(ChainRun{*first, static_cast<std::size_t>(last - first)});
        first = last;
      }

      // Engine addition (sim_ParallelBlipFlush): every chain is independent - its head lives in
      // its owner and each parked node is on exactly one chain - so the walks can run on the sim
      // workers; each chain ends the same whichever thread walks it.
      constexpr std::size_t kMinParallelChains = 64u;
      constexpr std::size_t kChainGrain = 16u;
      if (moho::sim_ParallelBlipFlush && mChainRuns.size() >= kMinParallelChains && !moho::IsSimWorkerThread()
          && moho::CSimWorkerPool::ParallelEnabled()) {
        moho::CSimWorkerPool::Get().ParallelFor(
          mChainRuns.size(), kChainGrain, [this, &isWaiting](const std::size_t begin, const std::size_t end) {
            for (std::size_t index = begin; index < end; ++index) {
              moho::WeakPtr<moho::Entity>::SpliceOutOfChain(mChainRuns[index].head, mChainRuns[index].count, isWaiting);
            }
          }
        );
      } else {
        for (const ChainRun& run : mChainRuns) {
          moho::WeakPtr<moho::Entity>::SpliceOutOfChain(run.head, run.count, isWaiting);
        }
      }

      for (const BlipList::ReleasedBlock& block : mBlocks) {
        BlipList::FreeReleasedBlock(block);
      }
      mBlocks.clear();
      mNodeCount = 0;
    }

  private:
    static constexpr std::size_t kFlushNodeCount = 1u << 20;

    struct ChainRun
    {
      moho::WeakObject* head;
      std::size_t count;
    };

    std::vector<BlipList::ReleasedBlock> mBlocks;
    std::vector<moho::WeakObject*> mChains;
    std::vector<ChainRun> mChainRuns;
    std::size_t mNodeCount = 0;
    std::uint32_t mTick = 0;
  };

  [[nodiscard]] DeferredBlipUnlinks& BlipListUnlinks()
  {
    static DeferredBlipUnlinks unlinks;
    return unlinks;
  }
  template <class T>
  void DeleteAndNull(T*& object) noexcept
  {
    T* const oldObject = object;
    object = nullptr;
    delete oldObject;
  }

  void DestroyUnitEconomyRequest(CEconRequest*& request) noexcept
  {
    CEconRequest* const oldRequest = request;
    request = nullptr;
    if (oldRequest == nullptr) {
      return;
    }

    oldRequest->mNode.ListUnlink();
    delete oldRequest;
  }

  void DestroyUnitExtraStorage(CEconStorage*& storage) noexcept
  {
    CEconStorage* const oldStorage = storage;
    storage = nullptr;
    // 0x006AD759..0x006AD768 is `delete` with ~CEconStorage inlined: the
    // destructor alone withdraws the contribution, exactly once.
    delete oldStorage;
  }

  void DestroyUnitEconomyEvents(Unit& unit) noexcept
  {
    while (!unit.mEconomyEventListHead.empty()) {
      delete unit.mEconomyEventListHead.front();
    }
  }

  void ClearUnitWeakReferences(Unit& unit) noexcept
  {
    unit.CreatorRef.UnlinkFromOwnerChain();
    unit.TransportedByRef.UnlinkFromOwnerChain();
    unit.AssignedTransportRef.UnlinkFromOwnerChain();
    unit.FocusEntityRef.UnlinkFromOwnerChain();
    unit.TargetBlipEntityRef.UnlinkFromOwnerChain();
    unit.GuardedUnitRef.UnlinkFromOwnerChain();
    unit.mInfoCache.mFormationLeadRef.UnlinkFromOwnerChain();

    // Engine change (sim_DeferBlipUnlinks): a heap-held list joins the deferred bulk unlink
    // instead of walking each blip's chain now; see `DeferredBlipUnlinks`.
    if (sim_DeferBlipUnlinks && !unit.mBlipsInRange.UsesInlineStorage()) {
      BlipListUnlinks().Park(unit.mBlipsInRange);
      return;
    }

    for (WeakPtr<Entity>& blip : unit.mBlipsInRange) {
      blip.UnlinkFromOwnerChain();
    }
    unit.mBlipsInRange.ResetStorageToInline();
  }

  void ClearGuardedByOwners(Unit& unit)
  {
    std::vector<Unit*> guardedByUnits;
    if (!unit.GuardedByList.Empty()) {
      guardedByUnits.reserve(unit.GuardedByList.Size());

      for (Entity* const entry : unit.GuardedByList.mVec) {
        Unit* const guardedByUnit = static_cast<Unit*>(entry);
        if (guardedByUnit != nullptr) {
          guardedByUnits.push_back(guardedByUnit);
        }
      }
    }

    for (Unit* const guardedByUnit : guardedByUnits) {
      guardedByUnit->SetGuardedUnit(nullptr);
    }

    unit.GuardedByList.mVec.ResetStorageToInline();
    unit.GuardedByList.ListUnlinkSelf();
    unit.SetGuardedUnit(nullptr);
  }
