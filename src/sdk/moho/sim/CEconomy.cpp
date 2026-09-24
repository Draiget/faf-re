#include "CEconomy.h"

#include <bit>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/Sim.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  class SEconValueTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SEconValue";
    }

    void Init() override
    {
      size_ = sizeof(moho::SEconValue);
      gpg::RType::Init();
      Finish();
    }
  };

  class SEconTotalsTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SEconTotals";
    }

    void Init() override
    {
      size_ = sizeof(moho::SEconTotals);
      gpg::RType::Init();
      Finish();
    }
  };

  // Exact source location cited by every `HandleAssertFailure` call this
  // file's real double-registration guards raise (confirmed per-assert from
  // raw disassembly: gpgcore/reflection/serialization.h, lines 84/87/231).
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kLoadAssertText = "!type->mSerLoadFunc";
  constexpr const char* kSaveAssertText = "!type->mSerSaveFunc";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
  constexpr int kSerializationLoadLine = 84;
  constexpr int kSerializationSaveLine = 87;
  constexpr int kSerializationConstructLine = 231;

  // Address: 0x010ACF84 -- process-global `SEconValueSerializer` singleton.
  // Constructing it runs SEconValueSerializer::SEconValueSerializer()
  // (0x00BCA870), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::SEconValueSerializer gSEconValueSerializer;

  // Address: 0x010ACF98 -- process-global `SEconTotalsSerializer` singleton.
  // Same registration/dispatch mechanism as gSEconValueSerializer above.
  moho::SEconTotalsSerializer gSEconTotalsSerializer;

  // Address: 0x010BB7E0 -- process-global `CEconomySerializer` singleton.
  // Unlike the two globals above, its real ctor (0x007730A0) registers no
  // atexit cleanup, so this class declares no destructor.
  moho::CEconomySerializer gCEconomySerializer;

  // Address: 0x010BB894 -- process-global `CEconomyConstruct` singleton.
  // Unlike gCEconomySerializer above, this real ctor (FUN_00BDD0D0) DOES
  // register an atexit cleanup (FUN_00C02250) -- see CEconomyConstruct's
  // own Doxygen block for the dead-duplicate-ctor evidence.
  moho::CEconomyConstruct gCEconomyConstruct;

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType) noexcept
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = staticType;
    return out;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (!moho::SEconValue::sType) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
      if (!moho::SEconValue::sType) {
        moho::SEconValue::sType = moho::preregister_SEconValueTypeInfo();
      }
    }
    return moho::SEconValue::sType;
  }

  [[nodiscard]] gpg::RType* CachedSEconTotalsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SEconTotals));
      if (!cached) {
        cached = moho::preregister_SEconTotalsTypeInfo();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Sim));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {"Moho::CEconStorage", "CEconStorage", "class Moho::CEconStorage"};
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached != nullptr) {
          break;
        }
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconomyType()
  {
    if (moho::CEconomy::sType == nullptr) {
      moho::CEconomy::sType = gpg::LookupRType(typeid(moho::CEconomy));
    }
    return moho::CEconomy::sType;
  }

  [[nodiscard]] moho::CEconRequest* RequestFromNode(moho::TDatListItem<void, void>* const node) noexcept
  {
    return reinterpret_cast<moho::CEconRequest*>(node);
  }
} // namespace

namespace moho
{
  extern float ai_InitialEnergyCurrency;
  extern float ai_InitialMassCurrency;
  extern float ai_InitialEnergyCurrencyMax;
  extern float ai_InitialMassCurrencyMax;

  /**
   * Address: 0x00563B10 (FUN_00563B10, preregister_SEconValueTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconValue`.
   */
  gpg::RType* preregister_SEconValueTypeInfo()
  {
    static SEconValueTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SEconValue), &typeInfo);
    SEconValue::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x00563D40 (FUN_00563D40, preregister_SEconTotalsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconTotals`.
   */
  gpg::RType* preregister_SEconTotalsTypeInfo()
  {
    static SEconTotalsTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SEconTotals), &typeInfo);
    return &typeInfo;
  }

  gpg::RType* CEconomy::sType = nullptr;

  /**
   * Address: 0x00BCA870 (FUN_00BCA870, register_SEconValueSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SEconValueSerializer::SEconValueSerializer()
    : mLoadCallback(&SEconValueSerializer::Deserialize)
    , mSaveCallback(&SEconValueSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF56C0 (FUN_00BF56C0, Moho::SEconValueSerializer::~SEconValueSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SEconValueSerializer::~SEconValueSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00563C50 (FUN_00563C50, Moho::SEconValueSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SEconValue`. Reads the two-float
   * (energy, mass) pair directly through the archive; `SEconValue` has no
   * MemberDeserialize of its own, matching the binary's inline field reads.
   */
  void SEconValueSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const value = reinterpret_cast<SEconValue*>(objectPtr);
    if (archive == nullptr || value == nullptr) {
      return;
    }
    archive->ReadFloat(&value->energy);
    archive->ReadFloat(&value->mass);
  }

  /**
   * Address: 0x00563C80 (FUN_00563C80, Moho::SEconValueSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SEconValue`. Writes the two-float
   * (energy, mass) pair directly through the archive; `SEconValue` has no
   * MemberSerialize of its own, matching the binary's inline field writes.
   */
  void SEconValueSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const value = reinterpret_cast<const SEconValue*>(objectPtr);
    if (archive == nullptr || value == nullptr) {
      return;
    }
    archive->WriteFloat(value->energy);
    archive->WriteFloat(value->mass);
  }

  /**
   * Address: 0x00564010 (FUN_00564010, gpg::SerSaveLoadHelper_SEconValue::Init)
   *
   * What it does:
   * Lazily resolves `SEconValue` RTTI and installs load/save callbacks from
   * this helper object into the type descriptor.
   */
  void SEconValueSerializer::Init()
  {
    gpg::RType* const type = CachedSEconValueType();
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure(kLoadAssertText, kSerializationLoadLine, kSerializationSourcePath);
    }
    const bool saveAlreadySet = type->serSaveFunc_ != nullptr;
    type->serLoadFunc_ = mLoadCallback;
    if (saveAlreadySet) {
      gpg::HandleAssertFailure(kSaveAssertText, kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BCA8D0 (FUN_00BCA8D0, register_SEconTotalsSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SEconTotalsSerializer::SEconTotalsSerializer()
    : mLoadCallback(&SEconTotalsSerializer::Deserialize)
    , mSaveCallback(&SEconTotalsSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF5750 (FUN_00BF5750, Moho::SEconTotalsSerializer::~SEconTotalsSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SEconTotalsSerializer::~SEconTotalsSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00563E80 (FUN_00563E80, Moho::SEconTotalsSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SEconTotals`. Forwards the
   * reflected object pointer to `SEconTotals::MemberDeserialize`.
   */
  void SEconTotalsSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const totals = reinterpret_cast<SEconTotals*>(objectPtr);
    if (totals == nullptr) {
      return;
    }
    totals->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00563E90 (FUN_00563E90, Moho::SEconTotalsSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SEconTotals`. Forwards the
   * reflected object pointer to `SEconTotals::MemberSerialize`.
   */
  void SEconTotalsSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const totals = reinterpret_cast<SEconTotals*>(objectPtr);
    if (totals == nullptr) {
      return;
    }
    totals->MemberSerialize(archive);
  }

  /**
   * Address: 0x005640B0 (FUN_005640B0, gpg::SerSaveLoadHelper_SEconTotals::Init)
   *
   * What it does:
   * Lazily resolves `SEconTotals` RTTI and installs load/save callbacks from
   * this helper object into the type descriptor.
   */
  void SEconTotalsSerializer::Init()
  {
    gpg::RType* const type = CachedSEconTotalsType();
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure(kLoadAssertText, kSerializationLoadLine, kSerializationSourcePath);
    }
    const bool saveAlreadySet = type->serSaveFunc_ != nullptr;
    type->serLoadFunc_ = mLoadCallback;
    if (saveAlreadySet) {
      gpg::HandleAssertFailure(kSaveAssertText, kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00771880 (FUN_00771880, struct_EconomyData::struct_EconomyData)
   * Mangled: ??0struct_EconomyData@@QAE@@Z
   *
   * CEconomy(Sim* sim, std::int32_t armyIndex)
   *
   * IDA signature:
   * Moho::CEconomy *__thiscall struct_EconomyData::struct_EconomyData(
   *   int index, Moho::CEconomy *this, Moho::Sim *sim);
   *
   * What it does:
   * Initializes one army economy state, creates its max-storage lane, and
   * seeds stored energy/mass from the initial economy convars.
   */
  CEconomy::CEconomy(Sim* const sim, const std::int32_t armyIndex)
  {
    mSim = sim;
    mIndex = armyIndex;
    mResources = {};
    mPendingResources = {};
    mTotals = {};
    mExtraStorage = nullptr;
    mResourceSharing = 1u;
    mConsumptionData.mPrev = &mConsumptionData;
    mConsumptionData.mNext = &mConsumptionData;

    const SEconValue zeroStorage{};
    mExtraStorage = new CEconStorage(zeroStorage, this);

    const SEconValue initialMaxStorage{ai_InitialEnergyCurrencyMax, ai_InitialMassCurrencyMax};
    (void)mExtraStorage->ChangeAmt(initialMaxStorage);

    mTotals.mStored.ENERGY = ai_InitialEnergyCurrency;
    mTotals.mStored.MASS = ai_InitialMassCurrency;
  }

  /**
   * Address: 0x00772FC0 (FUN_00772FC0)
   *
   * What it does:
   * Allocates one `CEconomy` object, initializes constructor-default lanes,
   * then returns it through `SerConstructResult` as an unowned reflected ref.
   */
  void ConstructCEconomyForSerializer(gpg::SerConstructResult* const result)
  {
    CEconomy* economy = static_cast<CEconomy*>(::operator new(sizeof(CEconomy), std::nothrow));
    if (economy != nullptr) {
      economy->mSim = nullptr;
      economy->mIndex = -1;
      economy->mResources = {};
      economy->mPendingResources = {};
      economy->mTotals = {};
      economy->mExtraStorage = nullptr;
      economy->mResourceSharing = 1u;
      economy->mPad55To57[0] = 0u;
      economy->mPad55To57[1] = 0u;
      economy->mPad55To57[2] = 0u;
      economy->mConsumptionData.mPrev = &economy->mConsumptionData;
      economy->mConsumptionData.mNext = &economy->mConsumptionData;
    }

    if (result != nullptr) {
      result->SetUnowned(MakeTypedRef(economy, CachedCEconomyType()), 0u);
    }
  }

  /**
   * Address: 0x00772FB0 (FUN_00772FB0)
   *
   * What it does:
   * Serializer construct-callback thunk that forwards to
   * `ConstructCEconomyForSerializer`.
   */
  void ConstructCEconomySerializerThunk(
    gpg::ReadArchive* const, const int, gpg::RRef* const, gpg::SerConstructResult* const result
  )
  {
    ConstructCEconomyForSerializer(result);
  }

  /**
   * Address: 0x007742A0 (FUN_007742A0)
   *
   * What it does:
   * Serializer delete-callback thunk that clears one `CEconomy` object when
   * the pointer lane is non-null.
   */
  void ClearCEconomyIfPresent(CEconomy* const economy)
  {
    if (economy != nullptr) {
      (void)economy->Clear();
    }
  }

  namespace
  {
    /// The two resource lanes, in the order the binary indexes them.
    constexpr std::size_t kEnergyLane = 0u;
    constexpr std::size_t kMassLane = 1u;
    constexpr std::size_t kLaneCount = 2u;

    /// The sim runs ten ticks a second; `Economy_Trend_*` turns the per-tick
    /// figure into a per-second one with it (the float at 0x00DFF31C).
    constexpr float kTicksPerSecond = 10.0f;

    /// `mRequested - mGranted`, clamped at zero per lane, as at 0x00771BC0.
    [[nodiscard]] SEconValue OutstandingRequest(const CEconRequest& request) noexcept
    {
      const float energy = request.mRequested.energy - request.mGranted.energy;
      const float mass = request.mRequested.mass - request.mGranted.mass;
      return SEconValue{energy > 0.0f ? energy : 0.0f, mass > 0.0f ? mass : 0.0f};
    }

    [[nodiscard]] float Lane(const SEconValue& value, const std::size_t lane) noexcept
    {
      return lane == kEnergyLane ? value.energy : value.mass;
    }

    [[nodiscard]] float& Lane(SEconValue& value, const std::size_t lane) noexcept
    {
      return lane == kEnergyLane ? value.energy : value.mass;
    }

    [[nodiscard]] float Lane(const SEconPair& value, const std::size_t lane) noexcept
    {
      return lane == kEnergyLane ? value.ENERGY : value.MASS;
    }

    [[nodiscard]] float& Lane(SEconPair& value, const std::size_t lane) noexcept
    {
      return lane == kEnergyLane ? value.ENERGY : value.MASS;
    }

    /**
     * One lane of `mMaxStorage` as a float. The cap is an unsigned 64-bit pair,
     * and the split `fild` pairs the binary emits at every read of it
     * (0x007720C1, 0x00772150, 0x007723C1, 0x0077246B) are MSVC8's
     * unsigned-64 conversion -- the same sequence `SEconTotals::MaxStorageOf`
     * (0x00585920) compiles to -- not a sign-bit mask.
     */
    [[nodiscard]] float MaxStorage(const SEconTotals& totals, const std::size_t lane) noexcept
    {
      return static_cast<float>(lane == kEnergyLane ? totals.mMaxStorage.ENERGY : totals.mMaxStorage.MASS);
    }

    /// `sim.mArmiesList[index]`, or null when out of range. The binary
    /// open-codes this check at each of its three army lookups (0x00771C58,
    /// 0x00772012, 0x00772411) and dereferences the result unchecked.
    [[nodiscard]] CArmyImpl* ArmyAtEconomyIndex(const Sim& sim, const std::int32_t index) noexcept
    {
      if (index < 0 || static_cast<std::size_t>(index) >= sim.mArmiesList.size()) {
        return nullptr;
      }
      return sim.mArmiesList[static_cast<std::size_t>(index)];
    }

    /// `SimArmy::GetEconomy()` (vtable slot 9, `call [eax+24h]` at 0x00772135
    /// and 0x0077218F) hands the army's `CEconomy` out under the older
    /// `CSimArmyEconomyInfo` description of the same 0x60-byte object, which
    /// `CArmyImpl`'s constructor allocates as a `CEconomy`.
    [[nodiscard]] CEconomy* EconomyOf(CArmyImpl& army)
    {
      return reinterpret_cast<CEconomy*>(army.GetEconomy());
    }

    /// True while either lane of `economy` stores less than its cap: the test
    /// an ally has to pass to be offered overflow (0x0077213C).
    [[nodiscard]] bool HasStorageRoom(const CEconomy& economy) noexcept
    {
      for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
        if (Lane(economy.mTotals.mStored, lane) < MaxStorage(economy.mTotals, lane)) {
          return true;
        }
      }
      return false;
    }

    /// Stores `value` into one float army stat. Each "set" publish inlines this:
    /// resolve the item through `func_GetArmyStat2`, mark it float, then swap
    /// the new bits into the primary slot with a compare-exchange loop.
    void SetFloatStat(CArmyStats& stats, const char* const statPath, const float value)
    {
      CArmyStatItem* const item = ResolveArmyStatItemCachedCreate(&stats, statPath);
      item->SynchronizeAsFloat();
      const std::int32_t bits = std::bit_cast<std::int32_t>(value);
      (void)item->SetInt(&bits);
    }

    /// Adds `value` into one float army stat. The "accumulate" publishes inline
    /// the same resolve and mark, then the compare-exchange add that
    /// `StatItem::AddFloat` is.
    void AddFloatStat(CArmyStats& stats, const char* const statPath, float value)
    {
      CArmyStatItem* const item = ResolveArmyStatItemCachedCreate(&stats, statPath);
      item->SynchronizeAsFloat();
      (void)item->AddFloat(&value);
    }
  } // namespace

  /**
   * Address: 0x00771B50 (FUN_00771B50, func_ArmyProcessEconomy)
   *
   * IDA signature:
   * void __stdcall func_ArmyProcessEconomy(Moho::CEconomy *this);
   *
   * What it does:
   * The per-tick army economy solver. `Unit::HandleResourceManagement` banks
   * each producing unit's output into `mResources`; this is what turns that
   * into `mTotals`, which is what `cfunc_GetEconomyTotalsL` reports to the UI.
   * Its only caller is `CArmyImpl::OnTick`, which passes `army->EconomyInfo`
   * (`[army+0x1F4]`) at 0x006FFDC4.
   *
   * Consumption requests are served in two classes. A request that still wants
   * both energy and mass competes for the scarcer lane, so those are pooled
   * separately from requests wanting a single resource: the pooled demand sets
   * a ratio bounded by whichever lane runs out first, and single-lane requests
   * then get their own ratio out of what is left in the *other* lane. Every
   * request is granted its outstanding share at whichever ratio applies, and
   * that grant is added to its `mGranted` so the next tick asks only for the
   * remainder. The grants' sum is this tick's consumption.
   *
   * What the grants leave beyond max storage is overflow. When
   * `mResourceSharing` is set (0x00772112), it is offered to the allies from
   * `GetAlliedArmies`, in that order, that still have room in either lane:
   * each gets an equal cut of whatever is still unplaced, capped by its own
   * room, banked into its `mResources` and `mPendingResources` for its own tick
   * to store. This economy then stores what it holds clamped to
   * `[0, max storage]` whether or not anything was shared; overflow nobody
   * took is only counted, as `Economy_AccumExcess_*`.
   *
   * Last come the twenty-four `Economy_*` army stats (0x0077249E-0x00772D1B):
   * twenty-two resolved through `func_GetArmyStat2` and stored or accumulated
   * with an inlined interlocked loop, and the two `Economy_PeakStorage_*`
   * through `CArmyStats::SetUnitStatGreaterFloat`. Then both per-tick banks
   * are emptied.
   *
   * The body runs 0x00771B50-0x00772D81 (`ret 4` at 0x00772D7F). The
   * `fa_full_2026_03_26` capstone export stops at 0x007722C6, the nop pad
   * after the jump at 0x007722C4, so everything from the ally share loop on
   * has to be read from the PE.
   */
  void ProcessArmyEconomy(CEconomy& economy)
  {
    // Pass one: pool outstanding demand, splitting requests that still want
    // both lanes from those down to one (0x00771BE8 counts the non-zero lanes).
    SEconValue dualLaneDemand{0.0f, 0.0f};
    SEconValue singleLaneDemand{0.0f, 0.0f};

    TDatListItem<void, void>* const listHead = &economy.mConsumptionData;
    for (TDatListItem<void, void>* node = listHead->mNext; node != listHead; node = node->mNext) {
      const SEconValue outstanding = OutstandingRequest(*RequestFromNode(node));
      const int lanesWanted = (outstanding.energy != 0.0f ? 1 : 0) + (outstanding.mass != 0.0f ? 1 : 0);

      SEconValue& pool = lanesWanted > 1 ? dualLaneDemand : singleLaneDemand;
      pool.energy += outstanding.energy;
      pool.mass += outstanding.mass;
    }

    // Banked production, scaled by the army handicap when one is set. The gate
    // and the multiplier are read at [army+0x1DC] and [army+0x1E0] (0x00771C8D).
    CArmyImpl* const army = ArmyAtEconomyIndex(*economy.mSim, economy.mIndex);
    SEconValue banked = economy.mResources;
    if (army->mVarDat.mHandicapValue != 0.0f) {
      const float handicapExtra = army->mVarDat.mHandicapExtra;
      if (handicapExtra != 0.0f) {
        const float multiplier = handicapExtra + 1.0f;
        banked.energy *= multiplier;
        banked.mass *= multiplier;
      }
    }

    SEconValue available{
      economy.mTotals.mStored.ENERGY + banked.energy, economy.mTotals.mStored.MASS + banked.mass
    };

    const SEconValue totalDemand{
      dualLaneDemand.energy + singleLaneDemand.energy, dualLaneDemand.mass + singleLaneDemand.mass
    };

    // The pooled ratio is bounded by whichever lane runs out first; remember
    // which one, because single-lane requests are then served from the other.
    float dualLaneRatio = 1.0f;
    std::size_t limitingLane = kEnergyLane;
    for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
      const float demand = Lane(totalDemand, lane);
      if (demand * dualLaneRatio > Lane(available, lane)) {
        dualLaneRatio = Lane(available, lane) / demand;
        limitingLane = lane;
      }
    }

    SEconValue remaining{
      available.energy - dualLaneDemand.energy * dualLaneRatio,
      available.mass - dualLaneDemand.mass * dualLaneRatio
    };
    remaining.energy = remaining.energy > 0.0f ? remaining.energy : 0.0f;
    remaining.mass = remaining.mass > 0.0f ? remaining.mass : 0.0f;

    float singleLaneRatio = 1.0f;
    for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
      if (lane == limitingLane) {
        continue;
      }
      const float demand = Lane(singleLaneDemand, lane);
      if (demand * singleLaneRatio > Lane(remaining, lane)) {
        singleLaneRatio = Lane(remaining, lane) / demand;
      }
    }

    // Pass two: grant each request its share and record it, so next tick asks
    // only for the remainder. The grants sum to this tick's consumption.
    SEconValue consumed{0.0f, 0.0f};
    for (TDatListItem<void, void>* node = listHead->mNext; node != listHead; node = node->mNext) {
      CEconRequest* const request = RequestFromNode(node);
      const SEconValue outstanding = OutstandingRequest(*request);

      // A request that wants nothing from the limiting lane was pooled as a
      // single-lane one, so it is served at the single-lane ratio (0x00771E68).
      const float ratio = Lane(outstanding, limitingLane) == 0.0f ? singleLaneRatio : dualLaneRatio;
      const SEconValue granted{outstanding.energy * ratio, outstanding.mass * ratio};

      consumed.energy += granted.energy;
      consumed.mass += granted.mass;

      available.energy = available.energy - granted.energy > 0.0f ? available.energy - granted.energy : 0.0f;
      available.mass = available.mass - granted.mass > 0.0f ? available.mass - granted.mass : 0.0f;

      request->mGranted.energy += granted.energy;
      request->mGranted.mass += granted.mass;
    }

    economy.mTotals.mLastUseRequested.ENERGY = totalDemand.energy;
    economy.mTotals.mLastUseRequested.MASS = totalDemand.mass;

    // Reported usage is each pool at its own ratio, recomputed here
    // (0x00771F78-0x0077201E) -- not `consumed`, which is per request and
    // serves a single-lane request on the limiting lane at the pooled ratio.
    economy.mTotals.mLastUseActual.ENERGY =
      dualLaneDemand.energy * dualLaneRatio + singleLaneDemand.energy * singleLaneRatio;
    economy.mTotals.mLastUseActual.MASS =
      dualLaneDemand.mass * dualLaneRatio + singleLaneDemand.mass * singleLaneRatio;

    economy.mTotals.mIncome.ENERGY = economy.mResources.energy;
    economy.mTotals.mIncome.MASS = economy.mResources.mass;

    // Both locals are built whether or not sharing is on, and live to the end
    // of the function (0x00772058 fetches the allies, 0x0077205A-0x0077208A
    // arms the two-slot inline buffer).
    msvc8::vector<CArmyImpl*> allies;
    army->GetAlliedArmies(&allies);
    gpg::fastvector_n<CEconomy*, 2> recipients;

    // Overflow: whatever the grants left above max storage (0x007720B0).
    SEconValue shared{0.0f, 0.0f};
    SEconValue excess{0.0f, 0.0f};
    for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
      const float held = Lane(available, lane);
      const float cap = MaxStorage(economy.mTotals, lane);
      Lane(excess, lane) = held > cap ? held - cap : 0.0f;
    }

    if (economy.mResourceSharing != 0u) {
      // Allies still short of their cap in either lane, in army-list order.
      for (CArmyImpl* const ally : allies) {
        if (HasStorageRoom(*EconomyOf(*ally))) {
          recipients.push_back(EconomyOf(*ally));
        }
      }

      if (excess.energy != 0.0f || excess.mass != 0.0f) {
        const int recipientCount = static_cast<int>(recipients.size());
        for (int i = 0; i < recipientCount; ++i) {
          // Each ally is offered an equal cut of what is still unplaced, so
          // whatever one ally has no room for rolls on to the rest (0x00772228).
          const float fraction = 1.0f / static_cast<float>(recipientCount - i);
          SEconValue share{excess.energy * fraction, excess.mass * fraction};

          CEconomy& recipient = *recipients[static_cast<std::size_t>(i)];
          for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
            const float room = MaxStorage(recipient.mTotals, lane) - Lane(recipient.mTotals.mStored, lane);
            float& cut = Lane(share, lane);
            cut = room < 0.0f ? 0.0f : (cut < room ? cut : room);
          }

          // Banked like production, so the ally's own tick stores it.
          recipient.mResources.energy += share.energy;
          recipient.mResources.mass += share.mass;
          recipient.mPendingResources.energy += share.energy;
          recipient.mPendingResources.mass += share.mass;

          for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
            const float left = Lane(excess, lane) - Lane(share, lane);
            Lane(excess, lane) = left > 0.0f ? left : 0.0f;
          }
          shared.energy += share.energy;
          shared.mass += share.mass;
        }
      }
    }

    // What this economy holds is stored, clamped to [0, max storage]
    // (0x007723B0); the overflow was shared or is lost either way.
    for (std::size_t lane = 0u; lane < kLaneCount; ++lane) {
      const float cap = MaxStorage(economy.mTotals, lane);
      const float held = Lane(available, lane);
      const float capped = cap > held ? held : cap;
      Lane(economy.mTotals.mStored, lane) = capped < 0.0f ? 0.0f : capped;
    }

    // The army stats, in the binary's order (0x0077249E-0x00772D1B).
    CArmyStats& stats = *army->GetArmyStats();
    const SEconValue maxStorage{MaxStorage(economy.mTotals, kEnergyLane), MaxStorage(economy.mTotals, kMassLane)};

    AddFloatStat(stats, "Economy_TotalProduced_Mass", economy.mResources.mass);
    AddFloatStat(stats, "Economy_TotalProduced_Energy", economy.mResources.energy);
    AddFloatStat(stats, "Economy_TotalConsumed_Mass", consumed.mass);
    AddFloatStat(stats, "Economy_TotalConsumed_Energy", consumed.energy);
    SetFloatStat(stats, "Economy_Income_Mass", economy.mResources.mass);
    SetFloatStat(stats, "Economy_Income_Energy", economy.mResources.energy);
    SetFloatStat(stats, "Economy_Output_Mass", consumed.mass);
    SetFloatStat(stats, "Economy_Output_Energy", consumed.energy);
    SetFloatStat(stats, "Economy_Stored_Mass", economy.mTotals.mStored.MASS);
    SetFloatStat(stats, "Economy_Stored_Energy", economy.mTotals.mStored.ENERGY);
    SetFloatStat(stats, "Economy_MaxStorage_Mass", maxStorage.mass);
    SetFloatStat(stats, "Economy_MaxStorage_Energy", maxStorage.energy);
    SetFloatStat(stats, "Economy_Reclaimed_Mass", economy.mTotals.mReclaimed.MASS);
    SetFloatStat(stats, "Economy_Reclaimed_Energy", economy.mTotals.mReclaimed.ENERGY);
    AddFloatStat(stats, "Economy_Shared_Mass", shared.mass);
    AddFloatStat(stats, "Economy_Shared_Energy", shared.energy);
    SetFloatStat(
      stats,
      "Economy_Trend_Mass",
      (economy.mPendingResources.mass - economy.mTotals.mLastUseRequested.MASS) * kTicksPerSecond
    );
    SetFloatStat(
      stats,
      "Economy_Trend_Energy",
      (economy.mPendingResources.energy - economy.mTotals.mLastUseRequested.ENERGY) * kTicksPerSecond
    );
    SetFloatStat(
      stats, "Economy_Ratio_Mass", maxStorage.mass > 0.0f ? economy.mTotals.mStored.MASS / maxStorage.mass : 0.0f
    );
    SetFloatStat(
      stats,
      "Economy_Ratio_Energy",
      maxStorage.energy > 0.0f ? economy.mTotals.mStored.ENERGY / maxStorage.energy : 0.0f
    );
    stats.SetUnitStatGreaterFloat("Economy_PeakStorage_Mass", &maxStorage.mass);
    stats.SetUnitStatGreaterFloat("Economy_PeakStorage_Energy", &maxStorage.energy);
    AddFloatStat(stats, "Economy_AccumExcess_Energy", excess.energy);
    AddFloatStat(stats, "Economy_AccumExcess_Mass", excess.mass);

    // The per-tick banks are consumed, so they start the next tick empty
    // (0x00772D1D); without this, income would accumulate without bound.
    economy.mResources = SEconValue{0.0f, 0.0f};
    economy.mPendingResources = SEconValue{0.0f, 0.0f};
  }

  /**
   * Address: 0x007048F0 (FUN_007048F0, Moho::CEconomy::Clear)
   *
   * What it does:
   * Unlinks the consumption-request sentinel node, releases extra-storage
   * ownership (with max-storage rollback), then frees this economy object.
   */
  CEconomy* CEconomy::Clear()
  {
    mConsumptionData.mNext->mPrev = mConsumptionData.mPrev;
    mConsumptionData.mPrev->mNext = mConsumptionData.mNext;
    mConsumptionData.mPrev = &mConsumptionData;
    mConsumptionData.mNext = &mConsumptionData;

    CEconStorage* const extraStorage = mExtraStorage;
    if (extraStorage != nullptr) {
      if (extraStorage->mEconomy != nullptr) {
        (void)extraStorage->Chng(-1);
      }
      ::operator delete(extraStorage);
    }

    ::operator delete(this);
    return this;
  }

  /**
   * Address: 0x007731B0 (FUN_007731B0, Moho::CEconomy::SerializeRequests)
   *
   * What it does:
   * Writes economy-request intrusive-list pointers in reverse link order and
   * appends one null pointer terminator.
   */
void CEconomy::SerializeRequests(gpg::WriteArchive* const archive)
{
  if (archive == nullptr) {
    return;
    }

    const gpg::RRef nullOwner{};

    for (TDatListItem<void, void>* node = mConsumptionData.mPrev; node != &mConsumptionData; node = node->mPrev) {
      gpg::RRef requestRef{};
      gpg::RRef_CEconRequest(&requestRef, RequestFromNode(node));
      gpg::WriteRawPointer(archive, requestRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

  gpg::RRef endRef{};
  gpg::RRef_CEconRequest(&endRef, nullptr);
  gpg::WriteRawPointer(archive, endRef, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x00773130 (FUN_00773130, Moho::CEconomy::DeserializeRequests)
 *
 * What it does:
 * Reads CEconRequest intrusive nodes from archive and links each request into
 * `mConsumptionData` until one null terminator is encountered.
 */
void CEconomy::DeserializeRequests(gpg::ReadArchive* const archive)
{
  if (archive == nullptr) {
    return;
  }

  gpg::RRef ownerRef{};
  CEconRequest* request = nullptr;
  (void)archive->ReadPointer_CEconRequest(&request, &ownerRef);
  while (request != nullptr) {
    request->mNode.ListLinkAfter(&mConsumptionData);
    ownerRef = gpg::RRef{};
    (void)archive->ReadPointer_CEconRequest(&request, &ownerRef);
  }
}

  /**
   * Address: 0x00774730 (FUN_00774730, Moho::CEconomy::MemberDeserialize)
   *
   * What it does:
   * Deserializes Sim owner, index/value lanes, totals, owned extra-storage
   * pointer, sharing flag, and request list lanes from archive input.
   */
  void CEconomy::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_Sim(&mSim, &nullOwner);
    archive->ReadInt(&mIndex);
    archive->Read(CachedSEconValueType(), &mResources, nullOwner);
    archive->Read(CachedSEconValueType(), &mPendingResources, nullOwner);
    archive->Read(CachedSEconTotalsType(), &mTotals, nullOwner);

    // Canonical owned-pointer read (recovered from FUN_006B4F70): enforces
    // UNOWNED->OWNED transition and raises SerializationError on type mismatch.
    CEconStorage* loadedExtraStorage = nullptr;
    (void)archive->ReadPointerOwned_CEconStorage(&loadedExtraStorage, &nullOwner);

    CEconStorage* const previousExtraStorage = mExtraStorage;
    mExtraStorage = loadedExtraStorage;
    if (previousExtraStorage != nullptr) {
      if (previousExtraStorage->mEconomy != nullptr) {
        (void)previousExtraStorage->Chng(-1);
      }
      ::operator delete(previousExtraStorage);
    }

    bool sharingEnabled = (mResourceSharing != 0u);
    archive->ReadBool(&sharingEnabled);
    mResourceSharing = static_cast<std::uint8_t>(sharingEnabled ? 1u : 0u);

    DeserializeRequests(archive);
  }

  // Addresses 0x007742F0/0x00774510 (the "ThunkA"/"ThunkB" jump-thunk
  // duplicates formerly modeled here) are dead: zero data_refs and zero
  // call_edges in the callgraph index for both, and no source-level caller
  // anywhere in src/sdk/**. `CEconomySerializer::Deserialize` below already
  // calls `CEconomy::MemberDeserialize` directly.

  /**
   * Address: 0x00774860 (FUN_00774860, Moho::CEconomy::MemberSerialize)
   *
   * What it does:
   * Serializes Sim owner, index/value lanes, totals, storage pointer ownership,
   * sharing flag, then emits the intrusive CEconRequest chain terminator.
   */
  void CEconomy::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::WriteRawPointer(
      archive,
      MakeTypedRef(mSim, CachedSimType()),
      gpg::TrackedPointerState::Unowned,
      nullOwner
    );

    archive->WriteInt(mIndex);
    archive->Write(CachedSEconValueType(), &mResources, nullOwner);
    archive->Write(CachedSEconValueType(), &mPendingResources, nullOwner);
    archive->Write(CachedSEconTotalsType(), &mTotals, nullOwner);

    gpg::WriteRawPointer(
      archive,
      MakeTypedRef(mExtraStorage, CachedCEconStorageType()),
      gpg::TrackedPointerState::Owned,
      nullOwner
    );

    archive->WriteBool(mResourceSharing != 0u);
    SerializeRequests(archive);
  }

  /**
   * Address: 0x007730A0 (FUN_007730A0, dynamic initializer for the global
   * `CEconomySerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields. No atexit cleanup is registered (confirmed
   * from raw disassembly: the ctor tail is `mov eax, offset Global; retn`,
   * with no `push Func; call _atexit` sequence), so this class declares no
   * destructor -- a user-declared one would make the compiler emit an
   * implicit registration that the real binary does not have.
   */
  CEconomySerializer::CEconomySerializer()
    : mLoadCallback(&CEconomySerializer::Deserialize)
    , mSaveCallback(&CEconomySerializer::Serialize)
  {}

  /**
   * Address: 0x00773080 (FUN_00773080, Moho::CEconomySerializer::Deserialize)
   *
   * What it does:
   * Forwards the reflected object pointer to `CEconomy::MemberDeserialize`.
   */
  void CEconomySerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const economy = reinterpret_cast<CEconomy*>(objectPtr);
    if (economy != nullptr) {
      economy->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00773090 (FUN_00773090, Moho::CEconomySerializer::Serialize)
   *
   * What it does:
   * Forwards the reflected object pointer to `CEconomy::MemberSerialize`.
   */
  void CEconomySerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const economy = reinterpret_cast<CEconomy*>(objectPtr);
    if (economy != nullptr) {
      economy->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00773D00 (FUN_00773D00, gpg::SerSaveLoadHelper_CEconomy::Init)
   *
   * What it does:
   * Lazily resolves `CEconomy` RTTI (via `CEconomy::sType`) and installs
   * load/save callbacks from this helper object into the type descriptor.
   */
  void CEconomySerializer::Init()
  {
    gpg::RType* const type = CachedCEconomyType();
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure(kLoadAssertText, kSerializationLoadLine, kSerializationSourcePath);
    }
    const bool saveAlreadySet = type->serSaveFunc_ != nullptr;
    type->serLoadFunc_ = mLoadCallback;
    if (saveAlreadySet) {
      gpg::HandleAssertFailure(kSaveAssertText, kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BDD0D0 (FUN_00BDD0D0, dynamic initializer for the global
   * `CEconomyConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields, then registers `atexit(FUN_00C02250)`.
   * Unlike `CEconomySerializer`, this real ctor DOES register an atexit
   * cleanup -- see the destructor below and the class-level Doxygen block
   * in CEconomy.h for the dead-duplicate evidence (`FUN_00772F20`) that
   * previously led this citation astray.
   */
  CEconomyConstruct::CEconomyConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCEconomySerializerThunk))
    , mDeleteCallback(reinterpret_cast<gpg::RType::delete_func_t>(&ClearCEconomyIfPresent))
  {}

  /**
   * Address: 0x00C02250 (FUN_00C02250, atexit target registered by the real
   * ctor above)
   */
  CEconomyConstruct::~CEconomyConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00773C80 (FUN_00773C80, Moho::CEconomyConstruct::Init)
   *
   * What it does:
   * Resolves `CEconomy` RTTI and installs startup construct/delete callbacks
   * from this helper's own fields.
   */
  void CEconomyConstruct::Init()
  {
    gpg::RType* const type = CachedCEconomyType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x005641F0 (FUN_005641F0, Moho::SEconTotals::MemberDeserialize)
   *
   * What it does:
   * Reads five `SEconPair` lanes through the reflected `SEconValue` type,
   * then reads `mMaxStorage` as two u64 lanes (`ENERGY`, `MASS`).
   */
  void SEconTotals::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    gpg::RType* const econValueType = CachedSEconValueType();
    archive->Read(econValueType, &mStored, nullOwner);
    archive->Read(econValueType, &mIncome, nullOwner);
    archive->Read(econValueType, &mReclaimed, nullOwner);
    archive->Read(econValueType, &mLastUseRequested, nullOwner);
    archive->Read(econValueType, &mLastUseActual, nullOwner);
    archive->ReadUInt64(&mMaxStorage.ENERGY);
    archive->ReadUInt64(&mMaxStorage.MASS);
  }

  /**
   * Address: 0x00564320 (FUN_00564320, Moho::SEconTotals::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::SEconTotals::MemberSerialize(BinaryWriteArchive *a1@<edi>, Moho::SEconTotals *a2@<esi>);
   *
   * What it does:
   * Writes the five SEconPair resource lanes (stored, income, reclaimed,
   * requested, actual) using the cached SEconValue RType, then emits the
   * u64 max-storage energy/mass fields through the archive's WriteUInt64
   * virtual slot. Mirrors the binary's lazy LookupRType caching sequence.
   */
  void SEconTotals::MemberSerialize(gpg::WriteArchive* const archive)
  {
    const gpg::RRef nullOwner{};

    gpg::RType* const econValueType = CachedSEconValueType();
    archive->Write(econValueType, &mStored, nullOwner);
    archive->Write(econValueType, &mIncome, nullOwner);
    archive->Write(econValueType, &mReclaimed, nullOwner);
    archive->Write(econValueType, &mLastUseRequested, nullOwner);
    archive->Write(econValueType, &mLastUseActual, nullOwner);

    archive->WriteUInt64(mMaxStorage.ENERGY);
    archive->WriteUInt64(mMaxStorage.MASS);
  }

  /**
   * Address: 0x00585920 (FUN_00585920, Moho::SEconTotals::MaxStorageOf)
   *
   * What it does:
   * Returns selected max-storage resource lane as a floating-point scalar.
   */
  double SEconTotals::MaxStorageOf(const EEconResource resource) const noexcept
  {
    const std::uint64_t* const maxStorageLanes = &mMaxStorage.ENERGY;
    return static_cast<double>(maxStorageLanes[static_cast<std::uint32_t>(resource)]);
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SEconValueTypeInfo_e739f5, moho::preregister_SEconValueTypeInfo)
GPG_PREREGISTER_INIT(preregister_SEconTotalsTypeInfo_e739f5, moho::preregister_SEconTotalsTypeInfo)
