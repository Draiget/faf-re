#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/CEconomyEvent.h"
#include "moho/sim/CSimArmyEconomyInfo.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconStorage;
  class Sim;

  class CEconomy;

  /**
   * Address: 0x00771B50 (FUN_00771B50, func_ArmyProcessEconomy)
   *
   * What it does:
   * Runs one army's per-tick economy: pools outstanding consumption demand,
   * serves it from stored plus banked production at a ratio bounded by the
   * scarcer resource, publishes `mIncome`/`mLastUse*`/`mStored`, and empties
   * the per-tick banks. Called by `CArmyImpl::OnTick` with `army->EconomyInfo`.
   */
  void ProcessArmyEconomy(CEconomy& economy);

  /**
   * Runtime economy state serialized on army save/load lanes.
   */
  class CEconomy
  {
  public:
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
    CEconomy(Sim* sim, std::int32_t armyIndex);

    /**
     * Address: 0x007048F0 (FUN_007048F0, Moho::CEconomy::Clear)
     *
     * What it does:
     * Unlinks the consumption-request sentinel node, releases extra-storage
     * ownership (with max-storage rollback), then frees this economy object.
     */
    CEconomy* Clear();

    /**
     * Address: 0x00774860 (FUN_00774860, Moho::CEconomy::MemberSerialize)
     *
     * What it does:
     * Serializes Sim owner, index/value lanes, totals, storage pointer ownership,
     * sharing flag, then emits the intrusive CEconRequest chain terminator.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00774730 (FUN_00774730, Moho::CEconomy::MemberDeserialize)
     *
     * What it does:
     * Deserializes Sim owner, index/value lanes, totals, owned extra-storage
     * pointer, sharing flag, and request list lanes from archive input.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x007731B0 (FUN_007731B0, Moho::CEconomy::SerializeRequests)
     *
     * What it does:
     * Writes economy-request intrusive-list pointers in reverse link order and
     * appends one null pointer terminator.
     */
    void SerializeRequests(gpg::WriteArchive* archive);

    /**
     * Address: 0x00773130 (FUN_00773130, Moho::CEconomy::DeserializeRequests)
     *
     * What it does:
     * Reads CEconRequest intrusive nodes from archive and relinks each request
     * into `mConsumptionData` until a null pointer terminator is read.
     */
    void DeserializeRequests(gpg::ReadArchive* archive);

  public:
    static gpg::RType* sType;

    Sim* mSim;                         // +0x00
    std::int32_t mIndex;               // +0x04
    SEconValue mResources;             // +0x08
    SEconValue mPendingResources;      // +0x10
    SEconTotals mTotals;               // +0x18
    CEconStorage* mExtraStorage;       // +0x50
    std::uint8_t mResourceSharing;     // +0x54
    std::uint8_t mPad55To57[0x03];     // +0x55
    TDatListItem<void, void> mConsumptionData; // +0x58
  };

  static_assert(offsetof(CEconomy, mSim) == 0x00, "CEconomy::mSim offset must be 0x00");
  static_assert(offsetof(CEconomy, mIndex) == 0x04, "CEconomy::mIndex offset must be 0x04");
  static_assert(offsetof(CEconomy, mResources) == 0x08, "CEconomy::mResources offset must be 0x08");
  static_assert(
    offsetof(CEconomy, mPendingResources) == 0x10, "CEconomy::mPendingResources offset must be 0x10"
  );
  static_assert(offsetof(CEconomy, mTotals) == 0x18, "CEconomy::mTotals offset must be 0x18");
  static_assert(offsetof(CEconomy, mExtraStorage) == 0x50, "CEconomy::mExtraStorage offset must be 0x50");
  static_assert(
    offsetof(CEconomy, mResourceSharing) == 0x54, "CEconomy::mResourceSharing offset must be 0x54"
  );
  static_assert(
    offsetof(CEconomy, mConsumptionData) == 0x58, "CEconomy::mConsumptionData offset must be 0x58"
  );
  static_assert(sizeof(CEconomy) == 0x60, "CEconomy size must be 0x60");

  /**
   * Address: 0x00563B10 (FUN_00563B10, preregister_SEconValueTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconValue`.
   */
  [[nodiscard]] gpg::RType* preregister_SEconValueTypeInfo();

  /**
   * Address: 0x00563D40 (FUN_00563D40, preregister_SEconTotalsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconTotals`.
   */
  [[nodiscard]] gpg::RType* preregister_SEconTotalsTypeInfo();

  /**
   * Address: 0x00772FC0 (FUN_00772FC0)
   *
   * What it does:
   * Allocates one `CEconomy` runtime object with constructor-default field
   * lanes and stores an unowned reflected reference in `result`.
   */
  void ConstructCEconomyForSerializer(gpg::SerConstructResult* result);

  /**
   * VFTABLE: 0x00E189AC
   */
  class SEconValueSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCA870 (FUN_00BCA870, register_SEconValueSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SEconValueSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. The `push offset ~SEconValueSerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it is not a call the 2007 source wrote), so it is not
     * reproduced explicitly here -- declaring a real destructor below is
     * sufficient for the compiler to emit the same registration.
     */
    SEconValueSerializer();

    /**
     * Address: 0x00BF56C0 (FUN_00BF56C0, Moho::SEconValueSerializer::~SEconValueSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SEconValueSerializer();

    /**
     * Address: 0x00563C50 (FUN_00563C50, Moho::SEconValueSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SEconValue`. Reads the two-float
     * (energy, mass) pair directly through the archive; `SEconValue` has no
     * MemberDeserialize of its own, matching the binary's inline field reads.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00563C80 (FUN_00563C80, Moho::SEconValueSerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade for `SEconValue`. Writes the two-float
     * (energy, mass) pair directly through the archive; `SEconValue` has no
     * MemberSerialize of its own, matching the binary's inline field writes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00564010 (FUN_00564010, gpg::SerSaveLoadHelper_SEconValue::Init)
     *
     * What it does:
     * Lazily resolves `SEconValue` RTTI and installs load/save callbacks
     * from this helper object into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SEconValueSerializer, mLoadCallback) == 0x0C, "SEconValueSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SEconValueSerializer, mSaveCallback) == 0x10, "SEconValueSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SEconValueSerializer) == 0x14, "SEconValueSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E189EC
   */
  class SEconTotalsSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCA8D0 (FUN_00BCA8D0, register_SEconTotalsSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SEconTotalsSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. Like `SEconValueSerializer`, the atexit registration visible in
     * the real ctor's tail is the compiler's implicit static-destructor
     * registration, not explicit source; a real destructor is enough.
     */
    SEconTotalsSerializer();

    /**
     * Address: 0x00BF5750 (FUN_00BF5750, Moho::SEconTotalsSerializer::~SEconTotalsSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SEconTotalsSerializer();

    /**
     * Address: 0x00563E80 (FUN_00563E80, Moho::SEconTotalsSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SEconTotals`. Forwards the
     * reflected object pointer to `SEconTotals::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00563E90 (FUN_00563E90, Moho::SEconTotalsSerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade for `SEconTotals`. Forwards the
     * reflected object pointer to `SEconTotals::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005640B0 (FUN_005640B0, gpg::SerSaveLoadHelper_SEconTotals::Init)
     *
     * What it does:
     * Lazily resolves `SEconTotals` RTTI and installs load/save callbacks
     * from this helper object into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SEconTotalsSerializer, mLoadCallback) == 0x0C,
    "SEconTotalsSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SEconTotalsSerializer, mSaveCallback) == 0x10,
    "SEconTotalsSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SEconTotalsSerializer) == 0x14, "SEconTotalsSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E36DB0
   */
  class CEconomySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x007730A0 (FUN_007730A0, dynamic initializer for the global
     * `CEconomySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: unlike
     * `SEconValueSerializer`/`SEconTotalsSerializer`, this constructor does
     * NOT register an atexit cleanup -- `CEconomySerializer` is never torn
     * down at process exit in the real binary (no `push offset Func; call
     * _atexit` sequence exists here).
     */
    CEconomySerializer();

    /**
     * Address: 0x00773080 (FUN_00773080, Moho::CEconomySerializer::Deserialize)
     *
     * What it does:
     * Forwards the reflected object pointer to `CEconomy::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00773090 (FUN_00773090, Moho::CEconomySerializer::Serialize)
     *
     * What it does:
     * Forwards the reflected object pointer to `CEconomy::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00773D00 (FUN_00773D00, gpg::SerSaveLoadHelper_CEconomy::Init)
     *
     * What it does:
     * Lazily resolves `CEconomy` RTTI (via `CEconomy::sType`) and installs
     * load/save callbacks from this helper object into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CEconomySerializer, mLoadCallback) == 0x0C, "CEconomySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconomySerializer, mSaveCallback) == 0x10, "CEconomySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconomySerializer) == 0x14, "CEconomySerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E36DA0
   */
  class CEconomyConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD0D0 (FUN_00BDD0D0, dynamic initializer for the global
     * `CEconomyConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields, then registers `atexit(FUN_00C02250)`.
     * `FUN_00772F20` decompiles to the identical field-write shape (same
     * `gpg::SerHelperBase` ctor call, same `mConstructCallback`/
     * `mDeleteCallback` values, same vtable install) but its tail returns
     * `&dword_10BB894` directly instead of calling `atexit` -- confirmed via
     * the callgraph index to have zero incoming xrefs (unlike `FUN_00BDD0D0`,
     * which is `__xc_a`-reachable via a data xref from the CRT static-
     * initializer table at 0x00C0FA60). It is a dead, unreachable
     * duplicate-emission twin of this real ctor, not a competing
     * initializer; a prior recovery pass had mistakenly cited it as "the"
     * ctor and concluded (based on that wrong body) that no atexit cleanup
     * was ever registered.
     */
    CEconomyConstruct();

    /**
     * Address: 0x00C02250 (FUN_00C02250, atexit target registered by the
     * real ctor above)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_00772F50`/
     * `FUN_00772F80` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneBK` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~CEconomyConstruct();

    /**
     * Address: 0x00773C80 (FUN_00773C80, Moho::CEconomyConstruct::Init)
     *
     * What it does:
     * Resolves `CEconomy` RTTI and installs startup construct/delete
     * callbacks from this helper's own fields (vtable slot 0, dispatched by
     * `gpg::SerHelperBase::InitNewHelpers`).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(CEconomyConstruct, mConstructCallback) == 0x0C,
    "CEconomyConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconomyConstruct, mDeleteCallback) == 0x10, "CEconomyConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconomyConstruct) == 0x14, "CEconomyConstruct size must be 0x14");
} // namespace moho
