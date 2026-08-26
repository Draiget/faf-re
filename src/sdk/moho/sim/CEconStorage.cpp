#include "moho/sim/CEconStorage.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CEconomy.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  // Note: parameter cv-qualifiers must match the definition in
  // gpg/core/containers/ArchiveSerialization.cpp:649 — MSVC mangles top-level
  // `T* const` parameters distinctly from `T*` parameters, so a mismatched
  // forward declaration would resolve to a different symbol at link time.
  gpg::RRef* RRef_CEconStorage(gpg::RRef* outRef, moho::CEconStorage* value);
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    if (moho::CEconStorage::sType == nullptr) {
      moho::CEconStorage::sType = gpg::LookupRType(typeid(moho::CEconStorage));
    }
    return moho::CEconStorage::sType;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (moho::SEconValue::sType == nullptr) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
  }

  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
  constexpr int kSerializationConstructLine = 231;

  /**
   * Address: 0x007734F0 (FUN_007734F0, Moho::CEconStorageConstruct::Construct)
   *
   * What it does:
   * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
   * publishes the object as an unowned construct result.
   */
  [[maybe_unused]] void ConstructCEconStorageSerializerCallback(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    if (result == nullptr) {
      return;
    }

    auto* const storage = new (std::nothrow) moho::CEconStorage{};
    gpg::RRef storageRef{};
    gpg::RRef_CEconStorage(&storageRef, storage);
    result->SetUnowned(storageRef, 0u);
  }

  /**
   * Address: 0x00774350 (FUN_00774350, Moho::CEconStorageConstruct::Deconstruct)
   *
   * What it does:
   * Removes one storage contribution from owning economy totals when present,
   * then releases the storage object.
   */
  [[maybe_unused]] void DeconstructCEconStorageSerializerCallback(moho::CEconStorage* const storage)
  {
    if (storage == nullptr) {
      return;
    }

    if (storage->mEconomy != nullptr) {
      (void)storage->Chng(-1);
    }
    ::operator delete(storage);
  }

  /**
   * Address: 0x00773560 (FUN_00773560, Moho::CEconStorageSerializer::Deserialize)
   *
   * What it does:
   * Forwards serializer-load callback lanes into `CEconStorage::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEconStorageSerializerCallback(
    gpg::ReadArchive* const archive,
    moho::CEconStorage* const storage
  )
  {
    if (storage != nullptr) {
      storage->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00773570 (FUN_00773570, Moho::CEconStorageSerializer::Serialize)
   *
   * What it does:
   * Forwards serializer-save callback lanes into `CEconStorage::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEconStorageSerializerCallback(
    gpg::WriteArchive* const archive,
    moho::CEconStorage* const storage
  )
  {
    if (storage != nullptr) {
      storage->MemberSerialize(archive);
    }
  }

  /**
   * Demangled: gpg::SerConstructHelper<class Moho::CEconStorage>
   *
   * Address context for this pair of classes: 0x00773490/0x007734C0
   * (CEconStorageConstruct) and 0x007735B0/0x007735E0 (CEconStorageSerializer)
   * -- formerly modeled here as "UnlinkCEconStorage{Construct,Serializer}
   * NodeVariantA/B" free functions -- are each a byte-identical ICF twin
   * (sha256 d0a84e4f.../9939ed1b... respectively) of these classes' own real
   * destructors (0x00C02310/0x00C02340, cited below). They are not separate
   * functions needing their own source-level caller; they *are* the
   * destructor bodies, and are removed as standalone free functions.
   *
   * Similarly, 0x00773460/0x00773580 (formerly modeled here as
   * `InitializeCEconStorageConstructHelperStorage` /
   * `InitializeCEconStorageSerializerHelperStorage`) are dead-duplicate
   * compiled bodies of these classes' own real constructors (0x00BDD170 /
   * 0x00BDD1B0, cited below) -- same field-write shape, but missing the
   * atexit registration and with zero incoming references of any kind
   * anywhere in the indexed binary. The real, `__xc_a`-registered
   * constructors are modeled directly below instead.
   */
  class CEconStorageConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD170 (FUN_00BDD170, register_CEconStorageConstruct;
     * dynamic initializer for the global `CEconStorageConstruct` singleton)
     *
     * What it does:
     * Binds construct/deconstruct callback lanes for `CEconStorage`.
     * Base-class construction (`gpg::SerHelperBase::SerHelperBase`)
     * self-links this node and splices it into the pending `sNewHelpers`
     * list. The real dynamic initializer also registers this class's
     * destructor (0x00C02310) via `atexit` -- reproduced here simply by
     * giving the class a real destructor below and defining
     * `gCEconStorageConstructHelper` as a plain global: the compiler emits
     * the equivalent atexit registration automatically for any static
     * object whose destructor is non-trivial, with no explicit
     * `std::atexit` call needed in this constructor's own body.
     */
    CEconStorageConstruct();

    /**
     * Address: 0x00C02310 (FUN_00C02310, Moho::CEconStorageConstruct::
     * ~CEconStorageConstruct)
     *
     * What it does:
     * Unlinks this helper node from the pending `sNewHelpers` list (or
     * restores its self-linked sentinel state if already drained).
     * Registered via `atexit` from the real constructor (0x00BDD170).
     */
    ~CEconStorageConstruct();

    /**
     * Address: 0x00773DA0 (FUN_00773DA0, Moho::CEconStorageConstruct::
     * RegisterConstructFunction)
     *
     * What it does:
     * Resolves `CEconStorage` RTTI and installs this helper's
     * construct/delete callbacks.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(CEconStorageConstruct, mConstructCallback) == 0x0C,
    "CEconStorageConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconStorageConstruct, mDeleteCallback) == 0x10,
    "CEconStorageConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconStorageConstruct) == 0x14, "CEconStorageConstruct size must be 0x14");

  CEconStorageConstruct::CEconStorageConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCEconStorageSerializerCallback))
    , mDeleteCallback(reinterpret_cast<gpg::RType::delete_func_t>(&DeconstructCEconStorageSerializerCallback))
  {}

  CEconStorageConstruct::~CEconStorageConstruct()
  {
    ResetLinks();
  }

  void CEconStorageConstruct::Init()
  {
    gpg::RType* const type = CachedCEconStorageType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }

    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  CEconStorageConstruct gCEconStorageConstructHelper;

  /**
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CEconStorage> (RTTI shows
   * `CEconStorageSerializer`'s vtable is literally
   * `??_7?$SerSaveLoadHelper@VCEconStorage@Moho@@@gpg@@6B@`, but per the
   * established prior art for this exact shape -- `gpg::SerSaveLoadHelper<T>`'s
   * own Doxygen block in gpg/core/reflection/Reflection.h, citing
   * `Rect2iSerializer` / `Moho::CEconRequestSerializer` -- it stays modeled
   * as a concrete `SerHelperBase`-derived class rather than converted to
   * inherit the template directly: this constructor points
   * `mLoadCallback`/`mSaveCallback` at CEconStorageSerializer's OWN static
   * methods below, not the template's, so collapsing the intermediate level
   * would be a source-shape change with no binary-behavior difference.)
   */
  class CEconStorageSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD1B0 (FUN_00BDD1B0, register_CEconStorageSerializer;
     * dynamic initializer for the global `CEconStorageSerializer` singleton)
     *
     * What it does:
     * Binds deserialize/serialize callback lanes for `CEconStorage`.
     * Base-class construction self-links this node and splices it into the
     * pending `sNewHelpers` list; the real destructor (0x00C02340) is
     * registered via `atexit` the same way described on
     * `CEconStorageConstruct::CEconStorageConstruct` above.
     */
    CEconStorageSerializer();

    /**
     * Address: 0x00C02340 (FUN_00C02340, Moho::CEconStorageSerializer::
     * ~CEconStorageSerializer)
     *
     * What it does:
     * Unlinks this helper node from the pending `sNewHelpers` list (or
     * restores its self-linked sentinel state if already drained).
     * Registered via `atexit` from the real constructor (0x00BDD1B0).
     */
    ~CEconStorageSerializer();

    /**
     * Address: 0x00773E20 (FUN_00773E20; VTABLE_CONFIRMED via a direct data
     * xref from `??_7CEconStorageSerializer@Moho@@6B@` vtable slot 0)
     *
     * What it does:
     * Resolves `CEconStorage` RTTI and installs this helper's load/save
     * callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
  static_assert(
    offsetof(CEconStorageSerializer, mLoadCallback) == 0x0C, "CEconStorageSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconStorageSerializer, mSaveCallback) == 0x10, "CEconStorageSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconStorageSerializer) == 0x14, "CEconStorageSerializer size must be 0x14");

  CEconStorageSerializer::CEconStorageSerializer()
    : mLoadCallback(reinterpret_cast<gpg::RType::load_func_t>(&DeserializeCEconStorageSerializerCallback))
    , mSaveCallback(reinterpret_cast<gpg::RType::save_func_t>(&SerializeCEconStorageSerializerCallback))
  {}

  CEconStorageSerializer::~CEconStorageSerializer()
  {
    ResetLinks();
  }

  void CEconStorageSerializer::Init()
  {
    gpg::RType* const type = CachedCEconStorageType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  CEconStorageSerializer gCEconStorageSerializerHelper;

  /**
   * Address: 0x00774B80 (FUN_00774B80)
   *
   * What it does:
   * Serializes one `CEconomy*` slot as an unowned tracked pointer and returns
   * the archive for callback chaining.
   */
  [[nodiscard]] gpg::WriteArchive*
  SerializeUnownedCEconomyPointer(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || economySlot == nullptr) {
      return archive;
    }

    gpg::RRef economyRef{};
    economyRef.mObj = *economySlot;
    economyRef.mType = gpg::LookupRType(typeid(moho::CEconomy));
    GPG_ASSERT(economyRef.mType != nullptr);
    gpg::WriteRawPointer(archive, economyRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    return archive;
  }

  /**
   * Address: 0x00774BC0 (FUN_00774BC0)
   *
   * What it does:
   * Binary-write callback variant of unowned `CEconomy*` slot serialization.
   */
  [[maybe_unused]] void
  SerializeUnownedCEconomyPointerBinary(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    (void)SerializeUnownedCEconomyPointer(economySlot, archive);
  }
} // namespace

namespace moho
{
  gpg::RType* CEconStorage::sType = nullptr;

  /**
   * Address: 0x00773270 (FUN_00773270)
   *
   * What it does:
   * Removes one storage contribution from owning economy max-storage totals
   * when this storage lane is currently bound to an economy.
   */
  [[maybe_unused]] [[nodiscard]] CEconStorage* RemoveCEconStorageContributionIfBound(CEconStorage* const storage)
  {
    if (storage->mEconomy != nullptr) {
      (void)storage->Chng(-1);
    }
    return storage;
  }

  /**
   * Address: 0x00773250 (FUN_00773250, Moho::CEconStorage::CEconStorage)
   *
   * What it does:
   * Binds one economy owner pointer, copies amount lanes, and applies this
   * storage lane into economy max-storage totals.
   */
  CEconStorage::CEconStorage(const SEconValue& amount, CEconomy* const economy)
  {
    mEconomy = economy;
    mAmt = amount;
    (void)Chng(1);
  }

  /**
   * Address: 0x00773280 (FUN_00773280, Moho::CEconStorage::ChangeAmt)
   *
   * What it does:
   * Removes previous amount contribution, copies new amount lanes, then
   * reapplies contribution to economy max-storage totals.
   */
  std::int64_t CEconStorage::ChangeAmt(const SEconValue& amount)
  {
    (void)Chng(-1);
    mAmt = amount;
    return Chng(1);
  }

  /**
   * Address: 0x00773500 (FUN_00773500, Moho::CEconStorage::MemberConstruct)
   *
   * What it does:
   * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
   * publishes the object as an unowned construct result.
   */
  void CEconStorage::MemberConstruct(
    gpg::ReadArchive&,
    const int,
    const gpg::RRef&,
    gpg::SerConstructResult& result
  )
  {
    auto* const storage = new (std::nothrow) CEconStorage{};

    gpg::RRef storageRef{};
    storageRef.mObj = storage;
    storageRef.mType = CachedCEconStorageType();
    result.SetUnowned(storageRef, 0u);
  }

  /**
   * Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
   *
   * What it does:
   * Applies this storage lane as a signed delta (`direction` is typically
   * `+1` or `-1`) into owning economy max-storage counters.
   */
  std::int64_t CEconStorage::Chng(const std::int32_t direction)
  {
    if (mEconomy == nullptr) {
      return 0;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    const float amounts[2] = {mAmt.energy, mAmt.mass};
    std::uint64_t* const totals[2] = {&mEconomy->mTotals.mMaxStorage.ENERGY, &mEconomy->mTotals.mMaxStorage.MASS};

    std::int64_t result = 0;
    for (int lane = 0; lane < 2; ++lane) {
      result = static_cast<std::int64_t>(amounts[lane]) * signedDirection;
      *totals[lane] += static_cast<std::uint64_t>(result);
    }
    return result;
  }

  /**
   * Address: 0x00774990 (FUN_00774990, Moho::CEconStorage::MemberDeserialize)
   *
   * What it does:
   * Deserializes referenced economy owner pointer, then reads one reflected
   * `SEconValue` payload lane.
   */
  void CEconStorage::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_CEconomy(&mEconomy, &nullOwner);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Read(econValueType, &mAmt, nullOwner);
  }

  /**
   * Address: 0x007749F0 (FUN_007749F0, Moho::CEconStorage::MemberSerialize)
   *
   * What it does:
   * Serializes referenced economy owner as an unowned pointer, then writes
   * one reflected `SEconValue` payload lane.
   */
  void CEconStorage::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)SerializeUnownedCEconomyPointer(&mEconomy, archive);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Write(econValueType, &mAmt, nullOwner);
  }

  // Addresses 0x007743D0/0x00774540 (the "ThunkA"/"ThunkB" save-lane
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // `SerializeCEconStorageSerializerCallback` above (`CEconStorageSerializer
  // ::Serialize`, confirmed by 3 real incoming xrefs incl. the real
  // `CEconStorageSerializer::CEconStorageSerializer` constructor at
  // 0x00BDD1B0) already calls `CEconStorage::MemberSerialize` directly.
} // namespace moho

// No bootstrap object is needed to force construction of
// `gCEconStorageConstructHelper` / `gCEconStorageSerializerHelper`: both are
// now plain globals of real `gpg::SerHelperBase`-derived types (see above),
// so the compiler already emits their dynamic initializers unconditionally,
// exactly matching the real binary's `__xc_a`-registered constructors
// (0x00BDD170 / 0x00BDD1B0). A prior pass modeled these two helpers as a
// hand-rolled `SerHelperNodeRuntime` aggregate (raw `void* mVtable` field,
// manual `InitializeHelperNode` splicing) that never actually joined
// `gpg::SerHelperBase::sNewHelpers` -- meaning `gpg::SerHelperBase::
// InitNewHelpers` could never have dispatched `Init()` on either helper, so
// `CEconStorage`'s `serConstructFunc_`/`deleteFunc_`/`serLoadFunc_`/
// `serSaveFunc_` would never have been installed at runtime. That bug is
// fixed by this real-class conversion, which also matches the
// already-established prior art for this exact anti-pattern (see
// moho/render/EmitterTypeTypeInfo.h's `EmitterTypePrimitiveSerializer`
// conversion note).
