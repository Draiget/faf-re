#include "RPropBlueprint.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetOwned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int value);
  };
} // namespace gpg

namespace moho
{
  // Forward declaration: the real definition sits further down in this TU;
  // RPropBlueprintConstruct's ctor below only needs the signature to bind
  // the callback pointer.
  void Construct_RPropBlueprint(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

  // Forward declaration: the real definition sits further down in this TU;
  // RPropBlueprintSaveConstruct's ctor below only needs the signature to
  // bind the callback pointer. Mirrors Construct_RPropBlueprint's forward
  // declaration above (this is the save-side counterpart).
  void SaveConstructArgsThunk_RPropBlueprint(
    gpg::WriteArchive* archive,
    int ownerToken,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* constructResult
  );

  // Forward declaration: the real definition sits further down in this TU;
  // the thunk above calls this canonical body before its own definition is
  // reached.
  void SaveConstructArgs_RPropBlueprint(
    int ownerToken,
    gpg::WriteArchive* archive,
    gpg::SerSaveConstructArgsResult* constructResult
  );
} // namespace moho

namespace
{
  struct SerSaveConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(SerSaveConstructHelperView, mSaveConstructArgsCallback) == 0x0C,
    "SerSaveConstructHelperView::mSaveConstructArgsCallback offset must be 0x0C"
  );

  [[nodiscard]] gpg::RType* ResolveRPropBlueprintTypeCached() noexcept
  {
    gpg::RType* type = moho::RPropBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RPropBlueprint));
      moho::RPropBlueprint::sType = type;
    }
    return type;
  }

  /**
   * VFTABLE: unknown - not independently observed for this instantiation.
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RPropBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RPropBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RPropBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    RPropBlueprintConstruct();

    /**
     * Address: 0x0051DE50 (FUN_0051DE50, gpg::SerConstructHelper<Moho::RPropBlueprint>::Init)
     *
     * IDA signature:
     * void(__cdecl *) __thiscall sub_51DE50(SerConstructHelperView *this);
     *
     * What it does:
     * Lazily resolves the `RPropBlueprint` reflection descriptor, asserts the
     * construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RPropBlueprintConstruct, mConstructCallback) == 0x0C,
    "RPropBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RPropBlueprintConstruct, mDeleteCallback) == 0x10,
    "RPropBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RPropBlueprintConstruct) == 0x14, "RPropBlueprintConstruct size must be 0x14");

  // NOTE: no binary evidence in this TU identifies a delete callback for
  // RPropBlueprint - Construct_RPropBlueprint below resolves an *existing*
  // blueprint out of RRuleGameRules's blueprint table (SetOwned on a lookup
  // result, not a fresh heap allocation), so a null delete callback is
  // plausible (the table, not the reflection system, owns blueprint
  // lifetime) but is not independently confirmed.
  RPropBlueprintConstruct::RPropBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&moho::Construct_RPropBlueprint))
    , mDeleteCallback(nullptr)
  {}

  void RPropBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = ResolveRPropBlueprintTypeCached();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  RPropBlueprintConstruct gRPropBlueprintConstructHelper;

  /**
   * VFTABLE: 0x00E11078 (`??_7RPropBlueprintSaveConstruct@Moho@@6B@`)
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RPropBlueprint>
   *
   * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
   * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
   * single save-construct-args callback lane@0x0C. Total 0x10 bytes,
   * matching the single-callback `SaveConstruct` shape (see
   * `moho::CSimSoundManagerSaveConstruct`), not the two-callback
   * `SerSaveLoadHelper<T>` shape (see `RPropBlueprintConstruct` above,
   * which is that OTHER, load-side mechanism for this same type -- Init()
   * writes `serConstructFunc_`/`deleteFunc_`, not `serSaveConstructArgsFunc_`).
   *
   * Investigation note (2026-08-25): this class replaces a prior
   * `InitRPropBlueprintSaveConstructHelper` free function operating on a
   * raw `SerSaveConstructHelperView` POD (never a real `gpg::SerHelperBase`,
   * so construction never spliced it into `sNewHelpers`, so it was never
   * actually dispatched -- the function was `[[maybe_unused]]` and uncalled).
   * The real construction site (0x00BC8830, confirmed sole caller: the
   * `__xc_a` static-init table) was previously mis-cited in
   * `ArchiveSerialization.cpp` as `gRRuleGameRulesOwnerFieldSaveConstructHelper`
   * -- a name describing the FIELD TYPE this helper happens to save
   * (`RRuleGameRules*`), not the TYPE the helper is actually registered for
   * (`RPropBlueprint`, confirmed by the vtable symbol and by
   * `Init()`'s own `typeid(RPropBlueprint)` lookup at 0x0051DDD0). That
   * duplicate citation, including its two ICF-twin unlink functions
   * (0x0051DB50/0x0051DB80, both twins of the real atexit target
   * 0x00BF3150) and its save-body thunk (0x0051DB30/0x0051DBB0, moved to
   * this file as `SaveConstructArgsThunk_RPropBlueprint`/
   * `SaveConstructArgs_RPropBlueprint` below), has been removed from
   * `ArchiveSerialization.cpp`.
   */
  class RPropBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8830 (FUN_00BC8830, register_RPropBlueprintSaveConstruct,
     * dynamic initializer for the global `RPropBlueprintSaveConstruct`
     * singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the save-construct-args callback field and installs
     * process-exit cleanup.
     */
    RPropBlueprintSaveConstruct();

    /**
     * Address: 0x0051DDD0 (FUN_0051DDD0, gpg::SerSaveConstructHelper<Moho::RPropBlueprint>::Init)
     *
     * What it does:
     * Resolves `RPropBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the reflected type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RPropBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RPropBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RPropBlueprintSaveConstruct) == 0x10, "RPropBlueprintSaveConstruct size must be 0x10");

  RPropBlueprintSaveConstruct gRPropBlueprintSaveConstructHelper;

  RPropBlueprintSaveConstruct::RPropBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&moho::SaveConstructArgsThunk_RPropBlueprint)
      )
  {}

  void RPropBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = ResolveRPropBlueprintTypeCached();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        kSaveConstructAssertText,
        kSerializationSaveConstructLine,
        kSerializationSourcePath
      );
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace

namespace moho
{
  gpg::RType* RPropBlueprint::sType = nullptr;

  /**
   * Address: 0x0051DC30 (FUN_0051DC30)
   *
   * What it does:
   * Unlinks `RPropBlueprint` construct-helper links and restores the node to
   * self-linked sentinel state.
   */
  [[maybe_unused]] void CleanupRPropBlueprintConstructHelperPrimary() noexcept
  {
    gRPropBlueprintConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x0051DC60 (FUN_0051DC60)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RPropBlueprint` construct-helper lane.
   */
  [[maybe_unused]] void CleanupRPropBlueprintConstructHelperSecondary() noexcept
  {
    gRPropBlueprintConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x00BF3150 (FUN_00BF3150, atexit-registered cleanup target)
   *
   * What it does:
   * Unlinks `RPropBlueprint` save-construct-helper links and restores the
   * node to self-linked sentinel state.
   */
  [[maybe_unused]] void CleanupRPropBlueprintSaveConstructHelperPrimary() noexcept
  {
    gRPropBlueprintSaveConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x0051DB50 (FUN_0051DB50)
   * ICF twin: 0x0051DB80 (FUN_0051DB80) -- identical unlink/self-link body
   * hardcoded to the same global; both are dead duplicates of the real
   * atexit target 0x00BF3150 above.
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RPropBlueprint` save-construct-helper lane.
   */
  [[maybe_unused]] void CleanupRPropBlueprintSaveConstructHelperSecondary() noexcept
  {
    gRPropBlueprintSaveConstructHelper.ResetLinks();
  }

  /**
   * Address: 0x0051DB30 (FUN_0051DB30, register-shape thunk)
   *
   * What it does:
   * Forwards save-construct serialization for one `RPropBlueprint`'s owner
   * lane (`RRuleGameRules*` + blueprint id string) to the canonical body
   * below. This is the thin cdecl-shaped adapter the reflection slot
   * dispatches to; `SaveConstructArgs_RPropBlueprint` below is what it
   * subsumes.
   */
  void SaveConstructArgsThunk_RPropBlueprint(
    gpg::WriteArchive* const archive,
    const int ownerToken,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const constructResult
  )
  {
    SaveConstructArgs_RPropBlueprint(ownerToken, archive, constructResult);
  }

  /**
   * Address: 0x0051DBB0 (FUN_0051DBB0)
   *
   * What it does:
   * Writes one `RPropBlueprint`'s owner `RRuleGameRules*` as an unowned
   * tracked pointer, then serializes its blueprint id string, then marks
   * the save-construct result as owned. Symmetric with `Construct_RPropBlueprint`
   * above, which reads the same two values back to look the blueprint up
   * again via `RRuleGameRules::GetPropBlueprint`.
   */
  void SaveConstructArgs_RPropBlueprint(
    const int ownerToken,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const constructResult
  )
  {
    auto* const blueprint = reinterpret_cast<RPropBlueprint*>(static_cast<std::uintptr_t>(ownerToken));

    gpg::RRef ownerFieldRef{};
    (void)gpg::RRef_RRuleGameRules(&ownerFieldRef, blueprint->mOwner);
    const gpg::RRef nullOwnerRef{};
    gpg::WriteRawPointer(archive, ownerFieldRef, gpg::TrackedPointerState::Unowned, nullOwnerRef);

    archive->WriteString(&blueprint->mBlueprintId);
    constructResult->SetOwned(1u);
  }

  /**
   * Address: 0x0051DC90 (FUN_0051DC90)
   *
   * What it does:
   * Reads save-construct args (`RRuleGameRules*`, prop blueprint id),
   * resolves the owning prop blueprint from game rules, and stores it as
   * owned construct-result payload.
   */
  void Construct_RPropBlueprint(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    RRuleGameRules* gameRules = nullptr;
    gpg::RRef ownerRef{};
    archive->ReadPointer_RRuleGameRules(&gameRules, &ownerRef);

    msvc8::string serializedId{};
    archive->ReadString(&serializedId);

    msvc8::string lookupId{};
    gpg::STR_CopyFilename(&lookupId, &serializedId);

    RPropBlueprint* const blueprint = gameRules != nullptr
      ? gameRules->GetPropBlueprint(lookupId)
      : nullptr;

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RPropBlueprint(&blueprintRef, blueprint);
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x0051E0A0 (FUN_0051E0A0)
   *
   * What it does:
   * Writes one reflected `{object,type}` lane from one `RPropBlueprint*`
   * into caller-provided `RRef` storage.
   */
  [[maybe_unused]] gpg::RRef* BuildRRefFromRPropBlueprint(
    RPropBlueprint* const blueprint,
    gpg::RRef* const outRef
  )
  {
    (void)gpg::RRef_RPropBlueprint(outRef, blueprint);
    return outRef;
  }

  /**
   * Address: 0x0051D250 (FUN_0051D250)
   * Mangled: ??0RPropBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
   *
   * What it does:
   * Runs base entity-blueprint construction with `(owner, resId)` and
   * restores prop blueprint display/defense/economy defaults.
   */
  RPropBlueprint::RPropBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : REntityBlueprint(owner, resId)
    , Display()
    , Defense()
    , Economy()
  {
    Display.MeshBlueprint.name.tidy(false, 0U);
    Display.UniformScale = 1.0f;
    Defense.MaxHealth = 1.0f;
    Defense.Health = 1.0f;
    Economy.ReclaimMassMax = 0.0f;
    Economy.ReclaimEnergyMax = 0.0f;
  }

  /**
   * Local source-compat convenience constructor for scratch/default lanes.
   */
  RPropBlueprint::RPropBlueprint()
    : RPropBlueprint(nullptr, RResId{})
  {}

  /**
   * Address: 0x0051D2B0 (FUN_0051D2B0, Moho::RPropBlueprint::dtr)
   *
   * What it does:
   * Releases `Display.MeshBlueprint.name` storage -- the only lane
   * `RPropBlueprint` owns beyond its `REntityBlueprint` base -- then chains
   * into base destruction.
   */
  RPropBlueprint::~RPropBlueprint()
  {
    Display.MeshBlueprint.name.tidy(true, 0U);
  }

  /**
   * Address: 0x0051D210 (FUN_0051D210)
   * Mangled: ?GetClass@RPropBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RPropBlueprint`.
   */
  gpg::RType* RPropBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RPropBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0051D230 (FUN_0051D230)
   * Mangled: ?GetDerivedObjectRef@RPropBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RPropBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0051D370 (FUN_0051D370)
   * Mangled: ?OnInitBlueprint@RPropBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
   * to a completed, lowercase, slash-normalized resource path.
   */
  void RPropBlueprint::OnInitBlueprint()
  {
    REntityBlueprint::OnInitBlueprint();

    msvc8::string completedMeshPath = RES_CompletePath(Display.MeshBlueprint.name.c_str(), mSource.c_str());
    gpg::STR_NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath.view());
  }
} // namespace moho
