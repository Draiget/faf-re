#include "RPropBlueprint.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
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
} // namespace gpg

namespace
{
  struct SerSaveLoadHelperNodeRuntime
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
  };

  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mNext) == 0x04,
    "SerSaveLoadHelperNodeRuntime::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mPrev) == 0x08,
    "SerSaveLoadHelperNodeRuntime::mPrev offset must be 0x08"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeRuntime) == 0x0C, "SerSaveLoadHelperNodeRuntime size must be 0x0C");

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    helper.mNext->mPrev = helper.mPrev;
    helper.mPrev->mNext = helper.mNext;

    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  SerSaveLoadHelperNodeRuntime gRPropBlueprintConstructHelper{};

  struct SerConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(SerConstructHelperView, mConstructCallback) == 0x0C,
    "SerConstructHelperView::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerConstructHelperView, mDeleteCallback) == 0x10,
    "SerConstructHelperView::mDeleteCallback offset must be 0x10"
  );

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
   * Address: 0x0051DE50 (FUN_0051DE50, gpg::SerConstructHelper<Moho::RPropBlueprint>::Init)
   *
   * IDA signature:
   * void(__cdecl *) __thiscall sub_51DE50(SerConstructHelperView *this);
   *
   * What it does:
   * Virtual-method body installed in the
   * `Moho::RPropBlueprintConstruct` and
   * `gpg::SerConstructHelper<Moho::RPropBlueprint>` vtables. Lazily resolves
   * the `RPropBlueprint` reflection descriptor, asserts the construct callback
   * slot is empty, and publishes this helper's construct/delete callbacks to
   * the descriptor.
   */
  [[maybe_unused]] gpg::RType::construct_func_t InitRPropBlueprintConstructHelper(
    const SerConstructHelperView& helper
  )
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = ResolveRPropBlueprintTypeCached();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  /**
   * Address: 0x0051DDD0 (FUN_0051DDD0, gpg::SerSaveConstructHelper<Moho::RPropBlueprint>::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall sub_51DDD0(SerSaveConstructHelperView *this);
   *
   * What it does:
   * Virtual-method body installed in the
   * `Moho::RPropBlueprintSaveConstruct` and
   * `gpg::SerSaveConstructHelper<Moho::RPropBlueprint>` vtables. Lazily
   * resolves the `RPropBlueprint` reflection descriptor, asserts the
   * save-construct-args callback slot is empty, and publishes this helper's
   * save-construct-args callback to the descriptor.
   */
  [[maybe_unused]] gpg::RType* InitRPropBlueprintSaveConstructHelper(
    const SerSaveConstructHelperView& helper
  )
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
    type->serSaveConstructArgsFunc_ = helper.mSaveConstructArgsCallback;
    return type;
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
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRPropBlueprintConstructHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRPropBlueprintConstructHelper);
  }

  /**
   * Address: 0x0051DC60 (FUN_0051DC60)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RPropBlueprint` construct-helper lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRPropBlueprintConstructHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRPropBlueprintConstructHelper);
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
